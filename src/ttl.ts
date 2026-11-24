/*
 * Copyright 2026 Bad Monkey, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The TTL floor (SPEC v0.1.36 §9.5 *TTLs*; srad/agentspaces-event-loop.md EL-E-03, EL-E-04, decision 18), as Java's
 * `TtlFloor`: a short TTL makes a noisy group, since every renewal is a frame, so a configured TTL, lease or expiry
 * under 60 s warns once, naming the key, the value and the principle, or throws under `strict`, unless it is the
 * registered default (whose register line carries the reason) or an expert override names the key with a reason.
 *
 *     const floor = new TtlFloor({ strict: false, overrides: { "binder.Clerk.handle.lease": "a 20 s SLA" } });
 *     floor.check("binder.Clerk.handle.lease", 20_000);
 */

/** Values under this are judged (60 s, the owner's floor of 2026-11-21). */
export const TTL_FLOOR_MILLIS = 60_000;

/** One registered default under the floor, and why it may be short. */
export type TtlRegisterLine = { millis: number; reason: string };

/**
 * This client's TTLs, leases and expiries under 60 s, each with its reason (Java's `ttl-register.txt`, for the
 * values this client configures). A key matches by its last member (`lease`, `takeLease`) under its verb.
 */
export const TTL_REGISTER: { [key: string]: TtlRegisterLine } = {
  "orderedTake.lease": { millis: 30_000,
    reason: "the @orderedTake take lease, renewed at half the lease while the handler runs (owner answer 12)" },
  "join.takeLease": { millis: 30_000,
    reason: "a @spaceJoin ticket's take lease, held at most min(lease / 2, 5 s) and renewed meanwhile (EL-E-08)" },
  "reduce.lease": { millis: 30_000,
    reason: "a @spaceReduce element's take lease, renewed before each step (EL-E-08)" },
};

/** A TTL under the floor refused under `strict`. */
export class TtlFloorError extends Error {
  constructor(readonly key: string, readonly millis: number) {
    super(`${key} = ${millis} ms is under the ${TTL_FLOOR_MILLIS} ms TTL floor: short TTLs make a noisy group, since `
      + "every renewal is a frame (SPEC §9.5); raise it, or name the key with a reason in the expert overrides");
    this.name = "TtlFloorError";
  }
}

export type TtlFloorOptions = {
  /** Refuse a value under the floor (a strict host); warn otherwise. Off by default, as Java's lenient default. */
  strict?: boolean;
  /** Keys a deployment names on purpose, each with its reason (`agentspaces.ttl.expert-overrides.<key>`). */
  overrides?: { [key: string]: string };
  /** Where a warning goes; `console.warn` by default, `null` for silence. */
  log?: ((line: string) => void) | null;
};

/** One finding of the floor: the key, the value, and what was done. */
export type TtlFinding = { key: string; millis: number; outcome: "warned" | "refused" | "override" };

/** The floor check (warn once per key, or refuse when strict). */
export class TtlFloor {
  readonly strict: boolean;
  private readonly overrides: { [key: string]: string };
  private readonly log: (line: string) => void;
  private readonly seen = new Set<string>();
  readonly findings: TtlFinding[] = [];

  constructor(options: TtlFloorOptions = {}) {
    this.strict = options.strict ?? false;
    this.overrides = { ...(options.overrides ?? {}) };
    for (const [key, reason] of Object.entries(this.overrides)) {
      if (typeof reason !== "string" || reason.trim().length === 0) {
        throw new Error(`the TTL override ${key} needs a reason`);
      }
    }
    this.log = options.log === null ? () => undefined : options.log ?? ((line) => console.warn(line));
  }

  /**
   * Judges one configured value. `registered` names the register line the value's default sits under (`"verb.member"`);
   * a value equal to that default passes silently. Returns whether the value is under the floor and passed anyway.
   */
  check(key: string, millis: number, registered: string | null = null): boolean {
    if (!Number.isFinite(millis) || millis >= TTL_FLOOR_MILLIS) {
      return false;
    }
    const line = registered === null ? undefined : TTL_REGISTER[registered];
    if (line !== undefined && line.millis === millis) {
      return true; // the registered default: its reason is on record
    }
    const override = this.overrides[key];
    if (override !== undefined) {
      if (!this.seen.has(key)) {
        this.seen.add(key);
        this.findings.push({ key, millis, outcome: "override" });
        this.log(`TTL floor: ${key} = ${millis} ms under ${TTL_FLOOR_MILLIS} ms by expert override: ${override}`);
      }
      return true;
    }
    if (this.strict) {
      this.findings.push({ key, millis, outcome: "refused" });
      throw new TtlFloorError(key, millis);
    }
    if (!this.seen.has(key)) {
      this.seen.add(key);
      this.findings.push({ key, millis, outcome: "warned" });
      this.log(`TTL floor: ${key} = ${millis} ms is under ${TTL_FLOOR_MILLIS} ms; short TTLs make a noisy group, since `
        + "every renewal is a frame (SPEC §9.5). Raise it, or name it in the expert overrides with a reason.");
    }
    return true;
  }
}
