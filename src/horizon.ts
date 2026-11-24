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
 * The collection horizons of SPEC §7.3 (v0.1.35; srad/replication-by-entry.md RE-H-03, RE-H-04, decision 22), as
 * Java's `SpaceStateCrdt.keepMillis` and `ReplicatedSpace`'s mode reckon them.
 *
 * - A lapsed entry, present but past its lease, keeps `min(2 x maxLease, 5 min)`.
 * - A completed entry keeps `2 x maxLease` under both rules.
 * - A withdrawn entry keeps `2 x maxLease` under the legacy rule and five minutes under the per-entry rule of
 *   `wire.horizon=1`, and never less than `MAX_DRIFT` (the drift floor), so `max(5 min, MAX_DRIFT)`, ten minutes,
 *   per entry.
 * - An entry both withdrawn and completed keeps `max(2 x maxLease, MAX_DRIFT)` under both rules, so it never goes
 *   before a copy that is withdrawn alone.
 *
 * The per-entry rule is read from the membership view, never from a caller: {@link HorizonMode} engages it after the
 * view has been fully hinted for three rounds, brings it into force one maximum lease plus the grace later, and drops
 * it at once when a member without the hint appears.
 */

import { MAX_HLC_SKEW_MILLIS } from "./wire.js";

/** How long a lapsed entry stays past its expiry, at most (SPEC §7.3). */
export const LAPSED_GRACE_MILLIS = 5 * 60_000;
/** The least a withdrawn entry keeps past its own expiry under either rule: the drift ceiling of SPEC §11. */
export const WITHDRAWN_DRIFT_FLOOR_MILLIS = MAX_HLC_SKEW_MILLIS;

/** The rule a replica's view allows for withdrawals. */
export type Rule = "legacy" | "per-entry";

/** What an entry is, for its horizon: present (live or lapsed), completed, withdrawn, or both withdrawn and completed. */
export type HorizonKind = "present" | "completed" | "withdrawn" | "withdrawn_completed";

/** How long a state of a kind is kept past its own lease expiry before it is collectable. */
export function keepMillis(kind: HorizonKind, maxLeaseMillis: number, rule: Rule): number {
  const twice = 2 * Math.max(0, maxLeaseMillis);
  switch (kind) {
    case "present":
      return Math.min(twice, LAPSED_GRACE_MILLIS);
    case "completed":
      return twice;
    case "withdrawn_completed":
      return Math.max(twice, WITHDRAWN_DRIFT_FLOOR_MILLIS);
    case "withdrawn":
      return Math.max(rule === "per-entry" ? LAPSED_GRACE_MILLIS : twice, WITHDRAWN_DRIFT_FLOOR_MILLIS);
  }
}

/** The time from which a state is collectable: its expiry plus what its kind keeps. */
export function collectionHorizon(kind: HorizonKind, expiry: number, maxLeaseMillis: number, rule: Rule): number {
  return expiry + keepMillis(kind, maxLeaseMillis, rule);
}

/** Whether a state is collectable now: a present entry never before its lease lapses, any entry from its horizon. */
export function collectableAt(kind: HorizonKind, expiry: number, nowMillis: number, maxLeaseMillis: number,
                              rule: Rule): boolean {
  if (kind === "present" && expiry > nowMillis) {
    return false;
  }
  return collectionHorizon(kind, expiry, maxLeaseMillis, rule) <= nowMillis;
}

/** Where one space stands on the per-entry horizon, as Java's `ReplicatedSpace.HorizonMode`. */
export type HorizonModeName = "LEGACY" | "WAITING" | "SETTLING" | "PER_ENTRY";

/** Default rounds the view must stay fully hinted before the per-entry horizon engages, and their bounds. */
export const HORIZON_ENGAGE_ROUNDS = 3;
export const HORIZON_ENGAGE_ROUNDS_FLOOR = 1;
export const HORIZON_ENGAGE_ROUNDS_CEILING = 64;

/**
 * The view's half of the per-entry horizon for one space (RE-H-04, RE-Q-REL-09). An unhinted member in view, or this
 * member on the legacy setting, disengages at once and resets the streak, since the rule rests on every writer
 * renewing by §7.2. A fully hinted view counts one round per judgement at least one round after the last counted one
 * and engages after {@link engageRounds} of them, so a card that flaps does not move the mode each time; once engaged
 * the rule comes into force one maximum lease plus the grace later, so every copy a member renewed while its card
 * lacked the hint has lapsed and passed its own lapse horizon first.
 */
export class HorizonMode {
  mode: HorizonModeName = "LEGACY";
  engagements = 0;
  settlements = 0;
  disengagements = 0;
  private rounds = HORIZON_ENGAGE_ROUNDS;
  private streak = 0;
  private countedAt: number | null = null;
  private engagedAt = 0;

  get engageRounds(): number {
    return this.rounds;
  }

  set engageRounds(rounds: number) {
    if (!Number.isInteger(rounds) || rounds < HORIZON_ENGAGE_ROUNDS_FLOOR || rounds > HORIZON_ENGAGE_ROUNDS_CEILING) {
      throw new RangeError(`horizon engage rounds must be from ${HORIZON_ENGAGE_ROUNDS_FLOOR} to `
        + `${HORIZON_ENGAGE_ROUNDS_CEILING}, not ${rounds}`);
    }
    this.rounds = rounds;
  }

  /**
   * Judges the rule this replica may apply now and moves the mode.
   *
   * @param hinted whether this member advertises the hint and every member of its view does too
   * @param roundMillis one round: the group's gossip period
   * @param maxLeaseMillis the space's longest observed lease
   */
  judge(now: number, hinted: boolean, roundMillis: number, maxLeaseMillis: number): Rule {
    if (!hinted) {
      if (this.mode === "SETTLING" || this.mode === "PER_ENTRY") {
        this.disengagements += 1;
      }
      this.mode = "LEGACY";
      this.streak = 0;
      this.countedAt = null;
      return "legacy";
    }
    if (this.mode === "LEGACY" || this.mode === "WAITING") {
      const round = Math.max(1, roundMillis);
      if (this.countedAt === null || now < this.countedAt) {
        this.countedAt = now; // the first hinted judgement, or a clock that stepped back
      } else if (now - this.countedAt >= round) {
        this.streak += 1;
        this.countedAt = now;
      }
      if (this.streak >= this.rounds) {
        this.engagedAt = now;
        this.mode = "SETTLING";
        this.engagements += 1;
      } else {
        this.mode = "WAITING";
      }
    }
    if (this.mode === "SETTLING") {
      const settle = Math.max(0, maxLeaseMillis) + LAPSED_GRACE_MILLIS;
      if (now < this.engagedAt) {
        this.engagedAt = now; // the clock stepped back: the wait counts from here
      } else if (now - this.engagedAt >= settle) {
        this.mode = "PER_ENTRY";
        this.settlements += 1;
      }
    }
    return this.mode === "PER_ENTRY" ? "per-entry" : "legacy";
  }

  /**
   * When this mode next needs a judgement to move (due work, SPEC v0.1.36 §9.5): one round on while a fully hinted
   * view counts its streak, the end of the settle wait while settling, never once engaged or while unhinted.
   */
  nextJudgement(now: number, hinted: boolean, roundMillis: number, maxLeaseMillis: number): number | null {
    if (!hinted || this.mode === "PER_ENTRY") {
      return null;
    }
    if (this.mode === "SETTLING") {
      return this.engagedAt + Math.max(0, maxLeaseMillis) + LAPSED_GRACE_MILLIS;
    }
    return (this.countedAt ?? now) + Math.max(1, roundMillis);
  }
}
