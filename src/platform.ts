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
 * The platform port of the portable core (srad/agentspaces-js.md §3.1, §3.6):
 * the runtime facilities a peer needs (crypto, clock, timers, key storage)
 * behind one object, and the residency a host declares. The defaults use
 * only what every JavaScript runtime offers (`globalThis.crypto`,
 * `setTimeout`, `Date.now`), so nothing here imports a Node module.
 */

import { CryptoPort, cryptoPort } from "./crypto.js";

/** Persistent storage for keys and small secrets, one value per name. */
export interface KeyStore {
  load(name: string): Promise<Uint8Array | null>;
  save(name: string, value: Uint8Array): Promise<void>;
  remove(name: string): Promise<void>;
}

/** A key store in memory: the default, for tests and visitor pages. */
export class MemoryKeyStore implements KeyStore {
  private readonly values = new Map<string, Uint8Array>();

  async load(name: string): Promise<Uint8Array | null> {
    const value = this.values.get(name);
    return value === undefined ? null : new Uint8Array(value);
  }

  async save(name: string, value: Uint8Array): Promise<void> {
    this.values.set(name, new Uint8Array(value));
  }

  async remove(name: string): Promise<void> {
    this.values.delete(name);
  }
}

/** A repeating timer's handle. */
export interface Repeating {
  /** How late, in milliseconds, the most recent run fired against its schedule. */
  readonly lastDriftMillis: number;
  /** Consecutive runs that fired more than one period late (JS-R-06). */
  readonly lateRuns: number;
  stop(): void;
}

/** Timers behind a port, so tests drive them on a fake clock (JS-P-10). */
export interface TimerPort {
  setTimeout(fn: () => void, millis: number): unknown;
  clearTimeout(handle: unknown): void;
  /** Runs `fn` every `periodMillis`, reporting how late each run fired. */
  every(periodMillis: number, fn: () => void): Repeating;
}

/** The runtime's own timers, with drift measured against the schedule. */
export const systemTimers: TimerPort = {
  setTimeout: (fn, millis) => globalThis.setTimeout(fn, millis),
  clearTimeout: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
  every(periodMillis, fn) {
    let next = Date.now() + periodMillis;
    let handle: ReturnType<typeof setTimeout> | null = null;
    let stopped = false;
    const state = {
      lastDriftMillis: 0,
      lateRuns: 0,
      stop(): void {
        stopped = true;
        if (handle !== null) {
          globalThis.clearTimeout(handle);
        }
      },
    };
    const schedule = (): void => {
      handle = globalThis.setTimeout(run, Math.max(0, next - Date.now()));
      unrefIfPossible(handle);
    };
    const run = (): void => {
      if (stopped) {
        return;
      }
      const now = Date.now();
      state.lastDriftMillis = Math.max(0, now - next);
      state.lateRuns = state.lastDriftMillis > periodMillis ? state.lateRuns + 1 : 0;
      next = Math.max(next + periodMillis, now + 1);
      try {
        fn();
      } finally {
        if (!stopped) {
          schedule();
        }
      }
    };
    schedule();
    return state;
  },
};

/** On Node a repeating tick must not keep the process alive by itself; elsewhere timers have no unref. */
function unrefIfPossible(handle: unknown): void {
  const maybe = handle as { unref?: () => void };
  if (typeof maybe?.unref === "function") {
    maybe.unref();
  }
}

/**
 * How long and how reliably a host runs (§3.6). A visitor is a page; a
 * resident is a SharedWorker or Worker holding a Web Lock; a service is a
 * Node, Deno, Bun, or Electron process; a cell is a Durable Object.
 */
export type Residency = "visitor" | "resident" | "service" | "cell";

/** The order residencies grant duties in; an unknown residency ranks as a visitor (JS-F-03). */
const RANK: Record<Residency, number> = { visitor: 0, resident: 1, cell: 2, service: 3 };

/** The residency a string names, or `visitor` for anything unknown (JS-F-03). */
export function residencyOf(value: unknown): Residency {
  return typeof value === "string" && value in RANK ? value as Residency : "visitor";
}

/** Duties a host must hold a residency for (§3.6). */
export type Duty = "voter" | "coordinator" | "keeper" | "listener" | "relay" | "connector";

const REQUIRED: Record<Duty, Residency[]> = {
  voter: ["service"],
  coordinator: ["service"],
  keeper: ["resident", "service", "cell"],
  listener: ["service"],
  relay: ["service"],
  connector: ["service", "cell"],
};

/** The package that supplies a host able to carry a duty, for refusal messages. */
const SUPPLIER: Record<Duty, string> = {
  voter: "@agentspaces/node",
  coordinator: "@agentspaces/node",
  keeper: "@agentspaces/browser, @agentspaces/node, or @agentspaces/workers",
  listener: "@agentspaces/node",
  relay: "@agentspaces/node",
  connector: "@agentspaces/node or @agentspaces/workers",
};

/** Whether a residency may carry a duty. */
export function mayHost(residency: Residency, duty: Duty): boolean {
  return REQUIRED[duty].includes(residencyOf(residency));
}

/**
 * Throws when the residency cannot carry the duty (JS-R-01), naming the
 * duty, the residency, and the package that supplies a host that can.
 */
export function requireResidency(residency: Residency, duty: Duty, what: string): void {
  if (!mayHost(residency, duty)) {
    throw new Error(`${what} needs residency ${REQUIRED[duty].join(" or ")}; this host is `
      + `${residencyOf(residency)}; run it in ${SUPPLIER[duty]}`);
  }
}

/** Everything a peer takes from its runtime. */
export interface Platform {
  readonly crypto: CryptoPort;
  readonly clock: () => number;
  readonly timers: TimerPort;
  readonly keys: KeyStore;
  readonly residency: Residency;
}

/** The default platform: the installed crypto port, `Date.now`, system timers, memory keys, a visitor. */
export function platform(overrides: Partial<Platform> = {}): Platform {
  return {
    crypto: overrides.crypto ?? cryptoPort(),
    clock: overrides.clock ?? Date.now,
    timers: overrides.timers ?? systemTimers,
    keys: overrides.keys ?? new MemoryKeyStore(),
    residency: residencyOf(overrides.residency ?? "visitor"),
  };
}
