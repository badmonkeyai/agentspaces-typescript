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
 * The Web Lock election of the resident host (srad/agentspaces-js.md
 * JS-R-02, §6.2 `LockElection`): one host per identity per origin holds
 * `agentspaces:<group>:<peerId>` for its life; a second host asking for the
 * same name waits its turn (so the next tab's host takes over when a worker
 * dies) or gives up after a bound, naming the lock. The browser releases a
 * lock when its holder's global is destroyed, which is what makes worker
 * termination hand the role on without a message.
 */

interface LockRequestOptions { mode?: "exclusive" | "shared"; ifAvailable?: boolean; signal?: unknown }
interface LockManagerLike {
  request(name: string, options: LockRequestOptions, callback: (lock: unknown) => Promise<unknown>): Promise<unknown>;
  query?(): Promise<{ held?: { name?: string }[]; pending?: { name?: string }[] }>;
}
interface AbortControllerLike { readonly signal: unknown; abort(reason?: unknown): void }

function manager(): LockManagerLike {
  const locks = (globalThis as { navigator?: { locks?: LockManagerLike } }).navigator?.locks;
  if (locks === undefined) {
    throw new Error("this runtime has no Web Locks (navigator.locks); the resident host needs them");
  }
  return locks;
}

/** A held lock; `release` returns it. */
export interface Held {
  readonly name: string;
  release(): void;
}

export class LockElection {
  /** Whether a holder is recorded for `name` right now (for diagnostics; never a decision). */
  static async heldBy(name: string): Promise<boolean> {
    const query = manager().query;
    if (query === undefined) {
      return false;
    }
    const state = await query.call(manager());
    return (state.held ?? []).some((l) => l.name === name);
  }

  /**
   * Takes `name` exclusively, waiting up to `waitMillis` (`null` waits for good); rejects with
   * an error naming the lock when the wait runs out, leaving no request pending.
   */
  static acquire(name: string, waitMillis: number | null): Promise<Held> {
    const Controller = (globalThis as { AbortController?: new () => AbortControllerLike }).AbortController;
    const controller = Controller !== undefined ? new Controller() : null;
    return new Promise<Held>((resolve, reject) => {
      let timer: unknown = null;
      let granted = false;
      const clear = (): void => {
        if (timer !== null) {
          globalThis.clearTimeout(timer as ReturnType<typeof setTimeout>);
          timer = null;
        }
      };
      if (waitMillis !== null && controller !== null) {
        timer = globalThis.setTimeout(() => {
          if (!granted) {
            controller.abort(new Error("lock wait expired"));
          }
        }, waitMillis);
      }
      manager().request(name, { mode: "exclusive", signal: controller?.signal }, (lock) => {
        if (lock === null) {
          reject(new Error(`another host holds the Web Lock ${name} in this origin`));
          return Promise.resolve();
        }
        granted = true;
        clear();
        return new Promise<void>((release) => {
          resolve({ name, release });
        });
      }).catch((e: unknown) => {
        clear();
        if (!granted) {
          const aborted = e instanceof Error && e.name === "AbortError" || String(e).includes("lock wait expired");
          reject(aborted
            ? new Error(`another host holds the Web Lock ${name} in this origin (waited ${waitMillis} ms)`)
            : e instanceof Error ? e : new Error(String(e)));
        }
      });
    });
  }

  /** Runs `fn` under `name`, releasing when it settles: the identity bootstrap's critical section. */
  static async withLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
    return manager().request(name, { mode: "exclusive" }, () => fn()) as Promise<T>;
  }
}
