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
 * The redial table (owner decision 1 of 2026-11-23): one table for the core and every client. A peer that lost its
 * link redials its seeds, and the waits between failed attempts follow the fixed cycling table 5 s, 10 s, 20 s, 30 s,
 * then wrap back to 5 s. Each wait carries a random spread of +/-10% so the many peers of a seed that restarts do not
 * redial in lockstep. The position goes back to 0 only when a link that held at least the first wait (5 s) ends, or
 * on a wake from sleep; a link that ends sooner counts as a failed round and waits the next step (owner decisions of
 * 2026-11-23, the same in every client).
 *
 *     const table = new RedialTable();
 *     table.next(); // about 5 000, then about 10 000, 20 000, 30 000, then about 5 000 again
 *     table.reset(); // a link that held 5 s ended, or the host woke: the next wait is the first again
 */

/** The waits of the table, in order; the position wraps to the first after the last. */
export const REDIAL_TABLE_MILLIS: readonly number[] = Object.freeze([5_000, 10_000, 20_000, 30_000]);

/** The random spread on each wait: a wait is its table value times a factor in [1 - spread, 1 + spread). */
export const REDIAL_SPREAD = 0.1;

/** A position in {@link REDIAL_TABLE_MILLIS}, one per peer or host. */
export class RedialTable {
  /** The index of the next wait in the table. */
  position = 0;

  /** `random` gives a value in [0, 1), as `Math.random` does; a test passes a fixed one. */
  constructor(private readonly random: () => number = Math.random) {}

  /**
   * The next wait, and the position moves on (wrapping after the last). `firstMillis` scales the table so that its
   * first wait is that long: 5 000 (the default) gives the table itself, and a host or test configured with a shorter
   * reconnect interval keeps the table's shape at its own scale.
   */
  next(firstMillis: number = REDIAL_TABLE_MILLIS[0]!): number {
    const wait = REDIAL_TABLE_MILLIS[this.position]! * (firstMillis / REDIAL_TABLE_MILLIS[0]!);
    this.position = (this.position + 1) % REDIAL_TABLE_MILLIS.length;
    return wait * (1 + REDIAL_SPREAD * (2 * this.random() - 1));
  }

  /** Back to the first wait: a link that held at least 5 s ended, or the host woke from sleep. */
  reset(): void {
    this.position = 0;
  }
}
