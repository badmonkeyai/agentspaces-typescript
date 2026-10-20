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
 * Exactly-once operations in a Durable Object (srad/agentspaces-js.md
 * JS-C-04; appendix F, invoke operations): task leases and single-writer
 * state together do not give exactly-once side effects, so a target
 * operation written for the connector wraps its body in
 * `once(storage, invocationId, fn)`. The invocation id is the client's,
 * constant across retries and takers; `once` records the id with the
 * serialised result in the table `aspace_once` of the object's own SQLite
 * storage, returns the stored result on a repeat without running `fn`
 * again, and deletes rows older than the retention (default 24 h). A call
 * whose `fn` throws records nothing, so a retry may run it again: the
 * target decides what a failed attempt means.
 */

import { durationMillis } from "@agentspaces/client";
import type { SqlStorageLike, SqlValue } from "./workers-types.js";

/** The table the ids and results live in. */
export const ONCE_TABLE = "aspace_once";

/** The default retention of a recorded invocation: 24 hours. */
export const DEFAULT_ONCE_RETENTION = "24h";

export type OnceOptions = {
  /** How long a recorded id is kept; default 24 hours. A per-source retention, never a cap. */
  retention?: number | string;
  /** The clock, for tests of the retention. */
  clock?: () => number;
};

/** Either the Durable Object storage (`ctx.storage`) or its `sql` member. */
export type OnceStorage = SqlStorageLike | { readonly sql: SqlStorageLike };

/** Calls in flight per storage, so two concurrent calls under one id share one run. */
const pending = new WeakMap<SqlStorageLike, Map<string, Promise<unknown>>>();
const prepared = new WeakSet<SqlStorageLike>();

function sqlOf(storage: OnceStorage): SqlStorageLike {
  const sql = "exec" in storage && typeof storage.exec === "function" ? storage as SqlStorageLike
    : (storage as { sql: SqlStorageLike }).sql;
  if (!prepared.has(sql)) {
    sql.exec(`CREATE TABLE IF NOT EXISTS ${ONCE_TABLE} (id TEXT PRIMARY KEY, result TEXT NOT NULL, at INTEGER NOT NULL)`);
    prepared.add(sql);
  }
  return sql;
}

/**
 * Runs `fn` once for `invocationId`: the first call runs it and records the
 * result; every later call within the retention returns the recorded
 * result and never runs `fn`. The result must survive `JSON.stringify`
 * (a string map, as the asset-invoke protocol carries).
 */
export async function once<T>(storage: OnceStorage, invocationId: string, fn: () => T | Promise<T>,
                              options: OnceOptions = {}): Promise<T> {
  if (typeof invocationId !== "string" || invocationId.length === 0) {
    throw new Error("once needs a non-empty invocationId");
  }
  const sql = sqlOf(storage);
  const clock = options.clock ?? Date.now;
  const retention = durationMillis(options.retention ?? DEFAULT_ONCE_RETENTION);
  prune(sql, clock() - retention);
  const stored = recorded<T>(sql, invocationId);
  if (stored.found) {
    return stored.result;
  }
  let inFlight = pending.get(sql);
  if (inFlight === undefined) {
    inFlight = new Map();
    pending.set(sql, inFlight);
  }
  const running = inFlight.get(invocationId);
  if (running !== undefined) {
    return running as Promise<T>;
  }
  const run = (async () => {
    try {
      // Deferred one turn, so the in-flight entry below is set before `fn` runs or throws.
      const result = await Promise.resolve().then(fn);
      sql.exec(`INSERT OR REPLACE INTO ${ONCE_TABLE} (id, result, at) VALUES (?, ?, ?)`, invocationId,
        JSON.stringify(result === undefined ? null : result), clock());
      return result;
    } finally {
      inFlight.delete(invocationId);
    }
  })();
  inFlight.set(invocationId, run);
  return run;
}

/** The recorded result of an invocation id, if any (`found` false otherwise). */
export function recorded<T>(storage: OnceStorage, invocationId: string): { found: boolean; result: T } {
  const sql = sqlOf(storage);
  const rows = sql.exec<{ result: SqlValue }>(`SELECT result FROM ${ONCE_TABLE} WHERE id = ?`, invocationId).toArray();
  if (rows.length === 0) {
    return { found: false, result: undefined as T };
  }
  return { found: true, result: JSON.parse(String(rows[0]!.result)) as T };
}

/** Deletes the rows recorded before `olderThanMillis`; returns nothing (the storage API reports no count). */
export function prune(storage: OnceStorage, olderThanMillis: number): void {
  sqlOf(storage).exec(`DELETE FROM ${ONCE_TABLE} WHERE at < ?`, olderThanMillis);
}

/** How many invocation ids are recorded, for inspection. */
export function recordedCount(storage: OnceStorage): number {
  const rows = sqlOf(storage).exec<{ n: number }>(`SELECT COUNT(*) AS n FROM ${ONCE_TABLE}`).toArray();
  return Number(rows[0]?.n ?? 0);
}
