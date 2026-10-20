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
 * The Durable Object SQL API (`ctx.storage.sql`) over Node's `node:sqlite`
 * for the unit tests: a real SQLite behind the same `exec(query,
 * ...bindings)` cursor shape, blobs bound as `ArrayBuffer` and returned as
 * the storage API returns them. Test harness only.
 */

import { DatabaseSync } from "node:sqlite";
import type { CellStorageLike, SqlCursorLike, SqlStorageLike, SqlValue } from "../src/workers-types.js";

export class NodeSqlStorage implements SqlStorageLike {
  readonly db = new DatabaseSync(":memory:");

  exec<T extends Record<string, SqlValue> = Record<string, SqlValue>>(query: string, ...bindings: unknown[]): SqlCursorLike<T> {
    const statement = this.db.prepare(query);
    const bound = bindings.map((b) => b instanceof ArrayBuffer ? new Uint8Array(b) : b) as (string | number | bigint | Uint8Array | null)[];
    const rows = /^\s*(select|pragma|with)/i.test(query) || /returning/i.test(query)
      ? statement.all(...bound) as Record<string, unknown>[] : (statement.run(...bound), []);
    const out = rows.map((row) => {
      const copy: Record<string, SqlValue> = {};
      for (const [k, v] of Object.entries(row)) {
        copy[k] = v instanceof Uint8Array ? v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength) as ArrayBuffer
          : typeof v === "bigint" ? Number(v) : v as SqlValue;
      }
      return copy as T;
    });
    return {
      toArray: () => out,
      one: () => {
        if (out.length !== 1) {
          throw new Error(`expected one row, got ${out.length}`);
        }
        return out[0]!;
      },
      [Symbol.iterator]: () => out[Symbol.iterator](),
    };
  }
}

/** A `ctx.storage` with the SQL API and an alarm slot. */
export class NodeCellStorage implements CellStorageLike {
  readonly sql = new NodeSqlStorage();
  alarmAt: number | null = null;

  async getAlarm(): Promise<number | null> {
    return this.alarmAt;
  }

  async setAlarm(scheduledTime: number | Date): Promise<void> {
    this.alarmAt = typeof scheduledTime === "number" ? scheduledTime : scheduledTime.getTime();
  }

  async deleteAlarm(): Promise<void> {
    this.alarmAt = null;
  }
}
