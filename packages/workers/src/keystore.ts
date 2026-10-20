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
 * The SQLite key store of a cell (srad/agentspaces-js.md JS-P-08, JS-R-05):
 * the core `KeyStore` port over the Durable Object's own SQLite storage,
 * one row per name in `aspace_keys`. The storage API is synchronous, so each
 * call completes before its promise resolves and a key is on disk before
 * any frame that depends on it leaves (§3.8, invariants). Values are stored
 * as `ArrayBuffer`, the blob type the storage API passes, and read back as a
 * fresh `Uint8Array` either way.
 */

import { Identity } from "@agentspaces/client";
import type { KeyStore } from "@agentspaces/client";
import type { SqlStorageLike, SqlValue } from "./workers-types.js";

/** The table the keys live in. */
export const KEYS_TABLE = "aspace_keys";

/** The name the cell's peer key is stored under (`peer.key`, the file keystore's name). */
export const PEER_KEY = "peer.key";

const SAFE_NAME = /^[A-Za-z0-9._-]{1,64}$/;

/** A blob column's value as bytes, whichever form the storage returned. */
export function bytesOf(value: unknown): Uint8Array | null {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value.slice(0));
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  return null;
}

/** Bytes as the `ArrayBuffer` the storage API binds to a blob column. */
export function blobOf(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

/** A {@link KeyStore} over a Durable Object's SQLite storage. */
export class SqliteKeyStore implements KeyStore {
  constructor(private readonly sql: SqlStorageLike, private readonly table = KEYS_TABLE) {
    if (!SAFE_NAME.test(table)) {
      throw new Error(`key table '${table}' is not a safe table name`);
    }
    sql.exec(`CREATE TABLE IF NOT EXISTS ${table} (name TEXT PRIMARY KEY, value BLOB NOT NULL)`);
  }

  async load(name: string): Promise<Uint8Array | null> {
    const rows = this.sql.exec<{ value: SqlValue }>(`SELECT value FROM ${this.table} WHERE name = ?`, this.check(name)).toArray();
    return rows.length === 0 ? null : bytesOf(rows[0]!.value);
  }

  async save(name: string, value: Uint8Array): Promise<void> {
    this.sql.exec(`INSERT OR REPLACE INTO ${this.table} (name, value) VALUES (?, ?)`, this.check(name), blobOf(value));
  }

  async remove(name: string): Promise<void> {
    this.sql.exec(`DELETE FROM ${this.table} WHERE name = ?`, this.check(name));
  }

  /** The names stored, for inspection. */
  names(): string[] {
    return this.sql.exec<{ name: string }>(`SELECT name FROM ${this.table} ORDER BY name`).toArray().map((r) => r.name);
  }

  private check(name: string): string {
    if (!SAFE_NAME.test(name) || name === "." || name === "..") {
      throw new Error(`key name '${name}' is not a safe key name`);
    }
    return name;
  }
}

/**
 * The cell's identity: the PKCS#8 key under `peer.key`, minted on first
 * construction and the same on every later one (JS-R-03: the identity
 * resumes across evictions and moves). A stored key that does not parse is
 * refused, naming the key, rather than silently replaced.
 */
export async function loadOrCreateIdentity(keys: KeyStore, name = PEER_KEY): Promise<Identity> {
  const stored = await keys.load(name);
  if (stored !== null) {
    try {
      return Identity.fromPkcs8(stored);
    } catch (e) {
      throw new Error(`the stored key '${name}' is not a PKCS#8 Ed25519 key: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  const identity = Identity.generate();
  await keys.save(name, identity.pkcs8());
  return identity;
}
