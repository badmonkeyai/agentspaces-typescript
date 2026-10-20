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
 * The core's `KeyStore` port over IndexedDB (srad/agentspaces-js.md
 * JS-P-08, §6.2 `IdbKeyStore`): one database per group holding two object
 * stores, `keys` (the peer and agent keys, by the names the file layout of
 * `@agentspaces/node` uses) and `state` (the peer's snapshot). The database
 * opens lazily on first use and is shared by every store over it. The IDB
 * API is typed here structurally, so the package compiles without the DOM
 * library, as the core's `ws` dialer does with `WebSocket`.
 */

import type { KeyStore } from "@agentspaces/client";

/** The object stores every host database carries. */
export const KEYS_STORE = "keys";
export const STATE_STORE = "state";
const VERSION = 1;

interface IdbRequest<T = unknown> {
  result: T;
  error: { message?: string } | null;
  onsuccess: ((event: unknown) => void) | null;
  onerror: ((event: unknown) => void) | null;
}

interface IdbOpenRequest extends IdbRequest<IdbDatabase> {
  onupgradeneeded: ((event: unknown) => void) | null;
  onblocked: ((event: unknown) => void) | null;
}

interface IdbObjectStore {
  get(key: string): IdbRequest;
  put(value: unknown, key: string): IdbRequest;
  delete(key: string): IdbRequest;
  getAllKeys(): IdbRequest<string[]>;
}

interface IdbTransaction {
  objectStore(name: string): IdbObjectStore;
  oncomplete: ((event: unknown) => void) | null;
  onerror: ((event: unknown) => void) | null;
  onabort: ((event: unknown) => void) | null;
  error: { message?: string } | null;
}

interface IdbDatabase {
  objectStoreNames: { contains(name: string): boolean };
  createObjectStore(name: string): unknown;
  transaction(stores: string | string[], mode: "readonly" | "readwrite"): IdbTransaction;
  close(): void;
  onversionchange: ((event: unknown) => void) | null;
}

interface IdbFactory {
  open(name: string, version: number): IdbOpenRequest;
  deleteDatabase(name: string): IdbRequest;
}

function factory(): IdbFactory {
  const idb = (globalThis as { indexedDB?: IdbFactory }).indexedDB;
  if (idb === undefined) {
    throw new Error("this runtime has no IndexedDB; the resident host needs one (a browser page or worker)");
  }
  return idb;
}

function settle<T>(request: IdbRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error(request.error?.message ?? "IndexedDB request failed"));
  });
}

/** One open database per name per process, shared by the stores over it. */
const open = new Map<string, Promise<IdbDatabase>>();

/** Opens (creating on first use) the host database `name` with its two stores. */
export function openDatabase(name: string): Promise<IdbDatabase> {
  let pending = open.get(name);
  if (pending === undefined) {
    pending = new Promise<IdbDatabase>((resolve, reject) => {
      const request = factory().open(name, VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        for (const store of [KEYS_STORE, STATE_STORE]) {
          if (!db.objectStoreNames.contains(store)) {
            db.createObjectStore(store);
          }
        }
      };
      request.onblocked = () => reject(new Error(`IndexedDB database ${name} is blocked by another open connection`));
      request.onsuccess = () => {
        const db = request.result;
        db.onversionchange = () => {
          db.close();
          open.delete(name);
        };
        resolve(db);
      };
      request.onerror = () => reject(new Error(request.error?.message ?? `cannot open IndexedDB database ${name}`));
    });
    pending.catch(() => open.delete(name));
    open.set(name, pending);
  }
  return pending;
}

/** Closes the shared connection to `name`, so a test can delete the database. */
export async function closeDatabase(name: string): Promise<void> {
  const pending = open.get(name);
  open.delete(name);
  if (pending !== undefined) {
    (await pending.catch(() => null))?.close();
  }
}

/** Deletes the database, closing the shared connection first. */
export async function deleteDatabase(name: string): Promise<void> {
  await closeDatabase(name);
  await settle(factory().deleteDatabase(name));
}

/**
 * A {@link KeyStore} over one object store of a host database: `keys` by
 * default, `state` for the snapshot. Values are copied in and out, so a
 * caller's later edits never reach the store.
 */
export class IndexedDbKeyStore implements KeyStore {
  constructor(readonly database: string, readonly store: string = KEYS_STORE) {}

  private async objectStore(mode: "readonly" | "readwrite"): Promise<{ store: IdbObjectStore; done: Promise<void> }> {
    const db = await openDatabase(this.database);
    const transaction = db.transaction(this.store, mode);
    const done = new Promise<void>((resolve, reject) => {
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error(transaction.error?.message ?? "IndexedDB transaction failed"));
      transaction.onabort = () => reject(new Error(transaction.error?.message ?? "IndexedDB transaction aborted"));
    });
    return { store: transaction.objectStore(this.store), done };
  }

  async load(name: string): Promise<Uint8Array | null> {
    const { store } = await this.objectStore("readonly");
    const value = await settle(store.get(name));
    if (value === undefined || value === null) {
      return null;
    }
    if (value instanceof Uint8Array) {
      return new Uint8Array(value);
    }
    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value.slice(0));
    }
    throw new Error(`${this.database}/${this.store}/${name} holds a ${typeof value}, not bytes`);
  }

  async save(name: string, value: Uint8Array): Promise<void> {
    const { store, done } = await this.objectStore("readwrite");
    store.put(new Uint8Array(value), name);
    await done;
  }

  async remove(name: string): Promise<void> {
    const { store, done } = await this.objectStore("readwrite");
    store.delete(name);
    await done;
  }

  /** Every name in the store. */
  async names(): Promise<string[]> {
    const { store } = await this.objectStore("readonly");
    return [...await settle(store.getAllKeys())];
  }
}
