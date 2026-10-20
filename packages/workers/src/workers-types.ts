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
 * The slice of the Workers platform this package touches, as structural
 * types (srad/agentspaces-js.md §3.8, appendix F): the Durable Object state
 * and its SQLite storage, and the bindings the manifest may name. Declared
 * here rather than taken from `@cloudflare/workers-types` so the package
 * compiles beside Node's globals (its unit tests run in Node over
 * `node:sqlite`) and a fake in a test satisfies the same shape; the
 * declarations follow the public Workers API exactly, so one bundle runs on
 * celld, workerd, and Cloudflare.
 */

/** A SQLite value as the storage API passes it (`SqlStorageValue`). */
export type SqlValue = ArrayBuffer | string | number | null;

/** One statement's cursor (`SqlStorageCursor`). */
export interface SqlCursorLike<T> {
  toArray(): T[];
  one(): T;
  [Symbol.iterator](): Iterator<T>;
}

/** `ctx.storage.sql`: synchronous SQL over the object's own SQLite database. */
export interface SqlStorageLike {
  exec<T extends Record<string, SqlValue> = Record<string, SqlValue>>(query: string, ...bindings: unknown[]): SqlCursorLike<T>;
}

/** `ctx.storage`: the SQL API and the one alarm an object holds. */
export interface CellStorageLike {
  readonly sql: SqlStorageLike;
  getAlarm(): Promise<number | null>;
  setAlarm(scheduledTime: number | Date): Promise<void>;
  deleteAlarm(): Promise<void>;
}

/** `ctx`: the Durable Object state handed to the constructor. */
export interface CellStateLike {
  readonly id: { toString(): string; readonly name?: string };
  readonly storage: CellStorageLike;
  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T>;
}

/** A Durable Object stub: `fetch` plus the object's RPC methods by name. */
export type DurableObjectStubLike = {
  fetch(input: string | URL, init?: RequestInit): Promise<Response>;
  readonly name?: string;
} & { [method: string]: unknown };

/** A Durable Object namespace binding. */
export interface DurableObjectNamespaceLike {
  getByName(name: string): DurableObjectStubLike;
}

/** A KV namespace binding, the two read operations appendix F allows. */
export interface KVNamespaceLike {
  get(key: string, type: "text"): Promise<string | null>;
  list(options?: { prefix?: string; limit?: number; cursor?: string }): Promise<{
    keys: { name: string; expiration?: number; metadata?: unknown }[]; list_complete: boolean; cursor?: string }>;
}

/** A D1 database binding: prepared statements bound positionally. */
export interface D1DatabaseLike {
  prepare(query: string): {
    bind(...values: unknown[]): { all<T = Record<string, unknown>>(): Promise<{ results: T[] }> };
    all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  };
}

/** One R2 object's metadata (`R2Object`). */
export interface R2ObjectLike {
  readonly key: string;
  readonly size: number;
  readonly etag: string;
  readonly uploaded: Date;
  readonly httpMetadata?: { contentType?: string };
}

/** An R2 bucket binding: `head`, `list`, and `get`. */
export interface R2BucketLike {
  head(key: string): Promise<R2ObjectLike | null>;
  list(options?: { prefix?: string; limit?: number; cursor?: string }): Promise<{
    objects: R2ObjectLike[]; truncated: boolean; cursor?: string }>;
  get(key: string): Promise<(R2ObjectLike & { arrayBuffer(): Promise<ArrayBuffer> }) | null>;
}

/** A Queue producer binding. */
export interface QueueLike {
  send(message: unknown, options?: { contentType?: string }): Promise<void>;
}

/** A Workflow instance handle. */
export interface WorkflowInstanceLike {
  readonly id: string;
  status(): Promise<unknown>;
}

/** A Workflow binding: `create` and `get`. */
export interface WorkflowLike {
  create(options?: { id?: string; params?: unknown }): Promise<WorkflowInstanceLike>;
  get(id: string): Promise<WorkflowInstanceLike>;
}

/** A service binding (`Fetcher`), the target of a route whose manifest entry names one. */
export interface FetcherLike {
  fetch(input: string | URL, init?: RequestInit): Promise<Response>;
}

/** The environment a cell reads its bindings and `vars` from. */
export type CellEnv = { [name: string]: unknown };
