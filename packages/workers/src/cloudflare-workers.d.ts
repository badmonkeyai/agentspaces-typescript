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
 * The `cloudflare:workers` module as this package uses it: the Durable
 * Object base class every cell extends (so its stub answers RPC). Declared
 * here for the package's own build, which compiles beside Node's globals; a
 * Worker that consumes the package has the full declaration from
 * `@cloudflare/workers-types`, and esbuild leaves the import external.
 */
declare module "cloudflare:workers" {
  /** The state as `./workers-types.ts` declares `CellStateLike`; an ambient module cannot import it by a relative name. */
  export interface AmbientCellState {
    readonly id: { toString(): string; readonly name?: string };
    readonly storage: {
      readonly sql: { exec<T extends Record<string, ArrayBuffer | string | number | null> = Record<string, ArrayBuffer | string | number | null>>(
        query: string, ...bindings: unknown[]): { toArray(): T[]; one(): T; [Symbol.iterator](): Iterator<T> } };
      getAlarm(): Promise<number | null>;
      setAlarm(scheduledTime: number | Date): Promise<void>;
      deleteAlarm(): Promise<void>;
    };
    blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T>;
  }

  export abstract class DurableObject<Env = unknown> {
    protected ctx: AmbientCellState;
    protected env: Env;
    constructor(ctx: AmbientCellState, env: Env);
    fetch?(request: Request): Response | Promise<Response>;
    alarm?(): void | Promise<void>;
    webSocketMessage?(ws: unknown, message: string | ArrayBuffer): void | Promise<void>;
    webSocketClose?(ws: unknown, code: number, reason: string, wasClean: boolean): void | Promise<void>;
    webSocketError?(ws: unknown, error: unknown): void | Promise<void>;
  }
}
