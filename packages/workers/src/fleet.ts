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
 * `fleet(env, binding, name)` (srad/agentspaces-js.md JS-S-06): space
 * handles for a Worker, whose calls go through the Durable Object stub of
 * a connector or agent cell, so a request handler writes, reads, and takes
 * with no transport code. The cell holds the connection and the identity;
 * the Worker holds nothing. Values travel as the core's payload
 * dictionaries over the stub's RPC and come back typed through the entry
 * class given.
 */

import { Class, EntryType, fromPayload, durationMillis, schemaOf, toPayload } from "@agentspaces/client";
import type { wire } from "@agentspaces/client";
import type { CellEntry, CellStatus, Where } from "./cell.js";
import type { CellEnv, DurableObjectNamespaceLike, DurableObjectStubLike } from "./workers-types.js";

type Dict = wire.Dict;

/** The RPC verbs a cell exposes (`CellHost`), as the stub presents them. */
type CellStub = DurableObjectStubLike & {
  cellStatus(): Promise<CellStatus>;
  cellWrite(space: string, schema: string, payload: Dict, leaseMillis: number, tags: Dict): Promise<string>;
  cellEntries(space: string, schema: string, where: Where, limit: number, includeTaken: boolean): Promise<CellEntry[]>;
  cellTake(space: string, schema: string, where: Where, leaseMillis: number, timeoutMillis: number):
    Promise<{ entryId: string; value: Dict } | null>;
  cellComplete(space: string, entryId: string, resultSchema: string | null, result: Dict | null, resultLeaseMillis: number):
    Promise<{ held: boolean; resultId: string | null }>;
  cellRenew(space: string, entryId: string, leaseMillis: number): Promise<boolean>;
};

/** One entry a handle read: the typed value with its metadata. */
export type FleetEntry<T> = { entryId: string; value: T; issuer: string; expiresAtMillis: number; tags: Dict; taken: boolean };

/** A take held by the cell on the caller's behalf. */
export class FleetTaken<T> {
  constructor(private readonly stub: CellStub, readonly space: string, readonly entryId: string, readonly value: T) {}

  /** Completes the take, writing `result` first when given; false when the cell no longer holds it. */
  async complete(result: object | null = null, lease: number | string = "1h"): Promise<{ held: boolean; resultId: string | null }> {
    const schema = result === null ? null : schemaOf(result.constructor as Class);
    return this.stub.cellComplete(this.space, this.entryId, schema, result === null ? null : toPayload(result),
      durationMillis(lease));
  }

  renew(lease: number | string): Promise<boolean> {
    return this.stub.cellRenew(this.space, this.entryId, durationMillis(lease));
  }
}

/** A space as a Worker sees it through the cell. */
export class FleetSpace {
  constructor(private readonly stub: CellStub, readonly name: string) {}

  /** Writes one `@entry` value; returns its id. */
  write(value: object, lease: number | string = "10m", tags: Dict = {}): Promise<string> {
    return this.stub.cellWrite(this.name, schemaOf(value.constructor as Class), toPayload(value), durationMillis(lease), tags);
  }

  /** The live entries of `type` matching the equality conditions. */
  async entries<T>(type: EntryType<T>, where: Where = {}, limit = 100, includeTaken = true): Promise<FleetEntry<T>[]> {
    const found = await this.stub.cellEntries(this.name, schemaOf(type), where, limit, includeTaken);
    return found.map((e) => ({ ...e, value: decode(type, e.value) }));
  }

  /** The live values of `type` matching the conditions. */
  async readAll<T>(type: EntryType<T>, where: Where = {}, limit = 100): Promise<T[]> {
    return (await this.entries(type, where, limit)).map((e) => e.value);
  }

  /** Takes one matching entry under a lease, waiting up to `timeout`. */
  async take<T>(type: EntryType<T>, where: Where = {}, lease: number | string = "1m",
                timeout: number | string = "15s"): Promise<FleetTaken<T> | null> {
    const taken = await this.stub.cellTake(this.name, schemaOf(type), where, durationMillis(lease), durationMillis(timeout));
    return taken === null ? null : new FleetTaken(this.stub, this.name, taken.entryId, decode(type, taken.value));
  }
}

function decode<T>(type: EntryType<T>, payload: Dict): T {
  return typeof type === "string" ? payload as unknown as T : fromPayload(type, payload);
}

/** The fleet as one cell presents it. */
export class Fleet {
  constructor(private readonly stub: CellStub) {}

  status(): Promise<CellStatus> {
    return this.stub.cellStatus();
  }

  space(name: string): FleetSpace {
    return new FleetSpace(this.stub, name);
  }
}

/**
 * The fleet through the cell `name` of the Durable Object `binding`
 * (default `FLEET` and `connector`, the one connector per deployment).
 */
export function fleet(env: CellEnv, binding = "FLEET", name = "connector"): Fleet {
  const namespace = env[binding] as DurableObjectNamespaceLike | undefined;
  if (namespace === undefined || typeof namespace.getByName !== "function") {
    throw new Error(`binding '${binding}' is not a Durable Object namespace in this environment`);
  }
  return new Fleet(namespace.getByName(name) as CellStub);
}
