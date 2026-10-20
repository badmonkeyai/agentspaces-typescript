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
 * The connector entry types (srad/agentspaces-js.md JS-C-01, JS-C-03,
 * JS-F-06): the `aspace:cap/data-query` entries of `DataQueryEntries.java`
 * (`DataQuery` at line 45, `DataResult` at 58, `AssetChange` at 74) and the
 * `aspace:cap/asset-invoke` entries of appendix F, each a class whose fields
 * sit in the Java record's component order so `toPayload` encodes the bytes
 * the Java codec writes, with every map-valued field in canonical order
 * (wire v3). The golden vectors `data_query_cbor`, `data_result_cbor`,
 * `asset_change_cbor`, `asset_invocation_cbor`, and
 * `asset_invocation_result_cbor` pin the encodings.
 *
 * A receiver ignores fields it does not know (JS-F-06): the `from` readers
 * pick the declared fields and drop the rest, so later operation metadata
 * needs no migration.
 */

import { bytes, cbor, deriveId } from "@agentspaces/client";
import type { wire } from "@agentspaces/client";

type Dict = wire.Dict;

/** A string-to-string map, the shape of parameters, rows, and results. */
export type StringMap = { [key: string]: string };

/** The schema names the Java `SimpleSchemaRegistry` gives the records: the binary class name plus `#v1`. */
export const DATA_QUERY_TYPE = "ai.badmonkey.agentspaces.connect.DataQueryEntries$DataQuery#v1";
export const DATA_RESULT_TYPE = "ai.badmonkey.agentspaces.connect.DataQueryEntries$DataResult#v1";
export const ASSET_CHANGE_TYPE = "ai.badmonkey.agentspaces.connect.DataQueryEntries$AssetChange#v1";
export const ASSET_INVOCATION_TYPE = "ai.badmonkey.agentspaces.connect.AssetInvocations$AssetInvocation#v1";
export const ASSET_INVOCATION_RESULT_TYPE =
  "ai.badmonkey.agentspaces.connect.AssetInvocations$AssetInvocationResult#v1";

/** The capability types the cards name in their `access` map. */
export const DATA_QUERY_CAPABILITY = "aspace:cap/data-query";
export const ASSET_INVOKE_CAPABILITY = "aspace:cap/asset-invoke";

/** The protocol version the asset-invoke entries carry (appendix F, JS-F-06). */
export const ASSET_INVOKE_VERSION = 1;

/** The error codes an `AssetInvocationResult` carries when `ok` is false (appendix F). */
export type InvokeError = "unknown-operation" | "bad-params" | "refused-scope" | "target-error" | "timeout";

/** A copy of a string map with its entries in the canonical (wire v3) order and every value a string. */
export function canonicalStrings(value: StringMap | null | undefined): StringMap {
  const out: Dict = {};
  for (const [key, item] of Object.entries(value ?? {})) {
    out[key] = String(item);
  }
  return cbor.canonicalMap(out) as StringMap;
}

/** `rows` as canonical maps, one per row. */
function canonicalRows(rows: StringMap[] | null | undefined): StringMap[] {
  return (rows ?? []).map(canonicalStrings);
}

/**
 * `DataQueryEntries.canonicalHash`: multibase(sha-256) over the asset name and
 * the parameters in sorted key order, so parameter ordering never splits the
 * pull-once cache. Keys sort as Java's `TreeMap<String>` sorts them (UTF-16
 * code units), which is the default string order here.
 */
export function canonicalHash(asset: string, parameters: StringMap): string {
  let canonical = asset;
  for (const key of Object.keys(parameters).sort()) {
    canonical += `|${key}=${parameters[key]}`;
  }
  return deriveId(bytes.utf8(canonical));
}

/** One query awaiting a connector (`DataQueryEntries.DataQuery`). */
export class DataQuery {
  static schema = DATA_QUERY_TYPE;
  /** The canonical hash of (asset, parameters). */
  readonly queryHash: string;
  /** The asset name from the card. */
  readonly asset: string;
  /** The query parameters. */
  readonly parameters: StringMap;
  /** The asking agent, for the audit trail. */
  readonly requester: string;

  constructor(queryHash: string, asset: string, parameters: StringMap, requester: string) {
    this.queryHash = queryHash;
    this.asset = asset;
    this.parameters = canonicalStrings(parameters);
    this.requester = requester;
  }

  /** The declared fields of a decoded payload; anything else is dropped. */
  static from(value: Dict): DataQuery {
    return new DataQuery(String(value["queryHash"]), String(value["asset"]),
      (value["parameters"] as StringMap | undefined) ?? {}, String(value["requester"]));
  }
}

/** One answered query, leased for its freshness window (`DataQueryEntries.DataResult`). */
export class DataResult {
  static schema = DATA_RESULT_TYPE;
  /** The canonical hash the result answers. */
  readonly queryHash: string;
  /** The asset name. */
  readonly asset: string;
  /** Result rows; column name to value. */
  readonly rows: StringMap[];
  /** An error message when the query failed; null on success. */
  readonly error: string | null;
  /** The connector that executed against the source. */
  readonly servedBy: string;

  constructor(queryHash: string, asset: string, rows: StringMap[], error: string | null, servedBy: string) {
    this.queryHash = queryHash;
    this.asset = asset;
    this.rows = canonicalRows(rows);
    this.error = error;
    this.servedBy = servedBy;
  }

  static from(value: Dict): DataResult {
    const error = value["error"];
    return new DataResult(String(value["queryHash"]), String(value["asset"]),
      (value["rows"] as StringMap[] | undefined) ?? [], error == null ? null : String(error),
      String(value["servedBy"]));
  }
}

/**
 * One change a materializing provider pushed (`DataQueryEntries.AssetChange`),
 * leased for the asset's freshness window so the lease is the retention
 * policy. Subscribe with `new Template(AssetChange, { asset: eq(name) })`.
 */
export class AssetChange {
  static schema = ASSET_CHANGE_TYPE;
  /** The asset name from its card. */
  readonly asset: string;
  /** The changed record's key within the asset. */
  readonly key: string;
  /** The changed record; column name to value. */
  readonly row: StringMap;
  /** The connector that materialized the change. */
  readonly servedBy: string;

  constructor(asset: string, key: string, row: StringMap, servedBy: string) {
    this.asset = asset;
    this.key = key;
    this.row = canonicalStrings(row);
    this.servedBy = servedBy;
  }

  static from(value: Dict): AssetChange {
    return new AssetChange(String(value["asset"]), String(value["key"]),
      (value["row"] as StringMap | undefined) ?? {}, String(value["servedBy"]));
  }
}

/**
 * One operation an agent asks a connector to run (appendix F,
 * `AssetInvocations.AssetInvocation`): the `aspace:cap/asset-invoke` request.
 * `invocationId` is the invocation's id, minted once by the client and
 * constant across retries and takers, so a target deduplicates on it.
 */
export class AssetInvocation {
  static schema = ASSET_INVOCATION_TYPE;
  /** The protocol version; receivers ignore fields they do not know (JS-F-06). */
  readonly v: number;
  /** The asset name from the card. */
  readonly asset: string;
  /** The operation, one of the card's `invoke-ops`. */
  readonly operation: string;
  /** The operation's parameters, by declared name. */
  readonly params: StringMap;
  /** The invocation's id, constant across retries and takers. */
  readonly invocationId: string;

  constructor(asset: string, operation: string, params: StringMap, invocationId: string, v = ASSET_INVOKE_VERSION) {
    this.v = v;
    this.asset = asset;
    this.operation = operation;
    this.params = canonicalStrings(params);
    this.invocationId = invocationId;
  }

  static from(value: Dict): AssetInvocation {
    return new AssetInvocation(String(value["asset"]), String(value["operation"]),
      (value["params"] as StringMap | undefined) ?? {}, String(value["invocationId"]),
      Number(value["v"] ?? ASSET_INVOKE_VERSION));
  }
}

/**
 * The connector's answer to an `AssetInvocation` (appendix F,
 * `AssetInvocations.AssetInvocationResult`), correlated by `invocationId`.
 * When `ok` is false, `error` is one of the appendix F codes and `result`
 * carries `rule` (the rule that refused) and `detail`.
 */
export class AssetInvocationResult {
  static schema = ASSET_INVOCATION_RESULT_TYPE;
  readonly v: number;
  readonly invocationId: string;
  readonly asset: string;
  readonly operation: string;
  /** Whether the operation ran and succeeded. */
  readonly ok: boolean;
  /** The operation's result on success; `rule` and `detail` on an error. */
  readonly result: StringMap;
  /** The error code when `ok` is false; null otherwise. */
  readonly error: string | null;

  constructor(invocationId: string, asset: string, operation: string, ok: boolean, result: StringMap,
              error: string | null, v = ASSET_INVOKE_VERSION) {
    this.v = v;
    this.invocationId = invocationId;
    this.asset = asset;
    this.operation = operation;
    this.ok = ok;
    this.result = canonicalStrings(result);
    this.error = error;
  }

  static from(value: Dict): AssetInvocationResult {
    const error = value["error"];
    return new AssetInvocationResult(String(value["invocationId"]), String(value["asset"]),
      String(value["operation"]), value["ok"] === true, (value["result"] as StringMap | undefined) ?? {},
      error == null ? null : String(error), Number(value["v"] ?? ASSET_INVOKE_VERSION));
  }

  /** An error result naming the rule that refused the invocation. */
  static refused(invocation: AssetInvocation, error: InvokeError, rule: string, detail: string): AssetInvocationResult {
    return new AssetInvocationResult(invocation.invocationId, invocation.asset, invocation.operation, false,
      { rule, detail }, error);
  }
}
