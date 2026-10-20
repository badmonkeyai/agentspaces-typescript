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
 * The connector SPI (srad/agentspaces-js.md JS-C-01; the port of
 * `AssetProvider.java` and `MaterializingAssetProvider.java`): one
 * implementation per source system. A provider enumerates the assets it
 * holds as AssetCards (SPEC §6.1a), answers one query against one asset, and
 * optionally runs one allowlisted operation; the `ConnectorRuntime` does
 * everything else. Providers hold the source credentials; agents never see
 * them.
 */

import { cbor, instantIso } from "@agentspaces/client";
import type { wire } from "@agentspaces/client";
import { ASSET_INVOKE_CAPABILITY, DATA_QUERY_CAPABILITY, InvokeError, StringMap, canonicalStrings } from "./entries.js";

type Dict = wire.Dict;

/** One query's answer (`AssetProvider.QueryResult`): rows on success or an error message. */
export type QueryResult = { rows: StringMap[]; error: string | null };

/** A successful query result. */
export function queryResult(rows: StringMap[]): QueryResult {
  return { rows, error: null };
}

/** A failed query result. */
export function queryFailed(error: string): QueryResult {
  return { rows: [], error };
}

/**
 * One operation's answer (`AssetProvider.InvokeResult`): `ok` with a result
 * map, or an appendix F error code with the rule that refused and a detail.
 */
export type InvokeResult = { ok: boolean; result: StringMap; error: InvokeError | null };

/** A successful operation result. */
export function invokeResult(result: StringMap): InvokeResult {
  return { ok: true, result, error: null };
}

/** A failed operation result naming the rule that refused it. */
export function invokeFailed(error: InvokeError, rule: string, detail: string): InvokeResult {
  return { ok: false, result: { rule, detail }, error };
}

/**
 * The connector SPI: enumerate assets, answer one query, and (optionally) run
 * one operation. `invoke` is optional; a provider without it refuses every
 * operation with `unknown-operation`, and the runtime refuses an operation
 * absent from the card's `invoke-ops` before the provider ever sees it
 * (JS-C-03, JS-C-07).
 */
export interface AssetProvider {
  /**
   * Describes the assets this connector currently holds, as AssetCard
   * dictionaries in Java field order (see `assetCard`).
   *
   * @param group  the group the cards are scoped to
   * @param issuer the connector's peer id
   * @param nowMillis the issue instant for the cards
   */
  describeAssets(group: string, issuer: string, nowMillis: number): Dict[];

  /**
   * Answers one query; the parameter shapes are asset-specific and declared
   * on the card.
   */
  query(asset: string, parameters: StringMap): QueryResult | Promise<QueryResult>;

  /**
   * Runs one operation the card's `invoke-ops` allowlists, passing the
   * invocation's id to the target so it can deduplicate (JS-C-04).
   */
  invoke?(asset: string, operation: string, params: StringMap, invocationId: string): InvokeResult | Promise<InvokeResult>;
}

/**
 * One change the source emitted (`MaterializingAssetProvider.Change`): the
 * asset name (which selects the freshness window the change is retained
 * for), the changed record's key within the asset, and the record normalized
 * to the shape the card declares.
 */
export type Change = { asset: string; key: string; row: StringMap };

/**
 * The materializing provider style (SPEC §6.1a): a connector that pushes
 * changes into a space as its source changes. The provider hands each change
 * to the sink until the returned handle is closed; the runtime writes it as
 * an `AssetChange` leased for the asset's declared freshness window, so the
 * lease is the retention policy.
 */
export interface MaterializingAssetProvider extends AssetProvider {
  /**
   * Starts pushing this connector's changes to the sink; the runtime calls
   * this once at `start()` and closes the handle at `close()`.
   */
  materialize(sink: (change: Change) => void): { close(): void };
}

/** Whether a provider implements the materializing style. */
export function isMaterializing(provider: AssetProvider): provider is MaterializingAssetProvider {
  return typeof (provider as MaterializingAssetProvider).materialize === "function";
}

/**
 * An AssetCard in Java field order (SPEC §6.1a, `AssetCard.java`): id,
 * issuer, group, issued, ttl, asset, uri, description, shape, freshness,
 * costHints, access. The id is `aspace://<group>/asset/<asset>` unless
 * given, so a refresh replaces the earlier card; the maps are put in
 * canonical order because the signature covers them.
 */
export function assetCard(group: string, issuer: string, issuedMillis: number, ttlIso: string, asset: string,
                          uri: string, description: string, shape: string, freshness: string,
                          costHints: StringMap, access: StringMap, id: string | null = null): Dict {
  return { id: id ?? `aspace://${group}/asset/${asset}`, issuer, group, issued: instantIso(issuedMillis), ttl: ttlIso,
    asset, uri, description, shape, freshness, costHints: cbor.canonicalMap(canonicalStrings(costHints)),
    access: cbor.canonicalMap(canonicalStrings(access)) };
}

/** The comma list of an `access` entry (`read-ops`, `invoke-ops`), trimmed and without empties. */
export function accessList(card: Dict, key: string): string[] {
  const access = (card["access"] as StringMap | undefined) ?? {};
  const value = access[key];
  return value === undefined ? [] : String(value).split(",").map((s) => s.trim()).filter((s) => s.length > 0);
}

/**
 * The reference provider (`TableAssetProvider.java`): an in-memory table.
 * Query parameters are column equality filters plus `limit`; invoke
 * operations are given as functions by name and listed on the card's
 * `invoke-ops`, so the SDK, the protocol, and the exactly-once rules all
 * test without a source system. The counters are what the tests read.
 */
export class TableAssetProvider implements AssetProvider {
  executions = 0;
  invocations = 0;
  private readonly operations: Map<string, (params: StringMap, invocationId: string) => StringMap | Promise<StringMap>>;

  constructor(readonly asset: string, readonly uri: string, readonly description: string, readonly shape: string,
              readonly freshness: string, readonly rows: StringMap[],
              operations: { [name: string]: (params: StringMap, invocationId: string) => StringMap | Promise<StringMap> } = {},
              readonly ttlIso = "PT15M") {
    this.operations = new Map(Object.entries(operations));
  }

  describeAssets(group: string, issuer: string, nowMillis: number): Dict[] {
    const access: StringMap = { mode: this.operations.size === 0 ? "read-only" : "read-only,invoke",
      query: DATA_QUERY_CAPABILITY };
    if (this.operations.size > 0) {
      access["invoke"] = ASSET_INVOKE_CAPABILITY;
      access["invoke-ops"] = [...this.operations.keys()].join(",");
    }
    return [assetCard(group, issuer, nowMillis, this.ttlIso, this.asset, this.uri, this.description, this.shape,
      this.freshness, { rows: String(this.rows.length) }, access)];
  }

  query(asset: string, parameters: StringMap): QueryResult {
    if (asset !== this.asset) {
      return queryFailed(`no asset named '${asset}'`);
    }
    this.executions += 1;
    const limit = parameters["limit"] === undefined ? Number.MAX_SAFE_INTEGER : Number(parameters["limit"]);
    const matched: StringMap[] = [];
    for (const row of this.rows) {
      const matches = Object.entries(parameters).every(([column, value]) => column === "limit" || row[column] === value);
      if (matches) {
        matched.push(row);
        if (matched.length >= limit) {
          break;
        }
      }
    }
    return queryResult(matched);
  }

  async invoke(asset: string, operation: string, params: StringMap, invocationId: string): Promise<InvokeResult> {
    const fn = this.operations.get(operation);
    if (asset !== this.asset || fn === undefined) {
      return invokeFailed("unknown-operation", "provider", `no operation '${operation}' on asset '${asset}'`);
    }
    this.invocations += 1;
    return invokeResult(await fn(params, invocationId));
  }
}
