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
 * The agent side (srad/agentspaces-js.md JS-C-01, JS-C-10): `DataQueryClient`
 * fetches data by asset name and parameters, local-first (a live result
 * under the same canonical hash answers at once and costs the source
 * nothing), and `invoke` runs one operation on an asset through
 * `aspace:cap/asset-invoke`, resolving with the connector's result. Both
 * trust a result only from the peers the caller names or the authorizer
 * permits (ASF-009): a result forged by any other admitted peer is ignored.
 */

import { Peer, Space, Template, WRITTEN, durationMillis, eq } from "@agentspaces/client";
import type { AgentIdentity, wire } from "@agentspaces/client";
import { bytes } from "@agentspaces/client";
import type { Authorizer } from "./authorizer.js";
import { AssetInvocation, AssetInvocationResult, DataQuery, DataResult, StringMap, canonicalHash } from "./entries.js";
import { ASSET_CARD_TYPE, DEFAULT_DATA_SPACE } from "./runtime.js";

type Dict = wire.Dict;

/** One fetch's answer (`DataQueryClient.Fetched`): the result and whether a live space result answered it. */
export type Fetched = { result: DataResult; fromCache: boolean };

export type DataQueryClientOptions = {
  /** The asking agent's name, stamped into queries. */
  requester: string;
  /** The space queries and results flow through; default `data`. */
  dataSpace?: string;
  /** Connector peers whose results to accept; empty accepts any peer's result. */
  trustedConnectors?: Iterable<string>;
  /** Trust a result only from a peer permitted `CONNECTOR_SERVE` for its asset. */
  authorizer?: Authorizer | null;
  /** The lease on a written query; default 1 minute. */
  queryLease?: number | string;
  /** How often the wait re-reads the space between folds; default 100 ms. */
  readThroughMillis?: number;
  /** The agent the queries are written as (v0.1.13); default the peer-signed `requester`. */
  agent?: AgentIdentity | null;
};

/** The peer id of an issuer agent id (`<peer>/<name>`). */
function peerOf(issuer: string): string {
  const slash = issuer.indexOf("/");
  return slash < 0 ? issuer : issuer.slice(0, slash);
}

/** Whether a result written by `issuer` for `asset` is trusted. */
type Trust = (issuerPeer: string, asset: string) => boolean;

function trustOf(trusted: Set<string>, authorizer: Authorizer | null): Trust {
  if (authorizer !== null) {
    return (peer, asset) => authorizer.permits(peer, "CONNECTOR_SERVE", asset);
  }
  return (peer) => trusted.size === 0 || trusted.has(peer);
}

/** The `DataQueryClient` of Java: fetch by asset and parameters, pull-once by canonical hash. */
export class DataQueryClient {
  /** Fetches answered by a live space result, with no source execution. */
  cacheHits = 0;
  /** Fetches that wrote a query entry for a connector to execute. */
  queriesSent = 0;
  readonly space: Space;
  private readonly requester: string;
  private readonly trust: Trust;
  private readonly queryLease: number;
  private readonly readThroughMillis: number;

  constructor(readonly peer: Peer, options: DataQueryClientOptions) {
    this.requester = options.requester;
    this.space = new Space(peer, options.dataSpace ?? DEFAULT_DATA_SPACE, options.agent ?? null, options.requester);
    this.trust = trustOf(new Set(options.trustedConnectors ?? []), options.authorizer ?? null);
    this.queryLease = durationMillis(options.queryLease ?? "1m");
    this.readThroughMillis = options.readThroughMillis ?? 100;
    peer.pullSpace(this.space.name);
  }

  /**
   * Fetches one asset query, pull-once: a trusted live result for the
   * canonical hash answers at once; otherwise a query is written and the
   * connector's result awaited. Null when no connector answered in time.
   */
  async fetch(asset: string, parameters: StringMap, timeout: number | string = "30s"): Promise<Fetched | null> {
    const hash = canonicalHash(asset, parameters);
    const template = new Template<Dict>(DataResult.schema, { queryHash: eq(hash) });
    const live = this.readTrusted(template);
    if (live !== null) {
      this.cacheHits += 1;
      return { result: live, fromCache: true };
    }
    // Subscribe before writing the query so the answer cannot slip between the write and the
    // wait; the listener applies the same issuer filter.
    let resolve!: (result: DataResult) => void;
    const answer = new Promise<DataResult>((r) => { resolve = r; });
    const subscription = this.space.watch(template, (event) => {
      if (event.kind === WRITTEN && this.trust(peerOf(event.entry.issuer), asset)) {
        resolve(DataResult.from(event.entry.value));
      }
    });
    try {
      this.queriesSent += 1;
      this.space.write(new DataQuery(hash, asset, parameters, this.requester), this.queryLease);
      const result = await this.await(answer, template, durationMillis(timeout));
      return result === null ? null : { result, fromCache: false };
    } finally {
      subscription.close();
    }
  }

  /** Waits for the subscription, re-reading the space between checks (pulling it, so a late fold arrives). */
  private async await(answer: Promise<DataResult>, template: Template<Dict>, timeoutMillis: number): Promise<DataResult | null> {
    const deadline = Date.now() + timeoutMillis;
    while (true) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        return null;
      }
      const slice = Math.min(remaining, this.readThroughMillis);
      const result = await Promise.race([answer, new Promise<null>((r) => setTimeout(() => r(null), slice))]);
      if (result !== null) {
        return result;
      }
      const read = this.readTrusted(template);
      if (read !== null) {
        return read;
      }
      this.peer.pullSpace(this.space.name);
    }
  }

  private readTrusted(template: Template<Dict>): DataResult | null {
    for (const entry of this.space.entries(template, 16, true)) {
      const result = DataResult.from(entry.value);
      if (this.trust(peerOf(entry.issuer), result.asset)) {
        return result;
      }
    }
    return null;
  }
}

/** The live AssetCards the ads stream carried, optionally only those of one asset. */
export function assetCards(peer: Peer, asset: string | null = null): Dict[] {
  const now = peer.now();
  return [...peer.ads.values()]
    .filter((e) => e.type === ASSET_CARD_TYPE && e.expires > now && (asset === null || e.ad["asset"] === asset))
    .map((e) => e.ad);
}

export type InvokeOptions = {
  /** How long to wait for the connector's result; default 30 s. */
  timeoutMillis?: number;
  /** The lease on the invocation entry; default 5 minutes. */
  lease?: number | string;
  /** The invocation id; default a fresh UUID. Pass the earlier id to retry an invocation. */
  invocationId?: string;
  /** How often the wait re-reads the space between folds; default 100 ms. */
  readThroughMillis?: number;
};

/**
 * `AssetInvocations.invoke` (JS-C-10): writes an `AssetInvocation` for the
 * card's asset into `space` and resolves with the `AssetInvocationResult`
 * the card's issuer writes for it, or null at the timeout. The invocation
 * id is minted here and carried in the entry, so a retry (`invocationId`
 * in the options) reaches the target under the same id (JS-C-04).
 */
export async function invoke(space: Space, card: Dict, operation: string, params: StringMap,
                             options: InvokeOptions = {}): Promise<AssetInvocationResult | null> {
  const asset = String(card["asset"]);
  const issuer = String(card["issuer"]);
  const invocationId = options.invocationId ?? bytes.randomUuid();
  const template = new Template<Dict>(AssetInvocationResult.schema, { invocationId: eq(invocationId) });
  const readThrough = options.readThroughMillis ?? 100;
  const fromIssuer = (): AssetInvocationResult | null => {
    for (const entry of space.entries(template, 16, true)) {
      if (peerOf(entry.issuer) === issuer) {
        return AssetInvocationResult.from(entry.value);
      }
    }
    return null;
  };
  let resolve!: (result: AssetInvocationResult) => void;
  const answer = new Promise<AssetInvocationResult>((r) => { resolve = r; });
  const subscription = space.watch(template, (event) => {
    if (event.kind === WRITTEN && peerOf(event.entry.issuer) === issuer) {
      resolve(AssetInvocationResult.from(event.entry.value));
    }
  });
  try {
    space.write(new AssetInvocation(asset, operation, params, invocationId), options.lease ?? "5m");
    const deadline = Date.now() + (options.timeoutMillis ?? 30_000);
    while (true) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        return null;
      }
      const result = await Promise.race([answer,
        new Promise<null>((r) => setTimeout(() => r(null), Math.min(remaining, readThrough)))]);
      if (result !== null) {
        return result;
      }
      const read = fromIssuer();
      if (read !== null) {
        return read;
      }
      space.peer.pullSpace(space.name);
    }
  } finally {
    subscription.close();
  }
}
