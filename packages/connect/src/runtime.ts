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
 * Runs one connector (srad/agentspaces-js.md JS-C-01 to JS-C-03, JS-C-07;
 * the port of `ConnectorRuntime.java`): publishes the provider's AssetCards
 * on the `ads` stream under leases refreshed at half their TTL, serves the
 * `aspace:cap/data-query` protocol from the data space with pull-once
 * semantics (a live result this connector issued for the same canonical hash
 * costs the source nothing), writes a materializing provider's changes as
 * `AssetChange` entries leased for the asset's freshness window, and serves
 * `aspace:cap/asset-invoke`: an invocation is taken under the claim lattice
 * with a lease, run only when the card's `invoke-ops` lists the operation
 * (and, under an authorizer, only when the requester holds
 * `aspace:connector-invoke:<asset>:<operation>`), its result written, and
 * the take completed.
 *
 * Every bound here is a per-message size or a per-source retention exposed
 * as an option; nothing caps the fleet.
 */

import { Peer, Space, Taken, Template, cbor, durationMillis, eq, oneOf, parseDurationMillis, toPayload } from "@agentspaces/client";
import type { wire } from "@agentspaces/client";
import { Authorizer, invokeScope, scopeName } from "./authorizer.js";
import { AssetChange, AssetInvocation, AssetInvocationResult, DataQuery, DataResult, InvokeError, StringMap,
  canonicalHash } from "./entries.js";
import { AssetProvider, Change, InvokeResult, accessList, isMaterializing } from "./provider.js";

type Dict = wire.Dict;

/** The AssetCard advertisement type on the `ads` stream (`AdCache.AD_TYPES`). */
export const ASSET_CARD_TYPE = "AssetCard";

/** The conventional name of the space queries, results, and changes flow through (`DataSpaces.DEFAULT_NAME`). */
export const DEFAULT_DATA_SPACE = "data";

/**
 * The inline payload limit of a Java `EntryRecord` (SPEC §7.1): a result
 * above it travels content-addressed in Java. The TypeScript core carries no
 * block exchange yet, so a result above `maxInlineResultBytes` is answered
 * with an error naming the limit rather than written into a record Java
 * replicas would refuse; an all-TypeScript fleet may raise the option up to
 * the frame cap.
 */
export const INLINE_PAYLOAD_LIMIT = 64 * 1024;

export type ConnectorOptions = {
  /** The connector's agent name, stamped into results as `servedBy` and the holder of its takes. */
  connectorName: string;
  /** The space queries and results flow through; default `data`. */
  dataSpace?: string;
  /** The space materialized changes are pushed into; default the data space. */
  changeSpace?: string;
  /** The space invocations and their results flow through; default the data space. */
  taskSpace?: string;
  /** The result and change lease when a card declares no parseable freshness window; default 1 minute. */
  defaultFreshness?: number | string;
  /** The take lease on a query; default 1 minute. */
  queryLease?: number | string;
  /** The take lease on an invocation (appendix F: 30 s); default 30 seconds. */
  invokeLease?: number | string;
  /** How long each take waits before the loop checks for a stop; default 1 second. */
  pollTimeout?: number | string;
  /** The lease on an error result; default 30 seconds. */
  errorLease?: number | string;
  /** The largest result payload written inline; default the Java inline limit (64 KiB). */
  maxInlineResultBytes?: number;
  /** How long an answered invocation's result is remembered for a retry with the same id; default 24 hours. */
  invocationRetention?: number | string;
  /** The fleet's authorizer (JS-C-02); none advertises and runs everything. */
  authorizer?: Authorizer | null;
  /** Where warnings go; default silent. */
  log?: (line: string) => void;
};

/** One remembered answer, so a retried invocation (same id) never re-runs the target here. */
type Answered = { result: AssetInvocationResult; at: number };

export class ConnectorRuntime {
  /** How many queries this connector executed against its source. */
  executed = 0;
  /** How many queries a live space result answered with no source execution. */
  servedFromSpace = 0;
  /** How many source changes this connector materialized into the change space. */
  materialized = 0;
  /** How many invocations ran against the provider. */
  invoked = 0;
  /** How many invocations were answered with an error result without running. */
  refused = 0;
  /** How many retried invocations were answered from the remembered result. */
  repeated = 0;

  readonly data: Space;
  readonly changes: Space;
  readonly tasks: Space;
  private readonly freshnessByAsset = new Map<string, number>();
  private readonly invokeOpsByAsset = new Map<string, Set<string>>();
  private readonly answered = new Map<string, Answered>();
  private readonly connectorName: string;
  private readonly defaultFreshness: number;
  private readonly queryLease: number;
  private readonly invokeLease: number;
  private readonly pollTimeout: number;
  private readonly errorLease: number;
  private readonly maxInlineResultBytes: number;
  private readonly invocationRetention: number;
  private readonly log: (line: string) => void;
  private gate: Authorizer | null;
  private running = false;
  private loops: Promise<void>[] = [];
  private refresher: { stop(): void } | null = null;
  private feed: { close(): void } | null = null;

  constructor(readonly peer: Peer, readonly provider: AssetProvider, options: ConnectorOptions) {
    this.connectorName = options.connectorName;
    const dataSpace = options.dataSpace ?? DEFAULT_DATA_SPACE;
    this.data = new Space(peer, dataSpace, null, this.connectorName);
    this.changes = options.changeSpace === undefined || options.changeSpace === dataSpace
      ? this.data : new Space(peer, options.changeSpace, null, this.connectorName);
    this.tasks = options.taskSpace === undefined || options.taskSpace === dataSpace
      ? this.data : new Space(peer, options.taskSpace, null, this.connectorName);
    this.defaultFreshness = durationMillis(options.defaultFreshness ?? "1m");
    this.queryLease = durationMillis(options.queryLease ?? "1m");
    this.invokeLease = durationMillis(options.invokeLease ?? "30s");
    this.pollTimeout = durationMillis(options.pollTimeout ?? "1s");
    this.errorLease = durationMillis(options.errorLease ?? "30s");
    this.maxInlineResultBytes = options.maxInlineResultBytes ?? INLINE_PAYLOAD_LIMIT;
    this.invocationRetention = durationMillis(options.invocationRetention ?? "24h");
    this.gate = options.authorizer ?? null;
    this.log = options.log ?? (() => undefined);
  }

  /**
   * Gives the runtime the fleet's authorizer (JS-C-02): from then on a card
   * is published only for an asset this connector's own peer is permitted
   * `CONNECTOR_SERVE` for, and an operation runs only for a requester
   * permitted `CONNECTOR_INVOKE` in `<asset>:<operation>`.
   */
  authorizer(authorizer: Authorizer): this {
    this.gate = authorizer;
    return this;
  }

  /** The assets currently advertised. */
  assets(): string[] {
    return [...this.freshnessByAsset.keys()];
  }

  /**
   * Publishes the current AssetCards, starts serving queries and
   * invocations, starts the card refresh at half the TTL, and, for a
   * materializing provider, starts the change feed.
   */
  start(): void {
    if (this.running) {
      return;
    }
    this.running = true;
    for (const space of new Set([this.data, this.changes, this.tasks])) {
      this.peer.pullSpace(space.name);
    }
    const cards = this.refreshCards();
    // The lease is the liveness contract (SPEC §6.1a): refresh at half the shortest TTL published.
    let ttl = Number.MAX_SAFE_INTEGER;
    for (const card of cards) {
      ttl = Math.min(ttl, this.parseFreshness(String(card["ttl"])));
    }
    if (ttl < Number.MAX_SAFE_INTEGER) {
      this.refresher = this.peer.every(Math.max(1, Math.floor(ttl / 2)), () => this.refreshCards());
    }
    this.loops = [this.serveQueries(), this.serveInvocations()];
    if (isMaterializing(this.provider)) {
      this.feed = this.provider.materialize((change) => this.push(change));
    }
  }

  /**
   * Re-publishes the provider's AssetCards with fresh issue times (SPEC
   * §6.1a: the lease is the liveness contract). Returns the cards published;
   * under an authorizer, an asset the connector's own peer may not serve is
   * left out and logged.
   */
  refreshCards(): Dict[] {
    const published: Dict[] = [];
    for (const card of this.provider.describeAssets(this.peer.group, this.peer.identity.peerId, this.peer.now())) {
      const asset = String(card["asset"]);
      if (this.gate !== null && !this.gate.permits(this.peer.identity.peerId, "CONNECTOR_SERVE", asset)) {
        this.log(`connector ${this.connectorName} is not permitted ${scopeName("CONNECTOR_SERVE", asset)}; not advertising it`);
        continue;
      }
      this.freshnessByAsset.set(asset, this.parseFreshness(String(card["freshness"])));
      this.invokeOpsByAsset.set(asset, new Set(accessList(card, "invoke-ops")));
      this.peer.publishAd(ASSET_CARD_TYPE, card);
      published.push(card);
    }
    return published;
  }

  /** Stops the loops, the refresh, and the change feed; resolves once the loops have returned. */
  async close(): Promise<void> {
    this.running = false;
    this.refresher?.stop();
    this.refresher = null;
    this.feed?.close();
    this.feed = null;
    await Promise.all(this.loops);
    this.loops = [];
  }

  // ---------------------------------------------------------------- queries

  private async serveQueries(): Promise<void> {
    while (this.running) {
      const assets = this.assets();
      if (assets.length === 0) {
        await sleep(this.pollTimeout);
        continue;
      }
      let taken: Taken<Dict> | null;
      try {
        // Only the queries for assets this connector advertises: several connectors may share
        // one data space, and a take of every DataQuery would let one claim, and fail, the other's.
        taken = await this.data.take(new Template<Dict>(DataQuery.schema, { asset: oneOf(...assets) }),
          this.queryLease, this.pollTimeout);
      } catch (e) {
        if (this.running) {
          this.log(`query take failed: ${String(e)}`);
        }
        continue;
      }
      if (taken !== null) {
        await this.answer(taken);
      }
    }
  }

  private async answer(taken: Taken<Dict>): Promise<void> {
    const query = DataQuery.from(taken.value);
    // ASF-009: the asker's queryHash is untrusted input. Recompute the canonical hash for the
    // dedupe check and the stored result, so a client-chosen hash can neither transplant a
    // result nor pre-poison the hash honest askers will compute.
    const hash = canonicalHash(query.asset, query.parameters);
    if (hash !== query.queryHash) {
      this.log(`dropping query with forged hash for asset ${query.asset}`);
      this.completeQuietly(taken);
      return;
    }
    const freshness = this.freshnessByAsset.get(query.asset) ?? this.defaultFreshness;
    try {
      // Pull once: a live result for this hash already serves the window, but only a result this
      // connector itself issued counts; another peer's never suppresses execution against the source.
      if (this.ownResult(this.data, DataResult.schema, "queryHash", hash) !== null) {
        this.servedFromSpace += 1;
        taken.complete();
        return;
      }
      const answered = await this.provider.query(query.asset, query.parameters);
      this.executed += 1;
      let result = new DataResult(hash, query.asset, answered.rows, answered.error, this.connectorName);
      const size = cbor.dumps(toPayload(result)).length;
      if (size > this.maxInlineResultBytes) {
        // The block path (SPEC §6.1a) is pending in the TypeScript core; name the limit instead.
        result = new DataResult(hash, query.asset, [],
          `result of ${size} bytes exceeds the ${this.maxInlineResultBytes}-byte inline limit (maxInlineResultBytes)`,
          this.connectorName);
      }
      taken.complete(result, freshness);
    } catch (e) {
      this.log(`query failed for asset ${query.asset}: ${String(e)}`);
      try {
        taken.complete(new DataResult(hash, query.asset, [], String(e instanceof Error ? e.message : e),
          this.connectorName), this.errorLease);
      } catch {
        // The take lease lapsed; the query reappears for a retry.
      }
    }
  }

  // ------------------------------------------------------------ invocations

  private async serveInvocations(): Promise<void> {
    while (this.running) {
      const assets = this.assets();
      if (assets.length === 0) {
        await sleep(this.pollTimeout);
        continue;
      }
      let taken: Taken<Dict> | null;
      try {
        taken = await this.tasks.take(new Template<Dict>(AssetInvocation.schema, { asset: oneOf(...assets) }),
          this.invokeLease, this.pollTimeout);
      } catch (e) {
        if (this.running) {
          this.log(`invocation take failed: ${String(e)}`);
        }
        continue;
      }
      if (taken !== null) {
        await this.handle(taken);
      }
    }
  }

  /**
   * One invocation under the claim lattice (JS-C-03): refused with an error
   * result naming the rule when the operation is absent from the card's
   * `invoke-ops` (JS-C-07) or the requester lacks the invoke scope
   * (JS-C-02); otherwise run once, its result remembered so a retry with
   * the same id is answered without a second run; the result written, then
   * the take completed.
   */
  private async handle(taken: Taken<Dict>): Promise<void> {
    const invocation = AssetInvocation.from(taken.value);
    const id = invocation.invocationId;
    const remembered = this.answered.get(id);
    if (remembered !== undefined) {
      this.repeated += 1;
      // The earlier result still serves the window: complete the retry under it. Otherwise
      // write the remembered result again; the target never runs twice here.
      if (this.ownResult(this.tasks, AssetInvocationResult.schema, "invocationId", id) !== null) {
        this.completeQuietly(taken);
      } else {
        this.finish(taken, remembered.result);
      }
      return;
    }
    const requester = this.requesterOf(id);
    const allowed = this.invokeOpsByAsset.get(invocation.asset) ?? new Set<string>();
    let result: AssetInvocationResult;
    if (!allowed.has(invocation.operation)) {
      this.refused += 1;
      result = AssetInvocationResult.refused(invocation, "unknown-operation", "invoke-ops",
        `operation '${invocation.operation}' is not in the invoke-ops of asset '${invocation.asset}'`
        + ` (${[...allowed].join(",") || "none"})`);
    } else if (this.gate !== null
        && (requester === null || !this.gate.permits(requester, "CONNECTOR_INVOKE",
          invokeScope(invocation.asset, invocation.operation)))) {
      this.refused += 1;
      result = AssetInvocationResult.refused(invocation, "refused-scope",
        scopeName("CONNECTOR_INVOKE", invokeScope(invocation.asset, invocation.operation)),
        `requester ${requester ?? "unknown"} is not permitted to invoke '${invocation.operation}' on '${invocation.asset}'`);
    } else {
      result = await this.run(invocation);
    }
    this.remember(id, result);
    this.finish(taken, result);
  }

  private async run(invocation: AssetInvocation): Promise<AssetInvocationResult> {
    let outcome: InvokeResult;
    try {
      if (this.provider.invoke === undefined) {
        outcome = { ok: false, error: "unknown-operation", result: { rule: "provider",
          detail: `the provider of '${invocation.asset}' exposes no operations` } };
      } else {
        this.invoked += 1;
        outcome = await this.provider.invoke(invocation.asset, invocation.operation, invocation.params,
          invocation.invocationId);
      }
    } catch (e) {
      this.log(`operation ${invocation.operation} on ${invocation.asset} failed: ${String(e)}`);
      outcome = { ok: false, error: "target-error", result: { rule: "target",
        detail: String(e instanceof Error ? e.message : e) } };
    }
    return new AssetInvocationResult(invocation.invocationId, invocation.asset, invocation.operation, outcome.ok,
      outcome.result, outcome.ok ? null : (outcome.error ?? "target-error" as InvokeError));
  }

  /** Writes the result (leased for the asset's freshness window, or the error lease) and completes the take. */
  private finish(taken: Taken<Dict>, result: AssetInvocationResult): void {
    const lease = result.ok ? this.freshnessByAsset.get(result.asset) ?? this.defaultFreshness : this.errorLease;
    try {
      taken.complete(result, lease);
    } catch (e) {
      this.log(`completing invocation ${result.invocationId} failed: ${String(e)}`);
    }
  }

  /** The peer that wrote the invocation entry, read from the taken record's issuer. */
  private requesterOf(invocationId: string): string | null {
    const found = this.tasks.entries(new Template<Dict>(AssetInvocation.schema, { invocationId: eq(invocationId) }), 1, true);
    if (found.length === 0) {
      return null;
    }
    const issuer = found[0]!.issuer;
    const slash = issuer.indexOf("/");
    return slash < 0 ? issuer : issuer.slice(0, slash);
  }

  private remember(id: string, result: AssetInvocationResult): void {
    const now = this.peer.now();
    for (const [key, entry] of this.answered) {
      if (now - entry.at > this.invocationRetention) {
        this.answered.delete(key);
      }
    }
    this.answered.set(id, { result, at: now });
  }

  // ---------------------------------------------------------------- changes

  /**
   * SPEC §6.1a, the materializing style: one source change becomes one typed
   * entry whose lease is the asset's freshness window, so retention is the
   * lease and a connector that stops pushing leaves nothing stale behind.
   */
  private push(change: Change): void {
    if (!this.running) {
      return;
    }
    const freshness = this.freshnessByAsset.get(change.asset) ?? this.defaultFreshness;
    try {
      this.changes.write(new AssetChange(change.asset, change.key, change.row, this.connectorName), freshness);
      this.materialized += 1;
    } catch (e) {
      this.log(`materializing change ${change.key} of asset ${change.asset} failed: ${String(e)}`);
    }
  }

  // -------------------------------------------------------------- internals

  /** A live entry of `schema` with `field == value` that this connector's own peer issued, or null. */
  private ownResult(space: Space, schema: string, field: string, value: string): Dict | null {
    const prefix = `${this.peer.identity.peerId}/`;
    for (const entry of space.entries(new Template<Dict>(schema, { [field]: eq(value) }), 16, true)) {
      if (entry.issuer.startsWith(prefix)) {
        return entry.value;
      }
    }
    return null;
  }

  private completeQuietly(taken: Taken<Dict>): void {
    try {
      taken.complete();
    } catch {
      // The take lease lapsed; nothing to do.
    }
  }

  private parseFreshness(freshness: string): number {
    try {
      const millis = parseDurationMillis(freshness);
      return Number.isFinite(millis) && millis > 0 ? millis : this.defaultFreshness;
    } catch {
      return this.defaultFreshness;
    }
  }
}

function sleep(millis: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, millis));
}
