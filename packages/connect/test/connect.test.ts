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
 * The connector runtime over in-memory peers (srad/agentspaces-js.md
 * JS-C-01, JS-C-02, JS-C-03, JS-C-07, JS-C-10, JS-F-06): a hub peer runs the
 * connector and dial-only members are the agents. Cards are published and
 * refreshed at half their TTL; a query is answered through the data space
 * and the second identical one from the space; materialized changes are
 * leased for the asset's freshness; an invocation is taken exactly once,
 * its result written and the take completed, and a retry under the same id
 * never runs the target again; an operation absent from `invoke-ops` is
 * refused and never run; under an authorizer the connector advertises only
 * what it may serve and invokes only for a requester holding the scope.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Identity, MemoryNetwork, Peer, Space, Template, eq, settle } from "@agentspaces/client";
import type { wire } from "@agentspaces/client";
import { AssetChange, AssetInvocation, AssetInvocationResult, ConnectorRuntime, DataQueryClient, TableAssetProvider,
  assetCards, invoke, scopeAuthorizer } from "../src/index.js";
import type { AssetProvider, Change, MaterializingAssetProvider, StringMap } from "../src/index.js";

type Dict = wire.Dict;
const GROUP = "zConnectGroup";
const sleep = (millis: number) => new Promise((resolve) => setTimeout(resolve, millis));

/** The reference table with one invoke operation, `reserve`, that records every run. */
function orders(freshness = "PT5M", ttl = "PT15M"): TableAssetProvider & { reserved: string[] } {
  const reserved: string[] = [];
  const provider = new TableAssetProvider("orders", "postgres://ops/public.orders",
    "Customer order history with line items and settlement status", "com.example.OrderRow#v1", freshness,
    [{ id: "1", region: "eu", amount: "120.00" }, { id: "2", region: "us", amount: "80.00" },
      { id: "3", region: "eu", amount: "45.50" }],
    { reserve: (params, invocationId) => { reserved.push(invocationId); return { reserved: params["qty"] ?? "0" }; } },
    ttl);
  return Object.assign(provider, { reserved });
}

/** A hub running the connector and `n` dial-only members pulling the data space and the ads. */
async function fleet(provider: AssetProvider, n: number, options: { authorizer?: ReturnType<typeof scopeAuthorizer> } = {}):
    Promise<{ hub: Peer; connector: ConnectorRuntime; members: Peer[]; stop: () => Promise<void> }> {
  const net = new MemoryNetwork();
  const hub = new Peer(Identity.generate(), GROUP);
  hub.endpoints.push({ transport: "mem", address: "hub:1", priority: 0 });
  const closeListener = await net.listen("hub:1", (channel) => hub.acceptChannel(channel));
  const connector = new ConnectorRuntime(hub, provider, { connectorName: "pg-connector", pollTimeout: 300,
    authorizer: options.authorizer ?? null });
  connector.start();
  const members: Peer[] = [];
  for (let i = 0; i < n; i++) {
    const member = new Peer(Identity.generate(), GROUP);
    member.registerDialer(net.dialer());
    await member.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    member.pullSpace("data");
    member.pullAds();
    members.push(member);
  }
  await settle(4);
  return { hub, connector, members,
    stop: async () => { await connector.close(); closeListener(); hub.close(); members.forEach((m) => m.close()); } };
}

/** Waits until `check` holds, settling the network between looks. */
async function until(check: () => boolean, maxMillis = 5_000): Promise<void> {
  const deadline = Date.now() + maxMillis;
  while (!check() && Date.now() < deadline) {
    await settle(2);
    await sleep(20);
  }
  assert.ok(check(), "the condition held in time");
}

/** The live results of one invocation id a peer's data space holds. */
function resultsFor(peer: Peer, invocationId: string): AssetInvocationResult[] {
  return new Space(peer, "data").readAll(new Template<Dict>(AssetInvocationResult.schema, { invocationId: eq(invocationId) }))
    .map(AssetInvocationResult.from);
}

test("cards are published on the ads stream and refreshed at half their TTL (JS-C-01)", async () => {
  const provider = orders("PT5M", "PT2S");
  const { hub, connector, members: [agent], stop } = await fleet(provider, 1);
  try {
    await until(() => assetCards(agent, "orders").length === 1);
    const card = assetCards(agent, "orders")[0]!;
    assert.equal(card["issuer"], hub.identity.peerId);
    assert.equal(card["id"], `aspace://${GROUP}/asset/orders`);
    assert.equal((card["access"] as StringMap)["query"], "aspace:cap/data-query");
    assert.equal((card["access"] as StringMap)["invoke-ops"], "reserve");
    assert.deepEqual(connector.assets(), ["orders"]);
    const first = String(card["issued"]);
    await sleep(1_300); // half of PT2S has passed: the refresh re-issued the card
    await until(() => String(assetCards(agent, "orders")[0]?.["issued"]) > first);
    assert.equal(assetCards(agent).length, 1, "the refresh replaced the card under the same id");
  } finally {
    await stop();
  }
});

test("a query is answered through the data space and an identical one from the space (JS-C-01, JS-C-10)", async () => {
  const provider = orders();
  const { members: [agent, other], connector, stop } = await fleet(provider, 2);
  try {
    const client = new DataQueryClient(agent, { requester: "analyst" });
    const fetched = await client.fetch("orders", { region: "eu" }, "15s");
    assert.ok(fetched !== null, "the connector answered");
    assert.equal(fetched.fromCache, false);
    assert.equal(fetched.result.servedBy, "pg-connector");
    assert.equal(fetched.result.error, null);
    assert.deepEqual(fetched.result.rows.map((r) => r["id"]), ["1", "3"]);
    assert.equal(provider.executions, 1);
    assert.equal(connector.executed, 1);
    // Another agent asks the same question, parameters in another order: a cache hit, no execution.
    const second = new DataQueryClient(other, { requester: "analyst-b" });
    await until(() => second.space.readAll(new Template<Dict>("ai.badmonkey.agentspaces.connect.DataQueryEntries$DataResult#v1")).length === 1);
    const again = await second.fetch("orders", { region: "eu" }, "15s");
    assert.equal(again?.fromCache, true);
    assert.equal(second.cacheHits, 1);
    assert.equal(provider.executions, 1);
    // A different question executes again.
    const us = await client.fetch("orders", { region: "us", limit: "1" }, "15s");
    assert.deepEqual(us?.result.rows, [{ amount: "80.00", id: "2", region: "us" }]);
    assert.equal(provider.executions, 2);
  } finally {
    await stop();
  }
});

test("a materializing provider's changes are leased for the asset's freshness (JS-C-01)", async () => {
  const table = orders("PT30S");
  const source: { sink: ((change: Change) => void) | null } = { sink: null };
  const feed: MaterializingAssetProvider = {
    describeAssets: (g, i, n) => table.describeAssets(g, i, n),
    query: (a, p) => table.query(a, p),
    materialize(s) { source.sink = s; return { close: () => { source.sink = null; } }; },
  };
  const { members: [agent], connector, stop } = await fleet(feed, 1);
  try {
    const sink = source.sink;
    assert.ok(sink !== null, "the runtime started the feed");
    const seen: AssetChange[] = [];
    const expiries: number[] = [];
    const space = new Space(agent, "data");
    const sub = space.notify(new Template<Dict>(AssetChange.schema, { asset: eq("orders") }), (event) => {
      if (event.kind === "WRITTEN") {
        seen.push(AssetChange.from(event.entry.value));
        expiries.push(event.entry.expiresAtMillis);
      }
    }, "5m");
    const before = Date.now();
    sink({ asset: "orders", key: "1", row: { id: "1", region: "eu", amount: "120.00" } });
    sink({ asset: "orders", key: "1", row: { id: "1", region: "eu", amount: "125.00" } });
    await until(() => seen.length === 2);
    sub.close();
    assert.equal(connector.materialized, 2);
    assert.deepEqual(seen.map((c) => c.key), ["1", "1"]);
    assert.equal(seen[1]!.row["amount"], "125.00");
    assert.equal(seen[1]!.servedBy, "pg-connector");
    for (const expires of expiries) {
      assert.ok(expires >= before + 30_000 - 5 && expires <= Date.now() + 30_000, "leased for PT30S, the asset's freshness");
    }
    await stop();
    assert.equal(source.sink, null, "close stopped the feed");
  } finally {
    await stop();
  }
});

test("an invocation is taken once, its result written, the take completed; a retry never runs the target again (JS-C-03)", async () => {
  const provider = orders();
  const { hub, members: [agent], connector, stop } = await fleet(provider, 1);
  try {
    await until(() => assetCards(agent, "orders").length === 1);
    const card = assetCards(agent, "orders")[0]!;
    const space = new Space(agent, "data", null, "planner");
    const result = await invoke(space, card, "reserve", { sku: "A-1", qty: "2" }, { timeoutMillis: 15_000 });
    assert.ok(result !== null, "the connector answered");
    assert.equal(result.ok, true);
    assert.equal(result.error, null);
    assert.deepEqual(result.result, { reserved: "2" });
    assert.equal(result.v, 1);
    assert.deepEqual(provider.reserved, [result.invocationId], "the target ran once, with the invocation id");
    assert.equal(connector.invoked, 1);
    // The take completed: the invocation is live nowhere, and the hub's replica marks it completed.
    await until(() => space.readAll(new Template<Dict>(AssetInvocation.schema)).length === 0);
    const taken = [...hub.states.values()].filter((dto) => (dto["record"] as Dict)["type"] === AssetInvocation.schema);
    assert.equal(taken.length, 1);
    assert.equal(taken[0]!["completed"], true);
    assert.equal(resultsFor(agent, result.invocationId).length, 1);
    // A forced retry under the same id: answered, the target not run again, still one result.
    const retry = await invoke(space, card, "reserve", { sku: "A-1", qty: "2" },
      { timeoutMillis: 15_000, invocationId: result.invocationId });
    assert.equal(retry?.ok, true);
    await until(() => connector.repeated === 1);
    assert.equal(provider.reserved.length, 1, "the retry never reached the target");
    assert.equal(resultsFor(agent, result.invocationId).length, 1, "one result per invocationId");
  } finally {
    await stop();
  }
});

test("an operation absent from the card's invoke-ops is answered with an error naming the rule and never run (JS-C-03, JS-C-07)", async () => {
  const provider = orders();
  const { members: [agent], connector, stop } = await fleet(provider, 1);
  try {
    await until(() => assetCards(agent, "orders").length === 1);
    const card = assetCards(agent, "orders")[0]!;
    const result = await invoke(new Space(agent, "data"), card, "drop", { table: "orders" }, { timeoutMillis: 15_000 });
    assert.ok(result !== null);
    assert.equal(result.ok, false);
    assert.equal(result.error, "unknown-operation");
    assert.equal(result.result["rule"], "invoke-ops");
    assert.match(result.result["detail"]!, /'drop' is not in the invoke-ops of asset 'orders' \(reserve\)/);
    assert.equal(connector.refused, 1);
    assert.equal(connector.invoked, 0);
    assert.deepEqual(provider.reserved, []);
  } finally {
    await stop();
  }
});

test("under an authorizer the connector advertises only what it may serve and invokes only for a requester holding the scope (JS-C-02)", async () => {
  const table = orders();
  const twoAssets: AssetProvider = {
    describeAssets: (g, i, n) => [...table.describeAssets(g, i, n),
      ...new TableAssetProvider("secrets", "vault://ops", "Credentials", "com.example.Secret#v1", "PT5M", []).describeAssets(g, i, n)],
    query: (a, p) => table.query(a, p),
    invoke: (a, o, p, id) => table.invoke(a, o, p, id),
  };
  const scopes = new Map<string, string[]>();
  const authorizer = scopeAuthorizer((peer) => scopes.get(peer));
  const net = new MemoryNetwork();
  const hub = new Peer(Identity.generate(), GROUP);
  hub.endpoints.push({ transport: "mem", address: "hub:1", priority: 0 });
  const closeListener = await net.listen("hub:1", (channel) => hub.acceptChannel(channel));
  scopes.set(hub.identity.peerId, ["aspace:connector-serve:orders"]); // not secrets
  const connector = new ConnectorRuntime(hub, twoAssets, { connectorName: "pg-connector", pollTimeout: 300 }).authorizer(authorizer);
  connector.start();
  const dial = async (): Promise<Peer> => {
    const member = new Peer(Identity.generate(), GROUP);
    member.registerDialer(net.dialer());
    await member.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    member.pullSpace("data");
    member.pullAds();
    return member;
  };
  const planner = await dial();
  const stranger = await dial();
  scopes.set(planner.identity.peerId, ["aspace:connector-invoke:orders:reserve"]);
  try {
    await settle(4);
    assert.deepEqual(connector.assets(), ["orders"], "the asset the connector may not serve is never advertised");
    await until(() => assetCards(planner).length === 1);
    assert.equal(assetCards(stranger, "secrets").length, 0);
    const card = assetCards(planner, "orders")[0]!;
    const granted = await invoke(new Space(planner, "data"), card, "reserve", { qty: "1" }, { timeoutMillis: 15_000 });
    assert.equal(granted?.ok, true);
    assert.equal(table.reserved.length, 1);
    const refused = await invoke(new Space(stranger, "data"), card, "reserve", { qty: "1" }, { timeoutMillis: 15_000 });
    assert.ok(refused !== null);
    assert.equal(refused.ok, false);
    assert.equal(refused.error, "refused-scope");
    assert.equal(refused.result["rule"], "aspace:connector-invoke:orders:reserve");
    assert.equal(table.reserved.length, 1, "the connector never touched the binding");
    assert.equal(connector.refused, 1);
    // The grant arrives: the next refresh advertises the second asset.
    scopes.set(hub.identity.peerId, ["aspace:connector-serve"]);
    connector.refreshCards();
    assert.deepEqual(connector.assets().sort(), ["orders", "secrets"]);
    await until(() => assetCards(stranger, "secrets").length === 1);
  } finally {
    await connector.close();
    closeListener();
    hub.close();
    planner.close();
    stranger.close();
  }
});

test("a receiver ignores fields it does not know on the asset-invoke entries (JS-F-06)", () => {
  const invocation = AssetInvocation.from({ v: 2, asset: "orders", operation: "reserve", params: { qty: "1" },
    invocationId: "id-1", idempotency: "once", schema: { qty: "int" } });
  assert.deepEqual(Object.keys(invocation), ["v", "asset", "operation", "params", "invocationId"]);
  assert.equal(invocation.v, 2);
  const result = AssetInvocationResult.from({ v: 1, invocationId: "id-1", asset: "orders", operation: "reserve", ok: true,
    result: { reserved: "1" }, error: null, cost: "3" });
  assert.deepEqual(Object.keys(result), ["v", "invocationId", "asset", "operation", "ok", "result", "error"]);
  assert.equal(result.ok, true);
});
