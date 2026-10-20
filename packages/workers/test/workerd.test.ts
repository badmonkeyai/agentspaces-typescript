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
 * The worked demonstration on workerd (srad/agentspaces-js.md JS-C-12,
 * JS-R-05, JS-R-03, JS-R-07, JS-C-05, JS-C-07, JS-C-08, JS-S-06, JS-S-07):
 * a `ServiceHost` hub over `ws` in this process; the example Worker
 * (`example/src/index.ts`, bundled) under workerd with the `Inventory`
 * Durable Object and the `Fleet` connector cell dialing the hub; a
 * TypeScript client discovering the AssetCards, querying the stock, and
 * invoking `reserveStock` exactly once under a forced retry (the same
 * invocation id twice: one run, two identical results), then again after
 * workerd restarts (the connector's memory gone, the object's `once` table
 * not: still one run). A refused operation and a refused parameter name
 * their rules. The cell pauses and resumes under the same identity.
 * Skipped when workerd or esbuild is missing unless
 * AGENTSPACES_RUNTIMES_REQUIRED=1.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Identity, Peer, Space, Template, eq } from "@agentspaces/client";
import type { wire } from "@agentspaces/client";
import { AssetInvocationResult, DataQueryClient, assetCards, invoke } from "@agentspaces/connect";
import type { StringMap } from "@agentspaces/connect";
import { ServiceHost } from "@agentspaces/node";
import { bundleExample, startWorkerd, toolsPresent } from "./workers/workerd-run.js";
import type { WorkerdRun } from "./workers/workerd-run.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

type Dict = wire.Dict;
const GROUP = "zWorkersCellGroup";

/** The agent cell's entries as the client sees them (the example declares the classes). */
class DamageReport {
  static schema = "aspace:DamageReport#v1";
  constructor(readonly claimId: string, readonly photos: number) {}
}
class DamageEstimate {
  static schema = "aspace:DamageEstimate#v1";
  constructor(readonly claimId: string, readonly estimate: string, readonly by: string) {}
  static from(payload: Dict): DamageEstimate {
    return new DamageEstimate(String(payload["claimId"]), String(payload["estimate"]), String(payload["by"]));
  }
}
const REQUIRED = process.env.AGENTSPACES_RUNTIMES_REQUIRED === "1";
const sleep = (millis: number) => new Promise((resolve) => setTimeout(resolve, millis));

async function until(check: () => boolean, maxMillis = 15_000, what = "the condition held in time"): Promise<void> {
  const deadline = Date.now() + maxMillis;
  while (!check() && Date.now() < deadline) {
    await sleep(50);
  }
  assert.ok(check(), what);
}

/** The hub: a service host with a `ws` listener, serving the data space. */
async function hub(): Promise<{ host: ServiceHost; port: number }> {
  const host = new ServiceHost(Identity.generate(), GROUP, { listeners: [{ scheme: "ws", bind: "127.0.0.1:0" }],
    spaces: ["data", "claims"], log: null });
  await host.start();
  const address = host.addresses.get("ws")!;
  return { host, port: Number(address.substring(address.lastIndexOf(":") + 1)) };
}

/** A dial-only TypeScript client of the hub, pulling the ads and the data space. */
async function client(port: number): Promise<Peer> {
  const peer = new Peer(Identity.generate(), GROUP);
  await peer.connectAny([{ host: "127.0.0.1", port, scheme: "ws" }]);
  peer.pullAds();
  peer.pullSpace("data");
  peer.pullSpace("claims");
  return peer;
}

test("the inventory cell on workerd: discovered, queried, reserved exactly once under a retry and a restart (JS-C-12)", async (t) => {
  const missing = toolsPresent();
  if (missing !== null) {
    if (REQUIRED) {
      throw new Error(missing);
    }
    t.skip(missing);
    return;
  }
  const { host, port } = await hub();
  const dir = mkdtempSync(join(tmpdir(), "aspace-workers-"));
  await bundleExample(dir);
  let workerd: WorkerdRun = await startWorkerd({ group: GROUP, seeds: `ws://127.0.0.1:${port}/aspace`, profile: "dev-local" }, { dir });
  const agent = await client(port);
  try {
    // The demonstration's fixture: ten of A-100 in warehouse-7.
    await workerd.get("/stock?object=warehouse-7&sku=A-100&qty=10");
    const woke = await workerd.get("/wake") as Record<string, unknown>;
    assert.equal(woke["connected"], true, `the cell dialed the hub (${workerd.output()})`);
    assert.equal(woke["residency"], "cell");
    const cellId = String(woke["peerId"]);
    assert.ok(cellId.startsWith("z"), "a PeerID");

    // JS-R-07: the hub sees js.residency=cell in the cell's advertisement.
    await until(() => host.peer.members.get(cellId)?.["resourceHints"] !== undefined, 15_000, "the hub heard the cell's advertisement");
    assert.equal((host.peer.members.get(cellId)!["resourceHints"] as StringMap)["js.residency"], "cell");

    // JS-C-05, JS-C-08: the class card and the two listed instance cards, ids <application>:<asset>, no AgentCard.
    await until(() => assetCards(agent).length >= 3, 20_000, `the client saw the cards (${workerd.output()})`);
    const cards = assetCards(agent);
    const byAsset = new Map(cards.map((c) => [String(c["asset"]), c]));
    const classCard = byAsset.get("do/Inventory")!;
    assert.ok(classCard !== undefined, "the class card");
    assert.equal(classCard["id"], "inventory:do/Inventory");
    assert.equal(classCard["uri"], "workers://inventory/do/Inventory");
    assert.equal(classCard["issuer"], cellId);
    assert.equal(classCard["freshness"], "PT30S");
    assert.equal(classCard["ttl"], "PT60S");
    const access = classCard["access"] as StringMap;
    assert.equal(access["mode"], "read-only,invoke");
    assert.equal(access["query"], "aspace:cap/data-query");
    assert.equal(access["invoke"], "aspace:cap/asset-invoke");
    assert.equal(access["read-ops"], "getInventory");
    assert.equal(access["invoke-ops"], "reserveStock,releaseStock");
    assert.equal(access["consistency"], "single-writer");
    assert.equal(access["object-param"], "object");
    assert.equal(access["runtime"], "workerd");
    assert.equal(access["connector"], "cell");
    assert.equal((classCard["costHints"] as StringMap)["objects"], "2");
    assert.equal(byAsset.get("do/Inventory/warehouse-7")!["uri"], "workers://inventory/do/Inventory/warehouse-7");
    assert.equal((byAsset.get("do/Inventory/warehouse-7")!["access"] as StringMap)["object"], "warehouse-7");
    assert.deepEqual(agent.cards().filter((c) => c["issuer"] === cellId), [], "the connector publishes no AgentCard");

    // The read through aspace:cap/data-query: the current stock of warehouse-7.
    const queries = new DataQueryClient(agent, { requester: "planner" });
    const stock = await queries.fetch("do/Inventory", { op: "getInventory", object: "warehouse-7" }, "20s");
    assert.ok(stock !== null, `the connector answered the query (${workerd.output()})`);
    assert.equal(stock.result.error, null);
    assert.deepEqual(stock.result.rows, [{ sku: "A-100", qty: "10" }]);
    assert.equal(stock.result.servedBy, "connector");

    // The operation, under a forced retry: the same invocation id twice, one run, two identical results.
    const space = new Space(agent, "data", null, "planner");
    const first = await invoke(space, classCard, "reserveStock", { object: "warehouse-7", sku: "A-100", qty: "3" },
      { timeoutMillis: 20_000 });
    assert.ok(first !== null, `the connector answered the invocation (${workerd.output()})`);
    assert.equal(first.ok, true, JSON.stringify(first));
    assert.deepEqual(first.result, { sku: "A-100", reserved: "3", remaining: "7" });
    const retry = await invoke(space, classCard, "reserveStock", { object: "warehouse-7", sku: "A-100", qty: "3" },
      { timeoutMillis: 20_000, invocationId: first.invocationId });
    assert.ok(retry !== null, "the retry was answered");
    assert.deepEqual(retry.result, first.result, "the retry's result is the first's");
    assert.equal(retry.invocationId, first.invocationId);
    let runs = await workerd.get("/runs?object=warehouse-7") as { inMemory: number; durable: number };
    assert.deepEqual(runs, { inMemory: 1, durable: 1 }, "the operation body ran once");

    // JS-C-07: an operation the card does not list, and a parameter the operation does not declare.
    const unknown = await invoke(space, classCard, "dropTable", { object: "warehouse-7" }, { timeoutMillis: 20_000 });
    assert.equal(unknown?.ok, false);
    assert.equal(unknown?.error, "unknown-operation");
    assert.equal(unknown?.result["rule"], "invoke-ops");
    const badParam = await invoke(space, classCard, "releaseStock", { object: "warehouse-7", sku: "A-100", qty: "1", sql: "x" },
      { timeoutMillis: 20_000 });
    assert.equal(badParam?.ok, false);
    assert.equal(badParam?.error, "bad-params");
    assert.equal(badParam?.result["rule"], "params");
    assert.match(String(badParam?.result["detail"]), /'sql' is not declared/);
    const noObject = await queries.fetch("do/Inventory", { op: "getInventory" }, "20s");
    assert.match(String(noObject?.result.error), /^object-param:/);
    runs = await workerd.get("/runs?object=warehouse-7") as { inMemory: number; durable: number };
    assert.equal(runs.durable, 1, "nothing refused ran");

    // JS-S-06: the Worker reads the data space through fleet() over the cell's stub.
    const seen = await workerd.get(`/entries?space=data&type=${encodeURIComponent(AssetInvocationResult.schema)}`) as { count: number };
    assert.ok(seen.count >= 1, "fleet().space('data').entries saw the results");

    // JS-S-05: the agent cell joins as a member of its own, publishes its AgentCard, and takes work in its name.
    const adjuster = await workerd.get("/adjuster/wake") as Record<string, unknown>;
    assert.equal(adjuster["connected"], true, `the agent cell dialed the hub (${workerd.output()})`);
    const adjusterId = String(adjuster["peerId"]);
    assert.notEqual(adjusterId, cellId, "its own identity");
    assert.deepEqual(adjuster["assets"], ["damage-estimator"]);
    await until(() => agent.cards().some((c) => c["issuer"] === adjusterId && c["agent"] === `${adjusterId}/damage-estimator`), 20_000,
      `the client saw the AgentCard (${workerd.output()})`);
    const claims = new Space(agent, "claims", null, "intake");
    claims.write(new DamageReport("claim-1", 4), "5m");
    await until(() => claims.readAll(new Template<Dict>(DamageEstimate.schema, { claimId: eq("claim-1") })).length === 1, 20_000,
      `the estimate was written (${workerd.output()})`);
    const estimate = DamageEstimate.from(claims.readAll(new Template<Dict>(DamageEstimate.schema, { claimId: eq("claim-1") }))[0]!);
    assert.equal(estimate.estimate, "1000");
    assert.equal(estimate.by, "damage-estimator");
    await until(() => claims.readAll(new Template<Dict>(DamageReport.schema)).length === 0, 20_000, "the report's take completed");
    const adjusterAd = host.peer.members.get(adjusterId)!;
    assert.equal((adjusterAd["resourceHints"] as StringMap)["js.residency"], "cell");

    // JS-R-03: pause closes the connection and renews nothing; wake resumes under the same identity.
    const paused = await workerd.get("/pause") as Record<string, unknown>;
    assert.equal(paused["connected"], false);
    await until(() => !host.peer.linkedMembers().includes(cellId), 15_000, "the hub saw the cell's link close");
    const resumed = await workerd.get("/wake") as Record<string, unknown>;
    assert.equal(resumed["connected"], true);
    assert.equal(resumed["peerId"], cellId, "the same identity resumed");
    await until(() => host.peer.linkedMembers().includes(cellId), 15_000, "the hub saw the cell return");

    // JS-R-05, JS-R-03: a restart of the runtime (the eviction of every object) brings the same identity
    // back from SQLite; the connector's remembered results are gone but the target's once table is not.
    await workerd.stop();
    workerd = await startWorkerd({ group: GROUP, seeds: `ws://127.0.0.1:${port}/aspace`, profile: "dev-local" },
      { dir, port: workerd.port });
    const back = await workerd.get("/wake") as Record<string, unknown>;
    assert.equal(back["peerId"], cellId, "the identity survived the restart");
    assert.equal(back["connected"], true);
    await until(() => assetCards(agent, "do/Inventory").some((c) => String(c["issued"]) > String(classCard["issued"])),
      20_000, "the restarted cell refreshed its card under the same id");
    assert.equal(assetCards(agent, "do/Inventory").length, 1, "one card per id");
    const again = await invoke(space, classCard, "reserveStock", { object: "warehouse-7", sku: "A-100", qty: "3" },
      { timeoutMillis: 20_000, invocationId: first.invocationId });
    assert.ok(again !== null, `the restarted connector answered (${workerd.output()})`);
    assert.deepEqual(again.result, first.result, "once() returned the stored result across the restart");
    runs = await workerd.get("/runs?object=warehouse-7") as { inMemory: number; durable: number };
    assert.deepEqual(runs, { inMemory: 0, durable: 1 }, "the body never ran again");
    // The first query's result still serves its freshness window (pull-once); the instance card's
    // canonical hash differs, so this one runs against the object.
    const after = await queries.fetch("do/Inventory/warehouse-7", { op: "getInventory" }, "20s");
    assert.equal(after?.fromCache, false);
    assert.deepEqual(after?.result.rows, [{ sku: "A-100", qty: "7" }], "stock reserved once");

    // One result per invocation id from the connector's identity, whatever the retries.
    const results = space.entries(new Template<Dict>(AssetInvocationResult.schema, { invocationId: eq(first.invocationId) }), 16, true)
      .filter((e) => e.issuer.startsWith(cellId));
    assert.ok(results.length >= 1, "a result exists for the id");
    for (const r of results) {
      assert.deepEqual(AssetInvocationResult.from(r.value).result, first.result);
    }
  } finally {
    agent.close();
    await workerd.stop();
    workerd.cleanup();
    await host.stop();
  }
});
