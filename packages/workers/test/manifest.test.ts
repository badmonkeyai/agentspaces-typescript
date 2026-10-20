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
 * The manifest and its cards (srad/agentspaces-js.md JS-C-06, JS-C-08,
 * appendix F): one card per Durable Object class, listed instance, KV
 * namespace, D1 database, R2 bucket, Queue, Workflow, and route group, with
 * the SPEC §6.1a fields alone, `workers://<application>/<kind>/<name>`
 * uris, the appendix F `access` keys, and ids `<application>:<asset>`
 * identical across two renderings; a manifest that could not be served
 * honestly is refused naming the rule.
 */

import assert from "node:assert/strict";
import test from "node:test";

import type { StringMap } from "@agentspaces/connect";
import { assetsOf, cardId, cardOf, cardTtl, validateManifest } from "../src/manifest.js";
import type { AssetManifest } from "../src/manifest.js";
import { everything } from "./fixtures.js";

const SPEC_FIELDS = ["id", "issuer", "group", "issued", "ttl", "asset", "uri", "description", "shape", "freshness", "costHints", "access"];

test("one card per asset with the SPEC §6.1a fields alone and the appendix F access keys (JS-C-06, JS-C-08)", () => {
  const manifest = validateManifest(everything());
  const assets = assetsOf(manifest);
  const cards = assets.map((a) => cardOf(manifest, a, "zGroup", "zIssuer", 1_700_000_000_000));
  assert.deepEqual(cards.map((c) => c["asset"]), ["do/Inventory", "do/Inventory/warehouse-7", "do/Inventory/warehouse-9",
    "kv/SETTINGS", "d1/CATALOG", "r2/IMAGES", "queue/EVENTS", "workflow/RESTOCK", "route/default", "route/admin"]);
  for (const card of cards) {
    assert.deepEqual(Object.keys(card), SPEC_FIELDS, `the fields of ${String(card["asset"])}`);
    assert.equal(card["id"], `inventory:${String(card["asset"])}`);
    assert.equal(card["uri"], `workers://inventory/${String(card["asset"])}`);
    assert.equal(card["issuer"], "zIssuer");
    assert.equal(card["group"], "zGroup");
    assert.equal(card["freshness"], "PT30S");
    assert.equal(card["ttl"], "PT60S", "the TTL is twice the freshness");
    const access = card["access"] as StringMap;
    assert.equal(access["runtime"], "celld");
    assert.equal(access["connector"], "cell");
    assert.ok(["read-only", "invoke", "read-only,invoke"].includes(access["mode"]!), access["mode"]);
    assert.equal(access["query"], access["read-ops"] === undefined ? undefined : "aspace:cap/data-query");
    assert.equal(access["invoke"], access["invoke-ops"] === undefined ? undefined : "aspace:cap/asset-invoke");
  }
  const byAsset = new Map(cards.map((c) => [String(c["asset"]), c]));
  const cls = byAsset.get("do/Inventory")!["access"] as StringMap;
  assert.deepEqual(cls, { mode: "read-only,invoke", runtime: "celld", connector: "cell", consistency: "single-writer",
    "object-param": "object", query: "aspace:cap/data-query", "read-ops": "getInventory", invoke: "aspace:cap/asset-invoke",
    "invoke-ops": "reserveStock,releaseStock" });
  assert.deepEqual(byAsset.get("do/Inventory")!["costHints"], { objects: "2" });
  const instance = byAsset.get("do/Inventory/warehouse-9")!["access"] as StringMap;
  assert.equal(instance["object"], "warehouse-9");
  assert.equal(instance["invoke-ops"], "reserveStock,releaseStock");
  assert.equal(byAsset.get("do/Inventory/warehouse-9")!["shape"], "aspace:InventoryState");
  const kv = byAsset.get("kv/SETTINGS")!["access"] as StringMap;
  assert.equal(kv["mode"], "read-only");
  assert.equal(kv["read-ops"], "get,list");
  assert.equal(kv["prefixes"], "public/,flags/");
  assert.equal(kv["invoke-ops"], undefined);
  const d1 = byAsset.get("d1/CATALOG")!;
  assert.equal((d1["access"] as StringMap)["read-ops"], "bySku,all");
  assert.equal(d1["shape"], "table:bySku(sku,name,price);all");
  assert.deepEqual(d1["costHints"], { queries: "2" });
  const r2 = byAsset.get("r2/IMAGES")!;
  assert.equal(r2["shape"], "object");
  assert.equal((r2["access"] as StringMap)["read-ops"], "head,list,get");
  assert.equal((r2["access"] as StringMap)["result"], "block");
  assert.equal((r2["access"] as StringMap)["prefixes"], "public/");
  const queue = byAsset.get("queue/EVENTS")!["access"] as StringMap;
  assert.equal(queue["mode"], "invoke");
  assert.equal(queue["invoke-ops"], "send");
  assert.equal(queue["read-ops"], undefined);
  const workflow = byAsset.get("workflow/RESTOCK")!["access"] as StringMap;
  assert.equal(workflow["invoke-ops"], "create");
  assert.equal(workflow["read-ops"], "status");
  const routes = byAsset.get("route/default")!["access"] as StringMap;
  assert.equal(routes["read-ops"], "health");
  assert.equal(routes["invoke-ops"], "reindex");
  assert.equal(routes["idempotent"], "reindex");
  assert.equal((byAsset.get("route/admin")!["access"] as StringMap)["invoke-ops"], "purge");
});

test("card ids are stable across renderings, restarts, and moves (JS-C-08)", () => {
  const a = assetsOf(validateManifest(everything())).map((x) => cardOf(everything(), x, "g", "zA", 1).id);
  const b = assetsOf(validateManifest(everything())).map((x) => cardOf(everything(), x, "g", "zB", 2_000_000).id);
  assert.deepEqual(a, b, "the id depends on the application and the asset alone, never the issuer or the instant");
  assert.equal(cardId("inventory", "do/Inventory"), "inventory:do/Inventory");
  assert.equal(cardTtl({ application: "x" }), "PT2M");
  assert.equal(cardTtl({ application: "x", freshness: "PT45S" }), "PT90S");
  assert.equal(cardTtl({ application: "x", freshness: "PT45S", ttl: "PT5M" }), "PT5M");
});

test("instances given as a function are resolved into cards by the caller's listing", () => {
  const manifest: AssetManifest = { application: "app", durableObjects: [{ binding: "B", className: "C", shape: "s",
    description: "d", objects: async () => ["x"], read: [{ name: "get", params: [], description: "" }] }] };
  assert.deepEqual(assetsOf(manifest).map((a) => a.asset), ["do/C"], "unresolved: the class alone");
  assert.deepEqual(assetsOf(manifest, new Map([["C", ["x", "y"]]])).map((a) => a.asset), ["do/C", "do/C/x", "do/C/y"]);
});

test("a manifest that could not be served honestly is refused naming the rule (JS-C-07)", () => {
  const refuses = (mutate: (m: AssetManifest) => void, rule: RegExp): void => {
    const manifest = everything();
    mutate(manifest);
    assert.throws(() => validateManifest(manifest), rule);
  };
  refuses((m) => { m.application = "bad app"; }, /manifest rule application/);
  refuses((m) => { m.runtime = "deno" as never; }, /manifest rule runtime/);
  refuses((m) => { m.kv!.push({ binding: "SETTINGS", description: "", shape: "" }); }, /manifest rule asset-name: asset 'kv\/SETTINGS' is listed twice/);
  refuses((m) => { m.durableObjects![0]!.objects = ["warehouse-7", "warehouse-7"]; }, /asset 'do\/Inventory\/warehouse-7' is listed twice/);
  refuses((m) => { m.durableObjects![0]!.invoke!.push({ name: "reserveStock", params: [], description: "" }); }, /operation 'reserveStock' of do\/Inventory is listed twice/);
  refuses((m) => { m.durableObjects![0]!.invoke![0]!.params = ["op"]; }, /parameter 'op' .* is reserved by the protocol/);
  refuses((m) => { m.durableObjects![0]!.invoke![0]!.params = ["sku", "sku"]; }, /parameter 'sku' .* is listed twice/);
  refuses((m) => { m.durableObjects![0]!.className = "Inven tory"; }, /manifest rule class-name/);
  refuses((m) => { m.d1![0]!.queries[0]!.sql = " "; }, /manifest rule d1-sql/);
  refuses((m) => { m.routes![0]!.path = "api/health"; }, /manifest rule route-path/);
  refuses((m) => { m.routes![0]!.method = "DELETE" as never; }, /manifest rule route-method/);
  refuses((m) => { m.routes!.push({ path: "/api/health", method: "GET", description: "", shape: "" }); }, /route operation 'health' of route\/default is listed twice/);
  refuses((m) => { m.workflows![0]!.params = ["object"]; }, /parameter 'object' .* is reserved/);
  assert.equal(validateManifest(everything()).application, "inventory", "the good manifest passes");
});
