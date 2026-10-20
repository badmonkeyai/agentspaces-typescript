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
 * The Workers asset provider over fake bindings (srad/agentspaces-js.md
 * JS-C-04, JS-C-06, JS-C-07, appendix F): every kind dispatches to its
 * binding as the appendix maps it, the invocation id reaches a Durable
 * Object as the last RPC argument and a route as `Aspace-Invocation-Id`,
 * and a request outside the allowlist (an unlisted operation, an
 * undeclared or missing parameter, a key outside the prefixes, a class
 * card without `object`, an instance card with another object) is refused
 * with the rule's name before anything runs.
 */

import assert from "node:assert/strict";
import test from "node:test";

import type { StringMap } from "@agentspaces/connect";
import { INVOCATION_HEADER, WorkersAssetProvider, rowOf, rowsOf } from "../src/providers.js";
import type { CellEnv } from "../src/workers-types.js";
import { everything } from "./fixtures.js";

/** Fake bindings recording every call. */
function fakeEnv(): { env: CellEnv; calls: unknown[][]; fetches: { url: string; init: RequestInit }[] } {
  const calls: unknown[][] = [];
  const fetches: { url: string; init: RequestInit }[] = [];
  const stub = (name: string): Record<string, unknown> => new Proxy({}, {
    get: (_t, method: string) => (...args: unknown[]) => {
      calls.push([name, method, ...args]);
      if (method === "getInventory") {
        return [{ sku: "A-100", qty: 10 }];
      }
      if (method === "explode") {
        throw new Error("boom");
      }
      return { ok: true, invocationId: args[1] };
    },
  });
  const env: CellEnv = {
    INVENTORY: { getByName: (name: string) => stub(name) },
    SETTINGS: {
      get: async (key: string) => { calls.push(["kv.get", key]); return key === "public/a" ? "1" : null; },
      list: async (o: { prefix?: string; limit?: number }) => {
        calls.push(["kv.list", o]);
        return { keys: [{ name: `${o.prefix ?? ""}k1` }, { name: `${o.prefix ?? ""}k2`, expiration: 99 }], list_complete: false, cursor: "c2" };
      },
    },
    CATALOG: { prepare: (sql: string) => ({
      bind: (...values: unknown[]) => ({ all: async () => { calls.push(["d1", sql, values]); return { results: [{ sku: values[0], price: 1.5 }] }; } }),
      all: async () => { calls.push(["d1", sql, []]); return { results: [{ sku: "A" }, { sku: "B" }] }; } }) },
    IMAGES: {
      head: async (key: string) => { calls.push(["r2.head", key]); return { key, size: 3, etag: "e", uploaded: new Date(0) }; },
      list: async (o: unknown) => { calls.push(["r2.list", o]); return { objects: [{ key: "public/x", size: 1, etag: "e", uploaded: new Date(0) }], truncated: false }; },
      get: async (key: string) => { calls.push(["r2.get", key]); return key === "public/big"
        ? { key, size: 100_000, etag: "e", uploaded: new Date(0), arrayBuffer: async () => new ArrayBuffer(100_000) }
        : { key, size: 3, etag: "e", uploaded: new Date(0), httpMetadata: { contentType: "text/plain" }, arrayBuffer: async () => new Uint8Array([104, 105, 33]).buffer }; },
    },
    EVENTS: { send: async (message: unknown, options: unknown) => { calls.push(["queue.send", message, options]); } },
    RESTOCK: {
      create: async (o: { id?: string; params?: unknown }) => { calls.push(["wf.create", o]); return { id: o.id ?? "new", status: async () => ({ status: "queued" }) }; },
      get: async (id: string) => { calls.push(["wf.get", id]); return { id, status: async () => ({ status: "running", output: { n: 1 } }) }; },
    },
    SELF: { fetch: async (url: string | URL, init?: RequestInit) => { fetches.push({ url: String(url), init: init ?? {} }); return new Response(JSON.stringify({ purged: 2 })); } },
  };
  return { env, calls, fetches };
}

function provider(fetches: { url: string; init: RequestInit }[] = []): { p: WorkersAssetProvider; calls: unknown[][]; fetches: typeof fetches } {
  const fake = fakeEnv();
  const p = new WorkersAssetProvider(fake.env, everything(), {
    fetch: async (url, init) => { fake.fetches.push({ url: String(url), init: init ?? {} }); return new Response(JSON.stringify([{ status: "ok" }])); },
    maxInlineResultBytes: 1_000 });
  fetches.push(...fake.fetches);
  return { p, calls: fake.calls, fetches: fake.fetches };
}

test("a Durable Object read and operation go to the named instance's stub, the invocation id last (JS-C-04, JS-C-06)", async () => {
  const { p, calls } = provider();
  const read = await p.query("do/Inventory", { op: "getInventory", object: "warehouse-7" });
  assert.equal(read.error, null);
  assert.deepEqual(read.rows, [{ sku: "A-100", qty: "10" }]);
  assert.deepEqual(calls[0], ["warehouse-7", "getInventory", {}]);
  const fixed = await p.query("do/Inventory/warehouse-9", { op: "getInventory" });
  assert.deepEqual(fixed.rows, [{ sku: "A-100", qty: "10" }]);
  assert.deepEqual(calls[1], ["warehouse-9", "getInventory", {}]);
  const ran = await p.invoke("do/Inventory", "reserveStock", { object: "warehouse-7", sku: "A-100", qty: "3" }, "inv-42");
  assert.equal(ran.ok, true);
  assert.deepEqual(ran.result, { ok: "true", invocationId: "inv-42" });
  assert.deepEqual(calls[2], ["warehouse-7", "reserveStock", { sku: "A-100", qty: "3" }, "inv-42"], "params then the id");
  const optional = await p.invoke("do/Inventory/warehouse-9", "releaseStock", { sku: "A", qty: "1", reason: "damaged" }, "inv-43");
  assert.equal(optional.ok, true);
  assert.deepEqual(calls[3], ["warehouse-9", "releaseStock", { sku: "A", qty: "1", reason: "damaged" }, "inv-43"]);
  assert.equal(p.executed, 4);
  assert.equal(p.refused, 0);
});

test("requests outside the allowlist are refused naming the rule, and nothing runs (JS-C-07)", async () => {
  const { p, calls } = provider();
  const cases: [Promise<{ error: string | null } | { ok: boolean; error: string | null; result: StringMap }>, string, string][] = [
    [p.query("do/Inventory", { op: "dropTable", object: "w" }), "unknown-operation", "read-ops"],
    [p.query("do/Inventory", { object: "w" }), "", "read-ops"],
    [p.query("do/Inventory", { op: "getInventory" }), "", "object-param"],
    [p.query("do/Inventory/warehouse-9", { op: "getInventory", object: "warehouse-7" }), "", "object"],
    [p.query("do/Inventory", { op: "getInventory", object: "w", sql: "1" }), "", "params"],
    [p.query("kv/SETTINGS", { op: "get", key: "public/a", object: "x" }), "", "params"],
    [p.query("nope", { op: "x" }), "", "asset"],
    [p.invoke("do/Inventory", "getInventory", { object: "w" }, "i"), "unknown-operation", "invoke-ops"],
    [p.invoke("do/Inventory", "reserveStock", { object: "w", sku: "A" }, "i"), "bad-params", "params"],
    [p.invoke("do/Inventory", "reserveStock", { object: "w", sku: "A", qty: "1", extra: "x" }, "i"), "bad-params", "params"],
    [p.invoke("do/Inventory", "reserveStock", { sku: "A", qty: "1" }, "i"), "bad-params", "object-param"],
    [p.invoke("kv/SETTINGS", "put", { key: "k" }, "i"), "unknown-operation", "invoke-ops"],
    [p.invoke("nope", "x", {}, "i"), "unknown-operation", "asset"],
  ];
  for (const [pending, code, rule] of cases) {
    const answer = await pending;
    if ("ok" in answer) {
      assert.equal(answer.ok, false);
      assert.equal(answer.error, code);
      assert.equal(answer.result["rule"], rule, answer.result["detail"]);
    } else {
      assert.match(String(answer.error), new RegExp(`^${rule}:`), String(answer.error));
    }
  }
  assert.deepEqual(calls, [], "no binding was touched");
  assert.equal(p.refused, cases.length);
  assert.equal(p.executed, 0);
});

test("KV answers get and list under the declared prefixes; a key outside them is refused (JS-C-06)", async () => {
  const { p, calls } = provider();
  assert.deepEqual((await p.query("kv/SETTINGS", { op: "get", key: "public/a" })).rows, [{ key: "public/a", value: "1" }]);
  assert.deepEqual((await p.query("kv/SETTINGS", { op: "get", key: "public/none" })).rows, []);
  const outside = await p.query("kv/SETTINGS", { op: "get", key: "secret/a" });
  assert.match(String(outside.error), /^target: prefixes: key 'secret\/a' is outside the prefixes/);
  assert.equal(calls.filter((c) => c[0] === "kv.get" && c[1] === "secret/a").length, 0, "the binding never saw it");
  const listed = await p.query("kv/SETTINGS", { op: "list", prefix: "flags/", limit: "5" });
  assert.deepEqual(listed.rows, [{ key: "flags/k1", expiration: "" }, { key: "flags/k2", expiration: "99", cursor: "c2" }]);
  assert.deepEqual(calls.find((c) => c[0] === "kv.list"), ["kv.list", { prefix: "flags/", limit: 5, cursor: undefined }]);
  const all = await p.query("kv/SETTINGS", { op: "list" });
  assert.equal(all.rows.length, 4, "no prefix given: every declared prefix is listed");
  assert.match(String((await p.query("kv/SETTINGS", { op: "list", prefix: "secret/" })).error), /prefixes/);
});

test("D1 runs only the named query with the parameters bound positionally (JS-C-06, JS-C-07)", async () => {
  const { p, calls } = provider();
  const rows = (await p.query("d1/CATALOG", { op: "bySku", sku: "A-100" })).rows;
  assert.deepEqual(rows, [{ sku: "A-100", price: "1.5" }]);
  assert.deepEqual(calls[0], ["d1", "SELECT * FROM products WHERE sku = ?1", ["A-100"]]);
  assert.deepEqual((await p.query("d1/CATALOG", { op: "all" })).rows, [{ sku: "A" }, { sku: "B" }]);
  const raw = await p.query("d1/CATALOG", { op: "DROP TABLE products" });
  assert.match(String(raw.error), /^read-ops: operation 'DROP TABLE products' is not in the read-ops/);
  assert.equal(calls.length, 2);
});

test("R2 answers head, list, and get with the body inline up to the limit (JS-C-06)", async () => {
  const { p } = provider();
  assert.deepEqual((await p.query("r2/IMAGES", { op: "head", key: "public/x" })).rows,
    [{ key: "public/x", size: "3", etag: "e", uploaded: "1970-01-01T00:00:00.000Z", contentType: "" }]);
  assert.deepEqual((await p.query("r2/IMAGES", { op: "list" })).rows.map((r) => r["key"]), ["public/x"]);
  const got = await p.query("r2/IMAGES", { op: "get", key: "public/x" });
  assert.equal(got.rows[0]!["body"], "aGkh", "the body as base64");
  assert.equal(got.rows[0]!["contentType"], "text/plain");
  const big = await p.query("r2/IMAGES", { op: "get", key: "public/big" });
  assert.match(String(big.error), /exceeds the 1000-byte inline limit \(maxInlineResultBytes\)/);
  assert.match(String((await p.query("r2/IMAGES", { op: "get", key: "private/x" })).error), /prefixes/);
});

test("a Queue send carries the invocation id in the message; a Workflow create uses it as the instance id (JS-C-04, JS-C-06)", async () => {
  const { p, calls } = provider();
  const sent = await p.invoke("queue/EVENTS", "send", { sku: "A", delta: "-1" }, "inv-7");
  assert.deepEqual(sent, { ok: true, error: null, result: { sent: "true", invocationId: "inv-7" } });
  assert.deepEqual(calls[0], ["queue.send", { invocationId: "inv-7", params: { sku: "A", delta: "-1" } }, { contentType: "json" }]);
  const created = await p.invoke("workflow/RESTOCK", "create", { sku: "A", qty: "5" }, "inv-8");
  assert.deepEqual(created.result, { id: "inv-8", status: "queued" });
  assert.deepEqual(calls[1], ["wf.create", { id: "inv-8", params: { sku: "A", qty: "5" } }]);
  const status = await p.query("workflow/RESTOCK", { op: "status", id: "inv-8" });
  assert.deepEqual(status.rows, [{ id: "inv-8", status: "running", output: "{\"n\":1}" }]);
  assert.equal((await p.invoke("queue/EVENTS", "send", { sku: "A" }, "inv-9")).result["rule"], "params", "a missing parameter");
});

test("a route is called GET-as-read with the query string and POST-as-invoke with the id as a header (JS-C-04, JS-C-06)", async () => {
  const fetches: { url: string; init: RequestInit }[] = [];
  const { p, fetches: seen } = provider(fetches);
  const health = await p.query("route/default", { op: "health" });
  assert.deepEqual(health.rows, [{ status: "ok" }]);
  assert.equal(seen[0]!.url, "https://inventory.example/api/health");
  assert.equal(seen[0]!.init.method, "GET");
  const reindexed = await p.invoke("route/default", "reindex", { scope: "all" }, "inv-10");
  assert.equal(reindexed.ok, true);
  assert.equal(seen[1]!.url, "https://inventory.example/api/reindex");
  assert.equal(seen[1]!.init.method, "POST");
  assert.equal((seen[1]!.init.headers as Record<string, string>)[INVOCATION_HEADER], "inv-10");
  assert.equal(seen[1]!.init.body, "{\"scope\":\"all\"}");
  const purged = await p.invoke("route/admin", "purge", {}, "inv-11");
  assert.deepEqual(purged.result, { purged: "2" });
  assert.equal(seen.length, 3, "the service binding carried the admin route");
  assert.equal(seen[2]!.url, "https://service/admin/purge");
  assert.equal((seen[2]!.init.headers as Record<string, string>)[INVOCATION_HEADER], "inv-11");
  assert.equal((await p.query("route/default", { op: "reindex" })).error?.startsWith("read-ops:"), true, "a POST route is no read");
  assert.equal((await p.invoke("route/default", "health", {}, "i")).result["rule"], "invoke-ops", "a GET route is no operation");
});

test("a target's failure is a target-error result, never an exception; rows stringify every value", async () => {
  const fake = fakeEnv();
  const manifest = everything();
  manifest.durableObjects![0]!.invoke!.push({ name: "explode", params: [], description: "" });
  const p = new WorkersAssetProvider(fake.env, manifest);
  const failed = await p.invoke("do/Inventory", "explode", { object: "w" }, "i");
  assert.deepEqual(failed, { ok: false, error: "target-error", result: { rule: "target", detail: "boom" } });
  const missing = await p.invoke("do/Inventory", "reserveStock", { object: "w", sku: "A", qty: "1" }, "i");
  assert.equal(missing.ok, true);
  assert.deepEqual(rowOf({ a: 1, b: null, c: [1, 2], d: true, e: new Date(0) }),
    { a: "1", b: "", c: "[1,2]", d: "true", e: "1970-01-01T00:00:00.000Z" });
  assert.deepEqual(rowsOf("x"), [{ value: "x" }]);
  assert.deepEqual(rowsOf(null), []);
  assert.deepEqual(rowsOf([{ a: 1 }, 2]), [{ a: "1" }, { value: "2" }]);
  const noBinding = new WorkersAssetProvider({}, everything());
  assert.match(String((await noBinding.query("kv/SETTINGS", { op: "get", key: "public/a" })).error), /binding 'SETTINGS' is not in the environment/);
});

test("the provider's cards and a refresh resolving listed instances (JS-C-08)", async () => {
  const manifest = everything();
  manifest.durableObjects![0]!.objects = async () => ["w-1"];
  const p = new WorkersAssetProvider(fakeEnv().env, manifest);
  assert.ok(!p.assetNames().includes("do/Inventory/w-1"), "unresolved before refresh");
  await p.refresh();
  assert.ok(p.assetNames().includes("do/Inventory/w-1"));
  const cards = p.describeAssets("zG", "zI", 0);
  assert.equal(cards.length, p.assetNames().length);
  assert.equal(cards.find((c) => c["asset"] === "do/Inventory/w-1")!["id"], "inventory:do/Inventory/w-1");
});
