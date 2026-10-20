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
 * The `vars` configuration and the `fleet()` handles (srad/agentspaces-js.md
 * JS-R-05, JS-S-06, JS-S-07): the group, seeds, invite, and profile read
 * from the environment, bare seeds dialed `wss` under `attested` and `ws`
 * under `dev-local`, a plaintext seed refused under `attested`; and the
 * space handles translating writes, reads, and takes into the cell stub's
 * RPC verbs with the core's payloads and schemas.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { entry } from "@agentspaces/client";
import { cellConfig, parseSeeds } from "../src/config.js";
import { fleet } from "../src/fleet.js";

test("the vars block configures the cell; seeds follow the profile (JS-R-05, JS-S-07)", () => {
  const config = cellConfig({ AGENTSPACES_GROUP: "ops.example", AGENTSPACES_SEEDS: "wss://fleet.example.com:443/aspace, other.example",
    AGENTSPACES_INVITE: "", AGENTSPACES_PROFILE: "attested", FLEET: {} }, { name: "connector" });
  assert.equal(config.group, "ops.example");
  assert.deepEqual(config.seeds, [{ host: "fleet.example.com", port: 443, scheme: "wss", path: "/aspace" },
    { host: "other.example", port: 443, scheme: "wss" }]);
  assert.equal(config.invite, null, "an empty invite is none");
  assert.equal(config.profile, "attested");
  assert.equal(config.name, "connector");
  assert.equal(config.dataSpace, "data");
  assert.equal(config.taskSpace, "data");
  assert.equal(config.tickMillis, 1000);
  assert.equal(config.reconnectMillis, 5000);
  const dev = cellConfig({ AGENTSPACES_GROUP: "g", AGENTSPACES_SEEDS: "127.0.0.1:7513 ws://[::1]:7514/x", AGENTSPACES_PROFILE: "dev-local",
    AGENTSPACES_INVITE: "ASPACE-ABC" });
  assert.deepEqual(dev.seeds, [{ host: "127.0.0.1", port: 7513, scheme: "ws" }, { host: "::1", port: 7514, scheme: "ws", path: "/x" }]);
  assert.equal(dev.invite, "ASPACE-ABC");
  assert.equal(dev.profile, "dev-local");
  assert.equal(cellConfig({ AGENTSPACES_GROUP: "g", AGENTSPACES_SEEDS: "h" }).profile, "attested", "the default profile");
  assert.throws(() => parseSeeds("ws://plain.example:80", "attested"), /profile attested dials only attested schemes; seed ws:\/\/plain.example:80 is plaintext ws; set AGENTSPACES_PROFILE=dev-local/);
  assert.throws(() => cellConfig({ AGENTSPACES_SEEDS: "h" }), /AGENTSPACES_GROUP/);
  assert.throws(() => cellConfig({ AGENTSPACES_GROUP: "g" }), /AGENTSPACES_SEEDS/);
  const overridden = cellConfig({ AGENTSPACES_GROUP: "g", AGENTSPACES_SEEDS: "h" }, { taskSpace: "tasks", idleMillis: 15_000, log: null });
  assert.equal(overridden.taskSpace, "tasks");
  assert.equal(overridden.changeSpace, "data");
  assert.equal(overridden.idleMillis, 15_000);
  assert.equal(overridden.log, null);
});

@entry("com.example.Order#v1")
class Order {
  constructor(readonly id: string, readonly qty: number) {}
}

@entry("com.example.Receipt#v1")
class Receipt {
  constructor(readonly id: string) {}
}

test("fleet() drives the cell's RPC verbs with the core's schemas and payloads (JS-S-06)", async () => {
  const calls: unknown[][] = [];
  const stub = new Proxy({}, { get: (_t, method: string) => (...args: unknown[]) => {
    calls.push([method, ...args]);
    switch (method) {
      case "cellStatus": return Promise.resolve({ peerId: "zCell", connected: true });
      case "cellWrite": return Promise.resolve("entry-1");
      case "cellEntries": return Promise.resolve([{ entryId: "e1", value: { id: "o-1", qty: 2 }, issuer: "zX/planner",
        expiresAtMillis: 5, tags: {}, taken: false }]);
      case "cellTake": return Promise.resolve({ entryId: "e2", value: { id: "o-2", qty: 3 } });
      case "cellComplete": return Promise.resolve({ held: true, resultId: "r1" });
      case "cellRenew": return Promise.resolve(true);
      default: return Promise.reject(new Error(`no ${method}`));
    }
  } });
  const env = { FLEET: { getByName: (name: string) => { calls.push(["getByName", name]); return stub; } } };
  const handle = fleet(env);
  assert.deepEqual(calls[0], ["getByName", "connector"]);
  assert.equal((await handle.status()).peerId, "zCell");
  const orders = handle.space("orders");
  assert.equal(await orders.write(new Order("o-1", 2), "5m", { region: "eu" }), "entry-1");
  assert.deepEqual(calls[2], ["cellWrite", "orders", "com.example.Order#v1", { id: "o-1", qty: 2 }, 300_000, { region: "eu" }]);
  const read = await orders.readAll(Order, { id: "o-1" });
  assert.ok(read[0] instanceof Order, "typed through the entry class");
  assert.deepEqual(read, [new Order("o-1", 2)]);
  assert.deepEqual(calls[3], ["cellEntries", "orders", "com.example.Order#v1", { id: "o-1" }, 100, true]);
  const taken = await orders.take(Order, {}, "2m", "10s");
  assert.ok(taken !== null);
  assert.equal(taken.entryId, "e2");
  assert.equal(taken.value.qty, 3);
  assert.deepEqual(calls[4], ["cellTake", "orders", "com.example.Order#v1", {}, 120_000, 10_000]);
  assert.deepEqual(await taken.complete(new Receipt("o-2"), "30m"), { held: true, resultId: "r1" });
  assert.deepEqual(calls[5], ["cellComplete", "orders", "e2", "com.example.Receipt#v1", { id: "o-2" }, 1_800_000]);
  assert.equal(await taken.renew("1m"), true);
  assert.deepEqual(calls[6], ["cellRenew", "orders", "e2", 60_000]);
  assert.deepEqual(await orders.entries("raw.Schema#v1"), [{ entryId: "e1", value: { id: "o-1", qty: 2 }, issuer: "zX/planner",
    expiresAtMillis: 5, tags: {}, taken: false }], "a string schema reads raw payloads");
  assert.throws(() => fleet({}, "NOPE"), /binding 'NOPE' is not a Durable Object namespace/);
});
