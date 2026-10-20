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
 * `once` and the SQLite key store over a real SQLite (srad/agentspaces-js.md
 * JS-C-04, JS-P-08): a repeat under the same invocation id returns the
 * stored result and never runs the function again; two concurrent calls
 * share one run; a failed run records nothing; rows older than the
 * retention are dropped; the key store round-trips bytes and the identity
 * is the same on every load.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Identity } from "@agentspaces/client";
import { PEER_KEY, SqliteKeyStore, loadOrCreateIdentity } from "../src/keystore.js";
import { ONCE_TABLE, once, recorded, recordedCount } from "../src/once.js";
import { NodeCellStorage, NodeSqlStorage } from "./sqlite.js";

test("once runs the function one time per invocation id and returns the stored result on a repeat (JS-C-04)", async () => {
  const storage = new NodeCellStorage();
  let runs = 0;
  const reserve = () => once(storage, "inv-1", async () => { runs += 1; return { reserved: "3", run: String(runs) }; });
  const first = await reserve();
  const second = await reserve();
  const third = await once(storage.sql, "inv-1", () => { runs += 1; return { reserved: "never" }; });
  assert.deepEqual(first, { reserved: "3", run: "1" });
  assert.deepEqual(second, first, "the repeat is the stored result");
  assert.deepEqual(third, first, "the storage's sql member and the storage itself address one table");
  assert.equal(runs, 1, "the body ran once");
  assert.equal(recordedCount(storage), 1);
  assert.deepEqual(recorded(storage, "inv-1"), { found: true, result: first });
  assert.equal(recorded(storage, "inv-2").found, false);
  const other = await once(storage, "inv-2", () => { runs += 1; return { reserved: "1" }; });
  assert.deepEqual(other, { reserved: "1" });
  assert.equal(runs, 2, "a new id runs");
  const rows = storage.sql.exec<{ id: string; result: string }>(`SELECT id, result FROM ${ONCE_TABLE} ORDER BY id`).toArray();
  assert.deepEqual(rows.map((r) => r.id), ["inv-1", "inv-2"]);
  assert.equal(JSON.parse(rows[0]!.result).reserved, "3");
});

test("two concurrent calls under one id share one run; a failed run records nothing (JS-C-04)", async () => {
  const storage = new NodeSqlStorage();
  let runs = 0;
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const slow = () => once(storage, "slow", async () => { runs += 1; await gate; return { done: "yes" }; });
  const a = slow();
  const b = slow();
  release();
  assert.deepEqual(await Promise.all([a, b]), [{ done: "yes" }, { done: "yes" }]);
  assert.equal(runs, 1);
  let failures = 0;
  await assert.rejects(once(storage, "fails", () => { failures += 1; throw new Error("no stock"); }), /no stock/);
  assert.equal(recorded(storage, "fails").found, false, "nothing recorded for a failed run");
  await assert.rejects(once(storage, "fails", () => { failures += 1; throw new Error("still none"); }), /still none/);
  assert.equal(failures, 2, "a retry after a failure runs again: the target decides what a failure means");
  await assert.rejects(once(storage, "", () => 1), /non-empty invocationId/);
});

test("rows older than the retention are dropped; the retention is an option (JS-C-04)", async () => {
  const storage = new NodeSqlStorage();
  let now = 1_000_000;
  const clock = () => now;
  await once(storage, "old", () => ({ v: "1" }), { clock, retention: "1h" });
  now += 30 * 60_000;
  await once(storage, "mid", () => ({ v: "2" }), { clock, retention: "1h" });
  assert.equal(recordedCount(storage), 2);
  now += 31 * 60_000; // "old" is 61 min old, "mid" 31
  let runs = 0;
  const again = await once(storage, "old", () => { runs += 1; return { v: "3" }; }, { clock, retention: "1h" });
  assert.deepEqual(again, { v: "3" }, "past the retention the id runs again");
  assert.equal(runs, 1);
  assert.deepEqual(await once(storage, "mid", () => ({ v: "x" }), { clock, retention: "1h" }), { v: "2" }, "within it, stored");
  // The default retention is 24 h: a day-old row is dropped, a younger one kept.
  now += 23 * 3_600_000;
  assert.deepEqual(await once(storage, "mid", () => ({ v: "y" }), { clock }), { v: "2" });
  now += 2 * 3_600_000;
  assert.deepEqual(await once(storage, "mid", () => ({ v: "y" }), { clock }), { v: "y" });
});

test("the SQLite key store round-trips bytes and the identity resumes on every load (JS-P-08, JS-R-03)", async () => {
  const storage = new NodeSqlStorage();
  const keys = new SqliteKeyStore(storage);
  assert.equal(await keys.load("peer.key"), null);
  await keys.save("peer.key", new Uint8Array([1, 2, 3, 0, 255]));
  assert.deepEqual(await keys.load("peer.key"), new Uint8Array([1, 2, 3, 0, 255]));
  await keys.save("peer.key", new Uint8Array([9]));
  assert.deepEqual(await keys.load("peer.key"), new Uint8Array([9]), "a save replaces");
  await keys.remove("peer.key");
  assert.equal(await keys.load("peer.key"), null);
  await assert.rejects(keys.save("../etc", new Uint8Array([1])), /not a safe key name/);

  const first = await loadOrCreateIdentity(keys);
  const second = await loadOrCreateIdentity(new SqliteKeyStore(storage));
  assert.equal(second.peerId, first.peerId, "the same identity on a second construction over the same storage");
  assert.deepEqual(keys.names(), [PEER_KEY]);
  const stored = Identity.fromPkcs8((await keys.load(PEER_KEY))!);
  assert.equal(stored.peerId, first.peerId);
  await keys.save(PEER_KEY, new Uint8Array([1, 2, 3]));
  await assert.rejects(loadOrCreateIdentity(keys), /not a PKCS#8 Ed25519 key/);
});
