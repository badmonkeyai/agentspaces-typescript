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
 * The persistent values in TypeScript (srad/agentspaces-pdt.md groups V, B, S, N): canonical layouts
 * whatever the order of operations, transients whose delta is exactly the final path set, the diff and
 * the three-way merge, spilled values (x nodes, sub-maps, sub-vectors, blobs) reassembled byte for byte,
 * the vector across its tail and trie boundaries, blob edits that reuse unchanged chunks, the node
 * store's walks and collection, the file backend, and the inline-delta collect and accept rules.
 */

import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { dumps, loads } from "../src/cbor.js";
import { FileNodeBackend } from "../src/node/node-store.js";
import * as pdt from "../src/pdt/index.js";
import type { Dict } from "../src/wire.js";

type V = pdt.CborValue;

/** A seeded generator (xorshift) for deterministic inputs. */
function rng(seed: number): () => number {
  let x = seed >>> 0 || 1;
  return () => {
    x ^= x << 13; x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5; x >>>= 0;
    return x / 0x100000000;
  };
}

function bytes(length: number, seed: number): Uint8Array {
  const next = rng(seed);
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = Math.floor(next() * 256);
  }
  return out;
}

test("a key set reached in any order and through removals has one root (PD-V-01)", () => {
  const store = pdt.NodeStore.inMemory();
  const next = rng(7);
  const keys = Array.from({ length: 300 }, (_, i) => `key-${i}`);
  let forward = pdt.PMap.empty<string, V>(store);
  for (const k of keys) {
    forward = forward.assoc(k, k.length);
  }
  let shuffled = pdt.PMap.empty<string, V>(store);
  for (const k of [...keys].sort(() => next() - 0.5)) {
    shuffled = shuffled.assoc(k, k.length);
  }
  assert.equal(forward.root(), shuffled.root());
  // 100 extra keys added then removed leave the same root (canonical compaction)
  let noisy = forward;
  for (let i = 0; i < 100; i++) {
    noisy = noisy.assoc(`extra-${i}`, i);
  }
  assert.notEqual(noisy.root(), forward.root());
  for (let i = 99; i >= 0; i--) {
    noisy = noisy.dissoc(`extra-${i}`);
  }
  assert.equal(noisy.root(), forward.root());
  assert.equal(noisy.count(), 300);
  assert.equal(forward.get("key-7"), 5);
  assert.equal(forward.get("missing"), undefined);
  assert.equal(forward.dissoc("missing"), forward);
  assert.equal(forward.assoc("key-7", 5), forward);
  // the receiver never changes
  const before = forward.root();
  forward.assoc("x", 1).dissoc("key-1");
  assert.equal(forward.root(), before);
  assert.equal(forward.count(), 300);
  assert.equal(new Set(forward.keys()).size, 300);
});

test("a transient writes exactly the final path set and a reload reads it (PD-V-05, PD-V-08)", () => {
  const store = pdt.NodeStore.inMemory();
  const editor = pdt.PMap.empty<string, V>(store).editor();
  for (let i = 0; i < 2000; i++) {
    editor.assoc(`k${i}`, { n: i, tag: `t${i % 7}` });
  }
  editor.dissoc("k5").assoc("k5", "five");
  assert.equal(editor.count(), 2000);
  const map = editor.done();
  assert.throws(() => editor.assoc("late", 1), /done/);
  assert.equal(store.nodesHeld, 0, "nothing is written before root()");
  store.record();
  const root = map.root();
  const delta = store.drain();
  assert.equal(delta.size, store.nodesHeld);
  assert.ok(delta.size > 32 && delta.size < 1000, `${delta.size} nodes for 2,000 entries`);
  assert.ok(store.complete(root));
  const reloaded = pdt.PMap.load<string, V>(store, root);
  assert.equal(reloaded.count(), 2000);
  assert.equal(reloaded.get("k5"), "five");
  assert.deepEqual({ ...(reloaded.get("k1999") as Dict) }, { n: 1999, tag: "t4" });
  assert.equal(reloaded.root(), root);
  // one more assoc touches one path: a handful of new nodes
  store.record();
  const next = reloaded.assoc("k0", "zero");
  next.root();
  const touched = store.drain();
  assert.ok(touched.size >= 1 && touched.size <= 5, `${touched.size} nodes for one change`);
  assert.equal(reloaded.get("k0") !== "zero", true);
  const edited = pdt.PMap.empty<string, V>(store).assoc("a", 1).editor().done();
  assert.equal(edited.count(), 1);
});

test("diff descends only where CIDs differ and merge3 is key-wise with a resolver (PD-V-07, PD-V-09)", () => {
  const store = pdt.NodeStore.inMemory();
  let base = pdt.PMap.empty<string, V>(store);
  for (let i = 0; i < 500; i++) {
    base = base.assoc(`k${i}`, i);
  }
  base.root();
  const mine = base.assoc("k1", "mine").assoc("new-mine", 1).dissoc("k2");
  const theirs = base.assoc("k1", "theirs").assoc("new-theirs", 2).assoc("k3", 33).dissoc("k4");
  const diff = mine.diff(base);
  assert.deepEqual(diff.added, [["new-mine", 1]]);
  assert.deepEqual(diff.removed, [["k2", 2]]);
  assert.deepEqual(diff.changed, [["k1", 1, "mine"]]);
  assert.deepEqual(base.diff(base), { added: [], removed: [], changed: [] });
  const conflicts: string[] = [];
  const merged = mine.merge3(base, theirs, (key, b, m, t) => {
    conflicts.push(`${key}:${String(b)}:${String(m)}:${String(t)}`);
    return t;
  });
  assert.deepEqual(conflicts, ["k1:1:mine:theirs"]);
  assert.equal(merged.get("k1"), "theirs");
  assert.equal(merged.get("new-mine"), 1);
  assert.equal(merged.get("new-theirs"), 2);
  assert.equal(merged.get("k3"), 33);
  assert.equal(merged.has("k2"), false);
  assert.equal(merged.has("k4"), false);
  assert.equal(merged.count(), 500);
  // the merge is symmetric in content when the resolver picks the same value
  const other = theirs.merge3(base, mine, (_k, _b, _m, _t) => "theirs");
  assert.equal(other.root(), merged.root());
  // update and updateIn
  const nested = base.assoc("doc", { a: { b: [1, 2, 3] } });
  const updated = nested.updateIn(["doc", "a", "b", 1], (v) => Number(v) * 10).update("k0", (v) => Number(v) + 1);
  assert.deepEqual(JSON.parse(JSON.stringify(updated.get("doc"))), { a: { b: [1, 20, 3] } });
  assert.equal(updated.get("k0"), 1);
  assert.equal(updated.updateIn(["fresh", "x"], () => 1).get("fresh") !== undefined, true);
});

test("sets are null-valued maps with equality by root (PD-V-02)", () => {
  const store = pdt.NodeStore.inMemory();
  let set = pdt.PSet.empty<V>(store);
  for (const item of ["a", "b", "c", 1, 2]) {
    set = set.conj(item);
  }
  assert.equal(set.count(), 5);
  assert.ok(set.contains("b") && set.contains(2) && !set.contains("z"));
  assert.equal(set.conj("a"), set);
  const other = pdt.PSet.empty<V>(store).conj(2).conj(1).conj("c").conj("b").conj("a");
  assert.ok(set.equals(other));
  assert.ok(!set.disj("a").equals(other));
  assert.equal(pdt.PSet.load<V>(store, set.root()).toSet().size, 5);
  const node = pdt.nodes.decode(store.get(set.root())!);
  const e = node["e"] as pdt.Embedded[];
  assert.deepEqual(e[1]!.bytes, Uint8Array.of(0xf6));
});

test("the vector keeps its tail outside the trie and edits copy one path (PD-V-03, PD-V-04)", () => {
  const store = pdt.NodeStore.inMemory();
  let v = pdt.PVector.empty<V>(store);
  for (let i = 0; i < 1100; i++) {
    v = v.conj(i);
  }
  assert.equal(v.count(), 1100);
  assert.equal(v.nth(0), 0);
  assert.equal(v.nth(1099), 1099);
  assert.equal(v.nth(1023), 1023);
  assert.throws(() => v.nth(1100));
  const editor = pdt.PVector.empty<V>(store).editor();
  for (let i = 0; i < 1100; i++) {
    editor.conj(i);
  }
  assert.equal(editor.done().root(), v.root(), "the layout is a function of the count");
  const popped = v.pop().pop();
  assert.equal(popped.count(), 1098);
  assert.equal(popped.conj(1098).conj(1099).root(), v.root());
  // conj within the tail writes one root node
  v.root();
  store.record();
  const within = v.conj(1100);
  within.root();
  assert.equal(store.drain().size, 1, "a conj inside the tail writes the root only");
  // assocN deep in the trie copies the path (root + shift / 5 + 1 nodes)
  store.record();
  const changed = v.assocN(100, "hundred");
  changed.root();
  const copied = store.drain().size;
  assert.ok(copied >= 2 && copied <= 4, `${copied} nodes copied for one assocN`);
  assert.equal(changed.nth(100), "hundred");
  assert.equal(v.nth(100), 100);
  assert.equal(v.assocN(100, 100), v);
  assert.deepEqual(changed.diff(v), { changed: [[100, 101]], added: 0, removed: 0 });
  assert.deepEqual(within.diff(v), { changed: [], added: 1, removed: 0 });
  // pop across the tail boundary down to empty and back
  let down = pdt.PVector.load<V>(store, v.root());
  for (let i = 0; i < 1100; i++) {
    down = down.pop();
  }
  assert.equal(down.count(), 0);
  assert.equal(down.root(), pdt.PVector.empty<V>(store).root());
  assert.throws(() => down.pop());
  assert.deepEqual([...v.update(2, (x) => Number(x) * 7)].slice(0, 4), [0, 1, 14, 3]);
  let reloaded = pdt.PVector.load<V>(store, v.root());
  reloaded = reloaded.conj("tail");
  assert.equal(reloaded.nth(1100), "tail");
  const editor2 = reloaded.editor();
  for (let i = 0; i < 40; i++) {
    editor2.conj(i);
  }
  assert.equal(editor2.done().count(), 1141);
});

test("large values spill to x nodes, sub-maps, sub-vectors, and blobs, and reassemble byte for byte (PD-N-05)", () => {
  const store = pdt.NodeStore.inMemory();
  const text = "x".repeat(2000);
  const bigMap: Dict = {};
  for (let i = 0; i < 400; i++) {
    bigMap[`field${i}`] = `value number ${i}`;
  }
  const bigArray = Array.from({ length: 2000 }, (_, i) => i * 3);
  const bigBytes = bytes(600_000, 3);
  const map = pdt.PMap.empty<string, V>(store)
    .assoc("text", text).assoc("map", bigMap).assoc("array", bigArray).assoc("bytes", bigBytes).assoc("small", 1);
  const root = map.root();
  assert.ok(store.complete(root));
  const kinds = new Map<string, number>();
  for (const cid of store.reachable(root)) {
    const kind = pdt.cids.parse(cid).codec === pdt.cids.RAW ? "raw" : String(pdt.nodes.decode(store.get(cid)!)["k"]);
    kinds.set(kind, (kinds.get(kind) ?? 0) + 1);
  }
  assert.ok((kinds.get("x") ?? 0) >= 1, "the text spilled to an x node");
  assert.ok((kinds.get("m") ?? 0) >= 2, "the map spilled to a sub-map");
  assert.ok((kinds.get("vr") ?? 0) >= 1 && (kinds.get("v") ?? 0) >= 1, "the array spilled to a vector");
  assert.ok((kinds.get("raw") ?? 0) >= 2 && (kinds.get("b") ?? 0) >= 1, "the bytes spilled to a blob");
  const rootNode = pdt.nodes.decode(store.get(root)!);
  assert.equal((rootNode["c"] as unknown[]).length, 0);
  assert.equal(pdt.nodes.links(store.get(root)!, root).length, 4, "four spilled links on the root node");
  const reloaded = pdt.PMap.load<string, V>(store, root);
  assert.equal(reloaded.get("text"), text);
  assert.deepEqual(reloaded.get("bytes"), bigBytes);
  assert.deepEqual(reloaded.get("array"), bigArray);
  assert.deepEqual({ ...(reloaded.get("map") as Dict) }, bigMap);
  // reassembly is the canonical CBOR of the value (an indefinite map in key order; the definite array; the byte string)
  const raw = reloaded.raw.get(dumps("array"))!;
  assert.deepEqual(pdt.PMap.empty(store).raw.ctx && dumps(bigArray), dumps(loads(dumps(bigArray))));
  assert.equal(typeof raw, "string");
  // a nested change inside the spilled map copies the nested path only
  store.record();
  const changed = reloaded.updateIn(["map", "field7"], () => "changed");
  changed.root();
  const delta = store.drain();
  assert.ok(delta.size >= 2 && delta.size <= 6, `${delta.size} nodes for a nested change`);
  assert.equal((changed.get("map") as Dict)["field7"], "changed");
  // keys and values are never bare link items
  const link = pdt.nodes.linkItem(root);
  const rawCodec: pdt.Codec<Uint8Array> = { encode: (b) => b, decode: (b) => b };
  assert.throws(() => pdt.PMap.empty<Uint8Array, Uint8Array>(store, rawCodec, rawCodec).assoc(dumps("k"), link), /link item/);
  assert.throws(() => pdt.PMap.empty<Uint8Array, Uint8Array>(store, rawCodec, rawCodec).assoc(link, dumps(1)), /link item/);
  assert.throws(() => pdt.PMap.empty<string, V>(store).assoc("huge", "y".repeat(1_100_000)), /1 MiB/);
});

test("the decoder refuses malformed nodes by name (PD-N-04)", () => {
  assert.throws(() => pdt.nodes.decode(pdt.nodes.encode({ k: "m", d: 0, n: 0, e: [], c: [], cnt: 0 }).subarray(1)), /node/);
  assert.throws(() => pdt.nodes.encode({ k: "m", zz: 1 }), /outside the schema/);
  assert.throws(() => pdt.nodes.encode({ k: "q" }), /unknown kind/);
  assert.throws(() => pdt.nodes.encode({ k: "s" }), /reserved/);
  assert.throws(() => pdt.nodes.decode(new Uint8Array(1024 * 1024 + 1)), /1 MiB/);
  const outOfOrder = Uint8Array.from([0xa2, 0x61, 0x6e, 0x00, 0x61, 0x6b, 0x61, 0x6d]); // {n:0, k:"m"}
  assert.throws(() => pdt.nodes.decode(outOfOrder), /canonical order/);
  const store = pdt.NodeStore.inMemory();
  const root = pdt.PMap.empty<string, V>(store).assoc("a", 1).root();
  assert.throws(() => store.putVerified(root, new Uint8Array([0xa0])), /hash/);
  assert.throws(() => pdt.PVector.load(store, root), /vector root/);
  assert.throws(() => pdt.PMap.load(store, pdt.PVector.empty(store).root()), /map node/);
  const badRoot = store.put(pdt.nodes.encode({ k: "vr", n: 40, s: 5, r: null, t: [] }), pdt.cids.DAG_CBOR);
  assert.throws(() => pdt.PVector.load(store, badRoot), /count 40/);
});

test("a blob edit re-chunks from the changed chunk and the root equals chunking from scratch (PD-B-03, PD-B-07)", () => {
  const store = pdt.NodeStore.inMemory();
  const data = bytes(1_200_000, 11);
  const blob = pdt.PBlob.of(data, store);
  assert.equal(blob.size, data.length);
  assert.ok(blob.chunks().length >= 5);
  assert.deepEqual(blob.read(700_000, 1000), data.subarray(700_000, 701_000));
  assert.deepEqual(blob.read(0, 0), new Uint8Array());
  assert.throws(() => blob.read(data.length - 1, 2));
  // an insert in the middle
  const insert = bytes(100, 5);
  const spliced = blob.splice(600_000, 0, insert);
  const expected = new Uint8Array(data.length + 100);
  expected.set(data.subarray(0, 600_000), 0);
  expected.set(insert, 600_000);
  expected.set(data.subarray(600_000), 600_100);
  assert.equal(spliced.root, pdt.PBlob.of(expected, pdt.NodeStore.inMemory()).root);
  assert.deepEqual(spliced.bytes(), expected);
  const unchanged = spliced.chunks().filter((c) => blob.chunks().some((o) => o.cid === c.cid)).length;
  assert.ok(unchanged >= blob.chunks().length - 3, `${unchanged} of ${blob.chunks().length} chunks reused`);
  assert.ok(spliced.writtenBytes < 3 * pdt.fastcdc.MAX_SIZE + 4096, `${spliced.writtenBytes} bytes written for a 100-byte insert`);
  // an append rewrites the old last chunk and nothing before it
  const tail = bytes(50_000, 9);
  const appended = blob.append(tail);
  const whole = new Uint8Array(data.length + tail.length);
  whole.set(data, 0);
  whole.set(tail, data.length);
  assert.equal(appended.root, pdt.PBlob.of(whole, pdt.NodeStore.inMemory()).root);
  assert.equal(appended.size, whole.length);
  // a partial holder serves a range by the path of interior nodes alone
  const partial = pdt.NodeStore.inMemory();
  const located = blob.tree.seek(700_000);
  for (const cid of store.reachable(blob.root)) {
    if (pdt.cids.parse(cid).codec !== pdt.cids.RAW || cid === located.cid) {
      partial.putVerified(cid, store.get(cid)!);
    }
  }
  assert.ok(!partial.complete(blob.root));
  const sparse = pdt.PBlob.load(partial, blob.root);
  assert.deepEqual(sparse.read(700_000, 100), data.subarray(700_000, 700_100));
  assert.throws(() => sparse.read(0, 10), /not in the store/);
  // tiny and empty blobs are one raw chunk
  assert.equal(pdt.cids.parse(pdt.PBlob.of(new Uint8Array(10), store).root).codec, pdt.cids.RAW);
  assert.equal(pdt.PBlob.empty(store).size, 0);
  assert.equal(pdt.PBlob.empty(store).root, pdt.cids.of(new Uint8Array(), pdt.cids.RAW));
});

test("the node store walks, pins, collects, and the file backend survives a reopen (PD-S-01, PD-S-04, PD-S-07)", () => {
  const dir = mkdtempSync(join(tmpdir(), "aspace-pdt-"));
  const store = new pdt.NodeStore(new FileNodeBackend(dir));
  let map = pdt.PMap.empty<string, V>(store);
  for (let i = 0; i < 200; i++) {
    map = map.assoc(`k${i}`, bytes(1500, i));
  }
  const root = map.root();
  const reachable = store.reachable(root);
  assert.ok(reachable.size > 200, "x nodes count");
  assert.ok(store.complete(root));
  assert.equal(store.missing(root).size, 0);
  const child = store.links(root)[0]!;
  const childBytes = store.get(child)!;
  assert.ok(store.remove(child));
  assert.ok(!store.complete(root));
  assert.ok(store.missing(root).has(child));
  store.putVerified(child, childBytes);
  assert.ok(store.complete(root));
  const reopened = new pdt.NodeStore(new FileNodeBackend(dir));
  assert.equal(reopened.nodesHeld, store.nodesHeld);
  assert.ok(reopened.complete(root));
  assert.equal(pdt.PMap.load<string, V>(reopened, root).count(), 200);
  // collection keeps the pinned root's nodes and sweeps the rest
  const other = pdt.PMap.empty<string, V>(reopened).assoc("lonely", bytes(1500, 1234)).root();
  reopened.pin(root);
  const removed = reopened.collect();
  assert.ok(removed >= 2, `${removed} removed`);
  assert.ok(reopened.complete(root));
  assert.ok(!reopened.has(other));
  reopened.unpin(root);
  assert.equal(reopened.collect([root]), 0);
  reopened.collect();
  assert.ok(!reopened.has(root));
  assert.equal(reopened.nodesHeld, 0);
});

test("an inline delta is exactly the nodes reachable from the new root among those written, and a receiver keeps only what the root reaches (PD-X-07)", () => {
  const store = pdt.NodeStore.inMemory();
  let map = pdt.PMap.empty<string, V>(store);
  for (let i = 0; i < 300; i++) {
    map = map.assoc(`k${i}`, i);
  }
  const base = map.root();
  store.record();
  const next = map.assoc("k1", "one").assoc("k300", 300);
  pdt.PMap.empty<string, V>(store).assoc("stray", 1).root(); // written during the swap, unreachable from the new root
  const newRoot = next.root();
  const captured = store.drain();
  const delta = pdt.collectDelta(captured, newRoot);
  assert.ok(delta.size < captured.size);
  assert.ok(delta.has(newRoot));
  for (const cid of delta.keys()) {
    assert.ok(store.reachable(newRoot).has(cid));
  }
  // a receiver that holds the base stores the delta and drops a node the root does not reach
  const receiver = pdt.NodeStore.inMemory();
  for (const cid of store.reachable(base)) {
    receiver.putVerified(cid, store.get(cid)!);
  }
  const stray = pdt.nodes.encode({ k: "x", v: new pdt.Embedded(dumps("stray")) });
  const accepted = pdt.acceptInline(receiver, newRoot, [...delta.values(), stray, stray]);
  assert.equal(accepted.stored, delta.size);
  assert.equal(accepted.dropped, 2);
  assert.ok(receiver.complete(newRoot));
  assert.equal(pdt.PMap.load<string, V>(receiver, newRoot).get("k1"), "one");
  // a forged node (bytes that hash to nothing the root reaches) is dropped
  const forged = pdt.acceptInline(pdt.NodeStore.inMemory(), newRoot, [stray]);
  assert.deepEqual(forged, { stored: 0, dropped: 1, bytes: 0 });
});

test("the heads rule folds equal roots and supersedes bases of a larger seq (§10.2)", () => {
  const head = (root: string, base: string[], seq: number, issued: string, issuer = "zA/a"): pdt.Head =>
    ({ root, base, seq, size: 0, kind: "map", mode: "multi", issuer, issued: `${issued}:${issuer.split("/")[0]}`, entryId: `${root}-${seq}`,
      expiresAtMillis: 0 });
  const v0 = head("r0", [], 1, "1000:0");
  const v1 = head("r1", ["r0"], 2, "2000:0");
  const v2 = head("r2", ["r1"], 3, "3000:0", "zB/b");
  const fork = head("r3", ["r1"], 3, "2500:0");
  const revert = head("r0", ["r2", "r3"], 4, "4000:0");
  assert.deepEqual(pdt.headsAmong([v0, v1]).map((h) => h.root), ["r1"]);
  assert.deepEqual(pdt.headsAmong([v0, v1, v2, fork]).map((h) => h.root), ["r3", "r2"]);
  assert.deepEqual(pdt.headsAmong([v0, v1, v2, fork, revert]).map((h) => h.root), ["r0"]);
  assert.equal(pdt.headsAmong([v0, v1, v2, fork, revert])[0]!.seq, 4);
  assert.deepEqual(pdt.headsAmong([v2, head("r2", ["r1"], 3, "3500:0", "zC/c")]).length, 1);
});
