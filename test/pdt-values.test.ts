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
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { CborDouble, canonicalMap, dumps, loads } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import { FileNodeBackend } from "../src/node/node-store.js";
import * as pdt from "../src/pdt/index.js";
import { ISSUED_ATTR, ISSUER_ATTR, MAX_ATTRS_BYTES, MAX_BASE_STEPS, MAX_SEQ, PREF_TYPE, Refs, pref } from "../src/pdt/refs.js";
import type { TreeExchange } from "../src/pdt/tree.js";
import { Peer } from "../src/peer.js";
import { Space } from "../src/space.js";
import * as wire from "../src/wire.js";
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

const NOW = 1_700_000_000_000;

/** A refs engine over an in-memory store on a peer whose wall reads `wall`, with `exchange` as its tree exchange. */
function engine(wall = NOW, exchange: TreeExchange | null = null): { refs: Refs; store: pdt.NodeStore; peer: Peer } {
  const store = pdt.NodeStore.inMemory();
  const peer = new Peer(Identity.generate(), "zPdtValuesTest", () => wall);
  return { refs: new Refs(peer, store, exchange), store, peer };
}

/** The engine's state of the ref `name` of `kind` in the space `s`, opened through `Refs.ref`. */
type RefState = { spaceId: string; known: Map<string, pdt.Head>; ignoredEntries: Set<string> };

function refState(refs: Refs, name = "doc", kind: pdt.RefKindName = "map"): RefState {
  refs.ref(new Space(refs.peer, "s"), name, kind);
  return (refs as unknown as { states: Map<string, RefState> }).states.get(`s/${name}`)!;
}

/** The head `toHead` reads from an entry issued at `issued` by `peer/a` whose payload is `payload`. */
function headOf(refs: Refs, state: RefState, payload: Uint8Array, entryId: string, issued = `${NOW}:0:peer`): pdt.Head | null {
  const record = { spaceId: state.spaceId, type: PREF_TYPE, payload, issued, issuer: "peer/a", entryId,
    lease: { expiresAtMillis: NOW + 60_000 } };
  return (refs as unknown as { toHead(state: unknown, dto: Dict): pdt.Head | null }).toHead(state, { record });
}

/** A map head named `doc` whose root hashes `seed`, with `attrs` as given, encoded as a writer writes it. */
function prefBytes(seed: string, attrs: Dict | null = null, fields: Partial<pdt.PRefFields> = {}): Uint8Array {
  const head = pref({ name: "doc", kind: "map", root: pdt.cids.of(new TextEncoder().encode(seed), 0x55), seq: 1, size: 1, ...fields });
  if (attrs !== null) {
    head["attrs"] = canonicalMap(attrs);
  }
  return dumps(head);
}

type Vector = { id: string; carrier: string; hex: string; verdict: "accept" | "refuse-undecodable" };

const VECTORS: Vector[] = (JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "test",
  "wire-encoding-vectors.json"), "utf-8")) as { vectors: Vector[] }).vectors;

test("every PRef vector is a head exactly when the wire encoding accepts it, and each refusal counts once in headsIgnored (R1, R3)", () => {
  // HLC round six, 2026-11-08 (F1, F3, R1, R3): a PRef is a protocol record. A field of the wrong
  // kind, attrs written as null, keys out of order, an item under a longer head, and a null or
  // non-text value under any attr but pdt.issued and pdt.issuer make it undecodable, and the reader
  // ignores the head and counts it in headsIgnored once per entry, as Java counts it.
  const wall = 1_800_000_000_000;
  const { refs } = engine(wall);
  const state = refState(refs, "facts");
  const own = `${wall - 1000}:0:peer`;
  const javaIssuer = "z6M1N9PyyHGkJfLZRmQ4VjAypZUi5uuUm8UDMHK1YfieJ";
  const advisory: { [id: string]: [string, string] } = {
    "pref-01": [`${wall}:0:${javaIssuer}`, `${javaIssuer}/java`],
    "pref-02": [own, "peer/a"],
    "pref-03": [own, "peer/a"],
    "pref-04": [own, "peer/a"],
    "pref-05": [own, "peer/a"],
    "pref-08": [`${wall}:0:${javaIssuer}`, "peer/a"],
  };
  const prefs = VECTORS.filter((v) => v.carrier === "pref");
  assert.equal(prefs.length, 12);
  let refused = 0;
  for (const vector of prefs) {
    const bytes = Uint8Array.from(Buffer.from(vector.hex, "hex"));
    for (let read = 0; read < 2; read++) {
      const head = headOf(refs, state, bytes, vector.id, own);
      if (vector.verdict === "accept") {
        assert.notEqual(head, null, vector.id);
        assert.deepEqual([head!.issued, head!.issuer], advisory[vector.id], vector.id);
      } else {
        assert.equal(head, null, vector.id);
      }
    }
    refused += vector.verdict === "accept" ? 0 : 1;
    assert.equal(refs.headsIgnored, refused, `${vector.id} counts once`);
  }
  assert.equal(refused, 6);
});

test("pdt.issued and pdt.issuer that are null or no text fall back to the entry's own pair together, and the head stays (R1, E10)", () => {
  const { refs } = engine();
  const state = refState(refs);
  const advisory = `${NOW + 9}:0:peer`;
  // HLC round six, 2026-11-08 (R1): the reserved pair holds any application value. A pdt.issued that
  // is absent, null, no text, or no acceptable stamp, or a pdt.issuer that is present and null, no
  // text, or no agent id under Java's grammar (R5), leaves the entry's own stamp and issuer together.
  const fallBack: Dict[] = [
    { [ISSUED_ATTR]: null, [ISSUER_ATTR]: "peer/b" },
    { [ISSUED_ATTR]: 7, [ISSUER_ATTR]: "peer/b" },
    { [ISSUED_ATTR]: new TextEncoder().encode(advisory), [ISSUER_ATTR]: "peer/b" },
    { [ISSUED_ATTR]: [advisory], [ISSUER_ATTR]: "peer/b" },
    { [ISSUER_ATTR]: "peer/b" },
    { [ISSUED_ATTR]: advisory, [ISSUER_ATTR]: null },
    { [ISSUED_ATTR]: advisory, [ISSUER_ATTR]: 7 },
    { [ISSUED_ATTR]: advisory, [ISSUER_ATTR]: new TextEncoder().encode("peer/b") },
    { [ISSUED_ATTR]: advisory, [ISSUER_ATTR]: { peer: "b" } },
    { [ISSUED_ATTR]: advisory, [ISSUER_ATTR]: "peer/b/c" },
    { [ISSUED_ATTR]: advisory, [ISSUER_ATTR]: "peer/b:c" },
  ];
  for (const [index, attrs] of fallBack.entries()) {
    const head = headOf(refs, state, prefBytes(`fallback-${index}`, attrs), `e-fallback-${index}`);
    assert.notEqual(head, null, `the head stays: ${index}`);
    assert.deepEqual([head!.issued, head!.issuer], [`${NOW}:0:peer`, "peer/a"], `falls back together: ${index}`);
  }
  const taken = headOf(refs, state, prefBytes("taken", { note: "x", [ISSUED_ATTR]: advisory, [ISSUER_ATTR]: "peer/b" }), "e-taken")!;
  assert.deepEqual([taken.issued, taken.issuer], [advisory, "peer/b"]);
  assert.equal(refs.headsIgnored, 0, "the reserved pair counts nothing");
});

test("a null or non-text value under any other attr makes the PRef undecodable, ignored and counted (R1, R3)", () => {
  const { refs } = engine();
  const state = refState(refs);
  const others: Dict[] = [{ note: null }, { note: 7 }, { note: true }, { note: new Uint8Array([1]) }, { note: ["x"] },
    { note: { a: "b" } }, { note: 2n ** 64n }];
  for (const [index, attrs] of others.entries()) {
    assert.equal(headOf(refs, state, prefBytes(`other-${index}`, { ...attrs, [ISSUED_ATTR]: `${NOW + 9}:0:peer` }), `e-other-${index}`),
      null, String(index));
  }
  assert.equal(refs.headsIgnored, others.length);
});

test("the attrs bound counts the UTF-8 bytes of keys and text values, and nothing for a reserved attr that is no text (R1)", () => {
  const over = `attrs larger than ${MAX_ATTRS_BYTES} bytes`;
  const head = (attrs: Dict): Dict => ({ ...pref({ name: "doc", kind: "map",
    root: pdt.cids.of(new TextEncoder().encode("bound"), 0x55), seq: 1, size: 1 }), attrs });
  // the key "a" counts one byte and the key "é" two
  assert.equal(pdt.prefViolation(head({ a: "x".repeat(MAX_ATTRS_BYTES - 3), "é": "" })), null);
  assert.equal(pdt.prefViolation(head({ a: "x".repeat(MAX_ATTRS_BYTES - 2), "é": "" })), over);
  assert.equal(pdt.prefViolation(head({ a: "é".repeat(MAX_ATTRS_BYTES / 2) })), over);
  const filler = "x".repeat(MAX_ATTRS_BYTES - 1 - ISSUED_ATTR.length - ISSUER_ATTR.length);
  assert.equal(pdt.prefViolation(head({ a: filler, [ISSUED_ATTR]: ["0123456789".repeat(100)], [ISSUER_ATTR]: 2n ** 70n })), null);
  assert.equal(pdt.prefViolation(head({ a: `${filler}x`, [ISSUED_ATTR]: null, [ISSUER_ATTR]: null })), over);
});

test("a pdt.issued past the reader's wall + MAX_DRIFT + 5 s falls back to the entry's own pair (R2)", () => {
  const { refs } = engine();
  const state = refState(refs);
  // HLC round six, 2026-11-08 (R2): a rewrite's stamp can no longer win every conflict by stamping ahead.
  const ceiling = NOW + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_MARGIN_MILLIS;
  const atCeiling = headOf(refs, state, prefBytes("ceiling", { [ISSUED_ATTR]: `${ceiling}:0:peer`, [ISSUER_ATTR]: "peer/b" }), "e-at")!;
  assert.deepEqual([atCeiling.issued, atCeiling.issuer], [`${ceiling}:0:peer`, "peer/b"]);
  const ahead = headOf(refs, state, prefBytes("ahead", { [ISSUED_ATTR]: `${ceiling + 1}:0:peer`, [ISSUER_ATTR]: "peer/b" }), "e-ahead")!;
  assert.deepEqual([ahead.issued, ahead.issuer], [`${NOW}:0:peer`, "peer/a"]);
  const far = headOf(refs, state, prefBytes("far", { [ISSUED_ATTR]: `${2n ** 62n}:0:peer` }), "e-far")!;
  assert.deepEqual([far.issued, far.issuer], [`${NOW}:0:peer`, "peer/a"]);
  assert.equal(refs.headsIgnored, 0);
});

test("headsIgnored counts a bound violation, another kind, another ref name, and an undecodable PRef, once per entry (R3)", () => {
  const { refs } = engine();
  const state = refState(refs);
  const ignored: [string, Uint8Array][] = [
    ["violation", dumps({ ...pref({ name: "doc", kind: "map", root: "not-a-cid", seq: 1, size: 1 }) })],
    ["kind", prefBytes("kind", null, { kind: "set" })],
    ["name", dumps(pref({ name: "other", kind: "map", root: pdt.cids.of(new TextEncoder().encode("name"), 0x55), seq: 1, size: 1 }))],
    ["float seq", dumps({ ...pref({ name: "doc", kind: "map", root: pdt.cids.of(new TextEncoder().encode("f"), 0x55), seq: 1, size: 1 }),
      seq: new CborDouble(1) })],
    ["unknown field", dumps({ ...pref({ name: "doc", kind: "map", root: pdt.cids.of(new TextEncoder().encode("u"), 0x55), seq: 1, size: 1 }),
      extra: "x" })],
    ["no record", dumps("text")],
    ["not cbor", Uint8Array.of(0xff)],
  ];
  for (const [why, payload] of ignored) {
    assert.equal(headOf(refs, state, payload, `e-${why}`), null, why);
    assert.equal(headOf(refs, state, payload, `e-${why}`), null, why);
  }
  assert.equal(refs.headsIgnored, ignored.length);
  assert.ok(state.ignoredEntries.has("e-kind"));
  assert.notEqual(headOf(refs, state, prefBytes("fine"), "e-fine"), null);
  assert.equal(refs.headsIgnored, ignored.length);
});

/** Writes a map version holding `entries` into the store and records it among the known versions. */
function version(known: Map<string, pdt.Head>, store: pdt.NodeStore, entries: [string, V][], base: string[], seq: number,
                 issued: string, issuer: string): pdt.Head {
  let map = pdt.PMap.empty<string, V>(store);
  for (const [k, v] of entries) {
    map = map.assoc(k, v);
  }
  const head: pdt.Head = { root: map.root(), base, seq, size: map.count(), kind: "map", mode: "multi", issuer,
    issued: `${issued}:${issuer.split("/")[0]}`, entryId: `${issuer}-${seq}`, expiresAtMillis: NOW + 60_000 };
  known.set(head.root, head);
  return head;
}

/** The merged value of `heads` (in merge order) and the conflict reasons the merge reported. */
async function merged(refs: Refs, known: Map<string, pdt.Head>, heads: pdt.Head[]): Promise<{ value: pdt.PMap<string, V>; reasons: string[] }> {
  const reasons: string[] = [];
  // PDT 2 phase 7 (P2-V-02): the walk also reads the chain nodes a state learned, none here
  const state = { name: "doc", kind: pdt.kindNamed("map"), known, ancestry: new Map(), chain: new Map(),
    conflictListeners: [(e: pdt.PConflict) => reasons.push(e.reason)] };
  const value = await (refs as unknown as { materialize(state: unknown, heads: pdt.Head[]): Promise<unknown> })
    .materialize(state, [...heads].sort(pdt.mergeOrder));
  return { value: value as pdt.PMap<string, V>, reasons };
}

test("two writers whose histories start from empty and share no version merge to the union of their keys (E16)", async () => {
  const { refs, store } = engine();
  const known = new Map<string, pdt.Head>();
  // HLC round five, 2026-11-08 (E16): two base walks that share no version but each end at a first
  // version within the 64-step limit share the empty value as their base.
  const a1 = version(known, store, [["a1", 1]], [], 1, "1000:0", "zA/a");
  const a2 = version(known, store, [["a1", 1], ["a2", 2]], [a1.root], 2, "2000:0", "zA/a");
  const b1 = version(known, store, [["b1", 1]], [], 1, "1100:0", "zB/b");
  const b2 = version(known, store, [["b1", 1], ["b2", 2], ["both", "b"]], [b1.root], 2, "2100:0", "zB/b");
  const b3 = version(known, store, [["b1", 1], ["b2", 2], ["b3", 3], ["both", "b"]], [b2.root], 3, "3100:0", "zB/b");
  const a3 = version(known, store, [["a1", 1], ["a2", 2], ["both", "a"]], [a2.root], 3, "3000:0", "zA/a");
  const two = await merged(refs, known, [a2, b2]);
  assert.deepEqual([...two.value.keys()].sort(), ["a1", "a2", "b1", "b2", "both"]);
  assert.deepEqual(two.reasons, []);
  // a first version against a longer history merges from empty too
  const mixed = await merged(refs, known, [a1, b3]);
  assert.deepEqual([...mixed.value.keys()].sort(), ["a1", "b1", "b2", "b3", "both"]);
  // a key both writers set to different values takes the later head, as any three-way merge does
  const clash = await merged(refs, known, [a3, b3]);
  assert.deepEqual([...clash.value.keys()].sort(), ["a1", "a2", "b1", "b2", "b3", "both"]);
  assert.equal(clash.value.get("both"), "b");
  assert.deepEqual(clash.reasons, ["LATER_HLC"]);
});

test("a base walk that reaches an unknown version or the step limit gives no common base, and a shared version stays the base (E16)", async () => {
  const { refs, store } = engine();
  const known = new Map<string, pdt.Head>();
  const a1 = version(known, store, [["a1", 1]], [], 1, "1000:0", "zA/a");
  const a2 = version(known, store, [["a1", 1], ["a2", 2]], [a1.root], 2, "2000:0", "zA/a");
  // a version whose base this replica never saw: the walk does not end at a first version
  const orphan = version(known, store, [["o", 1]], [pdt.cids.of(new TextEncoder().encode("unseen"), 0x71)], 2, "2100:0", "zB/b");
  const unseen = await merged(refs, known, [a2, orphan]);
  assert.deepEqual([...unseen.value.keys()], ["o"]);
  assert.deepEqual(unseen.reasons, ["NO_COMMON_BASE"]);
  // a history longer than the walk bound: its first version lies one step past the limit. HLC round
  // five, 2026-11-08 (E16): the walk holds the version it first reaches at step MAX_BASE_STEPS and
  // follows none of its bases, as Java's Refs.ancestors does, so the limit cuts off step 65.
  let deep = version(known, store, [["d", 0]], [], 1, "5000:0", "zB/b");
  for (let i = 1; i <= MAX_BASE_STEPS + 1; i++) {
    deep = version(known, store, [["d", i]], [deep.root], i + 1, `${5000 + i}:0`, "zB/b");
  }
  const past = await merged(refs, known, [a2, deep]);
  assert.deepEqual([...past.value.keys()], ["d"]);
  assert.deepEqual(past.reasons, ["NO_COMMON_BASE"]);
  // one step shorter, the first version lies exactly at the limit, inside the walk
  const inside = known.get(deep.base[0]!)!;
  const within = await merged(refs, known, [a2, inside]);
  assert.deepEqual([...within.value.keys()].sort(), ["a1", "a2", "d"]);
  assert.deepEqual(within.reasons, []);
  // two forks of a shared version keep that version as their base: a key one side removed stays removed
  const left = version(known, store, [["a2", 2], ["l", 1]], [a2.root], 3, "3000:0", "zA/a");
  const right = version(known, store, [["a1", 1], ["a2", 2], ["r", 1]], [a2.root], 3, "3100:0", "zC/c");
  const forks = await merged(refs, known, [left, right]);
  assert.deepEqual([...forks.value.keys()].sort(), ["a2", "l", "r"]);
});

test("the base walk holds the version it first reaches at the step limit, as Java's Refs.ancestors does (E16)", async () => {
  const { refs, store } = engine();
  const known = new Map<string, pdt.Head>();
  // HLC round five, 2026-11-08 (E16): Java, Python, and Ruby add the root first reached at step
  // MAX_BASE_STEPS to the walk and follow none of its bases, so a version shared at exactly that
  // depth stays the common base: the key one side removed stays removed.
  const shared = version(known, store, [["s", 1], ["gone", 1]], [], 1, "1000:0", "zA/a");
  let left = shared;
  for (let i = 1; i <= MAX_BASE_STEPS; i++) {
    left = version(known, store, [["s", 1], ["gone", 1], ["l", i]], [left.root], i + 1, `${1000 + i}:0`, "zA/a");
  }
  const right = version(known, store, [["s", 1], ["r", 1]], [shared.root], 2, "9000:0", "zC/c");
  const forks = await merged(refs, known, [left, right]);
  assert.deepEqual([...forks.value.keys()].sort(), ["l", "r", "s"]);
  assert.deepEqual(forks.reasons, []);
});

test("a history whose first version a revert recreated still merges from empty, as Python and Ruby merge it (E16)", async () => {
  const { refs, store } = engine();
  const known = new Map<string, pdt.Head>();
  // HLC round five, 2026-11-08 (E16): a revert to the first version gives that root a base, so the
  // walk holds no version with an empty base. The replica knows every version on the walk and the
  // limit cut nothing off, so the history still began at the empty value, and the merge keeps every
  // key of both writers.
  const first = version(known, store, [["c", 1]], [], 1, "1000:0", "zA/a");
  const second = version(known, store, [["c", 2]], [first.root], 2, "2000:0", "zA/a");
  known.get(first.root)!.base = [second.root];
  const b1 = version(known, store, [["b1", 1]], [], 1, "1100:0", "zB/b");
  const b2 = version(known, store, [["b1", 1], ["b2", 2]], [b1.root], 2, "2100:0", "zB/b");
  const both = await merged(refs, known, [second, b2]);
  assert.deepEqual([...both.value.keys()].sort(), ["b1", "b2", "c"]);
  assert.deepEqual(both.reasons, []);
});

/** A tree fetch that lands its root's nodes from `source` when awaited, or fails when `source` lacks them. */
class FakeFetch {
  done = false;
  failure: string | null = null;
  bytesReceived = 0;

  constructor(private readonly root: string, private readonly source: pdt.NodeStore, private readonly target: pdt.NodeStore) {}

  get complete(): boolean {
    return this.done && this.failure === null;
  }

  async await(_timeoutMillis: number): Promise<boolean> {
    if (!this.done) {
      this.done = true;
      if (this.source.complete(this.root)) {
        for (const cid of this.source.reachable(this.root)) {
          if (!this.target.has(cid)) {
            this.target.putVerified(cid, this.source.get(cid)!);
          }
        }
      } else {
        this.failure = "no holder";
      }
    }
    return this.complete;
  }

  cancel(): void {
    this.done = true;
    this.failure ??= "cancelled";
  }
}

/** An exchange whose fetches copy from `source`; `asked` lists every root a fetch started for. */
function fakeExchange(source: pdt.NodeStore, target: () => pdt.NodeStore): { exchange: TreeExchange; asked: string[]; fetches: FakeFetch[] } {
  const asked: string[] = [];
  const fetches: FakeFetch[] = [];
  const exchange = {
    fetchTree: (root: string) => {
      asked.push(root);
      const fetch = new FakeFetch(root, source, target());
      fetches.push(fetch);
      return fetch;
    },
    holdTree: () => {},
    release: () => {},
  };
  return { exchange: exchange as unknown as TreeExchange, asked, fetches };
}

/** Copies every node `root` reaches from `from` into `to`. */
function copyTree(from: pdt.NodeStore, to: pdt.NodeStore, root: string): void {
  for (const cid of from.reachable(root)) {
    if (!to.has(cid)) {
      to.putVerified(cid, from.get(cid)!);
    }
  }
}

test("basesFetched counts a base fetch when it settles, as Java's Refs.settle counts it, and never one that failed (R4)", async () => {
  // HLC round six, 2026-11-08 (R4): Java counts basesFetched when a base fetch completes and settles,
  // and its ensureBases fetches only a base this engine saw a head of; this client counted every
  // base fetch it started, failed ones and roots it never saw a record of included.
  const source = pdt.NodeStore.inMemory();
  let target: pdt.NodeStore | null = null;
  const fake = fakeExchange(source, () => target!);
  const { refs, store } = engine(NOW, fake.exchange);
  target = store;
  const state = refState(refs) as RefState & { pending: Map<string, unknown>; conflictListeners: ((e: pdt.PConflict) => void)[] };
  const reasons: string[] = [];
  state.conflictListeners.push((e) => reasons.push(e.reason));
  const base = version(state.known, source, [["k", 1], ["gone", 1]], [], 1, "1000:0", "zA/a");
  const left = version(state.known, source, [["k", 1], ["gone", 1], ["l", 1]], [base.root], 2, "2000:0", "zA/a");
  const right = version(state.known, source, [["k", 1], ["r", 1]], [base.root], 2, "2100:0", "zC/c");
  copyTree(source, store, left.root);
  copyTree(source, store, right.root);
  assert.equal(store.complete(base.root), false);
  const materialize = (heads: pdt.Head[]): Promise<unknown> =>
    (refs as unknown as { materialize(state: unknown, heads: pdt.Head[]): Promise<unknown> }).materialize(state, heads);

  // the common base fetched and settled: one base, and the merge removes the key the right side removed
  const value = await materialize([left, right]) as pdt.PMap<string, V>;
  assert.deepEqual([...value.keys()].sort(), ["k", "l", "r"]);
  assert.deepEqual([refs.basesFetched, reasons], [1, []]);

  // a base fetch that fails counts nothing, and the merge has no base
  const lost = version(state.known, pdt.NodeStore.inMemory(), [["lost", 1]], [], 1, "1000:0", "zA/a");
  const l2 = version(state.known, source, [["l2", 1]], [lost.root], 2, "2000:0", "zA/a");
  const r2 = version(state.known, source, [["r2", 1]], [lost.root], 2, "2100:0", "zC/c");
  copyTree(source, store, l2.root);
  copyTree(source, store, r2.root);
  await materialize([l2, r2]);
  assert.deepEqual([refs.basesFetched, reasons], [1, ["NO_COMMON_BASE"]]);

  // a head that arrives held fetches only the bases this engine saw a record of; the count waits for the settle
  const arrived = (head: pdt.Head): void =>
    (refs as unknown as { arrived(state: unknown, head: pdt.Head, own: boolean): void }).arrived(state, head, false);
  const seenBase = version(state.known, source, [["s", 1]], [], 1, "3000:0", "zA/a");
  const unseen = pdt.cids.of(new TextEncoder().encode("never seen as a head"), 0x71);
  const next = version(state.known, source, [["s", 2]], [seenBase.root, unseen], 2, "3100:0", "zA/a");
  copyTree(source, store, next.root);
  const before = fake.asked.length;
  arrived(next);
  assert.deepEqual(fake.asked.slice(before), [seenBase.root], "no fetch for a base never seen as a head");
  assert.equal(refs.basesFetched, 1, "a base fetch under way counts nothing yet");
  await fake.fetches.at(-1)!.await(0);
  refs.tick();
  assert.ok(store.complete(seenBase.root));
  assert.equal(refs.basesFetched, 2, "the base counts when it settles");
});

test("a head whose fetch failed counts once per cause in headsLate across reads and ticks, and a seq of 2^53 is a head (R3)", async () => {
  // HLC round six, 2026-11-08 (R3): Java counts an entry once, since its Set.add answers whether the
  // entry is new; a JavaScript Set.add answers the set, so the deref and the tick each counted it.
  const source = pdt.NodeStore.inMemory();
  let target: pdt.NodeStore | null = null;
  const fake = fakeExchange(source, () => target!);
  const { refs, store, peer } = engine(NOW, fake.exchange);
  target = store;
  const ref = refs.ref<pdt.PMap<string, V>>(new Space(peer, "s"), "doc", "map");
  const lost = pdt.PMap.empty<string, V>(pdt.NodeStore.inMemory()).assoc("lost", 1).root();
  const head = pref({ name: "doc", kind: "map", root: lost, seq: MAX_SEQ, size: 1 });
  peer.writeEntry("s", PREF_TYPE, head, "a", 60_000, null, pdt.prefTags(head));
  assert.equal(ref.heads().length, 0);
  assert.equal(refs.liveEntries((refs as unknown as { states: Map<string, never> }).states.get("s/doc")!).length, 1,
    "a seq of 2^53 is within the bound, as Java's PRef.violation reads it");
  assert.equal((await ref.deref()).count(), 0);
  // swarm retries (ROBUSTNESS.md 10.3 E2): a root still loading is late, apart from the heads ignored for a fault
  assert.equal(refs.headsIgnored, 0);
  assert.equal(refs.headsLate.timeout + refs.headsLate.failedFetch, 1);
  refs.tick();
  await ref.deref();
  refs.tick();
  assert.equal(refs.headsIgnored, 0);
  assert.ok(refs.headsLate.timeout <= 1 && refs.headsLate.failedFetch <= 1, "each cause counts once while the entry lives");
});

test("an entry ignored while it stays live counts once in headsIgnored across ticks, as Java prunes against every entry read (R3)", () => {
  // HLC round six, 2026-11-08 (R3): Java's liveEntries keeps the id of every entry of the name it
  // read, well formed or not, and prunes the ignored entries against those ids, so an entry of
  // another kind counts once while it stays live. Pruned against the heads alone, each tick forgot
  // the entry and the next read counted it again.
  const { refs, peer } = engine();
  const ref = refs.ref<pdt.PMap<string, V>>(new Space(peer, "s"), "doc", "map");
  const root = pdt.PMap.empty<string, V>(pdt.NodeStore.inMemory()).assoc("x", 1).root();
  const set = pref({ name: "doc", kind: "set", root, seq: 1, size: 1 });
  peer.writeEntry("s", PREF_TYPE, set, "a", 60_000, null, pdt.prefTags(set));
  assert.equal(ref.heads().length, 0);
  assert.equal(refs.headsIgnored, 1);
  for (let i = 0; i < 3; i++) {
    refs.tick();
  }
  assert.equal(ref.heads().length, 0);
  assert.equal(refs.headsIgnored, 1);
});

test("a version a later record recreates walks that record's bases first, as Java's Refs.toHead joins them (R4)", async () => {
  // HLC round six, 2026-11-08 (R4): a record of a known root with a larger seq lists its own bases
  // first and then the bases the version held, as Java's toHead joins them. The base walk visits the
  // bases in that order, so the order picks the common base when two candidates tie.
  const { refs, store } = engine();
  const state = refState(refs);
  const roots = new Map<string, string>();
  const root = (label: string): string => {
    if (!roots.has(label)) {
      roots.set(label, pdt.PMap.empty<string, V>(store).assoc("v", label).root());
    }
    return roots.get(label)!;
  };
  const read = (label: string, base: string[], seq: number, entryId: string): pdt.Head =>
    headOf(refs, state, dumps(pref({ name: "doc", kind: "map", root: root(label), base: base.map(root), seq, size: 1 })), entryId)!;
  read("p", [], 1, "e-p");
  read("q", [], 1, "e-q");
  read("x", ["p"], 2, "e-x");
  read("x", ["q", "p"], 5, "e-x-revert");
  const a = read("a", ["x"], 6, "e-a");
  const b = read("b", ["q", "p"], 3, "e-b");
  assert.deepEqual(state.known.get(root("x"))!.base, [root("q"), root("p")]);
  const base = await (refs as unknown as { commonBase(state: unknown, heads: pdt.Head[]): Promise<string | null> }).commonBase(state, [b, a]);
  assert.equal(base, root("q"));
});
