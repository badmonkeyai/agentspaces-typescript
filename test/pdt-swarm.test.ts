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
 * Refs and the tree exchange over an in-memory fleet (srad/agentspaces-pdt.md groups X and R, PD-C-05):
 * two in-process peers as `content.test.ts` wires them. A swap derefs on the other peer through the
 * inline delta alone; a version above the inline cap travels by request and the next version's fetch
 * carries only the delta against the held base; concurrent swaps converge on every peer with the
 * merge of §3.6.1 (and a both-side conflict takes the later head); a sealed group moves nodes under
 * the content key; a linear ref serialises writers through takes; a blob ref ships a file.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { loads } from "../src/cbor.js";
import * as pdt from "../src/pdt/index.js";
import type { Dict } from "../src/wire.js";
import { Network, closeAll, fleet, node, run } from "./pdt-fleet.js";
import type { Node, V } from "./pdt-fleet.js";

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

test("a swap derefs on the other peer through the inline delta alone (PD-X-07, PD-R-02, PD-R-03)", async () => {
  const nodes = fleet(2);
  const [a, b] = nodes as [Node, Node];
  try {
    const facts = a.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    const written = await facts.swap((m) => m.assoc("sky", "blue").assoc("grass", "green"));
    assert.equal(written.get("sky"), "blue");
    await run(nodes, 2);
    const theirs = b.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    const value = await theirs.deref();
    assert.equal(value.get("sky"), "blue");
    assert.equal(value.count(), 2);
    assert.equal(value.root(), written.root());
    assert.equal(b.pdt.refs.deltasInline, 1);
    assert.equal(b.pdt.refs.deltasFetched, 0);
    assert.equal(b.pdt.exchange!.fetches.size, 0);
    assert.equal(theirs.heads().length, 1);
    assert.deepEqual(theirs.heads()[0]!.base, []);
    // a second swap on a lists the first head as its base; b sees one head of seq 2 and the merged value
    const seen: string[] = [];
    theirs.watch((v) => seen.push(String((v as pdt.PMap<string, V>).get("sky"))));
    await facts.swap((m) => m.assoc("sky", "grey"));
    await run(nodes, 2);
    assert.deepEqual(seen, ["grey"]);
    const heads = theirs.heads();
    assert.equal(heads.length, 1);
    assert.equal(heads[0]!.seq, 2);
    assert.deepEqual(heads[0]!.base, [written.root()]);
    assert.equal((await theirs.deref()).get("sky"), "grey");
    assert.deepEqual(theirs.history(5).map((h) => h.root), [written.root()]);
    // the superseded own head is cancelled after the grace, on the tick
    await sleep(2100);
    await run(nodes, 2);
    assert.equal(a.pdt.refs.liveEntries(a.pdt.refs["states"].values().next().value!).length, 1);
    assert.equal(b.pdt.refs.liveEntries(b.pdt.refs["states"].values().next().value!).length, 1);
    assert.equal(b.pdt.stats()["heads"], 1);
  } finally {
    closeAll(nodes);
  }
});

test("a version above the inline cap travels by request, and the next one ships only its delta against the held base (PD-X-03, PD-X-06)", async () => {
  const nodes = fleet(2, { inlineDelta: 1024 });
  const [a, b] = nodes as [Node, Node];
  try {
    const facts = a.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    const big = await facts.swap((m) => {
      const editor = m.editor();
      for (let i = 0; i < 3000; i++) {
        editor.assoc(`key-${i}`, { n: i, text: `value ${i}` });
      }
      return editor.done();
    });
    const treeBytes = [...a.pdt.store.reachable(big.root())].reduce((sum, cid) => sum + a.pdt.store.get(cid)!.length, 0);
    assert.ok(treeBytes > 100_000, `${treeBytes} bytes of tree`);
    const head = facts.heads()[0]!;
    const record = loads(a.peer.payloadOf(a.peer.states.get(head.entryId)!)!) as Dict;
    assert.equal(record["nodes"], undefined, "the delta is above the inline cap: no nodes on the head");
    assert.equal(a.content.holdings(big.root()).length, 1, "the writer holds the root for the swarm");
    const theirs = b.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    for (let i = 0; i < 40 && b.pdt.refs.deltasFetched === 0; i++) {
      await run(nodes, 1);
    }
    assert.equal(b.pdt.refs.deltasFetched, 1);
    const first = b.pdt.refs.bytesReceived;
    assert.ok(first >= treeBytes, `${first} bytes fetched for ${treeBytes} bytes of tree`);
    assert.ok(b.pdt.store.complete(big.root()));
    const value = await theirs.deref();
    assert.equal(value.count(), 3000);
    assert.deepEqual({ ...(value.get("key-2999") as Dict) }, { n: 2999, text: "value 2999" });
    // the next version changes one entry: b holds the base, so the fetch carries the path only
    const next = await facts.swap((m) => m.assoc("key-17", "changed"));
    for (let i = 0; i < 40 && b.pdt.refs.deltasFetched < 2; i++) {
      await run(nodes, 1);
    }
    assert.equal(b.pdt.refs.deltasFetched, 2);
    const delta = b.pdt.refs.bytesReceived - first;
    assert.ok(delta > 0 && delta < treeBytes / 20, `${delta} delta bytes against ${treeBytes} bytes of tree`);
    assert.ok(delta > 1024, "the delta of a 3,000-entry map's path is above the (lowered) inline cap");
    assert.equal((await theirs.deref()).get("key-17"), "changed");
    assert.equal((await theirs.deref()).root(), next.root());
    assert.equal(b.pdt.exchange!.nodesStruck, 0);
    assert.ok(Number(a.pdt.exchange!.stats()["nodesServed"]) > 0);
  } finally {
    closeAll(nodes);
  }
});

test("concurrent swaps converge: a key-wise merge on both readers, the later head on a both-side conflict (PD-R-05, PD-R-06)", async () => {
  const nodes = fleet(2);
  const [a, b] = nodes as [Node, Node];
  const network = a.peer.network;
  try {
    const ra = a.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    const rb = b.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    const v0 = await ra.swap((m) => m.assoc("shared", 0).assoc("stable", "yes"));
    await run(nodes, 2);
    assert.equal((await rb.deref()).root(), v0.root());
    // neither writer sees the other's head until the network flushes
    network.holding = true;
    const va = await ra.swap((m) => m.assoc("from-a", 1).assoc("shared", "a"));
    await sleep(5); // a later HLC on b's head
    const vb = await rb.swap((m) => m.assoc("from-b", 2).assoc("shared", "b"));
    assert.deepEqual(ra.heads().map((h) => h.base), [[v0.root()]]);
    network.flush();
    await run(nodes, 3);
    assert.equal(ra.heads().length, 2);
    assert.equal(rb.heads().length, 2);
    const conflictsA: pdt.PConflict[] = [];
    ra.onConflict((e) => conflictsA.push(e));
    const mergedA = await ra.deref();
    const mergedB = await rb.deref();
    assert.equal(mergedA.get("from-a"), 1);
    assert.equal(mergedA.get("from-b"), 2);
    assert.equal(mergedA.get("stable"), "yes");
    assert.equal(mergedA.get("shared"), "b", "the later head's value");
    assert.equal(mergedA.root(), mergedB.root(), "every reader computes the same merge");
    assert.equal(conflictsA.length, 1);
    assert.deepEqual([conflictsA[0]!.key, conflictsA[0]!.reason, conflictsA[0]!.winnerRoot, conflictsA[0]!.loserRoot],
      ["shared", "LATER_HLC", vb.root(), va.root()]);
    assert.ok(Number(b.pdt.stats()["conflicts"]) >= 1);
    // the next swap persists the merge with both heads as bases
    const settled = await ra.swap((m) => m.assoc("after", true));
    await run(nodes, 2);
    const heads = rb.heads();
    assert.equal(heads.length, 1);
    assert.deepEqual(new Set(heads[0]!.base), new Set([va.root(), vb.root()]));
    assert.equal(heads[0]!.seq, 3);
    assert.equal((await rb.deref()).root(), settled.root());
    assert.equal((await rb.deref()).get("shared"), "b");
  } finally {
    network.flush();
    closeAll(nodes);
  }
});

test("vectors take the later head whole unless a merge function is registered (PD-R-05)", async () => {
  const nodes = fleet(2);
  const [a, b] = nodes as [Node, Node];
  const network = a.peer.network;
  try {
    const ra = a.pdt.ref<pdt.PVector<V>>("refs", "log", "vector");
    const rb = b.pdt.ref<pdt.PVector<V>>("refs", "log", "vector");
    await ra.swap((v) => v.conj("start"));
    await run(nodes, 2);
    network.holding = true;
    await ra.swap((v) => v.conj("a"));
    await sleep(5);
    await rb.swap((v) => v.conj("b"));
    network.flush();
    await run(nodes, 3);
    const conflicts: pdt.PConflict[] = [];
    ra.onConflict((e) => conflicts.push(e));
    assert.deepEqual((await ra.deref()).toArray(), ["start", "b"]);
    assert.deepEqual((await rb.deref()).toArray(), ["start", "b"]);
    assert.equal(conflicts[0]!.reason, "WHOLE_HEAD");
    const concat: pdt.MergeFunction<pdt.PVector<V>> = (base, earlier, later) => {
      let out = base ?? earlier;
      const from = base === null ? 0 : base.count();
      for (let i = from; i < earlier.count(); i++) {
        out = out.conj(earlier.nth(i));
      }
      for (let i = from; i < later.count(); i++) {
        out = out.conj(later.nth(i));
      }
      return out;
    };
    a.pdt.mergeFor("log", concat);
    b.pdt.mergeFor("log", concat);
    assert.deepEqual((await ra.deref()).toArray(), ["start", "a", "b"]);
    assert.deepEqual((await rb.deref()).toArray(), ["start", "a", "b"]);
  } finally {
    network.flush();
    closeAll(nodes);
  }
});

test("a sealed group moves nodes under the content key, and a keyless member in it is refused (PD-P-03)", async () => {
  const key = new Uint8Array(32).fill(7);
  const network = new Network();
  const a = node(network, { keys: pdt.ContentKeys.of(key), inlineDelta: 1024 });
  const b = node(network, { keys: pdt.ContentKeys.of(key), inlineDelta: 1024 });
  const c = node(network, { inlineDelta: 1024 });
  const nodes = [a, b, c];
  for (const n of nodes) {
    n.peer.introduce();
  }
  for (const n of nodes) {
    n.pdt.advertise();
  }
  try {
    const sent: Dict[] = [];
    const original = a.content.pipes.send.bind(a.content.pipes);
    a.content.pipes.send = (to, type, payload, via) => {
      const tag = pdt.tree.peekTag(payload);
      if (tag === pdt.tree.NODES) {
        sent.push(loads(payload) as Dict);
      }
      original(to, type, payload, via);
    };
    const ra = a.pdt.ref<pdt.PMap<string, V>>("refs", "sealed", "map");
    const big = await ra.swap((m) => {
      const editor = m.editor();
      for (let i = 0; i < 500; i++) {
        editor.assoc(`k${i}`, `v${i}`);
      }
      return editor.done();
    });
    assert.equal(a.pdt.refs.config.sealing, "group-key");
    const rb = b.pdt.ref<pdt.PMap<string, V>>("refs", "sealed", "map");
    for (let i = 0; i < 40 && b.pdt.refs.deltasFetched === 0; i++) {
      await run(nodes, 1);
    }
    assert.equal((await rb.deref()).root(), big.root());
    assert.ok(sent.length > 0 && sent.every((m) => m["sealed"] instanceof Uint8Array && m["nodes"] === null && m["epoch"] === 0),
      "every NODES to b travelled sealed under epoch 0");
    // c holds no key: what the keyed holders send it stays sealed, so the head never loads here
    assert.ok(a.pdt.exchange!.groupSeals() && c.pdt.exchange!.groupSeals());
    const rc = c.pdt.ref<pdt.PMap<string, V>>("refs", "sealed", "map");
    await run(nodes, 3);
    assert.ok(!c.pdt.store.complete(big.root()));
    assert.equal(rc.heads().length, 0);
    assert.ok([...c.pdt.exchange!.fetches.values()].some((f) => f.trace.some((line) => line.includes("could not be opened"))));
    // a keyless holder in a sealing group refuses to serve plaintext: c's own version is refused to b (REJECT 3)
    const own = await rc.swap((m) => {
      const editor = m.editor();
      for (let i = 0; i < 300; i++) {
        editor.assoc(`c${i}`, i);
      }
      return editor.done();
    });
    await run(nodes, 3);
    assert.ok(Number(c.pdt.exchange!.stats()["treeRequestsRejected"]) >= 1, "c refused b's request");
    assert.ok(!b.pdt.store.complete(own.root()));
  } finally {
    closeAll(nodes);
  }
});

test("a linear ref serialises writers through takes, and a blob ref ships a file by request (PD-R-04, PD-B-04)", async () => {
  const nodes = fleet(2, { modes: { counter: "linear" }, take: { leaseMillis: 5000, timeoutMillis: 3000, retries: 2 },
    inlineDelta: 8192 });
  const [a, b] = nodes as [Node, Node];
  try {
    const ra = a.pdt.ref<pdt.PMap<string, V>>("refs", "counter", "map");
    const rb = b.pdt.ref<pdt.PMap<string, V>>("refs", "counter", "map");
    assert.equal(ra.mode, "linear");
    await ra.swap((m) => m.assoc("n", 0));
    await run(nodes, 2);
    const ticking = setInterval(() => { void run(nodes, 1); }, 50);
    try {
      for (let i = 0; i < 3; i++) {
        await ra.swap((m) => m.assoc("n", Number(m.get("n")) + 1));
        await rb.swap((m) => m.assoc("n", Number(m.get("n")) + 1));
      }
    } finally {
      clearInterval(ticking);
    }
    await run(nodes, 3);
    assert.equal((await ra.deref()).get("n"), 6);
    assert.equal((await rb.deref()).get("n"), 6);
    assert.equal(ra.heads().length, 1);
    assert.equal(ra.heads()[0]!.mode, "linear");
    // a blob
    const bytes = new Uint8Array(200_000).map((_, i) => (i * 31 + 7) & 0xff);
    const fa = a.pdt.ref<pdt.PBlob>("refs", "file", "blob");
    const blob = await fa.swap((empty) => empty.append(bytes));
    assert.equal(blob.size, bytes.length);
    const fb = b.pdt.ref<pdt.PBlob>("refs", "file", "blob");
    for (let i = 0; i < 40 && !b.pdt.store.complete(blob.root); i++) {
      await run(nodes, 1);
    }
    const got = await fb.deref();
    assert.deepEqual(got.bytes(), bytes);
    assert.deepEqual(got.read(100_000, 16), bytes.subarray(100_000, 100_016));
    const more = await fa.swap((current) => current.append(new Uint8Array([1, 2, 3])));
    for (let i = 0; i < 40 && !b.pdt.store.complete(more.root); i++) {
      await run(nodes, 1);
    }
    assert.equal((await fb.deref()).size, bytes.length + 3);
    assert.equal(fb.at(blob.root).size, bytes.length);
  } finally {
    closeAll(nodes);
  }
});

test("PDT 2 phase 4 measures: a sealed NODES that carries deltas is refused (§10.14)", () => {
  // the owner's default of 2026-11-09: frames travel in plaintext answers only, and every port refuses the pair
  const sealed = pdt.tree.sealedNodes(7, Uint8Array.of(1, 2, 3), 0);
  assert.equal(pdt.tree.treeViolation(sealed), null);
  const cid = pdt.cids.of(new Uint8Array([1]), pdt.cids.RAW);
  assert.equal(pdt.tree.treeViolation({ ...sealed, deltas: [{ cid, base: cid, dcz: Uint8Array.of(0x64) }] }),
    "a sealed NODES carries no deltas");
  assert.equal(pdt.tree.treeViolation({ ...sealed, deltas: [] }), "a sealed NODES carries no deltas");
});

test("the exchange drops frames outside the bounds and refuses a tree it does not hold (PD-X-02)", async () => {
  const nodes = fleet(2);
  const [a, b] = nodes as [Node, Node];
  try {
    const ex = b.pdt.exchange!;
    const dropped = Number(ex.stats()["treeMessagesDropped"]);
    const cid = pdt.cids.of(new Uint8Array([1]), pdt.cids.RAW);
    a.content.pipes.send(b.peer.identity.peerId, "aspace:cap/content-swarm", Uint8Array.of(0xbf, 0x61, 0x74, 0x08));
    const tooMany = pdt.tree.nodeWant(1, Array.from({ length: 257 }, () => cid));
    a.content.send(b.peer.identity.peerId, tooMany);
    a.content.send(b.peer.identity.peerId, pdt.tree.treeWant(2, cid, [], 0));
    await ex.settled();
    assert.equal(Number(ex.stats()["treeMessagesDropped"]), dropped + 3);
    assert.equal(pdt.tree.treeViolation(pdt.tree.treeEnd(3, [], 9)), "unknown reason");
    assert.equal(pdt.tree.treeViolation(pdt.tree.nodeWant(3, [cid])), null);
    // a TREE_WANT for a root b does not hold answers REJECT 1; a NODE_WANT for an absent node answers `missing`
    const unknown = pdt.cids.of(new Uint8Array([9]), pdt.cids.DAG_CBOR);
    a.content.send(b.peer.identity.peerId, pdt.tree.treeWant(5, unknown, []));
    await ex.settled();
    assert.equal(Number(b.pdt.exchange!.stats()["treeRequestsRejected"]), 1);
    const fetch = a.pdt.exchange!.fetchTree(unknown, [], [b.peer.identity.peerId]);
    await run(nodes, 2);
    assert.ok(!fetch.done);
    assert.ok([...fetch.sources.values()].some((s) => s.lacks(unknown, a.peer.now())), "b answered missing for the root");
    fetch.cancel();
    assert.ok(fetch.done && fetch.failure === "cancelled");
    assert.equal(a.pdt.exchange!.fetches.size, 1, "a cancelled fetch leaves the map on the next tick");
    await run(nodes, 1);
    assert.equal(a.pdt.exchange!.fetches.size, 0);
  } finally {
    closeAll(nodes);
  }
});

// ---- swarm retries (ROBUSTNESS.md §10.3, E2 and E4)

test("a holder that lacked a node is asked again once its bench ends, and the fetch completes (swarm retries, E4)", async () => {
  const nodes = fleet(2);
  const [a, b] = nodes as [Node, Node];
  try {
    let value = pdt.PMap.empty<string, V>(a.pdt.store);
    for (let i = 0; i < 300; i++) {
      value = value.assoc(`k${i}`, "v".repeat(200));
    }
    const root = value.root();
    a.pdt.exchange!.holdTree(root);
    await run(nodes, 2);
    const lacked = [...a.pdt.store.reachable(root)].filter((cid) => cid !== root).sort()[0]!;
    const bytes = a.pdt.store.get(lacked)!;
    a.pdt.store.remove(lacked);
    const fetch = b.pdt.exchange!.fetchTree(root);
    await run(nodes, 3);
    assert.ok(!fetch.done, "the holder lacks a node: the fetch waits");
    a.pdt.store.putVerified(lacked, bytes); // the holder's own fetch ran on and brought it
    const deadline = Date.now() + 4000;
    while (!fetch.done && Date.now() < deadline) {
      await run(nodes, 1);
      await sleep(50);
    }
    assert.ok(fetch.complete, fetch.trace.join("\n"));
    assert.ok(b.pdt.store.complete(root));
  } finally {
    closeAll(nodes);
  }
});

test("a late head is counted late, never ignored, and the tick fetches it again from another holder (swarm retries, E2)", async () => {
  const nodes = fleet(3, { loadTimeoutMillis: 300 });
  const [a, b, c] = nodes as [Node, Node, Node];
  try {
    const onA = a.pdt.ref<pdt.PMap<string, V>>("refs", "late", "map");
    const base = await onA.swap((m) => m.assoc("k1", "v1"));
    await run(nodes, 2);
    const onB = b.pdt.ref<pdt.PMap<string, V>>("refs", "late", "map");
    assert.equal((await onB.deref()).root(), base.root());
    const entries = (m: pdt.PMap<string, V>) => {
      let out = m;
      for (let i = 0; i < 300; i++) {
        out = out.assoc(`k${i}`, "v".repeat(200));
      }
      return out;
    };
    const later = entries(pdt.PMap.empty<string, V>(pdt.NodeStore.inMemory()));
    const head = pdt.pref({ name: "late", kind: "map", root: later.root(), base: [base.root()], seq: 2, size: 300 });
    a.peer.writeEntry("refs", pdt.PREF_TYPE, head, "typescript", 600_000, null, pdt.prefTags(head));
    await run(nodes, 2);
    assert.equal((await onB.deref()).root(), base.root(), "no member holds the new version yet");
    assert.equal(b.pdt.stats()["headsIgnored"], 0);
    assert.ok(Number(b.pdt.stats()["headsLate"]) >= 1);
    const mirror = await c.pdt.ref<pdt.PMap<string, V>>("refs", "mirror", "map").swap(entries);
    assert.equal(mirror.root(), later.root(), "the same content, the same root");
    const deadline = Date.now() + 15_000;
    while (!b.pdt.store.complete(later.root()) && Date.now() < deadline) {
      await run(nodes, 1); // the tick alone, no read
      await sleep(50);
    }
    assert.ok(b.pdt.store.complete(later.root()), "the tick fetched the head again");
    assert.equal((await onB.deref()).root(), later.root());
  } finally {
    closeAll(nodes);
  }
});
