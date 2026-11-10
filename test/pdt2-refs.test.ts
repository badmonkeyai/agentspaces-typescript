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
 * PDT 2 phase 7, refs at level 2 in TypeScript (srad/agentspaces-pdt2.md §6.10.3 rules 1 to 9; P2-C-01, P2-F-06,
 * P2-V-01, P2-V-02, P2-D-09, P2-R-04, P2-T-01): a level-2 reader reads `PRef.v` 2 heads and `db` heads, a writer
 * writes `v` 2 heads over a relaxed vector and over texts, every version names its `vg` node under `pdt.ancestry`,
 * and a late joiner that never saw the base's head finds the common base through the chain.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { fromHex } from "../src/bytes.js";
import { loads } from "../src/cbor.js";
import * as pdt from "../src/pdt/index.js";
import { DEFAULT_HEAD_LEASE_MILLIS } from "../src/pdt/refs.js";
import type { Dict } from "../src/wire.js";
import { closeAll, fleet, fleetOf, node, run } from "./pdt-fleet.js";
import type { Node, V } from "./pdt-fleet.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8"));
const hex = (name: string): Uint8Array => fromHex(GOLDEN[name]!);
const parts = (name: string): Uint8Array[] => GOLDEN[name]!.split(",").map(fromHex);
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** The record of a head as the entry carries it. */
function record(n: Node, head: pdt.Head): Dict {
  return loads(n.peer.payloadOf(n.peer.states.get(head.entryId)!)!) as Dict;
}

test("PDT 2 phase 7: a level-2 reader takes a PRef v 2 head and a db head, and a level-1 reader ignores both (rule 8, P2-F-06)", () => {
  const v2 = pdt.decodePRef(hex("pdt_ref_v2_cbor"));
  assert.equal(v2["v"], 2);
  assert.equal(pdt.prefViolation(v2), null);
  assert.equal(pdt.prefViolation(v2, 1), "unsupported PRef version 2");
  const head = pdt.decodePRef(hex("pdt_ref_min_cbor"));
  assert.equal(pdt.prefViolation({ ...head, kind: "db", v: 2 }), null);
  assert.equal(pdt.prefViolation({ ...head, kind: "db" }), "a db head is version 2, found 1");
  assert.equal(pdt.prefViolation({ ...head, kind: "db", v: 2 }, 1), "unsupported PRef version 2");
  assert.equal(pdt.prefViolation({ ...head, v: 3 }), "unsupported PRef version 3");
});

test("PDT 2 phase 7: a vector ref over an rr root writes a v 2 head that a level-2 member reads and a level-1 member ignores (rule 2, P2-R-04)", async () => {
  const nodes = fleetOf([{}, {}, { level: 1 }]);
  const [a, b, old] = nodes as [Node, Node, Node];
  try {
    const [root, , ...tree] = GOLDEN["pdt_rr_splice"]!.split(",");
    for (const n of tree) {
      a.pdt.store.put(fromHex(n), pdt.cids.DAG_CBOR);
    }
    const ra = a.pdt.ref<pdt.PVector<number>>("refs", "transcript", "vector");
    const written = await ra.swap(() => pdt.PVector.load<number>(a.pdt.store, root!));
    assert.equal(written.relaxed(), true);
    assert.equal(record(a, ra.heads()[0]!)["v"], 2);
    const rb = b.pdt.ref<pdt.PVector<number>>("refs", "transcript", "vector");
    const rold = old.pdt.ref<pdt.PVector<number>>("refs", "transcript", "vector");
    for (let i = 0; i < 20 && b.pdt.refs.deltasFetched + b.pdt.refs.deltasInline === 0; i++) {
      await run(nodes, 1);
    }
    const read = await rb.deref();
    assert.equal(read.count(), 1101);
    assert.equal(read.nth(500), -1);
    assert.equal((await rold.deref()).count(), 0, "a level-1 reader sees no head");
    assert.equal(old.pdt.refs.headsIgnored, 1);
    // a writer that stores the packed form writes v 1 again (rule 2)
    await ra.swap((v) => v.packed());
    assert.equal(record(a, ra.heads()[0]!)["v"], 1);
  } finally {
    closeAll(nodes);
  }
});

test("PDT 2 phase 7: a map ref of texts writes v 2 heads, and concurrent edits merge by union with no conflict (rule 3, P2-T-03)", async () => {
  const nodes = fleet(2);
  const [a, b] = nodes as [Node, Node];
  const network = a.peer.network;
  try {
    const ra = a.pdt.ref<pdt.PMap<string, pdt.PText>>("refs", "doc", "map", { values: pdt.PText.codec("alice") });
    const rb = b.pdt.ref<pdt.PMap<string, pdt.PText>>("refs", "doc", "map", { values: pdt.PText.codec("bob") });
    await ra.swap((m) => m.assoc("body", pdt.PText.empty("alice").insert(0, "Hello")));
    await run(nodes, 3);
    assert.equal(record(a, ra.heads()[0]!)["v"], 2);
    assert.equal((await rb.deref()).get("body")!.toString(), "Hello");
    network.holding = true;
    await ra.swap((m) => m.assoc("body", m.get("body")!.insert(5, " world")));
    await sleep(5);
    await rb.swap((m) => m.assoc("body", m.get("body")!.insert(0, ">> ")));
    network.flush();
    await run(nodes, 3);
    const conflicts: pdt.PConflict[] = [];
    ra.onConflict((e) => conflicts.push(e));
    const merged = await ra.deref();
    assert.equal(merged.get("body")!.toString(), ">> Hello world");
    assert.equal((await rb.deref()).get("body")!.toString(), ">> Hello world");
    assert.equal(conflicts.length, 0);
  } finally {
    network.flush();
    closeAll(nodes);
  }
});

test("PDT 2 phase 7: a db ref reads a db head a Java writer wrote: its v 2 record, its root, and the datoms (P2-D-09, rule 8)", async () => {
  const nodes = fleet(2);
  const [a, b] = nodes as [Node, Node];
  try {
    const [root, aevt, avet] = parts("pdt_db_root") as [Uint8Array, Uint8Array, Uint8Array];
    const inline = [root, aevt, avet, hex("pdt_dn_leaf"), hex("pdt_dn_tail")];
    const rootCid = pdt.cids.of(root, pdt.cids.DAG_CBOR);
    const head = pdt.pref({ v: 2, name: "graph", kind: "db", root: rootCid, seq: 1, size: 4, nodes: inline });
    a.peer.writeEntry("refs", pdt.PREF_TYPE, head, "writer", 60_000, null, pdt.prefTags(head));
    const rb = b.pdt.ref<pdt.DbReader | null>("refs", "graph", "db");
    await run(nodes, 2);
    const db = (await rb.deref())!;
    assert.equal(db.root, rootCid);
    assert.deepEqual(db.entity(2), { ":person/age": 46, ":person/name": "Grace" }, "the tail applied over the index");
    assert.deepEqual([...db.datoms("avet", ":person/name", "Grace")].map((d) => d.e), [2]);
    await assert.rejects(rb.swap((v) => v), /read-only/);
  } finally {
    closeAll(nodes);
  }
});

test("PDT 2 phase 7: each version names its vg node under pdt.ancestry, held by its writer and carried inline by no head (P2-V-01)", async () => {
  const nodes = fleet(1);
  const [a] = nodes as [Node];
  try {
    const ra = a.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    const first = await ra.swap((m) => m.assoc("k", 1));
    const second = await ra.swap((m) => m.assoc("k", 2));
    const r = record(a, ra.heads()[0]!);
    const vgCid = pdt.ancestryCid(r)!;
    assert.ok(vgCid !== null);
    const vg = pdt.readAncestry(r, a.pdt.store.get(vgCid)!)!;
    assert.equal(vg.root, second.root());
    assert.deepEqual(vg.bases, [first.root()]);
    assert.equal(vg.previous.length, 1, "the chain links the base's vg node");
    assert.ok(a.pdt.store.has(vg.previous[0]!.cid));
    assert.ok(!((r["nodes"] as Uint8Array[] | undefined) ?? []).some((n) => pdt.cids.of(n, pdt.cids.DAG_CBOR) === vgCid),
      "no head carries its vg node inline (rule 9)");
    assert.ok(a.pdt.refs.liveRoots().has(vgCid), "the collector keeps the chain");
  } finally {
    closeAll(nodes);
  }
});

test("PDT 2 phase 7: a late joiner that never saw the bases of two forks merges them by the chain's common base (P2-V-02)", async () => {
  const nodes = fleet(2);
  const [a, b] = nodes as [Node, Node];
  const network = a.peer.network;
  const all: Node[] = [...nodes];
  try {
    const ra = a.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    const rb = b.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    await ra.swap((m) => m.assoc("stable", "yes"));
    await run(nodes, 2);
    assert.equal((await rb.deref()).get("stable"), "yes");
    // a partition: each side writes two versions, and each writer cancels the versions below its own head
    network.holding = true;
    await ra.swap((m) => m.assoc("from-a-1", 1));
    await ra.swap((m) => m.assoc("from-a", 1));
    await sleep(5);
    await rb.swap((m) => m.assoc("from-b-1", 1));
    await rb.swap((m) => m.assoc("from-b", 2));
    await sleep(2100);
    await run(nodes, 2);
    // the late joiner arrives as the partition heals: it holds no entry of the forks' bases, live or cancelled
    const late = node(network);
    all.push(late);
    late.peer.introduce();
    for (const n of all) {
      n.pdt.advertise();
    }
    network.flush();
    await run(all, 3);
    const rl = late.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    await run(all, 3);
    assert.equal(rl.heads().length, 2);
    const conflicts: pdt.PConflict[] = [];
    rl.onConflict((e) => conflicts.push(e));
    const merged = await rl.deref();
    assert.equal(conflicts.length, 0, "the chain names the common base, so no head wins whole");
    for (const key of ["stable", "from-a-1", "from-a", "from-b-1", "from-b"]) {
      assert.ok(merged.has(key), key);
    }
    assert.equal(merged.root(), (await ra.deref()).root(), "the late joiner merges as the writers do");
  } finally {
    network.flush();
    closeAll(all);
  }
});

test("PDT 2 phase 7 gate: a head its writer renewed stays live past its first lease on every member (PD-R-08)", async () => {
  // A reader judges a head by its entry's lease register, which a renewal moves (SPEC §7.3), as Java's EntryState and
  // the Ruby reader do. Judging the lease the record was written with dropped the renewed head at that first lease
  // on every member, and its writer then rewrote it as a new entry.
  const nodes = fleet(2);
  const [a, b] = nodes as [Node, Node];
  const clock = { millis: Date.now() };
  for (const n of nodes) {
    (n.peer as unknown as { now: () => number }).now = () => clock.millis;
  }
  try {
    const ra = a.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    const rb = b.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    await ra.swap((m) => m.assoc("k", 1));
    await run(nodes, 2);
    assert.equal((await rb.deref()).get("k"), 1);
    const [entryId] = rb.heads().map((h) => h.entryId);
    clock.millis += DEFAULT_HEAD_LEASE_MILLIS / 2;
    await run(nodes, 1); // half the head lease: the writer renews its live head
    assert.equal(Number((b.peer.states.get(entryId!)!["leaseValue"] as Dict)["expiresAtMillis"]),
      clock.millis + DEFAULT_HEAD_LEASE_MILLIS);
    clock.millis += DEFAULT_HEAD_LEASE_MILLIS / 2 + 1; // past the lease the record was written with
    for (const r of [ra, rb]) {
      assert.deepEqual(r.heads().map((h) => h.entryId), [entryId]);
      assert.equal((await r.deref()).get("k"), 1);
    }
  } finally {
    closeAll(nodes);
  }
});

test("PDT 2 phase 7 gate: a chain node nobody serves costs a merge one load timeout, and later merges wait out its backoff (P2-V-02)", async () => {
  // Swarm retries (ROBUSTNESS.md §10.2): a node whose fetch failed is asked for again only after a backoff that doubles
  // with each failure, as Java's tick and the Python reader keep it. Fetching every missing chain node again on each
  // merge cost every read of a forked ref a full load timeout while the node's writer stayed out of reach.
  const nodes = fleet(2, { loadTimeoutMillis: 200 });
  const [a, b] = nodes as [Node, Node];
  const network = a.peer.network;
  try {
    const ra = a.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    const rb = b.pdt.ref<pdt.PMap<string, V>>("refs", "facts", "map");
    await ra.swap((m) => m.assoc("base", 0));
    await run(nodes, 2);
    const base = (await rb.deref()).root();
    const [baseEntry] = rb.heads().map((h) => h.entryId);
    network.holding = true; // a partition: each writer forks from the base
    await ra.swap((m) => m.assoc("a", 1));
    await rb.swap((m) => m.assoc("b", 1));
    network.flush();
    network.holding = true; // the heads crossed, and nothing either writer serves arrives now
    // b forgets the base's version and its entry, as a member that joined after the base's head went, so its walk
    // needs the chain node a's head names, which only a holds
    b.peer.states.delete(baseEntry!);
    const state = (b.pdt.refs as unknown as { states: Map<string, { known: Map<string, unknown>; ancestry: Map<string, string>;
      chain: Map<string, unknown> }> }).states.get("refs/facts")!;
    for (const map of [state.known, state.ancestry, state.chain]) {
      map.delete(base);
    }
    const exchange = b.pdt.exchange!;
    const fetchNodes = exchange.fetchNodes.bind(exchange);
    let batches = 0;
    (exchange as unknown as { fetchNodes: typeof fetchNodes }).fetchNodes = (list, prefer) => {
      batches += 1;
      return fetchNodes(list, prefer);
    };
    const first = await rb.deref();
    assert.equal(batches, 1, "the merge asks for the chain node once");
    for (const key of ["base", "a", "b"]) {
      assert.ok(first.has(key), key);
    }
    const second = await rb.deref();
    assert.equal(batches, 1, "the next merge waits out the node's backoff and asks for nothing");
    assert.equal(second.root(), first.root());
  } finally {
    network.flush();
    closeAll(nodes);
  }
});
