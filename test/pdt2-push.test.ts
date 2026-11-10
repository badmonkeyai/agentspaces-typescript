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
 * PDT 2 phase 7, push reception in TypeScript (srad/agentspaces-pdt2.md §3.4; P2-C-01, P2-P-02, P2-P-03,
 * P2-Q-SEC-03): the bundle of `pdt_push_bundle_cbor` read strictly, a follower that stores what an announced root
 * reaches and sends no request, the bounds that drop a bundle and keep it from going on, and the fetch once an
 * announced push is late past its grace.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { fromHex } from "../src/bytes.js";
import { dumps, loads } from "../src/cbor.js";
import * as pdt from "../src/pdt/index.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import { closeAll, fleetOf, run } from "./pdt-fleet.js";
import type { Node, V } from "./pdt-fleet.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8"));
const { push } = pdt;
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

test("PDT 2 phase 7: the bundle of pdt_push_bundle_cbor reads strictly, and one outside its grammar or bounds does not (P2-P-01, rule 16)", () => {
  const bytes = fromHex(GOLDEN["pdt_push_bundle_cbor"]!);
  const bundle = push.readBundle(bytes)!;
  const node = fromHex(GOLDEN["pdt_map_small"]!);
  assert.deepEqual([bundle["v"], bundle["root"], bundle["seq"], bundle["part"], bundle["parts"]],
    [1, pdt.cids.of(node, pdt.cids.DAG_CBOR), 3, 0, 1]);
  assert.deepEqual(bundle["nodes"], [node]);
  assert.deepEqual(dumps(bundle), bytes);
  const plain = loads(bytes) as Dict;
  const refused: [string, Dict][] = [
    ["another version", { ...plain, v: 2 }],
    ["a root that is no CID", { ...plain, root: "x" }],
    ["no parts", { ...plain, parts: 0 }],
    ["more than 64 parts", { ...plain, parts: 65 }],
    ["a part past its parts", { ...plain, part: 1 }],
    ["no node", { ...plain, nodes: [] }],
    ["an empty node", { ...plain, nodes: [new Uint8Array(0)] }],
    ["more than 1 MiB of nodes", { ...plain, nodes: [new Uint8Array(push.MAX_BYTES + 1)] }],
    ["a field the schema lacks", { ...plain, extra: 1 }],
  ];
  for (const [why, b] of refused) {
    assert.equal(push.readBundle(dumps(b)), null, why);
  }
  assert.equal(push.announced({ "pdt.push": "3" }), 3);
  for (const text of ["0", "03", "65", "x", ""]) {
    assert.equal(push.announced({ "pdt.push": text }), 0, text);
  }
});

type Internals = { send(kind: string, body: Uint8Array, to?: string | null): void };

/** A map of `n` keys in `n.pdt.store`, its root, and every node under it, parents first. */
function bigMap(store: pdt.NodeStore, n: number, tag: string): { root: string; nodes: Uint8Array[] } {
  const editor = pdt.PMap.empty<string, V>(store).editor();
  for (let i = 0; i < n; i++) {
    editor.assoc(`${tag}${i}`, `value ${i} of ${tag}`);
  }
  const root = editor.done().root();
  return { root, nodes: [...store.reachable(root)].map((cid) => store.get(cid)!) };
}

/** Writes a head of `root` announcing `parts` bundles, with no inline nodes, as a pushing writer does. */
function announce(writer: Node, name: string, root: string, parts: number, size: number): void {
  const head = pdt.pref({ name, kind: "map", root, seq: 1, size, attrs: { [push.ATTR]: String(parts) } });
  writer.peer.writeEntry("refs", pdt.PREF_TYPE, head, "writer", 60_000, null, pdt.prefTags(head));
  writer.pdt.exchange!.holdTree(root);
}

function sendBundle(writer: Node, name: string, root: string, nodes: Uint8Array[], part = 0, parts = 1): void {
  const bundle = dumps({ v: 1, root, seq: 1, part, parts, nodes });
  (writer.peer as unknown as Internals).send("RUMOR", wire.rumorBody(push.stream("refs", name), `${root}:${part}`, 6, bundle));
}

/** The tree requests a member sends. */
function treeAsks(n: Node): Dict[] {
  const asked: Dict[] = [];
  const original = n.content.pipes.send.bind(n.content.pipes);
  n.content.pipes.send = (to, type, payload, via) => {
    const tag = pdt.tree.peekTag(payload);
    if (tag === pdt.tree.TREE_WANT || tag === pdt.tree.NODE_WANT) {
      asked.push(loads(payload) as Dict);
    }
    original(to, type, payload, via);
  };
  return asked;
}

test("PDT 2 phase 7: a follower stores the pushed nodes an announced root reaches and sends no request (P2-P-02, P2-P-03)", async () => {
  const nodes = fleetOf([{}, { push: true }]);
  const [a, b] = nodes as [Node, Node];
  try {
    const asked = treeAsks(b);
    const rb = b.pdt.ref<pdt.PMap<string, V>>("refs", "big", "map");
    // the bundle first, the head after it
    const first = bigMap(a.pdt.store, 400, "k");
    sendBundle(a, "big", first.root, first.nodes);
    announce(a, "big", first.root, 1, 400);
    await run(nodes, 2);
    assert.ok(b.pdt.store.complete(first.root));
    assert.equal((await rb.deref()).get("k399"), "value 399 of k");
    // the head first, the bundles after it, in two parts
    const second = bigMap(a.pdt.store, 300, "j");
    const name2 = "big2";
    const rb2 = b.pdt.ref<pdt.PMap<string, V>>("refs", name2, "map");
    announce(a, name2, second.root, 2, 300);
    await run(nodes, 1);
    assert.ok(!b.pdt.store.complete(second.root));
    const half = Math.ceil(second.nodes.length / 2);
    sendBundle(a, name2, second.root, second.nodes.slice(0, half), 0, 2);
    sendBundle(a, name2, second.root, second.nodes.slice(half), 1, 2);
    await run(nodes, 2);
    assert.equal((await rb2.deref()).get("j0"), "value 0 of j");
    assert.equal(asked.length, 0, "a root the push completes needs no request");
    const stats = b.pdt.stats()["push"] as Dict;
    assert.equal(stats["bundlesReceived"], 3);
    assert.equal(stats["fallbacks"], 0);
  } finally {
    closeAll(nodes);
  }
});

test("PDT 2 phase 7: a bundle outside its bounds is dropped and never goes on, and nodes no announced root reaches never enter the store (P2-Q-SEC-03)", async () => {
  const nodes = fleetOf([{}, { push: { maxBytes: 160 * 10 } }]);
  const [a, b] = nodes as [Node, Node];
  try {
    b.pdt.ref<pdt.PMap<string, V>>("refs", "big", "map");
    const handler = b.peer.streamHandlers.get(push.stream("refs", "big"))!;
    const tiny = Array.from({ length: 11 }, (_, i) => Uint8Array.of(i + 1));
    const root = pdt.cids.of(tiny[0]!, pdt.cids.RAW);
    assert.equal(handler(a.peer.identity.peerId, dumps({ v: 1, root, seq: 1, part: 0, parts: 1, nodes: tiny })), false,
      "past the bound per root on nodes: dropped, never forwarded");
    assert.equal(handler(a.peer.identity.peerId, Uint8Array.of(0xff)), false, "outside the grammar");
    const stray = bigMap(a.pdt.store, 5, "s");
    assert.equal(handler(a.peer.identity.peerId, dumps({ v: 1, root: stray.root, seq: 1, part: 0, parts: 1, nodes: stray.nodes })), true,
      "a bundle within its bounds is taken and goes on");
    await run(nodes, 1);
    assert.ok(!b.pdt.store.has(stray.root), "no head announced the root, so nothing is stored");
    assert.equal(b.peer.streamHandlers.has(push.stream("refs", "other")), false, "a stream this follower does not follow has no handler");
    assert.equal((b.pdt.stats()["push"] as Dict)["bundlesDropped"], 2);
  } finally {
    closeAll(nodes);
  }
});

test("PDT 2 phase 7: an announced push whose bundles never come is fetched once its grace runs out (P2-P-02; swarm retries, P4)", async () => {
  const nodes = fleetOf([{}, { push: { graceMillis: 1000, maxGraceMillis: 1000 } }]);
  const [a, b] = nodes as [Node, Node];
  try {
    const asked = treeAsks(b);
    const rb = b.pdt.ref<pdt.PMap<string, V>>("refs", "big", "map");
    const value = bigMap(a.pdt.store, 400, "m");
    announce(a, "big", value.root, 1, 400);
    await run(nodes, 2);
    assert.equal(asked.length, 0, "within the grace the follower waits for the bundle");
    await sleep(1100);
    for (let i = 0; i < 20 && !b.pdt.store.complete(value.root); i++) {
      await run(nodes, 1);
    }
    assert.ok(b.pdt.store.complete(value.root));
    assert.ok(asked.length > 0, "past the grace it fetched");
    assert.equal((b.pdt.stats()["push"] as Dict)["fallbacks"], 1);
    assert.equal((await rb.deref()).get("m1"), "value 1 of m");
  } finally {
    closeAll(nodes);
  }
});
