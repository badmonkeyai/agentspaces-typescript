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
 * PDT 2 phase 7, group K in TypeScript (srad/agentspaces-pdt2.md §3.6; P2-C-01, P2-K-01, P2-K-02, P2-K-04, P2-K-05,
 * P2-F-01): negentropy v1 against every message of `negentropy-vectors.json`, RIBLT against `pdt_riblt_symbols`, the
 * sketch forms of `content_tree_want_sketch_cbor` and `content_tree_end_sketch_cbor`, and a reconciliation of held
 * roots between two level-2 members, which a level-1 member never takes part in.
 */

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { fromHex, utf8 } from "../src/bytes.js";
import { TYPE as CONTENT_TYPE } from "../src/capabilities/content.js";
import { dumps, loads } from "../src/cbor.js";
import { cryptoPort } from "../src/crypto.js";
import * as pdt from "../src/pdt/index.js";
import type { Dict } from "../src/wire.js";
import { closeAll, fleet, fleetOf, run } from "./pdt-fleet.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8"));
const VECTORS_FILE = join(here, "..", "..", "test", "negentropy-vectors.json");
const VECTORS = JSON.parse(readFileSync(VECTORS_FILE, "utf8"));
const { sync, tree, cids } = pdt;
const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

type Range = [number, number];
interface Case { name: string; universe: string; frameSizeLimit: number; client: Range[]; server: Range[]; rounds: number;
  messages?: { from: string; hex: string }[]; have: string[] | number; need: string[] | number }

function universe(name: string): (i: number) => pdt.sync.Item {
  const per = VECTORS.recipe.universes.find((u: { name: string }) => u.name === name).perTimestamp as number;
  return (i) => ({ timestamp: BigInt(1792320000 + Math.floor(i / per)),
    id: cryptoPort().sha256(utf8(`aspace:negentropy:${name}:${i}`)) });
}

function storage(name: string, ranges: Range[]): pdt.sync.Storage {
  const item = universe(name);
  const items: pdt.sync.Item[] = [];
  for (const [from, to] of ranges) {
    for (let i = from; i < to; i++) {
      items.push(item(i));
    }
  }
  return sync.Storage.of(items);
}

test("PDT 2 phase 7: the vendored negentropy vectors equal the spec's copy (P2-K-01)", (t) => {
  const spec = join(here, "..", "..", "..", "agentspaces-spec", "negentropy-vectors.json");
  if (!existsSync(spec)) {
    t.skip("agentspaces-spec is not beside this checkout");
    return;
  }
  assert.equal(readFileSync(VECTORS_FILE, "utf8"), readFileSync(spec, "utf8"));
});

test("PDT 2 phase 7: negentropy writes every message of every recorded case byte for byte (P2-K-01)", () => {
  for (const c of [...VECTORS.cases, ...VECTORS.measurements] as Case[]) {
    const client = new sync.Negentropy(storage(c.universe, c.client), c.frameSizeLimit);
    const server = new sync.Negentropy(storage(c.universe, c.server), c.frameSizeLimit);
    const messages: { from: string; hex: string }[] = [];
    let query: Uint8Array | null = client.initiate();
    const have: Uint8Array[] = [], need: Uint8Array[] = [];
    let rounds = 0, bytes = 0;
    while (query !== null) {
      messages.push({ from: "client", hex: toHex(query) });
      const reply: Uint8Array = server.reconcile(query);
      messages.push({ from: "server", hex: toHex(reply) });
      bytes += query.length + reply.length;
      rounds += 1;
      query = client.reconcile(reply, have, need);
    }
    assert.equal(rounds, c.rounds, c.name);
    if (c.messages !== undefined) {
      assert.deepEqual(messages, c.messages, c.name);
    }
    if (Array.isArray(c.have)) {
      assert.deepEqual(have.map(toHex).sort(), [...c.have].sort(), `${c.name} have`);
      assert.deepEqual(need.map(toHex).sort(), [...(c.need as string[])].sort(), `${c.name} need`);
    } else {
      assert.equal(have.length, c.have, `${c.name} have`);
      assert.equal(need.length, c.need, `${c.name} need`);
      assert.equal(bytes, (c as unknown as { bytes: number }).bytes, `${c.name} bytes`);
    }
  }
});

test("PDT 2 phase 7: a responder answers another version byte with its own and refuses a malformed message (P2-K-04)", () => {
  for (const u of VECTORS.upgrade as { server: [number, string][]; message: string; reply: string }[]) {
    const server = new sync.Negentropy(sync.Storage.of(u.server.map(([ts, id]) => ({ timestamp: BigInt(ts), id: fromHex(id) }))), 0);
    assert.equal(toHex(server.reconcile(fromHex(u.message))), u.reply);
  }
  const server = new sync.Negentropy(sync.Storage.of([]), 0);
  for (const [why, hex] of [["a version byte outside 0x60..0x6f", "51"], ["a premature end", "6100"],
    ["a bound key over 32 bytes", "610021"], ["an unknown mode", "61000003"], ["a varint past 63 bits", "61ffffffffffffffffff7f"]]) {
    assert.throws(() => server.reconcile(fromHex(hex!)), RangeError, why);
  }
});

test("PDT 2 phase 7: RIBLT codes the symbols of pdt_riblt_symbols byte for byte (P2-K-05)", () => {
  const [key, ids, symbols] = GOLDEN["pdt_riblt_symbols"]!.split(",").map(fromHex) as [Uint8Array, Uint8Array, Uint8Array];
  const list = Array.from({ length: 10 }, (_, i) => ids.subarray(i * 32, (i + 1) * 32));
  assert.deepEqual(list[3], cryptoPort().sha256(utf8("aspace:riblt:3")));
  const encoder = new sync.Riblt.Encoder(key, list);
  assert.equal(toHex(sync.Riblt.writeSymbols(encoder.next(12))), toHex(symbols));
});

test("PDT 2 phase 7: RIBLT decodes a difference in one pass and refuses a stream that peels more ids than symbols (P2-K-05, P2-Q-SEC-04)", () => {
  const key = Uint8Array.from({ length: 16 }, (_, i) => i * 7);
  const id = (i: number): Uint8Array => cryptoPort().sha256(utf8(`id:${i}`));
  const mine = Array.from({ length: 2000 }, (_, i) => id(i));
  const theirs = [...mine.slice(50), ...Array.from({ length: 50 }, (_, i) => id(5000 + i))];
  const encoder = new sync.Riblt.Encoder(key, theirs);
  const decoder = new sync.Riblt.Decoder(key, mine);
  while (!decoder.decoded()) {
    decoder.add(encoder.next(1)[0]!);
    assert.ok(decoder.symbols() < 400, "100 differences decode well under 400 symbols");
  }
  assert.equal(decoder.remoteOnly().length, 50);
  assert.equal(decoder.localOnly().length, 50);
  // a forged symbol 0 that names one id the holder lacks, at an index its own mapping never carries
  const forger = new sync.Riblt.Decoder(key, []);
  const lone = id(1);
  const checksum = sync.Riblt.sipHash24(key, lone);
  assert.throws(() => {
    for (let i = 0; i < 64; i++) {
      forger.add(i === 0 ? { sum: lone, checksum, count: 1 } : { sum: new Uint8Array(32), checksum: 0n, count: 0 });
    }
  }, /peels more ids than its/);
});

const sketchCids = (from: number, to: number): string[] =>
  Array.from({ length: to - from }, (_, i) => cids.of(utf8(`aspace:sketch:${from + i}`), cids.DAG_CBOR));

test("PDT 2 phase 7: the sketch TREE_WANT and TREE_END match content_tree_want_sketch_cbor and content_tree_end_sketch_cbor (P2-K-02)", () => {
  const want = new sync.Negentropy(sync.SketchSet.of(sketchCids(0, 40)).storage, sync.MAX_SKETCH_BYTES).initiate();
  const wantMessage = tree.sketchWant(42, want, sync.MAX_SKETCH_BYTES);
  assert.equal(toHex(dumps(wantMessage)), GOLDEN["content_tree_want_sketch_cbor"]);
  assert.deepEqual(tree.readTreeMessage(fromHex(GOLDEN["content_tree_want_sketch_cbor"]!)), wantMessage);
  const holder = sync.SketchSet.of([...sketchCids(0, 30), ...sketchCids(40, 50)]);
  const reply = new sync.Negentropy(holder.storage, sync.MAX_SKETCH_BYTES).reconcile(want);
  const end = tree.sketchEnd(42, reply);
  assert.equal(toHex(dumps(end)), GOLDEN["content_tree_end_sketch_cbor"]);
  assert.deepEqual(tree.readTreeMessage(fromHex(GOLDEN["content_tree_end_sketch_cbor"]!)), end);
  const asker = new sync.Negentropy(sync.SketchSet.of(sketchCids(0, 40)).storage, sync.MAX_SKETCH_BYTES);
  asker.initiate();
  const have: Uint8Array[] = [], need: Uint8Array[] = [];
  assert.equal(asker.reconcile(reply, have, need), null);
  assert.equal(have.length, 10);
  assert.equal(need.length, 10);
  const refused: [string, Dict][] = [
    ["a sketch want that names haves", { ...wantMessage, haves: [sketchCids(0, 1)[0]!] }],
    ["a sketch end with a frontier", { ...end, frontier: sketchCids(0, 1) }],
    ["a reason 5 without a sketch", tree.treeEnd(42, [], tree.END_SKETCH)],
    ["a sketch on another reason", { ...tree.treeEnd(42, [], tree.END_DONE), sketch: reply }],
  ];
  for (const [why, message] of refused) {
    assert.equal(tree.readTreeMessage(dumps(message)), null, why);
  }
});

test("PDT 2 phase 7: the holder's answer drops a sketch past 64 KiB or of an unknown encoding, and ends a session after 64 rounds (P2-K-04, P2-F-01)", () => {
  const server = new sync.SketchServer(() => sketchCids(0, 10), () => 0);
  assert.deepEqual(server.answer("p", 1, new Uint8Array(sync.MAX_SKETCH_BYTES + 1), 65536).kind, "dropped");
  const unknown = server.answer("p", 1, Uint8Array.of(0x51, 0), 65536);
  assert.equal(unknown.kind, "dropped");
  assert.match((unknown as { why: string }).why, /unknown sketch encoding 0x51/);
  const query = new sync.Negentropy(sync.SketchSet.of(sketchCids(0, 5)).storage, 0).initiate();
  for (let round = 0; round < sync.MAX_ROUNDS; round++) {
    assert.equal(server.answer("p", 2, query, 65536).kind, "reply");
  }
  const past = server.answer("p", 2, query, 65536);
  assert.equal(past.kind, "refusal");
  assert.equal((past as { reason: number }).reason, tree.REASON_OVER_BUDGET);
});

async function heldRoots(n: ReturnType<typeof fleet>[number], from: number, to: number): Promise<string[]> {
  const roots: string[] = [];
  for (let i = from; i < to; i++) {
    const map = pdt.PMap.empty<string, number>(n.pdt.store).assoc("i", i);
    roots.push(map.root());
    n.pdt.exchange!.holdTree(map.root());
  }
  return roots;
}

test("PDT 2 phase 7: two level-2 members reconcile their held roots by negentropy and by RIBLT (P2-K-02, P2-K-03, P2-K-05)", async () => {
  const nodes = fleet(2);
  try {
    const [a, b] = nodes as [typeof nodes[number], typeof nodes[number]];
    const shared = await heldRoots(a, 0, 100);
    for (const root of shared) {
      b.pdt.exchange!.holdTree(PMapCopy(a, b, root));
    }
    const aOnly = await heldRoots(a, 100, 110);
    const bOnly = await heldRoots(b, 200, 205);
    await run(nodes, 2);
    for (const expected of [0, 20]) {
      const pending = a.pdt.exchange!.reconcileHeld(b.peer.identity.peerId, expected);
      await run(nodes, 8);
      const outcome = await pending;
      assert.deepEqual([...outcome.have].sort(), [...aOnly].sort(), `have, expected ${expected}`);
      assert.deepEqual([...outcome.need].sort(), [...bOnly].sort(), `need, expected ${expected}`);
      assert.equal(outcome.encoding, expected === 0 ? "negentropy" : "riblt");
    }
  } finally {
    closeAll(nodes);
  }
});

/** Copies a root's nodes from one member's store to another's and returns the root. */
function PMapCopy(from: ReturnType<typeof fleet>[number], to: ReturnType<typeof fleet>[number], root: string): string {
  for (const cid of from.pdt.store.reachable(root)) {
    to.pdt.store.putVerified(cid, from.pdt.store.get(cid)!);
  }
  return root;
}

test("PDT 2 phase 7: a member at level 1 is never sent a sketch, and a sketch from one gets the level-1 REJECT 3 (P2-F-05, rule 12)", async () => {
  const nodes = fleetOf([{}, { level: 1 }]);
  try {
    const [a, old] = nodes as [typeof nodes[number], typeof nodes[number]];
    assert.equal(a.pdt.exchange!.pdtLevel(old.peer.identity.peerId), 1);
    await assert.rejects(a.pdt.exchange!.reconcileHeld(old.peer.identity.peerId, 0), /level 1/);
    const heard: Dict[] = [];
    const previous = old.peer.pipeHandlers.get(CONTENT_TYPE)!;
    old.peer.pipeHandlers.set(CONTENT_TYPE, (from, payload) => {
      heard.push(loads(payload) as Dict);
      previous(from, payload);
    });
    const query = new sync.Negentropy(sync.SketchSet.of([]).storage, 0).initiate();
    old.pdt.exchange!.send(a.peer.identity.peerId, tree.sketchWant(9, query));
    await run(nodes, 2);
    assert.deepEqual(heard.map((m) => [m["t"], m["root"], m["reason"]]), [[5, "", tree.REASON_POLICY]]);
  } finally {
    closeAll(nodes);
  }
});
