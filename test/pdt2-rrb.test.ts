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
 * PDT 2 phase 7, the RRB reader in TypeScript (srad/agentspaces-pdt2.md §3.7; P2-C-01, P2-R-03, P2-R-04): a relaxed
 * tree read through its size tables (`pdt_rr_splice`), packed to the `vr` root of the same elements, the refusals of
 * §3.7 by name, and an `rr` root whose tail another port left empty.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { fromHex } from "../src/bytes.js";
import { dumps } from "../src/cbor.js";
import * as pdt from "../src/pdt/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8"));
const parts = (name: string): string[] => GOLDEN[name]!.split(",");
const { RrRoot, RvNode } = pdt.kinds;
const { Embedded, Link } = pdt.nodes;

/** The elements of `pdt_rr_splice`: 0 to 1,099 with -1 inserted before index 500. */
const SPLICED = [...Array.from({ length: 500 }, (_, i) => i), -1, ...Array.from({ length: 600 }, (_, i) => 500 + i)];

function spliceStore(): { store: pdt.NodeStore; root: string; packed: string } {
  const [root, packed, ...nodes] = parts("pdt_rr_splice");
  const store = pdt.NodeStore.inMemory();
  for (const node of nodes) {
    store.put(fromHex(node), pdt.cids.DAG_CBOR);
  }
  return { store, root: root!, packed: packed! };
}

const leaf = (from: number, to: number): Uint8Array => pdt.nodes.encode({ k: "v",
  e: Array.from({ length: to - from }, (_, i) => new Embedded(dumps(from + i))) });

/** A store holding nodes, and a link to each. */
function holding(store: pdt.NodeStore, node: Uint8Array): pdt.nodes.Link {
  return new Link(store.put(node, pdt.cids.DAG_CBOR));
}

test("PDT 2 phase 7: the relaxed tree of pdt_rr_splice reads its elements through z and packs to its vr root (P2-R-03, P2-R-04)", () => {
  const { store, root, packed } = spliceStore();
  const read = pdt.PVector.load<number>(store, root);
  assert.equal(read.relaxed(), true);
  assert.equal(read.count(), 1101);
  assert.deepEqual(read.toArray(), SPLICED);
  for (const i of [0, 31, 32, 499, 500, 501, 1000, 1068, 1069, 1100]) {
    assert.equal(read.nth(i), SPLICED[i], `index ${i}`);
  }
  const vr = read.packed();
  assert.equal(vr.relaxed(), false);
  assert.equal(vr.root(), packed);
  const editor = pdt.PVector.empty<number>(pdt.NodeStore.inMemory()).editor();
  SPLICED.forEach((n) => editor.conj(n));
  assert.equal(editor.done().root(), packed, "the packed root is the vr root of the same elements");
  assert.ok(read.equals(vr), "equality compares packed roots");
  assert.equal(read.root(), root, "a loaded relaxed vector keeps its root");
});

test("PDT 2 phase 7: an edit of a relaxed vector packs it first, and a level-2 reader reads the result (P2-R-03)", () => {
  const { store, root } = spliceStore();
  const read = pdt.PVector.load<number>(store, root);
  const grown = read.conj(1100).assocN(500, -2).pop();
  assert.equal(grown.relaxed(), false);
  assert.deepEqual(grown.toArray(), SPLICED.map((n, i) => (i === 500 ? -2 : n)));
  assert.deepEqual(pdt.PVector.load<number>(store, grown.root()).toArray(), grown.toArray());
});

test("PDT 2 phase 7: an rr root whose tail another port left empty reads (P2-R-04)", () => {
  const store = pdt.NodeStore.inMemory();
  const ranges = [[0, 32], [32, 40], [40, 72]] as const;
  const interior = new RvNode(ranges.map(([from, to]) => holding(store, leaf(from, to))), ranges.map(([, to]) => to));
  const root = store.put(new RrRoot(72, 5, holding(store, interior.encode()), []).encode(), pdt.cids.DAG_CBOR);
  const read = pdt.PVector.load<number>(store, root);
  assert.deepEqual(read.toArray(), Array.from({ length: 72 }, (_, i) => i));
  assert.equal(read.nth(71), 71);
  assert.equal(read.packed().count(), 72);
});

test("PDT 2 phase 7: the reader refuses by name the relaxed forms §3.7 refuses (P2-R-04)", () => {
  const cases: [string, (store: pdt.NodeStore) => string, RegExp][] = [
    ["an rv node without z", (store) => {
      const node = pdt.nodes.encode({ k: "rv", c: [holding(store, leaf(0, 32)), holding(store, leaf(32, 40))] });
      return store.put(new RrRoot(41, 5, holding(store, node), [new Embedded(dumps(40))]).encode(), pdt.cids.DAG_CBOR);
    }, /without z/],
    ["a z table a radix index reads the same way", (store) => {
      const node = new RvNode([holding(store, leaf(0, 32)), holding(store, leaf(32, 40))], [32, 40]);
      return store.put(new RrRoot(41, 5, holding(store, node.encode()), [new Embedded(dumps(40))]).encode(), pdt.cids.DAG_CBOR);
    }, /dense node/],
    ["a child that holds more than its level holds", (store) => {
      const node = new RvNode([holding(store, leaf(0, 8)), holding(store, leaf(8, 40))], [8, 48]);
      return store.put(new RrRoot(49, 5, holding(store, node.encode()), [new Embedded(dumps(48))]).encode(), pdt.cids.DAG_CBOR);
    }, /more than the 32/],
    ["an rv node at the leaf level", (store) => {
      const inner = new RvNode([holding(store, leaf(0, 8)), holding(store, leaf(8, 16))], [8, 16]);
      const node = new RvNode([holding(store, inner.encode()), holding(store, leaf(16, 24))], [16, 24]);
      return store.put(new RrRoot(25, 5, holding(store, node.encode()), [new Embedded(dumps(24))]).encode(), pdt.cids.DAG_CBOR);
    }, /where a vector leaf belongs/],
    ["a leaf where an interior node belongs", (store) => {
      const node = new RvNode([holding(store, leaf(0, 8)), holding(store, leaf(8, 16))], [8, 16]);
      return store.put(new RrRoot(17, 10, holding(store, node.encode()), [new Embedded(dumps(16))]).encode(), pdt.cids.DAG_CBOR);
    }, /vector leaf at level/],
    ["a size table that ends at another count", (store) => {
      const node = new RvNode([holding(store, leaf(0, 8)), holding(store, leaf(8, 16))], [8, 16]);
      return store.put(new RrRoot(21, 5, holding(store, node.encode()), [new Embedded(dumps(20))]).encode(), pdt.cids.DAG_CBOR);
    }, /does not hold the 20 elements/],
    ["a leaf of another length than its parent counts", (store) => {
      const node = new RvNode([holding(store, leaf(0, 8)), holding(store, leaf(8, 16))], [10, 16]);
      return store.put(new RrRoot(17, 5, holding(store, node.encode()), [new Embedded(dumps(16))]).encode(), pdt.cids.DAG_CBOR);
    }, /does not hold the 10 elements/],
  ];
  for (const [why, build, message] of cases) {
    const store = pdt.NodeStore.inMemory();
    const root = build(store);
    assert.throws(() => pdt.PVector.load<number>(store, root).toArray(), (e: unknown) => e instanceof pdt.NodeFormatError
      && message.test(e.message), why);
  }
});
