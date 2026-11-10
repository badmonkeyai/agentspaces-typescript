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
 * PDT 2 phase 7, verified windows in TypeScript (srad/agentspaces-pdt2.md §3.5; P2-C-01, P2-B-01 to P2-B-03): a window
 * of a blob read through its Bao outboard, every 16 KiB group delivered only after its chaining value verifies up to
 * the BLAKE3 identity, across the seam of the 8 MiB leaves of `pdt_bo_split`, with a corrupt group refused and the
 * groups around it delivered, and a reader that fetches only the nodes its window needs.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import * as pdt from "../src/pdt/index.js";
import { closeAll, fleet, run } from "./pdt-fleet.js";
import type { Node } from "./pdt-fleet.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8"));
const GROUP = pdt.kinds.BoNode.GROUP_BYTES;

/** `java.util.Random(42).nextBytes`, as the PDT vectors seed their blobs. */
function seeded(size: number): Uint8Array {
  const out = new Uint8Array(size);
  let seed = (42n ^ 0x5deece66dn) & ((1n << 48n) - 1n);
  const next = (): number => {
    seed = (seed * 0x5deece66dn + 0xbn) & ((1n << 48n) - 1n);
    return Number(BigInt.asIntN(32, seed >> 16n));
  };
  for (let i = 0; i < size;) {
    let rnd = next();
    for (let n = Math.min(size - i, 4); n-- > 0; rnd >>= 8) {
      out[i++] = rnd & 0xff;
    }
  }
  return out;
}

/** A blob, its outboard nodes, and its identity in one store. */
function published(data: Uint8Array, store = pdt.NodeStore.inMemory()): { store: pdt.NodeStore; root: string; bao: string; identity: string } {
  const blob = pdt.PBlob.of(data, store);
  const outboard = pdt.blake3.outboard([data]);
  for (const node of outboard.nodes.values()) {
    store.put(node, pdt.cids.DAG_CBOR);
  }
  return { store, root: blob.root, bao: outboard.root, identity: outboard.identity };
}

const SPLIT = seeded(pdt.kinds.BoNode.LEAF_GROUPS * GROUP + 5000);

test("PDT 2 phase 7: a window across the seam of pdt_bo_split's two leaves verifies group by group (P2-B-02, P2-B-03)", () => {
  const { store, root, bao, identity } = published(SPLIT);
  const [baoHex, identityText] = GOLDEN["pdt_bo_split"]!.split(",");
  assert.equal(identity, identityText);
  assert.equal(pdt.cids.of(store.get(bao)!, pdt.cids.DAG_CBOR), pdt.cids.of(Buffer.from(baoHex!, "hex"), pdt.cids.DAG_CBOR));
  const seam = pdt.kinds.BoNode.LEAF_GROUPS * GROUP;
  for (const [offset, length] of [[seam - 3 * GROUP - 7, 3 * GROUP + 4000], [0, 1], [SPLIT.length - 5000, 5000], [12_345, 70_000]]) {
    const window = pdt.window.readVerified(store, root, identity, bao, offset!, length!);
    assert.deepEqual(window, SPLIT.subarray(offset!, offset! + length!), `[${offset}, +${length})`);
  }
});

test("PDT 2 phase 7: a one-group blob verifies against its identity as the root, and an empty window reads nothing (P2-B-03)", () => {
  const data = seeded(5000);
  const { store, root, bao, identity } = published(data);
  assert.deepEqual(pdt.window.readVerified(store, root, identity, bao, 100, 4000), data.subarray(100, 4100));
  assert.deepEqual(pdt.window.readVerified(store, root, identity, bao, 10, 0), new Uint8Array(0));
});

/** A backend that serves one node's bytes with one byte flipped. */
class Corrupting extends pdt.MemoryBackend {
  constructor(private readonly victim: string, private readonly at: number) {
    super();
  }
  override get(cid: string): Uint8Array | undefined {
    const bytes = super.get(cid);
    if (bytes === undefined || cid !== this.victim) {
      return bytes;
    }
    const out = bytes.slice();
    out[this.at] = out[this.at]! ^ 0x01;
    return out;
  }
}

test("PDT 2 phase 7: one corrupt byte refuses its group, and the groups around it deliver (P2-B-03)", () => {
  const data = seeded(40 * GROUP + 999);
  const honest = published(data);
  const chunk = pdt.PBlob.load(honest.store, honest.root).chunks()[2]!;
  let start = 0;
  for (const c of pdt.PBlob.load(honest.store, honest.root).chunks()) {
    if (c.cid === chunk.cid) {
      break;
    }
    start += c.length;
  }
  const corruptAt = start + 10;
  const backend = new Corrupting(chunk.cid, 10);
  const store = new pdt.NodeStore(backend);
  for (const cid of honest.store.backend.cids()) {
    backend.put(cid, honest.store.get(cid)!);
  }
  const group = Math.floor(corruptAt / GROUP);
  assert.throws(() => pdt.window.readVerified(store, honest.root, honest.identity, honest.bao, group * GROUP, GROUP),
    new RegExp(`group ${group} does not verify`));
  assert.throws(() => pdt.window.readVerified(store, honest.root, honest.identity, honest.bao, 0, data.length));
  const after = (group + 1) * GROUP;
  assert.deepEqual(pdt.window.readVerified(store, honest.root, honest.identity, honest.bao, after, 3 * GROUP),
    data.subarray(after, after + 3 * GROUP));
});

test("PDT 2 phase 7: an outboard of other content, or of another size, is refused (P2-B-01, P2-B-03)", () => {
  const data = seeded(20 * GROUP);
  const { store, root, bao } = published(data);
  const other = published(seeded(20 * GROUP + 1), store);
  assert.throws(() => pdt.window.readVerified(store, root, other.identity, bao, 0, GROUP), /does not verify/);
  assert.throws(() => pdt.window.readVerified(store, root, other.identity, other.bao, 0, GROUP), /outboard of 327681 bytes/);
  assert.throws(() => pdt.window.readVerified(store, root, "not-an-identity", bao, 0, GROUP), /identity/);
});

test("PDT 2 phase 7: a reader fetches only the chunks, b nodes, and bo nodes its window needs (P2-B-03)", async () => {
  const nodes = fleet(2);
  const [a, b] = nodes as [Node, Node];
  try {
    const { root, bao, identity } = published(SPLIT, a.pdt.store);
    a.pdt.exchange!.holdTree(root);
    await run(nodes, 1);
    const offset = 3 * 1024 * 1024, length = 64 * 1024;
    const reading = b.pdt.openVerified(root, identity, bao, offset, length, [a.peer.identity.peerId]);
    for (let i = 0; i < 20; i++) {
      await run(nodes, 1);
    }
    assert.deepEqual(await reading, SPLIT.subarray(offset, offset + length));
    const held = b.pdt.store.bytesHeld;
    assert.ok(held < 400 * 1024, `the reader holds ${held} bytes, a small part of ${SPLIT.length}`);
  } finally {
    closeAll(nodes);
  }
});

test("PDT 2 phase 7: a blob ref's head names the identity and outboard of its value, which a reader verifies a window against (P2-B-01)", async () => {
  const nodes = fleet(2);
  const [a, b] = nodes as [Node, Node];
  try {
    const data = seeded(600 * 1024);
    const ra = a.pdt.ref<pdt.PBlob>("refs", "file", "blob");
    const written = await ra.swap(() => pdt.PBlob.of(data, a.pdt.store));
    const expected = pdt.blake3.outboard([data]);
    const rb = b.pdt.ref<pdt.PBlob>("refs", "file", "blob");
    for (let i = 0; i < 20 && rb.heads().length === 0; i++) {
      await run(nodes, 1);
    }
    const head = rb.heads()[0]!;
    assert.equal(head.root, written.root);
    assert.deepEqual([head.blake3, head.bao], [expected.identity, expected.root]);
    const window = await b.pdt.openVerified(head.root, head.blake3!, head.bao!, 300_000, 20_000, [a.peer.identity.peerId]);
    assert.deepEqual(window, data.subarray(300_000, 320_000));
  } finally {
    closeAll(nodes);
  }
});
