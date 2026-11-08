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
 * The PDT golden vectors in TypeScript (srad/agentspaces-pdt.md PD-N-07, PD-O-02, PD-B-01, PD-R-01): every
 * `pdt_*` field of the vendored golden.json recomputed from this port, every node vector round-tripped
 * through the node codec to the same bytes, the four tree messages (`content_*` tree keys) encoded byte
 * for byte, and the PD-N-03 check: the IPLD reference decoder `@ipld/dag-cbor` accepts `pdt_node_dagcbor`
 * and refuses `pdt_node_embedded`, which a generic CBOR decoder reads.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import * as dagCbor from "@ipld/dag-cbor";

import { dumps, loads } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import * as pdt from "../src/pdt/index.js";
import type { Dict } from "../src/wire.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8"));
const hex = (name: string): Uint8Array => new Uint8Array(Buffer.from(GOLDEN[name]!, "hex"));
const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

/** `java.util.Random`: the 48-bit LCG, so `new Random(42).nextBytes` reproduces the Java streams. */
class JavaRandom {
  private seed: bigint;
  constructor(seed: number) {
    this.seed = (BigInt(seed) ^ 0x5deece66dn) & ((1n << 48n) - 1n);
  }
  nextInt(): number {
    this.seed = (this.seed * 0x5deece66dn + 0xbn) & ((1n << 48n) - 1n);
    return Number(BigInt.asIntN(32, this.seed >> 16n));
  }
  nextBytes(out: Uint8Array): void {
    for (let i = 0; i < out.length;) {
      let rnd = this.nextInt();
      for (let n = Math.min(out.length - i, 4); n-- > 0; rnd >>= 8) {
        out[i++] = rnd & 0xff;
      }
    }
  }
}

function seeded(size: number): Uint8Array {
  const out = new Uint8Array(size);
  new JavaRandom(42).nextBytes(out);
  return out;
}

function rootNode(store: pdt.NodeStore, root: string): Uint8Array {
  const bytes = store.get(root);
  assert.ok(bytes !== undefined, `root ${root} was not flushed`);
  return bytes;
}

const NODE_VECTORS = ["pdt_map_empty", "pdt_map_small", "pdt_map_deep", "pdt_vector_tail", "pdt_vector_deep",
  "pdt_node_dagcbor", "pdt_node_embedded"];

test("the map and vector root nodes match the Java golden vectors", () => {
  const store = pdt.NodeStore.inMemory();
  assert.equal(toHex(rootNode(store, pdt.PMap.empty(store).root())), GOLDEN["pdt_map_empty"]);
  const small = pdt.PMap.empty<string, pdt.CborValue>(store).assoc("a", 1).assoc("b", "two");
  assert.equal(toHex(rootNode(store, small.root())), GOLDEN["pdt_map_small"]);
  assert.equal(GOLDEN["pdt_node_dagcbor"], GOLDEN["pdt_map_small"]);
  const editor = pdt.PMap.empty<string, pdt.CborValue>(store).editor();
  for (let i = 0; i < 100; i++) {
    editor.assoc(`k${i}`, i);
  }
  const deep = editor.done();
  assert.equal(toHex(rootNode(store, deep.root())), GOLDEN["pdt_map_deep"]);
  assert.equal(deep.count(), 100);
  assert.equal(deep.get("k42"), 42);
  // the same key set reached one key at a time has the same root (PD-V-01)
  let oneByOne = pdt.PMap.empty<string, pdt.CborValue>(store);
  for (let i = 99; i >= 0; i--) {
    oneByOne = oneByOne.assoc(`k${i}`, i);
  }
  assert.equal(oneByOne.root(), deep.root());
  const vectorOf = (count: number): string => {
    const ve = pdt.PVector.empty<pdt.CborValue>(store).editor();
    for (let i = 0; i < count; i++) {
      ve.conj(i);
    }
    return ve.done().root();
  };
  assert.equal(toHex(rootNode(store, vectorOf(10))), GOLDEN["pdt_vector_tail"]);
  assert.equal(toHex(rootNode(store, vectorOf(1100))), GOLDEN["pdt_vector_deep"]);
  const reloaded = pdt.PVector.load<pdt.CborValue>(store, vectorOf(1100));
  assert.equal(reloaded.count(), 1100);
  assert.equal(reloaded.nth(1050), 1050);
  assert.equal(reloaded.nth(3), 3);
});

test("pdt_node_embedded is the node of a map-valued and a float32-valued entry (PD-N-03)", () => {
  // the Java vector embeds a float32 (1.5f); the client's codec writes float64, so the node is built from the
  // raw items the Java codec produced, which is what the embedding rule of §10.2 allows
  const store = pdt.NodeStore.inMemory();
  const f32 = Uint8Array.of(0xfa, 0x3f, 0xc0, 0x00, 0x00);
  const rawCodec: pdt.Codec<Uint8Array> = { encode: (b) => b, decode: (b) => b };
  const map = pdt.PMap.empty<string, Uint8Array>(store, undefined, rawCodec)
    .assoc("rec", dumps({ x: 1, y: "two" }))
    .assoc("f", f32);
  assert.equal(toHex(rootNode(store, map.root())), GOLDEN["pdt_node_embedded"]);
  assert.deepEqual({ ...(loads(map.get("rec")!) as Dict) }, { x: 1, y: "two" });
});

test("every pdt_* node vector round-trips through the node codec to the same bytes", () => {
  for (const name of NODE_VECTORS) {
    const bytes = hex(name);
    const node = pdt.nodes.decode(bytes);
    assert.deepEqual(pdt.nodes.encode(node), bytes, name);
    assert.ok(pdt.nodes.links(bytes).every((cid) => pdt.cids.isCid(cid)), name);
  }
  assert.equal(pdt.nodes.links(hex("pdt_map_deep")).length, 25);
  assert.equal(pdt.nodes.links(hex("pdt_vector_deep")).length, 1);
  assert.equal(pdt.nodes.links(hex("pdt_map_small")).length, 0);
});

test("the IPLD reference decoder accepts pdt_node_dagcbor and refuses pdt_node_embedded (PD-N-03)", () => {
  const outcomes: { [name: string]: string } = {};
  for (const name of NODE_VECTORS) {
    try {
      dagCbor.decode(hex(name));
      outcomes[name] = "accepted";
    } catch (e) {
      outcomes[name] = `refused: ${e instanceof Error ? e.message : String(e)}`;
    }
  }
  const accepted = dagCbor.decode(hex("pdt_node_dagcbor")) as { k: string; cnt: number; e: unknown[] };
  assert.equal(accepted.k, "m");
  assert.equal(accepted.cnt, 2);
  assert.deepEqual(accepted.e, ["a", 1, "b", "two"]);
  const deep = dagCbor.decode(hex("pdt_map_deep")) as { c: { toString(): string }[] };
  assert.equal(deep.c.length, 25);
  assert.equal(String(deep.c[0]), pdt.nodes.links(hex("pdt_map_deep"))[0]);
  assert.match(outcomes["pdt_node_embedded"]!, /^refused/);
  for (const name of NODE_VECTORS) {
    if (name !== "pdt_node_embedded") {
      assert.equal(outcomes[name], "accepted", name);
    }
  }
  // the generic decoder reads the embedded node: the map value in its indefinite form, the float as float32
  const generic = pdt.nodes.decode(hex("pdt_node_embedded"));
  const e = generic["e"] as pdt.nodes.Embedded[];
  assert.deepEqual({ ...(loads(e[3]!.bytes) as Dict) }, { x: 1, y: "two" });
  assert.equal(e[1]!.bytes[0], 0xfa);
});

test("the seeded blob and the FastCDC cut points match Java", () => {
  const store = pdt.NodeStore.inMemory();
  const blob = pdt.PBlob.of(seeded(100 * 1024), store);
  assert.equal([blob.root, ...blob.chunks().map((c) => c.cid)].join(","), GOLDEN["pdt_blob_small"]);
  assert.deepEqual(blob.bytes(), seeded(100 * 1024));
  assert.deepEqual(blob.read(65_000, 10), seeded(100 * 1024).subarray(65_000, 65_010));
  const cuts = pdt.fastcdc.cuts(seeded(8 * 1024 * 1024));
  assert.equal(cuts.slice(0, 20).join(","), GOLDEN["pdt_fastcdc_cuts"]);
  for (let i = 1; i < cuts.length; i++) {
    const length = cuts[i]! - cuts[i - 1]!;
    assert.ok(length >= pdt.fastcdc.MIN_SIZE && length <= pdt.fastcdc.MAX_SIZE);
  }
});

test("the PRef head records match pdt_ref_cbor and pdt_ref_min_cbor (PD-R-01)", () => {
  const store = pdt.NodeStore.inMemory();
  const editor = pdt.PMap.empty<string, pdt.CborValue>(store).editor();
  for (let i = 0; i < 100; i++) {
    editor.assoc(`k${i}`, i);
  }
  const deepRoot = editor.done().root();
  const deepNode = rootNode(store, deepRoot);
  const firstChild = pdt.nodes.links(deepNode, deepRoot)[0]!;
  const smallRoot = pdt.PMap.empty<string, pdt.CborValue>(store).assoc("a", 1).assoc("b", "two").root();
  const ref = pdt.pref({ name: "facts", kind: "map", root: deepRoot, base: [smallRoot], seq: 2, size: 100,
    nodes: [deepNode, rootNode(store, firstChild)], mode: "multi", sealing: "none", keyEpoch: 3, attrs: { origin: "golden" } });
  assert.deepEqual(dumps(ref), hex("pdt_ref_cbor"));
  assert.equal(pdt.prefViolation(loads(hex("pdt_ref_cbor")) as Dict), null);
  const min = pdt.pref({ name: "facts", kind: "map", root: pdt.PMap.empty(store).root(), base: [], seq: 1, size: 0,
    mode: "multi", sealing: "none" });
  assert.deepEqual(dumps(min), hex("pdt_ref_min_cbor"));
  assert.equal(pdt.prefViolation(min), null);
  assert.deepEqual(pdt.prefTags(min), { name: "facts", root: min["root"] });
  assert.equal(pdt.prefViolation({ ...min, root: "bafkrei" }), "root is not a CID");
  assert.equal(pdt.prefViolation({ ...min, kind: "list" }), "unknown kind list");
});

test("the tree messages match the content_* tree vectors (PD-X-02)", () => {
  const nodeWant = loads(hex("content_node_want_cbor")) as Dict;
  assert.deepEqual(dumps(pdt.tree.nodeWant(42, nodeWant["cids"] as string[])), hex("content_node_want_cbor"));
  const nodes = loads(hex("content_nodes_cbor")) as Dict;
  assert.deepEqual(dumps(pdt.tree.nodesMessage(42, nodes["nodes"] as Uint8Array[], nodes["missing"] as string[])),
    hex("content_nodes_cbor"));
  const treeWant = loads(hex("content_tree_want_cbor")) as Dict;
  assert.deepEqual(dumps(pdt.tree.treeWant(43, String(treeWant["root"]), treeWant["haves"] as string[], Number(treeWant["budget"]))),
    hex("content_tree_want_cbor"));
  assert.deepEqual(dumps(pdt.tree.treeEnd(43, [String((treeWant["haves"] as string[])[0])], pdt.tree.END_BUDGET)),
    hex("content_tree_end_cbor"));
  assert.equal(pdt.tree.peekTag(hex("content_tree_end_cbor")), 11);
  assert.equal(pdt.tree.peekTag(hex("content_piece_want_cbor")), 1);
});

test("CIDs parse, verify, and tell the two codecs apart", () => {
  const bytes = new TextEncoder().encode("hello");
  const raw = pdt.cids.of(bytes, pdt.cids.RAW);
  const dag = pdt.cids.of(bytes, pdt.cids.DAG_CBOR);
  assert.notEqual(raw, dag);
  assert.equal(pdt.cids.parse(raw).codec, 0x55);
  assert.equal(pdt.cids.parse(dag).codec, 0x71);
  assert.ok(raw.startsWith("bafkrei") && dag.startsWith("bafyrei"));
  assert.ok(pdt.cids.verifies(raw, bytes) && !pdt.cids.verifies(raw, new Uint8Array(5)));
  assert.equal(pdt.cids.fromBinary(pdt.cids.binary(dag)), dag);
  assert.throws(() => pdt.cids.parse(raw.slice(0, -1)));
  assert.ok(!pdt.cids.isCid(Identity.generate().peerId));
  assert.equal(GOLDEN["content_root_cidv1"]!.length, 59);
  assert.equal(pdt.cids.parse(GOLDEN["content_root_cidv1"]!).codec, pdt.cids.RAW);
});

test("the sealed node vector walks as an sn envelope whose nonce is the keyed digest of the plaintext", async () => {
  // PD-P-05 (srad/agentspaces-pdt.md 10.2, SPEC annex H): pdt_sealed_node is the sn envelope of
  // pdt_map_small's root under the test key 0x00..0x1f at epoch 3. This port walks the envelope
  // (its links are in the clear) and checks the keyed nonce; it carries no AES-GCM-SIV, so the
  // open under the key is the Java conformance test's and the Python port's.
  const { hkdf } = await import("@noble/hashes/hkdf.js");
  const { hmac } = await import("@noble/hashes/hmac.js");
  const { sha256 } = await import("@noble/hashes/sha2.js");
  const sealed = Buffer.from(GOLDEN["pdt_sealed_node"]!, "hex");
  const plain = Buffer.from(GOLDEN["pdt_map_small"]!, "hex");
  const node = pdt.nodes.decode(sealed);
  assert.equal(node["k"], pdt.nodes.KIND_SN);
  assert.equal(node["ep"], 3);
  assert.deepEqual(node["ln"], []);
  const nonce = new Uint8Array(node["nc"] as Uint8Array);
  const ciphertext = node["ct"] as Uint8Array;
  assert.equal(nonce.length, 12);
  assert.equal(ciphertext.length, plain.length + 16);
  assert.deepEqual(pdt.nodes.links(sealed), []);
  assert.deepEqual(new Uint8Array(pdt.nodes.encode(node)), new Uint8Array(sealed));
  const key = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    key[i] = i;
  }
  const nodeKey = hkdf(sha256, key, new Uint8Array(0), new TextEncoder().encode("aspace:pdt:node"), 32);
  assert.deepEqual(nonce, new Uint8Array(hmac(sha256, nodeKey, plain).subarray(0, 12)));
  assert.notDeepEqual(nonce, new Uint8Array(sha256(plain).subarray(0, 12)), "the nonce is keyed, not the bare digest");
  assert.equal(pdt.nodes.MAX_SEALED_NODE_BYTES, 1024 * 1024 + 48 * 1024);
  assert.deepEqual([...pdt.nodes.RESERVED_KINDS].sort(), ["rr", "s"]);
  assert.throws(() => pdt.nodes.decode(Buffer.from("a1616b627272", "hex")), /reserved/);
});
