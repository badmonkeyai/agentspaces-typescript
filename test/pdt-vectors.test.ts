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

import { fromHex } from "../src/bytes.js";
import { CborDouble, dumps, loads } from "../src/cbor.js";
import { Identity, deriveId } from "../src/identity.js";
import { manifestViolation } from "../src/capabilities/content.js";
import type { Content } from "../src/capabilities/content.js";
import * as pdt from "../src/pdt/index.js";
import { UndecodableError } from "../src/records.js";
import type { Dict } from "../src/wire.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8"));
const hex = (name: string): Uint8Array => new Uint8Array(Buffer.from(GOLDEN[name]!, "hex"));
const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

/**
 * `java.util.Random`: the 48-bit LCG, so `new Random(42).nextBytes` reproduces the Java streams. The seed
 * is held as two 24-bit halves in doubles, every product below 2^53, so a long stream (PDT 2 phase 0,
 * P2-B-02, pdt_bo_split) costs no BigInt per word.
 */
class JavaRandom {
  private hi: number;
  private lo: number;
  constructor(seed: number) {
    const scrambled = (BigInt(seed) ^ 0x5deece66dn) & ((1n << 48n) - 1n);
    this.hi = Number(scrambled >> 24n);
    this.lo = Number(scrambled & 0xffffffn);
  }
  nextInt(): number {
    const low = this.lo * 0xece66d + 0xb;
    const carry = Math.floor(low / 0x1000000);
    this.hi = (this.lo * 0x5de + this.hi * 0xece66d + carry) % 0x1000000;
    this.lo = low - carry * 0x1000000;
    return (this.hi << 8) | (this.lo >>> 16);
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
});

// ------------------------------------------------------------------ PDT 2 phase 0 (srad/agentspaces-pdt2.md §8)

/** The sixteen vectors PDT 2 phase 0 added to golden.json (P2-O-01), each reproduced below. */
/**
 * Every vector PDT 2 added after the first design's, in the order golden.json lists them, and the test file that reads
 * it (PDT 2 phase 7, P2-C-01, P2-O-02): the phase 7 vectors leave no list of vectors still to read, as Python's
 * `PHASE7_VECTORS` ends empty.
 */
const PDT2_VECTORS: { readonly [name: string]: string } = {
  pdt_db_root: "pdt-vectors.test.ts", pdt_dn_leaf: "pdt-vectors.test.ts", pdt_dn_branch: "pdt-vectors.test.ts",
  pdt_dn_tail: "pdt-vectors.test.ts", pdt_datom_values: "pdt-vectors.test.ts", pdt_store_pin_cbor: "pdt-vectors.test.ts",
  pdt_store_receipt_cbor: "pdt-vectors.test.ts", pdt_blake3_identity: "pdt-vectors.test.ts", pdt_bo_small: "pdt-vectors.test.ts",
  pdt_bo_split: "pdt2-window.test.ts", pdt_rr_relaxed: "pdt-vectors.test.ts", pdt_rr_packed: "pdt-vectors.test.ts",
  pdt_text_runs: "pdt-vectors.test.ts", pdt_text_merge: "pdt-vectors.test.ts", pdt_vg_chain: "pdt-vectors.test.ts",
  pdt_ref_ancestry_cbor: "pdt-vectors.test.ts", pdt_vg_merge: "pdt-vectors.test.ts", pdt_ref_v2_cbor: "pdt2-refs.test.ts",
  pdt_db_sample: "pdt-db-reader.test.ts", pdt_db_sample_answers: "pdt-db-reader.test.ts", pdt_signed_pin_cbor: "pdt-vectors.test.ts",
  pdt_signed_pin_consent_cbor: "pdt-vectors.test.ts", pdt_manifest_tree_cbor: "pdt-vectors.test.ts",
  pdt_rr_splice: "pdt2-rrb.test.ts", pdt_text_edits: "pdt2-text.test.ts", pdt_text_value: "pdt2-text.test.ts",
  pdt_text_spill: "pdt2-text.test.ts", pdt_text_replica: "pdt2-text.test.ts", pdt_dcz_frame: "pdt2-deltas.test.ts",
  content_nodes_deltas_cbor: "pdt2-deltas.test.ts", content_challenge_cbor: "pdt2-stores.test.ts",
  asset_card_content_store_cbor: "pdt2-stores.test.ts", content_tree_want_sketch_cbor: "pdt2-sync.test.ts",
  content_tree_end_sketch_cbor: "pdt2-sync.test.ts", pdt_push_bundle_cbor: "pdt2-push.test.ts", pdt_riblt_symbols: "pdt2-sync.test.ts",
};
const { Datom, DatomTag, TextRun, CharId, Link, Embedded } = pdt.nodes;
const { DbRoot, DnNode, RrRoot, RvNode, TextLeaf, VgNode, BoNode } = pdt.kinds;
const TX1 = 536_870_913, TX2 = 536_870_914;
const AGE_1 = new Datom(1, ":person/age", 36, TX1);
const NAME_1 = new Datom(1, ":person/name", "Ada", TX1);
const AGE_2 = new Datom(2, ":person/age", 45, TX1);
const NAME_2 = new Datom(2, ":person/name", "Grace", TX1);
const parts = (name: string): string[] => GOLDEN[name]!.split(",");
const linkTo = (node: Uint8Array): pdt.nodes.Link => new Link(pdt.cids.of(node, pdt.cids.DAG_CBOR));
const cidOf = (node: Uint8Array): string => pdt.cids.of(node, pdt.cids.DAG_CBOR);
const counting = (from: number): Uint8Array => Uint8Array.from({ length: 32 }, (_, i) => from + i);
const GOLDEN_REQUESTER = deriveId(counting(0));
const GOLDEN_HOLDER = deriveId(counting(32));
const goldenIndex = (index: string): pdt.kinds.DnNode => DnNode.leaf(index, index === "eavt" ? [AGE_1, NAME_1, AGE_2, NAME_2]
  : index === "aevt" ? [AGE_1, AGE_2, NAME_1, NAME_2] : [NAME_1, NAME_2]);
const goldenTail = (): pdt.kinds.DnNode => DnNode.tail([new Datom(2, ":person/age", 45, -TX2), new Datom(2, ":person/age", 46, TX2)]);

/** The first `size` bytes of the `Random(42)` stream, 64 KiB at a time, as Java's PdtVectors.SeededStream reads it. */
function* seededStream(size: number): Generator<Uint8Array> {
  const random = new JavaRandom(42);
  for (let remaining = size; remaining > 0; remaining -= 64 * 1024) {
    const block = new Uint8Array(64 * 1024);
    random.nextBytes(block);
    yield block.subarray(0, Math.min(block.length, remaining));
  }
}

test("PDT 2 phase 7: golden.json lists every PDT 2 vector after the first design's, and a test file reads each one (P2-O-02, P2-C-01)", () => {
  const keys = Object.keys(GOLDEN);
  const after = keys.slice(keys.indexOf("pdt_sealed_node") + 1).filter((k) => /^(?:pdt_|content_|asset_card_)/.test(k));
  assert.deepEqual(after, Object.keys(PDT2_VECTORS), "a PDT 2 vector golden.json adds needs a reader here");
  for (const [name, file] of Object.entries(PDT2_VECTORS)) {
    const source = readFileSync(join(here, "..", "..", "test", file), "utf8");
    assert.ok(source.includes(`"${name}"`), `${file} reads ${name}`);
  }
});

test("PDT 2 phase 0: the db root, its index leaves and its tail match pdt_db_root, pdt_dn_leaf and pdt_dn_tail (P2-D-01)", () => {
  const schema = new Embedded(dumps({ ":person/name": { ":db/index": true } }));
  const root = new DbRoot({ schema, maxEid: 2, maxTx: TX2, branching: DbRoot.BRANCHING,
    eavt: linkTo(goldenIndex("eavt").encode()), aevt: linkTo(goldenIndex("aevt").encode()),
    avet: linkTo(goldenIndex("avet").encode()), tail: linkTo(goldenTail().encode()) });
  assert.equal([root.encode(), goldenIndex("aevt").encode(), goldenIndex("avet").encode()].map(toHex).join(","),
    GOLDEN["pdt_db_root"]);
  assert.equal(toHex(goldenIndex("eavt").encode()), GOLDEN["pdt_dn_leaf"]);
  assert.equal(toHex(goldenTail().encode()), GOLDEN["pdt_dn_tail"]);
  const [rootHex, aevtHex, avetHex] = parts("pdt_db_root");
  const read = DbRoot.decode(fromHex(rootHex!));
  assert.deepEqual(read.encode(), fromHex(rootHex!));
  assert.equal(read.maxEid, 2);
  assert.equal(read.maxTx, TX2);
  assert.equal(read.branching, 128);
  assert.equal(read.eavt.cid, cidOf(hex("pdt_dn_leaf")));
  assert.equal(read.aevt.cid, cidOf(fromHex(aevtHex!)));
  assert.equal(read.avet.cid, cidOf(fromHex(avetHex!)));
  assert.equal(read.tail?.cid, cidOf(hex("pdt_dn_tail")), "the tail travels linked from the root (§10.4, phase 0)");
  assert.deepEqual(pdt.nodes.links(fromHex(rootHex!)),
    [read.aevt.cid, read.avet.cid, read.eavt.cid, read.tail!.cid], "the index map in aevt, avet, eavt order, then the tail");
  const tail = DnNode.decode(hex("pdt_dn_tail"));
  assert.equal(tail.index, "tail");
  assert.deepEqual(tail.datoms.map((d) => d.tx), [-TX2, TX2]);
  assert.deepEqual(DnNode.decode(fromHex(avetHex!)).datoms.map((d) => d.v), ["Ada", "Grace"]);
});

test("PDT 2 phase 0: the branch keys each child by its largest datom (pdt_dn_branch, P2-D-01)", () => {
  const first = DnNode.leaf("eavt", [AGE_1, NAME_1]);
  const second = DnNode.leaf("eavt", [AGE_2, NAME_2]);
  const branch = DnNode.branch(1, "eavt", [NAME_1, NAME_2], [linkTo(first.encode()), linkTo(second.encode())]);
  assert.equal([branch, first, second].map((n) => toHex(n.encode())).join(","), GOLDEN["pdt_dn_branch"]);
  const read = DnNode.decode(fromHex(parts("pdt_dn_branch")[0]!));
  assert.equal(read.level, 1);
  assert.deepEqual(read.children.map((l) => l.cid), [cidOf(first.encode()), cidOf(second.encode())]);
  assert.deepEqual(read.datoms, [NAME_1, NAME_2]);
});

test("PDT 2 phase 0: one datom per value form matches pdt_datom_values (P2-D-01)", () => {
  const spill = new Link(pdt.cids.of(new Uint8Array(5000), pdt.cids.RAW));
  const leaf = DnNode.leaf("eavt", [
    new Datom(3, ":v/bigint", DatomTag.bigint(2n ** 70n), TX1),
    new Datom(3, ":v/bool", true, TX1),
    new Datom(3, ":v/bytes", Uint8Array.of(0, 1, 2), TX1),
    new Datom(3, ":v/float", new CborDouble(1.5), TX1),
    new Datom(3, ":v/instant", DatomTag.instant(1_792_320_000_000), TX1),
    new Datom(3, ":v/int", -7, TX1),
    new Datom(3, ":v/keyword", ":status/active", TX1),
    new Datom(3, ":v/ref", 2, TX1),
    new Datom(3, ":v/spill", spill, TX1),
    new Datom(3, ":v/text", "Ada ✓", TX1),
    new Datom(3, ":v/uuid", DatomTag.uuid(fromHex("0123456789abcdeffedcba9876543210")), -TX2)]);
  assert.equal(toHex(leaf.encode()), GOLDEN["pdt_datom_values"]);
  const read = DnNode.decode(hex("pdt_datom_values"));
  assert.deepEqual(read.datoms, leaf.datoms);
  assert.deepEqual(pdt.nodes.links(hex("pdt_datom_values")), [spill.cid], "a spilled datom value is a link of the node");
  assert.deepEqual(DatomTag.bigint(-129n).inner, Uint8Array.of(0xff, 0x7f), "BigInteger.toByteArray's minimal form");
  assert.deepEqual(DatomTag.bigint(128n).inner, Uint8Array.of(0x00, 0x80));
  assert.deepEqual(DatomTag.bigint(0n).inner, Uint8Array.of(0x00));
});

test("PDT 2 phase 0: StorePin and StoreReceipt match their vectors and read strictly (P2-S-02)", () => {
  const { storePin, storeReceipt, decodeStorePin, decodeStoreReceipt, storePinViolation, storeReceiptViolation }
    = pdt.storeRecords;
  const deep = cidOf(hex("pdt_map_deep")), small = cidOf(hex("pdt_map_small"));
  const pin = storePin({ root: deep, kind: "tree", lease: 86_400, copies: 2, requester: GOLDEN_REQUESTER, haves: [small],
    attrs: { purpose: "golden" } });
  assert.deepEqual(dumps(pin), hex("pdt_store_pin_cbor"));
  const receipt = storeReceipt({ root: deep, holder: GOLDEN_HOLDER, bytes: 12_345, until: 1_792_406_400_000, blind: true });
  assert.deepEqual(dumps(receipt), hex("pdt_store_receipt_cbor"));
  const readPin = decodeStorePin(hex("pdt_store_pin_cbor"));
  assert.equal(storePinViolation(readPin), null);
  assert.equal(readPin["requester"], GOLDEN_REQUESTER);
  assert.deepEqual(readPin["haves"], [small]);
  assert.deepEqual(pdt.storeRecords.storePinTags(readPin), { root: deep, requester: GOLDEN_REQUESTER });
  const readReceipt = decodeStoreReceipt(hex("pdt_store_receipt_cbor"));
  assert.equal(storeReceiptViolation(readReceipt), null);
  assert.deepEqual(pdt.storeRecords.storeReceiptTags(readReceipt), { root: deep, holder: GOLDEN_HOLDER });
  assert.equal(pdt.storeRecords.STORE_PIN_TYPE, "ai.badmonkey.agentspaces.agent.content.StorePin#v1");
  assert.equal(pdt.storeRecords.STORE_RECEIPT_TYPE, "ai.badmonkey.agentspaces.agent.content.StoreReceipt#v1");
});

test("PDT 2 phase 0: a store record with a field its schema lacks, or out of its form, is undecodable (P2-F-08)", () => {
  const { decodeStorePin, decodeStoreReceipt, storePinViolation, storeReceiptViolation } = pdt.storeRecords;
  const pin = decodeStorePin(hex("pdt_store_pin_cbor"));
  const receipt = decodeStoreReceipt(hex("pdt_store_receipt_cbor"));
  assert.throws(() => decodeStorePin(dumps({ ...pin, extra: 1 })), RangeError);
  assert.throws(() => decodeStoreReceipt(dumps({ ...receipt, extra: 1 })), RangeError);
  assert.throws(() => decodeStoreReceipt(dumps({ ...receipt, bytes: "12345" })), RangeError);
  const { haves: _haves, ...withoutHaves } = pin;
  assert.throws(() => decodeStorePin(dumps(withoutHaves)), RangeError, "haves is never absent");
  const { attrs: _attrs, ...withoutAttrs } = pin;
  assert.equal(decodeStorePin(dumps(withoutAttrs))["attrs"], undefined, "attrs is absent when null");
  assert.equal(storePinViolation({ ...pin, v: 2 }), "unsupported StorePin version 2");
  assert.equal(storePinViolation({ ...pin, root: "bafy" }), "root is not a CID");
  assert.equal(storePinViolation({ ...pin, kind: "file" }), "unknown kind file");
  assert.equal(storePinViolation({ ...pin, lease: 0 }), "lease of 0 seconds");
  assert.equal(storePinViolation({ ...pin, copies: 0 }), "copies below 1");
  assert.equal(storePinViolation({ ...pin, haves: Array(9).fill(pin["root"]) }), "more than 8 haves");
  assert.equal(storePinViolation({ ...pin, haves: ["x"] }), "have is not a CID");
  const many = Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`k${i}`, "v"]));
  assert.equal(storePinViolation({ ...pin, attrs: many }), "more than 32 attrs");
  assert.equal(storePinViolation({ ...pin, attrs: { big: "é".repeat(2048) } }), "attrs larger than 4096 bytes");
  assert.equal(storeReceiptViolation({ ...receipt, v: 2 }), "unsupported StoreReceipt version 2");
  assert.equal(storeReceiptViolation({ ...receipt, root: "x" }), "root is not a CID");
  assert.equal(storeReceiptViolation({ ...receipt, bytes: -1 }), "negative bytes");
  assert.equal(storeReceiptViolation({ ...receipt, until: -1 }), "negative until");
});

// ------------------------------------------------------------------ PDT 2 follow-ups, 2026-11-09, F1 and F3

const SIGNED_PIN_GROUP = "zGolden", SIGNED_PIN_NOT_AFTER = 1_792_323_600_000;

test("PDT 2 follow-ups: the signed pin rebuilds from its requester's seed and carries its consent (F1)", () => {
  const { storePin, signPin, consentBytes, decodeSignedPin, signedPinViolation, signedPinConsented, signedPinTags }
    = pdt.storeRecords;
  const requester = Identity.fromSeed(counting(64));
  const deep = cidOf(hex("pdt_map_deep")), small = cidOf(hex("pdt_map_small"));
  const pin = storePin({ root: deep, kind: "tree", lease: 86_400, copies: 2, requester: requester.peerId, haves: [small],
    attrs: { "pdt.stores": GOLDEN_HOLDER } });
  assert.deepEqual(consentBytes(pin, SIGNED_PIN_GROUP, SIGNED_PIN_NOT_AFTER), hex("pdt_signed_pin_consent_cbor"));
  const signed = signPin(pin, SIGNED_PIN_GROUP, SIGNED_PIN_NOT_AFTER, requester);
  assert.deepEqual(dumps(signed), hex("pdt_signed_pin_cbor"));
  const read = decodeSignedPin(hex("pdt_signed_pin_cbor"));
  assert.equal(signedPinViolation(read), null);
  assert.deepEqual(dumps(read), hex("pdt_signed_pin_cbor"));
  assert.equal(read["left"], 2);
  assert.ok(signedPinConsented(read, SIGNED_PIN_GROUP));
  assert.ok(!signedPinConsented(read, "zOther"), "a consent in one group is none in another");
  assert.deepEqual(signedPinTags(read), { root: deep, requester: requester.peerId });
  assert.equal(pdt.storeRecords.SIGNED_PIN_TYPE, "ai.badmonkey.agentspaces.agent.content.SignedPin#v1");
});

test("PDT 2 follow-ups: a pin its requester did not sign is no consent, and a signed pin reads strictly (F1)", () => {
  const { storePin, signPin, decodeSignedPin, signedPinViolation, signedPinConsented } = pdt.storeRecords;
  const alice = Identity.generate(), mallory = Identity.generate();
  const terms = (who: Identity, copies = 1): Dict => storePin({ root: cidOf(hex("pdt_map_deep")), kind: "tree", lease: 86_400,
    copies, requester: who.peerId, attrs: { "pdt.stores": "zA" } });
  const forged = signPin(terms(mallory), "zStores", SIGNED_PIN_NOT_AFTER, mallory);
  const renamed = { ...forged, pin: terms(alice) };
  assert.equal(signedPinViolation(renamed), null);
  assert.ok(!signedPinConsented(renamed, "zStores"), "the key is not the requester's");
  assert.ok(!signedPinConsented({ ...renamed, key: alice.publicRaw }, "zStores"));
  // mallory's own key over the very consent bytes of terms naming alice verifies, so the key binding refuses it
  const consent = pdt.storeRecords.consentBytes(terms(alice), "zStores", SIGNED_PIN_NOT_AFTER);
  const ownKey = { ...renamed, sig: mallory.sign(consent) };
  assert.ok(Identity.verify(mallory.publicRaw, consent, ownKey.sig));
  assert.ok(!signedPinConsented(ownKey, "zStores"), "a forger's own key over terms naming alice");
  const honest = signPin(terms(alice, 2), "zStores", SIGNED_PIN_NOT_AFTER, alice);
  assert.ok(!signedPinConsented({ ...honest, pin: terms(alice, 3) }, "zStores"), "changed terms");
  assert.ok(!signedPinConsented({ ...honest, notAfter: SIGNED_PIN_NOT_AFTER + 1 }, "zStores"), "a later deadline");
  assert.ok(signedPinConsented({ ...honest, left: 1 }, "zStores"), "a store counts the copies down");
  assert.throws(() => signPin(terms(alice), "zStores", SIGNED_PIN_NOT_AFTER, mallory), /requester/);
  assert.throws(() => decodeSignedPin(dumps({ ...honest, holder: "zForger" })), RangeError);
  assert.throws(() => decodeSignedPin(dumps({ ...honest, left: true })), RangeError);
  assert.throws(() => decodeSignedPin(dumps({ ...honest, key: "aa" })), RangeError);
  assert.throws(() => decodeSignedPin(dumps({ ...honest, pin: { ...(honest["pin"] as Dict), extra: 1 } })), RangeError);
  const { left: _left, ...withoutLeft } = honest;
  assert.throws(() => decodeSignedPin(dumps(withoutLeft)), RangeError);
  assert.equal(signedPinViolation({ ...honest, v: 2 }), "unsupported SignedPin version 2");
  assert.equal(signedPinViolation({ ...honest, left: 3 }), "left 3 is outside 1 to 2 copies");
  assert.equal(signedPinViolation({ ...honest, notAfter: -1 }), "negative notAfter");
  assert.equal(signedPinViolation({ ...honest, key: new Uint8Array(31) }), "key is not 32 bytes");
  assert.equal(signedPinViolation({ ...honest, sig: new Uint8Array(63) }), "sig is not 64 bytes");
  assert.equal(signedPinViolation({ ...honest, pin: { ...(honest["pin"] as Dict), root: "root" } }), "root is not a CID");
});

test("PDT 2 follow-ups: the tree manifest of the small blob carries no piece table and passes the manifest check (F3)", () => {
  const m = loads(hex("pdt_manifest_tree_cbor")) as Dict;
  assert.equal(m["layout"], "tree");
  assert.equal(m["table"], null);
  assert.equal(m["tableRef"], null);
  assert.equal(m["root"], parts("pdt_blob_small")[0]);
  assert.equal(pdt.cids.parse(m["root"] as string).codec, pdt.cids.DAG_CBOR);
  assert.equal(manifestViolation(m), null);
  assert.deepEqual(dumps(m), hex("pdt_manifest_tree_cbor"));
  const { layout: _layout, ...flat } = m;
  assert.equal(manifestViolation(flat), "exactly one of table and tableRef must be present");
});

test("PDT 2 phase 0: the BLAKE3 identity of the seeded 8 MiB stream matches pdt_blake3_identity (P2-B-02)", () => {
  const bytes = seeded(8 * 1024 * 1024);
  assert.equal(pdt.blake3.identity(pdt.blake3.digest(bytes)), GOLDEN["pdt_blake3_identity"]);
  assert.ok(GOLDEN["pdt_blake3_identity"]!.startsWith("bafkr4i"));
});

test("PDT 2 phase 0: the chaining-value tree reaches the BLAKE3 digest at every boundary (P2-B-02)", () => {
  const bytes = seeded(70 * 1024);
  for (const size of [0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 3073, 16 * 1024 - 1, 16 * 1024, 16 * 1024 + 1,
    32 * 1024, 48 * 1024 + 7, 64 * 1024, 70 * 1024]) {
    const data = bytes.subarray(0, size);
    const built = pdt.blake3.outboard([data]);
    assert.equal(built.identity, pdt.blake3.identity(pdt.blake3.digest(data)), `size ${size}`);
    const root = BoNode.decode(built.nodes.get(built.root)!);
    const digest = root.parents.length === 0
      ? pdt.blake3.digest(data)
      : pdt.blake3.parent(root.parents.subarray(0, 32), root.parents.subarray(32, 64), true);
    assert.equal(pdt.blake3.identity(digest), built.identity, `the root pair of size ${size} hashes to its identity`);
  }
});

test("PDT 2 phase 0: the outboard of the seeded 100 KiB blob matches pdt_bo_small (P2-B-02)", () => {
  const built = pdt.blake3.outboard([seeded(100 * 1024)]);
  assert.equal(`${toHex(built.nodes.get(built.root)!)},${built.identity}`, GOLDEN["pdt_bo_small"]);
  const node = BoNode.decode(fromHex(parts("pdt_bo_small")[0]!));
  assert.equal(node.size, 100 * 1024);
  assert.deepEqual(node.children, []);
  assert.equal(node.parents.length, 6 * 64, "seven groups take six parents");
});

test("PDT 2 phase 4 measures: the outboard of 8 MiB plus 5000 bytes splits as pdt_bo_split (P2-B-02, P2-Q-PRF-05)", () => {
  const size = BoNode.LEAF_GROUPS * BoNode.GROUP_BYTES + 5000;
  const built = pdt.blake3.outboard(seededStream(size));
  const root = BoNode.decode(built.nodes.get(built.root)!);
  assert.equal([toHex(built.nodes.get(built.root)!), built.identity, ...root.children.map((l) => l.cid)].join(","),
    GOLDEN["pdt_bo_split"]);
  assert.equal(root.parents.length, 64, "two children, one parent above the cut");
  assert.equal(built.nodes.size, 3);
  const full = BoNode.decode(built.nodes.get(root.children[0]!.cid)!);
  assert.equal(full.parents.length, (BoNode.LEAF_GROUPS - 1) * 64);
  assert.equal(built.nodes.get(root.children[0]!.cid)!.length, 32728, "a full leaf of 8 MiB");
});

test("PDT 2 phase 0: the relaxed RRB tree and the packed vector match pdt_rr_relaxed and pdt_rr_packed (P2-R-01)", () => {
  const leaf = (from: number, to: number): Uint8Array => pdt.nodes.encode({ k: "v",
    e: Array.from({ length: to - from }, (_, i) => new Embedded(dumps(from + i))) });
  const ranges = [[0, 32], [32, 40], [40, 72], [72, 96]] as const;
  const interior = new RvNode(ranges.map(([from, to]) => linkTo(leaf(from, to))), ranges.map(([, to]) => to));
  const root = new RrRoot(100, 5, linkTo(interior.encode()), [96, 97, 98, 99].map((i) => new Embedded(dumps(i))));
  assert.equal(`${toHex(root.encode())},${toHex(interior.encode())}`, GOLDEN["pdt_rr_relaxed"]);
  const store = pdt.NodeStore.inMemory();
  const editor = pdt.PVector.empty<pdt.CborValue>(store).editor();
  for (let i = 0; i < 100; i++) {
    editor.conj(i);
  }
  assert.equal(toHex(rootNode(store, editor.done().root())), GOLDEN["pdt_rr_packed"]);
  const [rootHex, interiorHex] = parts("pdt_rr_relaxed");
  const read = RrRoot.decode(fromHex(rootHex!));
  assert.equal(read.trie?.cid, cidOf(fromHex(interiorHex!)));
  assert.deepEqual(RvNode.decode(fromHex(interiorHex!)).sizes, [32, 40, 72, 96]);
  assert.deepEqual(read.tail.map((e) => loads(e.bytes)), [96, 97, 98, 99]);
});

test("PDT 2 phase 0: the text leaves read and merge in Fugue order as pdt_text_runs and pdt_text_merge (P2-T-01)", () => {
  const runs = new TextLeaf([
    new TextRun("alice", 0, null, "R", 4, false, "Ab\u{1F600}c"),
    new TextRun("alice", 4, new CharId("alice", 1), "L", 2, true, ""),
    new TextRun("bob", 0, new CharId("alice", 3), "R", 2, false, "é!")]);
  assert.equal(toHex(runs.encode()), GOLDEN["pdt_text_runs"]);
  assert.equal(TextLeaf.decode(hex("pdt_text_runs")).text(), "Ab\u{1F600}cé!");
  const alice = new TextLeaf([
    new TextRun("alice", 0, null, "R", 2, false, "ac"),
    new TextRun("alice", 2, new CharId("alice", 1), "L", 1, false, "b")]);
  const bob = new TextLeaf([
    new TextRun("alice", 0, null, "R", 1, true, ""),
    new TextRun("alice", 1, new CharId("alice", 0), "R", 1, false, "c"),
    new TextRun("bob", 0, new CharId("alice", 1), "L", 2, false, "XY")]);
  const merged = alice.union(bob);
  assert.equal([alice.encode(), bob.encode(), merged.encode()].map(toHex).join(",") + `,${merged.text()}`,
    GOLDEN["pdt_text_merge"]);
  assert.deepEqual(bob.union(alice).encode(), merged.encode(), "the union commutes");
  assert.equal(merged.text(), "bXYc");
  const [aliceHex, bobHex, mergedHex] = parts("pdt_text_merge");
  assert.deepEqual(TextLeaf.decode(fromHex(aliceHex!)).union(TextLeaf.decode(fromHex(bobHex!))).encode(), fromHex(mergedHex!));
});

test("PDT 2 phase 0: the vg chain and the head that names it match pdt_vg_chain and pdt_ref_ancestry_cbor (P2-V-01)", () => {
  const deepRoot = cidOf(hex("pdt_map_deep")), smallRoot = cidOf(hex("pdt_map_small"));
  const writer = `${GOLDEN_REQUESTER}/writer`;
  const small = new VgNode(smallRoot, [], writer, "1792320000000:0:golden", []);
  const deep = new VgNode(deepRoot, [smallRoot], writer, "1792320000001:0:golden", [linkTo(small.encode())]);
  assert.equal(`${toHex(deep.encode())},${toHex(small.encode())}`, GOLDEN["pdt_vg_chain"]);
  assert.deepEqual(pdt.nodes.links(deep.encode()), [cidOf(small.encode())], "a vg node links no root");
  const head = pdt.pref({ name: "facts", kind: "map", root: deepRoot, base: [smallRoot], seq: 2, size: 100,
    attrs: { [pdt.ANCESTRY_ATTR]: cidOf(deep.encode()) } });
  assert.deepEqual(dumps(head), hex("pdt_ref_ancestry_cbor"));
  const read = pdt.decodePRef(hex("pdt_ref_ancestry_cbor"));
  assert.equal(read["v"], 1, "ancestry needs no new record version (rule 9)");
  assert.equal(pdt.prefViolation(read), null);
  assert.equal(pdt.ancestryCid(read), cidOf(deep.encode()));
  assert.deepEqual(pdt.readAncestry(read, deep.encode())?.encode(), deep.encode());
});

test("PDT 2 phase 0: a head's ancestry is advisory and reads as absent unless it names a vg node of the head's root (P2-V-02)", () => {
  const [deepHex, smallHex] = parts("pdt_vg_chain");
  const read = pdt.decodePRef(hex("pdt_ref_ancestry_cbor"));
  const withAttr = (text: pdt.CborValue): Dict => ({ ...read, attrs: { [pdt.ANCESTRY_ATTR]: text } });
  assert.equal(pdt.ancestryCid({ ...read, attrs: undefined as unknown as Dict }), null);
  assert.equal(pdt.ancestryCid(withAttr("not a cid")), null);
  assert.equal(pdt.ancestryCid(withAttr(pdt.cids.of(fromHex(deepHex!), pdt.cids.RAW))), null, "a raw CID names no node");
  assert.equal(pdt.ancestryCid(withAttr(7)), null);
  assert.equal(pdt.readAncestry(read, fromHex(smallHex!)), null, "bytes of another node");
  const smallHead = withAttr(cidOf(fromHex(smallHex!)));
  assert.equal(pdt.readAncestry(smallHead, fromHex(smallHex!)), null, "a vg node of another root");
  const leafHead = withAttr(cidOf(hex("pdt_dn_leaf")));
  assert.equal(pdt.readAncestry(leafHead, hex("pdt_dn_leaf")), null, "a node of another kind");
});

test("PDT 2 phase 0: every PDT 2 node vector round-trips through the node codec and its typed reader", () => {
  const nodeHex = [GOLDEN["pdt_dn_leaf"]!, GOLDEN["pdt_dn_tail"]!, GOLDEN["pdt_datom_values"]!, GOLDEN["pdt_text_runs"]!,
    GOLDEN["pdt_rr_packed"]!, ...parts("pdt_db_root"), ...parts("pdt_dn_branch"), ...parts("pdt_rr_relaxed"),
    ...parts("pdt_vg_chain"), parts("pdt_bo_small")[0]!, parts("pdt_bo_split")[0]!, ...parts("pdt_text_merge").slice(0, 3)];
  const readers: { [kind: string]: (bytes: Uint8Array) => { encode(): Uint8Array } } = {
    db: (b) => DbRoot.decode(b), dn: (b) => DnNode.decode(b), rr: (b) => RrRoot.decode(b), rv: (b) => RvNode.decode(b),
    t: (b) => TextLeaf.decode(b), vg: (b) => VgNode.decode(b), bo: (b) => BoNode.decode(b) };
  for (const text of nodeHex) {
    const bytes = fromHex(text);
    assert.deepEqual(pdt.nodes.encode(pdt.nodes.decode(bytes)), bytes, text.slice(0, 40));
    const reader = readers[pdt.nodes.kindOf(bytes)];
    if (reader !== undefined) {
      assert.deepEqual(reader(bytes).encode(), bytes, text.slice(0, 40));
    }
  }
});

test("PDT 2 phase 0: the node codec refuses by name what the level-2 schemas do not allow (P2-F-04, annex H)", () => {
  assert.deepEqual([...pdt.nodes.RESERVED_KINDS].sort(), ["ec", "s", "tm"]);
  for (const [kind, node] of [["s", "a1616b6173"], ["tm", "a1616b62746d"], ["ec", "a1616b626563"]] as const) {
    assert.throws(() => pdt.nodes.encode({ k: kind }), /reserved/, kind);
    assert.throws(() => pdt.nodes.decode(fromHex(node)), /reserved/, kind);
  }
  assert.equal(pdt.nodes.kindOf(fromHex("a1616b627272")), "rr", "rr has a schema now");
  const leaf = pdt.nodes.decode(hex("pdt_dn_leaf"));
  assert.throws(() => pdt.nodes.encode({ ...leaf, z: [] }), /outside the schema of kind 'dn'/);
  // a non-shortest integer head: l = 0 written as 0x18 0x00
  const bytes = hex("pdt_dn_leaf");
  const at = toHex(bytes).indexOf("616c00") / 2;
  const widened = new Uint8Array([...bytes.subarray(0, at + 2), 0x18, 0x00, ...bytes.subarray(at + 3)]);
  assert.throws(() => pdt.nodes.decode(widened), /shortest/);
  // malformed UTF-8 in a strict text field: the index name "eavt" with an invalid byte
  const index = toHex(bytes).indexOf("6465617674") / 2;
  const broken = Uint8Array.from(bytes);
  broken[index + 1] = 0xff;
  assert.throws(() => pdt.nodes.decode(broken), /UTF-8/);
  assert.throws(() => DnNode.leaf("eavt", [new Datom(1, ":a/\ud800", 1, TX1)]).encode(), /lone surrogate/);
  assert.throws(() => pdt.nodes.encode({ k: "vg", r: "x", b: [], i: "p/w", t: "1:0:n", p: [] }), /CID as text/);
  assert.throws(() => pdt.nodes.encode({ ...pdt.nodes.decode(fromHex(parts("pdt_db_root")[0]!)),
    i: { eavt: new Link(cidOf(hex("pdt_dn_leaf"))) } as unknown as pdt.nodes.IndexLinks }), /aevt, avet and eavt/);
});

test("PDT 2 phase 0: datoms refuse a value outside the grammar of §3.1.1 (P2-D-01)", () => {
  assert.throws(() => new Datom(1, ":a/b", 1, 0), /tx is non-zero/);
  assert.throws(() => new Datom(1, ":a/b", 1.5, TX1), /CborDouble/);
  assert.throws(() => new Datom(1, ":a/b", new CborDouble(Number.NaN), TX1), /finite/);
  assert.throws(() => new Datom(1, ":a/b", null as unknown as string, TX1), /grammar/);
  assert.throws(() => new Datom(2 ** 64 as unknown as number, ":a/b", 1, TX1), /64-bit/);
  assert.throws(() => new Datom(2n ** 63n, ":a/b", 1, TX1), /64-bit/);
  assert.throws(() => new DatomTag("u", Uint8Array.of(1)), /16 bytes/);
  assert.throws(() => new DatomTag("n", Uint8Array.of(0, 1)), /minimal/);
  assert.throws(() => new DatomTag("n", Uint8Array.of(0xff, 0x80)), /minimal/);
  assert.throws(() => new DatomTag("x" as "u", Uint8Array.of(1)), /unknown value tag/);
  const extreme = DnNode.leaf("eavt", [new Datom(-(2n ** 63n), ":a/b", 2n ** 63n - 1n, 2n ** 63n - 1n)]);
  const read = DnNode.decode(extreme.encode());
  assert.deepEqual(read.datoms[0], extreme.datoms[0], "entity, value and tx keep every 64-bit value");
  assert.equal(read.datoms[0]!.e, -(2n ** 63n));
  const leafBytes = toHex(DnNode.leaf("eavt", [new Datom(1, ":a/b", new CborDouble(1.5), TX1)]).encode());
  const asFloat32 = leafBytes.replace("fb3ff8000000000000", "fa3fc00000");
  assert.throws(() => pdt.nodes.decode(fromHex(asFloat32)), /float32/);
  const asNull = leafBytes.replace("fb3ff8000000000000", "f6");
  assert.throws(() => pdt.nodes.decode(fromHex(asNull)), /null/);
});

test("PDT 2 phase 0: the typed readers refuse shapes the kinds do not allow", () => {
  assert.throws(() => DnNode.leaf("vaet", [AGE_1]), /index/);
  assert.throws(() => DnNode.tail([]), /empty tail/);
  assert.throws(() => new DnNode(0, "tail", [AGE_1], [linkTo(hex("pdt_dn_leaf"))]), /level 0|carries no 'c'/);
  assert.throws(() => DnNode.branch(1, "eavt", [AGE_1, NAME_1], [linkTo(hex("pdt_dn_leaf"))]), /one link per key/);
  assert.throws(() => DnNode.decode(hex("pdt_text_runs")), /where a 'dn' node belongs/);
  const rootBytes = fromHex(parts("pdt_db_root")[0]!);
  const node = pdt.nodes.decode(rootBytes);
  assert.throws(() => DbRoot.decode(pdt.nodes.encode({ ...node, v: 2 })), /version 2/);
  assert.throws(() => DbRoot.decode(pdt.nodes.encode({ ...node, s: new Embedded(dumps([1])) })), /schema is a map/);
  const read = DbRoot.decode(rootBytes);
  // the codec's wire check refuses an integer key on the way in; the constructor refuses one it is handed
  assert.throws(() => new DbRoot({ ...read, schema: new Embedded(fromHex("bf0102ff")) }), /keys are text/);
  assert.throws(() => new DbRoot({ ...read, branching: 1 }), /at least 2/);
  const { t: _t, ...noTail } = node;
  assert.throws(() => DbRoot.decode(pdt.nodes.encode(noTail)), /lacks 't'/);
  assert.throws(() => new RrRoot(40, 5, null, Array.from({ length: 33 }, (_, i) => new Embedded(dumps(i)))), /at most 32/);
  assert.throws(() => new RrRoot(4, 3, null, []), /multiple of 5/);
  assert.throws(() => new RrRoot(4, 5, linkTo(hex("pdt_dn_leaf")), [1, 2, 3, 4].map((i) => new Embedded(dumps(i)))),
    /no element/);
  assert.throws(() => new RvNode([], null), /1 to 32/);
  assert.throws(() => new RvNode([linkTo(hex("pdt_dn_leaf")), linkTo(hex("pdt_dn_tail"))], [4, 4]), /strictly increasing/);
  assert.throws(() => new BoNode(100 * 1024, new Uint8Array(64), []), /parents/);
  assert.throws(() => new BoNode(-1, new Uint8Array(0), []), /non-negative/);
  const split = BoNode.decode(fromHex(parts("pdt_bo_split")[0]!));
  assert.throws(() => new BoNode(split.size, split.parents, split.children.slice(0, 1)), /2 children, found 1/);
  assert.throws(() => new BoNode(100 * 1024, new Uint8Array(6 * 64), split.children.slice(0, 1)), /0 children, found 1/);
  const bo = pdt.nodes.decode(fromHex(parts("pdt_bo_small")[0]!));
  assert.throws(() => BoNode.decode(pdt.nodes.encode({ ...bo, g: 6 })), /group size/);
  const raw = new Link(pdt.cids.of(Uint8Array.of(1), pdt.cids.RAW));
  const smallRoot = cidOf(hex("pdt_map_small"));
  assert.throws(() => new VgNode(smallRoot, [smallRoot], `${GOLDEN_REQUESTER}/writer`, "1:0:n", [raw]), /dag-cbor/);
  assert.throws(() => new VgNode(smallRoot, [], "no-slash", "1:0:n", []), /issuer/);
  assert.throws(() => new VgNode(smallRoot, [], `${GOLDEN_REQUESTER}/writer`, "01:0:n", []), /issued/);
  assert.throws(() => new VgNode(smallRoot, [], `${GOLDEN_REQUESTER}/writer`, "1:0:n", [linkTo(hex("pdt_dn_leaf"))]),
    /one earlier vg node per base/);
  assert.throws(() => new VgNode(smallRoot, Array(9).fill(smallRoot), `${GOLDEN_REQUESTER}/writer`, "1:0:n", []), /at most 8/);
});

test("PDT 2 phase 0: text runs and leaves keep the one canonical form of §3.9 (P2-T-01)", () => {
  assert.throws(() => new TextRun("alice", 0, null, "L", 1, false, "a"), /document root hangs on its right/);
  assert.throws(() => new TextRun("alice", 0, null, "R", 1, true, "a"), /deleted run carries no text/);
  assert.throws(() => new TextRun("alice", 0, null, "R", 2, false, "a"), /length 2/);
  assert.throws(() => new TextRun("", 0, null, "R", 1, false, "a"), /non-empty replica/);
  assert.throws(() => new TextRun("alice", 0, null, "X" as "L", 1, false, "a"), /L or R/);
  assert.throws(() => new TextRun("alice", 0, null, "R", 0, true, ""), /at least 1/);
  assert.throws(() => new TextLeaf([new TextRun("alice", 0, null, "R", 1, false, "a"),
    new TextRun("alice", 1, new CharId("alice", 0), "R", 1, false, "b")]), /canonical form/, "a run that is not maximal");
  assert.throws(() => new TextLeaf([new TextRun("bob", 0, null, "R", 1, false, "b"),
    new TextRun("alice", 0, null, "R", 1, false, "a")]), /canonical form/, "runs out of id order");
  assert.throws(() => new TextLeaf([new TextRun("alice", 0, new CharId("carol", 0), "R", 1, false, "a")]), /not in the leaf/);
  assert.throws(() => new TextLeaf([new TextRun("alice", 0, new CharId("bob", 0), "R", 1, false, "a"),
    new TextRun("bob", 0, new CharId("alice", 0), "R", 1, false, "b")]), /cycle/);
  // the id order is the replica's UTF-8 bytes: U+E000 (ee 80 80) before U+1F600 (f0 9f 98 80), the reverse of UTF-16
  const leaf = TextLeaf.of([new TextRun("\u{1F600}", 0, null, "R", 1, false, "b"), new TextRun("", 0, null, "R", 1, false, "a")]);
  assert.deepEqual(leaf.runs.map((r) => r.replica), ["", "\u{1F600}"]);
  assert.equal(leaf.text(), "ab");
  const other = new TextLeaf([new TextRun("alice", 0, null, "R", 1, false, "z")]);
  assert.throws(() => new TextLeaf([new TextRun("alice", 0, null, "R", 1, false, "a")]).union(other), /disagree/);
});

test("PDT 2 phase 0: a text leaf holds at most the node byte bound of characters (P2-T-01, gate finding G1)", () => {
  // a deleted run costs no text bytes, so without a bound a 29-byte node naming one deleted run of 2^40
  // characters would expand forever in every port; the bound is checked before expansion, as in Java
  assert.equal(TextLeaf.MAX_CHARS, pdt.nodes.MAX_NODE_BYTES);
  const full = new TextLeaf([new TextRun("alice", 0, null, "R", TextLeaf.MAX_CHARS, true, "")]);
  assert.equal(full.text(), "");
  assert.throws(() => new TextLeaf([new TextRun("alice", 0, null, "R", TextLeaf.MAX_CHARS + 1, true, "")]),
    /at most 1048576 characters/);
  assert.throws(() => TextLeaf.of([new TextRun("alice", 0, null, "R", TextLeaf.MAX_CHARS, true, ""),
    new TextRun("bob", 0, null, "R", 1, false, "b")]), /at most 1048576 characters/);
  assert.throws(() => full.union(new TextLeaf([new TextRun("bob", 0, null, "R", 1, false, "b")])), /at most 1048576 characters/);
  const hostile = pdt.nodes.encode({ k: "t", r: [new TextRun("a", 0, null, "R", 2 ** 40, true, "")], v: 1 });
  assert.equal(hostile.length, 29);
  const started = performance.now();
  assert.throws(() => TextLeaf.decode(hostile), (e: Error) => e.name === "NodeFormatError" && /at most 1048576 characters/.test(e.message));
  assert.ok(performance.now() - started < 1000);
});

test("PDT 2 phase 0: a member is at the pdt level its newest content advertisement states, else level 1 (P2-F-05)", () => {
  const ad = (parameters: Dict | null): Dict => ({ parameters });
  assert.equal(pdt.tree.PDT_PARAMETER, "pdt");
  assert.equal(pdt.tree.TREES_VERSION, "1", "trees stays 1, which 0.5.0 peers compare exactly");
  assert.equal(pdt.tree.featureLevel(null), 1);
  assert.equal(pdt.tree.featureLevel(ad(null)), 1);
  assert.equal(pdt.tree.featureLevel(ad({ trees: "1" })), 1);
  assert.equal(pdt.tree.featureLevel(ad({ pdt: "2" })), 2);
  assert.equal(pdt.tree.featureLevel(ad({ pdt: "17" })), 17);
  for (const text of ["02", " 2", "2.0", "+2", "two", "", "0x2", "٢"]) {
    assert.equal(pdt.tree.featureLevel(ad({ pdt: text })), 1, `'${text}' is no canonical decimal`);
  }
  assert.equal(pdt.tree.featureLevel(ad({ pdt: 2 })), 1, "a level is text");
  assert.equal(pdt.tree.featureLevel(ad({ pdt: "99999999999999999999" })), Number.MAX_SAFE_INTEGER);
  assert.equal(pdt.tree.featureLevel(ad({ pdt: "0" })), 1, "no member is below level 1");
});

test("PDT 2 phase 7: this client advertises trees 1 and pdt 2, a member built at level 1 no pdt, and it reads a member's level from its newest live advertisement (P2-F-05, P2-C-01)", () => {
  const published: Dict[] = [];
  const ads = new Map<string, { type: string; ad: Dict; stored: Dict; issuer: string; expires: number }>();
  const peer = { group: "g", now: () => 100_000, ads, pipeHandlers: new Map(),
    publishAd: (_type: string, ad: Dict) => { published.push(ad); } };
  const exchange = new pdt.TreeExchange({ peer, selfId: GOLDEN_HOLDER, pipes: { send: () => undefined } } as unknown as Content,
    pdt.NodeStore.inMemory());
  const parameters = published[0]!["parameters"] as Dict;
  assert.equal(parameters["trees"], "1");
  assert.equal(parameters["pdt"], "2", "the decoders carry every level-2 schema of 6.10.4 (PDT 2 phase 7)");
  new pdt.TreeExchange({ peer, selfId: GOLDEN_HOLDER, pipes: { send: () => undefined } } as unknown as Content,
    pdt.NodeStore.inMemory(), { level: 1 });
  assert.ok(!Object.hasOwn(published[1]!["parameters"] as Dict, "pdt"), "a member built at level 1 states no level");
  const ad = (issued: string, expires: number, extra: Dict): { type: string; ad: Dict; stored: Dict; issuer: string; expires: number } =>
    ({ type: "CapabilityAdvertisement", issuer: GOLDEN_REQUESTER, expires, stored: {},
      ad: { capabilityType: "aspace:cap/content-swarm", issued, parameters: { trees: "1", ...extra } } });
  assert.equal(exchange.pdtLevel(GOLDEN_REQUESTER), 1, "a member without an advertisement");
  ads.set("a", ad("1970-01-01T00:00:10Z", 200_000, { pdt: "2" }));
  assert.equal(exchange.pdtLevel(GOLDEN_REQUESTER), 2);
  ads.set("b", ad("1970-01-01T00:00:20Z", 200_000, {}));
  assert.equal(exchange.pdtLevel(GOLDEN_REQUESTER), 1, "the newest advertisement states no level");
  ads.set("c", ad("1970-01-01T00:00:30Z", 50_000, { pdt: "2" }));
  assert.equal(exchange.pdtLevel(GOLDEN_REQUESTER), 1, "an expired advertisement counts for nothing");
});

test("PDT 2 phase 0: a reader at level 1 ignores a PRef v 2 head and a head of kind db (rule 8, P2-F-06)", () => {
  const head = pdt.decodePRef(hex("pdt_ref_min_cbor"));
  assert.equal(pdt.prefViolation({ ...head, v: 2 }, 1), "unsupported PRef version 2");
  assert.equal(pdt.prefViolation({ ...head, kind: "db" }, 1), "unknown kind db");
});

// ------------------------------------------------------------------ PDT 2 phase 0, the adversary's pass (2026-11-09)

test("PDT 2 phase 0: the store record writers refuse a value their annex I schema refuses, so no reader drops what they write (P2-S-02, P2-F-08)", () => {
  const { storePin, storeReceipt, decodeStorePin, decodeStoreReceipt } = pdt.storeRecords;
  const root = cidOf(hex("pdt_map_deep"));
  const pin = { root, kind: "tree", lease: 60, copies: 1, requester: GOLDEN_REQUESTER };
  assert.deepEqual(decodeStorePin(dumps(storePin(pin))), storePin(pin), "an honest pin round-trips");
  for (const [field, value] of [["lease", 1.5], ["lease", 2 ** 60], ["lease", Number.NaN], ["copies", 2 ** 31], ["copies", 0.5],
    ["requester", ""]] as const) {
    assert.throws(() => storePin({ ...pin, [field]: value }), UndecodableError, `${field} ${String(value)}`);
  }
  assert.throws(() => storePin({ ...pin, attrs: { purpose: 1 as unknown as string } }), UndecodableError, "an attrs value is text");
  const receipt = { root, holder: GOLDEN_HOLDER, bytes: 1, until: 1, blind: false };
  assert.deepEqual(decodeStoreReceipt(dumps(storeReceipt(receipt))), storeReceipt(receipt), "an honest receipt round-trips");
  for (const [field, value] of [["bytes", 2 ** 60], ["until", 0.5], ["holder", ""], ["blind", 1]] as const) {
    assert.throws(() => storeReceipt({ ...receipt, [field]: value } as unknown as typeof receipt), UndecodableError,
      `${field} ${String(value)}`);
  }
});

test("PDT 2 phase 0: the level-2 node codec refuses every integer, text and shape a Java NodeCodec refuses (P2-D-01, P2-T-01, P2-V-01)", () => {
  const leafOf = (datom: Uint8Array): Uint8Array => fromHex(`a4616581${toHex(datom)}616b62646e616c0061786465617674`);
  const datom = (e: string, v = "01", tx = "05"): Uint8Array => fromHex(`84${e}63${toHex(new TextEncoder().encode(":ab"))}${v}${tx}`);
  assert.equal(DnNode.decode(leafOf(datom("1b0000000100000000"))).datoms[0]!.e, 2 ** 32, "a 9-byte head from 2^32 up");
  assert.throws(() => pdt.nodes.decode(leafOf(datom("1b00000000ffffffff"))), /shortest/, "a 9-byte head below 2^32");
  assert.throws(() => pdt.nodes.decode(leafOf(datom("3b0000000000000007"))), /shortest/, "a negative one too");
  for (const big of ["1b8000000000000000", "3b8000000000000000", "1bffffffffffffffff"]) {
    assert.throws(() => pdt.nodes.decode(leafOf(datom(big))), pdt.NodeFormatError, `${big} is past the signed 64-bit range`);
  }
  const bom = DnNode.leaf("eavt", [new Datom(1, ":a/b", "\ufeffAda", TX1)]).encode();
  assert.deepEqual(pdt.nodes.encode(pdt.nodes.decode(bom)), bom, "a leading U+FEFF is text and stays");
  const rootNode = pdt.nodes.decode(fromHex(parts("pdt_db_root")[0]!));
  const renamed = toHex(pdt.nodes.encode(rootNode)).replace("6461657674", "64617a7a7a");
  assert.throws(() => pdt.nodes.decode(fromHex(renamed)), /aevt, avet and eavt/, "an index map whose first key is azzz");
  const vgHex = parts("pdt_vg_chain")[1]!;
  const vgRoot = (pdt.nodes.decode(fromHex(vgHex))["r"]) as string;
  const notCid = vgHex.replace(toHex(dumps(vgRoot)), toHex(dumps("x".repeat(59))));
  assert.throws(() => pdt.nodes.decode(fromHex(notCid)), /CID as text/, "the node codec reads a vg root as a CID");
  const leafWithC = `a5616380${toHex(hex("pdt_dn_leaf")).slice(2)}`;
  assert.throws(() => DnNode.decode(fromHex(leafWithC)), /leaf carries no 'c'/, "an empty c list is still a c");
  const v2 = toHex(hex("pdt_text_runs")).replace(/617601$/, "617602");
  assert.throws(() => TextLeaf.decode(fromHex(v2)), /version 2/);
  assert.throws(() => new TextRun("a", Number.MAX_SAFE_INTEGER, null, "R", 1, false, "x"), /2\^53 - 1/);
  assert.throws(() => new RvNode(Array(33).fill(linkTo(hex("pdt_dn_leaf"))), null), /1 to 32/);
});

test("PDT 2 phase 4 measures: a bo node splits one level higher past 2^13 groups, as Java's BoNode.childSizes does (P2-B-02)", () => {
  const leaf = BoNode.LEAF_GROUPS * BoNode.GROUP_BYTES;
  const level = leaf * BoNode.FANOUT;
  const shape = (size: number): string => {
    const sizes = BoNode.childSizes(size);
    return sizes.length === 0 ? "leaf" : `${sizes.length} of ${sizes[0]}, last ${sizes[sizes.length - 1]}`;
  };
  assert.equal(shape(leaf), "leaf");
  assert.equal(shape(leaf + 1), `2 of ${leaf}, last 1`);
  assert.equal(leaf, 8 * 1024 * 1024);
  assert.equal(shape(level), `16 of ${leaf}, last ${leaf}`);
  assert.equal(shape(level + 1), `2 of ${level}, last 1`);
  assert.equal(shape(16 * level), `16 of ${level}, last ${level}`);
});

test("PDT 2 phase 0: a pin at its bounds passes and one past them does not (P2-S-02, §3.2.2)", () => {
  const { storePin, storePinViolation } = pdt.storeRecords;
  const root = cidOf(hex("pdt_map_deep"));
  const pin = storePin({ root, kind: "tree", lease: 1, copies: 1, requester: GOLDEN_REQUESTER });
  assert.equal(storePinViolation({ ...pin, haves: Array(8).fill(root) }), null, "8 haves");
  const attrs = (n: number): { [key: string]: string } => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, "v"]));
  assert.equal(storePinViolation({ ...pin, attrs: attrs(32) }), null, "32 attrs");
  assert.equal(storePinViolation({ ...pin, attrs: { a: "x".repeat(2047), b: "y".repeat(2047) } }), null, "4096 bytes");
  assert.equal(storePinViolation({ ...pin, attrs: { a: "x".repeat(2047), b: "y".repeat(2048) } }), "attrs larger than 4096 bytes");
});

test("PDT 2 phase 0: a head's ancestry reads only the bytes its CID names, even from a vg node of the same root (P2-V-02)", () => {
  const read = pdt.decodePRef(hex("pdt_ref_ancestry_cbor"));
  const deep = VgNode.decode(fromHex(parts("pdt_vg_chain")[0]!));
  const forged = new VgNode(deep.root, deep.bases, deep.issuer, "1792320000002:0:golden", deep.previous).encode();
  assert.equal(pdt.readAncestry(read, forged), null, "a vg node of the head's root under another CID");
});

// ------------------------------------------------------------------ PDT 2 phase 1 (srad/agentspaces-pdt2.md §8)

test("PDT 2 phase 1: a merge version's vg node links each base's node in the order of its bases, as pdt_vg_merge (P2-V-01)", () => {
  const [deepHex, smallHex] = parts("pdt_vg_chain");
  const deepRoot = cidOf(hex("pdt_map_deep")), smallRoot = cidOf(hex("pdt_map_small"));
  const merge = new VgNode(cidOf(hex("pdt_map_empty")), [deepRoot, smallRoot], `${GOLDEN_REQUESTER}/writer`,
    "1792320000002:0:golden", [linkTo(fromHex(deepHex!)), linkTo(fromHex(smallHex!))]);
  assert.equal(toHex(merge.encode()), GOLDEN["pdt_vg_merge"]);
  const read = VgNode.decode(hex("pdt_vg_merge"));
  assert.deepEqual(read.bases, [deepRoot, smallRoot]);
  assert.deepEqual(read.previous.map((link) => link.cid), [cidOf(fromHex(deepHex!)), cidOf(fromHex(smallHex!))]);
  assert.deepEqual(pdt.nodes.encode(pdt.nodes.decode(hex("pdt_vg_merge"))), hex("pdt_vg_merge"));
});

/** The CID with the lowest of its two padding bits set: the same 36 bytes in a text that is not their one form. */
const withPaddingBit = (cid: string): string => {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const last = alphabet.indexOf(cid[cid.length - 1]!);
  assert.equal(last & 3, 0, "a canonical CID's padding bits are zero");
  return cid.slice(0, -1) + alphabet[last | 1];
};

test("PDT 2 phase 1: tree messages read as Java's fromWire reads them, and a relabelled one is undecodable (P2-X-09)", () => {
  for (const name of ["content_node_want_cbor", "content_nodes_cbor", "content_tree_want_cbor", "content_tree_end_cbor"]) {
    assert.deepEqual(dumps(pdt.tree.readTreeMessage(hex(name))!), hex(name), name);
  }
  const reject = pdt.tree.treeReject(cidOf(hex("pdt_map_small")), 1);
  assert.deepEqual(pdt.tree.readTreeMessage(dumps(reject)), reject);
  const want = loads(hex("content_tree_want_cbor")) as Dict;
  const relabelled: [string, Dict][] = [
    ["an unknown field", { ...want, extra: "x" }],
    ["a field out of order", { t: want["t"]!, root: want["root"]!, req: want["req"]!, haves: want["haves"]!,
      budget: want["budget"]!, sketch: null }],
    ["an absent field", { t: want["t"]!, req: want["req"]!, root: want["root"]!, haves: want["haves"]!, budget: want["budget"]! }],
    ["a budget as text", { ...want, budget: String(want["budget"]) }],
    ["a CID with a padding bit set", { ...want, root: withPaddingBit(String(want["root"])) }],
    ["a tag that names another schema", { ...want, t: pdt.tree.TREE_END }],
  ];
  for (const [why, message] of relabelled) {
    assert.equal(pdt.tree.readTreeMessage(dumps(message)), null, why);
  }
  assert.equal(pdt.tree.readTreeMessage(dumps({ t: 13, req: 1 })), null, "an unknown tag");
  assert.equal(pdt.tree.readTreeMessage(dumps({ ...reject, index: "-1" })), null, "a reject index as text");
});
