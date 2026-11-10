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
 * PDT 2 phase 7, group Z in TypeScript (srad/agentspaces-pdt2.md §3.8; P2-C-01, P2-Z-01, P2-Z-04, P2-F-02): the
 * `dcz` field opened over its base (`pdt_dcz_frame`) with every refusal of Java's decision 4, the level-2 `NODES`
 * with its appended `deltas` read strictly (`content_nodes_deltas_cbor`), and a fetch that applies the deltas of a
 * `TREE_WANT` answer by the rules of Java's TreeFetchSession.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

import { concat, fromHex } from "../src/bytes.js";
import { dumps, loads } from "../src/cbor.js";
import { cryptoPort } from "../src/crypto.js";
import * as pdt from "../src/pdt/index.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8"));
const parts = (name: string): Uint8Array[] => GOLDEN[name]!.split(",").map(fromHex);
const { dcz, tree, cids } = pdt;
const [BASE, TARGET, FIELD] = parts("pdt_dcz_frame") as [Uint8Array, Uint8Array, Uint8Array];
const HEADER = dcz.HEADER_BYTES;

/** A field over the base with the zstd frame `frame` and the right RFC 9842 header. */
const fieldOf = (frame: Uint8Array, base: Uint8Array = BASE): Uint8Array =>
  concat(Uint8Array.of(0x64, 0x5e, 0x2a, 0x4d, 0x18, 0x20, 0x00, 0x00, 0x00), cryptoPort().sha256(base), frame);
const frameOf = (target: Uint8Array, contentSize = true): Uint8Array => new Uint8Array(zlib.zstdCompressSync(target,
  { dictionary: BASE, params: { [zlib.constants.ZSTD_c_contentSizeFlag]: contentSize ? 1 : 0,
    [zlib.constants.ZSTD_c_checksumFlag]: 0, [zlib.constants.ZSTD_c_dictIDFlag]: 0 } }));
const withByte = (bytes: Uint8Array, at: number, value: number): Uint8Array => {
  const out = bytes.slice();
  out[at] = value;
  return out;
};

test("PDT 2 phase 7: the dcz field of pdt_dcz_frame opens over its base to the target (P2-Z-01, P2-Z-04)", () => {
  assert.deepEqual(dcz.decode(BASE, FIELD), TARGET);
  assert.deepEqual(dcz.decode(BASE, fieldOf(frameOf(TARGET))), TARGET, "any encoder's frame opens alike");
});

test("PDT 2 phase 7: the dcz reader refuses by name what decision 4 refuses, before it decompresses (P2-Q-SEC-05)", () => {
  const descriptor = HEADER + 4;
  const big = new Uint8Array(300 * 1024);
  const magicBase = concat(Uint8Array.of(0x37, 0xa4, 0x30, 0xec), BASE.subarray(4));
  const cases: [string, () => Uint8Array, RegExp][] = [
    ["a VCDIFF frame", () => withByte(FIELD, 0, 0x76), /VCDIFF/],
    ["an unknown format byte", () => withByte(FIELD, 0, 0x78), /unknown format byte 0x78/],
    ["no RFC 9842 header", () => withByte(FIELD, 1, 0x00), /no RFC 9842 dcz header/],
    ["another base", () => withByte(FIELD, 20, FIELD[20]! ^ 1), /names another base/],
    ["no zstd frame", () => withByte(FIELD, HEADER, 0x00), /no zstd frame/],
    ["a reserved header bit", () => withByte(FIELD, descriptor, FIELD[descriptor]! | 0x08), /reserved bit/],
    ["a dictionary id", () => withByte(FIELD, descriptor, FIELD[descriptor]! | 0x01), /dictionary id/],
    ["no content size", () => fieldOf(frameOf(TARGET, false)), /declares no content size/],
    ["two frames", () => concat(FIELD, FIELD.subarray(HEADER)), /more than one zstd frame/],
    ["trailing bytes", () => concat(FIELD, Uint8Array.of(0)), /more than one zstd frame|cut short/],
    ["a cut frame", () => FIELD.subarray(0, FIELD.length - 3), /cut short/],
    ["a field too short", () => FIELD.subarray(0, HEADER + 2), /holds no format byte/],
  ];
  for (const [why, field, message] of cases) {
    assert.throws(() => dcz.decode(BASE, field()), (e: unknown) => e instanceof RangeError && e.message.startsWith("dcz:")
      && message.test(e.message), why);
  }
  assert.throws(() => dcz.decode(big, FIELD), /past the chunk bound/, "a base past 256 KiB");
  assert.throws(() => dcz.decode(magicBase, fieldOf(frameOf(TARGET), magicBase)), /dictionary magic/);
  // a content size past 256 KiB: the declared four-byte size of a frame of 300 KiB of zeros
  const zeros = new Uint8Array(zlib.zstdCompressSync(big, { params: { [zlib.constants.ZSTD_c_contentSizeFlag]: 1 } }));
  assert.throws(() => dcz.decode(BASE, fieldOf(zeros)), /past the chunk bound/);
  // a frame whose blocks write more than its header declares
  const frame = frameOf(TARGET);
  assert.equal(frame[4]! >> 6, 1, "a 4,106-byte target declares its size in two bytes");
  const at = 5 + ((frame[4]! & 0x20) !== 0 ? 0 : 1);
  const lying = frame.slice();
  const declared = (frame[at]! | (frame[at + 1]! << 8)) - 10;
  lying[at] = declared & 0xff;
  lying[at + 1] = declared >> 8;
  assert.throws(() => dcz.decode(BASE, fieldOf(lying)), /not one zstd frame that opens|wrote/);
});

test("PDT 2 phase 7: without a zstd port the reader refuses the frame by name, so the chunk travels whole (P2-Z-04)", () => {
  const port = dcz.zstdPort();
  dcz.installZstd(null);
  try {
    assert.throws(() => dcz.decode(BASE, FIELD), /zstd is not available/);
  } finally {
    dcz.installZstd(port);
  }
});

test("PDT 2 phase 7: the level-2 NODES of content_nodes_deltas_cbor reads strictly and its delta opens (P2-Z-01, P2-F-07)", () => {
  const bytes = fromHex(GOLDEN["content_nodes_deltas_cbor"]!);
  const msg = tree.readTreeMessage(bytes)!;
  assert.ok(msg !== null);
  assert.deepEqual(dumps(msg), bytes);
  const [delta] = msg["deltas"] as Dict[];
  assert.equal(delta!["cid"], cids.of(TARGET, cids.RAW));
  assert.equal(delta!["base"], cids.of(BASE, cids.RAW));
  assert.deepEqual(dcz.decode(BASE, delta!["dcz"] as Uint8Array), TARGET);
  const plain = loads(bytes) as Dict;
  delete plain["deltas"];
  assert.deepEqual(tree.readTreeMessage(dumps(plain))!["deltas"], undefined, "a NODES without deltas keeps its level-1 form");
  assert.equal(tree.readTreeMessage(dumps({ ...plain, deltas: null })), null, "a null deltas is omitted, never written");
  assert.equal(tree.readTreeMessage(dumps({ ...(loads(bytes) as Dict), deltas: [{ cid: "x", base: "y", dcz: FIELD }] })), null);
});

// ------------------------------------------------------------------ a fetch that applies deltas

class Host implements pdt.tree.FetchHost {
  readonly store = pdt.NodeStore.inMemory();
  readonly selfId = "self";
  readonly sent: [string, Dict][] = [];
  readonly struck: string[] = [];
  private req = 0;
  constructor(private readonly levelTwo = true) {}
  nextReq(): number { return ++this.req; }
  send(to: string, message: Dict): void { this.sent.push([to, message]); }
  holdersOf(): [string, string[] | null][] { return [["holder", null], ["other", null]]; }
  advertisesTrees(): boolean { return true; }
  hopsTo(): number { return 1; }
  readsDeltas(): boolean { return this.levelTwo; }
  async open(_from: string, _req: number, msg: Dict): Promise<Uint8Array[] | null> { return (msg["nodes"] as Uint8Array[]) ?? []; }
  strike(peer: string): void { this.struck.push(peer); }
  nowMillis(): number { return 1_000; }
  wants(kind: number): [string, Dict][] { return this.sent.filter(([, m]) => m["t"] === kind); }
}

/** A blob node over the target chunk and one more chunk, so the fetch walks two subtrees. */
function blobOver(other: Uint8Array): { root: Uint8Array; rootCid: string; target: string; other: string } {
  const target = cids.of(TARGET, cids.RAW), otherCid = cids.of(other, cids.RAW);
  const root = pdt.blob.encodeNode(1, [{ cid: target, length: TARGET.length }, { cid: otherCid, length: other.length }]);
  return { root, rootCid: cids.of(root, cids.DAG_CBOR), target, other: otherCid };
}

async function walkTo(host: Host, other: Uint8Array): Promise<{ fetch: pdt.tree.TreeFetch; walk: Dict; tree: ReturnType<typeof blobOver> }> {
  const t = blobOver(other);
  const fetch = new tree.TreeFetch(host, t.rootCid, [], ["holder"]);
  fetch.start();
  const [, rootWant] = host.wants(tree.NODE_WANT)[0]!;
  await fetch.onNodes("holder", tree.nodesMessage(Number(rootWant["req"]), [t.root]));
  const walk = host.wants(tree.TREE_WANT).find(([, m]) => m["root"] === t.target)![1];
  return { fetch, walk, tree: t };
}

const withDeltas = (req: number, nodes: Uint8Array[], deltas: Dict[]): Dict => ({ ...tree.nodesMessage(req, nodes), deltas });

test("PDT 2 phase 7: a fetch rebuilds a chunk from a delta over a base it holds and stores the chunk (P2-Z-01)", async () => {
  const host = new Host();
  host.store.put(BASE, cids.RAW);
  const { fetch, walk, tree: t } = await walkTo(host, Uint8Array.of(1, 2, 3));
  await fetch.onNodes("holder", withDeltas(Number(walk["req"]), [], [{ cid: t.target, base: cids.of(BASE, cids.RAW), dcz: FIELD }]));
  assert.deepEqual(host.store.get(t.target), TARGET);
  assert.equal(fetch.deltasApplied, 1);
  assert.deepEqual(host.struck, []);
});

test("PDT 2 phase 7: a delta over a base this peer lacks is ignored and its chunk asked for by NODE_WANT (P2-Z-01)", async () => {
  const host = new Host();
  const { fetch, walk, tree: t } = await walkTo(host, Uint8Array.of(1, 2, 3));
  await fetch.onNodes("holder", withDeltas(Number(walk["req"]), [], [{ cid: t.target, base: cids.of(BASE, cids.RAW), dcz: FIELD }]));
  await fetch.onTreeEnd("holder", tree.treeEnd(Number(walk["req"]), [], tree.END_DONE));
  assert.equal(host.store.has(t.target), false);
  assert.ok(host.wants(tree.NODE_WANT).some(([, m]) => (m["cids"] as string[]).includes(t.target)));
  assert.deepEqual(host.struck, []);
});

test("PDT 2 phase 7: a frame that does not open costs no strike, and the source's later frames are not opened (P2-Q-SEC-05)", async () => {
  const host = new Host();
  host.store.put(BASE, cids.RAW);
  const { fetch, walk, tree: t } = await walkTo(host, Uint8Array.of(1, 2, 3));
  const bad = withByte(FIELD, HEADER + 4, FIELD[HEADER + 4]! | 0x08);
  await fetch.onNodes("holder", withDeltas(Number(walk["req"]), [], [{ cid: t.target, base: cids.of(BASE, cids.RAW), dcz: bad },
    { cid: t.target, base: cids.of(BASE, cids.RAW), dcz: FIELD }]));
  assert.equal(fetch.deltasRefused, 1);
  assert.equal(fetch.deltasApplied, 0, "the honest frame after it is not opened either");
  assert.deepEqual(host.struck, []);
});

test("PDT 2 phase 7: a frame that rebuilds other bytes, or a delta no verified node links, strikes its sender (P2-Z-01)", async () => {
  const forged = new Host();
  forged.store.put(BASE, cids.RAW);
  const other = Uint8Array.of(9, 9, 9);
  const first = await walkTo(forged, other);
  const wrong = fieldOf(frameOf(concat(TARGET.subarray(0, 10), Uint8Array.of(0), TARGET.subarray(11))));
  await first.fetch.onNodes("holder", withDeltas(Number(first.walk["req"]), [],
    [{ cid: first.tree.target, base: cids.of(BASE, cids.RAW), dcz: wrong }]));
  assert.deepEqual(forged.struck, ["holder"]);
  assert.equal(forged.store.has(first.tree.target), false);
  const foreign = new Host();
  foreign.store.put(BASE, cids.RAW);
  const second = await walkTo(foreign, other);
  await second.fetch.onNodes("holder", withDeltas(Number(second.walk["req"]), [],
    [{ cid: cids.of(Uint8Array.of(7), cids.RAW), base: cids.of(BASE, cids.RAW), dcz: FIELD }]));
  assert.deepEqual(foreign.struck, ["holder"]);
});

test("PDT 2 phase 7: a peer that reads no level-2 forms ignores deltas and asks for the chunks (P2-F-05)", async () => {
  const host = new Host(false);
  host.store.put(BASE, cids.RAW);
  const { fetch, walk, tree: t } = await walkTo(host, Uint8Array.of(1, 2, 3));
  await fetch.onNodes("holder", withDeltas(Number(walk["req"]), [], [{ cid: t.target, base: cids.of(BASE, cids.RAW), dcz: FIELD }]));
  assert.equal(fetch.deltasApplied, 0);
  assert.equal(host.store.has(t.target), false);
});
