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
 * The content swarm and relay paths in TypeScript (SPEC v0.1.23 §5.4, §7.1, §8, annex G): the
 * golden vectors byte for byte, a swarm over an in-memory fleet, a file store that resumes, a
 * space that escalates a large payload to an artifact and a mid-sized one to a block, and the
 * dial-only relay rule.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { Content, MemoryStore, Pipes } from "../src/capabilities/index.js";
import * as c from "../src/capabilities/content.js";
import { dumps, loads } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import { FileStore } from "../src/node/content-store.js";
import { Peer } from "../src/peer.js";
import { Space, Template, entry } from "../src/space.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8"));
const hex = (name: string): Uint8Array => new Uint8Array(Buffer.from(GOLDEN[name], "hex"));
const GROUP = "zTypeScriptContent";
const PIECE = 64 * 1024;

function pieceTable(pieces: number, pieceSize: number, lastLength: number): Uint8Array {
  const table = new Uint8Array(pieces * 32);
  for (let i = 0; i < pieces; i++) {
    const piece = new Uint8Array(i === pieces - 1 ? lastLength : pieceSize).fill(i + 1);
    table.set(createHash("sha256").update(piece).digest(), i * 32);
  }
  return table;
}

// ------------------------------------------------------------------ vectors

test("records and messages match the Java golden vectors", () => {
  const identity = Identity.fromPkcs8(hex("private_key_pkcs8"));
  const me = identity.peerId;
  const table = pieceTable(3, PIECE, 100);
  const root = c.contentRoot(table);
  assert.equal(root, GOLDEN["content_root_cidv1"]);
  assert.ok(root.startsWith("bafkrei") && root.length === 59);
  const inline = c.manifest(root, 2 * PIECE + 100, PIECE, table, me, 1735689600000,
    { name: "golden.bin", mediaType: "application/octet-stream", attrs: { run: "42" } });
  assert.deepEqual(dumps(inline), hex("content_manifest_inline_cbor"));
  assert.equal(c.manifestViolation(inline), null);
  assert.equal(c.manifestViolation(loads(hex("content_manifest_inline_cbor")) as Dict), null);
  const big = pieceTable(65, PIECE, PIECE);
  const referenced = c.manifest(c.contentRoot(big), 65 * PIECE, PIECE, null, me, 1735689600000,
    { tableRef: wire.contentId(big), sealing: c.SEALING_GROUP_KEY, keyEpoch: 3 });
  assert.deepEqual(dumps(referenced), hex("content_manifest_tableref_cbor"));
  const partial = c.holding(root, me, new Set([0, 2]), 3, ["zB"]);
  assert.deepEqual(partial["have"], new Uint8Array([0, 1, 1, 1]));
  assert.deepEqual(dumps(partial), hex("content_holding_partial_cbor"));
  assert.deepEqual(c.decodeHave(new Uint8Array([0, 1, 1, 1]), 3), new Set([0, 2]));
  assert.deepEqual(dumps(c.holding(root, me, new Set([0, 1, 2]), 3)), hex("content_holding_complete_cbor"));
  assert.deepEqual(dumps(c.pieceWant(root, 2, PIECE, PIECE, 42)), hex("content_piece_want_cbor"));
  assert.deepEqual(dumps(c.piece(root, 2, PIECE, new Uint8Array(Array.from({ length: 16 }, (_, i) => i)), 42)),
    hex("content_piece_cbor"));
  assert.deepEqual(dumps(c.haveMessage(root, new Uint8Array([0, 1, 1, 1]), false)), hex("content_have_cbor"));
  assert.deepEqual(dumps(c.cancel(root, 2, 42)), hex("content_cancel_cbor"));
  assert.deepEqual(dumps(c.reject(root, 2, c.REASON_OVER_BUDGET)), hex("content_reject_cbor"));
  assert.deepEqual(dumps(c.manifestWant(root)), hex("content_manifest_want_cbor"));
  assert.deepEqual(dumps(c.manifestReply(root, dumps(inline))), hex("content_manifest_cbor"));
});

test("relay bodies and the via hint match Java", () => {
  const identity = Identity.fromPkcs8(hex("private_key_pkcs8"));
  const inner = hex("ping_frame_cbor");
  assert.deepEqual(wire.relayFrameBody("zB", inner), hex("relay_frame_body_cbor"));
  assert.deepEqual(wire.relayFrameBody("zB", inner, ["zR1", "zR2"], 0), hex("relay_frame_with_path_cbor"));
  assert.deepEqual(wire.relaySignalBody("zB", "zR2", "unreachable"), hex("relay_signal_unreachable_cbor"));
  const ad = wire.peerAdvertisement(GOLDEN["group_id"], identity, "2026-01-01T00:00:00Z", "PT10M",
    { "relay.via": "zR1,zR2" });
  assert.deepEqual(dumps(ad), hex("peer_ad_with_via_hint_cbor"));
});

test("have runs round-trip at every size", () => {
  const cases: [number, number[]][] = [[1, []], [1, [0]], [7, [1, 2, 5]], [300, Array.from({ length: 100 }, (_, i) => i * 3)],
    [1000, [999]]];
  for (const [pieces, have] of cases) {
    assert.deepEqual(c.decodeHave(c.encodeHave(new Set(have), pieces), pieces), new Set(have));
  }
});

// -------------------------------------------------------------------- swarm

type Internals = { fold(dto: Dict): void; foldClaim(entryId: string, signed: Dict): void;
  handle(env: Dict): void; send(kind: string, body: Uint8Array, to?: string | null): void; channel: unknown };

class Network {
  readonly peers = new Map<string, NetPeer>();
}

class NetPeer extends Peer {
  constructor(readonly network: Network) {
    super(Identity.generate(), GROUP);
    network.peers.set(this.identity.peerId, this);
    const self = this as unknown as Internals;
    self.send = (kind: string, body: Uint8Array, to: string | null = null) => {
      const env = wire.envelope(this.group, kind, this.identity.peerId,
        wire.hlcNow(this.identity.peerId, this.now()), body, to);
      const targets = to !== null ? [network.peers.get(to)!]
        : [...network.peers.values()].filter((p) => p.identity.peerId !== this.identity.peerId);
      for (const target of targets) {
        if (target.accepts(env)) {
          (target as unknown as Internals).handle(env);
        }
      }
      if (kind === "RUMOR" && to === null) {
        const rumor = loads(body) as Dict;
        if (String(rumor["streamId"] ?? "").startsWith("space:")) {
          const delta = loads(rumor["payload"] as Uint8Array) as Dict;
          if (delta["state"] !== null && typeof delta["state"] === "object") {
            self.fold(delta["state"] as Dict);
          }
        }
      }
    };
  }

  override pullSpace(_space: string): void {}
  override pullRevocations(): void {}
}

type Node = { peer: NetPeer; space: Space; content: Content };

function node(network: Network, store: c.PieceStore = new MemoryStore(), options: c.ContentOptions = {}): Node {
  const peer = new NetPeer(network);
  const space = new Space(peer, "content");
  let seed = 7;
  const random = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
  const content = new Content(new Pipes(peer), space, store, { pieceSize: PIECE, random, ...options });
  return { peer, space, content };
}

function fleet(n: number, options: c.ContentOptions = {}): Node[] {
  const network = new Network();
  const nodes = Array.from({ length: n }, () => node(network, new MemoryStore(), options));
  for (const { peer } of nodes) {
    peer.introduce();
  }
  return nodes;
}

function run(nodes: Node[], rounds = 20): void {
  for (let r = 0; r < rounds; r++) {
    for (const { content } of nodes) {
      content.tick();
    }
  }
}

function pattern(length: number, mul: number, add: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = (i * mul + add) & 0xff;
  }
  return out;
}

test("two peers fetch a published artifact from the publisher and each other", async () => {
  const nodes = fleet(3);
  const [a, b, cc] = nodes as [Node, Node, Node];
  const data = pattern(2 * PIECE + 100, 31, 7);
  const manifest = a.content.publish(data, { name: "checkpoint.bin" });
  assert.equal(manifest["pieces"], 3);
  assert.equal(b.content.describe(String(manifest["root"]))!["completeHolders"], 1);
  const fb = b.content.fetch(String(manifest["root"]));
  const fc = cc.content.fetch(String(manifest["root"]));
  run(nodes);
  assert.ok(await fb.await(5000), fb.trace.join("\n"));
  assert.ok(await fc.await(5000), fc.trace.join("\n"));
  assert.deepEqual(fb.readBytes(), data);
  assert.deepEqual(fc.readBytes(), data);
  assert.equal(fb.progress().piecesVerified, 3);
  assert.ok(a.content.bytesServed > 0);
  run(nodes, 2);
  assert.equal(b.content.describe(String(manifest["root"]))!["completeHolders"], 3);
  assert.deepEqual(cc.content.listManifests().map((m) => m["root"]), [manifest["root"]]);
  assert.ok(b.content.fetch(String(manifest["root"])).complete);
});

test("a file store resumes what it holds and a restarted holder republishes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "aspace-content-"));
  const network = new Network();
  const a = node(network, new FileStore(join(dir, "a")));
  const b = node(network, new FileStore(join(dir, "b")));
  b.peer.introduce();
  const data = new Uint8Array(2 * PIECE + 4);
  data.set(pattern(2 * PIECE, 1, 0), 0);
  data.set(Buffer.from("tail"), 2 * PIECE);
  const manifest = a.content.publish(data);
  const root = String(manifest["root"]);
  assert.ok(await b.content.fetch(root).await(5000));
  const reopened = new FileStore(join(dir, "b"));
  assert.deepEqual(reopened.roots(), new Set([root]));
  assert.deepEqual(reopened.have(root), new Set([0, 1, 2]));
  assert.deepEqual(reopened.readAll(root), data);
  assert.deepEqual(Buffer.from(reopened.read(root, 2, 0, 4)!).toString(), "tail");
  // a late member learns the root only from a holding: the holder restarts over its store,
  // republishes, and answers the newcomer's MANIFEST_WANT before the pieces
  const late = node(network, new MemoryStore());
  const b2 = node(network, reopened);
  assert.deepEqual(late.content.holdings(root).map((h) => h["holder"]), [b2.peer.identity.peerId]);
  assert.equal(late.content.manifestOf(root), null);
  const fetched = late.content.fetch(root);
  run([late, b2]);
  assert.ok(await fetched.await(5000), fetched.trace.join("\n"));
  assert.deepEqual(fetched.readBytes(), data);
  assert.deepEqual(fetched.progress().bytesBySource, { [b2.peer.identity.peerId]: data.length });
});

@entry("com.acme.Blob#v1")
class Blob {
  constructor(public name = "", public data: Uint8Array = new Uint8Array()) {}
}

test("a space escalates large payloads to artifacts and mid-sized ones to blocks", () => {
  const nodes = fleet(2, { escalateAbove: 1024 * 1024 });
  const [a, b] = nodes as [Node, Node];
  const big = pattern(1024 * 1024 + 5, 7, 0);
  a.space.write(new Blob("big", big));
  const mid = new Uint8Array(100 * 1024).fill(0x6d);
  a.space.write(new Blob("mid", mid));
  const refs = [...b.peer.states.values()]
    .filter((d) => (d["record"] as Dict)["type"] === "com.acme.Blob#v1")
    .map((d) => String((d["record"] as Dict)["payloadRef"] ?? "")[0]).sort();
  assert.deepEqual(refs, ["b", "z"]);
  const found = new Map<string, Uint8Array>();
  for (let i = 0; i < 10 && found.size < 2; i++) {
    for (const e of b.space.readAll(new Template(Blob))) {
      found.set(e.name, e.data);
    }
    run(nodes, 2);
  }
  assert.deepEqual(found.get("big"), big);
  assert.deepEqual(found.get("mid"), mid);
  assert.ok([...b.peer.blocks.keys()].every((ref) => ref.startsWith("z")) && b.peer.blocks.size === 1);
  assert.deepEqual(a.space.readAll(new Template(Blob, { name: "big" }))[0]!.data, big);
});

// ------------------------------------------------------------------- relays

class CapturePeer extends Peer {
  readonly sent: [string, Uint8Array, string | null][] = [];
  constructor() {
    super(Identity.generate(), GROUP);
    const self = this as unknown as Internals;
    self.channel = { attestedPeer: () => null, send: () => {}, close: () => {} };
    self.send = (kind: string, body: Uint8Array, to: string | null = null) => { this.sent.push([kind, body, to]); };
  }
}

test("a dial-only peer sends through its seed and unwraps what the seed carries", () => {
  const me = new CapturePeer();
  const handle = (env: Dict) => (me as unknown as Internals).handle(env);
  const seed = Identity.generate();
  const origin = Identity.generate();
  const now = me.now();
  handle(wire.envelope(GROUP, "ACK", seed.peerId, wire.hlcNow(seed.peerId, now), wire.ackBody(1), me.identity.peerId));
  assert.equal(me.seedPeer, seed.peerId);
  assert.equal(me.resourceHints["relay.via"], seed.peerId);
  assert.equal(me.sent.at(-1)![0], "RUMOR"); // re-introduced with the hint
  me.sent.length = 0;
  me.sendPipe(seed.peerId, "aspace:cap/x", Buffer.from("direct"));
  assert.deepEqual([me.sent.at(-1)![0], me.sent.at(-1)![2]], ["PIPE_DATA", seed.peerId]);
  me.sendPipe(origin.peerId, "aspace:cap/x", Buffer.from("carried"));
  const [kind, body, to] = me.sent.at(-1)!;
  assert.deepEqual([kind, to], ["RELAY_FRAME", seed.peerId]);
  const relayed = loads(body) as Dict;
  assert.equal(relayed["target"], origin.peerId);
  assert.ok(!("path" in relayed));
  const inner = wire.decodeFrame(relayed["frame"] as Uint8Array)!;
  assert.deepEqual([inner["kind"], inner["to"]], ["PIPE_DATA", origin.peerId]);
  me.sendPipe(origin.peerId, "aspace:cap/x", Buffer.from("far"), ["zFar"]);
  const withPath = loads(me.sent.at(-1)![1]) as Dict;
  assert.deepEqual(withPath["path"], [seed.peerId, "zFar"]);
  assert.equal(withPath["hop"], 0);
  const got: [string, string][] = [];
  me.pipeHandlers.set("aspace:cap/x", (sender, payload) => got.push([sender, Buffer.from(payload).toString()]));
  const innerEnv = wire.envelope(GROUP, "PIPE_DATA", origin.peerId, wire.hlcNow(origin.peerId, now),
    dumps({ capability: "aspace:cap/x", payload: Buffer.from("hello") }), me.identity.peerId);
  handle(wire.envelope(GROUP, "RELAY_FRAME", seed.peerId, wire.hlcNow(seed.peerId, now + 1),
    wire.relayFrameBody(me.identity.peerId, wire.encodeFrame(innerEnv, origin)), me.identity.peerId));
  assert.deepEqual(got, [[origin.peerId, "hello"]]);
  assert.ok(!me.reachable.has(origin.peerId) && me.reachable.has(seed.peerId));
  handle(wire.envelope(GROUP, "PIPE_DATA", seed.peerId, wire.hlcNow(seed.peerId, now + 2),
    wire.relaySignalBody(origin.peerId, "zFar"), me.identity.peerId));
  assert.equal(me.relaySignals.at(-1)!["failedHop"], "zFar");
});

test("a relay host forwards a path frame to the next hop and signals when it cannot", () => {
  // three capture peers wired by hand: origin -> R1 (path [R1, R2]) with R2 linked to R1 or not
  const r1 = new CapturePeer();
  const origin = Identity.generate();
  const r2 = Identity.generate();
  const target = "zTarget";
  const now = r1.now();
  const inner = wire.encodeFrame(wire.envelope(GROUP, "PIPE_DATA", origin.peerId, wire.hlcNow(origin.peerId, now),
    dumps({ capability: "aspace:cap/x", payload: Buffer.from("x") }), target), origin);
  const handle = (env: Dict) => (r1 as unknown as Internals).handle(env);
  // R2 not linked: the frame is dropped and the origin told which hop failed
  handle(wire.envelope(GROUP, "RELAY_FRAME", origin.peerId, wire.hlcNow(origin.peerId, now + 1),
    wire.relayFrameBody(target, inner, [r1.identity.peerId, r2.peerId], 0), r1.identity.peerId));
  assert.equal(r1.relayedDroppedUnreachable, 1);
  const signal = r1.sent.find(([kind]) => kind === "PIPE_DATA")!;
  assert.equal(signal[2], origin.peerId);
  const body = loads(signal[1]) as Dict;
  assert.equal(body["capability"], wire.RELAY_SIGNAL_CAPABILITY);
  assert.equal((loads(body["payload"] as Uint8Array) as Dict)["failedHop"], r2.peerId);
  // a frame naming another relay at this hop is malformed
  handle(wire.envelope(GROUP, "RELAY_FRAME", origin.peerId, wire.hlcNow(origin.peerId, now + 2),
    wire.relayFrameBody(target, inner, ["zOther", r2.peerId], 0), r1.identity.peerId));
  assert.equal(r1.relayedDroppedBadPath, 1);
});

/**
 * LB-Q-INT-01: the root decodes as the multiformats specifications define a CID, checked by an
 * independent decoder written from the specs (multibase `b` = RFC 4648 base32 lower case
 * unpadded; CIDv1 = varint version 1, varint multicodec 0x55 raw, multihash with varint code
 * 0x12 sha2-256 and varint length 32), not by the encoder under test.
 */
function decodeCidV1(text: string): { version: number; codec: number; hashCode: number; digest: Uint8Array } {
  assert.equal(text[0], "b", "multibase prefix b is base32 lower");
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of text.slice(1)) {
    const v = alphabet.indexOf(ch);
    assert.ok(v >= 0, `base32 character ${ch}`);
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
    buffer &= 0xff;
  }
  const bytes = Uint8Array.from(out);
  let pos = 0;
  const varint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = bytes[pos++]!;
      value |= (b & 0x7f) << shift;
      shift += 7;
      if ((b & 0x80) === 0) {
        return value;
      }
    }
  };
  const version = varint();
  const codec = varint();
  const hashCode = varint();
  const length = varint();
  const digest = bytes.slice(pos, pos + length);
  assert.equal(pos + length, bytes.length, "nothing after the multihash");
  return { version, codec, hashCode, digest };
}

test("a content root is a CIDv1 as the multiformats specifications decode it (LB-Q-INT-01)", () => {
  const golden = decodeCidV1(GOLDEN["content_root_cidv1"]);
  assert.deepEqual([golden.version, golden.codec, golden.hashCode, golden.digest.length], [1, 0x55, 0x12, 32]);
  assert.deepEqual(golden.digest, new Uint8Array(createHash("sha256").update(pieceTable(3, PIECE, 100)).digest()));
  for (let seed = 1; seed <= 20; seed++) {
    const table = new Uint8Array(seed * 32).map((_, i) => (i * seed * 31) & 0xff);
    const cid = decodeCidV1(c.contentRoot(table));
    assert.deepEqual([cid.version, cid.codec, cid.hashCode], [1, 0x55, 0x12]);
    assert.deepEqual(cid.digest, new Uint8Array(createHash("sha256").update(table).digest()));
  }
});
