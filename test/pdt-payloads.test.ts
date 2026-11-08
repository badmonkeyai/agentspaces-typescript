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
 * Escalated space payloads as trees (srad/agentspaces-pdt.md group E, PD-E-01 to PD-E-03,
 * PD-C-05): `writePayload` and `readPayload` mirror the Java `PayloadTree` byte for byte (the
 * roots below were printed by the Java build over the same payload bytes), and the peer routes a
 * dag-cbor `payloadRef` to the facade and a raw one to the content swarm.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Identity } from "../src/identity.js";
import * as pdt from "../src/pdt/index.js";
import { Ctx, readPayload, writePayload } from "../src/pdt/values.js";
import { Peer } from "../src/peer.js";

function head(major: number, n: number): Uint8Array {
  const m = major << 5;
  if (n < 24) {
    return Uint8Array.of(m | n);
  }
  if (n < 256) {
    return Uint8Array.of(m | 24, n);
  }
  if (n < 65536) {
    return Uint8Array.of(m | 25, n >> 8, n & 0xff);
  }
  return Uint8Array.of(m | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let p = 0;
  for (const part of parts) {
    out.set(part, p);
    p += part.length;
  }
  return out;
}

const text = (s: string): Uint8Array => { const b = new TextEncoder().encode(s); return cat(head(3, b.length), b); };
const bytes = (b: Uint8Array): Uint8Array => cat(head(2, b.length), b);
const uint = (n: number): Uint8Array => head(0, n);
const imap = (entries: [Uint8Array, Uint8Array][]): Uint8Array =>
  cat(Uint8Array.of(0xbf), ...entries.flatMap(([k, v]) => [k, v]), Uint8Array.of(0xff));
const array = (items: Uint8Array[]): Uint8Array => cat(head(4, items.length), ...items);

function seeded(n: number, seed: bigint): Uint8Array {
  const out = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++) {
    x = (x * 6364136223846793005n + 1442695040888963407n) & 0xffffffffffffffffn;
    out[i] = Number(x >> 56n);
  }
  return out;
}

/** The Java roots (PayloadTree.write over these exact bytes, 2026-11-08) and the root kinds. */
const JAVA_ROOTS: { [name: string]: [string, string] } = {
  "small": ["bafyreifdj6bnlsvnuvib4x4p4vgirarvrisn3plvlyomyugqfyeicfkltq", "x"],
  "map-canonical": ["bafyreifzgezfiu7ndlurbsev4uxyu2u7whvoyuq3zx2sew2wpo2wnpww2q", "m"],
  "map-ordered": ["bafyreibtfzos5dom6344mc7sbfl5sr7si7kbgenuyot5bhkujylizsp6qe", "x"],
  "array": ["bafyreiarn7mcsbtu7syoxfeakjizgezl7g6ud54ugzmm5o5plrtfcgoybu", "vr"],
  "bytes-300k": ["bafyreihjqlkrs6dzaqqvx7ykotng7y3xretlvnzvdl4wmcdsae5ldqzfae", "b"],
  "bytes-20k": ["bafyreifqxcwx5mht4xy27i65viihmrqjkkdizac4dbb4kuxuht7uwiln6y", "x"],
  "nested": ["bafyreibpy5wseon2rhp22favy6doyeffb2ntzifauhyc254demoil3x7ge", "m"],
};

function payloads(): { [name: string]: Uint8Array } {
  const canon: [Uint8Array, Uint8Array][] = [];
  for (let i = 0; i < 3000; i++) {
    canon.push([text(`k${String(i).padStart(4, "0")}`), uint(i)]);
  }
  const items: Uint8Array[] = [];
  for (let i = 0; i < 2000; i++) {
    items.push(text(`item-${i}`));
  }
  const ints: Uint8Array[] = [];
  for (let i = 0; i < 5000; i++) {
    ints.push(uint(i));
  }
  return {
    "small": imap([[text("a"), uint(1)], [text("b"), text("two")]]),
    "map-canonical": imap(canon),
    "map-ordered": imap([...canon].reverse()),
    "array": array(items),
    "bytes-300k": bytes(seeded(300_000, 7n)),
    "bytes-20k": bytes(seeded(20_000, 11n)),
    "nested": imap([[text("blob"), bytes(seeded(100_000, 3n))], [text("list"), array(ints)]]),
  };
}

test("payload trees match the Java roots and round trip", () => {
  for (const [name, item] of Object.entries(payloads())) {
    const store = pdt.NodeStore.inMemory();
    const { root } = writePayload(item, store);
    const [expectedRoot, expectedKind] = JAVA_ROOTS[name]!;
    assert.equal(root, expectedRoot, name);
    assert.equal(pdt.nodes.kindOf(store.get(root)!), expectedKind, name);
    assert.equal(pdt.cids.parse(root).codec, pdt.cids.DAG_CBOR);
    assert.ok(store.complete(root), name);
    assert.deepEqual(readPayload(root, new Ctx(store)), item, name);
  }
});

test("a text above the node bound is refused as in Java", () => {
  assert.throws(() => writePayload(text("x".repeat(2 * 1024 * 1024)), pdt.NodeStore.inMemory()), /1048569/);
  assert.throws(() => writePayload(new Uint8Array(0), pdt.NodeStore.inMemory()), /empty payload/);
});

test("the peer routes a tree root to the facade and a raw root to the swarm", () => {
  const peer = new Peer(Identity.generate(), "zPdtPayloadsTest", () => 1_000);
  const store = pdt.NodeStore.inMemory();
  const item = payloads()["array"]!;
  const { root } = writePayload(item, store);
  const rawRoot = pdt.cids.of(new TextEncoder().encode("pieces"), pdt.cids.RAW);
  const asked: string[] = [];
  (peer as unknown as { content: unknown }).content = {
    local: (r: string) => (r === rawRoot ? new Uint8Array([1, 2, 3]) : null),
    ensure: (r: string) => { asked.push(r); },
  };
  // no facade: a tree root is invisible and never sent to the flat seam
  assert.equal(peer.payloadOf({ record: { payloadRef: root } }), null);
  assert.deepEqual(asked, []);
  assert.deepEqual(peer.payloadOf({ record: { payloadRef: rawRoot } }), new Uint8Array([1, 2, 3]));
  const fetched: string[] = [];
  (peer as unknown as { pdt: unknown }).pdt = {
    payload: (r: string) => { fetched.push(r); return readPayload(r, new Ctx(store)); },
  };
  assert.deepEqual(peer.payloadOf({ record: { payloadRef: root } }), item);
  assert.deepEqual(fetched, [root]);
  assert.deepEqual(asked, []);
  assert.deepEqual(peer.payloadOf({ record: {} }), new Uint8Array([0xf6]));
});
