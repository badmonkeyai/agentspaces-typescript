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
 * HLC round six, 2026-11-08: the wire encoding (owner rulings F1, F2 and F3). Every document holds one
 * item in the one form the encoding gives its value (rules S1 to S12), every protocol record holds its
 * schema's fields in declared order with their declared kinds (P1 to P4), and a receiver refuses a
 * carrier unless re-encoding what it decoded yields exactly the bytes it received. The vectors in
 * wire-encoding-vectors.json are the definition stage's own vectors with those of HLC round seven,
 * 2026-11-08, a byte-for-byte copy of agentspaces/tools/wire-encoding/vectors.json.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { concat, equals, toHex, utf8 } from "../src/bytes.js";
import { CborDecimal, CborDouble, CborFloat32, canonicalMap, dumps, loads } from "../src/cbor.js";
import { Identity, durationIso } from "../src/identity.js";
import * as records from "../src/records.js";
import { Peer } from "../src/peer.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

type Vector = { id: string; carrier: string; hex: string; verdict: "accept" | "refuse-undecodable"; rule: string; why: string };

const here = dirname(fileURLToPath(import.meta.url));
const VECTORS: Vector[] = (JSON.parse(readFileSync(join(here, "..", "..", "test", "wire-encoding-vectors.json"), "utf-8")) as
  { vectors: Vector[] }).vectors;
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf-8"));
/** The golden fixture key, which signed every carrier vector. */
const FIXTURE = Identity.fromPkcs8(Uint8Array.from(Buffer.from(GOLDEN["private_key_pkcs8"]!, "hex")));
/** The vectors' frame stamps and claim stamps lie at this instant. */
const NOW = 1_800_000_000_000;
const hex = (text: string): Uint8Array => Uint8Array.from(Buffer.from(text.replace(/\s/g, ""), "hex"));

function decodes(bytes: Uint8Array): boolean {
  try {
    loads(bytes);
    return true;
  } catch {
    return false;
  }
}

test("every document vector decodes exactly when the encoding accepts it, and re-encodes to its own bytes", () => {
  const documents = VECTORS.filter((v) => v.carrier === "document");
  assert.equal(documents.length, 80); // 73, and 7 of HLC round seven, 2026-11-08
  const wrong: string[] = [];
  for (const vector of documents) {
    const bytes = hex(vector.hex);
    const accepted = decodes(bytes);
    if (accepted !== (vector.verdict === "accept")) {
      wrong.push(`${vector.id} (${vector.rule}): ${vector.why}`);
    } else if (accepted && !equals(dumps(loads(bytes)), bytes)) {
      wrong.push(`${vector.id} re-encodes as ${toHex(dumps(loads(bytes))).slice(0, 60)}`);
    }
  }
  assert.deepEqual(wrong, []);
});

test("a text past 3996 UTF-16 units is refused as one definite string, wherever it stands (S6)", () => {
  // Jackson writes such a text only in chunks, so its one definite spelling is no document.
  const long = "x".repeat(3997);
  assert.throws(() => loads(concat(Uint8Array.of(0x79, 0x0f, 0x9d), utf8(long))), RangeError);
  assert.throws(() => loads(concat(hex("bf 61 6b 79 0f 9d"), utf8(long), hex("ff"))), RangeError);
  assert.equal(loads(dumps(long)), long);
});

test("an integer past a Java long is a bignum in Jackson's magnitude form, and one inside is a plain integer", () => {
  assert.equal(toHex(dumps(1n << 63n)), "c249008000000000000000");
  assert.equal(toHex(dumps(-(1n << 63n) - 1n)), "c349008000000000000001");
  assert.equal(toHex(dumps(1n << 64n)), "c249010000000000000000");
  assert.equal(toHex(dumps((1n << 63n) - 1n)), "1b7fffffffffffffff");
  assert.equal(toHex(dumps(-(1n << 63n))), "3b7fffffffffffffff");
  assert.equal(loads(hex("c249008000000000000000")), 1n << 63n);
  assert.equal(loads(hex("c349008000000000000001")), -(1n << 63n) - 1n);
});

test("a decimal is exact and normalized: trailing zeros stripped, zero as [0, 0], the mantissa under its shortest head", () => {
  assert.equal(toHex(dumps(new CborDecimal(-2, 150))), "c482200f");
  assert.equal(toHex(dumps(new CborDecimal(5, 0))), "c4820000");
  assert.equal(toHex(dumps(new CborDecimal(-3, 2n ** 31n))), "c482221a80000000");
  const big = new CborDecimal(0, 100000000000000000000000000000001n);
  assert.equal(big.mantissa, 100000000000000000000000000000001n);
  assert.ok(equals(dumps(loads(dumps(big))), dumps(big)));
  assert.throws(() => new CborDecimal(2 ** 31 - 1, 10), RangeError);
  assert.throws(() => new CborDecimal(-(2 ** 31), 1), RangeError);
  const read = loads(hex("c48220387c")) as CborDecimal;
  assert.ok(read instanceof CborDecimal);
  assert.equal(read.exponent, -1);
  assert.equal(read.mantissa, -125);
});

test("a float32 stays a float32, and a NaN of either width is the one NaN Java's constants hold", () => {
  assert.equal(toHex(dumps(new CborFloat32(1.5))), "fa3fc00000");
  assert.ok(loads(hex("fa3fc00000")) instanceof CborFloat32);
  assert.equal(toHex(dumps(Number.NaN)), "fb7ff8000000000000");
  assert.equal(toHex(dumps(new CborDouble(-Number.NaN))), "fb7ff8000000000000");
  assert.equal(toHex(dumps(new CborFloat32(Number.NaN))), "fa7fc00000");
});

test("the encoder refuses a text holding a lone surrogate, which no UTF-8 can carry", () => {
  assert.throws(() => dumps("a\ud800b"), RangeError);
  assert.throws(() => dumps({ ["\udc00"]: 1 }), RangeError);
  assert.equal(toHex(dumps("😀")), "64f09f9880");
});

test("a canonical map writes its keys shorter first then bytewise, integer-like keys included", () => {
  // A JS object puts "10" before "b"; the RFC 8949 order puts the one-byte key first.
  assert.equal(toHex(dumps(canonicalMap({ zz: "1", b: "2", 10: "3" }))), "bf616261326231306133627a7a6131ff");
});

test("a decoded map re-encodes in the order its keys arrived", () => {
  const bytes = hex("bf 6162 01 623130 02 6161 03 ff"); // {b: 1, "10": 2, a: 3}
  assert.ok(equals(dumps(loads(bytes)), bytes));
  const decoded = loads(bytes) as { [key: string]: unknown };
  decoded["c"] = 4;
  assert.equal(toHex(dumps(decoded as never)), "bf616201623130026161036163" + "04ff");
});

/** A peer at NOW whose frames come from a test, in the vectors' group, holding the space `tasks`. */
class Receiver extends Peer {
  private counter = 0;

  constructor(group: string) {
    super(Identity.generate(), group, () => NOW);
    this.joinSpace("tasks");
  }

  protected send(): void {
    // nothing leaves a receiver under test
  }

  /** A RUMOR carrying `payload` on `stream`, signed by a fresh sender. */
  rumor(stream: string, payload: Uint8Array): void {
    const sender = Identity.generate();
    const body = wire.rumorBody(stream, `w:${this.counter}`, 6, payload);
    const env = wire.envelope(this.group, "RUMOR", sender.peerId, `${NOW}:${this.counter++}:${sender.peerId}`, body,
      this.identity.peerId);
    (this as unknown as { onFrame(frame: Uint8Array): void }).onFrame(wire.encodeFrame(env, sender));
  }
}

test("a map field keyed __proto__ reads and re-encodes as Java's Map holds it (HLC round six, 2026-11-08, P2)", () => {
  // Java holds "__proto__" as any other text key; a plain JS object assignment would set the
  // prototype instead and drop the key, so the strict read would refuse an honest record.
  const tagsBytes = hex("bf 6161 6162 69" + toHex(new TextEncoder().encode("__proto__")) + " 6178 ff");
  assert.deepEqual(Object.keys(records.decodeRecord(tagsBytes, { mapOf: "String" }) as object), ["a", "__proto__"]);
  const hashes = hex("bf 69" + toHex(new TextEncoder().encode("__proto__")) + " 4101 ff");
  assert.deepEqual(Object.keys(records.decodeRecord(hashes, { mapOf: "bytes" }) as object), ["__proto__"]);
  const tags: Dict = { a: "b" };
  Object.defineProperty(tags, "__proto__", { value: "x", enumerable: true, writable: true, configurable: true });
  assert.deepEqual(Object.keys(canonicalMap(tags)), ["a", "__proto__"]);
  const writer = Identity.generate();
  const { body } = wire.entryDelta("tasks", "zVectors", "T#v1", dumps({ job: 1 }), writer, "w", 60_000, null, NOW, tags);
  const peer = new Receiver("zVectors");
  peer.rumor("space:tasks", (loads(body) as Dict)["payload"] as Uint8Array);
  assert.deepEqual([peer.states.size, peer.deltasUndecodable], [1, 0]);
});

const vectorsOf = (carrier: string): Vector[] => VECTORS.filter((v) => v.carrier === carrier);
const groupOf = (frame: Uint8Array): string => String(((loads(frame) as Dict)["envelope"] as Dict)["group"]);

test("every frame vector verifies exactly when the encoding accepts it (F1, F3)", () => {
  const wrong: string[] = [];
  for (const vector of vectorsOf("frame")) {
    const decoded = wire.decodeFrameDetailed(hex(vector.hex), {});
    if ((decoded !== null) !== (vector.verdict === "accept")) {
      wrong.push(`${vector.id} (${vector.rule}): ${vector.why}`);
    }
  }
  assert.deepEqual(wrong, []);
});

test("a peer counts a frame whose body is no record of its kind as malformed and never handles it (frame-23 to frame-26)", () => {
  const group = groupOf(hex(vectorsOf("frame")[0]!.hex));
  for (const vector of vectorsOf("frame").filter((v) => ["frame-01", "frame-23", "frame-24", "frame-25", "frame-26", "frame-27"].includes(v.id))) {
    const peer = new Receiver(group);
    (peer as unknown as { onFrame(frame: Uint8Array): void }).onFrame(hex(vector.hex));
    const handled = peer.frames.stale + peer.frames.replayed + peer.frames.framesFarFuture === 0 && peer.malformedFrames === 0;
    assert.equal(handled, vector.verdict === "accept", `${vector.id}: ${vector.why}`);
    assert.equal(peer.malformedFrames, vector.verdict === "accept" ? 0 : 1, vector.id);
  }
});

/**
 * The vectors whose state Java's fold drops after the encoding accepts it (HLC round six, 2026-11-08,
 * reference rule): delta-13's dots name U+E000 and U+1F600, replicas other than its issuer's peer
 * (ASF-025), so it decodes, counts nothing, and merges nothing.
 */
const FOLD_DROPS = new Set(["delta-13"]);

test("every space delta vector folds exactly when the encoding accepts it, and counts as undecodable otherwise", () => {
  const wrong: string[] = [];
  for (const vector of vectorsOf("space-delta")) {
    const peer = new Receiver("zVectors");
    peer.rumor("space:tasks", hex(vector.hex));
    const folded = peer.states.size + peer.claims.size > 0;
    const accepted = vector.verdict === "accept";
    if (folded !== (accepted && !FOLD_DROPS.has(vector.id)) || peer.deltasUndecodable !== (accepted ? 0 : 1)) {
      wrong.push(`${vector.id} (${vector.rule}) folded ${folded}, undecodable ${peer.deltasUndecodable}: ${vector.why}`);
    }
  }
  assert.deepEqual(wrong, []);
});

test("delta-13's state signature covers its dots in Java's UTF-16 order (3.2), U+1F600 before U+E000", () => {
  const state = (loads(hex(vectorsOf("space-delta").find((v) => v.id === "delta-13")!.hex)) as Dict)["state"] as Dict;
  const record = state["record"] as Dict;
  const adds = state["adds"] as Dict[];
  assert.deepEqual(adds.map((dot) => dot["replica"]), ["\ue000", "\u{1f600}"]);
  const view = wire.stateSignView(String(record["spaceId"]), String(record["entryId"]), adds, state["removes"] as Dict[],
    wire.leaseStampOf(state), state["leaseValue"] as Dict, Boolean(state["completed"]));
  assert.deepEqual((view["adds"] as Dict[]).map((dot) => dot["replica"]), ["\u{1f600}", "\ue000"]);
  assert.ok(Identity.verify(FIXTURE.publicRaw, dumps(view), state["stateSig"] as Uint8Array));
});

test("every signed peer advertisement vector is held exactly when the encoding accepts it", () => {
  const wrong: string[] = [];
  for (const vector of vectorsOf("signed-peer-ad")) {
    const bytes = hex(vector.hex);
    const ad = loads((loads(bytes) as Dict)["adBytes"] as Uint8Array) as Dict;
    const peer = new Receiver(String(ad["group"]));
    peer.rumor("peers", bytes);
    if (peer.members.has(FIXTURE.peerId) !== (vector.verdict === "accept")) {
      wrong.push(`${vector.id} (${vector.rule}): ${vector.why}`);
    }
  }
  assert.deepEqual(wrong, []);
});

test("a bid of -0.0 wins over a bid of 0.0, as Java's Double.compare orders them", () => {
  const holder = `${FIXTURE.peerId}/a`;
  const claim = (bid: number): Dict => wire.takeClaim("e", "s", 1, `${NOW}:0:${FIXTURE.peerId}`, holder, bid, NOW + 1000);
  assert.ok(wire.compareClaims(claim(-0), claim(0)) < 0);
  assert.ok(wire.compareClaims(claim(0), claim(-0)) > 0);
  assert.equal(wire.javaDoubleCompare(-0, 0), -1);
  assert.equal(wire.javaDoubleCompare(0, 0), 0);
});

test("a DIGEST this client writes holds its digests in the RFC 8949 order (frame-28, frame-29)", () => {
  const body = wire.digestBody({ "space:s": new Uint8Array(), peers: new Uint8Array() });
  assert.equal(toHex(body).indexOf(toHex(new TextEncoder().encode("peers"))) < toHex(body).indexOf(toHex(new TextEncoder().encode("space:s"))), true);
  const frame29 = loads(hex(vectorsOf("frame").find((v) => v.id === "frame-29")!.hex)) as Dict;
  assert.ok(equals(body, (frame29["envelope"] as Dict)["body"] as Uint8Array));
});

test("Instant and Duration text is exactly what Java prints, and this client prints durations that way (P2)", () => {
  for (const [millis, text] of [[0, "PT0S"], [60_000, "PT1M"], [3_661_000, "PT1H1M1S"], [500, "PT0.5S"],
    [172_800_000, "PT48H"], [600_000, "PT10M"], [1_250, "PT1.25S"]] as [number, string][]) {
    assert.equal(durationIso(millis), text);
    assert.equal(records.isJavaDuration(text), true, text);
  }
  for (const text of ["PT600S", "PT60S", "PT0M", "PT1H0M", "PT0.50S", "P1D", "PT", "-PT1S", "PT01S", "PT1.S"]) {
    assert.equal(records.isJavaDuration(text), false, text);
  }
  for (const text of ["2026-01-01T00:00:00Z", "2027-01-15T08:00:00.123Z", "2027-01-15T08:00:00.000100Z",
    "2027-01-15T08:00:00.000000100Z", "0000-01-01T00:00:00Z"]) {
    assert.equal(records.isJavaInstant(text), true, text);
  }
  for (const text of ["2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.100000Z", "2026-02-30T00:00:00Z",
    "2026-01-01T24:00:00Z", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00.1Z", "1767225600"]) {
    assert.equal(records.isJavaInstant(text), false, text);
  }
});
