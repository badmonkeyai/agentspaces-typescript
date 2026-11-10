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
 * HLC round five, 2026-11-08: the decisions that bring this client into line with Java, Python and
 * Ruby. E1: a stamp item carries the shortest length header. E4: an agent-signed record or claim
 * meets D4's far-future rule exactly as a peer-signed one does, and a state's signedAt keeps the
 * drift ceiling. E6: signatures, then revocation, then the stamp checks. E7: a state without its
 * lease stamp or its lease value decodes, and the replica drops it uncounted. E8: indefinite-length
 * text decodes outside a stamp, the big-number tags Jackson writes (2, 3 and 4) decode as Jackson
 * reads them, every other tag and every ill-formed UTF-8 text is refused, and the encoder chunks a
 * long string and writes a decimal as Jackson does. E11: the local node holds no lone surrogate. E12: a
 * revoked actor's state is acknowledged. E13: a claim proof verifies over the TakeClaim's canonical
 * encoding, and a claim Java's TakeClaim refuses verifies nowhere and makes its carrier undecodable. E14: the refused-offer memory
 * forgets the least recently offered key.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { concat, utf8 } from "../src/bytes.js";
import { CborDecimal, CborDouble, CborFloat32, dumps, loads } from "../src/cbor.js";
import type { CborValue } from "../src/cbor.js";
import { Identity, instantIso } from "../src/identity.js";
import type { AgentIdentity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import * as revocation from "../src/revocation.js";
import { stateHash } from "../src/serving.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const GROUP = "zTsHlcRoundFive";
const NOW = 1_800_000_000_000;
/** The receiver's far-future ceiling at NOW: wall + MAX_DRIFT + the skew margin (D4). */
const CEILING = NOW + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_MARGIN_MILLIS;

/** A peer on a settable clock whose sends are captured instead of written to a socket. */
class CapturingPeer extends Peer {
  readonly sent: string[] = [];
  private frameCounter = 0;
  private readonly clock: { millis: number };

  constructor(millis: number = NOW) {
    const clock = { millis };
    super(Identity.generate(), GROUP, () => clock.millis);
    this.clock = clock;
    this.joinSpace("tasks"); // the replica holds the space these tests write to (HLC round five, 2026-11-08)
  }

  get millis(): number {
    return this.clock.millis;
  }

  set millis(value: number) {
    this.clock.millis = value;
  }

  protected send(kind: string): void {
    this.sent.push(kind);
  }

  /** Signs a frame as `sender` with an honest frame stamp and hands it to the peer's reader. */
  deliver(sender: Identity, kind: string, body: Uint8Array): void {
    const stamp = `${this.millis}:${this.frameCounter++}:${sender.peerId}`;
    this.deliverFrame(wire.encodeFrame(wire.envelope(GROUP, kind, sender.peerId, stamp, body, this.identity.peerId), sender));
  }

  deliverFrame(frame: Uint8Array): void {
    (this as unknown as { onFrame(frame: Uint8Array): void }).onFrame(frame);
  }

  /** A space delta, as a RUMOR on the space's stream. */
  rumor(sender: Identity, delta: Uint8Array): void {
    this.deliver(sender, "RUMOR", wire.rumorBody("space:tasks", `w:${this.frameCounter}`, 6, delta));
  }

  /** A space's anti-entropy answer holding `states` and `claims`. */
  pulled(sender: Identity, states: Dict[], claims: Dict = {}): void {
    this.deliver(sender, "PULL_RESP", dumps({ deltas: { "space:tasks": dumps({ states, claims }) } }));
  }

  /** The `a:` lines of this replica's digest for the space. */
  acknowledged(): string[] {
    return new TextDecoder().decode(this.spaceDigest("tasks")).split("\n").filter((line) => line.startsWith("a:"));
  }
}

const hex = (text: string): Uint8Array => Uint8Array.from(Buffer.from(text.replace(/\s/g, ""), "hex"));

function textItem(bytes: Uint8Array): Uint8Array {
  return concat(bytes.length < 24 ? Uint8Array.of(0x60 | bytes.length) : Uint8Array.of(0x78, bytes.length), bytes);
}

/** `stamp`'s UTF-8 bytes under every length header longer than the shortest (§14.5 rows 5 to 9). */
function longerHeads(stamp: string): Map<string, Uint8Array> {
  const bytes = utf8(stamp);
  const n = bytes.length;
  const items = new Map<string, Uint8Array>();
  if (n < 24) {
    items.set("one-byte length", concat(Uint8Array.of(0x78, n), bytes));
  }
  items.set("two-byte length", concat(Uint8Array.of(0x79, 0, n), bytes));
  items.set("four-byte length", concat(Uint8Array.of(0x7a, 0, 0, 0, n), bytes));
  items.set("eight-byte length", concat(Uint8Array.of(0x7b, 0, 0, 0, 0, 0, 0, 0, n), bytes));
  return items;
}

/** `blob` with every canonical text item of `stamp` replaced by `item`. */
function respell(blob: Uint8Array, stamp: string, item: Uint8Array): Uint8Array {
  const needle = textItem(utf8(stamp));
  const parts: Uint8Array[] = [];
  let from = 0;
  for (let i = 0; i + needle.length <= blob.length;) {
    if (needle.every((b, j) => blob[i + j] === b)) {
      parts.push(blob.subarray(from, i), item);
      i += needle.length;
      from = i;
    } else {
      i += 1;
    }
  }
  assert.ok(parts.length > 0, `no ${stamp} in the blob`);
  parts.push(blob.subarray(from));
  return concat(...parts);
}

/** `blob` with its first run of `from` replaced by `to`. */
function replaceOnce(blob: Uint8Array, from: Uint8Array, to: Uint8Array): Uint8Array {
  for (let i = 0; i + from.length <= blob.length; i++) {
    if (from.every((b, j) => blob[i + j] === b)) {
      return concat(blob.subarray(0, i), to, blob.subarray(i + from.length));
    }
  }
  assert.fail("no such bytes in the blob");
}

/** An honest write of `writer` at `wall`, its state DTO as the rumor carries it. */
function writtenState(writer: Identity, wall = NOW, tags: Dict = {}): Dict {
  const { body } = wire.entryDelta("tasks", GROUP, "T#v1", dumps({ job: 1 }), writer, "w", 60_000, null, wall, tags);
  return (loads((loads(body) as Dict)["payload"] as Uint8Array) as Dict)["state"] as Dict;
}

/** An agent-signed write of `agent` at `wall`: record, certificate and state all the agent's own. */
function agentWrite(host: Identity, agent: AgentIdentity, wall: number): Dict {
  const { body } = wire.entryDelta("tasks", GROUP, "T#v1", dumps({ job: 2 }), host, "ignored", 60_000, agent, wall);
  return (loads((loads(body) as Dict)["payload"] as Uint8Array) as Dict)["state"] as Dict;
}

/**
 * An agent-signed write issued at `wall` whose state the agent signs at NOW, inside the drift
 * ceiling a state's signedAt keeps, so only the record's issue stamp leads the receiver.
 */
function agentRecord(host: Identity, agent: AgentIdentity, wall: number): Dict {
  const state = agentWrite(host, agent, wall);
  const record = state["record"] as Dict;
  const signedAt = `${NOW}:0:${agent.agentId}`;
  const view = wire.stateSignView(String(record["spaceId"]), String(record["entryId"]), state["adds"] as Dict[],
    state["removes"] as Dict[], String(state["leaseStamp"]), state["leaseValue"] as Dict, false, agent.agentId, signedAt);
  return { ...state, stateSig: agent.sign(dumps(view)), signedAt };
}

/** The same write re-issued at `issued`, record and state re-signed by its writer. */
function reissued(writer: Identity, state: Dict, issued: string): Dict {
  const record: Dict = { ...(state["record"] as Dict), issued };
  record["sig"] = writer.sign(dumps(wire.signViewOf(record)));
  return wire.signState({ ...state, record, leaseStamp: issued }, writer, null, NOW);
}

/** The write renewed at `leaseStamp`, the state re-signed by its writer. */
function renewed(writer: Identity, state: Dict, leaseStamp: string): Dict {
  const record = state["record"] as Dict;
  return wire.signState({ ...state, leaseStamp,
    leaseValue: { holder: record["issuer"], expiresAtMillis: NOW + 120_000, kind: "WRITE" } }, writer, null, NOW);
}

function stateDelta(dto: Dict): Uint8Array {
  return dumps({ state: dto, claimEntry: null, claim: null });
}

function entryOf(state: Dict): string {
  return String((state["record"] as Dict)["entryId"]);
}

function claimOn(holder: Identity, state: Dict, stamp: string, agent: AgentIdentity | null = null): Dict {
  const record = state["record"] as Dict;
  return wire.signedClaim(wire.takeClaim(String(record["entryId"]), String(record["spaceId"]), 1, stamp,
    agent === null ? holder.agent("worker") : agent.agentId, 0.0, NOW + 60_000), holder, agent);
}

/** Retires `agent` (an agent id) from `effective` on, signed by its own peer `issuer`. */
function retire(peer: Peer, issuer: Identity, agent: string, effective: number): void {
  const ad: Dict = { id: revocation.revocationId(GROUP, { kind: "AGENT", agent }), issuer: issuer.peerId, group: GROUP,
    issued: instantIso(NOW), ttl: "PT720H", target: { kind: "AGENT", agent }, reason: "retired",
    effectiveFrom: instantIso(effective) };
  const adBytes = dumps(ad);
  assert.equal(peer.revocations.acceptSigned(revocation.CREDENTIAL_STREAM,
    { adBytes, publicKey: issuer.publicRaw, signature: issuer.sign(adBytes) }, NOW), true);
}

// ------------------------------------------------------------------------------------------- E1

/** Issue ISSUE-HlcCanonicalStamps §14.5 rows 1 to 9: the item, and whether a stamp position accepts it. */
const ROW_2_TEXT = "1762560000000:65536:zPeer";
const STAMP_ROWS: [number, Uint8Array, boolean, string][] = [
  [1, hex("65 35 3A 30 3A 6E"), true, "5:0:n"],
  [2, concat(hex("78 19"), utf8(ROW_2_TEXT)), true, ROW_2_TEXT],
  [3, hex("66 35 3A 30 3A C3 B1"), true, "5:0:ñ"],
  [4, hex("68 35 3A 30 3A F0 9F 98 80"), true, "5:0:😀"],
  [5, hex("78 05 35 3A 30 3A 6E"), false, "5:0:n"],
  [6, hex("79 00 05 35 3A 30 3A 6E"), false, "5:0:n"],
  [7, hex("7A 00 00 00 05 35 3A 30 3A 6E"), false, "5:0:n"],
  [8, hex("7B 00 00 00 00 00 00 00 05 35 3A 30 3A 6E"), false, "5:0:n"],
  [9, concat(hex("79 00 19"), utf8(ROW_2_TEXT)), false, ROW_2_TEXT],
];

test("E1: §14.5 rows 5 to 9 under a frame's stamp drop the frame at decode, and rows 1 to 4 pass", () => {
  const peer = new CapturingPeer();
  const sender = Identity.generate();
  for (const [row, item, accepted, stamp] of STAMP_ROWS) {
    // HLC round six, 2026-11-08 (S3): rows 5 to 9 are no document anywhere, a stamp or any other text.
    assert.equal(accepted ? loads(item) : null, accepted ? stamp : null, `row ${row}`);
    if (!accepted) {
      assert.throws(() => loads(item), RangeError, `row ${row}`);
    }
    const frame = wire.encodeFrame(wire.envelope(GROUP, "PING", sender.peerId, stamp, wire.pingBody(row),
      peer.identity.peerId), sender);
    const respelled = respell(frame, stamp, item);
    assert.equal(wire.decodeFrame(respelled) !== null, accepted, `row ${row}`);
    peer.deliverFrame(respelled);
  }
  assert.equal(peer.malformedFrames, 5, "rows 5 to 9 count as malformed; the signature covers the canonical bytes");
});

test("E1: a longer length header under issued, a lease stamp, signedAt or a claim's stamp makes the delta undecodable", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const state = writtenState(writer);
  const issuer = String((state["record"] as Dict)["issuer"]);
  const issued = String((state["record"] as Dict)["issued"]);
  const renewal = renewed(writer, state, `${NOW + 1}:0:${issuer}`);
  const host = Identity.generate();
  const agent = host.renewingSubordinate("planner", "PT24H", Identity.generate(), () => NOW);
  const agentState = agentWrite(host, agent, NOW);
  const holder = Identity.generate();
  const claimStamp = `${NOW}:7:${holder.peerId}`;
  const claim = claimOn(holder, state, claimStamp);
  let expected = 0;
  for (const [stamp, delta] of [[issued, stateDelta(state)], [`${NOW + 1}:0:${issuer}`, stateDelta(renewal)],
    [String(agentState["signedAt"]), stateDelta(agentState)], [claimStamp, wire.claimDelta(entryOf(state), claim)]] as const) {
    for (const [name, item] of longerHeads(stamp)) {
      peer.rumor(writer, respell(delta, stamp, item));
      expected += 1;
      assert.equal(peer.deltasUndecodable, expected, `${name} under ${stamp}`);
    }
  }
  for (const item of longerHeads(claimStamp).values()) {
    peer.deliver(holder, "PULL_RESP", dumps({ deltas: { "space:tasks":
      respell(dumps({ states: [], claims: { [entryOf(state)]: claim } }), claimStamp, item) } }));
    expected += 1;
  }
  assert.deepEqual([peer.deltasUndecodable, peer.states.size, peer.claims.size], [expected, 0, 0]);
  assert.deepEqual([peer.stampsLogicalRefused, peer.stampsFarFutureRefused, peer.stampsFarFutureDeferred], [0, 0, 0]);
  peer.rumor(writer, stateDelta(state));
  peer.rumor(holder, wire.claimDelta(entryOf(state), claim));
  assert.deepEqual([peer.states.size, peer.claims.size], [1, 1], "the shortest spelling of each merges");
});

// ------------------------------------------------------------------------------------------- E8

test("S6: an indefinite-length text decodes only past 3996 UTF-16 units and only in Jackson's chunks (HLC round six, 2026-11-08)", () => {
  const long = "x".repeat(3997);
  assert.equal(loads(concat(hex("7F 79 0F 9C"), utf8("x".repeat(3996)), hex("61 78 FF"))), long);
  assert.throws(() => loads(hex("7F 65 35 3A 30 3A 6E FF")), RangeError, "a short text in one chunk");
  assert.throws(() => loads(hex("7F 62 35 3A 63 30 3A 6E FF")), RangeError, "a short text in two chunks");
  assert.throws(() => loads(hex("7F FF")), RangeError, "an empty indefinite text");
  assert.throws(() => loads(hex("BF 7F 61 6B FF 7F 61 76 FF FF")), RangeError, "short indefinite key and value");
  assert.throws(() => loads(concat(hex("7F 61 78 79 0F 9C"), utf8("x".repeat(3996)), hex("FF"))), RangeError,
    "3997 units cut 1 + 3996");
  assert.throws(() => loads(hex("7F 42 35 36 FF")), RangeError, "a byte-string chunk");
  assert.throws(() => loads(hex("7F 7F 61 61 FF FF")), RangeError, "an indefinite chunk");
  assert.throws(() => loads(hex("7F 61 C3 61 B1 FF")), RangeError, "a character split across two chunks");
  assert.throws(() => loads(hex("7F 61 61")), RangeError, "no break");
  assert.throws(() => loads(hex("62 C1 AE")), RangeError, "overlong UTF-8 outside a stamp");
  assert.throws(() => loads(hex("63 ED A0 80")), RangeError, "a surrogate in UTF-8 outside a stamp");
  assert.throws(() => loads(hex("61 FF")), RangeError, "an invalid byte outside a stamp");
});

/**
 * The bignums the wire encoding holds (HLC round six, 2026-11-08, S9): tag 2 or 3 over
 * BigInteger.toByteArray of a magnitude past a Java long, read as Jackson reads them (tag 3 negates).
 */
const BIG_NUMBERS: [string, string, bigint][] = [
  ["tag 2, 2^63 as Java writes it", "C2 49 00 80 00 00 00 00 00 00 00", 1n << 63n],
  ["tag 2, 2^64", "C2 49 01 00 00 00 00 00 00 00 00", 1n << 64n],
  ["tag 3, -2^63 - 1", "C3 49 00 80 00 00 00 00 00 00 01", -(1n << 63n) - 1n],
  ["tag 3, -2^64", "C3 49 01 00 00 00 00 00 00 00 00", -(1n << 64n)],
];

/** Big-number forms Jackson read in round five and the wire encoding refuses (S3, S9). */
const REFUSED_BIG_NUMBERS: [string, string][] = [
  ["tag 2, a small bignum a long holds", "C2 41 05"],
  ["tag 2 over no bytes", "C2 40"],
  ["tag 2 with a redundant leading zero byte", "C2 42 00 05"],
  ["tag 2 under a one-byte tag head", "D8 02 41 05"],
  ["tag 2 over a byte string with a one-byte length", "C2 58 01 05"],
  ["tag 2 with its high bit set", "C2 48 80 00 00 00 00 00 00 00"],
  ["tag 3 over 2^63, which is -2^63, a long", "C3 48 80 00 00 00 00 00 00 00"],
  ["tag 3, a BigInteger of -5 as Jackson writes it today", "C3 41 05"],
  ["tag 3 over a zero byte", "C3 41 00"],
];

test("S9: a bignum decodes to its bigint only past a Java long and only in BigInteger.toByteArray form (HLC round six, 2026-11-08)", () => {
  for (const [name, item, value] of BIG_NUMBERS) {
    assert.equal(loads(hex(item)), value, name);
    assert.deepEqual(dumps(value), hex(item), name);
  }
  for (const [name, item] of REFUSED_BIG_NUMBERS) {
    assert.throws(() => loads(hex(item)), RangeError, name);
  }
});

/** Each normalized tag 4 item, its exponent, its mantissa, and the double a filter compares (HLC round six, 2026-11-08, S9). */
const DECIMALS: [string, string, number, number | bigint, number][] = [
  ["1.25", "C4 82 21 18 7D", -2, 125, 1.25],
  ["zero", "C4 82 00 00", 0, 0, 0],
  ["0.1, the double nearest it", "C4 82 20 01", -1, 1, 0.1],
  ["1E+3", "C4 82 03 01", 3, 1, 1000],
  ["-0.5", "C4 82 20 24", -1, -5, -0.5],
  ["a bignum mantissa", "C4 82 01 C2 49 01 00 00 00 00 00 00 00 01", 1, (1n << 64n) + 1n, 1.8446744073709552e20],
  ["the largest exponent", "C4 82 1A 7F FF FF FF 01", 2147483647, 1, Number.POSITIVE_INFINITY],
  ["the smallest exponent", "C4 82 3A 7F FF FF FE 01", -2147483647, 1, 0],
  ["0.99999999999999999999 rounds to the nearest double", "C4 82 33 C2 49 05 6B C7 5E 2D 63 0F FF FF", -20,
    99999999999999999999n, 1],
];

/** Decimal forms round five read and the wire encoding refuses (S3, S9). */
const REFUSED_DECIMALS: [string, string][] = [
  ["a mantissa with a trailing zero, 1.0", "C4 82 20 0A"],
  ["a zero with an exponent", "C4 82 24 00"],
  ["a mantissa of tag 3 a long holds", "C4 82 20 C3 41 05"],
  ["a mantissa past a long as a plain integer", "C4 82 00 1B FF FF FF FF FF FF FF FF"],
  ["an exponent under an eight-byte head", "C4 82 1B 00 00 00 00 00 00 00 05 01"],
  ["under a one-byte tag head", "D8 04 82 21 18 7D"],
  ["the exponent -2^31, whose scale Java's int negation wraps", "C4 82 3A 7F FF FF FF 01"],
  ["a mantissa of 2^31 under an eight-byte head", "C4 82 22 1B 00 00 00 00 80 00 00 00"],
];

test("S9: tag 4 decodes to an exact CborDecimal only when normalized under shortest heads (HLC round six, 2026-11-08)", () => {
  for (const [name, item, exponent, mantissa, value] of DECIMALS) {
    const decimal = loads(hex(item));
    assert.ok(decimal instanceof CborDecimal, name);
    assert.deepEqual([decimal.exponent, decimal.mantissa, decimal.value], [exponent, mantissa, value], name);
    assert.deepEqual(dumps(decimal), hex(item), name);
  }
  for (const [name, item] of REFUSED_DECIMALS) {
    assert.throws(() => loads(hex(item)), RangeError, name);
  }
});

test("S9: every tag but 2, 3 and 4 is refused, and so is a big-number tag over any other item", () => {
  for (const [name, item] of [["tag 0 over text", "C0 65 35 3A 30 3A 6E"], ["tag 1 over an integer", "C1 1A 51 4B 67 B0"],
    ["tag 5, a bigfloat", "C5 82 20 03"], ["tag 32 over text", "D8 20 65 35 3A 30 3A 6E"],
    ["tag 42 over bytes", "D8 2A 42 00 01"], ["tag 55799 over a map", "D9 D9 F7 A1 61 61 01"],
    ["tag 55799 over a bignum", "D9 D9 F7 C2 41 05"], ["a tag past 2^53", "DB 00 20 00 00 00 00 00 02 41 05"],
    ["tag 2 over an integer", "C2 05"], ["tag 2 over text", "C2 61 61"], ["tag 2 over a map", "C2 A0"],
    ["tag 2 over an indefinite-length byte string", "C2 5F 41 05 FF"], ["tag 2 over a bignum", "C2 C2 41 05"],
    ["tag 3 over an array", "C3 80"], ["tag 4 over a map", "C4 A0"], ["tag 4 over one element", "C4 81 01"],
    ["tag 4 over three elements", "C4 83 01 01 01"], ["tag 4 over an indefinite-length array", "C4 9F 00 00 FF"],
    ["tag 4 with a bignum exponent", "C4 82 C2 41 01 01"], ["tag 4 with a float exponent", "C4 82 F9 3C 00 01"],
    ["tag 4 with an exponent of 2^31", "C4 82 1A 80 00 00 00 01"],
    ["tag 4 with an exponent below -2^31", "C4 82 3A 80 00 00 00 01"],
    ["tag 4 with a decimal mantissa", "C4 82 00 C4 82 00 00"], ["tag 4 with a text mantissa", "C4 82 00 61 31"],
    ["tag 4 whose bignum mantissa sits under a one-byte tag head", "C4 82 00 D8 02 41 05"],
    ["a refused tag inside a map", "A1 61 61 C1 05"], ["a bignum as a map key", "A1 C2 41 05 01"],
    ["a decimal as a map key", "A1 C4 82 21 18 7D 01"], ["a refused tag inside an array", "9F 01 C0 61 61 FF"],
    ["an indefinite tag head", "DF 01"]]) {
    assert.throws(() => loads(hex(item)), RangeError, name);
  }
});

test("S9: Java's {count: BigInteger 5, price: BigDecimal 1.25} decodes as the encoding writes it, and Jackson's tag 2 form for 5 is refused", () => {
  const written = hex("BF 65 63 6F 75 6E 74 05 65 70 72 69 63 65 C4 82 21 18 7D FF");
  const decoded = loads(written) as Dict;
  assert.equal(decoded["count"], 5);
  const price = decoded["price"];
  assert.ok(price instanceof CborDecimal);
  assert.deepEqual([price.exponent, price.mantissa, price.value], [-2, 125, 1.25]);
  assert.deepEqual(dumps(decoded), written);
  assert.throws(() => loads(hex("BF 65 63 6F 75 6E 74 C2 41 05 65 70 72 69 63 65 C4 82 21 18 7D FF")), RangeError,
    "a BigInteger a long holds is a plain integer (JC-1)");
});

test("S4, S9: the encoder writes an integer past a long and a decimal in the one form the encoding gives them", () => {
  for (const [name, value, item] of [
    ["BigInteger 2^64", 1n << 64n, "C2 49 01 00 00 00 00 00 00 00 00"],
    ["BigInteger -(2^64) - 1", -(1n << 64n) - 1n, "C3 49 01 00 00 00 00 00 00 00 01"],
    ["BigInteger 2^71, its top bit set", 1n << 71n, "C2 4A 00 80 00 00 00 00 00 00 00 00"],
    ["BigInteger 2^64 - 1, past a long", (1n << 64n) - 1n, "C2 49 00 FF FF FF FF FF FF FF FF"],
    ["BigDecimal 1.0, normalized", new CborDecimal(-1, 10), "C4 82 00 01"],
    ["BigDecimal 0E-5, zero", new CborDecimal(-5, 0), "C4 82 00 00"],
    ["a decimal built with the exponent -0", new CborDecimal(-0, -0), "C4 82 00 00"],
    ["BigDecimal -12345678901234567890123.5", new CborDecimal(-1, -123456789012345678901235n),
      "C4 82 20 C3 4A 1A 24 9B 1F 10 A0 6C 96 AF F3"],
    ["BigDecimal 18446744073709551615, its mantissa past a long", new CborDecimal(0, (1n << 64n) - 1n),
      "C4 82 00 C2 49 00 FF FF FF FF FF FF FF FF"],
  ] as [string, CborValue, string][]) {
    assert.deepEqual(dumps(value), hex(item), name);
  }
  assert.equal(new CborDecimal(-2, 125).value, 1.25);
  assert.throws(() => new CborDecimal(1.5, 1), RangeError, "an exponent that is no integer");
  assert.throws(() => new CborDecimal(2 ** 31, 1), RangeError, "an exponent past the range");
  assert.throws(() => new CborDecimal(-(2 ** 31), 1), RangeError, "the exponent -2^31");
  assert.throws(() => new CborDecimal(0, 0.5), RangeError, "a mantissa that is no integer");
});

test("F1: a claim whose epoch arrives as a tag 2 bignum or whose bid arrives as a tag 4 decimal is undecodable and folds nowhere", () => {
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  const record = state["record"] as Dict;
  const signed = wire.signedClaim(wire.takeClaim(entryOf(state), String(record["spaceId"]), 1, `${NOW}:0:${holder.peerId}`,
    holder.agent("worker"), 1.25, NOW + 60_000), holder);
  for (const [name, from, to] of [
    ["epoch as tag 2", concat(textItem(utf8("epoch")), hex("01")), concat(textItem(utf8("epoch")), hex("C2 41 01"))],
    ["bid as tag 4", concat(textItem(utf8("bid")), dumps(new CborDouble(1.25))), concat(textItem(utf8("bid")), hex("C4 82 21 18 7D"))],
  ] as [string, Uint8Array, Uint8Array][]) {
    const peer = new CapturingPeer();
    peer.rumor(writer, stateDelta(state));
    peer.rumor(holder, replaceOnce(wire.claimDelta(entryOf(state), signed), from, to));
    assert.deepEqual([peer.claims.size, peer.deltasUndecodable], [0, 1], name);
  }
  const claim = signed["claim"] as Dict;
  assert.equal(wire.verifyClaimProof({ ...signed, claim: { ...claim, bid: new CborDecimal(-2, 125) } }), false,
    "a decimal is no float64 bid");
  assert.equal(wire.verifyClaimProof({ ...signed, claim: { ...claim, epoch: new CborDecimal(0, 1) } }), false,
    "a decimal is no long epoch");
});

/** The bytes Jackson 2.21.7's CBORGenerator writes for each string (checked against Jackson itself). */
const JACKSON_STRINGS: [string, string, Uint8Array][] = [
  ["3996 units, definite", "x".repeat(3996), concat(hex("79 0F 9C"), utf8("x".repeat(3996)))],
  ["3997 units, two chunks", "x".repeat(3997),
    concat(hex("7F 79 0F 9C"), utf8("x".repeat(3996)), hex("61 78 FF"))],
  ["a surrogate pair ending the first chunk", `${"x".repeat(3994)}😀yyyy`,
    concat(hex("7F 79 0F 9E"), utf8(`${"x".repeat(3994)}😀`), hex("64"), utf8("yyyy"), hex("FF"))],
  ["a surrogate pair across the boundary moves to the next chunk", `${"x".repeat(3995)}😀yyyy`,
    concat(hex("7F 79 0F 9B"), utf8("x".repeat(3995)), hex("68"), utf8("😀yyyy"), hex("FF"))],
  ["two-byte characters chunk by units", "é".repeat(4000),
    concat(hex("7F 79 1F 38"), utf8("é".repeat(3996)), hex("68"), utf8("éééé"), hex("FF"))],
  ["1998 pairs are 3996 units, definite", "😀".repeat(1998), concat(hex("79 1F 38"), utf8("😀".repeat(1998)))],
];

test("E8: the encoder writes a string over 3996 UTF-16 units in Jackson's chunks, and both forms round-trip", () => {
  for (const [name, text, bytes] of JACKSON_STRINGS) {
    assert.deepEqual(dumps(text), bytes, name);
    assert.equal(loads(bytes), text, name);
  }
  const key = "k".repeat(5000);
  const map = concat(hex("BF 7F 79 0F 9C"), utf8("k".repeat(3996)), hex("79 03 EC"), utf8("k".repeat(1004)), hex("FF 01 FF"));
  assert.deepEqual(dumps({ [key]: 1 }), map, "a long map key chunks the same way");
  assert.deepEqual(dumps(loads(map)), map);
});

test("E8: a record whose tag holds a long string crosses the wire in Jackson's form and verifies", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const note = "n".repeat(5000);
  const { body } = wire.entryDelta("tasks", GROUP, "T#v1", dumps({ job: 1 }), writer, "w", 60_000, null, NOW, { note });
  const delta = (loads(body) as Dict)["payload"] as Uint8Array;
  assert.ok(Buffer.from(delta).includes(Buffer.from(hex("7F 79 0F 9C"))), "the tag value travels chunked");
  peer.rumor(writer, delta);
  assert.equal(peer.states.size, 1);
  assert.equal(((peer.states.values().next().value!["record"] as Dict)["tags"] as Dict)["note"], note);
});

// ------------------------------------------------------------------------------------------ E13

test("F3: a claim whose map arrives out of TakeClaim order, with an integer bid, or with an extra field verifies nowhere and its delta is undecodable", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  peer.rumor(writer, stateDelta(state));
  const record = state["record"] as Dict;
  const claim = wire.takeClaim(entryOf(state), String(record["spaceId"]), 1, `${NOW}:0:${holder.peerId}`,
    holder.agent("worker"), 0.0, NOW + 60_000);
  const signature = holder.sign(dumps(claim));
  const reordered: Dict = Object.fromEntries(Object.entries(claim).reverse());
  peer.rumor(holder, wire.claimDelta(entryOf(state), { claim: reordered, holderKey: holder.publicRaw, signature }));
  assert.deepEqual([peer.claims.size, peer.deltasUndecodable], [0, 1], "a claim out of order is undecodable (claim-18)");
  for (const arrived of [{ ...claim, bid: 0 }, { ...claim, note: "unsigned" }] as Dict[]) {
    assert.equal(wire.verifyClaimProof({ claim: arrived, holderKey: holder.publicRaw, signature }), false);
    peer.rumor(holder, wire.claimDelta(entryOf(state), { claim: arrived, holderKey: holder.publicRaw, signature }));
  }
  assert.deepEqual([peer.claims.size, peer.deltasUndecodable], [0, 3]);
  peer.rumor(holder, wire.claimDelta(entryOf(state), { claim, holderKey: holder.publicRaw, signature }));
  assert.equal(peer.claims.size, 1, "the claim in its record's form folds");
});

test("E13: a claim whose fields Java's TakeClaim refuses has no canonical encoding, so no proof verifies, nothing folds, and its delta counts as undecodable", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  peer.rumor(writer, stateDelta(state));
  const record = state["record"] as Dict;
  const claim = (fields: Dict): Dict => ({ ...wire.takeClaim(entryOf(state), String(record["spaceId"]), 1,
    `${NOW}:0:${holder.peerId}`, holder.agent("worker"), 0.0, NOW + 60_000), ...fields });
  // Java's AgentId.parse, EntryId, SpaceId and the TakeClaim constructor refuse each of these.
  for (const fields of [{ holder: `${holder.peerId}/a/b` }, { holder: `${holder.peerId}/` }, { holder: holder.peerId },
    { entryId: "" }, { spaceId: "" }, { epoch: 0 }, { epoch: -1 }, { bid: Number.POSITIVE_INFINITY }, { bid: Number.NaN }] as Dict[]) {
    const arrived = claim(fields);
    assert.equal(wire.canonicalClaim(arrived), null, JSON.stringify(fields));
    const signed: Dict = { claim: arrived, holderKey: holder.publicRaw, signature: holder.sign(dumps(arrived)) };
    assert.equal(wire.verifyClaimProof(signed), false, JSON.stringify(fields));
    assert.throws(() => wire.signedClaim(arrived, holder), /claim/, JSON.stringify(fields));
    peer.rumor(holder, wire.claimDelta(entryOf(state), signed));
  }
  // Java's codec cannot build the TakeClaim, so it counts each delta in deltasUndecodable (HLC round five, 2026-11-08, E13).
  assert.deepEqual([peer.claims.size, peer.deltasUndecodable], [0, 9]);
  peer.rumor(holder, wire.claimDelta(entryOf(state), wire.signedClaim(claim({}), holder)));
  assert.deepEqual([peer.claims.size, peer.deltasUndecodable], [1, 9], "the claim Java decodes folds");
});

/**
 * Claim fields Java's TakeClaim refuses or that are of no TakeClaim kind (HLC round six, 2026-11-08, F1),
 * each as it travels and as a snapshot holds it.
 */
const REFUSED_CLAIM_FIELDS: [string, string, CborValue][] = [
  ["expiresAtMillis 2^64, past a long", "expiresAtMillis", 1n << 64n],
  ["bid 1E+1000, a decimal", "bid", new CborDecimal(1000, 1)],
  ["epoch -1", "epoch", -1],
  ["epoch 0", "epoch", 0],
  ["epoch as text", "epoch", "1"],
  ["bid as a float32", "bid", new CborFloat32(0)],
  ["holder as a byte string", "holder", utf8("h")],
];

test("F1: a claim delta whose epoch, bid, expiry or holder is no TakeClaim's counts in deltasUndecodable by rumor, anti-entropy and snapshot", () => {
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  const record = state["record"] as Dict;
  for (const [name, field, value] of REFUSED_CLAIM_FIELDS) {
    const claim = { ...wire.takeClaim(entryOf(state), String(record["spaceId"]), 1, `${NOW}:0:${holder.peerId}`,
      holder.agent("worker"), 0.0, NOW + 60_000), [field]: value };
    const signed: Dict = { claim, holderKey: holder.publicRaw, signature: holder.sign(dumps(claim)) };
    const peer = new CapturingPeer();
    peer.rumor(writer, stateDelta(state));
    peer.rumor(holder, wire.claimDelta(entryOf(state), signed));
    assert.deepEqual([peer.claims.size, peer.deltasUndecodable], [0, 1], `${name}, by rumor`);
    peer.pulled(holder, [state], { [entryOf(state)]: signed });
    assert.deepEqual([peer.claims.size, peer.deltasUndecodable], [0, 2], `${name}, by anti-entropy`);
    const restored = new CapturingPeer();
    restored.restoreSnapshot({ group: GROUP, states: [state], claims: { [entryOf(state)]: signed } });
    assert.deepEqual([restored.states.size, restored.claims.size, restored.deltasUndecodable], [1, 0, 1], `${name}, by snapshot`);
    const counters = [peer.stampsLogicalRefused, peer.stampsFarFutureRefused, peer.stampsFarFutureDeferred];
    assert.deepEqual(counters, [0, 0, 0], `${name} counts in no stamp counter`);
  }
});

// ------------------------------------------------------------------------------------------- E4

test("E4: an agent-signed record past the old certificate bound merges inside the margin, defers past it, and is hostile an hour out", () => {
  const peer = new CapturingPeer();
  const host = Identity.generate();
  const agent = host.renewingSubordinate("planner", "PT24H", Identity.generate(), () => NOW);
  peer.rumor(host, stateDelta(agentRecord(host, agent, NOW + wire.MAX_HLC_SKEW_MILLIS + 1_000)));
  assert.equal(peer.states.size, 1, "past wall + MAX_DRIFT, inside the margin: merged");
  const deferred = agentRecord(host, agent, CEILING + 1_000);
  peer.rumor(host, stateDelta(deferred));
  peer.rumor(host, stateDelta(deferred));
  assert.deepEqual([peer.states.size, peer.stampsFarFutureDeferred, peer.stampsFarFutureRefused], [1, 1, 0]);
  const hostile = agentRecord(host, agent, CEILING + wire.FAR_FUTURE_HOSTILE_MILLIS + 1_000);
  peer.rumor(host, stateDelta(hostile));
  assert.deepEqual([peer.states.size, peer.stampsFarFutureRefused, peer.stampsLogicalRefused], [1, 1, 0]);
  assert.ok(peer.acknowledged().includes(`a:e:${entryOf(hostile)}=${stateHash(hostile)}`));
  peer.millis = NOW + 2_000;
  peer.pulled(host, [deferred]);
  assert.equal(peer.states.size, 2, "the deferred write merges once the wall catches up");
});

test("E4: an agent-attested claim past the margin defers and merges later, and one an hour out is hostile", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const clerk = holder.renewingSubordinate("clerk", "PT24H", Identity.generate(), () => NOW);
  const state = writtenState(writer);
  peer.rumor(writer, stateDelta(state));
  const hostile = claimOn(holder, state, `${CEILING + wire.FAR_FUTURE_HOSTILE_MILLIS + 1}:0:${clerk.agentId}`, clerk);
  peer.rumor(holder, wire.claimDelta(entryOf(state), hostile));
  assert.deepEqual([peer.claims.size, peer.stampsFarFutureRefused], [0, 1]);
  const deferred = claimOn(holder, state, `${CEILING + 1}:0:${clerk.agentId}`, clerk);
  peer.rumor(holder, wire.claimDelta(entryOf(state), deferred));
  assert.deepEqual([peer.claims.size, peer.stampsFarFutureDeferred], [0, 1]);
  peer.millis = NOW + 1;
  peer.pulled(holder, [], { [entryOf(state)]: deferred });
  assert.equal(peer.claims.size, 1);
});

/** An agent's write issued at NOW whose state the agent signed at `signedAt`, record and certificate unchanged. */
function agentSignedAt(host: Identity, agent: AgentIdentity, signedAt: number): Dict {
  const state = agentWrite(host, agent, NOW);
  const record = state["record"] as Dict;
  const stamp = `${signedAt}:0:${agent.agentId}`;
  const view = wire.stateSignView(String(record["spaceId"]), String(record["entryId"]), state["adds"] as Dict[],
    state["removes"] as Dict[], String(state["leaseStamp"]), state["leaseValue"] as Dict, false, agent.agentId, stamp);
  return { ...state, stateSig: agent.sign(dumps(view)), signedAt: stamp };
}

test("F4: a state's signedAt meets the far-future rule: merged inside the margin, deferred past it, hostile an hour out (HLC round six, 2026-11-08)", () => {
  const peer = new CapturingPeer();
  const host = Identity.generate();
  const agent = host.renewingSubordinate("planner", "PT24H", Identity.generate(), () => NOW);
  peer.rumor(host, stateDelta(agentSignedAt(host, agent, NOW + wire.MAX_HLC_SKEW_MILLIS + 1_000)));
  assert.equal(peer.states.size, 1, "past wall + MAX_DRIFT, inside the margin: merged");
  const deferred = agentSignedAt(host, agent, CEILING + 1_000);
  peer.rumor(host, stateDelta(deferred));
  peer.rumor(host, stateDelta(deferred));
  assert.deepEqual([peer.states.size, peer.stampsFarFutureDeferred, peer.stampsFarFutureRefused], [1, 1, 0]);
  assert.ok(!peer.acknowledged().includes(`a:e:${entryOf(deferred)}=${stateHash(deferred)}`), "a deferral is not acknowledged");
  const hostile = agentSignedAt(host, agent, CEILING + wire.FAR_FUTURE_HOSTILE_MILLIS + 1_000);
  peer.rumor(host, stateDelta(hostile));
  assert.deepEqual([peer.states.size, peer.stampsFarFutureRefused, peer.stampsLogicalRefused], [1, 1, 0]);
  assert.ok(peer.acknowledged().includes(`a:e:${entryOf(hostile)}=${stateHash(hostile)}`), "a hostile state is acknowledged");
  peer.millis = NOW + 2_000;
  peer.pulled(host, [deferred]);
  assert.equal(peer.states.size, 2, "the deferred state merges once the wall catches up");
});

test("E4: the certificate's own validity window still applies, and a record outside it counts nothing", () => {
  const peer = new CapturingPeer();
  const host = Identity.generate();
  const agent = host.renewingSubordinate("planner", "PT24H", Identity.generate(), () => NOW);
  const state = agentWrite(host, agent, NOW);
  const record: Dict = { ...(state["record"] as Dict), issued: `${NOW - 3_600_000}:0:${agent.agentId}` };
  record["sig"] = agent.sign(dumps(wire.signViewOf(record)));
  peer.rumor(host, stateDelta(wire.signState({ ...state, record }, host, agent, NOW)));
  assert.equal(peer.states.size, 0);
  assert.deepEqual([peer.stampsLogicalRefused, peer.stampsFarFutureRefused, peer.stampsFarFutureDeferred], [0, 0, 0]);
});

// --------------------------------------------------------------------------------------- E6, E12

test("E6, E12: a revoked writer's state counts in no stamp counter and its digest line is acknowledged", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const state = writtenState(writer);
  const issuer = String((state["record"] as Dict)["issuer"]);
  retire(peer, writer, issuer, NOW - 60_000);
  const refused = [state,
    reissued(writer, state, `${NOW}:${wire.LOGICAL_LIMIT + 1}:${issuer}`),
    reissued(writer, state, `${CEILING + 1}:0:${issuer}`),
    reissued(writer, state, `${CEILING + wire.FAR_FUTURE_HOSTILE_MILLIS + 1}:0:${issuer}`)];
  for (const dto of refused) {
    peer.rumor(writer, stateDelta(dto));
  }
  assert.equal(peer.states.size, 0);
  assert.deepEqual([peer.stampsLogicalRefused, peer.stampsFarFutureRefused, peer.stampsFarFutureDeferred], [0, 0, 0]);
  const lines = peer.acknowledged();
  for (const dto of refused) {
    assert.ok(lines.includes(`a:e:${entryOf(dto)}=${stateHash(dto)}`), String((dto["record"] as Dict)["issued"]));
  }
});

test("E6: a revoked holder's claim counts in no stamp counter, whatever its stamp", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  peer.rumor(writer, stateDelta(state));
  retire(peer, holder, holder.agent("worker"), NOW - 60_000);
  for (const stamp of [`${NOW}:${wire.LOGICAL_LIMIT + 1}:${holder.peerId}`, `${CEILING + 1}:0:${holder.peerId}`,
    `${CEILING + wire.FAR_FUTURE_HOSTILE_MILLIS + 1}:0:${holder.peerId}`]) {
    const claim = claimOn(holder, state, stamp);
    peer.rumor(holder, wire.claimDelta(entryOf(state), claim));
    assert.equal(peer.refusesClaimStamp(entryOf(state), claim), wire.parseHlc(stamp) === null, stamp);
  }
  assert.equal(peer.claims.size, 0);
  assert.deepEqual([peer.stampsLogicalRefused, peer.stampsFarFutureRefused, peer.stampsFarFutureDeferred], [0, 0, 0]);
});

// ------------------------------------------------------------------------------------------- E7

test("E7: a state with a null lease stamp decodes, and one whose lease stamp is absent is undecodable (HLC round six, 2026-11-08, P1)", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const nullLease: Dict = { ...writtenState(writer), leaseStamp: null };
  peer.rumor(writer, stateDelta(nullLease));
  peer.pulled(writer, [nullLease]);
  assert.deepEqual([peer.deltasUndecodable, peer.stampsLogicalRefused, peer.stampsFarFutureRefused], [0, 0, 0]);
  const absent: Dict = { ...writtenState(writer) };
  delete absent["leaseStamp"];
  peer.rumor(writer, stateDelta(absent));
  peer.pulled(writer, [absent]);
  assert.deepEqual([peer.deltasUndecodable, peer.stampsLogicalRefused, peer.stampsFarFutureRefused], [2, 0, 0]);
});

test("E7: a signed state without its lease stamp or its lease value merges nothing and counts nothing, as Java drops it", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const held = writtenState(writer);
  const entryId = entryOf(held);
  const issuer = String((held["record"] as Dict)["issuer"]);
  peer.rumor(writer, stateDelta(held));
  const revoked = Identity.generate();
  const revokedWrite = writtenState(revoked);
  retire(peer, revoked, String((revokedWrite["record"] as Dict)["issuer"]), NOW - 60_000);
  for (const gap of [{ leaseStamp: null }, { leaseValue: null }, { leaseStamp: null, leaseValue: null }] as Dict[]) {
    const renewal = wire.signState({ ...renewed(writer, held, `${NOW + 1}:0:${issuer}`), ...gap }, writer, null, NOW);
    const unheld = wire.signState({ ...writtenState(writer), ...gap }, writer, null, NOW);
    for (const [dto, signer] of [[{ ...writtenState(writer), ...gap }, writer],
      [renewal, writer], [{ ...revokedWrite, ...gap }, revoked]] as [Dict, Identity][]) {
      peer.rumor(signer, stateDelta(wire.signState(dto, signer, null, NOW)));
    }
    // Recordless, over the held record and for an entry this replica does not hold; a recordless state
    // omits its record, which Java writes NON_NULL (HLC round six, 2026-11-08, P1).
    for (const signed of [renewal, unheld]) {
      const recordless: Dict = { ...signed, entryId: entryOf(signed) };
      delete recordless["record"];
      peer.rumor(writer, stateDelta(recordless));
    }
  }
  assert.deepEqual([...peer.states.keys()], [entryId], "no write missing its lease merged");
  assert.deepEqual(dumps(peer.states.get(entryId)!), dumps(held), "no renewal missing its lease changed the held state");
  assert.equal(peer.pendingStates.size, 0, "no recordless state missing its lease waits");
  assert.deepEqual(peer.acknowledged(), [], "the revoked writer's lease-less state is dropped before revocation is judged");
  assert.deepEqual([peer.deltasUndecodable, peer.stampsLogicalRefused, peer.stampsFarFutureRefused,
    peer.stampsFarFutureDeferred], [0, 0, 0, 0]);
  peer.rumor(writer, stateDelta(renewed(writer, held, `${NOW + 2}:0:${issuer}`)));
  assert.equal(peer.states.get(entryId)!["leaseStamp"], `${NOW + 2}:0:${issuer}`, "the replica goes on merging");
});

test("E7: a state without a lease stamp is signed over a null lease stamp, as Java's StateSignView encodes it", () => {
  const writer = Identity.generate();
  const state = writtenState(writer);
  const record = state["record"] as Dict;
  const javaView: Dict = { spaceId: record["spaceId"], entryId: record["entryId"], adds: state["adds"],
    removes: state["removes"], leaseStamp: null, leaseValue: state["leaseValue"], completed: false };
  for (const unsigned of [{ ...state, leaseStamp: null }, Object.fromEntries(Object.entries(state).filter(([k]) => k !== "leaseStamp"))]) {
    const signed = wire.signState(unsigned as Dict, writer, null, NOW);
    assert.equal(Identity.verify(writer.publicRaw, dumps(javaView), signed["stateSig"] as Uint8Array), true);
  }
});

// ------------------------------------------------------------------------------------------ E11

test("E11: the clock never stamps for a node holding a lone surrogate, and the grammar refuses one", () => {
  for (const node of ["a\uD800b", "a\uDC00", "\uD83D", "\uDE00x"]) {
    assert.throws(() => wire.hlcNow(node, NOW), /HLC node/, JSON.stringify(node));
    assert.throws(() => wire.hlcObserve(node, `${NOW}:0:x`, NOW), /HLC node/, JSON.stringify(node));
    assert.equal(wire.decodeHlc(`${NOW}:0:${node}`), null, JSON.stringify(node));
  }
  assert.equal(wire.hlcNow("round-five 😀", NOW), `${NOW}:0:round-five 😀`, "a surrogate pair is one character");
});

// ------------------------------------------------------------------------------------------ E14

test("E14: the refused-offer memory holds 4096 offers and forgets the least recently offered", () => {
  const peer = new CapturingPeer();
  const holder = Identity.generate();
  const refused = (i: number): Dict => wire.signedClaim(wire.takeClaim("e-lru", "s-lru", 1,
    `${NOW}:${wire.LOGICAL_LIMIT + 1 + i}:${holder.peerId}`, holder.agent("w"), 0.0, NOW + 60_000), holder);
  const first = refused(0);
  const others = Array.from({ length: 4095 }, (_, i) => refused(i + 1));
  for (const claim of [first, ...others]) {
    peer.refusesClaimStamp("e-lru", claim);
  }
  assert.equal(peer.stampsLogicalRefused, 4096);
  peer.refusesClaimStamp("e-lru", first);
  assert.equal(peer.stampsLogicalRefused, 4096, "re-offered: remembered, and now the most recent");
  peer.refusesClaimStamp("e-lru", refused(4096));
  peer.refusesClaimStamp("e-lru", first);
  assert.equal(peer.stampsLogicalRefused, 4097, "the re-offered claim stayed in memory");
  peer.refusesClaimStamp("e-lru", others[0]);
  assert.equal(peer.stampsLogicalRefused, 4098, "the least recently offered claim was forgotten");
});

test("E14: the deferred-offer memory forgets the least recently offered too", () => {
  const peer = new CapturingPeer();
  const holder = Identity.generate();
  const fold = (claim: Dict): void =>
    (peer as unknown as { foldClaim(entryId: string, signed: Dict): void }).foldClaim("e-lru", claim);
  const deferred = (i: number): Dict => wire.signedClaim(wire.takeClaim("e-lru", "s-lru", 1,
    `${CEILING + 1}:${i}:${holder.peerId}`, holder.agent("w"), 0.0, NOW + 60_000), holder);
  const first = deferred(0);
  const others = Array.from({ length: 4095 }, (_, i) => deferred(i + 1));
  for (const claim of [first, ...others]) {
    fold(claim);
  }
  fold(first);
  fold(deferred(4096));
  fold(first);
  assert.equal(peer.stampsFarFutureDeferred, 4097, "the re-offered claim stayed in memory");
  fold(others[0]);
  assert.equal(peer.stampsFarFutureDeferred, 4098, "the least recently offered claim was forgotten");
});
