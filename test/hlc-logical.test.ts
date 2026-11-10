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
 * HLC logical counter, 2026-11-08 (Rust team report). One signed stamp with a physical part just
 * under the drift cap and a huge logical counter used to pin the clock: a JavaScript number stops
 * adding one at 2^53, so every later stamp repeated, and receivers dropped the frozen peer's frames
 * as replays. The rule every implementation follows: a remote stamp whose logical counter exceeds
 * wire.LOGICAL_LIMIT never reaches the clock, and every receiver ignores the frame, folded record,
 * lease stamp or claim carrying it; a local increment past the limit carries into the physical part.
 *
 * Round two of the same report: a negative, fractional, exponent, NaN, empty or missing counter
 * slipped past a check that only asked "above the limit", and a counter of -1e300 froze the clock
 * because adding one to it changes nothing. One strict parser (wire.parseHlc) now accepts only
 * Java's canonical form, and every merge and ordering point refuses and counts whatever it
 * rejects. A remote physical part merges clamped one millisecond inside the drift cap, so a carry
 * after it lands at most on the cap and a receiver's far-future check never refuses it.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { concat, utf8 } from "../src/bytes.js";
import { dumps, loads } from "../src/cbor.js";
import * as cids from "../src/pdt/cids.js";
import { ISSUED_ATTR, ISSUER_ATTR, PREF_TYPE, Refs, mergeOrder, pref } from "../src/pdt/refs.js";
import type { Head } from "../src/pdt/refs.js";
import { hlcHash, stateHash } from "../src/serving.js";
import { NodeStore } from "../src/pdt/store.js";
import { Identity } from "../src/identity.js";
import type { AgentIdentity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const GROUP = "zTsHlcLogical";
const NOW = 1_800_000_000_000;
/** The Java wire's logical type maximum (Integer.MAX_VALUE), the stamp the Rust team reported. */
const JAVA_INT_MAX = 2_147_483_647;
/** The largest counter a JavaScript number holds exactly; one more and increments are lost. */
const HOSTILE = [JAVA_INT_MAX, Number.MAX_SAFE_INTEGER];

/** A peer on a settable clock whose sends are captured instead of written to a socket. */
class CapturingPeer extends Peer {
  readonly sent: string[] = [];
  readonly bodies: Uint8Array[] = [];
  private frameCounter = 0;
  private readonly clock: { millis: number };

  constructor(millis: number = NOW) {
    const clock = { millis };
    super(Identity.generate(), GROUP, () => clock.millis);
    this.clock = clock;
    this.joinSpace("tasks"); // the replica holds the space these tests write to (HLC round five, 2026-11-08)
  }

  /** The peer's wall time; a test moves it to let a deferred record merge (HLC round four, 2026-11-08). */
  get millis(): number {
    return this.clock.millis;
  }

  set millis(value: number) {
    this.clock.millis = value;
  }

  protected send(kind: string, body: Buffer, to: string | null = null): void {
    void to;
    this.sent.push(kind);
    this.bodies.push(body);
  }

  /** Signs a frame as `sender` and hands it to the peer's reader, an honest frame stamp by default. */
  deliver(sender: Identity, kind: string, body: Uint8Array,
          stamp = `${this.millis}:${this.frameCounter++}:${sender.peerId}`): void {
    const env = wire.envelope(GROUP, kind, sender.peerId, stamp, body, this.identity.peerId);
    this.deliverFrame(wire.encodeFrame(env, sender));
  }

  /** Hands raw frame bytes to the peer's reader, decoding included (HLC round four, 2026-11-08). */
  deliverFrame(frame: Uint8Array): void {
    (this as unknown as { onFrame(frame: Uint8Array): void }).onFrame(frame);
  }

  /** A space delta, as a RUMOR on the space's stream. */
  rumor(sender: Identity, delta: Uint8Array): void {
    this.deliver(sender, "RUMOR", wire.rumorBody("space:tasks", `w:${this.frameCounter}`, 6, delta));
  }
}

function hostileStamp(logical: number, node: string, physical = NOW): string {
  return `${physical}:${logical}:${node}`;
}

/** An honest write of `writer` at `wall`, its state DTO as the rumor carries it. */
function writtenState(writer: Identity, wall = NOW): Dict {
  const { body } = wire.entryDelta("tasks", GROUP, "T#v1", dumps({ job: 1 }), writer, "w", 60_000, null, wall);
  const rumor = loads(body) as Dict;
  return (loads(rumor["payload"] as Uint8Array) as Dict)["state"] as Dict;
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

/**
 * A claim `holder` signs whatever its stamp: wire.signedClaim refuses to sign a stamp outside the grammar
 * (HLC round six, 2026-11-08, F1), and these tests send such claims on purpose.
 */
function claimOn(holder: Identity, state: Dict, stamp: string): Dict {
  const record = state["record"] as Dict;
  const claim = wire.takeClaim(String(record["entryId"]), String(record["spaceId"]), 1,
    stamp, holder.agent("worker"), 0.0, NOW + 60_000);
  return { claim, holderKey: holder.publicRaw, signature: holder.sign(dumps(claim)) };
}

test("the clock refuses the reported attack, a maximal counter under the drift cap, and stays unchanged", () => {
  for (const logical of HOSTILE) {
    const node = `hlc-attack-${logical}`;
    assert.equal(wire.hlcNow(node, NOW), `${NOW}:0:${node}`);
    wire.hlcObserve(node, hostileStamp(logical, "evil", NOW + wire.MAX_HLC_SKEW_MILLIS - 1), NOW);
    const first = wire.hlcNow(node, NOW);
    const second = wire.hlcNow(node, NOW);
    assert.equal(first, `${NOW}:1:${node}`, `a counter of ${logical} never reaches the clock`);
    assert.equal(second, `${NOW}:2:${node}`);
    assert.notEqual(first, second, "the clock never freezes on one stamp");
  }
  const node = "hlc-attack-just-over";
  wire.hlcObserve(node, hostileStamp(wire.LOGICAL_LIMIT + 1, "evil", NOW + 5_000), NOW);
  assert.equal(wire.hlcNow(node, NOW), `${NOW}:0:${node}`, "one past the limit is refused too");
});

test("the clock accepts a remote stamp at exactly LOGICAL_LIMIT and sorts its next stamp after it", () => {
  assert.equal(wire.LOGICAL_LIMIT, 65_536);
  const node = "hlc-at-limit";
  const observed = hostileStamp(wire.LOGICAL_LIMIT, "remote", NOW + 5_000);
  wire.hlcObserve(node, observed, NOW);
  const next = wire.hlcNow(node, NOW);
  assert.equal(next, `${NOW + 5_001}:0:${node}`);
  assert.ok(wire.compareHlc(next, observed) > 0);
});

test("a local counter driven to LOGICAL_LIMIT carries into the physical part", () => {
  const node = "hlc-carry";
  let last = "";
  for (let i = 0; i <= wire.LOGICAL_LIMIT; i++) {
    last = wire.hlcNow(node, NOW);
  }
  assert.equal(last, `${NOW}:${wire.LOGICAL_LIMIT}:${node}`);
  assert.equal(wire.hlcNow(node, NOW), `${NOW + 1}:0:${node}`);
  // The wall clock reaching the carried millisecond continues from it.
  assert.equal(wire.hlcNow(node, NOW + 1), `${NOW + 1}:1:${node}`);
});

test("stamps after an accepted stamp at LOGICAL_LIMIT never repeat and always increase", () => {
  const node = "hlc-monotonic";
  let previous = hostileStamp(wire.LOGICAL_LIMIT, "remote", NOW + 1_000);
  wire.hlcObserve(node, previous, NOW);
  const seen = new Set<string>();
  const calls = 3 * wire.LOGICAL_LIMIT;
  for (let i = 0; i < calls; i++) {
    const next = wire.hlcNow(node, NOW);
    assert.ok(wire.compareHlc(next, previous) > 0, `${next} after ${previous}`);
    assert.ok(Number(next.split(":")[1]) <= wire.LOGICAL_LIMIT);
    seen.add(next);
    previous = next;
  }
  assert.equal(seen.size, calls);
});

test("the peer refuses and counts a frame stamped above LOGICAL_LIMIT before its clock takes the stamp", () => {
  const peer = new CapturingPeer();
  const other = Identity.generate();
  for (const logical of HOSTILE) {
    peer.deliver(other, "PING", wire.pingBody(logical),
      hostileStamp(logical, other.peerId, NOW + wire.MAX_HLC_SKEW_MILLIS - 1));
  }
  assert.deepEqual(peer.sent, [], "no ACK for a refused frame");
  // HLC round four, 2026-11-08: Java's int counter reads 2^31 - 1 and refuses it after the
  // signature verifies; a counter past it does not decode, so the frame is malformed, as in Java.
  assert.deepEqual([peer.frames.framesLogicalRefused, peer.malformedFrames], [1, 1]);
  assert.equal(wire.hlcNow(peer.identity.peerId, NOW), `${NOW}:0:${peer.identity.peerId}`);
  // The honest path: a frame at exactly the limit is answered and merges into the clock.
  const honest = hostileStamp(wire.LOGICAL_LIMIT, other.peerId, NOW + 5_000);
  peer.deliver(other, "PING", wire.pingBody(1), honest);
  assert.deepEqual(peer.sent, ["ACK"]);
  assert.deepEqual([peer.frames.framesLogicalRefused, peer.malformedFrames], [1, 1]);
  assert.ok(wire.compareHlc(wire.hlcNow(peer.identity.peerId, NOW), honest) > 0);
});

test("the replica ignores a record issued above LOGICAL_LIMIT and folds an honest one", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const state = writtenState(writer);
  const issuer = String((state["record"] as Dict)["issuer"]);
  for (const logical of HOSTILE) {
    peer.rumor(writer, stateDelta(reissued(writer, state, hostileStamp(logical, issuer))));
  }
  assert.equal(peer.states.size, 0);
  // HLC round four, 2026-11-08: a counter past 2^31 - 1 does not decode, so its delta is undecodable.
  assert.deepEqual([peer.stampsLogicalRefused, peer.deltasUndecodable], [1, 1]);
  peer.rumor(writer, stateDelta(reissued(writer, state, hostileStamp(wire.LOGICAL_LIMIT, issuer))));
  assert.equal(peer.states.size, 1);
  assert.deepEqual([peer.stampsLogicalRefused, peer.deltasUndecodable], [1, 1]);
});

test("a lease stamp above LOGICAL_LIMIT never extends the lease, and an honest renewal does", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  const issuer = String((state["record"] as Dict)["issuer"]);
  peer.rumor(writer, stateDelta(state));
  assert.equal(peer.states.get(entryId)!["leaseStamp"], state["leaseStamp"]);
  for (const logical of HOSTILE) {
    peer.rumor(writer, stateDelta(renewed(writer, state, hostileStamp(logical, issuer))));
  }
  assert.equal(peer.states.get(entryId)!["leaseStamp"], state["leaseStamp"], "the lease kept its stamp");
  assert.deepEqual([peer.stampsLogicalRefused, peer.deltasUndecodable], [1, 1]);
  const honest = hostileStamp(0, issuer, NOW + 1);
  peer.rumor(writer, stateDelta(renewed(writer, state, honest)));
  assert.equal(peer.states.get(entryId)!["leaseStamp"], honest);
  // A recordless renewal (PD-L-01) passes the same refusal.
  const recordless = renewed(writer, state, hostileStamp(JAVA_INT_MAX, issuer, NOW + 2));
  delete recordless["record"];
  recordless["entryId"] = entryId;
  peer.rumor(writer, stateDelta(recordless));
  assert.equal(peer.states.get(entryId)!["leaseStamp"], honest);
  assert.deepEqual([peer.stampsLogicalRefused, peer.deltasUndecodable], [2, 1]);
});

test("the replica ignores a claim stamped above LOGICAL_LIMIT and folds an honest one", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  peer.rumor(writer, stateDelta(state));
  for (const logical of HOSTILE) {
    peer.rumor(holder, wire.claimDelta(entryId, claimOn(holder, state, hostileStamp(logical, holder.peerId))));
  }
  assert.equal(peer.claims.size, 0);
  assert.deepEqual([peer.stampsLogicalRefused, peer.deltasUndecodable], [1, 1]);
  peer.rumor(holder, wire.claimDelta(entryId, claimOn(holder, state, hostileStamp(wire.LOGICAL_LIMIT, holder.peerId))));
  assert.equal(peer.claims.size, 1);
});

test("anti-entropy refuses the same stamps a rumor does", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  const issuer = String((state["record"] as Dict)["issuer"]);
  const sync = (states: Dict[], claims: Dict): Uint8Array =>
    dumps({ deltas: { "space:tasks": dumps({ states, claims }) } });
  peer.deliver(writer, "PULL_RESP", sync([reissued(writer, state, hostileStamp(JAVA_INT_MAX, issuer))],
    { [entryId]: claimOn(holder, state, hostileStamp(JAVA_INT_MAX, holder.peerId)) }));
  assert.equal(peer.states.size, 0);
  assert.equal(peer.claims.size, 0);
  assert.equal(peer.stampsLogicalRefused, 2);
  peer.deliver(writer, "PULL_RESP", sync([state], { [entryId]: claimOn(holder, state, `${NOW}:3:${holder.peerId}`) }));
  assert.equal(peer.states.size, 1);
  assert.equal(peer.claims.size, 1);
});

// ---------------------------------------------------------------------------
// Round two (HLC logical counter, 2026-11-08, Rust team report): the strict parser.

/** Counters Java's Integer.parseInt or the 0..LOGICAL_LIMIT range refuses, and Ruby's 0x10001. */
const BAD_COUNTERS = ["-1e300", "-18014398509481984", "-1", "0.5", "65535.5", "NaN", "", "+1", "1e3",
  "0x10001", " 1", "65537"];

/**
 * How many of `stamps` do not decode at all; the rest decode with a counter above LOGICAL_LIMIT, so a
 * receiver verifies them and counts their refusal (HLC round four, 2026-11-08, D5).
 */
function undecodable(stamps: string[]): number {
  return stamps.filter((stamp) => wire.decodeHlc(stamp) === null).length;
}

/** Every malformed stamp the round-two report names, for `node` near `physical`. */
function malformedStamps(node: string, physical = NOW): string[] {
  return [
    ...BAD_COUNTERS.map((logical) => `${physical}:${logical}:${node}`),
    `${physical}:${node}`, // the counter missing
    `${physical}`, // the counter and the node missing
    `${physical}:0:`, // the node empty
    `${physical}:0:${node}:extra`, // Java refuses a colon in the node
    `${physical}.5:0:${node}`, // a fractional physical
    `-${physical}:0:${node}`, // a negative physical
    `1.8e12:0:${node}`, // an exponent physical
    `:0:${node}`, // the physical empty
  ];
}

test("parseHlc accepts the canonical form and nothing looser", () => {
  assert.deepEqual(wire.parseHlc(`${NOW}:7:node-a`), { physical: BigInt(NOW), logical: 7, node: "node-a" });
  assert.deepEqual(wire.parseHlc(`0:${wire.LOGICAL_LIMIT}:n`), { physical: 0n, logical: wire.LOGICAL_LIMIT, node: "n" });
  for (const stamp of malformedStamps("node-a")) {
    assert.equal(wire.parseHlc(stamp), null, stamp);
  }
  for (const notText of [undefined, null, 42, NOW, {}, new Uint8Array(3)]) {
    assert.equal(wire.parseHlc(notText), null, String(notText));
  }
  assert.equal(wire.parseHlc(`${"0".repeat(64)}1:0:n`), null, "a leading zero is never canonical, however long the run");
});

test("the frame filter refuses and counts every malformed stamp and admits none as a replay", () => {
  const filter = new wire.FrameFilter();
  const stamps = malformedStamps("sender");
  for (const stamp of stamps) {
    assert.equal(filter.admit({ from: "sender", stamp }, NOW), false, stamp);
  }
  assert.deepEqual([filter.framesUndecodable, filter.framesLogicalRefused], [undecodable(stamps), stamps.length - undecodable(stamps)]);
  assert.deepEqual([filter.stale, filter.framesFarFuture, filter.replayed], [0, 0, 0]);
  assert.equal(filter.admit({ from: "sender", stamp: `${NOW}:0:sender` }, NOW), true);
  assert.equal(filter.admit({ from: "sender", stamp: `${NOW}:0:sender` }, NOW), false);
  assert.equal(filter.replayed, 1);
});

test("a peer answers no frame with a malformed stamp, and its clock never takes one", () => {
  const peer = new CapturingPeer();
  const other = Identity.generate();
  const stamps = malformedStamps(other.peerId);
  for (const stamp of stamps) {
    peer.deliver(other, "PING", wire.pingBody(1), stamp);
  }
  assert.deepEqual(peer.sent, []);
  // HLC round four, 2026-11-08: as in Java, a stamp that does not decode makes its frame malformed.
  assert.deepEqual([peer.malformedFrames, peer.frames.framesLogicalRefused], [undecodable(stamps), stamps.length - undecodable(stamps)]);
  assert.equal(peer.frames.framesUndecodable, 0, "the decoder drops the frame before the filter");
  const node = peer.identity.peerId;
  assert.equal(wire.hlcNow(node, NOW), `${NOW}:0:${node}`);
  assert.equal(wire.hlcNow(node, NOW), `${NOW}:1:${node}`, "the clock still counts by one");
});

test("hlcObserve ignores every malformed stamp, so -1e300 cannot freeze the clock", () => {
  for (const [index, stamp] of malformedStamps("evil").entries()) {
    const node = `hlc-observe-${index}`;
    wire.hlcObserve(node, stamp, NOW);
    assert.equal(wire.hlcNow(node, NOW), `${NOW}:0:${node}`, stamp);
    assert.equal(wire.hlcNow(node, NOW), `${NOW}:1:${node}`, stamp);
  }
  // The frozen-clock case: a later physical than the wall with a counter that adding one never moves.
  const node = "hlc-observe-frozen";
  wire.hlcObserve(node, `${NOW + 1_000}:-1e300:evil`, NOW);
  const first = wire.hlcNow(node, NOW);
  assert.notEqual(wire.hlcNow(node, NOW), first);
});

test("the clock clamps a merged remote physical one millisecond inside the drift cap, so a carry lands on the cap", () => {
  const cap = NOW + wire.MAX_HLC_SKEW_MILLIS;
  const node = "hlc-drift-carry";
  wire.hlcObserve(node, `${cap}:${wire.LOGICAL_LIMIT}:honest`, NOW);
  const carried = wire.hlcNow(node, NOW);
  assert.equal(carried, `${cap}:0:${node}`, "the carry lands at wall + MAX_DRIFT, never past it");
  // ASF-020 is strict greater-than wall + MAX_DRIFT: a receiver on the same wall admits the carried stamp.
  const receiver = new wire.FrameFilter();
  assert.equal(receiver.admit({ from: node, stamp: carried }, NOW), true);
  assert.equal(receiver.framesFarFuture, 0);
  assert.equal(receiver.admit({ from: node, stamp: `${cap + 1}:0:${node}` }, NOW), false);
  assert.deepEqual([receiver.framesFarFutureSkewed, receiver.framesFarFuture], [1, 0], "one millisecond past the cap is inside the margin");
  // A physical beyond the cap merges clamped to cap - 1, keeping its counter.
  const far = "hlc-drift-far";
  wire.hlcObserve(far, `${cap + 60_000}:5:remote`, NOW);
  assert.equal(wire.hlcNow(far, NOW), `${cap - 1}:6:${far}`);
});

test("the replica refuses and counts a record issued with a malformed stamp", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const state = writtenState(writer);
  const issuer = String((state["record"] as Dict)["issuer"]);
  const stamps = malformedStamps(issuer);
  for (const stamp of stamps) {
    peer.rumor(writer, stateDelta(reissued(writer, state, stamp)));
  }
  assert.equal(peer.states.size, 0);
  // HLC round four, 2026-11-08: Java's decoder refuses each such delta, so it counts as undecodable.
  assert.deepEqual([peer.deltasUndecodable, peer.stampsLogicalRefused], [undecodable(stamps), stamps.length - undecodable(stamps)]);
  peer.rumor(writer, stateDelta(state));
  assert.equal(peer.states.size, 1);
});

test("a lease stamp that is malformed or missing never reaches the lease join", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  const issuer = String((state["record"] as Dict)["issuer"]);
  peer.rumor(writer, stateDelta(state));
  const stamps = malformedStamps(issuer, NOW + 1);
  for (const stamp of stamps) {
    peer.rumor(writer, stateDelta(renewed(writer, state, stamp)));
  }
  // HLC round six, 2026-11-08 (P1): a state whose lease stamp is absent is undecodable, since
  // EntryStateDto writes a null lease stamp as null, and it never reaches the lease join.
  const missing = renewed(writer, state, "");
  delete missing["leaseStamp"];
  peer.rumor(writer, stateDelta(wire.signState(missing, writer, null, NOW)));
  assert.equal(peer.states.get(entryId)!["leaseStamp"], state["leaseStamp"], "the lease kept its stamp");
  assert.deepEqual([peer.deltasUndecodable, peer.stampsLogicalRefused],
    [undecodable(stamps) + 1, stamps.length - undecodable(stamps)]);
  const honest = `${NOW + 1}:0:${issuer}`;
  peer.rumor(writer, stateDelta(renewed(writer, state, honest)));
  assert.equal(peer.states.get(entryId)!["leaseStamp"], honest);
});

test("the replica refuses and counts a claim with a malformed stamp and still folds the honest claim after it", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  peer.rumor(writer, stateDelta(state));
  const first = `${NOW}:1:${holder.peerId}`;
  peer.rumor(holder, wire.claimDelta(entryId, claimOn(holder, state, first)));
  assert.equal((peer.claims.get(entryId)!["claim"] as Dict)["stamp"], first);
  const stamps = malformedStamps(holder.peerId);
  for (const stamp of stamps) {
    peer.rumor(holder, wire.claimDelta(entryId, claimOn(holder, state, stamp)));
  }
  assert.deepEqual([peer.deltasUndecodable, peer.stampsLogicalRefused], [undecodable(stamps), stamps.length - undecodable(stamps)]);
  assert.equal((peer.claims.get(entryId)!["claim"] as Dict)["stamp"], first, "no malformed claim won the lattice");
  // Ruby's wedge: an honest claim after the refused ones still merges into the entry.
  const earlier = `${NOW}:0:${holder.peerId}`;
  peer.rumor(holder, wire.claimDelta(entryId, claimOn(holder, state, earlier)));
  assert.equal((peer.claims.get(entryId)!["claim"] as Dict)["stamp"], earlier);
});

test("anti-entropy, a snapshot and a committed claim refuse malformed stamps as a rumor does", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  const issuer = String((state["record"] as Dict)["issuer"]);
  const sync = (states: Dict[], claims: Dict): Uint8Array =>
    dumps({ deltas: { "space:tasks": dumps({ states, claims }) } });
  // HLC round four, 2026-11-08: as in Java, one stamp that does not decode makes the whole sync
  // delta undecodable, the honest state beside it included; anti-entropy offers that state again.
  peer.deliver(writer, "PULL_RESP", sync([state, reissued(writer, state, `${NOW}:-1e300:${issuer}`)],
    { [entryId]: claimOn(holder, state, `${NOW}:0.5:${holder.peerId}`) }));
  assert.deepEqual([peer.states.size, peer.claims.size, peer.deltasUndecodable, peer.stampsLogicalRefused], [0, 0, 1, 0]);
  // A snapshot's states and claims are signed carriers too: each that does not decode counts.
  peer.restoreSnapshot({ group: GROUP, states: [reissued(writer, state, `${NOW}:NaN:${issuer}`)],
    claims: { [entryId]: claimOn(holder, state, `${NOW}::${holder.peerId}`) } });
  assert.deepEqual([peer.states.size, peer.claims.size, peer.deltasUndecodable, peer.stampsLogicalRefused], [0, 0, 3, 0]);
  peer.rumor(writer, stateDelta(state));
  // A committed claim whose stamp does not decode is dropped by the log host, which counts it there.
  assert.equal(peer.applyCommittedClaim("tasks", entryId, claimOn(holder, state, `-18014398509481984:0:${holder.peerId}`)), false);
  assert.deepEqual([peer.claims.size, peer.deltasUndecodable, peer.stampsLogicalRefused], [0, 3, 0]);
  assert.equal(peer.applyCommittedClaim("tasks", entryId, claimOn(holder, state, `${NOW}:2:${holder.peerId}`)), true);
});

test("compareClaims refuses an unparsed stamp, and compareHlc orders malformed stamps before every stamp", () => {
  const claim = (stamp: string): Dict => wire.takeClaim("e", "s", 1, stamp, "peer/a", 0.0, NOW + 1_000);
  const honest = claim(`${NOW}:0:a`);
  for (const stamp of malformedStamps("a")) {
    assert.throws(() => wire.compareClaims(honest, claim(stamp)), /HLC stamp/, stamp);
    assert.throws(() => wire.mergeClaims({ claim: claim(stamp) }, { claim: honest }), /HLC stamp/, stamp);
  }
  // compareHlc orders as Java's HlcTimestamp.compareTo: a counter above the limit still parses and orders.
  for (const stamp of malformedStamps("a").filter((s) => wire.decodeHlc(s) === null)) {
    assert.ok(wire.compareHlc(stamp, "0:0:a") < 0, stamp);
    assert.ok(wire.compareHlc("0:0:a", stamp) > 0, stamp);
    assert.equal(wire.compareHlc(stamp, stamp), 0, stamp);
  }
  assert.ok(wire.compareClaims(honest, claim(`${NOW}:1:a`)) < 0);
  assert.throws(() => wire.hlcPhysical(`${NOW}:-1:a`), /HLC stamp/);
});

// ---------------------------------------------------------------------------
// Round three (HLC canonical stamps, 2026-11-08): one canonical grammar, so the bytes a signer
// signed always equal the stamp's re-encoding; the far-future margin; Java's PRef head rule;
// refusals counted after verification, once per distinct state or claim; SPEC §9's filter order.

/** Spellings the canonical grammar refuses that a lenient reader would take for an honest stamp. */
const NON_CANONICAL = [
  "007:0:n", "07:1:n", "00:0:n", "7:00:n", "7:01:n", "0:065536:n", `0${NOW}:0:n`,
  "9223372036854775808:0:n", "99999999999999999999:0:n", // past a signed 64-bit integer
  "١:0:n", "１:0:n", "1:١:n", // an Arabic-Indic and a fullwidth digit one
  "1:0:a\u0000b", "1:0:\u001f", "1:0:a\u007f", "1:0:a\nb", // a control character in the node
  " 1:0:n", "1 :0:n", "1:0 :n",
];

test("parseHlc and decodeHlc refuse every non-canonical spelling, so no stamp has two spellings", () => {
  for (const stamp of NON_CANONICAL) {
    assert.equal(wire.parseHlc(stamp), null, JSON.stringify(stamp));
    assert.equal(wire.decodeHlc(stamp), null, JSON.stringify(stamp));
  }
  assert.deepEqual(wire.parseHlc(`9223372036854775807:${wire.LOGICAL_LIMIT}:n`),
    { physical: 9_223_372_036_854_775_807n, logical: wire.LOGICAL_LIMIT, node: "n" });
  assert.equal(wire.parseHlc("1:0:é b")?.node, "é b", "a node may hold any character but a colon or a control");
  assert.equal(wire.parseHlc(utf8("1:0:n")), null, "a byte string is no stamp");
  // decodeHlc reads as Java's HlcTimestamp.parse: a counter up to Integer.MAX_VALUE parses, and
  // parseHlc, the acceptable stamp, refuses it above LOGICAL_LIMIT.
  assert.equal(wire.decodeHlc(`1:${JAVA_INT_MAX}:n`)?.logical, JAVA_INT_MAX);
  assert.equal(wire.decodeHlc(`1:${JAVA_INT_MAX + 1}:n`), null);
  assert.equal(wire.parseHlc(`1:${wire.LOGICAL_LIMIT + 1}:n`), null);
});

test("physical parts past 2^53 order exactly, up to 2^63 - 1", () => {
  const above = "9007199254740993:0:n", below = "9007199254740992:0:n";
  assert.ok(wire.compareHlc(above, below) > 0);
  assert.ok(wire.compareHlc(below, above) < 0);
  assert.ok(wire.compareHlc("9223372036854775807:0:n", "9223372036854775806:0:n") > 0);
  const claim = (stamp: string): Dict => wire.takeClaim("e", "s", 1, stamp, "peer/a", 0.0, NOW + 1_000);
  assert.ok(wire.compareClaims(claim(below), claim(above)) < 0, "the lower stamp wins the lattice");
  // Java's Long.hashCode of 2^53 + 1, which a double rounds to 2^53, keys the digest's state hash.
  assert.equal(hlcHash(above), 2_097_153 * 961 + "n".charCodeAt(0));
  const node = "hlc-physical-max";
  wire.hlcObserve(node, "9223372036854775807:0:remote", NOW);
  assert.equal(wire.hlcNow(node, NOW), `${NOW + wire.MAX_HLC_SKEW_MILLIS - 1}:1:${node}`, "the clamp holds");
  const filter = new wire.FrameFilter();
  assert.equal(filter.admit({ from: "s", stamp: "9223372036854775807:0:s" }, NOW), false);
  assert.deepEqual([filter.framesFarFuture, filter.framesLogicalRefused], [1, 0]);
});

test("a claim signed over a non-canonical stamp never displaces an honest claim", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  const issuer = String((state["record"] as Dict)["issuer"]);
  peer.rumor(writer, stateDelta(state));
  const honest = `${NOW}:1:${holder.peerId}`;
  peer.rumor(holder, wire.claimDelta(entryId, claimOn(holder, state, honest)));
  // Read leniently as NOW:0, it sorts first; Java re-encodes it and can never verify the signature.
  peer.rumor(holder, wire.claimDelta(entryId, claimOn(holder, state, `0${NOW}:0:${holder.peerId}`)));
  assert.equal((peer.claims.get(entryId)!["claim"] as Dict)["stamp"], honest);
  peer.rumor(writer, stateDelta(reissued(writer, state, `0${NOW}:0:${issuer}`)));
  assert.deepEqual([peer.deltasUndecodable, peer.stampsLogicalRefused], [2, 0]);
});

test("the frame filter judges in SPEC §9's order: parse, stale, replay, far-future, acceptable", () => {
  const filter = new wire.FrameFilter();
  const counts = (): number[] => [filter.framesUndecodable + filter.framesLogicalRefused, filter.stale,
    filter.replayed, filter.framesFarFutureSkewed, filter.framesFarFuture];
  const old = NOW - wire.MAX_FRAME_AGE_MILLIS - 1;
  const far = NOW + wire.MAX_HLC_SKEW_MILLIS + 60_000;
  const over = wire.LOGICAL_LIMIT + 1;
  assert.equal(filter.admit({ from: "s", stamp: `${old}:-1:s` }, NOW), false);
  assert.deepEqual(counts(), [1, 0, 0, 0, 0], "a stamp that does not parse meets no time check");
  assert.equal(filter.admit({ from: "s", stamp: `${old}:${over}:s` }, NOW), false);
  assert.deepEqual(counts(), [1, 1, 0, 0, 0], "stale before the acceptable check");
  assert.equal(filter.admit({ from: "s", stamp: `${NOW}:${over}:s` }, NOW), false);
  assert.deepEqual(counts(), [2, 1, 0, 0, 0], "a fresh frame above the limit is refused last");
  assert.equal(filter.admit({ from: "s", stamp: `${NOW}:${over}:s` }, NOW), false);
  assert.deepEqual(counts(), [2, 1, 1, 0, 0], "its replay is a replay");
  assert.equal(filter.admit({ from: "s", stamp: `${far}:${over}:s` }, NOW), false);
  assert.deepEqual(counts(), [2, 1, 1, 0, 1], "far-future before the acceptable check");
  assert.equal(filter.admit({ from: "s", stamp: `${far}:${over}:s` }, NOW), false);
  assert.deepEqual(counts(), [2, 1, 2, 0, 1], "the replay set holds a far-future frame too");
});

test("a frame inside the far-future margin is dropped into its own count, and one past it is far-future", () => {
  assert.equal(wire.FAR_FUTURE_MARGIN_MILLIS, 5_000);
  const cap = NOW + wire.MAX_HLC_SKEW_MILLIS;
  const filter = new wire.FrameFilter();
  assert.equal(filter.admit({ from: "s", stamp: `${cap + wire.FAR_FUTURE_MARGIN_MILLIS}:0:s` }, NOW), false);
  assert.deepEqual([filter.framesFarFutureSkewed, filter.framesFarFuture], [1, 0]);
  assert.equal(filter.admit({ from: "s", stamp: `${cap + wire.FAR_FUTURE_MARGIN_MILLIS + 1}:0:s` }, NOW), false);
  assert.deepEqual([filter.framesFarFutureSkewed, filter.framesFarFuture], [1, 1]);
});

test("an honest peer a hostile member dragged to the ceiling only loses frames at a receiver whose wall trails", () => {
  const sender = "hlc-dragged-honest";
  wire.hlcObserve(sender, `${NOW + wire.MAX_HLC_SKEW_MILLIS}:${wire.LOGICAL_LIMIT}:evil`, NOW);
  const stamps = [wire.hlcNow(sender, NOW), wire.hlcNow(sender, NOW), wire.hlcNow(sender, NOW)];
  assert.equal(stamps[0], `${NOW + wire.MAX_HLC_SKEW_MILLIS}:0:${sender}`, "the carry lands on the ceiling");
  const receiver = new wire.FrameFilter();
  for (const stamp of stamps) {
    assert.equal(receiver.admit({ from: sender, stamp }, NOW - 3_000), false, stamp);
  }
  assert.deepEqual([receiver.framesFarFutureSkewed, receiver.framesFarFuture], [stamps.length, 0]);
});

/** A PRef head read from an entry issued at `NOW:0:peer` by `peer/a` with the given reserved attrs. */
function headWith(refs: Refs, attrs: Dict, entryId: string): Head | null {
  const state = { spaceId: "s", name: "doc", kind: { name: "map" }, known: new Map(), ignoredEntries: new Set() };
  const payload = dumps(pref({ name: "doc", kind: "map", root: cids.of(utf8(entryId), 0x55),
    seq: 1, size: 1, attrs: attrs as Record<string, string> }));
  const record = { spaceId: "s", type: PREF_TYPE, payload, issued: `${NOW}:0:peer`, issuer: "peer/a",
    entryId, lease: { expiresAtMillis: NOW + 60_000 } };
  return (refs as unknown as { toHead(state: unknown, dto: Dict): Head | null }).toHead(state, { record });
}

test("a PRef head takes an acceptable pdt.issued with its issuer, and falls back to the entry's own pair together", () => {
  const peer = new CapturingPeer();
  const refs = new Refs(peer, NodeStore.inMemory(), null);
  const limit = headWith(refs, { [ISSUED_ATTR]: `${NOW + 5}:${wire.LOGICAL_LIMIT}:peer`, [ISSUER_ATTR]: "peer/b" }, "e-limit")!;
  assert.deepEqual([limit.issued, limit.issuer], [`${NOW + 5}:${wire.LOGICAL_LIMIT}:peer`, "peer/b"]);
  // HLC round four, 2026-11-08 (D2), Java's Refs rule: a pdt.issued that is not canonical or carries a
  // counter above the limit, or a pdt.issuer that is no agent id, leaves the entry's own stamp AND
  // issuer, together, and nothing is refused or counted for it.
  const fallBack: Dict[] = [
    { [ISSUED_ATTR]: `${NOW + 5}:${wire.LOGICAL_LIMIT + 1}:peer`, [ISSUER_ATTR]: "peer/b" },
    { [ISSUED_ATTR]: `${NOW + 5}:70000:peer`, [ISSUER_ATTR]: "peer/b" },
    ...["-1e300", "007:0:peer", `${NOW}:${JAVA_INT_MAX + 1}:peer`, `${NOW}:0:`]
      .map((malformed) => ({ [ISSUED_ATTR]: malformed, [ISSUER_ATTR]: "peer/b" })),
    ...["/b", "peer/", "peer", "", "peer/b/c"]
      .map((issuer) => ({ [ISSUED_ATTR]: `${NOW + 8}:0:peer`, [ISSUER_ATTR]: issuer })),
  ];
  for (const [index, attrs] of fallBack.entries()) {
    const head = headWith(refs, attrs, `e-fallback-${index}`)!;
    assert.deepEqual([head.issued, head.issuer], [`${NOW}:0:peer`, "peer/a"], JSON.stringify(attrs));
  }
  // As Java's Refs: an acceptable stamp without an issuer attribute moves the order alone.
  const alone = headWith(refs, { [ISSUED_ATTR]: `${NOW + 7}:0:peer` }, "e-alone")!;
  assert.deepEqual([alone.issued, alone.issuer], [`${NOW + 7}:0:peer`, "peer/a"]);
  assert.ok(mergeOrder(alone, limit) > 0);
  assert.deepEqual([peer.stampsLogicalRefused, peer.deltasUndecodable], [0, 0], "advisory payload counts nothing");
});

test("the replica counts a refused state once per distinct state, and only after its signatures verify", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const state = writtenState(writer);
  const issuer = String((state["record"] as Dict)["issuer"]);
  const refused = reissued(writer, state, `${NOW}:${wire.LOGICAL_LIMIT + 1}:${issuer}`);
  peer.rumor(writer, stateDelta(refused));
  peer.rumor(writer, stateDelta(refused));
  peer.deliver(writer, "PULL_RESP", dumps({ deltas: { "space:tasks": dumps({ states: [refused], claims: {} }) } }));
  assert.equal(peer.stampsLogicalRefused, 1, "one distinct state, offered three times");
  peer.rumor(writer, stateDelta({ ...refused, stateSig: new Uint8Array(64) }));
  assert.equal(peer.stampsLogicalRefused, 1, "a forged state names no signer and counts nothing");
  peer.rumor(writer, stateDelta(reissued(writer, state, `${NOW}:${wire.LOGICAL_LIMIT + 2}:${issuer}`)));
  assert.equal(peer.stampsLogicalRefused, 2);
  assert.equal(peer.states.size, 0);
});

test("the replica counts a refused claim once per distinct claim, and only after its proof verifies", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  peer.rumor(writer, stateDelta(state));
  const refused = claimOn(holder, state, `${NOW}:${wire.LOGICAL_LIMIT + 1}:${holder.peerId}`);
  peer.rumor(holder, wire.claimDelta(entryId, refused));
  peer.rumor(holder, wire.claimDelta(entryId, refused));
  assert.equal(peer.applyCommittedClaim("tasks", entryId, refused), false);
  assert.equal(peer.stampsLogicalRefused, 1, "one distinct claim, offered three times");
  peer.rumor(holder, wire.claimDelta(entryId, { ...refused, signature: new Uint8Array(64) }));
  assert.equal(peer.stampsLogicalRefused, 1, "a forged claim names no signer and counts nothing");
  assert.equal(peer.claims.size, 0);
});

test("a recordless renewal waits for its record and is refused, counted once, when the record arrives", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  const issuer = String((state["record"] as Dict)["issuer"]);
  const recordless = renewed(writer, state, `${NOW + 1}:${wire.LOGICAL_LIMIT + 1}:${issuer}`);
  delete recordless["record"];
  recordless["entryId"] = entryId;
  peer.rumor(writer, stateDelta(recordless));
  assert.equal(peer.stampsLogicalRefused, 0, "nothing verifies it before its record arrives");
  peer.rumor(writer, stateDelta(state));
  assert.equal(peer.states.get(entryId)!["leaseStamp"], state["leaseStamp"]);
  assert.equal(peer.stampsLogicalRefused, 1);
});

// ---------------------------------------------------------------------------
// HLC round four, 2026-11-08: the binding decisions D1 to D6, so Java, Python, TypeScript and Ruby
// judge signedAt, pdt.issued, a stamp's CBOR item, far-future records and their counts alike.

/** A minimal CBOR text-string head (major 3) for `length` bytes. */
function textHead(length: number): Uint8Array {
  return length < 24 ? Uint8Array.of(0x60 | length) : Uint8Array.of(0x78, length);
}

function textItem(bytes: Uint8Array): Uint8Array {
  return concat(textHead(bytes.length), bytes);
}

/**
 * Items in a stamp's place that are no canonical CBOR text for `stamp` (D3): its first digit as an
 * overlong two- and three-byte sequence, a UTF-16 surrogate encoded in UTF-8, the text in two
 * indefinite-length chunks, the text under a tag, a leading byte order mark, and items of other types.
 */
function nonCanonicalItems(stamp: string): Map<string, Uint8Array> {
  const bytes = utf8(stamp);
  const first = bytes[0];
  return new Map([
    ["overlong two-byte", textItem(concat(Uint8Array.of(0xc0 | (first >> 6), 0x80 | (first & 0x3f)), bytes.subarray(1)))],
    ["overlong three-byte", textItem(concat(Uint8Array.of(0xe0, 0x80 | (first >> 6), 0x80 | (first & 0x3f)), bytes.subarray(1)))],
    ["surrogate in UTF-8", textItem(concat(bytes, Uint8Array.of(0xed, 0xa0, 0x80)))],
    ["indefinite-length", concat(Uint8Array.of(0x7f), textItem(bytes.subarray(0, 4)), textItem(bytes.subarray(4)), Uint8Array.of(0xff))],
    ["tag 0", concat(Uint8Array.of(0xc0), textItem(bytes))],
    ["tag 32", concat(Uint8Array.of(0xd8, 0x20), textItem(bytes))],
    ["byte order mark", textItem(concat(Uint8Array.of(0xef, 0xbb, 0xbf), bytes))],
    ["byte string", dumps(bytes)],
    ["number", dumps(42)],
    ["map", dumps({ stamp })],
  ]);
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

function digestLinesOf(digest: Uint8Array): string[] {
  return new TextDecoder().decode(digest).split("\n");
}

function syncBody(states: Dict[], claims: Dict = {}): Uint8Array {
  return dumps({ deltas: { "space:tasks": dumps({ states, claims }) } });
}

test("D3: the CBOR decoder refuses overlong UTF-8, surrogates, tagged text and indefinite-length byte strings", () => {
  const stamp = `${NOW}:0:node`;
  const items = nonCanonicalItems(stamp);
  for (const name of ["overlong two-byte", "overlong three-byte", "surrogate in UTF-8", "tag 0", "tag 32"]) {
    assert.throws(() => loads(items.get(name)!), RangeError, name);
  }
  // HLC round six, 2026-11-08 (S6): indefinite-length text decodes only past 3996 UTF-16 units, so a
  // stamp in one chunk is no document at all.
  assert.throws(() => loads(items.get("indefinite-length")!), RangeError, "a short text in one indefinite chunk");
  assert.throws(() => loads(Uint8Array.of(0x5f, 0x41, 0x01, 0xff)), RangeError, "an indefinite-length byte string");
  // A byte order mark is text like any other: the decoder keeps it, and the grammar refuses it.
  assert.equal(loads(items.get("byte order mark")!), `﻿${stamp}`);
  assert.equal(wire.decodeHlc(loads(items.get("byte order mark")!)), null);
  assert.equal(loads(textItem(utf8(stamp))), stamp);
  assert.equal(loads(dumps("é€😀")), "é€😀", "valid UTF-8 of every width decodes");
  assert.throws(() => loads(Uint8Array.of(0xc1, 0x05)), /tag/, "a tag over a number (HLC round six, 2026-11-08, S9)");
});

test("D3: a frame whose envelope stamp is no canonical CBOR text is malformed, though its signature covers the canonical bytes", () => {
  const peer = new CapturingPeer();
  const sender = Identity.generate();
  const stamp = `${NOW}:0:${sender.peerId}`;
  const frame = wire.encodeFrame(wire.envelope(GROUP, "PING", sender.peerId, stamp, wire.pingBody(1),
    peer.identity.peerId), sender);
  const items = nonCanonicalItems(stamp);
  for (const [name, item] of items) {
    const hostile = respell(frame, stamp, item);
    assert.equal(wire.decodeFrame(hostile), null, name);
    peer.deliverFrame(hostile);
  }
  assert.deepEqual(peer.sent, []);
  assert.equal(peer.malformedFrames, items.size);
  peer.deliverFrame(frame);
  assert.deepEqual(peer.sent, ["ACK"], "the canonical spelling of the same frame is answered");
});

test("D3: a space delta holding a stamp that is no canonical CBOR text is undecodable and counted, by rumor and by anti-entropy", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  const record = state["record"] as Dict;
  const entryId = String(record["entryId"]);
  const issued = String(record["issued"]);
  const items = nonCanonicalItems(issued);
  for (const item of items.values()) {
    peer.rumor(writer, respell(stateDelta(state), issued, item));
  }
  assert.deepEqual([peer.states.size, peer.deltasUndecodable, peer.stampsLogicalRefused], [0, items.size, 0]);
  peer.rumor(writer, stateDelta(state));
  assert.equal(peer.states.size, 1);
  const claimStamp = `${NOW}:1:${holder.peerId}`;
  const claim = claimOn(holder, state, claimStamp);
  for (const item of items.values()) {
    peer.rumor(holder, respell(wire.claimDelta(entryId, claim), claimStamp, item));
    peer.deliver(writer, "PULL_RESP", dumps({ deltas: { "space:tasks":
      respell(dumps({ claims: { [entryId]: claim }, states: [] }), claimStamp, item) } }));
  }
  assert.deepEqual([peer.claims.size, peer.deltasUndecodable, peer.stampsLogicalRefused], [0, 3 * items.size, 0]);
  peer.rumor(holder, wire.claimDelta(entryId, claim));
  assert.equal(peer.claims.size, 1);
  // Bytes that are no delta at all count the same way.
  peer.rumor(writer, Uint8Array.of(0xff));
  peer.deliver(writer, "PULL_RESP", dumps({ deltas: { "space:tasks": Uint8Array.of(0x1c) } }));
  assert.equal(peer.deltasUndecodable, 3 * items.size + 2);
});

/** An agent-signed write by `agent`, its state re-signed by the agent with `signedAt`. */
function agentSignedState(host: Identity, agent: AgentIdentity, signedAt: string): Dict {
  const { body } = wire.entryDelta("tasks", GROUP, "T#v1", dumps({ job: 2 }), host, "ignored", 60_000, agent, NOW);
  const state = (loads((loads(body) as Dict)["payload"] as Uint8Array) as Dict)["state"] as Dict;
  const record = state["record"] as Dict;
  const view = wire.stateSignView(String(record["spaceId"]), String(record["entryId"]), state["adds"] as Dict[],
    state["removes"] as Dict[], String(state["leaseStamp"]), state["leaseValue"] as Dict, false, agent.agentId, signedAt);
  return { ...state, stateSig: agent.sign(dumps(view)), signedAt };
}

test("D1: an agent-signed state whose signedAt is not acceptable is refused after it verifies, counted once and acknowledged", () => {
  const peer = new CapturingPeer();
  const host = Identity.generate();
  const agent = host.renewingSubordinate("planner", "PT24H", Identity.generate(), () => NOW);
  const refused = agentSignedState(host, agent, `${NOW}:${wire.LOGICAL_LIMIT + 1}:${agent.agentId}`);
  const entryId = String((refused["record"] as Dict)["entryId"]);
  peer.rumor(host, stateDelta(refused));
  peer.rumor(host, stateDelta(refused));
  peer.deliver(host, "PULL_RESP", syncBody([refused]));
  assert.deepEqual([peer.states.size, peer.stampsLogicalRefused], [0, 1], "one distinct state, offered three times");
  peer.rumor(host, stateDelta({ ...refused, stateSig: new Uint8Array(64) }));
  assert.equal(peer.stampsLogicalRefused, 1, "a forged state names no signer and counts nothing");
  // The digest acknowledges the refused state, so a partner that holds it stops offering it.
  const acknowledged = `a:e:${entryId}=${stateHash(refused)}`;
  assert.ok(digestLinesOf(peer.spaceDigest("tasks")).includes(acknowledged));
  const partner = new CapturingPeer();
  partner.states.set(entryId, refused);
  assert.equal(partner.spaceDeltaFor("tasks", peer.spaceDigest("tasks")).length, 0);
  // A dial-only pull carries the acknowledgement too.
  peer.pullSpace("tasks");
  const pulled = (loads(peer.bodies.at(-1)!) as Dict)["digests"] as Dict;
  assert.deepEqual(digestLinesOf(pulled["space:tasks"] as Uint8Array), [acknowledged, ""]);
  assert.equal(partner.spaceDeltaFor("tasks", pulled["space:tasks"] as Uint8Array).length, 0);
  // At exactly the limit an agent-signed state merges.
  peer.rumor(host, stateDelta(agentSignedState(host, agent, `${NOW}:${wire.LOGICAL_LIMIT}:${agent.agentId}`)));
  assert.equal(peer.states.size, 1);
  // A signedAt that does not decode makes its delta undecodable, as in Java.
  peer.rumor(host, stateDelta(agentSignedState(host, agent, `${NOW}:-1:${agent.agentId}`)));
  assert.deepEqual([peer.states.size, peer.deltasUndecodable, peer.stampsLogicalRefused], [1, 1, 1]);
});

test("D5: refusals key on signed content, and attested claims and records count once their certificates verify", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  const record = state["record"] as Dict;
  const entryId = String(record["entryId"]);
  const issuer = String(record["issuer"]);
  const over = wire.LOGICAL_LIMIT + 1;
  const refused = reissued(writer, state, `${NOW}:${over}:${issuer}`);
  peer.rumor(writer, stateDelta(refused));
  peer.rumor(writer, stateDelta({ ...refused, relayNote: "an unsigned field a relay may add" }));
  assert.equal(peer.stampsLogicalRefused, 1, "an unsigned field never makes a second refusal");
  peer.rumor(writer, stateDelta(state));
  const refusedClaim = claimOn(holder, state, `${NOW}:${over}:${holder.peerId}`);
  peer.rumor(holder, wire.claimDelta(entryId, refusedClaim));
  peer.rumor(holder, wire.claimDelta(entryId, { ...refusedClaim, relayNote: "again" }));
  assert.equal(peer.stampsLogicalRefused, 2);
  // An agent-attested claim decodes, verifies under its certificate at its stamp, then counts.
  const clerk = holder.renewingSubordinate("clerk", "PT24H", Identity.generate(), () => NOW);
  const claim = wire.takeClaim(entryId, String(record["spaceId"]), 1, `${NOW}:${over}:${clerk.agentId}`,
    clerk.agentId, 0.0, NOW + 60_000);
  const attested: Dict = { claim, holderKey: holder.publicRaw, signature: clerk.sign(dumps(claim)),
    holderCertificate: clerk.certificateCovering(NOW)! };
  peer.rumor(holder, wire.claimDelta(entryId, attested));
  peer.rumor(holder, wire.claimDelta(entryId, attested));
  assert.equal(peer.stampsLogicalRefused, 3);
  // An agent-signed record issued above the limit does the same.
  const author = writer.renewingSubordinate("author", "PT24H", Identity.generate(), () => NOW);
  const { body } = wire.entryDelta("tasks", GROUP, "T#v1", dumps({ job: 3 }), writer, "ignored", 60_000, author, NOW);
  const agentState = (loads((loads(body) as Dict)["payload"] as Uint8Array) as Dict)["state"] as Dict;
  const hostileRecord: Dict = { ...(agentState["record"] as Dict), issued: `${NOW}:${over}:${author.agentId}` };
  hostileRecord["sig"] = author.sign(dumps(wire.signViewOf(hostileRecord)));
  peer.rumor(writer, stateDelta(wire.signState({ ...agentState, record: hostileRecord }, writer, author, NOW)));
  assert.equal(peer.stampsLogicalRefused, 4);
  assert.equal(peer.claims.size, 0);
  assert.equal(peer.states.size, 1);
});

test("D4: a record issued past wall + MAX_DRIFT + the margin is deferred, uncounted and unacknowledged, and merges once the wall catches up", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const issuer = String((writtenState(writer)["record"] as Dict)["issuer"]);
  const ceiling = NOW + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_MARGIN_MILLIS;
  peer.rumor(writer, stateDelta(reissued(writer, writtenState(writer), `${ceiling}:0:${issuer}`)));
  assert.equal(peer.states.size, 1, "a record inside the margin merges");
  const ahead = reissued(writer, writtenState(writer), `${ceiling + 1}:0:${issuer}`);
  // Its lease runs a minute past the wall it merges at: the replica refuses at the door a state whose
  // lease lapsed past its grace (SPEC §7.3, HLC round five, 2026-11-08).
  const deferred = reissued(writer, writtenState(writer, NOW + wire.FAR_FUTURE_HOSTILE_MILLIS),
    `${ceiling + wire.FAR_FUTURE_HOSTILE_MILLIS}:0:${issuer}`);
  peer.rumor(writer, stateDelta(ahead));
  peer.deliver(writer, "PULL_RESP", syncBody([ahead, deferred]));
  assert.equal(peer.states.size, 1);
  assert.deepEqual([peer.stampsLogicalRefused, peer.stampsFarFutureRefused, peer.deltasUndecodable], [0, 0, 0]);
  assert.equal(peer.stampsFarFutureDeferred, 2, "two distinct states deferred, one of them offered twice");
  assert.ok(!digestLinesOf(peer.spaceDigest("tasks")).some((line) => line.startsWith("a:")), "nothing acknowledged");
  peer.millis = NOW + 1;
  peer.deliver(writer, "PULL_RESP", syncBody([ahead, deferred]));
  assert.equal(peer.states.size, 2, "anti-entropy offers it again and it merges");
  peer.millis = NOW + wire.FAR_FUTURE_HOSTILE_MILLIS;
  peer.deliver(writer, "PULL_RESP", syncBody([deferred]));
  assert.equal(peer.states.size, 3);
});

test("D4: a lease stamp past the margin is deferred, and the renewal merges once the wall catches up", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  const issuer = String((state["record"] as Dict)["issuer"]);
  peer.rumor(writer, stateDelta(state));
  const later = `${NOW + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_MARGIN_MILLIS + 1}:0:${issuer}`;
  const renewal = renewed(writer, state, later);
  peer.rumor(writer, stateDelta(renewal));
  assert.equal(peer.states.get(entryId)!["leaseStamp"], state["leaseStamp"], "the lease waits");
  assert.deepEqual([peer.stampsLogicalRefused, peer.stampsFarFutureRefused, peer.stampsFarFutureDeferred], [0, 0, 1]);
  peer.millis = NOW + 1;
  peer.deliver(writer, "PULL_RESP", syncBody([renewal]));
  assert.equal(peer.states.get(entryId)!["leaseStamp"], later);
});

test("D4: a record or lease more than an hour past the margin is refused as hostile, counted once and acknowledged", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  const issuer = String((state["record"] as Dict)["issuer"]);
  const hostile = `${NOW + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_MARGIN_MILLIS + wire.FAR_FUTURE_HOSTILE_MILLIS + 1}:0:${issuer}`;
  const refused = reissued(writer, state, hostile);
  peer.rumor(writer, stateDelta(refused));
  peer.deliver(writer, "PULL_RESP", syncBody([refused]));
  assert.deepEqual([peer.states.size, peer.stampsFarFutureRefused, peer.stampsLogicalRefused], [0, 1, 0]);
  assert.ok(digestLinesOf(peer.spaceDigest("tasks")).includes(`a:e:${entryId}=${stateHash(refused)}`));
  peer.rumor(writer, stateDelta(state));
  peer.rumor(writer, stateDelta(renewed(writer, state, hostile)));
  assert.equal(peer.states.get(entryId)!["leaseStamp"], state["leaseStamp"]);
  assert.equal(peer.stampsFarFutureRefused, 2);
});

test("D4: a claim past the margin is deferred and merges later, an hour past it is hostile, and an honest taker dragged to its ceiling merges", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  peer.rumor(writer, stateDelta(state));
  const ceiling = NOW + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_MARGIN_MILLIS;
  const hostile = claimOn(holder, state, `${ceiling + wire.FAR_FUTURE_HOSTILE_MILLIS + 1}:0:${holder.peerId}`);
  peer.rumor(holder, wire.claimDelta(entryId, hostile));
  peer.rumor(holder, wire.claimDelta(entryId, hostile));
  assert.deepEqual([peer.claims.size, peer.stampsFarFutureRefused], [0, 1], "hostile, counted once");
  const ahead = claimOn(holder, state, `${ceiling + 1}:0:${holder.peerId}`);
  peer.rumor(holder, wire.claimDelta(entryId, ahead));
  peer.rumor(holder, wire.claimDelta(entryId, ahead));
  assert.deepEqual([peer.claims.size, peer.stampsFarFutureRefused, peer.stampsLogicalRefused], [0, 1, 0], "deferred, no misbehaviour");
  assert.equal(peer.stampsFarFutureDeferred, 1, "one distinct claim deferred");
  peer.millis = NOW + 1;
  peer.deliver(holder, "PULL_RESP", syncBody([], { [entryId]: ahead }));
  assert.equal(peer.claims.size, 1, "merged once the wall caught up");
  // An honest taker a hostile member dragged to its own ceiling, whose wall leads this one by 3 s.
  const other = writtenState(writer);
  const otherId = String((other["record"] as Dict)["entryId"]);
  peer.rumor(writer, stateDelta(other));
  const dragged = claimOn(holder, other, `${peer.millis + 3_000 + wire.MAX_HLC_SKEW_MILLIS}:0:${holder.peerId}`);
  peer.rumor(holder, wire.claimDelta(otherId, dragged));
  assert.equal(peer.claims.size, 2, "the honest taker is neither deferred nor quarantined");
  assert.deepEqual([peer.stampsFarFutureRefused, peer.stampsFarFutureDeferred], [1, 1]);
});

test("D4: the ordered log's committed claim stays a pure function of the claim, whatever this replica's wall", () => {
  const peer = new CapturingPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  const entryId = String((state["record"] as Dict)["entryId"]);
  peer.rumor(writer, stateDelta(state));
  const far = NOW + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_MARGIN_MILLIS + wire.FAR_FUTURE_HOSTILE_MILLIS + 1;
  assert.equal(peer.applyCommittedClaim("tasks", entryId, claimOn(holder, state, `${far}:0:${holder.peerId}`)), true);
  assert.equal(peer.stampsFarFutureRefused, 0);
});

test("D6: the clock never stamps for a node outside the grammar", () => {
  for (const node of ["", "a:b", "a\u0000b", "a\nb", "a\u007f"]) {
    assert.throws(() => wire.hlcNow(node, NOW), /HLC node/, JSON.stringify(node));
    assert.throws(() => wire.hlcObserve(node, `${NOW}:0:x`, NOW), /HLC node/, JSON.stringify(node));
  }
  const writer = Identity.generate();
  // HLC round six, 2026-11-08 (R5): Identity.agent refuses the colon first, as Java's AgentId grammar does.
  assert.throws(() => wire.entryDelta("tasks", GROUP, "T#v1", null, writer, "bad:name", 60_000, null, NOW), /local name/);
  assert.equal(wire.hlcNow("hlc-node-é b", NOW), `${NOW}:0:hlc-node-é b`, "any other character is a node's own");
});
