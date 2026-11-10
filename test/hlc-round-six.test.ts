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
 * HLC round six, 2026-11-08: the owner's smaller rulings this client settles beside the wire encoding.
 * R5: Java's AgentId grammar everywhere. R7: a revoked holder's claim is acknowledged with a `c:` line,
 * under Java's acknowledgement cap. R9: lapsed tickets, TAKEN per epoch, the vote tally's own space,
 * and bulk payloads released on collection. R10: the claim map stays bounded under churn. Every carrier
 * this client builds reads strictly at a receiver.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { toHex } from "../src/bytes.js";
import { dumps, loads } from "../src/cbor.js";
import { Identity, instantIso } from "../src/identity.js";
import { JOIN_TAG, JOIN_TICKET_TYPE, KEY_TAG, KeyTickets } from "../src/join.js";
import type { OrderedLog } from "../src/capabilities/ordered.js";
import { BulkPayloads, MAX_REFUSED_ACK, Peer } from "../src/peer.js";
import { cids, Embedded, NodeFormatError, nodes } from "../src/pdt/index.js";
import * as records from "../src/records.js";
import * as revocation from "../src/revocation.js";
import { claimHash } from "../src/serving.js";
import { Space, TAKEN, Template } from "../src/space.js";
import type { SpaceEvent } from "../src/space.js";
import * as vote from "../src/vote.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const GROUP = "zTsHlcRoundSix";
const NOW = 1_800_000_000_000;
const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf-8"));
const fromHex = (text: string): Uint8Array => Uint8Array.from(Buffer.from(text, "hex"));

/** A peer on a settable clock whose sends are captured instead of written to a socket. */
class ClockPeer extends Peer {
  readonly sent: { kind: string; body: Uint8Array }[] = [];
  private counter = 0;
  private readonly clock: { millis: number };

  constructor(millis: number = NOW) {
    const clock = { millis };
    super(Identity.generate(), GROUP, () => clock.millis);
    this.clock = clock;
    this.joinSpace("tasks");
  }

  set millis(value: number) {
    this.clock.millis = value;
  }

  get millis(): number {
    return this.clock.millis;
  }

  protected send(kind: string, body: Uint8Array): void {
    this.sent.push({ kind, body });
  }

  /** A RUMOR on the space `tasks` carrying `delta`, signed by `sender`. */
  rumor(sender: Identity, delta: Uint8Array): void {
    const body = wire.rumorBody("space:tasks", `w:${this.counter}`, 6, delta);
    const env = wire.envelope(GROUP, "RUMOR", sender.peerId, `${this.millis}:${this.counter++}:${sender.peerId}`, body,
      this.identity.peerId);
    (this as unknown as { onFrame(frame: Uint8Array): void }).onFrame(wire.encodeFrame(env, sender));
  }
}

function writtenState(writer: Identity, wall = NOW, tags: Dict = {}, leaseMillis = 60_000): Dict {
  const { body } = wire.entryDelta("tasks", GROUP, "T#v1", dumps({ job: 1 }), writer, "w", leaseMillis, null, wall, tags);
  return (loads((loads(body) as Dict)["payload"] as Uint8Array) as Dict)["state"] as Dict;
}

function entryOf(state: Dict): string {
  return String((state["record"] as Dict)["entryId"]);
}

function claimOn(holder: Identity, entryId: string, spaceId: string, stamp: string, epoch = 1,
                 expiresAtMillis = NOW + 60_000): Dict {
  return wire.signedClaim(wire.takeClaim(entryId, spaceId, epoch, stamp, holder.agent("worker"), 0.0, expiresAtMillis), holder);
}

// ------------------------------------------------------------------------------------------- R5

test("R5: an agent's local name holds no '/' and no ':', at Identity.agent and on the wire", () => {
  const peer = Identity.generate();
  assert.equal(peer.agent("worker"), `${peer.peerId}/worker`);
  for (const local of ["a/b", "a:b", "", "x:"]) {
    assert.throws(() => peer.agent(local), /local name/, local);
  }
  assert.equal(records.isAgentId(`${peer.peerId}/a:b`), false);
  assert.equal(records.isAgentId(`${peer.peerId}/a/b`), false);
  assert.equal(records.isAgentId(`/a`), false);
  // A record whose issuer names a local part with a colon is undecodable, signed or not.
  const receiver = new ClockPeer();
  const state = writtenState(peer);
  const record: Dict = { ...(state["record"] as Dict), issuer: `${peer.peerId}/w:x` };
  record["sig"] = peer.sign(dumps(wire.signViewOf(record)));
  receiver.rumor(peer, dumps({ state: { ...state, record }, claimEntry: null, claim: null }));
  assert.deepEqual([receiver.states.size, receiver.deltasUndecodable], [0, 1]);
});

test("R5: a state's signer is text as Java's EntryStateDto holds it, so a signer outside the grammar fails verification uncounted", () => {
  // Java reads signer as a String and drops a state whose signer is not its party at verifyState,
  // counting nothing; the delta stays decodable, so a claim beside the state still folds.
  const receiver = new ClockPeer();
  const writer = Identity.generate();
  const state = writtenState(writer);
  receiver.rumor(writer, dumps({ state: { ...state, signer: "not an agent id" }, claimEntry: null, claim: null }));
  assert.deepEqual([receiver.states.size, receiver.deltasUndecodable], [0, 0]);
});

test("F1: what Java's record constructors refuse is undecodable here too: an inline payload past 64 KiB, a short encryption key", () => {
  // EntryRecord refuses an inline payload past INLINE_PAYLOAD_LIMIT and AgentCertificate an encryption key
  // of other than 32 bytes, so Jackson builds neither and the delta counts as undecodable at Java.
  const receiver = new ClockPeer();
  const writer = Identity.generate();
  const big = wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array(wire.INLINE_PAYLOAD_LIMIT + 1), writer, "w", 60_000,
    null, NOW);
  receiver.rumor(writer, (loads(big.body) as Dict)["payload"] as Uint8Array);
  assert.deepEqual([receiver.states.size, receiver.deltasUndecodable], [0, 1]);
  const agent = writer.renewingSubordinate("planner", "PT24H", Identity.generate(), () => NOW, new Uint8Array(31));
  const agentWrite = wire.entryDelta("tasks", GROUP, "T#v1", dumps({ job: 1 }), writer, "w", 60_000, agent, NOW);
  receiver.rumor(writer, (loads(agentWrite.body) as Dict)["payload"] as Uint8Array);
  assert.deepEqual([receiver.states.size, receiver.deltasUndecodable], [0, 2]);
  const edge = wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array(wire.INLINE_PAYLOAD_LIMIT), writer, "w", 60_000,
    null, NOW);
  receiver.rumor(writer, (loads(edge.body) as Dict)["payload"] as Uint8Array);
  assert.deepEqual([receiver.states.size, receiver.deltasUndecodable], [1, 2]);
  // EntryRecord holds exactly one of payload and payloadRef.
  const state = writtenState(writer);
  for (const both of [{ payloadRef: "zabc" }, { payload: null }] as Dict[]) {
    receiver.rumor(writer, dumps({ state: { ...state, record: { ...(state["record"] as Dict), ...both } }, claimEntry: null,
      claim: null }));
  }
  assert.deepEqual([receiver.states.size, receiver.deltasUndecodable], [1, 4]);
});

test("F1: an advertisement field Java's record requires is refused when null, and only a revocation's successor may be", () => {
  // Java's ad records refuse a null in every field they write always, with requireNonNull or by
  // writing a default the received bytes do not hold; RevocationAdvertisement.successor alone stays null.
  const id = Identity.generate();
  const card = wire.agentCard(GROUP, id, "planner", instantIso(NOW), "PT10M", "plans", ["g"], ["c"], ["p"], { b: "c" },
    { "T#v1": "tasks" });
  assert.doesNotThrow(() => records.decodeRecord(dumps(card), records.AGENT_CARD));
  for (const field of ["id", "issuer", "group", "issued", "ttl", "agent", "description", "goals", "costHints", "spaceBindings"]) {
    assert.throws(() => records.decodeRecord(dumps({ ...card, [field]: null }), records.AGENT_CARD), records.UndecodableError, field);
  }
  const group = { id: "g", issuer: id.peerId, group: GROUP, issued: instantIso(NOW), ttl: "PT10M", name: "n",
    membershipPolicy: "OPEN", defaultStrategy: "LEASE_RACE", gossip: { fanout: 3, period: "PT1S" } };
  assert.doesNotThrow(() => records.decodeRecord(dumps(group), records.GROUP_ADVERTISEMENT));
  assert.throws(() => records.decodeRecord(dumps({ ...group, name: null }), records.GROUP_ADVERTISEMENT), records.UndecodableError);
  assert.throws(() => records.decodeRecord(dumps({ ...group, gossip: { fanout: 3, period: null } }), records.GROUP_ADVERTISEMENT),
    records.UndecodableError);
  const revoked = { id: "r", issuer: id.peerId, group: GROUP, issued: instantIso(NOW), ttl: "PT720H", revoked: "zOther",
    reason: "retired", successor: null };
  assert.doesNotThrow(() => records.decodeRecord(dumps(revoked), records.REVOCATION_ADVERTISEMENT));
  assert.throws(() => records.decodeRecord(dumps({ ...revoked, reason: null }), records.REVOCATION_ADVERTISEMENT),
    records.UndecodableError);
});

test("F1: a signed claim with a null claim, key or signature decodes as Java's and fails verification alone", () => {
  // Java's SignedClaim takes a null in each of these fields, and verifyClaim then drops the claim
  // uncounted, so the state beside it in the same delta still merges.
  const receiver = new ClockPeer();
  const writer = Identity.generate();
  const state = writtenState(writer);
  const claim = claimOn(writer, entryOf(state), String((state["record"] as Dict)["spaceId"]), `${NOW}:0:${writer.peerId}`);
  for (const field of ["claim", "holderKey", "signature"]) {
    receiver.rumor(writer, dumps({ state, claimEntry: entryOf(state), claim: { ...claim, [field]: null } }));
  }
  assert.deepEqual([receiver.states.size, receiver.claims.size, receiver.deltasUndecodable], [1, 0, 0]);
});

// ------------------------------------------------------------------------------------------- R6

/** A receiver holding an entry issued at `wall` whose lease runs `leaseMillis`, and the entry's ids. */
function heldEntry(wall: number, leaseMillis = 60_000): { peer: ClockPeer; entryId: string; spaceId: string } {
  const peer = new ClockPeer();
  const writer = Identity.generate();
  const state = writtenState(writer, wall, {}, leaseMillis);
  peer.rumor(writer, dumps({ state, claimEntry: null, claim: null }));
  assert.equal(peer.states.size, 1);
  return { peer, entryId: entryOf(state), spaceId: String((state["record"] as Dict)["spaceId"]) };
}

/** The counters a dropped claim must leave alone. */
function counters(peer: Peer): number[] {
  return [peer.deltasUndecodable, peer.stampsLogicalRefused, peer.stampsFarFutureRefused, peer.stampsFarFutureDeferred];
}

test("R6: a claim whose stamp lies more than the drift ceiling before its entry's issue stamp never folds, as Java's mergeClaim", () => {
  // ReplicatedSpace.MAX_CLAIM_PREDATES_ISSUE_MILLIS is the drift ceiling: a claim answers a write, so it
  // cannot sort that far before the entry it answers.
  const holder = Identity.generate();
  const early = heldEntry(NOW);
  early.peer.rumor(holder, wire.claimDelta(early.entryId,
    claimOn(holder, early.entryId, early.spaceId, `${NOW - wire.MAX_HLC_SKEW_MILLIS - 1}:0:${holder.agent("t")}`)));
  assert.equal(early.peer.claims.size, 0, "a claim at T-600001 predates its entry");
  assert.deepEqual(counters(early.peer), [0, 0, 0, 0]);
  const edge = heldEntry(NOW);
  edge.peer.rumor(holder, wire.claimDelta(edge.entryId,
    claimOn(holder, edge.entryId, edge.spaceId, `${NOW - wire.MAX_HLC_SKEW_MILLIS}:0:${holder.agent("t")}`)));
  assert.equal(edge.peer.claims.size, 1, "a claim at T-600000 folds");
});

test("R6: a far-past claim contesting another holder's claim never folds, and one inside the settle window races it", () => {
  // Java drops a rival whose stamp lies before now - MAX_DRIFT - settleWindow (200 ms by default): LEASE_RACE
  // picks the lowest stamp, so a far-past stamp would jump the queue.
  const holder = Identity.generate();
  const rival = Identity.generate();
  const heldStamp = `${NOW - wire.MAX_HLC_SKEW_MILLIS - 50}:0:${holder.agent("t")}`;
  const holderOf = (peer: Peer, entryId: string): unknown => ((peer.claims.get(entryId)!["claim"]) as Dict)["holder"];
  for (const [lead, winner] of [[201, holder], [199, rival]] as const) {
    const { peer, entryId, spaceId } = heldEntry(NOW - 2 * wire.MAX_HLC_SKEW_MILLIS, 3_600_000 + 2 * wire.MAX_HLC_SKEW_MILLIS);
    peer.rumor(holder, wire.claimDelta(entryId, claimOn(holder, entryId, spaceId, heldStamp)));
    assert.equal(holderOf(peer, entryId), holder.agent("worker"));
    peer.rumor(rival, wire.claimDelta(entryId,
      claimOn(rival, entryId, spaceId, `${NOW - wire.MAX_HLC_SKEW_MILLIS - lead}:0:${rival.agent("t")}`)));
    assert.equal(holderOf(peer, entryId), winner.agent("worker"), `a rival at T-${wire.MAX_HLC_SKEW_MILLIS + lead}`);
    assert.deepEqual(counters(peer), [0, 0, 0, 0]);
  }
});

// --------------------------------------------------------------------------------------- ASF-025

test("ASF-025: a state whose dots name a replica other than its issuer's peer merges nothing and counts nothing (delta-13)", () => {
  // Java's ReplicatedSpace.dotsBoundToIssuer: only an entry's writer mints its dots, so a dot naming
  // another replica is fabricated provenance. delta-13 is honestly signed and decodes, and its dots name
  // U+E000 and U+1F600.
  const vectors = (JSON.parse(readFileSync(join(here, "..", "..", "test", "wire-encoding-vectors.json"), "utf-8")) as
    { vectors: { id: string; hex: string }[] }).vectors;
  const peer = new ClockPeer();
  peer.rumor(Identity.generate(), fromHex(vectors.find((v) => v.id === "delta-13")!.hex));
  assert.deepEqual([peer.states.size, peer.claims.size, peer.malformedFrames], [0, 0, 0]);
  assert.deepEqual(counters(peer), [0, 0, 0, 0]);
  // The same rule on a state this client signs: a remove naming another replica.
  const writer = Identity.generate();
  const state = writtenState(writer);
  const record = state["record"] as Dict;
  const forged: Dict = { ...state, removes: [{ replica: Identity.generate().peerId, counter: 1 }] };
  forged["stateSig"] = writer.sign(dumps(wire.stateSignView(String(record["spaceId"]), entryOf(state),
    forged["adds"] as Dict[], forged["removes"] as Dict[], wire.leaseStampOf(forged), forged["leaseValue"] as Dict,
    false, null, null)));
  peer.rumor(writer, dumps({ state: forged, claimEntry: null, claim: null }));
  assert.equal(peer.states.size, 0);
  assert.deepEqual(counters(peer), [0, 0, 0, 0]);
  peer.rumor(writer, dumps({ state, claimEntry: null, claim: null }));
  assert.equal(peer.states.size, 1, "the writer's own dots merge");
});

// ------------------------------------------------------------------------------------ JD-4, 2.4

/** golden pdt_node_embedded with its value item 1.5f (fa3fc00000) replaced by `item`. */
function nodeHolding(item: string): Uint8Array {
  const golden = GOLDEN["pdt_node_embedded"]!;
  assert.ok(golden.includes("6166fa3fc00000"));
  const replaced = golden.replace("6166fa3fc00000", `6166${item}`);
  // The embedded list's length head is unchanged: one item replaces one item.
  return fromHex(replaced);
}

test("2.4: a node whose embedded item breaks the wire encoding does not decode, as Java's NodeCodec refuses it (JD-4)", () => {
  const refused = [
    "c24101", // tag 2 inside a long (S9)
    "c482211896", // tag 4 unnormalized 1.50 (S9)
    "c4823a7fffffff01", // tag 4 exponent -2^31 (S9)
    "c06161", // tag 0 over text
    "c11a5f000000", // tag 1 over an int
    "d9d9f701", // tag 55799 over an int
    "d82a420001", // tag 42 over bytes 00 01, no CID (PD-N-05 allows only a bare link)
    "7f6161ff", // indefinite text of one chunk (S6)
    "a1616101", // definite map (S8)
    "f93e00", // half float (S10)
    "fbfff8000000000000", // a NaN Java does not write (S10)
    "1801", // an integer under a wider head (S3)
    "f7", // undefined (S11)
    "bf616101616102ff", // duplicate map key (S8)
  ];
  for (const item of refused) {
    assert.throws(() => nodes.decode(nodeHolding(item)), NodeFormatError, item);
  }
  const accepted = [
    "fa3fc00000", // the golden float32 1.5
    "c249010000000000000000", // tag 2 bignum 2^64
    "c349008000000000000001", // tag 3 bignum -2^63-1
    "c482200f", // tag 4 decimal 1.5
    "c48200c24e04ee2d6d415b85acef8100000001", // tag 4 with a bignum mantissa
    "bf616201616102ff", // an application map in arrival order
    toHex(nodes.linkItem(linkTarget())), // a spilled value (PD-N-05)
  ];
  for (const item of accepted) {
    assert.doesNotThrow(() => nodes.decode(nodeHolding(item)), item);
  }
});

/** A CID to spill a value to: the CID of the golden embedded node itself. */
function linkTarget(): string {
  return cids.of(fromHex(GOLDEN["pdt_node_embedded"]!), cids.DAG_CBOR);
}

test("2.4: a link item stands in a value slot only, and the encoder refuses what the decoder refuses (JD-4)", () => {
  const link = nodes.linkItem(linkTarget());
  // A key never spills, so a link item in a key slot is tag 42 in an application document.
  const keyLinked = GOLDEN["pdt_node_embedded"]!.replace("846166fa3fc00000", `84${toHex(link)}fa3fc00000`);
  assert.throws(() => nodes.decode(fromHex(keyLinked)), NodeFormatError);
  const node = nodes.decode(fromHex(GOLDEN["pdt_node_embedded"]!));
  const entries = node["e"] as Embedded[];
  for (const item of ["c24101", "f93e00", "a1616101"]) {
    const bad = { ...node, e: [entries[0]!, new Embedded(fromHex(item)), entries[2]!, entries[3]!] };
    assert.throws(() => nodes.encode(bad), NodeFormatError, item);
  }
  assert.throws(() => nodes.encode({ ...node, e: [new Embedded(link), ...entries.slice(1)] }), NodeFormatError);
  assert.equal(toHex(nodes.encode({ ...node, e: [entries[0]!, new Embedded(link), entries[2]!, entries[3]!] })),
    toHex(nodeHolding(toHex(link))));
});

// ------------------------------------------------------------------------------------------- R7

/** Retires `agent` from `effective` on, signed by its own peer `issuer`. */
function retire(peer: Peer, issuer: Identity, agent: string, effective: number): void {
  const ad: Dict = { id: revocation.revocationId(GROUP, { kind: "AGENT", agent }), issuer: issuer.peerId, group: GROUP,
    issued: instantIso(NOW), ttl: "PT720H", target: { kind: "AGENT", agent }, reason: "retired",
    effectiveFrom: instantIso(effective) };
  const adBytes = dumps(ad);
  assert.equal(peer.revocations.acceptSigned(revocation.CREDENTIAL_STREAM,
    { adBytes, publicKey: issuer.publicRaw, signature: issuer.sign(adBytes) }, NOW), true);
}

test("R7: a revoked holder's claim is acknowledged with a c: line, and the acknowledgements keep Java's cap", () => {
  assert.equal(MAX_REFUSED_ACK, 8192, "ReplicatedSpace.REFUSED_ACK_CAP");
  const peer = new ClockPeer();
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer);
  peer.rumor(writer, dumps({ state, claimEntry: null, claim: null }));
  retire(peer, holder, holder.agent("worker"), NOW - 60_000);
  const signed = claimOn(holder, entryOf(state), String((state["record"] as Dict)["spaceId"]), `${NOW}:0:${holder.peerId}`);
  peer.rumor(holder, wire.claimDelta(entryOf(state), signed));
  assert.equal(peer.claims.size, 0);
  const lines = new TextDecoder().decode(peer.spaceDigest("tasks")).split("\n");
  assert.ok(lines.includes(`a:c:${entryOf(state)}=${claimHash(signed["claim"] as Dict)}`), lines.join("|"));
});

// ------------------------------------------------------------------------------------------- R9

test("R9: a lapsed ticket stays the earliest live lock until the replica collects it, as Java's KeyTickets reads it", () => {
  const peer = new ClockPeer();
  const space = new Space(peer, "tasks");
  let deliver: ((entryId: string, claim: Dict) => void) | null = null;
  const tickets = new KeyTickets("j", space, 60_000, 30_000, {} as OrderedLog, 16, (listener) => {
    deliver = listener;
    return () => { deliver = null; };
  });
  tickets.start();
  const entryId = peer.writeEntry("tasks", JOIN_TICKET_TYPE, { join: "j", key: "k" }, "w", 1_000, null,
    { [JOIN_TAG]: "j", [KEY_TAG]: "k" });
  deliver!(entryId, { entryId, epoch: 1, stamp: `${NOW}:5:${peer.identity.peerId}` });
  assert.equal(tickets.earliestLive("k"), entryId);
  peer.millis = NOW + 2_000; // the ticket's write lease lapsed; the replica still holds it
  assert.equal(tickets.earliestLive("k"), entryId, "a lapsed ticket is still the lock");
  peer.millis = NOW + 10 * 60_000;
  peer.collectTombstones();
  assert.equal(tickets.earliestLive("k"), null, "a collected ticket is no lock");
  tickets.close();
});

test("R9: TAKEN fires once per claim epoch, so a second take of a reappeared entry is heard", () => {
  const peer = new ClockPeer();
  const space = new Space(peer, "tasks");
  const events: SpaceEvent<Dict>[] = [];
  space.watch(new Template<Dict>("T#v1"), (event) => events.push(event));
  const writer = Identity.generate();
  const holder = Identity.generate();
  const state = writtenState(writer, NOW, {}, 600_000);
  peer.rumor(writer, dumps({ state, claimEntry: null, claim: null }));
  const spaceId = String((state["record"] as Dict)["spaceId"]);
  peer.rumor(holder, wire.claimDelta(entryOf(state), claimOn(holder, entryOf(state), spaceId, `${NOW}:1:${holder.peerId}`, 1,
    NOW + 1_000)));
  peer.millis = NOW + 2_000; // the first take lapsed
  peer.rumor(holder, wire.claimDelta(entryOf(state), claimOn(holder, entryOf(state), spaceId, `${NOW + 2_000}:0:${holder.peerId}`,
    2, NOW + 60_000)));
  assert.equal(events.filter((e) => e.kind === TAKEN).length, 2);
  // An expired claim announces no take.
  peer.rumor(holder, wire.claimDelta(entryOf(state), claimOn(holder, entryOf(state), spaceId, `${NOW + 2_000}:1:${holder.peerId}`,
    3, NOW + 1_500)));
  assert.equal(events.filter((e) => e.kind === TAKEN).length, 2);
});

test("R9: the vote tally counts only live proposals and ballots of its own space", () => {
  const peer = new ClockPeer();
  peer.joinSpace("votes");
  peer.joinSpace("other");
  vote.propose(peer, "votes", "p", "ship?", ["yes", "no"], 1, 60_000);
  vote.propose(peer, "other", "q", "elsewhere?", ["yes"], 1, 60_000);
  vote.cast(peer, "other", "p", "no", 60_000, null, "a");
  assert.deepEqual([...vote.proposals(peer, "votes").keys()], ["p"], "a proposal of another space is not this space's");
  const options = ["yes", "no"];
  assert.deepEqual([...vote.tally(peer, "votes", "p", options)], [["yes", 0], ["no", 0]], "a ballot of another space counts nothing");
  vote.cast(peer, "votes", "p", "yes", 1_000, null, "b");
  assert.deepEqual([...vote.tally(peer, "votes", "p", options)], [["yes", 1], ["no", 0]]);
  assert.equal(vote.decision(peer, "votes", "p")?.winner, "yes");
  peer.millis = NOW + 2_000; // the ballot's lease lapsed
  assert.deepEqual([...vote.tally(peer, "votes", "p", options)], [["yes", 0], ["no", 0]], "a lapsed ballot counts nothing");
  peer.millis = NOW + 61_000; // the proposal lapsed too
  assert.equal(vote.proposals(peer, "votes").size, 0);
  assert.equal(vote.decision(peer, "votes", "p"), null);
});

test("R9: collecting an entry releases the bulk payload it referenced, once no held entry names it (LB-E-04)", () => {
  const peer = new ClockPeer();
  const released: string[] = [];
  const published = new Map<string, Uint8Array>();
  const content: BulkPayloads = {
    escalateAbove: 16,
    publishOpaque: (payload) => {
      const root = `bulk${published.size}`;
      published.set(root, payload);
      return root;
    },
    local: (root) => published.get(root) ?? null,
    ensure: () => undefined,
    unpin: (root) => { released.push(root); },
  };
  peer.content = content;
  const big = { blob: "x".repeat(64) };
  const first = peer.writeEntry("tasks", "T#v1", big, "w", 1_000);
  const kept = peer.writeEntry("tasks", "T#v1", { small: 1 }, "w", 72 * 3_600_000);
  peer.cancelEntry("tasks", first);
  peer.millis = NOW + 49 * 3_600_000; // past the withdrawn entry's horizon, two of the longest tracked leases
  assert.deepEqual(released, [], "nothing is released before collection");
  assert.deepEqual(peer.collectTombstones(), [first]);
  assert.deepEqual(released, ["bulk0"]);
  assert.ok(peer.states.has(kept));
});

// ------------------------------------------------------------------------------------------ R10

test("R10: claims for entries the replica collected or never held go once they expire, so the claim map stays bounded", () => {
  const peer = new ClockPeer();
  const holder = Identity.generate();
  const writer = Identity.generate();
  const held = writtenState(writer, NOW, {}, 24 * 3_600_000);
  peer.rumor(writer, dumps({ state: held, claimEntry: null, claim: null }));
  const spaceId = String((held["record"] as Dict)["spaceId"]);
  peer.rumor(holder, wire.claimDelta(entryOf(held), claimOn(holder, entryOf(held), spaceId, `${NOW}:0:${holder.peerId}`, 1,
    NOW + 1_000)));
  const perRound = 50;
  let most = 0;
  for (let round = 0; round < 20; round++) {
    const wall = NOW + round * 2_000;
    peer.millis = wall;
    for (let i = 0; i < perRound; i++) {
      const entryId = `never-held-${round}-${i}`;
      peer.rumor(holder, wire.claimDelta(entryId, claimOn(holder, entryId, spaceId, `${wall}:${i}:${holder.peerId}`, 1,
        wall + 1_000)));
    }
    most = Math.max(most, peer.claims.size);
    peer.millis = wall + 1_500;
    peer.collectTombstones();
    assert.ok(peer.claims.size <= 1, `round ${round}: ${peer.claims.size} claims held after collection`);
  }
  assert.ok(most <= perRound + 1, `at most one round of claims at once: ${most}`);
  assert.ok(peer.claims.has(entryOf(held)), "an expired claim on a held entry stays, as the lattice keeps it");
});

test("R10: a replica that holds only claims still runs its collector, so their expiry drops them", () => {
  const peer = new ClockPeer();
  const runs: (() => void)[] = [];
  peer.timers = { setTimeout: () => 0, clearTimeout: () => undefined,
    every: (_period, fn) => { runs.push(fn); return { lastDriftMillis: 0, lateRuns: 0, stop: () => undefined }; } };
  const holder = Identity.generate();
  const spaceId = String(((writtenState(holder))["record"] as Dict)["spaceId"]);
  peer.rumor(holder, wire.claimDelta("never-held", claimOn(holder, "never-held", spaceId, `${NOW}:0:${holder.peerId}`, 1,
    NOW + 1_000)));
  assert.equal(peer.claims.size, 1);
  peer.millis = NOW + 1_500;
  runs.forEach((run) => run());
  assert.equal(peer.claims.size, 0);
});

test("F1: a StoredAd naming a type Java's AdCache does not register is refused, whatever its bytes hold", () => {
  const peer = new ClockPeer();
  const id = Identity.generate();
  const card = wire.agentCard(GROUP, id, "planner", instantIso(NOW), "PT10M", "plans", ["g"], ["c"], ["p"], {}, {});
  const stored = wire.storedAd("AgentCard", card, id);
  assert.notEqual(peer.acceptAd(stored), null);
  assert.equal(peer.acceptAd({ ...stored, adType: "AgentCardV2" }), null);
});

// ------------------------------------------------------------------------------- honest traffic

test("every carrier this client builds reads strictly at a receiver (HLC round six, 2026-11-08, F3)", () => {
  const id = Identity.generate();
  const agent = id.renewingSubordinate("planner", "PT24H", Identity.generate(), () => NOW);
  const tags = { b: "1", 10: "2", zz: "3" };
  const write = wire.entryDelta("tasks", GROUP, "T#v1", dumps({ job: 1 }), id, "w", 60_000, null, NOW, tags);
  const agentWrite = wire.entryDelta("tasks", GROUP, "T#v1", dumps({ job: 2 }), id, "w", 60_000, agent, NOW, tags);
  const state = (loads((loads(write.body) as Dict)["payload"] as Uint8Array) as Dict)["state"] as Dict;
  const claim = claimOn(id, write.entryId, String((state["record"] as Dict)["spaceId"]), `${NOW}:0:${id.peerId}`);
  const ad = wire.peerAdvertisement(GROUP, id, instantIso(NOW), "PT10M", { "wire.session": "1", 7: "x", a: "y" });
  const card = wire.agentCard(GROUP, id, "planner", instantIso(NOW), "PT10M", "plans", ["g"], ["c"], ["p"],
    { 2: "a", b: "c" }, { "T#v1": "tasks" });
  const carriers: [string, Uint8Array, records.Kind][] = [
    ["a write", (loads(write.body) as Dict)["payload"] as Uint8Array, records.SPACE_DELTA],
    ["an agent's write", (loads(agentWrite.body) as Dict)["payload"] as Uint8Array, records.SPACE_DELTA],
    ["a claim", wire.claimDelta(write.entryId, claim), records.SPACE_DELTA],
    ["a ping", wire.pingBody(-(2n ** 63n)), records.PING],
    ["an ack", wire.ackBody(7), records.ACK],
    ["a rumor", write.body, records.RUMOR],
    ["a digest", wire.digestBody({ "space:tasks": new Uint8Array(), peers: new Uint8Array(), 5: new Uint8Array() }),
      records.DIGEST],
    ["a relay frame", wire.relayFrameBody(id.peerId, new Uint8Array([1])), records.RELAY_FRAME],
    ["a path relay frame", wire.relayFrameBody(id.peerId, new Uint8Array([1]), [id.peerId], 0), records.RELAY_FRAME],
    ["a channel hello", wire.channelHelloBody(true, id.peerId), records.CHANNEL_HELLO],
    ["a block want", wire.blockWantBody("z1"), records.BLOCK_WANT],
    ["a block", wire.blockBody("z1", new Uint8Array([1])), records.BLOCK],
    ["a signed peer ad", wire.signedPeerAd(ad, id), records.SIGNED_PEER_AD],
    ["a peer ad", (loads(wire.signedPeerAd(ad, id)) as Dict)["adBytes"] as Uint8Array, records.PEER_ADVERTISEMENT],
    ["a stored card", dumps(wire.storedAd("AgentCard", card, id)), records.STORED_AD],
    ["a card", wire.storedAd("AgentCard", card, id)["adBytes"] as Uint8Array, records.AGENT_CARD],
  ];
  for (const [name, bytes, kind] of carriers) {
    assert.doesNotThrow(() => records.decodeRecord(bytes, kind), name);
  }
  // The peer's own pull answer, with claims that arrived out of their key order.
  const peer = new ClockPeer();
  const second = wire.entryDelta("tasks", GROUP, "T#v1", dumps({ job: 3 }), id, "w", 60_000, null, NOW);
  const spaceId = String((state["record"] as Dict)["spaceId"]);
  const [low, high] = [write.entryId, second.entryId].sort();
  for (const entryId of [high!, low!]) {
    const delta = entryId === write.entryId ? write : second;
    peer.rumor(id, (loads(delta.body) as Dict)["payload"] as Uint8Array);
    peer.rumor(id, wire.claimDelta(entryId, claimOn(id, entryId, spaceId, `${NOW}:0:${id.peerId}`)));
  }
  assert.equal(peer.claims.size, 2);
  peer.pullSpace("tasks");
  const answered = (peer as unknown as { spaceDeltaFor(space: string, digest: Uint8Array): Uint8Array }).spaceDeltaFor("tasks",
    new Uint8Array());
  assert.doesNotThrow(() => records.decodeRecord(answered, records.SYNC_DELTA));
  const digest = peer.sent.find((s) => s.kind === "DIGEST")!.body;
  assert.doesNotThrow(() => records.decodeRecord(digest, records.DIGEST));
});
