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
 * v0.1.13 agent behaviour in the TypeScript client (TODO-9-10-11 Phase 4):
 * agent-signed records, claims, and states a second peer folds; renewal
 * judged at signing time; the keystore's layout and checks; and revocation
 * applied at merge under the freeze rule.
 */

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync, rmSync } from "node:fs";
import { AddressInfo, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { dumps, loads } from "../src/cbor.js";
import { Identity, instantIso, parseInstantMillis } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import * as revocation from "../src/revocation.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";

const GROUP = "zTypeScriptAgents";
const T0 = parseInstantMillis("2026-03-01T00:00:00Z");

class Clock {
  constructor(public millis: number) {}
  readonly now = (): number => this.millis;
  advance(millis: number): void {
    this.millis += millis;
  }
}

function deltaState(body: Buffer): Dict {
  const rumor = loads(body) as Dict;
  return (loads(Buffer.from(rumor["payload"] as Uint8Array)) as Dict)["state"] as Dict;
}

type Folding = { fold(dto: Dict): void; foldClaim(entryId: string, signed: Dict): void;
  handle(env: Dict): void; send(kind: string, body: Buffer): void };
const internals = (peer: Peer): Folding => peer as unknown as Folding;

test("an agent-signed write folds at another peer as the agent's own", () => {
  const clock = new Clock(T0);
  const host = Identity.generate();
  const agent = host.renewingSubordinate("planner", "PT24H", Identity.generate(), clock.now);
  const state = deltaState(wire.entryDelta("tasks", GROUP, "T#v1", dumps({ x: 1 }), host, "ignored",
    60_000, agent, clock.millis).body);
  assert.equal((state["record"] as Dict)["issuer"], agent.agentId);
  assert.equal(state["signer"], agent.agentId);
  const receiver = new Peer(Identity.generate(), GROUP, clock.now);
  internals(receiver).fold(state);
  assert.equal(receiver.states.size, 1);
  const other = new Peer(Identity.generate(), GROUP, clock.now);
  internals(other).fold(wire.signState(state, host, null, clock.millis));
  assert.equal(other.states.size, 0, "a peer-signed transition on an attested entry (A6)");
});

test("a renewing agent stays verifiable after its first certificate lapses", () => {
  const clock = new Clock(T0);
  const host = Identity.generate();
  const agent = host.renewingSubordinate("planner", "PT1H", Identity.generate(), clock.now);
  const first = agent.certificate;
  const early = deltaState(wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array([1]), host, "x",
    600_000, agent, clock.millis).body);
  clock.advance(31 * 60 * 1000);
  const later = deltaState(wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array([2]), host, "x",
    600_000, agent, clock.millis).body);
  assert.notEqual(agent.certificate, first);
  assert.equal(agent.certificateCovering(T0), first);
  clock.advance(4 * 60 * 60 * 1000);
  const receiver = new Peer(Identity.generate(), GROUP, clock.now);
  internals(receiver).fold(early);
  internals(receiver).fold(later);
  assert.equal(receiver.states.size, 2, "judged at signing time, not at receipt");
});

test("an agent-signed take and completion land, and a peer-signed completion does not", () => {
  const clock = new Clock(T0);
  const writer = Identity.generate();
  const host = Identity.generate();
  const state = deltaState(wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array([1]), writer, "w",
    600_000, null, clock.millis).body);
  const record = state["record"] as Dict;
  const worker = host.renewingSubordinate("worker", "PT24H", Identity.generate(), clock.now);
  const claim = wire.takeClaim(String(record["entryId"]), String(record["spaceId"]), 1,
    wire.hlcNow(worker.agentId, clock.millis), worker.agentId, 0.0, clock.millis + 60_000);
  const receiver = new Peer(Identity.generate(), GROUP, clock.now);
  internals(receiver).fold(state);
  internals(receiver).foldClaim(String(record["entryId"]), wire.signedClaim(claim, host, worker));
  assert.equal(receiver.claims.size, 1);
  internals(receiver).fold(wire.signState({ ...state, completed: true }, host, null, clock.millis));
  assert.equal(receiver.states.get(String(record["entryId"]))!["completed"], false);
  internals(receiver).fold(wire.signState({ ...state, completed: true }, host, worker, clock.millis));
  assert.equal(receiver.states.get(String(record["entryId"]))!["completed"], true);
});

function signedRevocation(issuer: Identity, target: Dict, reason: string, issued: number,
                          effective: number | null = null): Dict {
  const ad: Dict = { id: revocation.revocationId(GROUP, target), issuer: issuer.peerId, group: GROUP,
    issued: instantIso(issued), ttl: "PT720H", target, reason };
  if (effective !== null) {
    ad["effectiveFrom"] = instantIso(effective);
  }
  const adBytes = dumps(ad);
  return { adBytes, publicKey: issuer.publicRaw, signature: issuer.sign(adBytes) };
}

test("a retired agent's history folds while its later writes and claims do not", () => {
  const clock = new Clock(T0);
  const host = Identity.generate();
  const agent = host.renewingSubordinate("planner", "PT24H", Identity.generate(), clock.now);
  const before = deltaState(wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array([1]), host, "x",
    600_000, agent, clock.millis).body);
  clock.advance(60_000);
  const retiredAt = clock.millis;
  clock.advance(60_000);
  const after = deltaState(wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array([2]), host, "x",
    600_000, agent, clock.millis).body);
  const receiver = new Peer(Identity.generate(), GROUP, clock.now);
  assert.equal(receiver.revocations.acceptSigned(revocation.CREDENTIAL_STREAM, signedRevocation(host,
    { kind: "AGENT", agent: agent.agentId }, "retired", clock.millis, retiredAt), clock.millis), true);
  internals(receiver).fold(before);
  internals(receiver).fold(after);
  assert.equal(receiver.states.size, 1, "history before the effect, nothing after");
  const entryId = [...receiver.states.keys()][0];
  const claim = wire.takeClaim(entryId, String((before["record"] as Dict)["spaceId"]), 1,
    wire.hlcNow(agent.agentId, retiredAt - 1), agent.agentId, 0.0, clock.millis + 60_000);
  internals(receiver).foldClaim(entryId, wire.signedClaim(claim, host, agent));
  assert.equal(receiver.claims.size, 0, "a claim is refused whatever its stamp");
  const local = new Peer(host, GROUP, clock.now);
  local.revocations = receiver.revocations;
  assert.throws(() => local.writeEntry("tasks", "T#v1", { x: 3 }, "x", 600_000, agent), /revoked/);
});

test("only the agent's peer or the founder may revoke it", () => {
  const founder = Identity.generate();
  const host = Identity.generate();
  const stranger = Identity.generate();
  const target: Dict = { kind: "AGENT", agent: host.agent("planner") };
  const registry = new revocation.Registry(() => founder.peerId, () => GROUP);
  assert.equal(registry.acceptSigned(revocation.CREDENTIAL_STREAM,
    signedRevocation(stranger, target, "retired", T0), T0), false);
  assert.equal(registry.acceptSigned(revocation.CREDENTIAL_STREAM,
    signedRevocation(founder, target, "retired", T0), T0), true);
  registry.acceptSigned(revocation.CREDENTIAL_STREAM,
    signedRevocation(host, target, "key-compromise", T0 + 1000), T0);
  assert.equal(registry.credentials.get(`AGENT:${host.agent("planner")}`)!.ad["reason"], "retired");
  const peerAd: Dict = { id: `aspace://${GROUP}/revocation/${host.peerId}`, issuer: founder.peerId,
    group: GROUP, issued: instantIso(T0), ttl: "PT720H", revoked: host.peerId, reason: "compromised",
    successor: null };
  const adBytes = dumps(peerAd);
  assert.equal(registry.acceptSigned(revocation.PEER_STREAM, { adBytes, publicKey: founder.publicRaw,
    signature: founder.sign(adBytes) }, T0), true);
  assert.equal(registry.refuses(host.agent("anyone"), null, T0), true);
});

test("the keystore matches Java's layout and refuses damage", () => {
  const dir = mkdtempSync(join(tmpdir(), "aspace-keys-"));
  try {
    const first = Identity.loadOrCreate(dir);
    assert.equal(Identity.loadOrCreate(dir).peerId, first.peerId);
    assert.equal(statSync(join(dir, "peer.key")).mode & 0o777, 0o600);
    assert.deepEqual(readFileSync(join(dir, "peer.pub")), Buffer.from(first.publicRaw));
    const agent = Identity.agentKeys(join(dir, "agents"), first.peerId, "planner");
    assert.equal(existsSync(join(dir, "agents", first.peerId, "planner", "agent.key")), true);
    assert.deepEqual(Buffer.from(Identity.agentKeys(join(dir, "agents"), first.peerId, "planner")
      .publicRaw), Buffer.from(agent.publicRaw));
    assert.throws(() => Identity.agentKeys(join(dir, "agents"), first.peerId, "../escape"));
    writeFileSync(join(dir, "peer.pub"), Identity.generate().publicRaw);
    assert.throws(() => Identity.loadOrCreate(dir), /does not belong/);
    rmSync(join(dir, "peer.pub"));
    assert.throws(() => Identity.loadOrCreate(dir), /does not/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** Records what a socketless peer would send, as [kind, body] pairs. */
function capture(peer: Peer): [string, Buffer][] {
  const sent: [string, Buffer][] = [];
  internals(peer).send = (kind, body) => { sent.push([kind, body]); };
  return sent;
}

function digestStreams(body: Buffer): string[] {
  return Object.keys((loads(body) as Dict)["digests"] as Dict).sort();
}

test("a pull names the revocation streams, and a join pulls them once", async () => {
  const clock = new Clock(T0);
  const peer = new Peer(Identity.generate(), GROUP, clock.now);
  const sent = capture(peer);
  peer.pullSpace("tasks");
  assert.equal(sent.at(-1)![0], "DIGEST");
  assert.deepEqual(digestStreams(sent.at(-1)![1]),
    ["credential-revocations", "revocations", "space:tasks"]);
  const digests = (loads(sent.at(-1)![1]) as Dict)["digests"] as Dict;
  assert.equal((digests["revocations"] as Uint8Array).length, 0, "an empty digest asks for all");
  // A late joiner asks for the revocation streams as soon as it connects.
  const server = createServer((socket) => socket.destroy());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  sent.length = 0;
  try {
    await peer.connect("127.0.0.1", (server.address() as AddressInfo).port);
  } finally {
    peer.close();
    await new Promise((resolve) => server.close(resolve));
  }
  assert.deepEqual(sent.filter(([kind]) => kind === "DIGEST").map(([, body]) => digestStreams(body)),
    [["credential-revocations", "revocations"]]);
});

test("a pull response carrying a credential revocation applies it", () => {
  const clock = new Clock(T0);
  const host = Identity.generate();
  const agent = host.renewingSubordinate("planner", "PT24H", Identity.generate(), clock.now);
  const receiver = new Peer(Identity.generate(), GROUP, clock.now);
  const signed = signedRevocation(host, { kind: "AGENT", agent: agent.agentId },
    revocation.KEY_COMPROMISE, clock.millis);
  const body = dumps({ deltas: { [revocation.CREDENTIAL_STREAM]: dumps([signed]) } });
  internals(receiver).handle({ kind: "PULL_RESP", body, stamp: wire.hlcNow(host.peerId, clock.millis) });
  assert.equal(receiver.revocations.refuses(agent.agentId, agent.publicRaw, clock.millis), true);
  internals(receiver).fold(deltaState(wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array([1]),
    host, "x", 600_000, agent, clock.millis).body));
  assert.equal(receiver.states.size, 0);
});

test("a peer-signed renewal after the effective instant is not merged", () => {
  const clock = new Clock(T0);
  const host = Identity.generate();
  const writer = new Peer(host, GROUP, clock.now);
  const { entryId, body } = wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array([1]), host, "x",
    600_000, null, clock.millis);
  const original = deltaState(body);
  writer.states.set(entryId, original);
  const receiver = new Peer(Identity.generate(), GROUP, clock.now);
  internals(receiver).fold(original);
  clock.advance(60_000);
  const retiredAt = clock.millis;
  assert.equal(receiver.revocations.acceptSigned(revocation.CREDENTIAL_STREAM, signedRevocation(host,
    { kind: "AGENT", agent: host.agent("x") }, "retired", retiredAt, retiredAt), clock.millis), true);
  clock.advance(60_000);
  const sent = capture(writer);
  writer.renewEntry("tasks", entryId);
  const renewal = deltaState(sent.at(-1)![1]);
  assert.equal(renewal["signedAt"] ?? null, null, "the peer signs its own renewal");
  internals(receiver).fold(renewal);
  assert.deepEqual(receiver.states.get(entryId), original, "the held state stays as held");
  // The original history still folds at a replica that learns it late.
  const late = new Peer(Identity.generate(), GROUP, clock.now);
  late.revocations = receiver.revocations;
  internals(late).fold(original);
  assert.deepEqual(late.states.get(entryId), original);
});

test("a revoked holder's completion is refused though its claim came first", () => {
  const clock = new Clock(T0);
  const writer = Identity.generate();
  const host = Identity.generate();
  const state = deltaState(wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array([1]), writer, "w",
    600_000, null, clock.millis).body);
  const record = state["record"] as Dict;
  const worker = host.renewingSubordinate("worker", "PT24H", Identity.generate(), clock.now);
  const claim = wire.takeClaim(String(record["entryId"]), String(record["spaceId"]), 1,
    wire.hlcNow(worker.agentId, clock.millis), worker.agentId, 0.0, clock.millis + 600_000);
  const receiver = new Peer(Identity.generate(), GROUP, clock.now);
  internals(receiver).fold(state);
  internals(receiver).foldClaim(String(record["entryId"]), wire.signedClaim(claim, host, worker));
  assert.equal(receiver.claims.size, 1);
  clock.advance(60_000);
  assert.equal(receiver.revocations.acceptSigned(revocation.CREDENTIAL_STREAM, signedRevocation(host,
    { kind: "AGENT", agent: worker.agentId }, "retired", clock.millis, clock.millis), clock.millis), true);
  clock.advance(60_000);
  internals(receiver).fold(wire.signState({ ...state, completed: true }, host, worker, clock.millis));
  assert.equal(receiver.states.get(String(record["entryId"]))!["completed"], false);
});

test("a state whose signedAt is not a stamp is judged without throwing", () => {
  const clock = new Clock(T0);
  const host = Identity.generate();
  const state = deltaState(wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array([1]), host, "x",
    600_000, null, clock.millis).body);
  const record = state["record"] as Dict;
  // Peer-signed (no signer) yet naming a signedAt: the signature covers it.
  const view = wire.stateSignView(String(record["spaceId"]), String(record["entryId"]),
    state["adds"] as Dict[], state["removes"] as Dict[], String(state["leaseStamp"]),
    state["leaseValue"] as Dict, false, null, "not-a-stamp");
  const odd = { ...state, signedAt: "not-a-stamp", stateSig: host.sign(dumps(view)) };
  const receiver = new Peer(Identity.generate(), GROUP, clock.now);
  assert.doesNotThrow(() => internals(receiver).fold(odd));
  assert.equal(receiver.states.size, 1);
});

test("the peer clock judges skew and stamps the introduction", () => {
  const clock = new Clock(T0); // months behind wall time
  const peer = new Peer(Identity.generate(), GROUP, clock.now);
  const sent = capture(peer);
  const hostile = T0 + wire.MAX_HLC_SKEW_MILLIS + 60_000; // still behind wall time
  internals(peer).handle({ kind: "PING", body: wire.pingBody(1),
    stamp: `${hostile}:0:${Identity.generate().peerId}` });
  assert.equal(wire.hlcPhysical(wire.hlcNow(peer.identity.peerId, clock.millis)), T0);
  // A caller's clock ahead of wall time admits a stamp within skew of it.
  const node = Identity.generate().peerId;
  const ahead = T0 + 10 * 365 * 86_400_000;
  wire.hlcObserve(node, `${ahead + 1000}:0:x`, ahead);
  assert.equal(wire.hlcPhysical(wire.hlcNow(node, ahead)), ahead + 1000);
  sent.length = 0;
  clock.advance(1234);
  peer.introduce();
  const rumor = loads(sent.at(-1)![1]) as Dict;
  assert.equal(rumor["itemId"], `peer:${peer.identity.peerId}:${clock.millis}`);
  const signedAd = loads(Buffer.from(rumor["payload"] as Uint8Array)) as Dict;
  const ad = loads(Buffer.from(signedAd["adBytes"] as Uint8Array)) as Dict;
  assert.equal(ad["issued"], instantIso(clock.millis - (clock.millis % 1000)));
});

test("a PING with a Java-sized 64-bit nonce is answered with that exact nonce", () => {
  const peer = new Peer(Identity.generate(), GROUP, new Clock(T0).now);
  const sent = capture(peer);
  for (const nonce of [-4578347444961987476n, 8646844919576911264n - 2n ** 64n, 7n]) {
    internals(peer).handle({ kind: "PING", body: wire.pingBody(nonce),
      stamp: `${T0}:0:${Identity.generate().peerId}` });
    const [kind, body] = sent.at(-1)!;
    assert.equal(kind, "ACK");
    const echoed = (loads(Buffer.from(body)) as Dict)["nonce"];
    assert.equal(BigInt(echoed as number | bigint), nonce);
  }
});

test("savePkcs8 writes the key owner-only", () => {
  const dir = mkdtempSync(join(tmpdir(), "aspace-pkcs8-"));
  try {
    const identity = Identity.generate();
    const path = join(dir, "keys", "peer.key");
    identity.savePkcs8(path);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(Identity.fromPkcs8(new Uint8Array(readFileSync(path))).peerId, identity.peerId);
    Identity.generate().savePkcs8(path); // an atomic replace
    assert.notEqual(Identity.fromPkcs8(new Uint8Array(readFileSync(path))).peerId, identity.peerId);
    assert.deepEqual(readdirSync(join(dir, "keys")), ["peer.key"], "no temporary file is left");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an agent-signed renewal folds at another peer with a later lease", () => {
  const clock = new Clock(T0);
  const host = Identity.generate();
  const agent = host.renewingSubordinate("planner", "PT24H", Identity.generate(), clock.now);
  const writer = new Peer(host, GROUP, clock.now);
  const { entryId, body } = wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array([1]), host, "x",
    60_000, agent, clock.millis);
  const original = deltaState(body);
  writer.states.set(entryId, original);
  const receiver = new Peer(Identity.generate(), GROUP, clock.now);
  internals(receiver).fold(original);
  clock.advance(30_000);
  const sent = capture(writer);
  writer.renewEntry("tasks", entryId, 60_000, agent);
  internals(receiver).fold(deltaState(sent.at(-1)![1]));
  const held = receiver.states.get(entryId)!;
  assert.equal(Number((held["leaseValue"] as Dict)["expiresAtMillis"]), clock.millis + 60_000);
  assert.ok(wire.compareHlc(String(held["leaseStamp"]), String(original["leaseStamp"])) > 0);
});

test("a renewal under the wrong agent throws locally", () => {
  const clock = new Clock(T0);
  const host = Identity.generate();
  const agent = host.renewingSubordinate("planner", "PT24H", Identity.generate(), clock.now);
  const sibling = host.renewingSubordinate("sibling", "PT24H", Identity.generate(), clock.now);
  const writer = new Peer(host, GROUP, clock.now);
  const sent = capture(writer);
  const { entryId, body } = wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array([1]), host, "x",
    60_000, agent, clock.millis);
  writer.states.set(entryId, deltaState(body));
  assert.throws(() => writer.renewEntry("tasks", entryId, 60_000, sibling), /not/);
  // Without an agent, only an entry this peer's own agent names wrote renews.
  const foreign = wire.entryDelta("tasks", GROUP, "T#v1", new Uint8Array([2]), Identity.generate(),
    "x", 60_000, null, clock.millis);
  writer.states.set(foreign.entryId, deltaState(foreign.body));
  assert.throws(() => writer.renewEntry("tasks", foreign.entryId), /not by this peer/);
  assert.equal(sent.length, 0);
});
