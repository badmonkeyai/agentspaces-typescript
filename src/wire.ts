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
 * The wire protocol (spec §9) in TypeScript: signed CBOR envelopes, the
 * bodies this client speaks, entry-write deltas, and take claims. Every
 * object literal lists its keys in the Java record's field order, because
 * signatures cover the canonical CBOR and byte order is meaning.
 */

import { createHash, randomUUID } from "node:crypto";
import { CborDouble, CborValue, canonicalMap, dumps, loads } from "./cbor.js";
import {
  AgentIdentity, Identity, deriveId, spaceIdLocal, verifyAgentCertificateAt,
} from "./identity.js";

export type Dict = { [key: string]: CborValue };

/**
 * WireCodec.WIRE_VERSION: the only envelope version a receiver accepts. A
 * frame of any other version is dropped before its signature is examined
 * (SPEC §9, TECH-SPEC §3). 3 since ISSUE-CanonicalMaps: map entries sorted
 * by key in every encoding.
 */
export const WIRE_VERSION = 3;

/**
 * Largest frame accepted or sent, mirroring the JVM transport's cap: a length
 * prefix beyond it is hostile or corrupt, never legitimate (ASF-016).
 */
export const MAX_FRAME_BYTES = 8 * 1024 * 1024;

/**
 * ASF-004 bounds, mirroring ReplicatedSpace: the largest epoch advance a
 * remote claim may assert over the locally observed epoch, and the longest
 * TAKE hold it may assert beyond this client's clock.
 */
export const MAX_CLAIM_EPOCH_JUMP = 1 << 20;
export const MAX_CLAIM_HOLD_MILLIS = 24 * 60 * 60 * 1000;

/**
 * How far ahead of this client's clock a remote stamp may run before it
 * is ignored rather than merged (the HLC clamp, ASF-020/043).
 */
export const MAX_HLC_SKEW_MILLIS = 10 * 60 * 1000;

const hlcState = new Map<string, [number, number]>();

/**
 * A fresh hybrid-logical-clock stamp in the Java string form: physical time
 * never runs backwards, and the logical counter increments within one
 * millisecond, so two stamps from the same node never collide and stamps
 * after an observed remote stamp sort after it (ASF-043).
 */
export function hlcNow(node: string, nowMillis?: number): string {
  const wall = nowMillis ?? Date.now();
  let [physical, logical] = hlcState.get(node) ?? [0, -1];
  if (wall > physical) {
    physical = wall;
    logical = 0;
  } else {
    logical += 1;
  }
  hlcState.set(node, [physical, logical]);
  return `${physical}:${logical}:${node}`;
}

/** The physical milliseconds of an HLC stamp string: its signing time. */
export function hlcPhysical(stamp: unknown): number {
  const physical = Number(String(stamp ?? "").split(":")[0]);
  if (!Number.isFinite(physical)) {
    throw new Error(`not an HLC stamp: ${String(stamp)}`);
  }
  return physical;
}

/**
 * Merges a remote stamp into the local clock so later local stamps sort after
 * everything observed. Remote physicals beyond the skew ceiling are ignored:
 * a hostile far-future stamp cannot pin this clock (ASF-020). `nowMillis` is
 * the caller's clock the skew is judged against (a peer's); default wall time.
 */
export function hlcObserve(node: string, stamp: unknown, nowMillis?: number): void {
  const parts = String(stamp ?? "").split(":");
  const physical = Number(parts[0]);
  const logical = Number(parts[1]);
  if (!Number.isFinite(physical) || !Number.isFinite(logical)
      || physical > (nowMillis ?? Date.now()) + MAX_HLC_SKEW_MILLIS) {
    return;
  }
  const [currentPhysical, currentLogical] = hlcState.get(node) ?? [0, -1];
  if (physical > currentPhysical
      || (physical === currentPhysical && logical > currentLogical)) {
    hlcState.set(node, [physical, logical]);
  }
}

/** Compares two HLC stamps in the Java string form; positive when a > b. */
export function compareHlc(a: string, b: string): number {
  const [ap, al, an] = hlcTuple(a);
  const [bp, bl, bn] = hlcTuple(b);
  if (ap !== bp) {
    return ap - bp;
  }
  if (al !== bl) {
    return al - bl;
  }
  return an < bn ? -1 : an > bn ? 1 : 0;
}

/** An Envelope in field order: ver, group, kind, from, to, stamp, body. */
export function envelope(group: string, kind: string, sender: string,
                         stamp: string, body: Uint8Array,
                         to: string | null = null): Dict {
  // `to` binds the frame to its recipient (ASF-010); null is an unaddressed
  // frame (the bootstrap exception, SPEC §9). ver is WIRE_VERSION.
  return { ver: WIRE_VERSION, group, kind, from: sender, to, stamp, body };
}

/**
 * The join-by-GroupID request (SPEC §9, §10.1): an empty body, the wanted
 * group in the envelope's `group`. A real request is unaddressed (`to` null)
 * because the seed's PeerID is not known until it answers.
 */
export function groupAdWantEnvelope(group: string, sender: string, stamp: string,
                                    to: string | null = null): Dict {
  return envelope(group, "GROUP_AD_WANT", sender, stamp, new Uint8Array(), to);
}

/** The GROUP_AD body: the SignedGroupAdvertisement's canonical CBOR (§9). */
export function groupAdBody(signed: Dict): Buffer {
  return dumps(signed);
}

/** Signs and encodes an envelope into a frame (WireCodec.Signed). */
export function encodeFrame(env: Dict, identity: Identity): Buffer {
  const canonical = dumps(env);
  return dumps({
    envelope: env,
    senderPublicKey: identity.publicRaw,
    signature: identity.sign(canonical),
  });
}

/** Decodes and verifies a frame; returns the envelope or null. */
export function decodeFrame(frame: Buffer): Dict | null {
  let signed: CborValue;
  try {
    signed = loads(frame);
  } catch {
    return null;
  }
  if (typeof signed !== "object" || signed === null || Array.isArray(signed)) {
    return null;
  }
  const env = (signed as Dict)["envelope"];
  const key = (signed as Dict)["senderPublicKey"];
  const signature = (signed as Dict)["signature"];
  if (typeof env !== "object" || env === null || Array.isArray(env)
      || env instanceof CborDouble) {
    return null;
  }
  // The version check comes first, so a frame of another version costs no
  // signature work (SPEC §9, TECH-SPEC §3).
  if ((env as Dict)["ver"] !== WIRE_VERSION) {
    return null;
  }
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    return null;
  }
  if (deriveId(key) !== (env as Dict)["from"]) {
    return null;
  }
  if (!Identity.verify(key, dumps(env as Dict),
      signature instanceof Uint8Array ? signature : new Uint8Array())) {
    return null;
  }
  return env as Dict;
}

// -------------------------------------------------------------------- bodies

export function pingBody(nonce: number | bigint): Buffer {
  return dumps({ nonce });
}

export function ackBody(nonce: number | bigint): Buffer {
  return dumps({ nonce, onBehalf: null });
}

export function rumorBody(streamId: string, itemId: string, hops: number,
                          payload: Uint8Array): Buffer {
  return dumps({ streamId, itemId, hopsRemaining: hops, payload });
}

export function digestBody(digests: Dict): Buffer {
  return dumps({ digests });
}

/** A PeerAdvertisement with no endpoints: the dial-only NAT posture. */
export function peerAdvertisement(group: string, identity: Identity,
                                  issuedIso: string, ttlIso = "PT10M"): Dict {
  return {
    id: `aspace://${group}/peer/${identity.peerId}`,
    issuer: identity.peerId,
    group,
    issued: issuedIso,
    ttl: ttlIso,
    endpoints: [],
    roles: [],
    resourceHints: {},
  };
}

/** The 'peers' stream payload: PeerNode.SignedPeerAd. */
export function signedPeerAd(ad: Dict, identity: Identity): Buffer {
  const adBytes = dumps(ad);
  return dumps({
    adBytes,
    publicKey: identity.publicRaw,
    signature: identity.sign(adBytes),
  });
}

// ----------------------------------------------------- advertisements (§6.1)

/**
 * An AgentCard in Java field order: id, issuer, group, issued, ttl, agent,
 * description, goals, consumes, produces, costHints, spaceBindings. The id is
 * aspace://<group>/agent/<agentId> (§4.4).
 */
export function agentCard(group: string, identity: Identity, localName: string,
                          issuedIso: string, ttlIso: string, description: string,
                          goals: string[], consumes: string[], produces: string[],
                          costHints: Dict, spaceBindings: Dict,
                          agentPublicKey: Uint8Array | null = null,
                          actions: Dict[] | null = null,
                          agentCertificate: Dict | null = null): Dict {
  const agent = identity.agent(localName);
  const card: Dict = { id: `aspace://${group}/agent/${agent}`, issuer: identity.peerId,
    group, issued: issuedIso, ttl: ttlIso, agent, description, goals, consumes,
    produces, costHints: canonicalMap(costHints), spaceBindings: canonicalMap(spaceBindings) };
  if (agentCertificate !== null && (agentPublicKey === null
      || agentCertificate["agent"] !== agent
      || !Buffer.from(agentCertificate["agentPublicKey"] as Uint8Array).equals(Buffer.from(agentPublicKey)))) {
    throw new Error("a card's certificate must certify its agent and agentPublicKey");
  }
  if (agentPublicKey !== null) {
    // QA4 A4-7 phase 3: appended, and absent (not null) on a peer-signed agent's
    // card, so a card without it is byte-identical to the v0.1.10 card.
    card["agentPublicKey"] = agentPublicKey;
  }
  if (actions !== null && actions.length > 0) {
    card["actions"] = actions; // v0.1.13 (item 6): declared actions
  }
  if (agentCertificate !== null) {
    card["agentCertificate"] = agentCertificate; // v0.1.13: the agent's certificate
  }
  return card;
}

/**
 * A CardAction in Java field order (SPEC §6.1, v0.1.13): name, description,
 * consumes, produces, space (omitted when absent), kind.
 */
export function cardAction(name: string, description: string, consumes: string[],
                           produces: string[], kind: string, space: string | null = null): Dict {
  const action: Dict = { name, description, consumes, produces };
  if (space !== null) {
    action["space"] = space;
  }
  action["kind"] = kind;
  return action;
}

/**
 * A SpaceAdvertisement in Java field order: id, issuer, group, issued, ttl,
 * spaceName, schemaHints, strategy, admission, replication. Its canonical
 * CBOR is the space's founding document (SpaceId.fromFounding, §4.4).
 */
export function spaceAdvertisement(group: string, issuer: string, spaceName: string,
                                   issuedIso: string, ttlIso: string,
                                   schemaHints: string[], strategy: string,
                                   admission: string, replication: string): Dict {
  return { id: `aspace://${group}/${spaceName}`, issuer, group, issued: issuedIso,
    ttl: ttlIso, spaceName, schemaHints, strategy, admission, replication };
}

/**
 * AdCache.StoredAd: how a signed advertisement travels on the `ads` stream
 * and in QUERY_HIT answers (TECH-SPEC §6.2): the type name, the
 * advertisement's canonical bytes, the issuer's key, and the signature over
 * those bytes.
 */
export function storedAd(adType: string, ad: Dict, identity: Identity): Dict {
  const adBytes = dumps(ad);
  return { adType, adBytes, publicKey: identity.publicRaw,
    signature: identity.sign(adBytes) };
}

// --------------------------------------------------- capability frames (§8)

/**
 * A participant's aggregate roster token (SPEC §8 aggregate): the first 8
 * bytes of sha-256(PeerID) read big-endian as a signed int64. Returned as a
 * bigint because the value is generally outside the safe-integer range.
 */
export function rosterToken(peerId: string): bigint {
  return createHash("sha256").update(peerId, "utf-8").digest().readBigInt64BE(0);
}

function doubles(values: number[]): CborDouble[] {
  return values.map((v) => new CborDouble(v));
}

/**
 * The aspace:cap/aggregate PIPE_DATA payload, a union Frame {share, extremum,
 * histogram, roster} with exactly one variant set and the others present as
 * null. Numeric fields are Java doubles, so they encode as float64.
 */
export function aggregateShareFrame(epochId: string, value: number, weight: number): Dict {
  return { share: { epochId, value: new CborDouble(value), weight: new CborDouble(weight) },
    extremum: null, histogram: null, roster: null };
}

export function aggregateExtremumFrame(epochId: string, max: boolean, value: number): Dict {
  return { share: null, extremum: { epochId, max, value: new CborDouble(value) },
    histogram: null, roster: null };
}

export function aggregateHistogramFrame(epochId: string, lo: number, hi: number,
                                        buckets: number[]): Dict {
  return { share: null, extremum: null,
    histogram: { epochId, lo: new CborDouble(lo), hi: new CborDouble(hi),
      buckets: doubles(buckets) }, roster: null };
}

/** Roster members are int64 tokens ({@link rosterToken}), hence bigint. */
export function aggregateRosterFrame(epochId: string, members: bigint[]): Dict {
  return { share: null, extremum: null, histogram: null,
    roster: { epochId, members } };
}

/**
 * The aspace:cap/gossip-learn PIPE_DATA payload (SPEC §8, TECH-SPEC §8.5):
 * Exchange {modelId, token, kind, round, inline, cid}. Small models travel
 * `inline`; larger ones by content id (§7.8) with `inline` null.
 */
export function learnExchange(modelId: string, token: number | bigint, kind: string,
                              round: number | bigint, inline: Uint8Array | null,
                              cid: string | null): Dict {
  return { modelId, token, kind, round, inline, cid };
}

/** WeightAveraging.encode: a model vector as big-endian IEEE-754 doubles. */
export function encodeModel(weights: number[]): Buffer {
  const b = Buffer.alloc(weights.length * 8);
  weights.forEach((w, i) => b.writeDoubleBE(w, i * 8));
  return b;
}

/** BlockExchange.cidOf: multibase base58btc of sha-256 over the block (§7.8). */
export function contentId(block: Uint8Array): string {
  return deriveId(block);
}

// -------------------------------------------------------------- space writes

/**
 * ReplicatedSpace's SignView: the record identity the signature covers.
 * `keyEpoch` (v0.1.13, SPEC §11a.1) is appended only for a record sealed under
 * a content-key epoch from 1, so other records sign the same bytes.
 */
export function signView(entryId: string, spaceId: string, typeName: string,
                         payload: Uint8Array, issuer: string,
                         issued: string, keyEpoch: number | null = null,
                         tags: Dict = {}): Dict {
  // SPEC §7.1: the tags are part of the signed record, canonical on the wire.
  const view: Dict = { entryId, spaceId, type: typeName, payload, payloadRef: null,
    issuer, issued, tags: canonicalMap(tags) };
  if (keyEpoch !== null) {
    view["keyEpoch"] = keyEpoch;
  }
  return view;
}

/** The SignView for an already-built record, from its own fields. */
export function signViewOf(record: Dict): Dict {
  const view: Dict = { entryId: record["entryId"], spaceId: record["spaceId"],
    type: record["type"], payload: record["payload"],
    payloadRef: record["payloadRef"] ?? null, issuer: record["issuer"],
    issued: record["issued"], tags: record["tags"] ?? {} };
  if (record["keyEpoch"] !== undefined && record["keyEpoch"] !== null) {
    view["keyEpoch"] = record["keyEpoch"];
  }
  return view;
}

/**
 * TECH-SPEC §7.2's record rule, as ReplicatedSpace.verifyRecord applies it.
 * `issuerPublicRaw` must always be the 32-byte key of the record's issuing
 * peer. Without a certificate the record signature verifies under that peer
 * key. With one, the certificate must verify under the peer key for exactly
 * this issuer, judged at the record's own issue stamp (v0.1.13: signing time,
 * not receipt; `nowMillis` bounds how far that stamp may lead), and the record
 * signature must then verify under the certificate's agent key: a record that
 * arrives with a certificate but a peer-key signature is refused.
 */
export function verifyRecord(record: Dict, issuerPublicRaw: unknown, certificate: unknown,
                             nowMillis: number): boolean {
  if (!(issuerPublicRaw instanceof Uint8Array) || issuerPublicRaw.length !== 32) {
    return false;
  }
  const issuer = record["issuer"];
  if (typeof issuer !== "string" || !issuer.startsWith(deriveId(issuerPublicRaw) + "/")) {
    return false;
  }
  const signature = record["sig"];
  if (!(signature instanceof Uint8Array)) {
    return false;
  }
  const view = dumps(signViewOf(record));
  if (certificate === null || certificate === undefined) {
    return Identity.verify(issuerPublicRaw, view, signature);
  }
  let signedAt: number;
  try {
    signedAt = hlcPhysical(record["issued"]);
  } catch {
    return false;
  }
  if (!verifyAgentCertificateAt(certificate, issuerPublicRaw, issuer, signedAt, nowMillis)) {
    return false;
  }
  return Identity.verify((certificate as Dict)["agentPublicKey"] as Uint8Array, view, signature);
}

function sortedDots(dots: Dict[]): Dict[] {
  return [...dots].sort((a, b) => {
    const ra = String(a["replica"] ?? "");
    const rb = String(b["replica"] ?? "");
    if (ra !== rb) return ra < rb ? -1 : 1;
    return Number(a["counter"] ?? 0) - Number(b["counter"] ?? 0);
  });
}

/**
 * ReplicatedSpace's StateSignView (SPEC §11a): the mutable state the actor
 * signs so a receiver can authenticate a completion, removal, or lease. Field
 * order and dot sorting match the Java record exactly.
 */
export function stateSignView(spaceId: string, entryId: string, adds: Dict[],
                              removes: Dict[], leaseStamp: string,
                              leaseValue: Dict, completed: boolean,
                              signer: string | null = null,
                              signedAt: string | null = null): Dict {
  // An agent-signed state (v0.1.13, SPEC §11a.4) appends signer and signedAt;
  // a peer-signed one omits them and keeps its bytes.
  const view: Dict = { spaceId, entryId, adds: sortedDots(adds), removes: sortedDots(removes),
    leaseStamp, leaseValue, completed };
  if (signer !== null) {
    view["signer"] = signer;
  }
  if (signedAt !== null) {
    view["signedAt"] = signedAt;
  }
  return view;
}

/**
 * Signs a state DTO's mutable fields as its actor and returns the DTO. With
 * `agent` the agent signs (SPEC §11a.4, v0.1.13): the DTO names it as
 * `signer`, stamps `signedAt`, and carries the certificate covering that time
 * as `stateCertificate`; the peer's own transitions stay byte-identical.
 */
export function signState(dto: Dict, identity: Identity, agent: AgentIdentity | null = null,
                          nowMillis?: number): Dict {
  const record = (dto["record"] ?? {}) as Dict;
  let signer: string | null = null;
  let signedAt: string | null = null;
  let certificate: Dict | null = null;
  if (agent !== null) {
    signer = agent.agentId;
    signedAt = hlcNow(agent.agentId, nowMillis);
    certificate = agent.certificateCovering(hlcPhysical(signedAt));
    if (certificate === null) {
      throw new Error(`${agent.agentId} holds no certificate covering ${signedAt}`);
    }
  }
  const view = stateSignView(String(record["spaceId"]), String(record["entryId"]),
    (dto["adds"] ?? []) as Dict[], (dto["removes"] ?? []) as Dict[],
    String(dto["leaseStamp"]), dto["leaseValue"] as Dict, Boolean(dto["completed"]),
    signer, signedAt);
  const signed: Dict = {};
  for (const [key, value] of Object.entries(dto)) {
    if (!["stateSig", "agentCertificate", "stateCertificate", "signer", "signedAt"].includes(key)) {
      signed[key] = value;
    }
  }
  // EntryStateDto field order: ... stateSig, agentCertificate, stateCertificate, signer, signedAt.
  signed["stateSig"] = (agent ?? identity).sign(dumps(view));
  if (dto["agentCertificate"] !== undefined && dto["agentCertificate"] !== null) {
    signed["agentCertificate"] = dto["agentCertificate"];
  }
  if (agent !== null) {
    signed["stateCertificate"] = certificate;
    signed["signer"] = signer;
    signed["signedAt"] = signedAt;
  }
  return signed;
}

/**
 * Builds a full write delta; returns the entry id and the rumor body. With
 * `agent` (v0.1.13) the record is the agent's own: signed by its key, the
 * certificate covering its stamp attached, and the state agent-signed.
 */
export function entryDelta(spaceName: string, group: string, typeName: string,
                           payload: Uint8Array, identity: Identity,
                           agentName: string, leaseMillis: number,
                           agent: AgentIdentity | null = null, nowMillis?: number,
                           tags: Dict = {}):
    { entryId: string; body: Buffer } {
  const entryId = randomUUID();
  const spaceId = spaceIdLocal(`${group}/${spaceName}`);
  const issuer = agent !== null ? agent.agentId : identity.agent(agentName);
  const issued = hlcNow(issuer, nowMillis);
  const view = signView(entryId, spaceId, typeName, payload, issuer, issued, null, tags);
  let certificate: Dict | null = null;
  if (agent !== null) {
    certificate = agent.certificateCovering(hlcPhysical(issued));
    if (certificate === null) {
      throw new Error(`${issuer} holds no certificate covering ${issued}`);
    }
  }
  const signature = (agent ?? identity).sign(dumps(view));
  const expires = (nowMillis ?? Date.now()) + leaseMillis;
  const lease: Dict = { holder: issuer, expiresAtMillis: expires, kind: "WRITE" };
  const record: Dict = {
    entryId, spaceId, type: typeName, payload, payloadRef: null, issuer,
    issued, lease, tags: view["tags"], sig: signature,
  };
  const adds = [{ replica: identity.peerId, counter: 1 }];
  const leaseValue: Dict = { holder: issuer, expiresAtMillis: expires, kind: "WRITE" };
  const unsigned: Dict = {
    record,
    issuerPublicKey: identity.publicRaw,
    adds,
    removes: [],
    leaseStamp: issued,
    leaseValue,
    completed: false,
  };
  if (certificate !== null) {
    unsigned["agentCertificate"] = certificate;
  }
  // The issuer authenticates the whole mutable state (SPEC §11a).
  const dto = signState(unsigned, identity, agent, nowMillis);
  const delta = dumps({ state: dto, claimEntry: null, claim: null });
  return { entryId, body: rumorBody(`space:${spaceName}`, `w:${entryId}`, 6, delta) };
}

// --------------------------------------------------------------- take claims

/**
 * A TakeClaim in field order: entryId, spaceId, epoch, stamp, holder, bid,
 * expiresAtMillis. entryId and spaceId are signed bindings (ASF-002), so a
 * signed claim cannot be transplanted onto another entry. The bid encodes as a
 * CBOR double.
 */
export function takeClaim(entryId: string, spaceId: string, epoch: number,
                          stamp: string, holder: string,
                          bid: number, expiresAtMillis: number): Dict {
  return { entryId, spaceId, epoch, stamp, holder,
    bid: new CborDouble(bid), expiresAtMillis };
}

/**
 * A SignedClaim: the claim, the holder's *peer* key, the holder's signature.
 * With `agent` the signature is the agent key's and the peer's certificate
 * rides beside it in the appended `holderCertificate` field (QA4 A4-7
 * phase 3); without it the proof is byte-identical to before.
 */
export function signedClaim(claim: Dict, identity: Identity,
                            agent: AgentIdentity | null = null): Dict {
  const signed: Dict = { claim, holderKey: identity.publicRaw,
    signature: (agent ?? identity).sign(dumps(claim)) };
  if (agent !== null) {
    // v0.1.13: the certificate covering the claim's stamp, at which receivers judge it.
    const certificate = agent.certificateCovering(hlcPhysical(claim["stamp"]));
    if (certificate === null) {
      throw new Error(`${agent.agentId} holds no certificate covering ${String(claim["stamp"])}`);
    }
    signed["holderCertificate"] = certificate;
  }
  return signed;
}

/**
 * TECH-SPEC §7.6's proof rule, as ReplicatedSpace.verifyClaim applies it.
 * `holderKey` is always the holder's 32-byte peer key and must hash to the
 * claim's holder peer. Without a certificate the signature verifies under that
 * key; with one, the certificate must verify under the peer key for exactly the
 * claim's holder at the claim's own stamp (not at `nowMillis`, which only
 * bounds how far ahead that stamp may run) and the signature under the
 * certificate's agent key. The entry and space bindings are the caller's.
 */
export function verifyClaimProof(signed: Dict, nowMillis: number): boolean {
  const claim = signed["claim"];
  const holderKey = signed["holderKey"];
  const signature = signed["signature"];
  if (typeof claim !== "object" || claim === null || !(holderKey instanceof Uint8Array)
      || holderKey.length !== 32 || !(signature instanceof Uint8Array)) {
    return false;
  }
  const holder = (claim as Dict)["holder"];
  if (typeof holder !== "string" || !holder.startsWith(deriveId(holderKey) + "/")) {
    return false;
  }
  const certificate = signed["holderCertificate"];
  if (certificate === undefined || certificate === null) {
    return Identity.verify(holderKey, dumps(claim as Dict), signature);
  }
  let stamped: number;
  try {
    stamped = hlcPhysical((claim as Dict)["stamp"]);
  } catch {
    return false;
  }
  // v0.1.13: judged at the claim's own stamp, which a renewal keeps.
  if (!verifyAgentCertificateAt(certificate, holderKey, holder, stamped, nowMillis)) {
    return false;
  }
  return Identity.verify((certificate as Dict)["agentPublicKey"] as Uint8Array,
    dumps(claim as Dict), signature);
}

/** A claim-only Delta, as tryTakeOnce publishes it. */
export function claimDelta(entryId: string, signed: Dict): Buffer {
  return dumps({ state: null, claimEntry: entryId, claim: signed });
}

function hlcTuple(stamp: string): [number, number, string] {
  const first = stamp.indexOf(":");
  const second = stamp.indexOf(":", first + 1);
  return [Number(stamp.slice(0, first)),
    Number(stamp.slice(first + 1, second)), stamp.slice(second + 1)];
}

function num(value: CborValue): number {
  return value instanceof CborDouble ? value.value : Number(value ?? 0);
}

/** Coerces a claim's numeric field for validation; NaN for non-numbers. */
export function claimNumber(value: CborValue): number {
  if (typeof value === "number") {
    return value;
  }
  if (value instanceof CborDouble) {
    return value.value;
  }
  if (typeof value === "bigint") {
    return Number(value);
  }
  return Number.NaN;
}

/**
 * Compares two claims by the lattice's total order (spec §7.4): negative when
 * {@code a} wins. Epoch descending, bid ascending, HLC stamp ascending,
 * holder ascending, expiry descending; identical to TakeClaim.merge.
 */
export function compareClaims(a: Dict, b: Dict): number {
  if (num(a["epoch"]) !== num(b["epoch"])) {
    return num(b["epoch"]) - num(a["epoch"]);
  }
  if (num(a["bid"]) !== num(b["bid"])) {
    return num(a["bid"]) - num(b["bid"]);
  }
  const [ap, al, an] = hlcTuple(String(a["stamp"]));
  const [bp, bl, bn] = hlcTuple(String(b["stamp"]));
  if (ap !== bp) {
    return ap - bp;
  }
  if (al !== bl) {
    return al - bl;
  }
  if (an !== bn) {
    return an < bn ? -1 : 1;
  }
  if (String(a["holder"]) !== String(b["holder"])) {
    return String(a["holder"]) < String(b["holder"]) ? -1 : 1;
  }
  return num(b["expiresAtMillis"]) - num(a["expiresAtMillis"]);
}

/** Returns the winning SignedClaim of two, by the lattice order. */
export function mergeClaims(a: Dict | undefined, b: Dict): Dict {
  if (a === undefined) {
    return b;
  }
  return compareClaims(a["claim"] as Dict, b["claim"] as Dict) <= 0 ? a : b;
}
