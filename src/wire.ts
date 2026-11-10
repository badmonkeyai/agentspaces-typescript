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

import { equals, randomUuid, utf8 } from "./bytes.js";
import { cryptoPort } from "./crypto.js";
import { CborDouble, CborValue, canonicalMap, dumps, loads } from "./cbor.js";
import * as records from "./records.js";
import {
  AgentIdentity, Identity, deriveId, spaceIdLocal, verifyAgentCertificateCovering,
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

/**
 * How far before its entry's issue stamp a gossiped claim's stamp may lie: the drift ceiling, as Java's
 * ReplicatedSpace.MAX_CLAIM_PREDATES_ISSUE_MILLIS (HLC round six, 2026-11-08, R6). A claim answers a
 * write, so an honest claimant's clock has absorbed the record's stamp; the allowance covers a writer
 * whose clock ran ahead by up to the ceiling.
 */
export const MAX_CLAIM_PREDATES_ISSUE_MILLIS = MAX_HLC_SKEW_MILLIS;

/**
 * The race allowance a gossiped claim contesting another holder's claim keeps past the drift ceiling:
 * Java's default settle window, 200 ms (HLC round six, 2026-11-08, R6). An honest race settles within it.
 */
export const CLAIM_SETTLE_WINDOW_MILLIS = 200;

/**
 * The largest logical counter a remote stamp may carry (2^16), the bound Java, Rust, Python,
 * TypeScript and Ruby share (HLC logical counter, 2026-11-08, Rust team report). An honest
 * counter resets every millisecond and stays tiny, so every merge point refuses a remote stamp
 * above the limit: the clock never takes it, and the receiver ignores the frame, folded state, or
 * folded claim carrying it. A local increment past the limit carries into the physical part.
 */
export const LOGICAL_LIMIT = 65_536;

/**
 * The receiver's far-future margin (HLC canonical stamps, 2026-11-08): a frame whose physical part
 * lies past the receiver's wall + MAX_HLC_SKEW_MILLIS by at most this much is dropped and counted
 * apart from the far-future drops. Wall-clock skew between two hosts puts an honest peer that a
 * hostile member dragged to its ceiling there, so such a peer loses those frames and no receiver
 * strikes it for them; a frame further ahead is far-future (ASF-020).
 */
export const FAR_FUTURE_MARGIN_MILLIS = 5_000;

/**
 * How far past wall + MAX_HLC_SKEW_MILLIS + FAR_FUTURE_MARGIN_MILLIS a replica defers a folded record,
 * lease stamp or claim stamp before it refuses it as hostile (HLC round four, 2026-11-08, D4), as
 * Java's ReplicatedSpace does. Inside this hour the replica neither merges nor acknowledges the
 * state or claim, nor counts it as misbehaviour: anti-entropy offers it again, and it merges once
 * the receiver's wall catches up, so an honest taker a hostile member dragged ahead is never treated
 * as hostile. Past it the replica refuses and counts it.
 */
export const FAR_FUTURE_HOSTILE_MILLIS = 60 * 60 * 1000;

/** An HLC stamp that {@link decodeHlc} read; its physical part is exact up to 2^63 - 1. */
export interface HlcStamp {
  readonly physical: bigint;
  readonly logical: number;
  readonly node: string;
}

/** The largest physical part, Long.MAX_VALUE: a stamp's physical part fits a signed 64-bit integer. */
const PHYSICAL_MAX = (1n << 63n) - 1n;
/** The largest counter Java's HlcTimestamp.parse reads (Integer.MAX_VALUE). */
const DECODED_LOGICAL_MAX = 2_147_483_647;
/** "0", or a non-zero ASCII digit followed by ASCII digits: one spelling for each number. */
const CANONICAL_DIGITS = /^(?:0|[1-9][0-9]*)$/;
/**
 * A non-empty node holding no colon, no control character (U+0000..U+001F, U+007F), and no lone
 * surrogate (U+D800..U+DFFF outside a pair), which no peer can send as UTF-8 (HLC round five,
 * 2026-11-08, E11).
 */
const CANONICAL_NODE = /^[^:\u0000-\u001f\u007f\p{Cs}]+$/u;
/**
 * The longest stamp, in UTF-16 code units (HLC round seven, 2026-11-08; SPEC §9.1, S6): a stamp is
 * one definite text, and Jackson writes a longer text only in chunks, so no longer text is a stamp.
 */
export const MAX_STAMP_UNITS = 3996;
/**
 * The longest node a clock stamps with: {@link MAX_STAMP_UNITS} less the longest physical part
 * (19 digits), the longest logical part (10 digits) and their two colons (HLC round seven, 2026-11-08).
 */
export const MAX_NODE_UNITS = MAX_STAMP_UNITS - 31;

/**
 * Reads a stamp in the canonical `physical:logical:node` grammar, or returns null (HLC canonical
 * stamps, 2026-11-08). The physical and logical parts are each "0" or a non-zero ASCII digit
 * followed by ASCII digits: no leading zero, sign, fraction, exponent, whitespace, or non-ASCII
 * digit. The physical part fits a signed 64-bit integer, checked and held as a BigInt, so this
 * client orders every physical part Java orders, exactly. The node is non-empty and holds no colon,
 * no control character and no lone surrogate. One spelling per stamp means the bytes a signer
 * signed always equal the stamp's re-encoding, so Java and this client verify the same claims. The
 * counter reads up to
 * Integer.MAX_VALUE, as Java's HlcTimestamp.parse does: the frame decoder, the space-delta decoder
 * and the frame filter's first step read stamps this way, and {@link parseHlc} adds the limit every
 * merge point applies (HLC round four, 2026-11-08). A text past {@link MAX_STAMP_UNITS} UTF-16 units
 * is no stamp, a `pdt.issued` included, since it travels only in Jackson's chunks (HLC round seven,
 * 2026-11-08).
 */
export function decodeHlc(stamp: unknown): HlcStamp | null {
  if (typeof stamp !== "string" || stamp.length > MAX_STAMP_UNITS) {
    return null;
  }
  const first = stamp.indexOf(":");
  const second = first < 0 ? -1 : stamp.indexOf(":", first + 1);
  if (second < 0) {
    return null;
  }
  const physicalText = stamp.slice(0, first);
  const logicalText = stamp.slice(first + 1, second);
  const node = stamp.slice(second + 1);
  if (!CANONICAL_DIGITS.test(physicalText) || !CANONICAL_DIGITS.test(logicalText) || !CANONICAL_NODE.test(node)) {
    return null;
  }
  // Canonical digits have no leading zero, so the lengths bound the values before any is read.
  if (physicalText.length > 19 || logicalText.length > 10) {
    return null;
  }
  const physical = BigInt(physicalText);
  const logical = Number(logicalText);
  if (physical > PHYSICAL_MAX || logical > DECODED_LOGICAL_MAX) {
    return null;
  }
  return { physical, logical, node };
}

/**
 * Parses an acceptable HLC stamp, or returns null when a merge point must refuse it: the canonical
 * grammar of {@link decodeHlc} with a logical counter from 0 to LOGICAL_LIMIT (HLC logical counter,
 * 2026-11-08, Rust team report; HLC canonical stamps, 2026-11-08). Every merge and ordering point
 * shares this one parser: the clock, the state and claim folds, the lease join, the claim lattice,
 * and the frame filter's last step.
 */
export function parseHlc(stamp: unknown): HlcStamp | null {
  const decoded = decodeHlc(stamp);
  return decoded === null || decoded.logical > LOGICAL_LIMIT ? null : decoded;
}

/**
 * How far in the past a frame's stamp may be before it is dropped as stale, and how many
 * (sender, stamp) pairs the replay filter remembers (ROBUSTNESS.md §3.3, §3.4; the Java
 * node's MAX_FRAME_AGE_MILLIS and its recent-frames cache).
 */
export const MAX_FRAME_AGE_MILLIS = 5 * 60 * 1000;
export const FRAME_FILTER_CAPACITY = 4096;

/**
 * Admits each verified frame once, fresh, judging its stamp in SPEC §9's order against this
 * client's wall time (HLC canonical stamps, 2026-11-08). First it decodes the stamp, and one that
 * {@link decodeHlc} refuses counts as `framesUndecodable` and meets no time check; a peer's frame
 * decoder already drops such a frame as malformed, as Java's does. Then it drops a stamp older than
 * MAX_FRAME_AGE_MILLIS as `stale` and a (sender, stamp) pair seen before as `replayed`: late and
 * duplicated frames are the normal case on a network, and anyone can replay a frame its author
 * signed. The later checks judge a fresh frame only its sender could have produced. A stamp past
 * wall + MAX_HLC_SKEW_MILLIS by at most FAR_FUTURE_MARGIN_MILLIS counts as `framesFarFutureSkewed`,
 * and one further ahead as `framesFarFuture` (ASF-020). A counter above LOGICAL_LIMIT counts as
 * `framesLogicalRefused`. The counters carry the names of Java's PeerNode counters (HLC round
 * four, 2026-11-08, D5). This client keeps no strikes against frame senders, so each count records
 * its drop.
 */
export class FrameFilter {
  private readonly seen = new Set<string>();
  stale = 0;
  /** Far-future frames past the margin (ASF-020): Java strikes their senders. */
  framesFarFuture = 0;
  /** Far-future frames inside FAR_FUTURE_MARGIN_MILLIS: Java strikes nobody for them. */
  framesFarFutureSkewed = 0;
  replayed = 0;
  /** Frames whose stamp decodes with a counter above LOGICAL_LIMIT. */
  framesLogicalRefused = 0;
  /** Frames whose stamp does not decode at all (HLC round four, 2026-11-08). */
  framesUndecodable = 0;

  constructor(private readonly capacity: number = FRAME_FILTER_CAPACITY) {}

  admit(env: Dict, nowMillis: number): boolean {
    const stamp = decodeHlc(env["stamp"]);
    if (stamp === null) {
      this.framesUndecodable += 1;
      return false;
    }
    const now = BigInt(Math.trunc(nowMillis));
    if (now - stamp.physical > BigInt(MAX_FRAME_AGE_MILLIS)) {
      this.stale += 1;
      return false;
    }
    // A canonical stamp has one spelling, so its text keys the replay set.
    const key = `${String(env["from"])}|${String(env["stamp"])}`;
    if (this.seen.has(key)) {
      this.replayed += 1;
      return false;
    }
    this.seen.add(key);
    if (this.seen.size > this.capacity) {
      const eldest = this.seen.values().next().value;
      if (eldest !== undefined) {
        this.seen.delete(eldest);
      }
    }
    const lead = stamp.physical - now - BigInt(MAX_HLC_SKEW_MILLIS);
    if (lead > 0n) {
      if (lead <= BigInt(FAR_FUTURE_MARGIN_MILLIS)) {
        this.framesFarFutureSkewed += 1;
      } else {
        this.framesFarFuture += 1;
      }
      return false;
    }
    if (stamp.logical > LOGICAL_LIMIT) {
      this.framesLogicalRefused += 1;
      return false;
    }
    return true;
  }
}

const hlcState = new Map<string, [number, number]>();

/**
 * The clock state of `node`, which must be a node the canonical grammar accepts: non-empty, with no
 * colon, no control character, and no lone surrogate (HLC round five, 2026-11-08, E11). A peer
 * therefore never emits a stamp another implementation refuses for its node (HLC round four,
 * 2026-11-08, D6); an agent named with a colon fails here, at its first stamp.
 */
function clockOf(node: string): [number, number] {
  if (!CANONICAL_NODE.test(node)) {
    throw new Error(`not an HLC node (empty, a colon, a control character, or a lone surrogate): ${JSON.stringify(node)}`);
  }
  if (node.length > MAX_NODE_UNITS) {
    // HLC round seven, 2026-11-08: every stamp this clock issues stays one definite text
    throw new Error(`an HLC node holds at most ${MAX_NODE_UNITS} UTF-16 units: ${node.length}`);
  }
  return hlcState.get(node) ?? [0, -1];
}

/**
 * A fresh hybrid-logical-clock stamp in the Java string form: physical time
 * never runs backwards, and the logical counter increments within one
 * millisecond, so two stamps from the same node never collide and stamps
 * after an observed remote stamp sort after it (ASF-043). An increment that
 * would pass LOGICAL_LIMIT carries instead: the physical part advances one
 * millisecond and the counter resets to 0, so the clock never returns the
 * same stamp twice (HLC logical counter, 2026-11-08, Rust team report).
 * Throws when `node` breaks the stamp grammar (HLC round four, 2026-11-08, D6).
 */
export function hlcNow(node: string, nowMillis?: number): string {
  const wall = nowMillis ?? Date.now();
  let [physical, logical] = clockOf(node);
  if (wall > physical) {
    physical = wall;
    logical = 0;
  } else if (logical < LOGICAL_LIMIT) {
    logical += 1;
  } else {
    physical += 1;
    logical = 0;
  }
  hlcState.set(node, [physical, logical]);
  return `${physical}:${logical}:${node}`;
}

/**
 * The physical milliseconds of an HLC stamp string: its signing time; throws when parseHlc refuses
 * it. A physical part past 2^53 reads as the nearest double, which still lies past every wall-clock
 * time a caller judges a signing time against; stamps order by {@link compareHlc}, exactly.
 */
export function hlcPhysical(stamp: unknown): number {
  return Number(requireHlc(stamp).physical);
}

/**
 * The physical milliseconds of a stamp {@link decodeHlc} reads, or null: the signing time a receiver
 * judges a certificate at. A counter above LOGICAL_LIMIT still decodes, so a record, state or claim
 * carrying one verifies first and its refusal is then counted against its signer, as in Java (HLC
 * round four, 2026-11-08, D5).
 */
export function decodedPhysical(stamp: unknown): number | null {
  const decoded = decodeHlc(stamp);
  return decoded === null ? null : Number(decoded.physical);
}

/** The parsed stamp, or an error naming it when {@link parseHlc} refuses it. */
function requireHlc(stamp: unknown): HlcStamp {
  const parsed = parseHlc(stamp);
  if (parsed === null) {
    throw new Error(`not an acceptable HLC stamp: ${String(stamp)}`);
  }
  return parsed;
}

/**
 * Merges a remote stamp into the local clock so later local stamps sort after
 * everything observed. The clock ignores a stamp that {@link parseHlc} refuses:
 * one counter above LOGICAL_LIMIT near the skew ceiling, or one of -1e300, froze
 * the clock, since adding one to such a number changes nothing (HLC logical
 * counter, 2026-11-08, Rust team report). A remote physical merges clamped at
 * wall + MAX_HLC_SKEW_MILLIS - 1, one millisecond inside the cap: a hostile
 * far-future stamp cannot pin this clock (ASF-020), and a carry after the merge
 * lands at most on the cap, which a receiver's strict greater-than check admits.
 * `nowMillis` is the caller's clock (a peer's), which sets the cap; wall time
 * by default. Throws when `node` breaks the stamp grammar (HLC round four, 2026-11-08, D6).
 */
export function hlcObserve(node: string, stamp: unknown, nowMillis?: number): void {
  const [currentPhysical, currentLogical] = clockOf(node);
  const parsed = parseHlc(stamp);
  if (parsed === null) {
    return;
  }
  const cap = BigInt(Math.trunc(nowMillis ?? Date.now()) + MAX_HLC_SKEW_MILLIS - 1);
  const physical = Number(parsed.physical < cap ? parsed.physical : cap);
  const logical = parsed.logical;
  if (physical > currentPhysical
      || (physical === currentPhysical && logical > currentLogical)) {
    hlcState.set(node, [physical, logical]);
  }
}

/**
 * Compares two HLC stamps in the Java string form; positive when a > b, as Java's
 * HlcTimestamp.compareTo orders every stamp its parse reads. The order is total: a stamp
 * {@link decodeHlc} refuses sorts before every stamp it reads, and two refused stamps compare as
 * strings (HLC logical counter, 2026-11-08, Rust team report). The folds refuse such stamps, so
 * held state never carries one; the order only keeps a sort over unchecked text sound.
 */
export function compareHlc(a: unknown, b: unknown): number {
  const pa = decodeHlc(a);
  const pb = decodeHlc(b);
  if (pa === null || pb === null) {
    if (pa !== null || pb !== null) {
      return pa === null ? -1 : 1;
    }
    const sa = String(a), sb = String(b);
    return sa < sb ? -1 : sa > sb ? 1 : 0;
  }
  return compareParsed(pa, pb);
}

/**
 * Java's HlcTimestamp.compareTo: physical, then logical, then node. The physical parts compare as
 * BigInts, exactly to 2^63 - 1, and the nodes by UTF-16 code unit, as Java's String.compareTo does.
 */
function compareParsed(a: HlcStamp, b: HlcStamp): number {
  if (a.physical !== b.physical) {
    return a.physical < b.physical ? -1 : 1;
  }
  if (a.logical !== b.logical) {
    return a.logical - b.logical;
  }
  return a.node < b.node ? -1 : a.node > b.node ? 1 : 0;
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
export function groupAdBody(signed: Dict): Uint8Array {
  return dumps(signed);
}

/**
 * The body of a `RELAY_FRAME` (SPEC §5.4; SRAD srad/agentspaces-js.md JS-W-03): a peerID `target`
 * and the origin's fully signed inner `frame`, which a RELAY-role member forwards verbatim to the
 * target. Byte-identical to Java's `Bodies.RelayFrame(target, frame)` record (component order).
 */
export function relayFrameBody(target: string, frame: Uint8Array, path: string[] | null = null,
                               hop: number | null = null): Uint8Array {
  if (path === null) {
    return dumps({ target, frame });
  }
  // SPEC v0.1.23 §5.4: `path` is the relays to traverse and `hop` the index of the relay this
  // envelope is addressed to; both absent in the one-hop form (Java writes them NON_NULL).
  return dumps({ target, frame, path: [...path], hop: hop ?? 0 });
}

/** The capability a relay signals an origin on when the next hop of a path could not carry its frame. */
export const RELAY_SIGNAL_CAPABILITY = "aspace:cap/relay-signal";

/** The PIPE_DATA body of an unreachable signal (SPEC v0.1.23 §5.4). */
export function relaySignalBody(target: string, failedHop: string, reason = "unreachable"): Uint8Array {
  return dumps({ capability: RELAY_SIGNAL_CAPABILITY,
    payload: dumps({ target, failedHop, reason }) });
}

/** Payloads above this travel as a block or an artifact and the record carries a reference (SPEC §7.1). */
export const INLINE_PAYLOAD_LIMIT = 64 * 1024;

/** A BLOCK_WANT body: one block by id. */
export function blockWantBody(cid: string): Uint8Array {
  return dumps({ cid });
}

/** A BLOCK body: the bytes under their id. */
export function blockBody(cid: string, bytes: Uint8Array): Uint8Array {
  return dumps({ cid, bytes });
}

/** Signs and encodes an envelope into a frame (WireCodec.Signed). */
export function encodeFrame(env: Dict, identity: Identity): Uint8Array {
  const canonical = dumps(env);
  return dumps({
    envelope: env,
    senderPublicKey: identity.publicRaw,
    signature: identity.sign(canonical),
  });
}

/** The Signed wrapper of a frame decoded without any verification (tests and diagnostics). */
export function loadsSigned(frame: Uint8Array): CborValue {
  return loads(frame);
}

/** The crypto port in use, re-exported for callers that already import the wire. */
export { cryptoPort } from "./crypto.js";

/** How a decoded frame was authenticated (WireCodec.Auth). */
export type Auth = "SIGNED" | "ATTESTED" | "SESSION";

/** An established session on one connection: the peer it attests and the key its frames carry a tag under. */
export type EstablishedSession = { peer: string; key: Uint8Array };

/** What a connection knows about its remote end, for the decoder. */
export type Channel = { attestedPeer?: string | null; session?: EstablishedSession | null };

/** Decodes and verifies a fully signed frame; returns the envelope or null. */
export function decodeFrame(frame: Uint8Array): Dict | null {
  const decoded = decodeFrameDetailed(frame, {});
  return decoded === null ? null : decoded.env;
}

/**
 * WireCodec.decodeDetailed: a frame with a key and a signature verifies under
 * the key; one with neither is accepted when the channel attested its sender;
 * one with no key and a 32-byte tag is a session frame, accepted when the
 * channel's session names its sender and the tag verifies under the session
 * key (SPEC §5.6, v0.1.17). A hello is accepted only fully signed.
 *
 * HLC round six, 2026-11-08 (F3): the frame is read in the wire encoding's order of steps. The
 * document must pass the item rules; a frame of another `ver` is dropped before anything else, so a
 * later version still coexists; the frame must then hold exactly the fields of WireCodec.Signed and
 * Envelope with their declared kinds, and re-encoding it must give exactly the bytes received. Only
 * then does a signature or tag verify, over the envelope's bytes as they arrived. Last, the body
 * must read strictly as its kind's record ({@link decodeBody}), or the frame is undecodable
 * (vectors frame-23 to frame-26).
 */
export function decodeFrameDetailed(frame: Uint8Array, channel: Channel): { env: Dict; auth: Auth; body: Dict } | null {
  const verified = verifyFrame(frame, channel);
  if (verified === null) {
    return null;
  }
  const body = decodeBody(verified.env);
  return body === null ? null : { ...verified, body };
}

/** The envelope and how it authenticated, for {@link decodeFrameDetailed}, or null. */
function verifyFrame(frame: Uint8Array, channel: Channel): { env: Dict; auth: Auth } | null {
  let decoded: CborValue;
  try {
    decoded = loads(frame);
  } catch {
    return null;
  }
  const arrived = decoded as Dict;
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded) || decoded instanceof Uint8Array
      || decoded instanceof CborDouble || typeof arrived["envelope"] !== "object" || arrived["envelope"] === null
      || (arrived["envelope"] as Dict)["ver"] !== WIRE_VERSION) {
    return null;
  }
  let signed: Dict;
  try {
    signed = records.conform(decoded, records.SIGNED_FRAME) as Dict;
  } catch {
    return null;
  }
  const envelopeBytes = dumps(signed["envelope"] as Dict);
  if (!equals(dumps(signed), frame)) {
    return null;
  }
  const env = signed["envelope"] as Dict;
  const key = signed["senderPublicKey"];
  const signature = signed["signature"];
  const kind = env["kind"];
  const hello = kind === "SESSION_HELLO" || kind === "CHANNEL_HELLO";
  if (key === null && signature === null) {
    const attested = channel.attestedPeer ?? null;
    return !hello && attested !== null && attested === env["from"] ? { env, auth: "ATTESTED" } : null;
  }
  if (key === null && signature instanceof Uint8Array) {
    const session = channel.session ?? null;
    if (hello || session === null || signature.length !== 32 || session.peer !== env["from"]) {
      return null;
    }
    const expected = cryptoPort().hmacSha256(session.key, envelopeBytes);
    return equals(expected, signature) ? { env, auth: "SESSION" } : null;
  }
  if (!(key instanceof Uint8Array) || key.length !== 32 || !(signature instanceof Uint8Array)) {
    return null;
  }
  if (deriveId(key) !== env["from"] || !Identity.verify(key, envelopeBytes, signature)) {
    return null;
  }
  return { env, auth: "SIGNED" };
}

/**
 * The body of a verified envelope as its kind's record, or null when the body is undecodable, which
 * makes the frame undecodable (HLC round six, 2026-11-08, F3). A kind whose body this client never
 * reads, and GROUP_AD_WANT, whose body is empty, decode to an empty map.
 */
export function decodeBody(env: Dict): Dict | null {
  const schema = records.BODIES.get(String(env["kind"]));
  if (schema === undefined) {
    return {};
  }
  return records.readRecord(env["body"], schema);
}

// -------------------------------------------------------------------- bodies

export function pingBody(nonce: number | bigint): Uint8Array {
  return dumps({ nonce });
}

export function ackBody(nonce: number | bigint): Uint8Array {
  return dumps({ nonce, onBehalf: null });
}

export function rumorBody(streamId: string, itemId: string, hops: number,
                          payload: Uint8Array): Uint8Array {
  return dumps({ streamId, itemId, hopsRemaining: hops, payload });
}

/** Bodies.ChannelHello (SPEC §5.6): this peer accepts channel-attested frames on the connection whose remote end it attested as `attestedRemote`. */
export function channelHelloBody(acceptsBare: boolean, attestedRemote: string): Uint8Array {
  return dumps({ acceptsBare, attestedRemote });
}

/**
 * A DIGEST body. Its `digests` map is a protocol map field, so it goes out in the RFC 8949 key order
 * (`peers` before `space:<name>`), which a strict receiver requires (HLC round six, 2026-11-08, P2).
 */
export function digestBody(digests: Dict): Uint8Array {
  return dumps({ digests: canonicalMap(digests) });
}

/**
 * A PeerAdvertisement with no endpoints: the dial-only NAT posture. The
 * resource hints are the free-form string map every member reads
 * (`aspace:join` carries a join credential, SPEC §5.1/§6.1).
 */
export function peerAdvertisement(group: string, identity: Identity,
                                  issuedIso: string, ttlIso = "PT10M",
                                  resourceHints: { [key: string]: string } = {}): Dict {
  return {
    id: `aspace://${group}/peer/${identity.peerId}`,
    issuer: identity.peerId,
    group,
    issued: issuedIso,
    ttl: ttlIso,
    endpoints: [],
    roles: [],
    resourceHints: canonicalMap(resourceHints),
  };
}

/** The 'peers' stream payload: PeerNode.SignedPeerAd. */
export function signedPeerAd(ad: Dict, identity: Identity): Uint8Array {
  const adBytes = dumps(records.conform(ad, records.PEER_ADVERTISEMENT)); // P1 and P2, HLC round six, 2026-11-08
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
                          agentCertificate: Dict | null = null,
                          ui: Dict | null = null): Dict {
  const agent = identity.agent(localName);
  const card: Dict = { id: `aspace://${group}/agent/${agent}`, issuer: identity.peerId,
    group, issued: issuedIso, ttl: ttlIso, agent, description, goals, consumes,
    produces, costHints: canonicalMap(costHints), spaceBindings: canonicalMap(spaceBindings) };
  if (agentCertificate !== null && (agentPublicKey === null
      || agentCertificate["agent"] !== agent
      || !equals(agentCertificate["agentPublicKey"] as Uint8Array, agentPublicKey))) {
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
  if (ui !== null) {
    card["ui"] = ui; // v0.1.26 (ISSUE-UiComponents): what the agent can show
  }
  return card;
}

/** One component of a UiDeclaration in Java field order (SPEC §6.1a.3): id, catalogId, component, entry, controls, role. */
export function uiComponent(id: string, catalogId: string, component: string, entry = "", controls: string[] = [],
                            role: "panel" | "control" | "row" = "panel"): Dict {
  return { id, catalogId, component, entry, controls, role };
}

/**
 * The host group of a published AppCard in Java field order (SPEC §6.1a.4, v0.1.28): url, port, hostAgent, path,
 * signOn, publishedBy, publishedAt, status (serving or stopped). It follows `ui` on the card; a card without it keeps
 * its bytes. `signOn` is `idp`, the identity provider of whoever runs the host, enforced at its door, or `none`
 * (v0.1.32; AppCard origin and formats, 2026-11-09).
 */
export function appCardHost(url: string, port = 0, hostAgent = "", path = "/", signOn: "idp" | "none" = "idp",
                            publishedBy = "", publishedAtIso = "", status: "serving" | "stopped" = "serving"): Dict {
  if (!url) throw new Error("a host has a url");
  if (port < 0 || port > 65535) throw new Error("a host's port is 0 to 65535");
  if (!(records.APP_CARD_SIGN_ONS as readonly string[]).includes(signOn)) throw new Error("a host's signOn is idp or none");
  if (status !== "serving" && status !== "stopped") throw new Error("a host's status is serving or stopped");
  return { url, port, hostAgent, path: path || "/", signOn, publishedBy, publishedAt: publishedAtIso, status };
}

// ------------------------------------------- AppCard origin, formats, and the card spill (§6.1a.2, §6.1a.5)

/** A card whose encoding is more than this many bytes spills: the inline limit of a payload (SPEC §7.1, §6.1a.5). */
export const CARD_SPILL_THRESHOLD_BYTES = 65_536;
/** A publisher warns once a card's encoding passes this many bytes (56 KiB), just before it spills. */
export const CARD_SPILL_WARN_BYTES = 57_344;
/** The piece size of a parts document, so every implementation computes the same root for the same bytes. */
export const CARD_SPILL_PIECE_SIZE = 65_536;
/** The default bound on a parts document a reader fetches. */
export const CARD_SPILL_MAX_FETCH_BYTES = 16_777_216;
/** The largest `spill.size`: 2^53 - 1, the largest integer every implementation holds exactly. */
export const CARD_SPILL_MAX_SIZE = Number.MAX_SAFE_INTEGER;

/**
 * An AppCard's origin in Java field order (SPEC §6.1a.2, v0.1.32; AppCard origin and formats, 2026-11-09): the
 * external system the app came from, its id there, its version there (`""` when the system names none), and the
 * registry's attributes, keyed `<system>.<name>` and written in the wire's map order; an empty map is stored as
 * absent. The values are open (`agentspaces-spec/REGISTRY.md`); throws when one breaks a bound or grammar.
 */
export function appCardOrigin(system: string, ref: string, version = "",
                              attrs: { [key: string]: string } | null = null): Dict {
  const origin: Dict = { system, ref, version };
  if (attrs !== null && Object.keys(attrs).length > 0) {
    origin["attrs"] = attrs;
  }
  return records.conform(origin, records.APP_CARD_ORIGIN, "origin") as Dict;
}

/**
 * An AppCard's formats normalised as Java's `withFormats` does (FR-3): a media type lower-cased, a repeated entry
 * dropped after its first occurrence, the issuer's order kept, and an empty or null list stored as absent (null).
 * Throws when an entry breaks the rules a reader applies.
 */
export function appCardFormats(formats: readonly string[] | null): string[] | null {
  if (formats === null || formats.length === 0) {
    return null;
  }
  const normalised = [...new Set(formats.map((f) => (f.includes(":") ? f : f.toLowerCase())))];
  records.checkFormats(normalised, "formats");
  return normalised;
}

/**
 * Whether an AppCard came from an origin system (FR-8), and with `ref` from that ref: a `ref` ending in `/*` matches
 * every ref that starts with the part before `*`. `origin` never spills, so a stub reads as its full card.
 */
export function fromOrigin(card: Dict, system: string, ref?: string): boolean {
  const origin = card["origin"] as Dict | undefined;
  if (origin === undefined || origin["system"] !== system) {
    return false;
  }
  if (ref === undefined) {
    return true;
  }
  const held = String(origin["ref"]);
  return ref.endsWith("/*") ? held.startsWith(ref.slice(0, -1)) : held === ref;
}

/**
 * Whether an AppCard reads or renders a format (FR-8): a media type argument is lower-cased and matches an entry
 * exactly, `type/*` matches every media type of that type, and a vocabulary IRI matches exactly.
 */
export function handles(card: Dict, format: string): boolean {
  const formats = card["formats"] as string[] | undefined;
  if (formats === undefined) {
    return false;
  }
  if (format.includes(":")) {
    return formats.includes(format);
  }
  const wanted = format.toLowerCase();
  if (wanted.endsWith("/*")) {
    const type = wanted.slice(0, -1);
    return formats.some((f) => !f.includes(":") && f.startsWith(type));
  }
  return formats.includes(wanted);
}

/**
 * The AppCard a view may receive (FR-7): the card itself while every member reads the AppCard level, and otherwise
 * the card without `origin`, `formats`, and a host whose `signOn` is `idp`; a `none` host reads at level 1 and stays.
 */
export function appCardForView(card: Dict, gateOpen: boolean): Dict {
  if (card["spill"] !== undefined) {
    throw new Error("the gate applies to a full card; a stub exists only behind an open gate");
  }
  if (gateOpen) {
    return card;
  }
  const out: Dict = { ...card };
  delete out["origin"];
  delete out["formats"];
  if ((out["host"] as Dict | undefined)?.["signOn"] === "idp") {
    delete out["host"];
  }
  return out;
}

/** Which of the two spilling kinds a card is: an AppCard names its shape, an AgentCard its agent. */
export function spillKindOf(card: Dict): "AppCard" | "AgentCard" {
  if ("shape" in card) {
    return "AppCard";
  }
  if ("agent" in card) {
    return "AgentCard";
  }
  throw new Error("only an AppCard and an AgentCard spill");
}

/** The non-empty spill-set fields of a full card, in its field order: what its stub's `spill.parts` lists. */
export function cardSpillParts(card: Dict): string[] {
  return nonEmptyParts(spillKindOf(card), cardParts(card));
}

/** The non-empty fields of a parts record, in the kind's field order: what `spill.parts` lists. */
function nonEmptyParts(kind: "AppCard" | "AgentCard", parts: Dict): string[] {
  const set = kind === "AppCard" ? records.APP_CARD_SPILL_SET : records.AGENT_CARD_SPILL_SET;
  return set.filter((field) => {
    const value = parts[field];
    return value !== undefined && value !== null && !(Array.isArray(value) && value.length === 0);
  });
}

/**
 * The parts record of a full card (SPEC §6.1a.5): the full values of its kind's spill set and nothing else, what a
 * publisher writes as the parts document. An AppCard's lists are always written; an AgentCard's absent fields stay
 * absent. Throws on a stub, whose parts are in its document.
 */
export function cardParts(card: Dict): Dict {
  if (card["spill"] !== undefined) {
    throw new Error("a stub's parts are in its spill document; resolve the card first");
  }
  const kind = spillKindOf(card);
  const parts: Dict = {};
  for (const field of kind === "AppCard" ? records.APP_CARD_SPILL_SET : records.AGENT_CARD_SPILL_SET) {
    if (card[field] !== undefined) {
      parts[field] = card[field]!;
    }
  }
  return parts;
}

/**
 * The stub of a full card (SPEC §6.1a.5): every spill-set field at its placeholder (`[]` for an AppCard's lists,
 * absent otherwise) and `spill` last. The reference's `parts` must be the card's non-empty spill-set fields.
 */
export function cardStub(card: Dict, spill: Dict): Dict {
  const kind = spillKindOf(card);
  const expected = cardSpillParts(card);
  if (JSON.stringify(spill["parts"]) !== JSON.stringify(expected)) {
    throw new Error(`a stub moves every non-empty part [${expected.join(", ")}]: [${String(spill["parts"])}]`);
  }
  const stub: Dict = { ...card };
  for (const field of kind === "AppCard" ? records.APP_CARD_SPILL_SET : records.AGENT_CARD_SPILL_SET) {
    if (kind === "AppCard" && field !== "ui") {
      stub[field] = [];
    } else {
      delete stub[field];
    }
  }
  stub["spill"] = spill;
  return stub;
}

/**
 * The full card of a stub (FR-15): the parts document's values in place and no `spill`; conform it to the card's
 * record for its field order. Throws when the document's non-empty fields are not exactly `spill.parts`, or when
 * the card is not a stub.
 */
export function cardComplete(stub: Dict, parts: Dict): Dict {
  const spill = stub["spill"] as Dict | undefined;
  if (spill === undefined) {
    throw new Error("only a stub completes; this card carries its parts inline");
  }
  const kind = spillKindOf(stub);
  const held = nonEmptyParts(kind, parts);
  if (JSON.stringify(held) !== JSON.stringify(spill["parts"])) {
    throw new Error(`the parts document holds [${held.join(", ")}] where the stub names [${String(spill["parts"])}]`);
  }
  const full: Dict = { ...stub };
  delete full["spill"];
  for (const field of kind === "AppCard" ? records.APP_CARD_SPILL_SET : records.AGENT_CARD_SPILL_SET) {
    if (parts[field] !== undefined) {
      full[field] = parts[field]!;
    }
  }
  return full;
}

/** A UiDeclaration in Java field order: protocol, version, components, entries {reads, writes}, catalogIds (derived). */
export function uiDeclaration(components: Dict[], reads: string[] = [], writes: string[] = [],
                              protocol = "a2ui", version = "v0.9.1"): Dict {
  const catalogIds = [...new Set(components.map(c => String(c["catalogId"])))];
  return { protocol, version, components, entries: { reads, writes }, catalogIds };
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
 * those bytes. The advertisement is conformed to its type's record first (HLC
 * round six, 2026-11-08, P1 and P2), so its maps go out in the RFC 8949 order a
 * strict receiver requires; a type Java does not register, or an advertisement
 * that is no record of its type, throws.
 */
export function storedAd(adType: string, ad: Dict, identity: Identity): Dict {
  const schema = records.AD_TYPES.get(adType);
  if (schema === undefined) {
    throw new Error(`no receiver reads an advertisement of type ${adType}`);
  }
  const adBytes = dumps(records.conform(ad, schema));
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
  const digest = cryptoPort().sha256(utf8(peerId));
  return new DataView(digest.buffer, digest.byteOffset, 8).getBigInt64(0, false);
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
export function encodeModel(weights: number[]): Uint8Array {
  const b = new Uint8Array(weights.length * 8);
  const view = new DataView(b.buffer);
  weights.forEach((w, i) => view.setFloat64(i * 8, w, false));
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
                         payload: Uint8Array | null, issuer: string,
                         issued: string, keyEpoch: number | null = null,
                         tags: Dict = {}, payloadRef: string | null = null): Dict {
  // SPEC §7.1: the tags are part of the signed record, canonical on the wire; `payloadRef`
  // names a block (`z`) or a content root (`b`) when the payload travels outside the record.
  const view: Dict = { entryId, spaceId, type: typeName, payload, payloadRef,
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
 * not receipt), and the record signature must then verify under the
 * certificate's agent key: a record that arrives with a certificate but a
 * peer-key signature is refused. How far the issue stamp may lead the
 * receiver's wall is D4's question, which the replica asks after this check
 * for an agent-signed record as for a peer-signed one (HLC round five,
 * 2026-11-08, E4).
 */
export function verifyRecord(record: Dict, issuerPublicRaw: unknown, certificate: unknown): boolean {
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
  // HLC round four, 2026-11-08 (D5): judged at a stamp that decodes, a counter above the limit
  // included, so the replica refuses and counts such a record after it verifies.
  const signedAt = decodedPhysical(record["issued"]);
  if (signedAt === null) {
    return false;
  }
  if (!verifyAgentCertificateCovering(certificate, issuerPublicRaw, issuer, signedAt)) {
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
 * order and dot sorting match the Java record exactly. A state without a lease
 * stamp signs a null one, as Java's record encodes it (HLC round five,
 * 2026-11-08, E7).
 */
export function stateSignView(spaceId: string, entryId: string, adds: Dict[],
                              removes: Dict[], leaseStamp: string | null,
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

/** A state DTO's lease stamp as its signed view holds it: the text, or null when the state names none. */
export function leaseStampOf(dto: Dict): string | null {
  const stamp = dto["leaseStamp"];
  return stamp === null || stamp === undefined ? null : String(stamp);
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
    leaseStampOf(dto), dto["leaseValue"] as Dict, Boolean(dto["completed"]),
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
                           payload: Uint8Array | null, identity: Identity,
                           agentName: string, leaseMillis: number,
                           agent: AgentIdentity | null = null, nowMillis?: number,
                           tags: Dict = {}, payloadRef: string | null = null):
    { entryId: string; body: Uint8Array } {
  const entryId = randomUuid();
  const spaceId = spaceIdLocal(`${group}/${spaceName}`);
  const issuer = agent !== null ? agent.agentId : identity.agent(agentName);
  const issued = hlcNow(issuer, nowMillis);
  const view = signView(entryId, spaceId, typeName, payload, issuer, issued, null, tags, payloadRef);
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
    entryId, spaceId, type: typeName, payload, payloadRef, issuer,
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
 * The TakeClaim a claim map stands for, conformed to the record (HLC round six, 2026-11-08, F1): its
 * fields in declared order with Java's kinds and nothing else, an epoch of 1 or more, a finite bid
 * that is a float64, and a holder that is an agent id (R5). Null when the map is no such claim, which
 * leaves nobody a claim to verify. A claim that arrived in a carrier the strict read accepted is its
 * own conformed form, so a signature verifies over exactly the bytes its holder signed.
 */
export function canonicalClaim(claim: unknown): Dict | null {
  return records.conformed(claim, records.TAKE_CLAIM);
}

/**
 * A SignedClaim: the claim, the holder's *peer* key, the holder's signature.
 * With `agent` the signature is the agent key's and the peer's certificate
 * rides beside it in the appended `holderCertificate` field (QA4 A4-7
 * phase 3); without it the proof is byte-identical to before. The signature
 * covers the claim's canonical TakeClaim encoding (HLC round five,
 * 2026-11-08, E13), which is the claim's own encoding when it comes from
 * {@link takeClaim}.
 */
export function signedClaim(claim: Dict, identity: Identity,
                            agent: AgentIdentity | null = null): Dict {
  const canonical = canonicalClaim(claim);
  if (canonical === null) {
    throw new Error("a claim needs a non-empty entryId and spaceId, a canonical stamp, an agent id holder, an epoch of 1 or more, an integer expiry, and a finite float64 bid");
  }
  const signed: Dict = { claim: canonical, holderKey: identity.publicRaw,
    signature: (agent ?? identity).sign(dumps(canonical)) };
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
 * claim's holder at the claim's own stamp and the signature under the
 * certificate's agent key. Either signature covers the claim's TakeClaim
 * encoding ({@link canonicalClaim}); a claim that is no conformed TakeClaim verifies
 * nowhere (HLC round six, 2026-11-08, F1). How far the stamp may lead the
 * receiver's wall is D4's question, asked after this check (E4). The entry and
 * space bindings are the caller's.
 */
export function verifyClaimProof(signed: Dict): boolean {
  const claim = signed["claim"];
  const holderKey = signed["holderKey"];
  const signature = signed["signature"];
  if (!(holderKey instanceof Uint8Array) || holderKey.length !== 32 || !(signature instanceof Uint8Array)) {
    return false;
  }
  const canonical = canonicalClaim(claim);
  if (canonical === null) {
    return false;
  }
  const holder = canonical["holder"] as string;
  if (!holder.startsWith(deriveId(holderKey) + "/")) {
    return false;
  }
  const certificate = signed["holderCertificate"];
  if (certificate === undefined || certificate === null) {
    return Identity.verify(holderKey, dumps(canonical), signature);
  }
  // HLC round four, 2026-11-08 (D5): a stamp that decodes, so an attested claim above the limit
  // verifies first and the replica counts its refusal.
  const stamped = decodedPhysical((claim as Dict)["stamp"]);
  if (stamped === null) {
    return false;
  }
  // v0.1.13: judged at the claim's own stamp, which a renewal keeps.
  if (!verifyAgentCertificateCovering(certificate, holderKey, holder, stamped)) {
    return false;
  }
  return Identity.verify((certificate as Dict)["agentPublicKey"] as Uint8Array,
    dumps(canonical), signature);
}

/** A claim-only Delta, as tryTakeOnce publishes it. */
export function claimDelta(entryId: string, signed: Dict): Uint8Array {
  return dumps({ state: null, claimEntry: entryId, claim: signed });
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
 * Java's Double.compare: -0.0 orders below 0.0 and NaN above everything (HLC round six, 2026-11-08,
 * P2), so every implementation picks the same winner between a bid of -0.0 and one of 0.0.
 */
export function javaDoubleCompare(a: number, b: number): number {
  if (a < b) {
    return -1;
  }
  if (a > b) {
    return 1;
  }
  const bitsA = Number.isNaN(a) ? 2 : Object.is(a, -0) ? 0 : 1;
  const bitsB = Number.isNaN(b) ? 2 : Object.is(b, -0) ? 0 : 1;
  return bitsA - bitsB;
}

/** Java's Long.compare over two decoded longs, exactly past 2^53. */
function compareLong(a: CborValue, b: CborValue): number {
  const x = BigInt(a as number | bigint);
  const y = BigInt(b as number | bigint);
  return x < y ? -1 : x > y ? 1 : 0;
}

/**
 * Compares two claims by the lattice's total order (spec §7.4): negative when
 * {@code a} wins. Epoch descending, bid ascending, HLC stamp ascending,
 * holder ascending, expiry descending; identical to TakeClaim.merge, which compares longs as longs
 * and bids by Double.compare. The claims are conformed TakeClaims. Throws
 * when a claim's stamp is one {@link parseHlc} refuses: every merge point
 * refuses such a claim before the lattice, so a throw here is a caller's bug
 * (HLC logical counter, 2026-11-08, Rust team report).
 */
export function compareClaims(a: Dict, b: Dict): number {
  const byEpoch = compareLong(b["epoch"], a["epoch"]);
  if (byEpoch !== 0) {
    return byEpoch;
  }
  const byBid = javaDoubleCompare(num(a["bid"]), num(b["bid"]));
  if (byBid !== 0) {
    return byBid;
  }
  const byStamp = compareParsed(requireHlc(a["stamp"]), requireHlc(b["stamp"]));
  if (byStamp !== 0) {
    return byStamp;
  }
  if (String(a["holder"]) !== String(b["holder"])) {
    return String(a["holder"]) < String(b["holder"]) ? -1 : 1;
  }
  return compareLong(b["expiresAtMillis"], a["expiresAtMillis"]);
}

/** Returns the winning SignedClaim of two, by the lattice order. */
export function mergeClaims(a: Dict | undefined, b: Dict): Dict {
  if (a === undefined) {
    return b;
  }
  return compareClaims(a["claim"] as Dict, b["claim"] as Dict) <= 0 ? a : b;
}
