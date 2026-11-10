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
 * A minimal wire-compatible AgentSpaces peer in TypeScript: joins a Java
 * fleet over TCP in the dial-only posture (by a literal group or by asking a
 * seed for a self-certifying founding document, SPEC §5.1/§10.1), answers
 * SWIM pings, re-leases its self-advertisement, writes signed entries, takes
 * under the LEASE_RACE claim lattice, and reads spaces back through
 * anti-entropy. The trilingual proof: the same wire the Java and Python peers
 * speak. The peer holds frame channels (srad/agentspaces-js.md §3.2) and dials
 * each seed with the dialer its scheme names; the portable core loads in
 * every JavaScript runtime and `@agentspaces/client/node` adds `tcp`.
 */

import * as beacon from "./beacon.js";
import { equals, fromBase64, toHex, utf8 } from "./bytes.js";
import { cryptoPort } from "./crypto.js";
import { CborDouble, CborValue, canonicalMap, dumps, loads, readDocument } from "./cbor.js";
import type { Pdt } from "./pdt/index.js";
import * as pdtCids from "./pdt/cids.js";
import { AgentIdentity, Identity, deriveId, instantIso, parseDurationMillis, parseInstantMillis, spaceIdLocal, verifyAgentCertificateCovering, verifySignedGroupAd } from "./identity.js";
import * as records from "./records.js";
import * as revocation from "./revocation.js";
import * as serving from "./serving.js";
import { SESSION_HELLO_MAX_AGE_MILLIS, SESSION_HINT, Session, parseSessionHello } from "./session.js";
import * as social from "./social.js";
import * as wire from "./wire.js";
import type { Dict } from "./wire.js";
import { DIALER_PACKAGES, Dialer, FrameChannel, defaultDialers } from "./transport.js";
import "./transport/defaults.js";
import { Seed, schemeOf, seedUrl } from "./seed.js";
import { Repeating, TimerPort, systemTimers } from "./platform.js";

const wireSpaceId = (group: string, space: string): string => spaceIdLocal(`${group}/${space}`);

function sleep(millis: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, millis));
}

/**
 * The join through a beacon document waits in slices of 1 s, 2 s, 4 s, then 5 s each inside
 * its budget: the schedule of the Java join by id (ISSUE-BootstrapRobustness §9.4).
 */
const JOIN_SLICE_FIRST_MS = 1_000;
const JOIN_SLICE_MAX_MS = 5_000;

/**
 * `Peer.bootstrap` spent its `joinTimeoutMs`: the message and the fields say how many times
 * the document was fetched, how many seeds were dialed and how many of them connected, and
 * `cause` is the last error.
 */
export class BootstrapTimeoutError extends Error {
  constructor(message: string, readonly fetches: number, readonly dialed: number, readonly connected: number,
    cause: unknown) {
    super(message, { cause });
    this.name = "BootstrapTimeoutError";
  }
}

/** A join-by-GroupID in flight: the group wanted and its resolver (§10.1). */
interface PendingFounding {
  group: string;
  resolve(signed: Dict): void;
}

/** An advertisement as the cache holds it. */
export type CachedAd = { type: string; ad: Dict; stored: Dict; issuer: string; expires: number };

export type { Seed } from "./seed.js";

/** Lets a repeating timer stop holding a Node process open; other runtimes have no unref. */
function unref(timer: unknown): void {
  const t = timer as { unref?: () => void };
  if (typeof t?.unref === "function") {
    t.unref();
  }
}

/** What {@link Peer.joinInvite} yields: the group joined and the content key the secret derives. */
export type InviteJoined = {
  groupId: string;
  /** The group's content key, epoch 0, 32 bytes (SRAD §3.8). */
  contentKey: Uint8Array;
  /** The delegation the credential was issued under (base64 CBOR), from the key or the document. */
  delegation: string;
  key: social.InviteKey;
  /**
   * The key pinned to that delegation, compact form. Persist it and join with it next time:
   * the members that admitted this peer re-admit it after the key's window only under the
   * same credential (SPEC §5.1, v0.1.20), and the beacon document may carry a newer
   * delegation by then. Ed25519 is deterministic, so the same pinned key gives the same credential.
   */
  pinnedKey: string;
};

/**
 * One accepted connection of a peer that listens (JS-R-04): its channel, the
 * session established on it (one per connection, SPEC §5.6), and the members
 * heard on it, which addressed frames to them follow.
 */
export type Link = { channel: FrameChannel; session: Session | null; readonly peers: Set<string> };

/**
 * The content swarm's seam on a peer (SPEC §7.1 group E): a payload above `escalateAbove` is
 * published as an artifact and the record carries its root; a read resolves the root here.
 */
export interface BulkPayloads {
  readonly escalateAbove: number;
  publishOpaque(payload: Uint8Array, leaseMillis: number): string;
  local(root: string): Uint8Array | null;
  ensure(root: string): void;
  /** Releases a root no held entry references any more, once its entry is collected (LB-E-04). */
  unpin(root: string): void;
}

/**
 * The wire hint this client advertises (SPEC v0.1.17 §9, srad/agentspaces-pdt.md §3.9, PD-L-04): a
 * renew, cancel, or complete may reach it as an EntryStateDto without its record (PD-L-01); it merges
 * the state over the record it holds or keeps it pending, without an event, until the record arrives.
 */
export const RECORDLESS_HINT = "wire.recordless";

/** The most recordless states kept pending for records that have not arrived (PD-L-02). */
export const MAX_PENDING_RECORDLESS = 1024;

/**
 * The hint a peer advertises once every decoder it runs reads the v0.1.32 schemas of the AppCard and the AgentCard
 * (`wire.appcard=2`; SPEC §6.1a.2, §9; AppCard origin and formats, 2026-11-09): canonical decimal text, read as
 * level N or above. An issuer writes a card's origin, formats, an `idp` host, and a spill reference only while every
 * member it knows is at level 2.
 */
export const APPCARD_HINT = "wire.appcard";
/** The AppCard level this build reads and, by default, advertises. */
export const APPCARD_LEVEL = 2;

/**
 * The AppCard level a hint's text states, as Java's `PeerNode.appCardLevelOf` reads it: 1 for no hint, any text
 * that is not canonical decimal (a leading zero, a sign, a space), or a value below 1; a value past nine digits reads
 * as the largest int.
 */
export function appCardLevelOf(text: unknown): number {
  if (typeof text !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(text)) {
    return 1;
  }
  return text.length > 9 ? 2_147_483_647 : Math.max(1, Number(text));
}

/** The advertisement cache's default entry bound (ASF-019) and byte budget (SPEC §6.3, v0.1.32), as Java's AdCache. */
export const AD_CACHE_MAX_ENTRIES = 8_192;
export const AD_CACHE_MAX_BYTES = 33_554_432;

/** How often a peer that holds parts documents for its stubs checks whether one may lapse. */
const SPILL_SWEEP_MILLIS = 5_000;

/**
 * Where a publisher puts a stub card's parts document and a reader fetches it (SPEC §6.1a.5, v0.1.32;
 * ISSUE-AppCardOriginFormats §9.8; AppCard origin and formats, 2026-11-09): the group's content swarm, whose
 * `ContentSpillStore` (`capabilities/content`) installs itself on the peer it attaches to. With none installed a
 * publisher never spills and {@link Peer.resolve} fails a stub.
 */
export interface SpillStore {
  /**
   * Publishes a parts document as a content-swarm artifact in 65,536-byte pieces, manifest `name`, media type
   * `application/cbor`, sealing `none`, and keeps it served until {@link release}; returns its root. The same bytes
   * give the same root. Throws when the swarm does not take the document.
   */
  put(name: string, document: Uint8Array): string;
  /**
   * Fetches a parts document, every piece verified against the root. Rejects with a {@link SpillRefusedError} when
   * the artifact's length is not `size`, found from its manifest before a piece is fetched, and with another error
   * when no holder serves it within the store's deadline.
   */
  get(root: string, size: number): Promise<Uint8Array>;
  /** Stops keeping a root served on behalf of the cards that named it, so the artifact lapses. */
  release(root: string): void;
}

/** A parts document that does not complete its stub (SPEC §6.1a.5, FR-15): counted in `spillsRefused`. */
export class SpillRefusedError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "SpillRefusedError";
  }
}

/**
 * A card this peer issues under the AppCard level: the full card, its type, the last issue instant signed, and the
 * gate it was last issued under (null before its first issue), so a change of the members' level reissues exactly the
 * cards that went out under the other gate (AppCard origin and formats, 2026-11-09, adversary pass).
 */
interface IssuedCard { adType: "AppCard" | "AgentCard"; full: Dict; issued: number; open: boolean | null }

/**
 * How many distinct refused states and claims a replica remembers so a re-offer counts no second
 * refusal, as Java's ReplicatedSpace REJECTED_OFFERS_CAP (HLC canonical stamps, 2026-11-08); the
 * same cap bounds the deferred offers (HLC round four, 2026-11-08). Past the cap each memory forgets
 * its least recently offered key, as Java's access-ordered maps do (HLC round five, 2026-11-08, E14).
 */
const MAX_REFUSED_STAMPS = 4096;

/**
 * How many refused-and-acknowledged digest lines a replica keeps, Java's ReplicatedSpace
 * REFUSED_ACK_CAP (HLC round six, 2026-11-08, R7), the least recently refused forgotten first.
 */
export const MAX_REFUSED_ACK = 8192;

/**
 * How long an entry whose write lease lapsed stays held past its expiry, at most (SPEC §7.3, Java's
 * SpaceStateCrdt.LAPSED_GRACE_MILLIS). HLC round five, 2026-11-08: a lapse needs no long tombstone,
 * since every replica judges the same lease stamp lapsed; a completion or a withdrawal keeps twice
 * the longest lease, so every replica that could still learn of it has two full leases to do so.
 */
export const LAPSED_GRACE_MILLIS = 5 * 60_000;

/**
 * The ceiling on the lease that feeds the collection horizon (SPEC §7.3, Java's
 * MAX_TRACKED_LEASE_MILLIS, HLC round five, 2026-11-08): one member's century-long lease cannot stop
 * collection fleet-wide.
 */
export const MAX_TRACKED_LEASE_MILLIS = 24 * 60 * 60_000;

/** How often a replica collects its tombstones (SPEC §7.3). */
const COLLECT_PERIOD_MILLIS = 1000;

/** Whether a `b` reference names a persistent tree (dag-cbor) rather than a piece artifact. */
function isTreeRoot(ref: string): boolean {
  try {
    return pdtCids.parse(ref).codec === pdtCids.DAG_CBOR;
  } catch {
    return false;
  }
}

export class Peer {
  readonly states = new Map<string, Dict>();
  readonly claims = new Map<string, Dict>();
  /** Recordless states for entries whose record has not arrived yet, by entry id (PD-L-02). */
  readonly pendingStates = new Map<string, Dict>();
  /** The founding advertisement this peer joined with, when it joined by GroupID. */
  founding: Dict | null = null;
  private channel: FrameChannel | null = null;
  /**
   * The channel authentication mode (PeerNode.ChannelAuth): `session` (the default, and the
   * dev-local profile's) advertises `wire.session=1` and, on a channel the transport cannot
   * attest, establishes a session with a member that advertises the same, after which frames
   * to it carry a tag in place of a signature (SPEC §5.6, v0.1.17); `signed` signs every frame.
   */
  channelAuth: "signed" | "session" = "session";
  /** The members whose advertisement carries the session hint. */
  readonly sessionPeers = new Set<string>();
  private session: Session | null = null;
  /**
   * The connections a listener handed this peer (a service host), each with its own session and
   * the members heard on it; the dialed channel above stays the route for everyone else.
   */
  readonly inbound = new Map<FrameChannel, Link>();
  /** The endpoints this peer's advertisement names (a host's listeners); empty is the dial-only posture. */
  readonly endpoints: Dict[] = [];
  /** How many hops a rumor this peer originates may travel (GossipBus defaultHops). */
  rumorHops = 6;
  /** Rumors forwarded to other links (a host relays what one connection brings to the others). */
  rumorsForwarded = 0;
  /** DIGESTs answered with a PULL_RESP, and PING_REQs relayed. */
  pullsAnswered = 0;
  pingsRelayed = 0;
  /** How many rumor keys stay remembered for duplicate suppression: a cache size, not a cap on anything. */
  rumorMemory = 65_536;
  private readonly rumorsSeen = new Set<string>();
  /** PING_REQ relays in flight: the relay nonce to who asked, their nonce, and the target vouched for. */
  private readonly relays = new Map<string, { origin: string; originNonce: number | bigint; target: string }>();
  /** Frames sent under a session key rather than a signature. */
  sessionFramesSent = 0;
  /** Session hellos ignored as older than the hello age window (never a strike). */
  framesStale = 0;
  /**
   * States and claims this replica refused because a stamp they carry (a record's `issued`, a
   * state's `leaseStamp` or `signedAt`, a claim's `stamp`) decodes with a logical counter above
   * wire.LOGICAL_LIMIT (HLC logical counter, 2026-11-08, Rust team report). Rumors, anti-entropy,
   * snapshots and committed claims all fold through the same check. This peer keeps no strikes, so
   * the count records each refusal: after the signatures verify, since an unverified carrier names
   * no signer, and once per distinct offer, keyed on signed content alone, since a re-offer is no
   * new refusal. The name is Java's ReplicatedSpace counter (HLC round four, 2026-11-08, D5).
   */
  stampsLogicalRefused = 0;
  /**
   * States and gossiped claims this replica refused as hostile because a stamp they carry lies more
   * than wire.FAR_FUTURE_HOSTILE_MILLIS past its wall + MAX_HLC_SKEW_MILLIS +
   * FAR_FUTURE_MARGIN_MILLIS, counted as stampsLogicalRefused is (HLC round four, 2026-11-08, D4).
   */
  stampsFarFutureRefused = 0;
  /**
   * Distinct states and gossiped claims this replica deferred because a stamp lies past that
   * margin by at most wire.FAR_FUTURE_HOSTILE_MILLIS: neither merged, acknowledged, nor taken for
   * misbehaviour, each merges when anti-entropy offers it after this replica's wall catches up (HLC
   * round four, 2026-11-08, D4). The names are Java's ReplicatedSpace counters.
   */
  stampsFarFutureDeferred = 0;
  /** The distinct deferred states and claims counted above, the eldest forgotten past the cap. */
  private readonly deferredStamps = new Set<string>();
  /**
   * Space deltas, by rumor or by anti-entropy, and snapshot entries this replica dropped because
   * they did not decode: bytes that are no delta, or a delta holding a stamp that is no canonical
   * CBOR text (HLC round four, 2026-11-08, D3). Such a carrier names no verified signer. The name
   * is Java's ReplicatedSpace counter.
   */
  deltasUndecodable = 0;
  /** The distinct refused states and claims counted above, the eldest forgotten past the cap. */
  private readonly refusedStamps = new Set<string>();
  /**
   * The digest lines (`e:<entry>=<state hash>`) of verified states this replica refused for their
   * stamps, by line with the state's SpaceId, the eldest forgotten past the cap. Each digest names
   * them as `a:<line>`, as Java's acknowledges them, so partners stop re-offering them (HLC round
   * four, 2026-11-08, D5).
   */
  private readonly refusedAck = new Map<string, string>();
  /** The dialers this peer dials with, by scheme; the registered defaults at construction. */
  readonly dialers = new Map<string, Dialer>();
  private pendingFounding: PendingFounding | null = null;

  /**
   * @param group the GroupID this peer belongs to (a literal-founding id, or
   *              the self-certifying id {@link joinByGroupId} will verify)
   */
  /**
   * @param now epoch milliseconds; a test pins it to verify time-bound material
   *            (agent certificates) against a fixed instant, as Java's TestClock does
   */
  /**
   * The group's revocations (SPEC §5.6, v0.1.13), verified founder-rooted
   * (when the founder is known, from `founder` or the verified founding
   * document) or, for an agent and its keys, by the agent's own peer.
   */
  revocations: revocation.Registry;

  constructor(readonly identity: Identity, public group: string,
              readonly now: () => number = Date.now, private readonly founder: string | null = null) {
    this.revocations = new revocation.Registry(() => this.founderId(), () => this.group);
    for (const dialer of defaultDialers()) {
      this.dialers.set(dialer.scheme.toLowerCase(), dialer);
    }
  }

  /** The timers this peer schedules on (JS-P-10); a test installs a fake before using the peer. */
  timers: TimerPort = systemTimers;
  private readonly repeating: Repeating[] = [];

  /** Runs `fn` every `periodMillis` on this peer's timers until {@link close}; never holds a Node process open. */
  every(periodMillis: number, fn: () => void): Repeating {
    const handle = this.timers.every(periodMillis, fn);
    this.repeating.push(handle);
    return handle;
  }

  /** Adds (or replaces) the dialer for its scheme. */
  registerDialer(dialer: Dialer): this {
    this.dialers.set(dialer.scheme.toLowerCase(), dialer);
    return this;
  }

  /** The schemes this peer can dial. */
  dialableSchemes(): string[] {
    return [...this.dialers.keys()];
  }

  /** The channel the peer's link is on, if any. */
  currentChannel(): FrameChannel | null {
    return this.channel;
  }

  // ROBUSTNESS.md: late, replayed and unknown frames are the normal case; count, never fail.
  readonly frames = new wire.FrameFilter();
  readonly ignoredKinds = new Map<string, number>();
  /** Frames accepted bare under the dialed channel's attestation (SPEC §5.6), after this peer's CHANNEL_HELLO. */
  attestedFrames = 0;
  /** The dialed channel a CHANNEL_HELLO went out on, so one announcement serves one connection. */
  private helloSentOn: FrameChannel | null = null;
  malformedFrames = 0;
  // A lost socket is reconnected to the seeds in turn (the next seed first, a pause after every
  // full round that backs off from reconnectIntervalMs to six times it with a random spread) and
  // the peer re-introduced and re-pulled, until a close() by the owner, which is final (swarm retries).
  reconnects = 0;
  /** The pause after the first full round of reconnect dials; each later round doubles it, up to six times it. */
  reconnectIntervalMs = 5000;
  /**
   * Whether a lost link re-dials the seeds on its own. A host whose own durable timer owns every dial, as the
   * workers cell's alarm does, turns it off and dials again with `connectAny` (swarm retries, ROBUSTNESS.md §10.3 E5).
   */
  redial = true;
  /** The seeds this peer dials, in order; `seeds[seedIndex]` is the one in use or tried last. */
  seeds: Seed[] = [];
  seedIndex = 0;
  /**
   * Resolve a seed hostname to every address and dial each (DB-X-03); off, the runtime's
   * resolver picks one address per dial.
   */
  resolveSeeds = true;
  /**
   * The free-form resource hints this peer's self-advertisement carries (SPEC §5.2); a join
   * credential rides under `aspace:join`. Set before `connect`, or call `introduce()` again.
   */
  readonly resourceHints: { [key: string]: string } = {};
  /**
   * SPEC v0.1.23 §5.4 (srad/large-networks-bulk-data.md): the seed's PeerID, learned from the
   * first frame it addresses to this peer on the dialed channel. A dial-only peer reaches the
   * seed directly and every other member through it (a `RELAY_FRAME` the seed forwards), and
   * declares the seed as its relay in the `relay.via` hint so members reach it the same way back.
   */
  seedPeer: string | null = null;
  /** The longest path a relayed frame of this peer's names (LB-R-03). */
  maxPathHops = 4;
  /** Frames this peer sent through its seed. */
  relayedFrames = 0;
  /** The last unreachable signals relays sent back (`aspace:cap/relay-signal`). */
  readonly relaySignals: Dict[] = [];
  /** Block-stored payloads (SPEC §7.1, `z` references): put here or fetched, by id. */
  readonly blocks = new Map<string, Uint8Array>();
  private readonly blockAsked = new Map<string, number>();
  /** The content swarm attached to this peer (`capabilities/content`): resolves `b` references and takes payloads above its bound. */
  content: BulkPayloads | null = null;
  /**
   * Where a stub card's parts document goes and comes from (SPEC §6.1a.5, v0.1.32): a content swarm installs its
   * `ContentSpillStore` when it attaches; null, and this peer never spills and fails to resolve a stub.
   */
  spillStore: SpillStore | null = null;
  /** The largest parts document {@link resolve} fetches (16 MiB by default). */
  spillMaxFetchBytes = wire.CARD_SPILL_MAX_FETCH_BYTES;
  /** AppCards issued without a gated field because a member is below the AppCard level (SPEC §6.1a.2). */
  appCardsDowngraded = 0;
  /** Cards issued as stubs (SPEC §6.1a.5). */
  cardsSpilled = 0;
  /** Cards above the spill threshold issued inline: a closed gate, no spill store, a refused document, or nothing to move. */
  cardsOversizeInline = 0;
  /** Resolutions that failed a check of the parts document. */
  spillsRefused = 0;
  /** Resolutions refused because the stub's `size` passed {@link spillMaxFetchBytes}. */
  spillsOverLimit = 0;
  /** Where this peer's warnings go: the soft warning of a card near the spill threshold (FR-13), and a refused spill. */
  onWarning: (message: string) => void = (message) => console.warn(message);
  private level = APPCARD_LEVEL;
  /** The cards this peer issues under the AppCard level, by id, so a change of the members' level reissues them. */
  private readonly issuedCards = new Map<string, IssuedCard>();
  /** The size each card id last warned at, so a refresh at the same size stays quiet. */
  private readonly warnedSizes = new Map<string, number>();
  /** Each parts-document root this peer named, to the moment the last card that named it expires. */
  private readonly spillHolds = new Map<string, number>();
  private spillSweep: Repeating | null = null;

  /**
   * The AppCard level this peer advertises (`wire.appcard`), 1 or 2; 1 advertises no hint, so a test builds a mixed
   * fleet. Advertise a change with {@link introduce}.
   */
  get appCardLevel(): number {
    return this.level;
  }

  set appCardLevel(level: number) {
    if (level !== 1 && level !== APPCARD_LEVEL) {
      throw new RangeError(`this build reads AppCard levels 1 to ${APPCARD_LEVEL}: ${level}`);
    }
    this.level = level;
    this.appCardLevelChanged();
  }
  /** The persistent data structures attached to this peer (`pdt`): refs, values, and the tree exchange (PD-C-05). */
  pdt: Pdt | null = null;
  private running = false;
  private readonly pulledSpaces = new Set<string>();
  /**
   * The spaces this peer joined: pulled, written to, or opened as a Space. HLC round five,
   * 2026-11-08: this peer relays a rumor of any other space without decoding or folding it, as
   * Java's GossipBus relays a stream it holds no handler for.
   */
  private readonly joinedSpaces = new Set<string>();
  /** The longest lease observed per space id, capped at MAX_TRACKED_LEASE_MILLIS, for the collection horizon (SPEC §7.3, HLC round five, 2026-11-08). */
  private readonly longestLease = new Map<string, number>();
  /** The periodic tombstone collection, started by the first state this replica stores. */
  private collector: Repeating | null = null;
  private pulledAds = false;

  private founderId(): string | null {
    if (this.founder !== null) {
      return this.founder;
    }
    const ad = this.founding?.["advertisement"] as Dict | undefined;
    return typeof ad?.["issuer"] === "string" ? ad["issuer"] : null;
  }

  /** Dials the seed (`tcp` unless `scheme` says otherwise, `tls` for instance) and introduces this peer to the group. */
  async connect(host: string, port: number, scheme?: string): Promise<void> {
    await this.connectAny([scheme === undefined ? { host, port } : { host, port, scheme }]);
  }

  /**
   * Dials the seeds in order until one answers, then introduces this peer to
   * the group (DB-X-02). A lost socket later fails over to the next seed
   * inside the reconnect window (ROBUSTNESS.md §6a). Rejects when no seed
   * answers, with the last dial's error.
   */
  /**
   * Takes a connection a listener accepted (JS-R-04): frames on it are handled like those on
   * the dialed channel, with a session of its own; a member heard on it is reachable until the
   * connection ends. The host introduces itself on the new link so the other end learns this
   * peer, and the rumor it brings travels on to the other links.
   */
  acceptChannel(channel: FrameChannel): Link {
    const link: Link = { channel, session: null, peers: new Set() };
    this.inbound.set(channel, link);
    this.running = true;
    channel.onFrame((frame) => this.onFrame(frame, link));
    channel.onClose(() => this.onInboundClosed(link));
    this.sendOn(link, "RUMOR", this.selfAdRumor(), null);
    return link;
  }

  private onInboundClosed(link: Link): void {
    if (this.inbound.get(link.channel) !== link) {
      return;
    }
    this.inbound.delete(link.channel);
    for (const peer of link.peers) {
      if (!this.linkedElsewhere(peer, link)) {
        this.reachable.delete(peer);
      }
    }
  }

  /** Whether a member is heard on some link other than `except` (null: other than the dialed channel). */
  private linkedElsewhere(peer: string, except: Link | null): boolean {
    if (except !== null && this.dialPeers.has(peer)) {
      return true;
    }
    for (const other of this.inbound.values()) {
      if (other !== except && other.peers.has(peer)) {
        return true;
      }
    }
    return false;
  }

  /** The members heard on the dialed channel. */
  private readonly dialPeers = new Set<string>();

  /** The link a member was heard on, or null for the dialed channel (the route for everyone else). */
  private linkFor(peer: string): Link | null {
    if (this.dialPeers.has(peer) && this.channel !== null) {
      return null;
    }
    for (const link of this.inbound.values()) {
      if (link.peers.has(peer)) {
        return link;
      }
    }
    return null;
  }

  /** The members this peer has a connection to, in no particular order. */
  linkedMembers(): string[] {
    const out = new Set<string>(this.dialPeers);
    for (const link of this.inbound.values()) {
      for (const peer of link.peers) {
        out.add(peer);
      }
    }
    out.delete(this.identity.peerId);
    return [...out];
  }

  async connectAny(seeds: Seed[]): Promise<void> {
    await this.dialAny(seeds);
    this.introduce();
    this.pullRevocations();
  }

  /** The seed the link is on (or was tried last), if any. */
  currentSeed(): Seed | null {
    return this.seeds[this.seedIndex] ?? null;
  }

  private async dialAny(seeds: Seed[]): Promise<void> {
    const dialable = seeds.filter((s) => this.dialers.has(schemeOf(s)));
    if (dialable.length === 0 && seeds.length > 0) {
      // JS-Q-AVL-03: name what was seen and what dials it.
      const schemes = [...new Set(seeds.map(schemeOf))];
      throw new Error(`no dialer for the seeds' schemes (${schemes.join(", ")}); this peer dials `
        + `${this.dialableSchemes().join(", ") || "nothing"}; add `
        + schemes.map((s) => DIALER_PACKAGES[s] ?? `a ${s} dialer`).join(" or "));
    }
    const expanded = await this.expandSeeds(dialable);
    if (expanded.length === 0) {
      throw new Error("no seed to dial");
    }
    this.seeds = expanded;
    this.seedIndex = 0;
    this.running = true;
    let lastError: unknown = null;
    for (let i = 0; i < this.seeds.length; i++) {
      this.seedIndex = i;
      try {
        await this.dial(this.seeds[i]);
        return;
      } catch (e) {
        lastError = e;
      }
    }
    this.running = false;
    throw new Error(`no seed answered (${this.seeds.map((s) => schemeOf(s) === "tcp" && s.scheme === undefined
      ? `${s.host}:${s.port}` : seedUrl(s)).join(", ")}): `
      + (lastError instanceof Error ? lastError.message : String(lastError)));
  }

  /** DB-X-03: each dialer may expand a seed (a hostname into one seed per address, for tcp). */
  private async expandSeeds(seeds: Seed[]): Promise<Seed[]> {
    const out: Seed[] = [];
    for (const seed of seeds) {
      const dialer = this.dialers.get(schemeOf(seed));
      if (dialer?.expand === undefined) {
        out.push(seed);
        continue;
      }
      try {
        out.push(...await dialer.expand(seed, this.resolveSeeds));
      } catch {
        out.push(seed); // let the dial report the resolver's verdict
      }
    }
    return out;
  }

  /**
   * DB-X-02: fetches a beacon document (signature verified, the pinned
   * signer honoured), selects the group (`groupId`, else `name`, else the
   * document's only group), verifies its founding advertisement with the
   * four checks `joinByGroupId` applies and, when `groupId` is given, that
   * it is exactly that group, then dials the document's seeds of every scheme
   * this peer dials, in priority order (JS-P-07). Returns the group selected.
   *
   * `timeoutMs` (3 000 by default) bounds one fetch of the document and
   * `joinTimeoutMs` (10 000) bounds the whole call. A first attempt that
   * succeeds fetches once and dials once. Otherwise the call keeps asking
   * inside the budget, in slices of 1 s, 2 s, 4 s, then 5 s each, the shape
   * of the Java join by id (ISSUE-BootstrapRobustness FR-4): at the start of
   * each slice it fetches the document again when the previous fetch left the
   * beacon unavailable ({@link beacon.BeaconUnavailableError}) or the document
   * named no seed this peer dials, and dials again, once per slice, every seed
   * that refused. A beacon or a seed that starts a few seconds after this peer
   * is reached on a later slice. A refusal (the scheme policy, a document or a
   * founding that does not verify, a founding for another id, a group the
   * document does not carry) rejects at once, as before. When the budget runs
   * out the call rejects with {@link BootstrapTimeoutError}, whose message
   * carries the number of fetches, the seeds dialed, how many connected, and
   * the last error.
   */
  async bootstrap(url: string, options: {
    groupId?: string | null; name?: string | null; allowPlain?: boolean;
    beaconPeer?: string | null; timeoutMs?: number; joinTimeoutMs?: number; fetch?: typeof fetch;
  } = {}): Promise<beacon.BeaconGroup> {
    const joinTimeoutMs = options.joinTimeoutMs ?? 10_000;
    const attemptMs = options.timeoutMs ?? 3_000;
    const deadline = Date.now() + joinTimeoutMs;
    let fetches = 0;
    const dialed = new Set<string>();
    let lastError: unknown = null;
    let group: beacon.BeaconGroup | null = null;
    let seeds: Seed[] = [];
    let slice = JOIN_SLICE_FIRST_MS;
    for (;;) {
      const started = Date.now();
      if (seeds.length === 0) {
        fetches += 1;
        try {
          const document = await beacon.fetchBeaconDocument(url,
            { ...options, timeoutMs: Math.min(attemptMs, Math.max(deadline - started, 1)) });
          const selected = beacon.groupFromDocument(document, { groupId: options.groupId, name: options.name });
          const wanted = beacon.bareGroupId(options.groupId) ?? beacon.bareGroupId(selected.id);
          const founding = this.verifyFounding(selected, wanted);
          this.group = founding.group;
          this.founding = founding.signed;
          group = selected;
          seeds = this.seedsOfGroup(selected);
          if (seeds.length === 0) {
            lastError = new Error(`the beacon document lists no ${this.dialableSchemes().join(" or ")} seed for ${selected.name}`);
          }
        } catch (e) {
          if (!(e instanceof beacon.BeaconUnavailableError)) {
            throw e; // a refusal: asking again would not change it
          }
          lastError = e; // the beacon is unreachable or answered an error: ask again
        }
      }
      if (seeds.length > 0 && Date.now() < deadline) {
        try {
          await this.dialAny(seeds); // one dial per seed, in order
          this.introduce();
          this.pullRevocations();
          return group as beacon.BeaconGroup;
        } catch (e) {
          lastError = e;
        } finally {
          for (const seed of this.seeds) {
            dialed.add(seedUrl(seed));
          }
        }
      }
      const now = Date.now();
      const wait = Math.min(slice - (now - started), deadline - now);
      if (wait > 0) {
        await sleep(wait);
      }
      if (Date.now() >= deadline) {
        const last = lastError instanceof Error ? lastError.message : String(lastError);
        throw new BootstrapTimeoutError(`no join through ${url} within ${joinTimeoutMs} ms: ${fetches} fetch(es), `
          + `0 of ${dialed.size} seed(s) connected; last error: ${last}`, fetches, dialed.size, 0, lastError);
      }
      slice = Math.min(slice * 2, JOIN_SLICE_MAX_MS);
    }
  }

  /**
   * DB-X-07: joins a group for friends with an invite key. Parses the key,
   * fetches the beacon document under its code, takes the delegation from
   * the key or the document's `invite`, derives the credential for this
   * peer under the invite signing key and carries it in the self-ad's
   * `aspace:join` hint, verifies the founding against the delegation's
   * group, and dials the seeds. The returned content key is the group's
   * (epoch 0); the beacon never sees it.
   */
  async joinInvite(keyText: string, options: {
    allowPlain?: boolean; timeoutMs?: number; fetch?: typeof fetch;
  } = {}): Promise<InviteJoined> {
    const key = social.InviteKey.parse(keyText);
    const scheme = options.allowPlain ? "http" : "https";
    const document = await beacon.fetchBeaconDocument(key.documentUrl(scheme), options);
    const claimed = key.delegation === null ? null : social.delegationGroup(key.delegation);
    const group = beacon.groupFromDocument(document, { groupId: claimed });
    const delegation = key.delegation ?? group.invite ?? null;
    if (delegation === null) {
      throw new Error("the invite key carries no delegation and the beacon document has none");
    }
    const groupId = social.delegationGroup(delegation);
    const founding = this.verifyFounding(group, groupId);
    const issuer = (founding.signed["advertisement"] as Dict)["issuer"];
    if (typeof issuer !== "string" || issuer !== social.describeDelegation(delegation)?.founder) {
      throw new Error("the delegation was not signed by the group's founder");
    }
    this.resourceHints[social.JOIN_HINT] = social.issueDelegated(delegation, key.secret.inviteSeed(),
      this.identity.peerId);
    this.group = groupId;
    this.founding = founding.signed;
    const seeds = this.seedsOfGroup(group);
    if (seeds.length === 0) {
      throw new Error(`the beacon lists no ${this.dialableSchemes().join(" or ")} seed under ${key.code}`);
    }
    await this.connectAny(seeds);
    return { groupId, contentKey: key.secret.contentKey(), delegation, key,
      pinnedKey: key.withDelegation(delegation).compact() };
  }

  /**
   * A beacon group's seeds this peer can dial; a `tcp` seed keeps the bare
   * `{host, port}` form the earlier clients used.
   */
  private seedsOfGroup(group: beacon.BeaconGroup): Seed[] {
    return beacon.seedsFor(group, this.dialableSchemes()).map((s) => {
      if (s.scheme === "tcp") {
        const { scheme: _scheme, ...rest } = s;
        return rest;
      }
      return s;
    });
  }

  /**
   * The founding a document carries, verified as `joinByGroupId` verifies a
   * GROUP_AD (the four checks of GroupFounding.verify) and, when `wanted`
   * is given, required to be exactly that group.
   */
  private verifyFounding(group: beacon.BeaconGroup, wanted: string | null): { group: string; signed: Dict } {
    if (!group.founding) {
      throw new Error(`the beacon document carries no founding for ${group.name}`);
    }
    let bytes: Uint8Array;
    try {
      bytes = fromBase64(group.founding);
    } catch {
      throw new Error(`the founding of ${group.name} is not base64`);
    }
    const signed = records.readRecord(bytes, records.SIGNED_GROUP_ADVERTISEMENT);
    if (signed === null) {
      throw new Error(`the founding of ${group.name} is no SignedGroupAdvertisement in the wire encoding`);
    }
    const verified = verifySignedGroupAd(signed);
    if (verified === null) {
      throw new Error(`the founding of ${group.name} does not verify`);
    }
    const id = beacon.bareGroupId(group.id);
    if (id !== null && id !== verified) {
      throw new Error(`the document says ${group.name} is ${id} but its founding is ${verified}`);
    }
    if (wanted !== null && verified !== wanted) {
      throw new Error(`the founding of ${group.name} is ${verified}, not ${wanted}`);
    }
    return { group: verified, signed };
  }

  /** Whether the seed connection is up (a reconnect may be in progress while it is not). */
  connected(): boolean {
    return this.running && this.channel !== null;
  }

  /**
   * After a lost socket: dials the seeds again, then introduces this peer again and pulls what it
   * had pulled before, so a network hiccup costs a few seconds rather than the membership
   * (ROBUSTNESS.md §3.6). The pauses between rounds back off 5, 10, 20, 30 s with a random spread,
   * so the clients of a seed that restarts do not all dial it at once, and the dials go on until the
   * owner closes the peer (swarm retries, ROBUSTNESS.md §10.3 E5).
   */
  private reconnecting = false;

  private reconnect(rounds: number, lastTried: number): void {
    if (!this.running || this.seeds.length === 0) {
      this.reconnecting = false;
      return;
    }
    this.reconnecting = true;
    // The next seed first: a lost link to one seed is the moment to try another; the one that
    // dropped comes round again after the others.
    this.seedIndex = (lastTried + 1) % this.seeds.length;
    const tried = this.seedIndex;
    const seed = this.seeds[tried];
    this.dial(seed).then(() => {
      this.reconnecting = false;
      this.reconnects += 1;
      this.introduce();
      this.pullRevocations();
      if (this.pulledAds) {
        this.pullAds();
      }
      for (const space of this.pulledSpaces) {
        this.pullSpace(space);
      }
    }).catch(() => {
      if (!this.running) {
        this.reconnecting = false;
        return;
      }
      // One dial at a time, never a tight loop: the seeds of a round are tried back to back and
      // every full round of refusals waits its backoff.
      const endOfRound = (tried + 1) % this.seeds.length === this.roundStart;
      const done = endOfRound ? rounds + 1 : rounds;
      const pause = endOfRound ? this.reconnectPause(done) : 0;
      const timer = setTimeout(() => this.reconnect(done, tried), pause);
      unref(timer);
    });
  }

  /** The pause after the `rounds`-th failed round of dials: the interval doubling to six times it, with a spread of up to a quarter. */
  private reconnectPause(rounds: number): number {
    return Math.min(6 * this.reconnectIntervalMs, this.reconnectIntervalMs * 2 ** Math.min(rounds - 1, 3)) * (1 + Math.random() / 4);
  }

  /** Where the current round of reconnect dials began: the seed after the one that dropped. */
  private roundStart = 0;
  /** When the current link was dialed, and how many links in a row ended within the reconnect interval (swarm retries). */
  private linkSince = 0;
  private quickDrops = 0;

  private onChannelClosed(channel: FrameChannel): void {
    if (this.channel !== channel) {
      return; // an old link, already replaced
    }
    this.channel = null;
    this.session = null; // a session ends with its connection
    this.dialPeers.clear();
    for (const peer of [...this.reachable]) {
      if (!this.linkedElsewhere(peer, null)) {
        this.reachable.delete(peer);
      }
    }
    if (this.running && this.redial && this.seeds.length > 0 && !this.reconnecting) {
      this.roundStart = (this.seedIndex + 1) % this.seeds.length;
      // A link that ended within the reconnect interval counts as a failed round of dials, so a seed that accepts each
      // dial and drops it at once gets the backoff and no dial loop (swarm retries, ROBUSTNESS.md §10.6).
      const quick = Date.now() - this.linkSince < this.reconnectIntervalMs;
      this.quickDrops = quick ? this.quickDrops + 1 : 0;
      const last = this.seedIndex;
      if (quick) {
        this.reconnecting = true;
        unref(setTimeout(() => this.reconnect(0, last), this.reconnectPause(this.quickDrops)));
      } else {
        this.reconnect(0, last);
      }
    }
  }

  /**
   * Joins a self-certifying group knowing only its GroupID and a seed (SPEC
   * §5.1, §10.1 `join: "aspace://<groupID>"`): dials the seed, sends an
   * unaddressed GROUP_AD_WANT naming the group, waits for the first GROUP_AD
   * whose body verifies as the founding document of exactly that GroupID
   * (the four checks of GroupFounding.verify), and only then introduces this
   * peer. Answers that fail verification are ignored, so a hostile seed can
   * delay the join but never substitute a policy. Rejects with a timeout
   * error when no verified document arrives in time.
   */
  async joinByGroupId(host: string, port: number, groupId: string,
                      timeoutMillis = 10_000): Promise<Dict> {
    this.group = groupId;
    await this.dialAny([{ host, port }]);
    const founding = this.awaitFounding(groupId, timeoutMillis);
    // Unaddressed: the seed's PeerID is unknown until it answers (§9).
    this.sendEnvelope(wire.groupAdWantEnvelope(groupId, this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now())));
    try {
      this.founding = await founding;
    } catch (e) {
      this.close();
      throw e;
    }
    this.introduce();
    this.pullRevocations();
    return this.founding;
  }

  /**
   * The waiting half of {@link joinByGroupId}, exposed so the verification
   * path can be driven without a socket: resolves with the first verified
   * founding advertisement {@link offerGroupAd} receives for `groupId`.
   */
  awaitFounding(groupId: string, timeoutMillis: number): Promise<Dict> {
    if (this.pendingFounding !== null) {
      return Promise.reject(new Error(`a join of ${this.pendingFounding.group} is already in progress`));
    }
    return new Promise<Dict>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingFounding = null;
        reject(new Error(`timed out after ${timeoutMillis} ms waiting for a verified`
          + ` GROUP_AD for ${groupId}`));
      }, timeoutMillis);
      this.pendingFounding = {
        group: groupId,
        resolve: (signed) => {
          clearTimeout(timer);
          this.pendingFounding = null;
          resolve(signed);
        },
      };
    });
  }

  /**
   * Offers a decoded GROUP_AD envelope to the join in progress. Returns true
   * only when the body verified as the founding document of exactly the
   * wanted group and resolved the join; every other answer is ignored. The
   * reader calls this for GROUP_AD frames; tests call it directly.
   */
  offerGroupAd(env: Dict): boolean {
    const pending = this.pendingFounding;
    if (pending === null || env["kind"] !== "GROUP_AD" || env["group"] !== pending.group) {
      return false;
    }
    const signed = records.readRecord(env["body"], records.SIGNED_GROUP_ADVERTISEMENT);
    if (signed === null || verifySignedGroupAd(signed) !== pending.group) {
      return false; // not the self-certifying founding document of this group
    }
    pending.resolve(signed);
    return true;
  }

  close(): void {
    this.running = false;
    for (const handle of this.repeating.splice(0)) {
      handle.stop();
    }
    const channel = this.channel;
    this.channel = null;
    channel?.close();
    for (const link of [...this.inbound.values()]) {
      this.inbound.delete(link.channel);
      link.channel.close();
    }
  }

  /** Publishes this peer's leased self-advertisement (spec §5.2) on every link. */
  introduce(): void {
    this.send("RUMOR", this.selfAdRumor());
    this.maybeAnnounceChannel();
  }

  /**
   * On a dialed channel the transport attested (`tls`), announces once that this peer accepts
   * channel-attested frames there (CHANNEL_HELLO, SPEC §5.6; PeerNode.maybeAnnounceChannel), so
   * a Java node in ATTESTED or SESSION mode stops signing every frame toward it. The announcement
   * travels signed, and this peer keeps signing what it sends. Nothing is announced in `signed` mode.
   */
  private maybeAnnounceChannel(): void {
    const channel = this.channel;
    const attested = channel?.attestedPeer() ?? null;
    if (channel === null || attested === null || this.channelAuth === "signed" || this.helloSentOn === channel) {
      return;
    }
    this.helloSentOn = channel;
    const env = wire.envelope(this.group, "CHANNEL_HELLO", this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now()), wire.channelHelloBody(true, attested), attested);
    channel.send(wire.encodeFrame(env, this.identity));
  }

  /** This peer's advertisement as of now: its endpoints, hints, and lease (whole seconds, as always stamped). */
  private selfAd(): Dict {
    const now = this.now();
    const hints: { [key: string]: string } = { ...this.resourceHints, [RECORDLESS_HINT]: "1" };
    if (this.channelAuth === "session") {
      hints[SESSION_HINT] = "1";
    }
    if (this.level > 1) {
      hints[APPCARD_HINT] = String(this.level); // AppCard origin and formats, 2026-11-09
    }
    const ad = wire.peerAdvertisement(this.group, this.identity, instantIso(now - (now % 1000)),
      "PT10M", hints);
    ad["endpoints"] = this.endpoints.map((e) => ({ ...e }));
    return ad;
  }

  /** The `peers` rumor carrying this peer's signed advertisement. */
  private selfAdRumor(): Uint8Array {
    const payload = wire.signedPeerAd(this.selfAd(), this.identity);
    const itemId = `peer:${this.identity.peerId}:${this.now()}`;
    return wire.rumorBody("peers", itemId, this.rumorHops, payload);
  }

  /**
   * Writes one signed entry into a replicated space; returns its id. With
   * `agent` (v0.1.13) the entry is the agent's own: agent-signed record and
   * state, stored AGENT_ATTESTED everywhere.
   */
  writeEntry(space: string, typeName: string, value: Dict,
             agentName = "typescript", leaseMillis = 600_000,
             agent: AgentIdentity | null = null, tags: Dict = {}): string {
    if (agent !== null && this.revocations.refuses(agent.agentId, agent.publicRaw, null)) {
      throw new Error(`${agent.agentId} is revoked in this group`);
    }
    let payload: Uint8Array | null = dumps(value);
    let payloadRef: string | null = null;
    if (this.content !== null && this.content.escalateAbove > 0 && payload.length > this.content.escalateAbove) {
      // SPEC §7.1 group E: above the bound the payload becomes an artifact of the content swarm
      // and the record carries its root.
      payloadRef = this.content.publishOpaque(payload, leaseMillis);
      payload = null;
    } else if (payload.length > wire.INLINE_PAYLOAD_LIMIT) {
      payloadRef = this.putBlock(payload);
      payload = null;
    }
    this.joinSpace(space);
    const { entryId, body } = wire.entryDelta(space, this.group, typeName,
      payload, this.identity, agentName, leaseMillis, agent, this.now(), tags, payloadRef);
    // The writer holds its own entry too, folded into the verified local
    // replica before transport, so a local read sees it at once.
    // HLC round six, 2026-11-08 (F3): read strictly, as a receiver reads it, so a write this client
    // could not deliver to a strict receiver fails here, loudly.
    this.foldDelta(records.decodeRecord((loads(body) as Dict)["payload"] as Uint8Array, records.SPACE_DELTA) as Dict);
    this.send("RUMOR", body);
    return entryId;
  }

  /**
   * Publishes an advertisement this peer issued (an AgentCard, an AssetCard)
   * on the `ads` stream as DiscoveryService.publish does: the stored form,
   * under the advertisement's id and issue time. An AppCard or an AgentCard is
   * issued under the AppCard level and the card spill (SPEC §6.1a.2, §6.1a.5,
   * v0.1.32; AppCard origin and formats, 2026-11-09): pass the full card, and
   * the peer strips the gated fields while a member it knows is below level 2,
   * sends a card above 65,536 bytes as a stub behind an open gate, and reissues
   * the card at once when the members' level changes.
   */
  publishAd(adType: string, ad: Dict): void {
    if (adType === "AppCard" || adType === "AgentCard") {
      if (ad["spill"] !== undefined) {
        throw new Error("publish the full card: the peer decides whether it travels as a stub");
      }
      // read as the record before it is kept, so a card that fails its schema throws here and never reaches a
      // reissue (AppCard origin and formats, 2026-11-09, adversary pass)
      records.conform(ad, adType === "AppCard" ? records.APP_CARD : records.AGENT_CARD);
      const id = String(ad["id"]);
      this.pruneIssuedCards();
      const previous = this.issuedCards.get(id);
      this.issuedCards.set(id, { adType, full: ad, issued: previous?.issued ?? Number.NEGATIVE_INFINITY,
        open: previous?.open ?? null });
      this.issueCard(id);
      return;
    }
    this.sendAd(adType, ad);
  }

  /**
   * Stops reissuing a card published with {@link publishAd} (AppCardPublisher.withdraw; AppCard origin and formats,
   * 2026-11-09, adversary pass): the last card signed lapses at its ttl, and a parts document it named is released
   * once that card expires.
   */
  withdrawAd(id: string): void {
    this.issuedCards.delete(id);
    this.warnedSizes.delete(id);
  }

  /** Signs an advertisement, holds it in this peer's own cache, and sends it on the `ads` stream. */
  private sendAd(adType: string, ad: Dict): void {
    const stored = wire.storedAd(adType, ad, this.identity);
    this.acceptAd(stored); // our own cache holds it too, as DiscoveryService.publish does
    const itemId = `${String(ad["id"])}:${parseInstantMillis(ad["issued"])}`;
    this.send("RUMOR", wire.rumorBody("ads", itemId, 6, dumps(stored)));
  }

  /** Layer 4 (SPEC §6, §8): the members heard from (peer id to its advertisement, `{}` when only heard). */
  readonly members = new Map<string, Dict>();
  /** The signed `peers` payloads held per member, served on the `view` stream (SPEC §5.2, v0.1.17). */
  private readonly heldPeerAds = new Map<string, Uint8Array>();
  /**
   * The members a frame of ours can reach: those that signed a frame that
   * arrived on our connection. A dial-only peer has one socket, so a member
   * learned only from the peers stream (another dial-only peer behind the
   * same seed) is not among them; the seed drops, not relays, a frame to it.
   */
  readonly reachable = new Set<string>();
  /**
   * The advertisements the `ads` stream carried, by id, bounded by {@link adCacheMaxEntries} and by
   * {@link adCacheMaxBytes} of encoded advertisements (SPEC §6.3, v0.1.32).
   */
  readonly ads = new Map<string, CachedAd>();
  /** The most advertisements the cache holds (8,192 by default). */
  adCacheMaxEntries = AD_CACHE_MAX_ENTRIES;
  /** The most bytes of advertisement encodings the cache holds (32 MiB by default). */
  adCacheMaxBytes = AD_CACHE_MAX_BYTES;
  /** Advertisements the cache refused under its entry bound or its byte budget. */
  adsRefusedCacheFull = 0;
  private cachedBytes = 0;

  /** The sum of the cached advertisements' encodings, expired ones included until a refusal evicts them. */
  get adCacheBytes(): number {
    return this.cachedBytes;
  }
  /** Capability frame handlers by capability type: `(fromPeerId, payload)`. */
  readonly pipeHandlers = new Map<string, (from: string, payload: Uint8Array) => void>();
  /**
   * Handlers of gossip streams by stream id (PDT 2 phase 7, P2-P-02): a push follower takes the bundles of a ref's
   * stream `pdt:<space>:<name>`, and the handler's answer says whether this peer forwards the rumour, so a follower
   * forwards only what it took. A stream without a handler is relayed unread (rule 16).
   */
  readonly streamHandlers = new Map<string, (from: string, payload: Uint8Array) => boolean>();

  /** Anti-entropy pull of the `ads` stream (SPEC §6.2): the cards and capability advertisements the group holds. */
  pullAds(): void {
    this.pulledAds = true;
    this.send("DIGEST", wire.digestBody({ ads: new Uint8Array() }), null, "dial");
  }

  /**
   * Admits a StoredAd as AdCache.accept does: an advertisement type Java registers, the advertisement
   * read strictly as that type (HLC round six, 2026-11-08, F3), the signature over its bytes under
   * the carried key, the issuer derived from that key, and the TTL not yet passed. Returns the
   * cached entry, or null.
   */
  acceptAd(stored: unknown): CachedAd | null {
    const s = records.conformed(stored, records.STORED_AD);
    const schema = s === null ? undefined : records.AD_TYPES.get(String(s["adType"]));
    if (s === null || schema === undefined) {
      return null;
    }
    const adBytes = s["adBytes"] as Uint8Array;
    const key = s["publicKey"] as Uint8Array;
    if (key.length !== 32 || !Identity.verify(key, adBytes, s["signature"] as Uint8Array)) {
      return null;
    }
    const ad = records.readRecord(adBytes, schema);
    if (ad === null || ad["issuer"] !== deriveId(key)) {
      return null;
    }
    let expires: number;
    try {
      expires = parseInstantMillis(ad["issued"]) + parseDurationMillis(ad["ttl"]);
    } catch {
      return null;
    }
    if (expires <= this.now()) {
      return null;
    }
    const entry: CachedAd = { type: String(s["adType"]), ad, stored: s, issuer: String(ad["issuer"]), expires };
    const id = String(ad["id"]);
    const previous = this.ads.get(id);
    if (previous !== undefined && parseInstantMillis(previous.ad["issued"]) > parseInstantMillis(ad["issued"])) {
      return previous; // an older version leaves the held one in place
    }
    // SPEC §6.3 (v0.1.32; AppCard origin and formats, 2026-11-09): a new id that would pass either bound, or a version
    // that would pass the byte budget, is refused once the expired entries leave; nothing live is evicted for it
    if (!this.fitsCache(id, adBytes.length)) {
      this.evictExpiredAds();
      if (!this.fitsCache(id, adBytes.length)) {
        this.adsRefusedCacheFull += 1;
        return null;
      }
    }
    this.cachedBytes += adBytes.length - (this.ads.get(id)?.stored["adBytes"] as Uint8Array | undefined ?? new Uint8Array()).length;
    this.ads.set(id, entry);
    return entry;
  }

  /** Whether an advertisement of `length` bytes fits both bounds, given what the cache holds for its id. */
  private fitsCache(id: string, length: number): boolean {
    const held = this.ads.get(id);
    if (held === undefined) {
      return this.ads.size < this.adCacheMaxEntries && this.cachedBytes + length <= this.adCacheMaxBytes;
    }
    return this.cachedBytes - (held.stored["adBytes"] as Uint8Array).length + length <= this.adCacheMaxBytes;
  }

  /** Drops the cached advertisements whose TTL has passed. */
  private evictExpiredAds(): void {
    const now = this.now();
    for (const [id, entry] of this.ads) {
      if (entry.expires <= now) {
        this.ads.delete(id);
        this.cachedBytes -= (entry.stored["adBytes"] as Uint8Array).length;
      }
    }
  }

  /**
   * Whether this peer and every member it knows read the AppCard level (SPEC §6.1a.2, FR-6): the gate under which
   * it writes a card's origin, formats, an `idp` host, and a spill reference. A member heard before its
   * advertisement arrives counts as level 1.
   */
  appCardGateOpen(): boolean {
    if (this.level < APPCARD_LEVEL) {
      return false;
    }
    for (const ad of this.members.values()) {
      if (appCardLevelOf((ad["resourceHints"] as Dict | undefined)?.[APPCARD_HINT]) < APPCARD_LEVEL) {
        return false;
      }
    }
    return true;
  }

  /**
   * The full card of a stub (SPEC §6.1a.5, FR-15): a card without `spill` as it is, and otherwise the stub with its
   * parts document's values in place, read strictly as the card's record. A `size` above {@link spillMaxFetchBytes}
   * fails before any fetch (`spillsOverLimit`); a document of the wrong length, one that does not read as the kind's
   * parts record, or one whose non-empty fields are not exactly `spill.parts` fails (`spillsRefused`, a
   * {@link SpillRefusedError}). A document nobody serves in time fails uncounted. Nothing is struck, and a cached
   * stub stays cached.
   */
  async resolve(card: Dict): Promise<Dict> {
    const spill = card["spill"] as Dict | undefined;
    if (spill === undefined) {
      return card;
    }
    const kind = wire.spillKindOf(card);
    const id = String(card["id"]);
    const size = Number(spill["size"]);
    if (size > this.spillMaxFetchBytes) {
      this.spillsOverLimit += 1;
      throw new Error(`the parts document of ${id} is ${size} bytes, above the fetch bound of ${this.spillMaxFetchBytes}`);
    }
    const store = this.spillStore;
    if (store === null) {
      throw new Error(`no content swarm serves this group, so the stub ${id} stays a stub`);
    }
    let document: Uint8Array;
    try {
      document = await store.get(String(spill["root"]), size);
    } catch (e) {
      if (e instanceof SpillRefusedError) {
        this.spillsRefused += 1;
      }
      throw e;
    }
    try {
      if (document.length !== size) {
        throw new SpillRefusedError(`the parts document of ${id} is ${document.length} bytes; the stub states ${size}`);
      }
      const parts = records.decodeRecord(document, kind === "AppCard" ? records.APP_CARD_PARTS : records.AGENT_CARD_PARTS);
      return records.conform(wire.cardComplete(card, parts as Dict), kind === "AppCard" ? records.APP_CARD : records.AGENT_CARD) as Dict;
    } catch (e) {
      this.spillsRefused += 1;
      throw e instanceof SpillRefusedError ? e
        : new SpillRefusedError(`the parts document of ${id} does not complete its stub`, { cause: e });
    }
  }

  /**
   * Issues one kept card (FR-7, FR-12, FR-13): under a strictly newer `issued` than the last one signed, without the
   * gated fields when the gate is closed, and as a stub when it passes the spill threshold behind an open gate with
   * a spill store that takes its parts document; otherwise inline in full.
   */
  private issueCard(id: string): void {
    const kept = this.issuedCards.get(id)!;
    const open = this.appCardGateOpen();
    kept.open = open;
    const issued = Math.max(parseInstantMillis(kept.full["issued"]), kept.issued + 1);
    kept.issued = issued;
    const current: Dict = { ...kept.full, issued: instantIso(issued) };
    const card = kept.adType === "AppCard" ? wire.appCardForView(current, open) : current;
    if (Object.keys(card).length !== Object.keys(current).length) {
      this.appCardsDowngraded += 1;
    }
    const schema = kept.adType === "AppCard" ? records.APP_CARD : records.AGENT_CARD;
    const size = dumps(records.conform(card, schema)).length;
    const parts = size > wire.CARD_SPILL_THRESHOLD_BYTES ? wire.cardSpillParts(card) : [];
    const store = this.spillStore;
    // a card whose size sits outside the spill set (a long name or description) has nothing to move
    const spills = parts.length > 0 && open && store !== null;
    this.warnCard(kept.adType, card, size, spills);
    let signed = card;
    if (size > wire.CARD_SPILL_THRESHOLD_BYTES) {
      signed = spills ? this.spill(kept.adType, card, parts, store!) : card;
      if (signed === card) {
        this.cardsOversizeInline += 1;
      }
    }
    this.sendAd(kept.adType, signed);
  }

  /** The stub of a full card once its parts document is on the swarm, or the card itself when the swarm refuses it. */
  private spill(adType: "AppCard" | "AgentCard", card: Dict, parts: string[], store: SpillStore): Dict {
    const partsSchema = adType === "AppCard" ? records.APP_CARD_PARTS : records.AGENT_CARD_PARTS;
    const document = dumps(records.conform(wire.cardParts(card), partsSchema));
    let root: string;
    try {
      root = store.put(String(card["id"]), document);
    } catch (e) {
      this.onWarning(`the content swarm refused the parts document of ${String(card["id"])}; the card travels inline: ${String(e)}`);
      return card;
    }
    this.holdSpill(root, parseInstantMillis(card["issued"]) + parseDurationMillis(card["ttl"]));
    this.cardsSpilled += 1;
    return wire.cardStub(card, { root, size: document.length, parts });
  }

  /** FR-13: one warning per card id and encoded size past 57,344 bytes, naming the card and saying what happens. */
  private warnCard(adType: string, card: Dict, size: number, spills: boolean): void {
    const id = String(card["id"]);
    if (size <= wire.CARD_SPILL_WARN_BYTES || this.warnedSizes.get(id) === size) {
      return;
    }
    this.warnedSizes.set(id, size);
    const kind = adType === "AppCard" ? `AppCard (kind ${String(card["kind"])})` : adType;
    const fate = size <= wire.CARD_SPILL_THRESHOLD_BYTES ? "it travels inline until it passes the threshold"
      : spills ? "it spills its large parts to the content swarm"
        : "it travels inline, since a member is below the AppCard level, no content swarm serves the group,"
          + " or no field of its spill set holds anything";
    this.onWarning(`${kind} ${id} encodes to ${size} bytes, past the ${wire.CARD_SPILL_WARN_BYTES}-byte warning`
      + ` and ${size <= wire.CARD_SPILL_THRESHOLD_BYTES ? "within" : "past"} the ${wire.CARD_SPILL_THRESHOLD_BYTES}-byte`
      + ` spill threshold; ${fate}`);
  }

  /** Keeps a parts document served until the last card that names it expires. */
  private holdSpill(root: string, until: number): void {
    this.spillHolds.set(root, Math.max(this.spillHolds.get(root) ?? 0, until));
    this.spillSweep ??= this.every(SPILL_SWEEP_MILLIS, () => this.sweepSpills());
  }

  /** Releases every parts document whose last naming card has expired. */
  private sweepSpills(): void {
    const now = this.now();
    for (const [root, until] of [...this.spillHolds]) {
      if (now >= until) {
        this.spillHolds.delete(root);
        this.spillStore?.release(root);
      }
    }
    if (this.spillHolds.size === 0) {
      this.spillSweep?.stop();
      this.spillSweep = null;
    }
  }

  /** Forgets the kept cards whose last issue has expired: this peer issues them no more. */
  private pruneIssuedCards(): void {
    const now = this.now();
    for (const [id, kept] of [...this.issuedCards]) {
      if (kept.issued + parseDurationMillis(kept.full["ttl"]) <= now) {
        this.issuedCards.delete(id);
        this.warnedSizes.delete(id);
      }
    }
  }

  /**
   * A member's AppCard level may have changed (its advertisement arrived or changed, it left, or this peer's own
   * level changed): every kept card last issued under the other gate whose form depends on the gate goes out again at
   * once. A card issued while a member heard only by its frames held the gate closed thus follows when that member's
   * advertisement arrives, whatever the gate of the cards issued since.
   */
  private appCardLevelChanged(): void {
    if (this.issuedCards.size === 0) {
      return;
    }
    const open = this.appCardGateOpen();
    this.pruneIssuedCards();
    for (const [id, kept] of this.issuedCards) {
      if (kept.open === open) {
        continue;
      }
      const schema = kept.adType === "AppCard" ? records.APP_CARD : records.AGENT_CARD;
      const gated = kept.adType === "AppCard"
        && Object.keys(wire.appCardForView(kept.full, false)).length !== Object.keys(kept.full).length;
      if (gated || dumps(records.conform(kept.full, schema)).length > wire.CARD_SPILL_THRESHOLD_BYTES) {
        this.issueCard(id);
      } else {
        kept.open = open; // its form is the same under either gate
      }
    }
  }

  /** The live AgentCards the ads stream carried. */
  cards(): Dict[] {
    const now = this.now();
    return [...this.ads.values()].filter((e) => e.type === "AgentCard" && e.expires > now).map((e) => e.ad);
  }

  /**
   * One capability frame to a member (CapabilityPipes.send): a PIPE_DATA envelope addressed to
   * it. A dial-only peer's seed carries it when `to` is any other member (SPEC §5.4); `via` (the
   * relays the member declared) extends the path past the seed.
   */
  sendPipe(to: string, capability: string, payload: Uint8Array, via: string[] | null = null): void {
    this.sendAddressed("PIPE_DATA", dumps({ capability, payload }), to, via);
  }

  /**
   * The relay an addressed frame to `to` goes through, or null for a direct send: for a peer
   * that only dialed (no accepted links), the seed for everyone but the seed itself.
   */
  relayFor(to: string): string | null {
    if (this.channel === null || this.inbound.size > 0 || this.seedPeer === null || to === this.seedPeer) {
      return null;
    }
    return this.seedPeer;
  }

  /**
   * Sends an addressed frame directly or, when the seed must carry it, wrapped in a
   * `RELAY_FRAME` to the seed (the one-hop form), extended to a path `[seed, via...]` when
   * `via` names other relays (v0.1.23).
   */
  sendAddressed(kind: string, body: Uint8Array, to: string, via: string[] | null = null): void {
    const relay = this.relayFor(to);
    if (relay === null) {
      this.send(kind, body, to);
      return;
    }
    const inner = wire.encodeFrame(wire.envelope(this.group, kind, this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now()), body, to), this.identity);
    const path = [relay, ...(via ?? []).filter((v) => v !== relay && v !== to)].slice(0, Math.max(1, this.maxPathHops));
    this.relayedFrames += 1;
    this.send("RELAY_FRAME", path.length > 1 ? wire.relayFrameBody(to, inner, path, 0)
      : wire.relayFrameBody(to, inner), relay);
    this.noteRelayed(to);
  }

  /**
   * The payload bytes of an entry's record: inline, or resolved from a block (`z`) or a content
   * root (`b`) held here. A reference not yet held starts its transfer and returns null; reads
   * never block on the network (SPEC §7.2). A null payload with no reference is the CBOR null.
   */
  payloadOf(dto: Dict): Uint8Array | null {
    const record = (dto["record"] as Dict | undefined) ?? {};
    const payload = record["payload"];
    if (payload instanceof Uint8Array) {
      return payload;
    }
    const ref = record["payloadRef"];
    if (typeof ref !== "string" || ref.length === 0) {
      return new Uint8Array([0xf6]);
    }
    if (ref.startsWith("b")) {
      // SPEC §7.1 tree roots: the codec alone tells a persistent tree (dag-cbor, 0x71) from a piece
      // artifact (raw, 0x55); each goes to the seam that can carry it, never the other
      // (srad/agentspaces-pdt.md PD-E-01). Without a facade a tree root stays invisible here.
      if (isTreeRoot(ref)) {
        return this.pdt === null ? null : this.pdt.payload(ref);
      }
      if (this.content === null) {
        return null;
      }
      const data = this.content.local(ref);
      if (data === null) {
        this.content.ensure(ref);
      }
      return data;
    }
    const block = this.blocks.get(ref);
    if (block === undefined) {
      this.wantBlock(ref, dto);
    }
    return block ?? null;
  }

  /** Asks the entry's issuing peer (and the seed) for a block, at most once a second. */
  wantBlock(cid: string, dto: Dict | null = null): void {
    const now = Date.now();
    if (now - (this.blockAsked.get(cid) ?? Number.NEGATIVE_INFINITY) < 1000) {
      return;
    }
    this.blockAsked.set(cid, now);
    const targets: string[] = [];
    const key = dto?.["issuerPublicKey"];
    if (key instanceof Uint8Array) {
      targets.push(deriveId(key));
    }
    if (this.seedPeer !== null && !targets.includes(this.seedPeer)) {
      targets.push(this.seedPeer);
    }
    for (const target of targets) {
      if (target !== this.identity.peerId) {
        this.sendAddressed("BLOCK_WANT", wire.blockWantBody(cid), target);
      }
    }
  }

  /** Stores a block here and returns its id; served to any member that asks. */
  putBlock(data: Uint8Array): string {
    const cid = wire.contentId(data);
    this.blocks.set(cid, data);
    return cid;
  }

  /** The members whose advertisement declares the RELAY role (SPEC §5.4). */
  relayMembers(): string[] {
    const out: string[] = [];
    for (const [id, ad] of this.members) {
      const roles = ad["roles"];
      if (Array.isArray(roles) && roles.some((r) => String(r) === "RELAY") && id !== this.identity.peerId) {
        out.push(id);
      }
    }
    return out;
  }

  /**
   * A capability frame to a member (SRAD srad/agentspaces-js.md JS-W-03): sent directly when the
   * target is reachable, otherwise inside a `RELAY_FRAME` through a reachable RELAY-role member.
   * The inner frame is this peer's fully signed `PIPE_DATA` to the target, so the relay forwards
   * it verbatim and the target verifies the origin. Returns whether a route was found.
   */
  sendPipeOrRelay(to: string, capability: string, payload: Uint8Array): boolean {
    if (this.reachable.has(to) || this.relayFor(to) !== null) {
      this.sendPipe(to, capability, payload);
      return true;
    }
    const relay = this.relayMembers().find((m) => this.reachable.has(m));
    if (relay === undefined) {
      return false;
    }
    const inner = wire.encodeFrame(wire.envelope(this.group, "PIPE_DATA", this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now()), dumps({ capability, payload }), to), this.identity);
    this.send("RELAY_FRAME", wire.relayFrameBody(to, inner), relay);
    this.noteRelayed(to); // JS-W-11: a frame the relay carried for this pair
    return true;
  }

  /**
   * The relay offload's observation (SRAD srad/agentspaces-js.md JS-W-11, PeerNode.noteRelayed):
   * per member, the clock stamps of the frames relayed between this peer and it in the last
   * minute, sent through a relay or unwrapped from a `RELAY_FRAME` addressed here. The core only
   * counts and tells; a binding that can open a direct connection (`@agentspaces/webrtc`)
   * subscribes and decides, with its own threshold and backoff. Bounded as a cache, not a cap.
   */
  private readonly relayedWith = new Map<string, number[]>();
  private readonly relayedListeners: ((member: string, framesInLastMinute: number) => void)[] = [];
  /** How many members' relay windows stay remembered; the least recently relayed-with is dropped past it. */
  relayedMemory = 4096;

  /** Registers an observer told, on every frame relayed to or from a member, how many were in the sliding minute. */
  onRelayed(listener: (member: string, framesInLastMinute: number) => void): this {
    this.relayedListeners.push(listener);
    return this;
  }

  /** The frames relayed between this peer and a member in the last minute, as the offload counts them. */
  relayedWithInLastMinute(member: string): number {
    const times = this.relayedWith.get(member);
    return times === undefined ? 0 : pruneMinute(times, this.now());
  }

  private noteRelayed(member: string): void {
    const now = this.now();
    let times = this.relayedWith.get(member);
    if (times === undefined) {
      times = [];
    } else {
      this.relayedWith.delete(member); // re-inserted last: the map's order is the recency order
    }
    this.relayedWith.set(member, times);
    pruneMinute(times, now);
    times.push(now);
    while (this.relayedWith.size > this.relayedMemory) {
      const eldest = this.relayedWith.keys().next().value;
      if (eldest === undefined) {
        break;
      }
      this.relayedWith.delete(eldest);
    }
    const count = times.length;
    for (const listener of this.relayedListeners) {
      try {
        listener(member, count);
      } catch {
        // an observer's failure never stops the frame
      }
    }
  }

  /**
   * A `peers` stream item (PeerNode.SignedPeerAd): kept under its issuer when it and its
   * PeerAdvertisement read strictly (HLC round six, 2026-11-08, F3) and its signature verifies.
   */
  private acceptPeerAd(payload: Uint8Array): void {
    try {
      const signed = records.readRecord(payload, records.SIGNED_PEER_AD);
      if (signed === null) {
        return;
      }
      const adBytes = signed["adBytes"] as Uint8Array;
      const key = signed["publicKey"] as Uint8Array;
      if (key.length !== 32 || !Identity.verify(key, adBytes, signed["signature"] as Uint8Array)) {
        return;
      }
      const ad = records.readRecord(adBytes, records.PEER_ADVERTISEMENT);
      if (ad !== null && ad["issuer"] === deriveId(key)
          && ad["issuer"] !== this.identity.peerId) {
        const issuer = String(ad["issuer"]);
        const previous = this.members.get(issuer);
        if (previous !== undefined && previous["issued"] !== undefined
            && parseInstantMillis(previous["issued"]) > parseInstantMillis(ad["issued"])) {
          return; // an older issue of an advertisement already held
        }
        this.members.set(issuer, ad);
        this.heldPeerAds.set(issuer, payload);
        this.appCardLevelChanged();
        const hints = (ad["resourceHints"] ?? {}) as Dict;
        if (this.channelAuth === "session" && hints[SESSION_HINT] === "1") {
          this.sessionPeers.add(String(ad["issuer"]));
        } else {
          this.sessionPeers.delete(String(ad["issuer"]));
        }
      }
    } catch {
      // not a peer advertisement
    }
  }

  /**
   * Called after a state folds, for spaces and watches: the merged state, and the state this replica held
   * before, when it held one (core cancel events, 2026-11-09: a space raises EXPIRED for a withdrawal of an
   * entry that was present).
   */
  onState: ((dto: Dict, previous?: Dict) => void) | null = null;
  /** Takes waiting for the next fold (JS-V-02): woken by a state or a claim, or by their own deadline. */
  private readonly foldWaiters = new Set<() => void>();
  /** When the last anti-entropy pull of each space went out, so a waiting take pulls at most once per settle window. */
  private readonly lastPullMillis = new Map<string, number>();

  /** Resolves on the next fold (a state or a claim) or after `maxMillis`, whichever comes first. */
  awaitFold(maxMillis: number): Promise<void> {
    return this.foldOrTimeout(maxMillis);
  }

  /** Resolves on the next fold or after `maxMillis`, whichever comes first. */
  private foldOrTimeout(maxMillis: number): Promise<void> {
    return new Promise<void>((resolve) => {
      const timer = this.timers.setTimeout(() => {
        this.foldWaiters.delete(wake);
        resolve();
      }, Math.max(0, maxMillis));
      const wake = (): void => {
        this.timers.clearTimeout(timer);
        this.foldWaiters.delete(wake);
        resolve();
      };
      this.foldWaiters.add(wake);
    });
  }

  private wakeFoldWaiters(): void {
    for (const wake of [...this.foldWaiters]) {
      wake();
    }
  }

  /** Pulls a space unless it was pulled within `settleMillis` (JS-Q-PRF-01: one DIGEST per settle window). */
  private pullSpacePaced(space: string, settleMillis: number): void {
    const now = Date.now();
    if (now - (this.lastPullMillis.get(space) ?? -Infinity) >= settleMillis) {
      this.lastPullMillis.set(space, now);
      this.pullSpace(space);
    }
  }
  /** Called after a claim folds (the merged signed claim). */
  onClaim: ((entryId: string, signed: Dict) => void) | null = null;
  /** Called with the entry ids a tombstone collection dropped, so spaces forget what they judged of them. */
  onCollected: ((entryIds: string[]) => void) | null = null;

  /**
   * Installs a claim the ordered log committed (OrderedTakes.onCommand, SPEC §7.4 ORDERED):
   * exactly as the holder signed it, through the same verification gossip gets, and then
   * gossips it on the space's stream so members outside the log learn it. Returns whether the
   * claim is now the one held for the entry.
   */
  applyCommittedClaim(space: string, entryId: string, signed: Dict): boolean {
    this.foldClaim(entryId, signed, true);
    const held = this.claims.get(entryId);
    if (held === undefined || !equals(dumps((held["claim"] as Dict) ?? {}), dumps((signed["claim"] as Dict) ?? {}))) {
      return false;
    }
    this.send("RUMOR", wire.rumorBody(`space:${space}`, `c:${entryId}:${this.now()}`, this.rumorHops,
      wire.claimDelta(entryId, held)));
    return true;
  }

  /**
   * Joins a space by name: its rumors and anti-entropy answers fold here from now on. Pulling,
   * writing, and opening a Space join it; this peer relays a rumor of a space it has not joined
   * without decoding it (HLC round five, 2026-11-08).
   */
  joinSpace(space: string): void {
    this.joinedSpaces.add(space);
  }

  /**
   * Collects tombstones (SPEC §7.3, ReplicatedSpace's sweep): drops every entry past its collection
   * horizon, with its claim and any block or bulk payload no remaining entry names, and tells
   * `onCollected`. HLC round five, 2026-11-08: without it the replica held every entry ever written,
   * and each sweep, digest, and read grew with them. HLC round six, 2026-11-08: a collected entry's
   * bulk payload is released through the content seam (R9, Java's LB-E-04), and a claim on an entry
   * this replica collected or never held goes once its expiry passes, so the claim map stays bounded
   * (R10). Returns the collected entry ids.
   */
  collectTombstones(): string[] {
    const now = this.now();
    for (const [entryId, signed] of this.claims) {
      if (!this.states.has(entryId) && Number((signed["claim"] as Dict)["expiresAtMillis"]) <= now) {
        this.claims.delete(entryId);
      }
    }
    const collected: string[] = [];
    for (const [entryId, dto] of this.states) {
      if (collectable(dto, now, this.longestLeaseOf(dto))) {
        collected.push(entryId);
      }
    }
    if (collected.length === 0) {
      return collected;
    }
    const released = new Set<string>();
    for (const entryId of collected) {
      const ref = (this.states.get(entryId)!["record"] as Dict | undefined)?.["payloadRef"];
      if (typeof ref === "string" && (this.blocks.has(ref) || this.isBulk(ref))) {
        released.add(ref);
      }
      this.states.delete(entryId);
      this.claims.delete(entryId);
    }
    if (released.size > 0) {
      for (const dto of this.states.values()) {
        released.delete(String((dto["record"] as Dict | undefined)?.["payloadRef"]));
      }
      for (const ref of released) {
        if (this.isBulk(ref)) {
          this.content!.unpin(ref);
        } else {
          this.blocks.delete(ref);
          this.blockAsked.delete(ref);
        }
      }
    }
    this.onCollected?.(collected);
    return collected;
  }

  /** Whether `ref` names a payload the content seam holds: a `b` root that is no persistent tree. */
  private isBulk(ref: string): boolean {
    return this.content !== null && ref.startsWith("b") && !isTreeRoot(ref);
  }

  /** The longest lease observed in the space of `dto`, the horizon's measure (SPEC §7.3). */
  private longestLeaseOf(dto: Dict): number {
    return this.longestLease.get(String((dto["record"] as Dict | undefined)?.["spaceId"])) ?? 0;
  }

  /**
   * Records the lease `dto` grants, from its lease stamp to its expiry, as the longest of its space
   * when it is (SPEC §7.3, HLC round five, 2026-11-08), capped at MAX_TRACKED_LEASE_MILLIS; a
   * non-positive lease records nothing.
   */
  private observeLease(dto: Dict): void {
    this.observeGrant(String((dto["record"] as Dict)["spaceId"]), leaseExpiryOf(dto) - wire.hlcPhysical(dto["leaseStamp"]));
  }

  /**
   * Records the hold a claim this replica merges grants, from its stamp to its expiry, as Java's
   * ReplicatedSpace observes every claim it merges and every take it makes (SPEC §7.3, HLC round
   * five, 2026-11-08): a space of short writes and long holds keeps its tombstones two holds.
   */
  private observeClaimLease(signed: Dict): void {
    const claim = signed["claim"] as Dict;
    this.observeGrant(String(claim["spaceId"]), Number(claim["expiresAtMillis"]) - wire.hlcPhysical(claim["stamp"]));
  }

  /** Raises the longest lease of `spaceId` to `grantedMillis`, capped at MAX_TRACKED_LEASE_MILLIS. */
  private observeGrant(spaceId: string, grantedMillis: number): void {
    const granted = Math.min(grantedMillis, MAX_TRACKED_LEASE_MILLIS);
    if (granted > (this.longestLease.get(spaceId) ?? 0)) {
      this.longestLease.set(spaceId, granted);
    }
  }

  /**
   * Anti-entropy pull (spec §5.3): offer an empty digest. The revocation
   * streams ride along: a partner answers only the streams a digest names, so
   * a late joiner learns the group's revocations here.
   */
  pullSpace(space: string): void {
    this.joinSpace(space);
    this.pulledSpaces.add(space);
    // HLC round four, 2026-11-08 (D5): the digest names no entry, so the partner answers with every
    // state but those this replica refused and acknowledges.
    this.send("DIGEST", wire.digestBody({ [`space:${space}`]: utf8(this.acknowledgedLines(space)),
      ...revocationDigests() }), null, "dial");
  }

  /**
   * Anti-entropy pull of the membership view (SPEC §5.2, v0.1.17: the view is reconcilable
   * state, the `view` stream): the digest names the members this peer holds, and the partner
   * answers with the signed advertisements it lacks, so a late joiner behind a seed learns the
   * members whose introductions it never saw.
   */
  pullView(): void {
    this.pulledView = true;
    this.send("DIGEST", wire.digestBody({ view: this.viewDigest() }), null, "dial");
  }

  private pulledView = false;

  /** `PeerNode.ViewState.digest`: one line per member held, this peer included. */
  viewDigest(): Uint8Array {
    const ids = [...this.heldPeerAds.keys(), this.identity.peerId].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return utf8(ids.map((id) => `${id}\n`).join(""));
  }

  /** `PeerNode.ViewState.deltaFor`: the signed advertisements the remote digest does not name, this peer's own included. */
  viewDeltaFor(remoteDigest: Uint8Array): Uint8Array {
    const remote = serving.parseDigestLines(remoteDigest);
    const missing: Uint8Array[] = [];
    for (const [id, payload] of this.heldPeerAds) {
      if (!remote.has(id)) {
        missing.push(payload);
      }
    }
    if (!remote.has(this.identity.peerId)) {
      missing.push(wire.signedPeerAd(this.selfAd(), this.identity));
    }
    return missing.length === 0 ? new Uint8Array() : dumps(missing);
  }

  /**
   * Anti-entropy pull of the revocation streams alone (SPEC §5.6): sent once
   * on joining, so revocations issued before this peer arrived apply from its
   * first merge.
   */
  pullRevocations(): void {
    // The membership view rides along (SPEC §5.2, v0.1.17): a late joiner behind a seed learns the
    // members whose introductions it never saw, from the same answer.
    this.pulledView = true;
    this.send("DIGEST", wire.digestBody({ ...revocationDigests(), view: this.viewDigest() }), null, "dial");
  }

  /** Returns decoded values of known live entries of one schema type. */
  find(typeName: string): Dict[] {
    const results: Dict[] = [];
    for (const dto of this.states.values()) {
      const record = dto["record"] as Dict | undefined;
      if (record && record["type"] === typeName && present(dto)) {
        const read = applicationValue(this.payloadOf(dto));
        if (read !== null) {
          results.push(read.value);
        }
      }
    }
    return results;
  }

  /**
   * Takes one entry under LEASE_RACE (spec §7.4): publish a signed claim,
   * wait one settle window, and win when the lattice still says so.
   */
  async takeEntry(space: string, typeName: string, agentName = "ts-worker",
                  leaseMillis = 60_000, settleMillis = 600,
                  timeoutMillis = 15_000, agent: AgentIdentity | null = null,
                  exactEntryId: string | null = null,
                  matches: ((payload: Dict, tags: Dict) => boolean) | null = null,
                  bid: number | ((payload: Dict) => number) = 0.0): Promise<string | null> {
    const holder = agent !== null ? agent.agentId : this.identity.agent(agentName);
    if (this.revocations.refuses(holder, agent?.publicRaw ?? null, null)) {
      return null; // a revoked agent takes nothing, even locally
    }
    const deadline = Date.now() + timeoutMillis;
    while (Date.now() < deadline) {
      // Fold-driven (JS-V-02): one pull per settle window at most, then wait for a fold rather
      // than a fixed sleep, so an entry that arrives wakes the take at once.
      this.pullSpacePaced(space, settleMillis);
      await this.foldOrTimeout(Math.min(settleMillis, deadline - Date.now()));
      const now = this.now();
      for (const [entryId, dto] of this.states) {
        const record = dto["record"] as Dict | undefined;
        if (!record || record["type"] !== typeName || !present(dto)
            || (record["group"] !== undefined && record["group"] !== this.group)
            || record["spaceId"] !== wireSpaceId(this.group, space)
            || (exactEntryId !== null && entryId !== exactEntryId)) {
          continue;
        }
        if (leaseExpiryOf(dto) <= now) {
          continue;
        }
        const current = this.claims.get(entryId)?.["claim"] as Dict | undefined;
        if (current && Number(current["expiresAtMillis"]) > now) {
          continue;
        }
        // A template narrows the candidates; a bid function prices the claim (AUCTION).
        const read = applicationValue(this.payloadOf(dto));
        if (read === null) {
          continue; // its block or artifact is still on its way, or its value is unreadable
        }
        const payload = read.value;
        if (matches !== null && !matches(payload ?? {}, (record["tags"] as Dict) ?? {})) {
          continue;
        }
        const price = typeof bid === "function" ? bid(payload ?? {}) : bid;
        const epoch = current ? Number(current["epoch"]) + 1 : 1;
        const claim = wire.takeClaim(entryId, String(record["spaceId"]), epoch,
          wire.hlcNow(holder, now), holder, price, now + leaseMillis);
        const signed = wire.signedClaim(claim, this.identity, agent);
        this.observeClaimLease(signed);
        this.claims.set(entryId, wire.mergeClaims(this.claims.get(entryId), signed));
        this.send("RUMOR", wire.rumorBody(`space:${space}`,
          `c:${entryId}:${claim["stamp"]}`, 6, wire.claimDelta(entryId, signed)));
        await this.foldOrTimeout(settleMillis); // the settle window: a competing claim folds within it
        this.pullSpacePaced(space, settleMillis);
        await this.foldOrTimeout(Math.min(settleMillis, 300));
        const winner = this.claims.get(entryId)?.["claim"] as Dict | undefined;
        if (winner && winner["holder"] === holder
            && Number(winner["epoch"]) === epoch
            && Number(winner["expiresAtMillis"]) > this.now()
            // core cancel events, 2026-11-09: an entry completed or withdrawn during the settle window is nobody's
            && present(this.states.get(entryId) ?? {})
            && !this.revocations.refuses(holder, agent?.publicRaw ?? null, null)) {
          // As Java's take fires TAKEN for the claim it won (HLC round six, 2026-11-08, R9).
          this.onClaim?.(entryId, this.claims.get(entryId)!);
          return entryId;
        }
      }
    }
    return null;
  }

  /**
   * Completes a held entry: publish its state with completed set (monotone),
   * re-signed with our (holder) key and carrying our winning claim, so honest
   * replicas can authenticate the completion (SPEC §11a).
   */
  completeEntry(space: string, entryId: string, agent: AgentIdentity | null = null): void {
    this.requireHeld(space, entryId, agent);
    // A claim taken as an agent must be completed as that agent (A6, v0.1.13).
    const previous = this.states.get(entryId)!;
    const dto = wire.signState({ ...previous, completed: true }, this.identity, agent, this.now());
    this.states.set(entryId, dto);
    this.onState?.(dto, previous);
    const proof = this.claims.get(entryId) ?? null;
    this.send("RUMOR", wire.rumorBody(`space:${space}`, `d:${entryId}`, 6,
      dumps({ state: dto, claimEntry: proof ? entryId : null, claim: proof })));
  }

  /** Checks the exact current live claim before an application emits a result. */
  requireHeld(space: string, entryId: string, agent: AgentIdentity | null = null): void {
    const state = this.states.get(entryId), record = state?.["record"] as Dict | undefined;
    const claim = this.claims.get(entryId)?.["claim"] as Dict | undefined;
    const holder = agent?.agentId ?? claim?.["holder"];
    const signed = this.claims.get(entryId);
    const localPeerHolder = agent !== null || (typeof holder === "string"
      && holder.startsWith(this.identity.peerId + "/") && signed?.["holderCertificate"] == null
      && signed?.["holderKey"] instanceof Uint8Array
      && equals(signed["holderKey"] as Uint8Array, this.identity.publicRaw));
    if (!record || (record["group"] !== undefined && record["group"] !== this.group) || record["spaceId"] !== wireSpaceId(this.group, space)
        // core cancel events, 2026-11-09: a completed or withdrawn entry is held by nobody, as in Java
        || !localPeerHolder || !present(state ?? {}) || !claim || claim["entryId"] !== entryId
        || claim["spaceId"] !== record["spaceId"] || claim["holder"] !== holder
        || !Number.isFinite(Number(claim["expiresAtMillis"])) || Number(claim["expiresAtMillis"]) <= this.now()
        || Number(((state?.["leaseValue"] ?? record["lease"]) as Dict)?.["expiresAtMillis"]) <= this.now()
        || this.revocations.refuses(holder, agent?.publicRaw ?? null, null)) {
      throw new Error("Current exact live claim required");
    }
  }

  /** Extend a held claim using the existing claim lattice, with a fresh epoch. */
  renewClaim(space: string, entryId: string, leaseMillis: number, agent: AgentIdentity): void {
    if (!Number.isFinite(leaseMillis) || leaseMillis <= 0) throw new Error("Positive lease required");
    this.requireHeld(space, entryId, agent);
    const previous = this.claims.get(entryId)!["claim"] as Dict;
    const claim = wire.takeClaim(entryId, String(previous["spaceId"]), Number(previous["epoch"]) + 1,
      wire.hlcNow(agent.agentId, this.now()), agent.agentId, 0.0, this.now() + leaseMillis);
    const signed = wire.signedClaim(claim, this.identity, agent);
    this.observeClaimLease(signed);
    this.claims.set(entryId, wire.mergeClaims(this.claims.get(entryId), signed));
    this.send("RUMOR", wire.rumorBody(`space:${space}`, `c:${entryId}:${claim["stamp"]}`, 6,
      wire.claimDelta(entryId, signed)));
  }

  /** Snapshot contains signed public material only. Restore re-verifies every entry. */
  exportSnapshot(): Dict {
    return { group: this.group, states: [...this.states.values()], claims: Object.fromEntries(this.claims), revocations: this.revocations.exportSigned() };
  }
  restoreSnapshot(snapshot: Dict): void {
    if (snapshot["group"] !== this.group) throw new Error("Snapshot group mismatch");
    this.revocations.restoreSigned((snapshot["revocations"] ?? {}) as Dict, this.now());
    // HLC round six, 2026-11-08 (F1): a claim or state that is no conformed SignedClaim or
    // EntryStateDto counts as an undecodable carrier, as a delta bringing it would.
    for (const [id, held] of Object.entries((snapshot["claims"] ?? {}) as Dict)) {
      const claim = records.conformed(held, records.SIGNED_CLAIM);
      if (claim === null) {
        this.deltasUndecodable += 1;
        continue;
      }
      this.foldClaim(id, claim);
    }
    for (const held of (snapshot["states"] ?? []) as Dict[]) {
      const dto = records.conformed(held, records.ENTRY_STATE);
      if (dto === null) {
        this.deltasUndecodable += 1;
        continue;
      }
      if (dto["record"] !== undefined) this.fold(dto);
    }
  }

  /**
   * Renews this peer's write of an entry (SPEC §7.3): a later lease stamp and
   * expiry, re-signed by the issuer, as the agent when it wrote as one. Only
   * the issuer renews: `agent` must be the record's issuer, and without one
   * the issuer must be one of this peer's agent names.
   */
  /**
   * Cancels an entry this peer (or `agent`) wrote, as `EntryHandle.cancel` does in Java: a state whose
   * `removes` cover its `adds`, signed by the issuer, so every replica drops the entry. Reads, finds,
   * takes, and watches here skip it at once, and the replica keeps its tombstone until the collection
   * horizon (SPEC §7.3, HLC round five, 2026-11-08). Watches here hear EXPIRED at once, and every other
   * member's when the withdrawal folds there (core cancel events, 2026-11-09). An entry this replica holds
   * completed or withdrawn stays as it is and nothing goes out, as Java's `EntryHandle.cancel` leaves it: an
   * issuer's signature over a completed state verifies nowhere (SPEC §11a.4).
   */
  cancelEntry(space: string, entryId: string, agent: AgentIdentity | null = null): void {
    const previous = this.states.get(entryId);
    if (previous === undefined) {
      throw new Error(`${entryId} is not held here`);
    }
    const record = previous["record"] as Dict;
    const issuer = String(record["issuer"]);
    if (agent !== null && agent.agentId !== issuer) {
      throw new Error(`${entryId} was written by ${issuer}, not ${agent.agentId}`);
    }
    if (agent === null && !issuer.startsWith(this.identity.peerId + "/")) {
      throw new Error(`${entryId} was written by ${issuer}, not by this peer`);
    }
    if (!present(previous)) {
      return;
    }
    const now = this.now();
    const dto = wire.signState({ ...previous, removes: unionDots(previous["removes"], previous["adds"]) },
      this.identity, agent, now);
    this.states.set(entryId, dto);
    this.onState?.(dto, previous);
    this.send("RUMOR", wire.rumorBody(`space:${space}`, `x:${entryId}:${now}`, 6,
      dumps({ state: dto, claimEntry: null, claim: null })));
  }

  renewEntry(space: string, entryId: string, leaseMillis = 600_000,
             agent: AgentIdentity | null = null): void {
    const previous = this.states.get(entryId)!;
    const record = previous["record"] as Dict;
    const issuer = String(record["issuer"]);
    if (agent !== null && agent.agentId !== issuer) {
      throw new Error(`${entryId} was written by ${issuer}, not ${agent.agentId}`);
    }
    if (agent === null && !issuer.startsWith(this.identity.peerId + "/")) {
      throw new Error(`${entryId} was written by ${issuer}, not by this peer`);
    }
    const now = this.now();
    const dto = wire.signState({ ...previous, leaseStamp: wire.hlcNow(issuer, now),
      leaseValue: { holder: issuer, expiresAtMillis: now + leaseMillis, kind: "WRITE" } },
    this.identity, agent, now);
    this.observeLease(dto);
    this.states.set(entryId, dto);
    this.send("RUMOR", wire.rumorBody(`space:${space}`, `r:${entryId}:${now}`, 6,
      dumps({ state: dto, claimEntry: null, claim: null })));
  }

  // ------------------------------------------------------------------ internals

  private async dial(seed: Seed): Promise<void> {
    const dialer = this.dialers.get(schemeOf(seed));
    if (dialer === undefined) {
      throw new Error(`no dialer for ${schemeOf(seed)}`);
    }
    // The channel becomes this peer's link only once open: a refused dial ends too,
    // and that end must not start a second reconnect chain (one dial per interval).
    const channel = await dialer.dial(seed, { identity: this.identity });
    if (!this.running) {
      channel.close(); // closed while dialing
      return;
    }
    this.channel = channel;
    this.session = null;
    this.linkSince = Date.now();
    channel.onFrame((frame) => this.onFrame(frame, null));
    channel.onClose(() => this.onChannelClosed(channel));
  }

  /**
   * Sends a frame: addressed, on the link its recipient was heard on (the dialed channel for
   * anyone else); unaddressed, on the dialed channel and, with scope `all`, on every accepted
   * link too, so a host's own rumors reach each connection. An unaddressed frame under a
   * confirmed session is addressed to the session's peer, so it can travel tagged (the Java
   * node addresses its frames too).
   */
  protected send(kind: string, body: Uint8Array, to: string | null = null, scope: "all" | "dial" = "all"): void {
    if (kind === "RUMOR") {
      this.rememberRumor(body); // an echo of our own item is never forwarded again
    }
    if (to !== null) {
      const link = this.linkFor(to);
      if (link !== null || this.channel !== null) {
        this.sendOn(link, kind, body, to);
      } else {
        for (const other of this.inbound.values()) {
          this.sendOn(other, kind, body, to); // an unknown recipient with no dialed channel: every link
        }
      }
      return;
    }
    if (this.channel !== null) {
      this.sendOn(null, kind, body, this.session?.confirmed ? this.session.remote : null);
    }
    if (scope === "all" || this.channel === null) {
      for (const link of this.inbound.values()) {
        this.sendOn(link, kind, body, link.session?.confirmed ? link.session.remote : null);
      }
    }
  }

  /** One frame on one link (null: the dialed channel), under that link's session when it has one. */
  private sendOn(link: Link | null, kind: string, body: Uint8Array, to: string | null): void {
    this.sendEnvelopeOn(link, wire.envelope(this.group, kind, this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now()), body, to));
  }

  private sendEnvelope(env: Dict): void {
    this.sendEnvelopeOn(null, env);
  }

  private sendEnvelopeOn(link: Link | null, env: Dict): void {
    const session = link === null ? this.session : link.session;
    const channel = link === null ? this.channel : link.channel;
    const key = session?.keyFor(env["to"] as string | null, String(env["kind"])) ?? null;
    if (key !== null) {
      this.sessionFramesSent += 1;
    }
    const frame = session !== null
      ? session.encode(env, (e) => wire.encodeFrame(e, this.identity))
      : wire.encodeFrame(env, this.identity);
    channel?.send(frame);
  }

  /**
   * Opens this peer's half of a session (PeerNode.maybeSessionHello): once per connection, in
   * session mode, toward a member whose advertisement carries the hint, on a channel the
   * transport could not attest. The hello travels fully signed.
   */
  private maybeSessionHello(peer: string, link: Link | null): void {
    const channel = link === null ? this.channel : link.channel;
    if (this.channelAuth !== "session" || channel === null || !this.sessionPeers.has(peer)
        || peer === this.identity.peerId || channel.attestedPeer() !== null) {
      return;
    }
    const session = this.sessionOf(link);
    if (session.mayOpen(this.now())) {
      this.sendSessionHello(session, peer, null, link);
    }
  }

  /** The session slot of a link (the dialed channel's for null), created on first use. */
  private sessionOf(link: Link | null): Session {
    if (link === null) {
      this.session ??= new Session(this.identity.peerId);
      return this.session;
    }
    link.session ??= new Session(this.identity.peerId);
    return link.session;
  }

  /** Sends this peer's half (opening when `echo` is null, answering otherwise), fully signed. */
  private sendSessionHello(session: Session, peer: string, echo: Uint8Array | null, link: Link | null): void {
    session.sent(this.now(), echo !== null);
    const env = wire.envelope(this.group, "SESSION_HELLO", this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now()), session.hello(peer, echo), peer);
    (link === null ? this.channel : link.channel)?.send(wire.encodeFrame(env, this.identity));
  }

  /**
   * Handles a SESSION_HELLO (PeerNode.onSessionHello): the decoder admits it only fully signed;
   * it counts only when it names this peer; a hello older than the age window is ignored and
   * counted; an opening hello is answered with this peer's half echoing the opener's nonce.
   */
  private onSessionHello(env: Dict, link: Link | null): void {
    const channel = link === null ? this.channel : link.channel;
    if (this.channelAuth !== "session" || channel === null || channel.attestedPeer() !== null) {
      return;
    }
    const hello = parseSessionHello((env["body"] as Uint8Array) ?? new Uint8Array());
    if (hello === null || hello.remote !== this.identity.peerId) {
      return;
    }
    let physical: number;
    try {
      physical = wire.hlcPhysical(env["stamp"]);
    } catch {
      return;
    }
    if (this.now() - physical > SESSION_HELLO_MAX_AGE_MILLIS) {
      this.framesStale += 1; // a captured hello replayed on a fresh link, never a strike
      return;
    }
    const session = this.sessionOf(link);
    const verdict = session.accept(String(env["from"]), hello);
    if (verdict === "answer") {
      this.sendSessionHello(session, String(env["from"]), hello.nonce, link);
    }
  }

  /** One whole frame from a link (the channel did the framing, ASF-014/016); null is the dialed channel. */
  private onFrame(frame: Uint8Array, link: Link | null = null): void {
    const channel = link === null ? this.channel : link.channel;
    const session = link === null ? this.session : link.session;
    const decoded = wire.decodeFrameDetailed(frame, {
      attestedPeer: channel?.attestedPeer() ?? null,
      session: session?.established() ?? null,
    });
    const env = decoded?.env ?? null;
    if (env === null) {
      this.malformedFrames += 1;
    } else if (decoded!.auth === "SESSION" && session !== null) {
      session.confirmed = true; // the other end holds the key: key confirmation (SPEC §5.6)
    } else if (decoded!.auth === "ATTESTED") {
      this.attestedFrames += 1;
    }
    if (this.accepts(env)) {
      try {
        this.handle(env, link, false, decoded!.body);
      } catch {
        // One undecodable frame never stops the peer.
      }
    }
  }

  /**
   * The reader filter: a verified envelope for our group that is either
   * unaddressed (the bootstrap exception) or addressed to us. An addressed
   * frame is honored only by its intended recipient (ASF-010); a frame for a
   * group we never joined is dropped (SPEC section 9).
   */
  accepts(env: Dict | null): env is Dict {
    return env !== null && env["group"] === this.group
      && (env["to"] == null || env["to"] === this.identity.peerId);
  }

  /**
   * A verified frame for this peer; `decoded` is its body read strictly as its kind's record, and a
   * body that does not read makes the frame undecodable (HLC round six, 2026-11-08, F3).
   */
  private handle(env: Dict, link: Link | null = null, relayedFrame = false,
                 decoded: Dict | null = wire.decodeBody(env)): void {
    if (decoded === null) {
      this.malformedFrames += 1;
      return;
    }
    if (!this.frames.admit(env, this.now())) {
      return; // stale, far ahead, or a replay: dropped and counted, nothing more
    }
    let reintroduce = false;
    wire.hlcObserve(this.identity.peerId, env["stamp"], this.now());
    const kind = env["kind"];
    const sender = env["from"];
    if (typeof sender === "string" && sender !== this.identity.peerId) {
      if (!this.members.has(sender)) {
        this.members.set(sender, {}); // a verified frame is a member heard from
      }
      // A relayed inner frame arrives on a link whose other end is someone else (the session's or
      // the attestation's peer): its signer is heard, not reachable, so an answer to it goes back
      // through a relay rather than onto a link that would drop a frame addressed elsewhere.
      const channel = link === null ? this.channel : link.channel;
      const session = link === null ? this.session : link.session;
      const linkPeer = channel?.attestedPeer() ?? (session?.established() !== null && session?.established() !== undefined ? session.remote : null);
      const relayed = relayedFrame || (linkPeer !== null && linkPeer !== undefined && linkPeer !== sender);
      if (!relayed) {
        this.reachable.add(sender);
        (link === null ? this.dialPeers : link.peers).add(sender);
        if (link === null && this.channel !== null && env["to"] === this.identity.peerId
            && this.seedPeer !== sender) {
          // On the dialed channel an addressed frame is the seed's own; it is the relay this peer
          // declares, so members behind other seeds reach it through the seed (SPEC §5.4).
          this.seedPeer = sender;
          this.resourceHints["relay.via"] = sender;
          reintroduce = true; // after this frame's own answer, so a probe's ACK stays first
        }
      }
      if (kind !== "RUMOR" && kind !== "SESSION_HELLO" && kind !== "CHANNEL_HELLO" && !relayed) {
        this.maybeSessionHello(sender, link); // a frame past the introduction proves the member admitted us
      }
    }
    if (kind === "SESSION_HELLO") {
      this.onSessionHello(env, link);
    } else if (kind === "RELAY_FRAME") {
      this.onRelayFrame(decoded, link);
    } else if (kind === "DIGEST") {
      this.onDigest(String(sender), decoded);
    } else if (kind === "PING_REQ") {
      this.onPingReq(String(sender), decoded);
    } else if (kind === "ACK") {
      this.onAck(String(sender), decoded);
    } else if (kind === "PIPE_DATA") {
      if (decoded["capability"] === wire.RELAY_SIGNAL_CAPABILITY) {
        const signal = records.readRecord(decoded["payload"], records.RELAY_SIGNAL);
        if (signal !== null) {
          this.relaySignals.push(signal);
          this.relaySignals.splice(0, Math.max(0, this.relaySignals.length - 64));
        }
        return;
      }
      const handler = this.pipeHandlers.get(String(decoded["capability"]));
      if (handler !== undefined) {
        handler(String(sender), decoded["payload"] as Uint8Array);
      }
    } else if (kind === "PING") {
      // Java's probe nonces are random 64-bit longs: echo the decoded integer
      // as is (a bigint beyond 2^53), since a Number would lose it and the
      // encoder would refuse it, leaving the probe unanswered and this peer evicted.
      this.send("ACK", wire.ackBody(decoded["nonce"] as number | bigint));
    } else if (kind === "GROUP_AD") {
      this.offerGroupAd(env); // only a join in progress cares (§10.1)
    } else if (kind === "RUMOR") {
      const rumor = decoded;
      let forward = true;
      if (revocation.STREAMS.includes(String(rumor["streamId"]))) {
        this.revocations.accept(String(rumor["streamId"]), rumor["payload"], this.now());
      } else if (rumor["streamId"] === "peers") {
        this.acceptPeerAd(rumor["payload"] as Uint8Array);
      } else if (rumor["streamId"] === "ads") {
        this.acceptAd(records.readRecord(rumor["payload"], records.STORED_AD));
      } else if (this.streamHandlers.has(String(rumor["streamId"])) && rumor["payload"] instanceof Uint8Array) {
        forward = this.streamHandlers.get(String(rumor["streamId"]))!(String(sender), rumor["payload"]);
      } else if (String(rumor["streamId"] ?? "").startsWith("space:")
          && this.joinedSpaces.has(String(rumor["streamId"]).substring("space:".length))) {
        // a rumor of a space not joined is relayed undecoded (HLC round five, 2026-11-08); a PDT
        // facade joins its ref spaces itself (HLC round six, 2026-11-08, R11)
        const delta = this.decodeDelta(rumor["payload"], records.SPACE_DELTA);
        if (delta === null) {
          forward = false; // counted, and carried no further from here
        } else {
          if (isDict(delta["state"])) {
            nameRecordless(delta["state"] as Dict, rumor["itemId"]);
          }
          this.foldDelta(delta);
        }
      }
      if (forward) {
        this.forwardRumor(rumor, link);
      }
    } else if (kind === "BLOCK_WANT") {
      const data = this.blocks.get(String(decoded["cid"]));
      if (data !== undefined) {
        this.sendAddressed("BLOCK", wire.blockBody(String(decoded["cid"]), data), String(sender));
      }
    } else if (kind === "BLOCK") {
      const bytes = decoded["bytes"] as Uint8Array;
      if (this.blockAsked.has(String(decoded["cid"])) && wire.contentId(bytes) === decoded["cid"]) {
        this.blocks.set(String(decoded["cid"]), bytes);
        this.wakeFoldWaiters();
      }
    } else if (kind === "PULL_RESP") {
      const deltas = decoded["deltas"] as { [stream: string]: Uint8Array };
      for (const [stream, deltaBytes] of Object.entries(deltas)) {
        if (revocation.STREAMS.includes(stream) && deltaBytes.length > 0) {
          for (const signed of (records.readList(deltaBytes, records.SIGNED_REVOCATION) ?? [])) {
            this.revocations.acceptSigned(stream, signed, this.now());
          }
          continue;
        }
        if (stream === "view" && deltaBytes.length > 0) {
          for (const payload of (records.readList(deltaBytes, "bytes") ?? []) as Uint8Array[]) {
            this.acceptPeerAd(payload);
          }
          continue;
        }
        if (stream === "ads" && deltaBytes.length > 0) {
          for (const stored of ((records.readRecord(deltaBytes, records.AD_CACHE_DELTA)?.["ads"] as Dict[]) ?? [])) {
            this.acceptAd(stored);
          }
          continue;
        }
        if (!stream.startsWith("space:") || !this.joinedSpaces.has(stream.substring("space:".length))
            || deltaBytes.length === 0) {
          continue; // HLC round five, 2026-11-08: an answer for a space not joined folds nothing
        }
        const sync = this.decodeDelta(deltaBytes, records.SYNC_DELTA);
        if (sync === null) {
          continue; // counted: as in Java, one undecodable state or claim drops the whole sync delta
        }
        // Claims before states: a completion authenticates against the holder's
        // claim, which must be folded first.
        const claims = (sync["claims"] as Dict) ?? {};
        for (const [entryId, signed] of Object.entries(claims)) {
          this.foldClaim(entryId, signed as Dict);
        }
        for (const dto of (sync["states"] as CborValue[]) ?? []) {
          this.fold(dto as Dict);
        }
      }
    } else {
      // A kind this client does not speak (the hint-gated kinds of SPEC v0.1.17 are never
      // sent to it, but a misconfigured peer could): ignored, counted, never fatal.
      this.ignoredKinds.set(String(kind), (this.ignoredKinds.get(String(kind)) ?? 0) + 1);
    }
    if (reintroduce) {
      this.introduce();
    }
  }

  // ------------------------------------------------- the serving half (JS-R-04)

  /** The key a rumor is remembered under: its stream and the hash of its payload, as GossipBus keys it. */
  private rumorKey(stream: string, payload: Uint8Array): string {
    const hash = cryptoPort().sha256(payload);
    return `${stream}\u0000${[...hash.subarray(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  }

  /** Remembers a rumor this peer sends, so its echo is not forwarded; the memory is a bounded ring. */
  private rememberRumor(body: Uint8Array): boolean {
    let rumor: Dict;
    try {
      rumor = loads(body) as Dict;
    } catch {
      return false;
    }
    const payload = rumor["payload"];
    if (!(payload instanceof Uint8Array)) {
      return false;
    }
    return this.remember(this.rumorKey(String(rumor["streamId"] ?? ""), payload));
  }

  /** Adds a key to the rumor memory; false when it was there already. */
  private remember(key: string): boolean {
    if (this.rumorsSeen.has(key)) {
      return false;
    }
    this.rumorsSeen.add(key);
    if (this.rumorsSeen.size > this.rumorMemory) {
      this.rumorsSeen.delete(this.rumorsSeen.values().next().value as string); // the oldest
    }
    return true;
  }

  /**
   * Forwards a rumor that arrived on one link to every other link, one hop fewer, the first
   * time it is seen (GossipBus.onRumor with the hop budget clamped to this peer's own, ASF-012).
   * A dial-only peer has one link and forwards nothing.
   */
  private forwardRumor(rumor: Dict, from: Link | null): void {
    const payload = rumor["payload"];
    if (!(payload instanceof Uint8Array)) {
      return;
    }
    const first = this.remember(this.rumorKey(String(rumor["streamId"] ?? ""), payload));
    const hops = Math.min(this.rumorHops, Number(rumor["hopsRemaining"] ?? 0));
    if (!first || hops <= 1 || (this.inbound.size === 0) || (this.inbound.size === 1 && from !== null && this.channel === null)) {
      return;
    }
    const body = wire.rumorBody(String(rumor["streamId"]), String(rumor["itemId"] ?? ""), hops - 1, payload);
    if (from !== null && this.channel !== null) {
      this.sendOn(null, "RUMOR", body, this.session?.confirmed ? this.session.remote : null);
    }
    for (const link of this.inbound.values()) {
      if (link !== from) {
        this.sendOn(link, "RUMOR", body, link.session?.confirmed ? link.session.remote : null);
      }
    }
    this.rumorsForwarded += 1;
  }

  /** The streams this peer serves: the spaces it pulled or wrote, the ads, and the revocations. */
  private servesStream(stream: string): boolean {
    return stream === "ads" || stream === "view" || revocation.STREAMS.includes(stream)
      || (stream.startsWith("space:") && this.pulledSpaces.has(stream.substring("space:".length)));
  }

  /** The entry states of one space (by its SpaceId), as held. */
  private statesOf(space: string): Map<string, Dict> {
    const spaceId = spaceIdLocal(`${this.group}/${space}`);
    const out = new Map<string, Dict>();
    for (const [entryId, dto] of this.states) {
      if ((dto["record"] as Dict | undefined)?.["spaceId"] === spaceId) {
        out.set(entryId, dto);
      }
    }
    return out;
  }

  /** `ReplicatedSpace.digest` for one space: `e:`/`c:` lines in key order. */
  spaceDigest(space: string): Uint8Array {
    const summary = new Map<string, string>();
    const states = this.statesOf(space);
    for (const [entryId, dto] of states) {
      summary.set(`e:${entryId}`, serving.stateHash(dto));
    }
    for (const [entryId, signed] of this.claims) {
      if (states.has(entryId)) {
        summary.set(`c:${entryId}`, serving.claimHash((signed["claim"] as Dict) ?? {}));
      }
    }
    return utf8(serving.digestLines(summary) + this.acknowledgedLines(space));
  }

  /** `ReplicatedSpace.deltaFor`: the states and claims the remote digest does not name, as a SyncDelta. */
  spaceDeltaFor(space: string, remoteDigest: Uint8Array): Uint8Array {
    const remote = serving.parseDigestLines(remoteDigest);
    const states: Dict[] = [];
    const claims: Dict = {};
    const held = this.statesOf(space);
    for (const [entryId, dto] of held) {
      const key = `e:${entryId}=${serving.stateHash(dto)}`;
      if (!remote.has(key) && !remote.has(`a:${key}`)) {
        states.push(dto);
      }
    }
    for (const [entryId, signed] of this.claims) {
      if (!held.has(entryId)) {
        continue;
      }
      const key = `c:${entryId}=${serving.claimHash((signed["claim"] as Dict) ?? {})}`;
      if (!remote.has(key) && !remote.has(`a:${key}`)) {
        claims[entryId] = signed;
      }
    }
    if (states.length === 0 && Object.keys(claims).length === 0) {
      return new Uint8Array();
    }
    // HLC round six, 2026-11-08 (P2): `claims` is a protocol map field, written in the RFC 8949 order.
    return dumps({ states, claims: canonicalMap(claims) });
  }

  /** `AdCache.digest`: the live advertisements by id and issue instant. */
  adsDigest(): Uint8Array {
    const keys = new Map<string, string>();
    const now = this.now();
    for (const [id, entry] of this.ads) {
      if (entry.expires > now) {
        keys.set(id, String(parseInstantMillis(entry.ad["issued"])));
      }
    }
    return serving.adDigest(keys);
  }

  /** `AdCache.deltaFor`: the stored advertisements the remote digest does not name. */
  adsDeltaFor(remoteDigest: Uint8Array): Uint8Array {
    const remote = serving.parseAdDigestKeys(remoteDigest);
    const now = this.now();
    const missing: Dict[] = [];
    for (const [id, entry] of this.ads) {
      if (entry.expires > now && !remote.has(`${id}=${parseInstantMillis(entry.ad["issued"])}`)) {
        missing.push(entry.stored);
      }
    }
    return missing.length === 0 ? new Uint8Array() : dumps({ ads: missing });
  }

  /**
   * `RevocationRegistry.deltaFor` and `CredentialRevocationRegistry.deltaFor`: the signed
   * revocations of a stream the remote digest does not name, keyed `r:<revoked peer>` and
   * `c:<kind>:<canonical target>` with the SHA-256 of the signed bytes, as Java lines them.
   */
  revocationDeltaFor(stream: string, remoteDigest: Uint8Array): Uint8Array {
    const remote = serving.parseDigestLines(remoteDigest);
    const held = (this.revocations.exportSigned()[stream] ?? []) as Dict[];
    const missing: Dict[] = [];
    for (const signed of held) {
      const adBytes = signed["adBytes"];
      if (!(adBytes instanceof Uint8Array)) {
        continue;
      }
      let key: string;
      try {
        const ad = loads(adBytes) as Dict;
        key = stream === revocation.PEER_STREAM ? `r:${String(ad["revoked"])}`
          : `c:${String((ad["target"] as Dict)["kind"])}:${revocation.canonicalTarget(ad["target"] as Dict)}`;
      } catch {
        continue;
      }
      if (!remote.has(serving.revocationLine(key, adBytes))) {
        missing.push(signed);
      }
    }
    return missing.length === 0 ? new Uint8Array() : dumps(missing);
  }

  /** The full digests of every stream this peer serves, the opening of an anti-entropy round. */
  fullDigests(): Dict {
    const digests: Dict = { ads: this.adsDigest(), view: this.viewDigest() };
    for (const space of this.pulledSpaces) {
      digests[`space:${space}`] = this.spaceDigest(space);
    }
    for (const stream of revocation.STREAMS) {
      digests[stream] = new Uint8Array(); // asked in full: this peer serves them but keeps no digest of its own
    }
    return digests;
  }

  /**
   * One anti-entropy round (GossipBus.antiEntropy): this peer's full digests to one member it
   * has a connection to, chosen at random, which answers with what this peer lacks. A host's
   * tick calls it; a dial-only peer pulls on demand instead.
   */
  antiEntropyRound(): string | null {
    const partners = this.linkedMembers();
    if (partners.length === 0) {
      return null;
    }
    const partner = partners[Math.floor(Math.random() * partners.length)];
    this.send("DIGEST", wire.digestBody(this.fullDigests()), partner);
    return partner;
  }

  /**
   * Answers a DIGEST (GossipBus.onDigest): for each stream the asker names and this peer serves,
   * the delta its digest shows it lacks, in one PULL_RESP; nothing when nothing is missing. A
   * hashed opening (`hashes`) or a `want` list belongs to the hashed round this peer never
   * advertises, and is ignored.
   */
  private onDigest(from: string, digest: Dict): void {
    const digests = digest["digests"];
    if (digests === null || typeof digests !== "object" || Array.isArray(digests)) {
      return;
    }
    const deltas: Dict = {};
    for (const [stream, remote] of Object.entries(digests as Dict)) {
      if (!(remote instanceof Uint8Array) || !this.servesStream(stream)) {
        continue;
      }
      const delta = stream === "ads" ? this.adsDeltaFor(remote)
        : stream === "view" ? this.viewDeltaFor(remote)
        : revocation.STREAMS.includes(stream) ? this.revocationDeltaFor(stream, remote)
          : this.spaceDeltaFor(stream.substring("space:".length), remote);
      if (delta.length > 0) {
        deltas[stream] = delta;
      }
    }
    if (Object.keys(deltas).length > 0) {
      this.pullsAnswered += 1;
      this.send("PULL_RESP", dumps({ deltas: canonicalMap(deltas) }), from); // P2, HLC round six, 2026-11-08
    }
  }

  /** Relayed frames unwrapped for this peer, and forwarded on toward a linked target. */
  relayedIn = 0;
  relayedForwarded = 0;
  /** Path frames refused as malformed and frames no hop could deliver (SPEC v0.1.23 §5.4). */
  relayedDroppedBadPath = 0;
  relayedDroppedUnreachable = 0;

  /**
   * A `RELAY_FRAME` (SPEC §5.4; PeerNode.onRelayFrame): addressed to this peer, the inner frame is
   * decoded fully signed (never a nested relay) and handled as its origin's, marked relayed so the
   * origin is heard but not reachable; addressed to a member on one of this peer's links, it is
   * forwarded verbatim there, which is what a service host that advertises the RELAY role does
   * for the browsers behind it. Anyone else's is dropped.
   */
  private onRelayFrame(body: Dict, link: Link | null): void {
    const target = body["target"] as string;
    const frame = body["frame"] as Uint8Array;
    if (target === this.identity.peerId) {
      const decoded = wire.decodeFrameDetailed(frame, {}); // fully signed, whatever the link's session
      const inner = decoded?.env ?? null;
      if (inner === null || inner["kind"] === "RELAY_FRAME" || !this.accepts(inner)) {
        return;
      }
      this.relayedIn += 1;
      if (typeof inner["from"] === "string") {
        this.noteRelayed(inner["from"]); // JS-W-11: the other direction of the pair
      }
      try {
        this.handle(inner, link, true, decoded!.body);
      } catch {
        // one bad inner frame never stops the peer
      }
      return;
    }
    const path = Array.isArray(body["path"]) ? (body["path"] as unknown[]).map(String) : null;
    const hop = typeof body["hop"] === "number" ? body["hop"] : -1;
    if (path !== null && (hop < 0 || hop >= path.length || path[hop] !== this.identity.peerId
        || path.length > this.maxPathHops || path.includes(target))) {
      this.relayedDroppedBadPath += 1;
      return; // a path frame names this relay at its hop (LB-R-03); anything else is malformed
    }
    const route = this.linkFor(target);
    if (route !== null || this.dialPeers.has(target)) {
      this.relayedForwarded += 1;
      this.sendOn(route, "RELAY_FRAME", path === null ? dumps({ target, frame })
        : wire.relayFrameBody(target, frame, path, hop), target);
      return;
    }
    // Not deliverable from here: the next relay on the path carries it, once (LB-R-08).
    if (path !== null && hop + 1 < path.length) {
      const next = path[hop + 1];
      const link = this.linkFor(next);
      if (link !== null || this.dialPeers.has(next)) {
        this.relayedForwarded += 1;
        this.sendOn(link, "RELAY_FRAME", wire.relayFrameBody(target, frame, path, hop + 1), next);
        return;
      }
      const origin = wire.decodeFrame(frame)?.["from"];
      if (typeof origin === "string") {
        this.sendAddressed("PIPE_DATA", wire.relaySignalBody(target, next), origin);
      }
    }
    this.relayedDroppedUnreachable += 1;
  }

  /**
   * Relays a probe (PeerNode PING_REQ, SWIM indirect ping): pings the target under a nonce of
   * this peer's own and, when the target itself answers, vouches for it to the asker with an
   * ACK carrying the asker's nonce and `onBehalf` (ASF-011).
   */
  private onPingReq(from: string, request: Dict): void {
    const target = request["target"];
    if (typeof target !== "string" || target === this.identity.peerId) {
      return;
    }
    const nonce = BigInt.asIntN(64, (BigInt(Math.floor(Math.random() * 2 ** 32)) << 32n)
      | BigInt(Math.floor(Math.random() * 2 ** 32)));
    this.relays.set(String(nonce), { origin: from, originNonce: (request["nonce"] as number | bigint | undefined) ?? 0, target });
    this.pingsRelayed += 1;
    this.send("PING", wire.pingBody(nonce), target);
  }

  private onAck(from: string, ack: Dict): void {
    const relay = this.relays.get(String(ack["nonce"] ?? ""));
    if (relay !== undefined && from === relay.target) {
      this.relays.delete(String(ack["nonce"]));
      this.send("ACK", dumps({ nonce: relay.originNonce, onBehalf: relay.target }), relay.origin);
    }
  }

  /**
   * Forgets members whose advertisement lease has lapsed and who are heard on no link (a host
   * has no SWIM prober; a member that left or died ages out with its advertisement).
   */
  expireMembers(): string[] {
    const now = this.now();
    const gone: string[] = [];
    const linked = new Set(this.linkedMembers());
    for (const [peer, ad] of this.members) {
      if (linked.has(peer) || ad["issued"] === undefined) {
        continue;
      }
      try {
        if (parseInstantMillis(ad["issued"]) + parseDurationMillis(ad["ttl"]) > now) {
          continue;
        }
      } catch {
        continue;
      }
      gone.push(peer);
    }
    for (const peer of gone) {
      this.members.delete(peer);
      this.heldPeerAds.delete(peer);
      this.reachable.delete(peer);
      this.sessionPeers.delete(peer);
    }
    if (gone.length > 0) {
      this.appCardLevelChanged();
    }
    return gone;
  }

  private foldDelta(delta: Dict): void {
    // Claim before state: a completion authenticates against the holder's claim.
    if (delta["claimEntry"] && typeof delta["claim"] === "object"
        && delta["claim"] !== null) {
      this.foldClaim(String(delta["claimEntry"]), delta["claim"] as Dict);
    }
    if (delta["state"] !== null && typeof delta["state"] === "object") {
      this.fold(delta["state"] as Dict);
    }
  }

  private fold(dto: Dict): void {
    // HLC round five, 2026-11-08 (E7): a state without its lease stamp or its lease value decodes,
    // but a lease register holds nothing without both, so the replica drops it before it judges
    // anything, as Java's mergeState does: it merges nothing, waits for nothing, no digest
    // acknowledges it, and it counts in no counter.
    if (dto["leaseStamp"] === null || dto["leaseStamp"] === undefined
        || dto["leaseValue"] === null || dto["leaseValue"] === undefined) {
      return;
    }
    if (dto["record"] === null || dto["record"] === undefined) {
      this.foldRecordless(dto);
      return;
    }
    const record = dto["record"] as Dict;
    const entryId = record["entryId"];
    // ASF-025, as Java's ReplicatedSpace.dotsBoundToIssuer and before the signatures (HLC round six,
    // 2026-11-08, reference rule): only an entry's writer mints its dots, so a dot naming another
    // replica is fabricated provenance and the state is dropped, counted nowhere.
    if (typeof entryId !== "string" || !dotsBoundToIssuer(dto, record) || !this.verifyState(dto, record)) {
      return; // unauthenticated record or forged mutable state: drop it
    }
    // HLC logical counter, 2026-11-08 (Rust team report): every implementation refuses a state
    // whose issue or lease stamp fails the strict parse, so the replicas converge and no such
    // stamp reaches the lease's last-writer-wins join. HLC round four, 2026-11-08: an agent-signed
    // state's signedAt is a stamp like any other (D1), and a stamp that does not decode was counted
    // with the carrier that brought it (D3), so it is dropped here uncounted. The check follows the
    // signatures, and a re-offered state counts once.
    // A peer-signed state carries no signedAt, so only the stamps the state names are judged.
    const stamps = [record["issued"], dto["leaseStamp"], dto["signedAt"]]
      .filter((stamp) => stamp !== null && stamp !== undefined);
    if (stamps.some((stamp) => wire.decodeHlc(stamp) === null)) {
      return;
    }
    // HLC round five, 2026-11-08 (E6): revocation comes before the stamp checks, so a revoked actor's
    // state counts in no stamp counter, whatever its stamps.
    const pending = this.pendingStates.get(entryId);
    if (this.refusedForRevocation(dto, record)) {
      // Authentic, but its actor is revoked here (SPEC §5.6): what is already
      // held stays as held, and this state is not merged.
      this.pendingStates.delete(entryId);
      return;
    }
    if (stamps.some((stamp) => wire.parseHlc(stamp) === null)) {
      this.refuseState(dto, record, false);
      return;
    }
    // HLC round four, 2026-11-08 (D4), as Java's ReplicatedSpace: a record or lease stamp past the
    // far-future margin waits for this replica's wall, unmerged and unacknowledged, and counts only
    // as deferred, unless it lies so far ahead that no honest clock reaches it. HLC round six,
    // 2026-11-08 (F4): an agent-signed state's signedAt is judged the same way.
    const ahead = this.farFuture(record["issued"], dto["leaseStamp"], dto["signedAt"]);
    if (ahead === "hostile") {
      this.refuseState(dto, record, true);
      return;
    }
    if (ahead === "deferred") {
      this.countOnce(this.deferredStamps, stateOfferKey(dto, record), () => this.stampsFarFutureDeferred++);
      return;
    }
    // SPEC §7.3, as Java's ReplicatedSpace (HLC round five, 2026-11-08): this replica refuses at the
    // door a state past the collection horizon that a lagging replica re-offers, so a collected
    // tombstone never returns.
    this.observeLease(dto);
    if (collectable(dto, this.now(), this.longestLeaseOf(dto))) {
      return;
    }
    this.pendingStates.delete(entryId);
    // ASF-017: states JOIN, mirroring the Java CRDT — dot sets union, the
    // lease is last-writer-wins by HLC stamp, and completed is monotone. A
    // replayed early state (validly signed by its author) can therefore never
    // shrink the sets, roll back the lease, or undo a completion.
    const previous = this.states.get(entryId);
    this.states.set(entryId,
        previous === undefined ? dto : joinStates(previous, dto));
    if (this.collector === null) {
      this.collector = this.every(COLLECT_PERIOD_MILLIS, () => this.collectTombstones());
    }
    this.onState?.(this.states.get(entryId)!, previous);
    this.wakeFoldWaiters();
    if (pending !== undefined) {
      this.foldRecordless(pending);
    }
  }

  /**
   * A renew, cancel, or complete without its record (srad/agentspaces-pdt.md §3.9, PD-L-01, PD-L-02,
   * PD-L-04): the state is merged over the record this replica holds, through every check a full
   * state passes, or kept pending with no event until anti-entropy ships the whole DTO. The entry
   * id comes from the DTO's `entryId` or from the rumor item that carried it.
   */
  private foldRecordless(dto: Dict): void {
    const entryId = dto["entryId"];
    if (typeof entryId !== "string" || entryId.length === 0) {
      return;
    }
    // HLC canonical stamps, 2026-11-08: a lease stamp is judged once the record arrives, since
    // only the record's signer verifies the renewal; fold refuses it then and counts it once.
    const previous = this.states.get(entryId);
    if (previous === undefined) {
      if (this.pendingStates.size >= MAX_PENDING_RECORDLESS && !this.pendingStates.has(entryId)) {
        const oldest = this.pendingStates.keys().next().value;
        if (oldest !== undefined) {
          this.pendingStates.delete(oldest);
        }
      }
      this.pendingStates.set(entryId, dto);
      return;
    }
    const full: Dict = { ...dto, record: previous["record"] };
    for (const carried of ["issuerPublicKey", "agentCertificate"]) {
      if ((full[carried] === null || full[carried] === undefined) && previous[carried] !== undefined && previous[carried] !== null) {
        full[carried] = previous[carried];
      }
    }
    delete full["entryId"];
    this.fold(full);
  }

  /**
   * Authenticates a received state DTO: the record signature (the writer's
   * identity) and the state signature (the transition). The party authorized
   * for the transition is the take-claim holder for a completion and the
   * issuer otherwise. Mirrors ReplicatedSpace.verifyState (SPEC §11a.4): an
   * agent-signed state must name that party, carry a certificate the party's
   * peer key verifies at `signedAt`, and verify under its agent key; and an
   * agent-attested party's transitions must be agent-signed (A6, v0.1.13).
   */
  private verifyState(dto: Dict, record: Dict): boolean {
    const issuerKey = dto["issuerPublicKey"];
    if (!(issuerKey instanceof Uint8Array) || issuerKey.length !== 32) {
      return false;
    }
    // The record: peer-signed, or agent-signed under a peer certificate
    // (TECH-SPEC §7.2's two-key rule, QA4 A4-7), judged at its issue stamp.
    if (!wire.verifyRecord(record, issuerKey, dto["agentCertificate"])) {
      return false;
    }
    const stateSig = dto["stateSig"];
    if (!(stateSig instanceof Uint8Array)) {
      return false;
    }
    let signerKey: unknown;
    let party: unknown;
    let partyAttested: boolean;
    if (dto["completed"]) {
      const signed = this.claims.get(String(record["entryId"]));
      if (!signed) {
        return false; // no authenticated holder to attribute the completion to
      }
      // The claim authenticating this completion must be bound to exactly this
      // entry and space by its own signed fields (ASF-002/041).
      const claim = signed["claim"] as Dict;
      if (claim["entryId"] !== record["entryId"]
          || claim["spaceId"] !== record["spaceId"]
          || !wire.verifyClaimProof(signed)) {
        return false;
      }
      signerKey = signed["holderKey"];
      party = claim["holder"];
      partyAttested = signed["holderCertificate"] != null;
    } else {
      signerKey = issuerKey;
      party = record["issuer"];
      partyAttested = dto["agentCertificate"] != null;
    }
    if (!(signerKey instanceof Uint8Array) || signerKey.length !== 32) {
      return false;
    }
    const signer = dto["signer"] ?? null;
    const view = dumps(stateViewOf(dto, record));
    if (signer !== null) {
      const certificate = dto["stateCertificate"];
      // HLC round four, 2026-11-08 (D1): judged at a signedAt that decodes, so one above the limit
      // verifies and fold then refuses and counts it. HLC round six, 2026-11-08 (F4): the certificate
      // no longer drops a signedAt past the drift ceiling in silence; fold judges it by D4's rule.
      const signedMillis = wire.decodedPhysical(dto["signedAt"]);
      if (signedMillis === null) {
        return false;
      }
      return signer === party && typeof certificate === "object" && certificate !== null
        && verifyAgentCertificateCovering(certificate, signerKey, String(party), signedMillis)
        && Identity.verify((certificate as Dict)["agentPublicKey"] as Uint8Array, view, stateSig);
    }
    if (partyAttested) {
      return false; // A6: an attested party's transitions must be agent-signed
    }
    return Identity.verify(signerKey, view, stateSig);
  }

  /**
   * SPEC §5.6's freeze rule at merge, for every incoming state: the actor of
   * the transition (the claim holder for a completion, the issuer otherwise)
   * must not be revoked; an agent is judged at the state's `signedAt` with
   * the keys it signed with. A peer-signed state (no `signedAt`) is judged at
   * its `leaseStamp`, the stamp of the last write or renewal (the record's
   * issue stamp for an unrenewed write), so a renewal after the effective
   * instant is refused while the original history still folds. A refused state's digest line is
   * acknowledged, as Java's ReplicatedSpace acknowledges it, so partners stop re-offering it (HLC
   * round five, 2026-11-08, E12). The times are those of stamps that decode, a counter above the
   * limit included, since this judgement comes before the stamp checks (E6).
   */
  private refusedForRevocation(dto: Dict, record: Dict): boolean {
    // An unreadable time is an unknown one: refused under any revocation.
    const signedAt = dto["signedAt"] != null ? wire.decodedPhysical(dto["signedAt"]) : null;
    let refused: boolean;
    if (dto["completed"]) {
      const signed = this.claims.get(String(record["entryId"]));
      const claim = (signed?.["claim"] ?? {}) as Dict;
      const certificate = (signed?.["holderCertificate"] ?? {}) as Dict;
      refused = claim["holder"] != null
        && this.revocations.refuses(claim["holder"], certificate["agentPublicKey"], signedAt);
    } else {
      const certificate = (dto["agentCertificate"] ?? {}) as Dict;
      const stateCertificate = (dto["stateCertificate"] ?? {}) as Dict;
      refused = this.revocations.refuses(record["issuer"], certificate["agentPublicKey"],
        signedAt ?? wire.decodedPhysical(dto["leaseStamp"]))
        || (dto["signer"] != null
          && this.revocations.refuses(record["issuer"], stateCertificate["agentPublicKey"], signedAt));
    }
    if (refused) {
      this.acknowledge(dto, record);
    }
    return refused;
  }

  /**
   * Whether a claim's stamp is one the replica refuses: a stamp item that does not decode (E1, D3)
   * or one wire.parseHlc refuses. The replica counts a refusal in stampsLogicalRefused, once per
   * distinct claim on the entry (HLC canonical stamps, 2026-11-08), only when the stamp decodes, the
   * claim's proof verifies, and its holder is not revoked: signatures, then revocation, then the
   * stamp (HLC round five, 2026-11-08, E6). A stamp that does not decode names no verified signer
   * and counts where its carrier was decoded: as a space delta, or as the ordered-log host's dropped
   * command (HLC round four, 2026-11-08, D3). The ordered-log host asks this of every committed
   * claim before it installs or announces one.
   */
  refusesClaimStamp(entryId: string, signed: Dict): boolean {
    const claim = (signed["claim"] ?? {}) as Dict;
    if (wire.decodeHlc(claim["stamp"]) === null) {
      return true;
    }
    if (wire.parseHlc(claim["stamp"]) !== null) {
      return false;
    }
    if (wire.verifyClaimProof(signed) && !this.holderRevoked(signed)) {
      this.countRefusal(claimOfferKey(entryId, claim), false);
    }
    return true;
  }

  /**
   * SPEC §5.6 v0.1.13 (review M-1): a revoked holder takes nothing, whatever the claim's stamp,
   * since a renewal keeps it.
   */
  private holderRevoked(signed: Dict): boolean {
    const claim = (signed["claim"] ?? {}) as Dict;
    const certificate = (signed["holderCertificate"] ?? {}) as Dict;
    return this.revocations.refuses(claim["holder"], certificate["agentPublicKey"], null);
  }

  /**
   * Refuses a verified state for its stamps: counts it once per distinct state, keyed on its entry
   * id, issue stamp and signed state view alone, so no unsigned field a relay changes makes a second
   * refusal, and acknowledges its digest line so partners stop re-offering it (HLC round four,
   * 2026-11-08, D5).
   */
  private refuseState(dto: Dict, record: Dict, farFuture: boolean): void {
    this.countRefusal(stateOfferKey(dto, record), farFuture);
    this.acknowledge(dto, record);
  }

  /** Names a verified, refused state's digest line as acknowledged. */
  private acknowledge(dto: Dict, record: Dict): void {
    this.acknowledgeLine(`e:${String(record["entryId"])}=${serving.stateHash(dto)}`, String(record["spaceId"]));
  }

  /**
   * Names a digest line of the space `spaceId` as refused and acknowledged, the newest past
   * MAX_REFUSED_ACK, as Java's access-ordered refusedAck keeps them.
   */
  private acknowledgeLine(line: string, spaceId: string): void {
    this.refusedAck.delete(line); // re-offered: kept as the newest
    this.refusedAck.set(line, spaceId);
    if (this.refusedAck.size > MAX_REFUSED_ACK) {
      this.refusedAck.delete(this.refusedAck.keys().next().value!);
    }
  }

  /** Counts a verified refusal once per distinct offer `key`, as far-future or as a logical refusal. */
  private countRefusal(key: string, farFuture: boolean): void {
    this.countOnce(this.refusedStamps, key, farFuture
      ? () => this.stampsFarFutureRefused++ : () => this.stampsLogicalRefused++);
  }

  /**
   * Runs `count` the first time `seen` meets `key`. A key met again becomes the most recent, and
   * `seen` forgets its least recently met key past the cap (HLC round five, 2026-11-08, E14).
   */
  private countOnce(seen: Set<string>, key: string, count: () => void): void {
    if (seen.delete(key)) {
      seen.add(key);
      return;
    }
    seen.add(key);
    if (seen.size > MAX_REFUSED_STAMPS) {
      seen.delete(seen.values().next().value!);
    }
    count();
  }

  /**
   * Where the latest of `stamps` lies against this replica's wall (HLC round four, 2026-11-08, D4):
   * `inside` up to wall + MAX_HLC_SKEW_MILLIS + FAR_FUTURE_MARGIN_MILLIS, `deferred` up to
   * FAR_FUTURE_HOSTILE_MILLIS past that, and `hostile` beyond. The stamps are acceptable ones.
   */
  private farFuture(...stamps: CborValue[]): "inside" | "deferred" | "hostile" {
    const ceiling = BigInt(Math.trunc(this.now()) + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_MARGIN_MILLIS);
    let lead = 0n;
    for (const stamp of stamps) {
      const parsed = wire.parseHlc(stamp);
      if (parsed !== null && parsed.physical - ceiling > lead) {
        lead = parsed.physical - ceiling;
      }
    }
    return lead === 0n ? "inside" : lead <= BigInt(wire.FAR_FUTURE_HOSTILE_MILLIS) ? "deferred" : "hostile";
  }

  /** The `a:` lines of one space's digest: its refused states, acknowledged in Java's order. */
  private acknowledgedLines(space: string): string {
    const spaceId = spaceIdLocal(`${this.group}/${space}`);
    const lines = [...this.refusedAck].filter(([, id]) => id === spaceId).map(([line]) => line);
    return lines.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).map((line) => `a:${line}\n`).join("");
  }

  /**
   * The space delta in `bytes` read strictly as `schema`, or null once it is counted in
   * deltasUndecodable (HLC round six, 2026-11-08, F1 and F3): bytes that are no document in the wire
   * encoding, a record with a field the schema does not name, absent, out of order or of the wrong
   * kind, or any form other than the one its value encodes to. Such a delta names no verified signer.
   */
  private decodeDelta(bytes: CborValue | undefined, schema: records.Schema): Dict | null {
    const delta = records.readRecord(bytes, schema);
    if (delta === null) {
      this.deltasUndecodable += 1;
    }
    return delta;
  }

  /**
   * Whether a gossiped claim breaks Java's time bounds on a claim (HLC round six, 2026-11-08, R6): its
   * stamp lies more than MAX_CLAIM_PREDATES_ISSUE_MILLIS before the held entry's issue stamp, or it
   * contests `current`, another holder's claim, with a stamp before now - MAX_HLC_SKEW_MILLIS -
   * CLAIM_SETTLE_WINDOW_MILLIS. The claim's stamp parses, as foldClaim refused it otherwise.
   */
  private claimOutOfTime(entryId: string, claim: Dict, current: Dict | undefined): boolean {
    const physical = wire.parseHlc(claim["stamp"])!.physical;
    const issued = wire.parseHlc((this.states.get(entryId)?.["record"] as Dict | undefined)?.["issued"]);
    if (issued !== null && physical < issued.physical - BigInt(wire.MAX_CLAIM_PREDATES_ISSUE_MILLIS)) {
      return true;
    }
    return current !== undefined && current["holder"] !== claim["holder"]
      && physical < BigInt(Math.trunc(this.now()) - wire.MAX_HLC_SKEW_MILLIS - wire.CLAIM_SETTLE_WINDOW_MILLIS);
  }

  private foldClaim(entryId: string, signed: Dict, committed = false): void {
    // The claim is a conformed TakeClaim before the lattice sees it, so a NaN or infinite bid and a
    // non-positive epoch never reach it (ASF-033; HLC round six, 2026-11-08, F1), and a claim
    // transplanted under a foreign map key is dropped (ASF-002).
    const claim = wire.canonicalClaim(signed["claim"]);
    if (claim === null || claim["entryId"] !== entryId) {
      return;
    }
    const epoch = wire.claimNumber(claim["epoch"]);
    const expires = wire.claimNumber(claim["expiresAtMillis"]);
    // The proof: peer-signed, or agent-signed under a peer certificate
    // (TECH-SPEC §7.6's two-key rule, QA4 A4-7 phase 3).
    if (!wire.verifyClaimProof(signed)) {
      return;
    }
    // ASF-047, as Java's mergeClaim: a revoked holder takes nothing, whatever the claim's stamp, and
    // the refusal is acknowledged in the digest so partners stop re-offering it (HLC round six,
    // 2026-11-08, R7).
    if (this.holderRevoked(signed)) {
      this.acknowledgeLine(`c:${entryId}=${serving.claimHash(claim)}`, String(claim["spaceId"]));
      return;
    }
    // HLC logical counter, 2026-11-08 (Rust team report): every implementation refuses a claim
    // whose stamp fails the strict parse, so the lattice decides alike everywhere and
    // wire.compareClaims never sees an unparsed stamp. The refusal counts only after the proof
    // and the revocation check (HLC round five, 2026-11-08, E6).
    if (this.refusesClaimStamp(entryId, signed)) {
      return;
    }
    // HLC round four, 2026-11-08 (D4), in Java's order: a gossiped claim stamped far beyond the
    // far-future margin is refused and counted before the bounds below, and one past the margin
    // that meets them waits for this replica's wall. A claim the ordered log committed skips this
    // wall-dependent rule, so every member installs it alike.
    const ahead = committed ? "inside" : this.farFuture(claim["stamp"]);
    if (ahead === "hostile") {
      this.countRefusal(claimOfferKey(entryId, claim), true);
      return;
    }
    // ASF-004, mirroring ReplicatedSpace: bound what a remote claim may assert
    // before the lattice (where higher epochs win by design) sees it.
    const current = this.claims.get(entryId)?.["claim"] as Dict | undefined;
    const observed = current ? wire.claimNumber(current["epoch"]) : 0;
    if (epoch > observed + wire.MAX_CLAIM_EPOCH_JUMP
        || expires > this.now() + wire.MAX_CLAIM_HOLD_MILLIS) {
      return;
    }
    // HLC round six, 2026-11-08 (R6), Java's two checks in mergeClaim's order, on gossip alone as Java's
    // log path skips them: a claim cannot predate the entry it answers by more than the drift ceiling,
    // and a claim contesting another holder's claim with a stamp older than the ceiling plus one settle
    // window is a queue-jump, since LEASE_RACE picks the lowest stamp. Each drop counts nothing.
    if (!committed && this.claimOutOfTime(entryId, claim, current)) {
      return;
    }
    if (ahead === "deferred") {
      this.countOnce(this.deferredStamps, claimOfferKey(entryId, claim), () => this.stampsFarFutureDeferred++);
      return;
    }
    this.observeClaimLease(signed);
    this.claims.set(entryId, wire.mergeClaims(this.claims.get(entryId), signed));
    if (this.collector === null) {
      this.collector = this.every(COLLECT_PERIOD_MILLIS, () => this.collectTombstones()); // R10: claims expire too
    }
    this.onClaim?.(entryId, this.claims.get(entryId)!);
    this.wakeFoldWaiters();
  }
}

/** An empty digest for each revocation stream (SPEC §5.6). */
function revocationDigests(): Dict {
  return Object.fromEntries(revocation.STREAMS.map((stream) => [stream, new Uint8Array()]));
}

/** The value of an entry's payload, or null when it is not here yet or unreadable ({@link readDocument}). */
function applicationValue(raw: Uint8Array | null): { value: Dict } | null {
  return raw === null ? null : readDocument(raw) as { value: Dict } | null;
}

/** Whether a decoded item is a map, the shape of a delta, a state, and a claim. */
function isDict(value: unknown): value is Dict {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && !(value instanceof Uint8Array) && !(value instanceof CborDouble);
}

/**
 * The state view a state signature covers (SPEC §11a.4): the one verifyState checks, and the signed
 * content a refusal is keyed on (HLC round four, 2026-11-08, D5).
 */
function stateViewOf(dto: Dict, record: Dict): Dict {
  const signer = dto["signer"] ?? null;
  const signedAt = dto["signedAt"] ?? null;
  return wire.stateSignView(String(record["spaceId"]), String(record["entryId"]), (dto["adds"] as Dict[]) ?? [],
    (dto["removes"] as Dict[]) ?? [], wire.leaseStampOf(dto), dto["leaseValue"] as Dict,
    Boolean(dto["completed"]), signer === null ? null : String(signer), signedAt === null ? null : String(signedAt));
}

/**
 * The key a state offer is judged under, its signed content alone (HLC round four, 2026-11-08, D5),
 * as Java's: the entry, the issue stamp, and the SHA-256 of the signed state view.
 */
function stateOfferKey(dto: Dict, record: Dict): string {
  return `state:${String(record["entryId"])}=${String(record["issued"])}/${toHex(cryptoPort().sha256(dumps(stateViewOf(dto, record))))}`;
}

/**
 * The key a claim offer is judged under, as Java's: the SHA-256 of its canonical TakeClaim encoding,
 * the bytes its signature covers whatever order the map arrived in (HLC round five, 2026-11-08,
 * E13), and its entry.
 */
function claimOfferKey(entryId: string, claim: Dict): string {
  return `claim:${toHex(cryptoPort().sha256(dumps(wire.canonicalClaim(claim) ?? claim)))}@${entryId}`;
}

/** The state join (ASF-017), exported so the conformance suite can prove it. */
/**
 * Fills `entryId` of a recordless state from the rumor item id (`r:<id>:<stamp>`, `d:<id>`,
 * `x:<id>:<stamp>`, `c:<id>:<stamp>`) when the DTO does not carry one (PD-L-02).
 */
export function nameRecordless(state: Dict, itemId: unknown): void {
  if ((state["record"] !== null && state["record"] !== undefined) || state["entryId"] || typeof itemId !== "string") {
    return;
  }
  const parts = itemId.split(":");
  if (parts.length >= 2 && ["r", "d", "x", "c"].includes(parts[0]) && parts[1].length > 0) {
    state["entryId"] = parts[1];
  }
}

/**
 * When the entry of `dto` lapses: its lease register, which a renewal moves, else its record's first
 * lease (HLC round five, 2026-11-08: every read, take, and sweep judges the renewed lease).
 */
export function leaseExpiryOf(dto: Dict): number {
  const lease = (dto["leaseValue"] ?? (dto["record"] as Dict | undefined)?.["lease"]) as Dict | undefined;
  return Number(lease?.["expiresAtMillis"] ?? 0);
}

/**
 * Whether the entry of `dto` is present (Java's EntryState.present, HLC round five, 2026-11-08):
 * uncompleted, with an add dot no remove covers.
 */
export function present(dto: Dict): boolean {
  if (dto["completed"]) {
    return false;
  }
  const adds = (dto["adds"] as Dict[] | undefined) ?? [];
  const removes = (dto["removes"] as Dict[] | undefined) ?? [];
  if (removes.length === 0) {
    return adds.length > 0; // the common case, judged on every sweep without a set
  }
  const removed = new Set(removes.map(dotKey));
  return adds.some((dot) => !removed.has(dotKey(dot)));
}

/**
 * Whether `dto` lies past its collection horizon (SPEC §7.3, Java's SpaceStateCrdt.collectable, HLC
 * round five, 2026-11-08): the entry is no longer live, and its lease expired LAPSED_GRACE_MILLIS ago
 * (at most twice the longest lease) for a lapse, or twice the longest lease ago for a completion or a
 * withdrawal.
 */
export function collectable(dto: Dict, nowMillis: number, longestLeaseMillis: number): boolean {
  const expiry = leaseExpiryOf(dto);
  const live = present(dto);
  if (live && expiry > nowMillis) {
    return false;
  }
  const twice = 2 * Math.max(0, longestLeaseMillis);
  return expiry + (live ? Math.min(twice, LAPSED_GRACE_MILLIS) : twice) <= nowMillis;
}

/**
 * Whether every dot in a state's adds and removes names the record issuer's peer as its replica (ASF-025,
 * Java's ReplicatedSpace.dotsBoundToIssuer). The issuer is an AgentId, `<peerId>/<localName>` (R5).
 */
function dotsBoundToIssuer(dto: Dict, record: Dict): boolean {
  const issuer = String(record["issuer"]);
  const peer = issuer.substring(0, issuer.indexOf("/"));
  const dots = [...((dto["adds"] as Dict[] | undefined) ?? []), ...((dto["removes"] as Dict[] | undefined) ?? [])];
  return dots.every((dot) => dot["replica"] === peer);
}

/** The identity of a dot, its replica and counter, as unionDots keys it. */
function dotKey(dot: unknown): string {
  const d = (dot ?? {}) as Dict;
  return `${String(d["replica"] ?? "")}\u0000${Number(d["counter"] ?? 0)}`;
}

export function joinStates(previous: Dict, incoming: Dict): Dict {
  const merged: Dict = { ...previous };
  merged["adds"] = unionDots(previous["adds"], incoming["adds"]);
  merged["removes"] = unionDots(previous["removes"], incoming["removes"]);
  // compareHlc sorts a refused or missing stamp first; the folds hand this join parsed stamps only.
  if (wire.compareHlc(incoming["leaseStamp"], previous["leaseStamp"]) > 0) {
    merged["leaseStamp"] = incoming["leaseStamp"];
    merged["leaseValue"] = incoming["leaseValue"];
  }
  merged["completed"] = Boolean(previous["completed"]) || Boolean(incoming["completed"]);
  return merged;
}

/** The union of two dot lists, deduplicated by (replica, counter) and
 * deterministically ordered like the Java side's sorted dots. */
function unionDots(a: unknown, b: unknown): Dict[] {
  const seen = new Map<string, Dict>();
  for (const dot of [...(Array.isArray(a) ? a : []), ...(Array.isArray(b) ? b : [])]) {
    if (dot !== null && typeof dot === "object") {
      const d = dot as Dict;
      seen.set(dotKey(d), d);
    }
  }
  return [...seen.entries()]
      .sort(([ka], [kb]) => (ka < kb ? -1 : ka > kb ? 1 : 0))
      .map(([, dot]) => dot);
}

/** Drops stamps older than a minute from a window and returns what remains. */
function pruneMinute(times: number[], now: number): number {
  let drop = 0;
  while (drop < times.length && now - times[drop] >= 60_000) {
    drop += 1;
  }
  if (drop > 0) {
    times.splice(0, drop);
  }
  return times.length;
}
