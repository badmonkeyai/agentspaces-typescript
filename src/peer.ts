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
import { equals, fromBase64, utf8 } from "./bytes.js";
import { cryptoPort } from "./crypto.js";
import { CborValue, dumps, loads } from "./cbor.js";
import { AgentIdentity, Identity, deriveId, instantIso, parseDurationMillis, parseInstantMillis, spaceIdLocal, verifyAgentCertificateAt, verifySignedGroupAd } from "./identity.js";
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
}

export class Peer {
  readonly states = new Map<string, Dict>();
  readonly claims = new Map<string, Dict>();
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
  malformedFrames = 0;
  // A lost socket is reconnected to the seeds in turn (the next seed first, a pause of
  // reconnectIntervalMs after every full round, for reconnectWindowMs) and the peer
  // re-introduced and re-pulled; a close() by the owner is final.
  reconnects = 0;
  reconnectIntervalMs = 5000;
  reconnectWindowMs = 600_000;
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
  private running = false;
  private readonly pulledSpaces = new Set<string>();
  private pulledAds = false;

  private founderId(): string | null {
    if (this.founder !== null) {
      return this.founder;
    }
    const ad = this.founding?.["advertisement"] as Dict | undefined;
    return typeof ad?.["issuer"] === "string" ? ad["issuer"] : null;
  }

  /** Dials the seed and introduces this peer to the group. */
  async connect(host: string, port: number): Promise<void> {
    await this.connectAny([{ host, port }]);
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
   * this peer dials, in priority order, through {@link connectAny} (JS-P-07).
   * Returns the group selected.
   */
  async bootstrap(url: string, options: {
    groupId?: string | null; name?: string | null; allowPlain?: boolean;
    beaconPeer?: string | null; timeoutMs?: number; fetch?: typeof fetch;
  } = {}): Promise<beacon.BeaconGroup> {
    const document = await beacon.fetchBeaconDocument(url, options);
    const group = beacon.groupFromDocument(document, { groupId: options.groupId, name: options.name });
    const wanted = beacon.bareGroupId(options.groupId) ?? beacon.bareGroupId(group.id);
    const founding = this.verifyFounding(group, wanted);
    this.group = founding.group;
    this.founding = founding.signed;
    const seeds = this.seedsOfGroup(group);
    if (seeds.length === 0) {
      throw new Error(`the beacon document lists no ${this.dialableSchemes().join(" or ")} seed for ${group.name}`);
    }
    await this.connectAny(seeds);
    return group;
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
    let signed: CborValue;
    try {
      signed = loads(fromBase64(group.founding));
    } catch {
      throw new Error(`the founding of ${group.name} is not CBOR`);
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
    return { group: verified, signed: signed as Dict };
  }

  /** Whether the seed connection is up (a reconnect may be in progress while it is not). */
  connected(): boolean {
    return this.running && this.channel !== null;
  }

  /**
   * After a lost socket: dials the seed again until the window runs out, then introduces this
   * peer again and pulls what it had pulled before, so a network hiccup costs a few seconds
   * rather than the membership (ROBUSTNESS.md §3.6).
   */
  private reconnecting = false;

  private reconnect(deadline: number, lastTried: number): void {
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
      if (!this.running || Date.now() >= deadline) {
        this.reconnecting = false;
        return;
      }
      // One dial at a time, never a tight loop: the seeds of a round are tried back to back and
      // every full round of refusals waits reconnectIntervalMs.
      const endOfRound = (tried + 1) % this.seeds.length === this.roundStart;
      const timer = setTimeout(() => this.reconnect(deadline, tried), endOfRound ? this.reconnectIntervalMs : 0);
      unref(timer);
    });
  }

  /** Where the current round of reconnect dials began: the seed after the one that dropped. */
  private roundStart = 0;

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
    if (this.running && this.seeds.length > 0 && !this.reconnecting) {
      this.roundStart = (this.seedIndex + 1) % this.seeds.length;
      this.reconnect(Date.now() + this.reconnectWindowMs, this.seedIndex);
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
    const body = env["body"];
    if (!(body instanceof Uint8Array)) {
      return false;
    }
    let signed: CborValue;
    try {
      signed = loads(body);
    } catch {
      return false;
    }
    if (verifySignedGroupAd(signed) !== pending.group) {
      return false; // not the self-certifying founding document of this group
    }
    pending.resolve(signed as Dict);
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
  }

  /** This peer's advertisement as of now: its endpoints, hints, and lease (whole seconds, as always stamped). */
  private selfAd(): Dict {
    const now = this.now();
    const hints = this.channelAuth === "session"
      ? { ...this.resourceHints, [SESSION_HINT]: "1" } : { ...this.resourceHints };
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
    const { entryId, body } = wire.entryDelta(space, this.group, typeName,
      payload, this.identity, agentName, leaseMillis, agent, this.now(), tags, payloadRef);
    // The writer holds its own entry too, folded into the verified local
    // replica before transport, so a local read sees it at once.
    this.foldDelta(loads((loads(body) as Dict)["payload"] as Uint8Array) as Dict);
    this.send("RUMOR", body);
    return entryId;
  }

  /**
   * Publishes an advertisement this peer issued (an AgentCard, an AssetCard)
   * on the `ads` stream as DiscoveryService.publish does: the stored form,
   * under the advertisement's id and issue time.
   */
  publishAd(adType: string, ad: Dict): void {
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
  /** The advertisements the `ads` stream carried, by id. */
  readonly ads = new Map<string, CachedAd>();
  /** Capability frame handlers by capability type: `(fromPeerId, payload)`. */
  readonly pipeHandlers = new Map<string, (from: string, payload: Uint8Array) => void>();

  /** Anti-entropy pull of the `ads` stream (SPEC §6.2): the cards and capability advertisements the group holds. */
  pullAds(): void {
    this.pulledAds = true;
    this.send("DIGEST", wire.digestBody({ ads: new Uint8Array() }), null, "dial");
  }

  /**
   * Admits a StoredAd as AdCache.accept does: the signature over the canonical
   * bytes under the carried key, the issuer derived from that key, and the TTL
   * not yet passed. Returns the cached entry, or null.
   */
  acceptAd(stored: unknown): CachedAd | null {
    if (typeof stored !== "object" || stored === null) {
      return null;
    }
    const s = stored as Dict;
    const adBytes = s["adBytes"];
    const key = s["publicKey"];
    const signature = s["signature"];
    if (!(adBytes instanceof Uint8Array) || !(key instanceof Uint8Array) || !(signature instanceof Uint8Array)) {
      return null;
    }
    if (!Identity.verify(key, adBytes, signature)) {
      return null;
    }
    let ad: Dict;
    let expires: number;
    try {
      ad = loads(adBytes) as Dict;
      if (typeof ad !== "object" || ad === null || ad["issuer"] !== deriveId(key)) {
        return null;
      }
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
    if (previous === undefined || parseInstantMillis(previous.ad["issued"]) <= parseInstantMillis(ad["issued"])) {
      this.ads.set(id, entry);
    }
    return this.ads.get(id)!;
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

  /** A `peers` stream item (PeerNode.SignedPeerAd): kept under its issuer when it verifies. */
  private acceptPeerAd(payload: Uint8Array): void {
    try {
      const signed = loads(payload) as Dict;
      const adBytes = signed["adBytes"] as Uint8Array;
      const key = signed["publicKey"] as Uint8Array;
      if (!Identity.verify(key, adBytes, signed["signature"] as Uint8Array)) {
        return;
      }
      const ad = loads(adBytes) as Dict;
      if (typeof ad === "object" && ad !== null && ad["issuer"] === deriveId(key)
          && ad["issuer"] !== this.identity.peerId) {
        const issuer = String(ad["issuer"]);
        const previous = this.members.get(issuer);
        if (previous !== undefined && previous["issued"] !== undefined
            && parseInstantMillis(previous["issued"]) > parseInstantMillis(ad["issued"])) {
          return; // an older issue of an advertisement already held
        }
        this.members.set(issuer, ad);
        this.heldPeerAds.set(issuer, payload);
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

  /** Called after a state folds (the merged state), for spaces and watches. */
  onState: ((dto: Dict) => void) | null = null;
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

  /**
   * Installs a claim the ordered log committed (OrderedTakes.onCommand, SPEC §7.4 ORDERED):
   * exactly as the holder signed it, through the same verification gossip gets, and then
   * gossips it on the space's stream so members outside the log learn it. Returns whether the
   * claim is now the one held for the entry.
   */
  applyCommittedClaim(space: string, entryId: string, signed: Dict): boolean {
    this.foldClaim(entryId, signed);
    const held = this.claims.get(entryId);
    if (held === undefined || !equals(dumps((held["claim"] as Dict) ?? {}), dumps((signed["claim"] as Dict) ?? {}))) {
      return false;
    }
    this.send("RUMOR", wire.rumorBody(`space:${space}`, `c:${entryId}:${this.now()}`, this.rumorHops,
      wire.claimDelta(entryId, held)));
    return true;
  }

  /**
   * Anti-entropy pull (spec §5.3): offer an empty digest. The revocation
   * streams ride along: a partner answers only the streams a digest names, so
   * a late joiner learns the group's revocations here.
   */
  pullSpace(space: string): void {
    this.pulledSpaces.add(space);
    this.send("DIGEST", wire.digestBody({ [`space:${space}`]: new Uint8Array(),
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
      if (record && record["type"] === typeName && !dto["completed"]) {
        const payload = this.payloadOf(dto);
        if (payload !== null) {
          results.push(loads(payload) as Dict);
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
        if (!record || record["type"] !== typeName || dto["completed"]
            || (record["group"] !== undefined && record["group"] !== this.group)
            || record["spaceId"] !== wireSpaceId(this.group, space)
            || (exactEntryId !== null && entryId !== exactEntryId)) {
          continue;
        }
        const lease = (dto["leaseValue"] ?? record["lease"]) as Dict | undefined;
        if (!lease || Number(lease["expiresAtMillis"]) <= now) {
          continue;
        }
        const current = this.claims.get(entryId)?.["claim"] as Dict | undefined;
        if (current && Number(current["expiresAtMillis"]) > now) {
          continue;
        }
        // A template narrows the candidates; a bid function prices the claim (AUCTION).
        const raw = this.payloadOf(dto);
        if (raw === null) {
          continue; // its block or artifact is still on its way
        }
        const payload = loads(raw) as Dict;
        if (matches !== null && !matches(payload ?? {}, (record["tags"] as Dict) ?? {})) {
          continue;
        }
        const price = typeof bid === "function" ? bid(payload ?? {}) : bid;
        const epoch = current ? Number(current["epoch"]) + 1 : 1;
        const claim = wire.takeClaim(entryId, String(record["spaceId"]), epoch,
          wire.hlcNow(holder, now), holder, price, now + leaseMillis);
        const signed = wire.signedClaim(claim, this.identity, agent);
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
            && !this.states.get(entryId)?.["completed"]
            && !this.revocations.refuses(holder, agent?.publicRaw ?? null, null)) {
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
    const dto = wire.signState({ ...this.states.get(entryId)!, completed: true },
      this.identity, agent, this.now());
    this.states.set(entryId, dto);
    this.onState?.(dto);
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
        || !localPeerHolder || state?.["completed"] || !claim || claim["entryId"] !== entryId
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
    for (const [id, claim] of Object.entries((snapshot["claims"] ?? {}) as Dict)) {
      this.foldClaim(id, claim as Dict);
    }
    for (const dto of (snapshot["states"] ?? []) as Dict[]) {
      const record = dto["record"] as Dict | undefined;
      if (record && (record["group"] === undefined || record["group"] === this.group)) this.fold(dto);
    }
  }

  /**
   * Renews this peer's write of an entry (SPEC §7.3): a later lease stamp and
   * expiry, re-signed by the issuer, as the agent when it wrote as one. Only
   * the issuer renews: `agent` must be the record's issuer, and without one
   * the issuer must be one of this peer's agent names.
   */
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
    const channel = await dialer.dial(seed);
    if (!this.running) {
      channel.close(); // closed while dialing
      return;
    }
    this.channel = channel;
    this.session = null;
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
    }
    if (this.accepts(env)) {
      try {
        this.handle(env, link);
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

  private handle(env: Dict, link: Link | null = null, relayedFrame = false): void {
    if (!this.frames.admit(env, this.now())) {
      return; // stale, far ahead, or a replay: dropped and counted, nothing more
    }
    let reintroduce = false;
    wire.hlcObserve(this.identity.peerId, env["stamp"], this.now());
    const kind = env["kind"];
    const body = (env["body"] as Uint8Array) ?? new Uint8Array();
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
      if (kind !== "RUMOR" && kind !== "SESSION_HELLO" && !relayed) {
        this.maybeSessionHello(sender, link); // a frame past the introduction proves the member admitted us
      }
    }
    if (kind === "SESSION_HELLO") {
      this.onSessionHello(env, link);
    } else if (kind === "RELAY_FRAME") {
      this.onRelayFrame(env, link);
    } else if (kind === "DIGEST") {
      this.onDigest(String(sender), loads(body) as Dict);
    } else if (kind === "PING_REQ") {
      this.onPingReq(String(sender), loads(body) as Dict);
    } else if (kind === "ACK") {
      this.onAck(String(sender), loads(body) as Dict);
    } else if (kind === "PIPE_DATA") {
      const frame = loads(body) as Dict;
      if (typeof frame === "object" && frame !== null && frame["capability"] === wire.RELAY_SIGNAL_CAPABILITY) {
        const signal = loads((frame["payload"] as Uint8Array) ?? new Uint8Array([0xf6]));
        if (typeof signal === "object" && signal !== null) {
          this.relaySignals.push(signal as Dict);
          this.relaySignals.splice(0, Math.max(0, this.relaySignals.length - 64));
        }
        return;
      }
      const handler = typeof frame === "object" && frame !== null
        ? this.pipeHandlers.get(String(frame["capability"])) : undefined;
      if (handler !== undefined) {
        handler(String(sender), (frame["payload"] as Uint8Array) ?? new Uint8Array());
      }
    } else if (kind === "PING") {
      const ping = loads(body) as Dict;
      // Java's probe nonces are random 64-bit longs: echo the decoded integer
      // as is (a bigint beyond 2^53), since a Number would lose it and the
      // encoder would refuse it, leaving the probe unanswered and this peer evicted.
      this.send("ACK", wire.ackBody((ping["nonce"] as number | bigint | undefined) ?? 0));
    } else if (kind === "GROUP_AD") {
      this.offerGroupAd(env); // only a join in progress cares (§10.1)
    } else if (kind === "RUMOR") {
      const rumor = loads(body) as Dict;
      if (revocation.STREAMS.includes(String(rumor["streamId"]))) {
        this.revocations.accept(String(rumor["streamId"]), rumor["payload"], this.now());
      } else if (rumor["streamId"] === "peers") {
        this.acceptPeerAd((rumor["payload"] as Uint8Array) ?? new Uint8Array());
      } else if (rumor["streamId"] === "ads") {
        this.acceptAd(loads((rumor["payload"] as Uint8Array) ?? new Uint8Array([0xf6])));
      } else if (String(rumor["streamId"] ?? "").startsWith("space:")) {
        const delta = loads((rumor["payload"] as Uint8Array) ?? new Uint8Array([0xf6])) as Dict;
        this.foldDelta(delta);
      }
      this.forwardRumor(rumor, link);
    } else if (kind === "BLOCK_WANT") {
      const want = loads(body) as Dict;
      const data = typeof want === "object" && want !== null ? this.blocks.get(String(want["cid"])) : undefined;
      if (data !== undefined) {
        this.sendAddressed("BLOCK", wire.blockBody(String(want["cid"]), data), String(sender));
      }
    } else if (kind === "BLOCK") {
      const block = loads(body) as Dict;
      if (typeof block === "object" && block !== null && block["bytes"] instanceof Uint8Array
          && this.blockAsked.has(String(block["cid"])) && wire.contentId(block["bytes"]) === block["cid"]) {
        this.blocks.set(String(block["cid"]), block["bytes"]);
        this.wakeFoldWaiters();
      }
    } else if (kind === "PULL_RESP") {
      const resp = loads(body) as Dict;
      const deltas = (resp["deltas"] as Dict) ?? {};
      for (const [stream, deltaBytes] of Object.entries(deltas)) {
        if (revocation.STREAMS.includes(stream) && deltaBytes instanceof Uint8Array
            && deltaBytes.length > 0) {
          for (const signed of (loads(deltaBytes) as CborValue[]) ?? []) {
            this.revocations.acceptSigned(stream, signed, this.now());
          }
          continue;
        }
        if (stream === "view" && deltaBytes instanceof Uint8Array && deltaBytes.length > 0) {
          for (const payload of (loads(deltaBytes) as CborValue[]) ?? []) {
            if (payload instanceof Uint8Array) {
              this.acceptPeerAd(payload);
            }
          }
          continue;
        }
        if (stream === "ads" && deltaBytes instanceof Uint8Array && deltaBytes.length > 0) {
          const delta = loads(deltaBytes) as Dict;
          for (const stored of ((delta?.["ads"] as unknown[]) ?? [])) {
            this.acceptAd(stored);
          }
          continue;
        }
        if (!stream.startsWith("space:") || !(deltaBytes instanceof Uint8Array)
            || deltaBytes.length === 0) {
          continue;
        }
        const sync = loads(deltaBytes) as Dict;
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
    return utf8(serving.digestLines(summary));
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
    return dumps({ states, claims });
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
      this.send("PULL_RESP", dumps({ deltas }), from);
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
  private onRelayFrame(env: Dict, link: Link | null): void {
    let body: Dict;
    try {
      body = loads((env["body"] as Uint8Array) ?? new Uint8Array()) as Dict;
    } catch {
      return;
    }
    const target = body?.["target"];
    const frame = body?.["frame"];
    if (typeof target !== "string" || !(frame instanceof Uint8Array)) {
      return;
    }
    if (target === this.identity.peerId) {
      const inner = wire.decodeFrame(frame); // fully signed, whatever the link's session
      if (inner === null || inner["kind"] === "RELAY_FRAME" || !this.accepts(inner)) {
        return;
      }
      this.relayedIn += 1;
      if (typeof inner["from"] === "string") {
        this.noteRelayed(inner["from"]); // JS-W-11: the other direction of the pair
      }
      try {
        this.handle(inner, link, true);
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
    const record = dto["record"] as Dict | undefined;
    const entryId = record?.["entryId"];
    if (typeof entryId !== "string" || !this.verifyState(dto, record!)) {
      return; // unauthenticated record or forged mutable state: drop it
    }
    if (this.refusedForRevocation(dto, record!)) {
      // Authentic, but its actor is revoked here (SPEC §5.6): what is already
      // held stays as held, and this state is not merged.
      return;
    }
    // ASF-017: states JOIN, mirroring the Java CRDT — dot sets union, the
    // lease is last-writer-wins by HLC stamp, and completed is monotone. A
    // replayed early state (validly signed by its author) can therefore never
    // shrink the sets, roll back the lease, or undo a completion.
    const previous = this.states.get(entryId);
    this.states.set(entryId,
        previous === undefined ? dto : joinStates(previous, dto));
    this.onState?.(this.states.get(entryId)!);
    this.wakeFoldWaiters();
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
    const now = this.now();
    // The record: peer-signed, or agent-signed under a peer certificate
    // (TECH-SPEC §7.2's two-key rule, QA4 A4-7), judged at its issue stamp.
    if (!wire.verifyRecord(record, issuerKey, dto["agentCertificate"], now)) {
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
          || !wire.verifyClaimProof(signed, now)) {
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
    const signedAt = dto["signedAt"] ?? null;
    const view = dumps(wire.stateSignView(String(record["spaceId"]),
      String(record["entryId"]), (dto["adds"] as Dict[]) ?? [],
      (dto["removes"] as Dict[]) ?? [], String(dto["leaseStamp"]),
      dto["leaseValue"] as Dict, Boolean(dto["completed"]),
      signer === null ? null : String(signer), signedAt === null ? null : String(signedAt)));
    if (signer !== null) {
      const certificate = dto["stateCertificate"];
      let signedMillis: number;
      try {
        signedMillis = wire.hlcPhysical(signedAt);
      } catch {
        return false;
      }
      return signer === party && typeof certificate === "object" && certificate !== null
        && verifyAgentCertificateAt(certificate, signerKey, String(party), signedMillis, now)
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
   * instant is refused while the original history still folds.
   */
  private refusedForRevocation(dto: Dict, record: Dict): boolean {
    // An unreadable time is an unknown one: refused under any revocation.
    const signedAt = dto["signedAt"] != null ? physicalOrNull(dto["signedAt"]) : null;
    if (dto["completed"]) {
      const signed = this.claims.get(String(record["entryId"]));
      const claim = (signed?.["claim"] ?? {}) as Dict;
      const certificate = (signed?.["holderCertificate"] ?? {}) as Dict;
      return claim["holder"] != null
        && this.revocations.refuses(claim["holder"], certificate["agentPublicKey"], signedAt);
    }
    const certificate = (dto["agentCertificate"] ?? {}) as Dict;
    const stateCertificate = (dto["stateCertificate"] ?? {}) as Dict;
    return this.revocations.refuses(record["issuer"], certificate["agentPublicKey"],
      signedAt ?? physicalOrNull(dto["leaseStamp"]))
      || (dto["signer"] != null
        && this.revocations.refuses(record["issuer"], stateCertificate["agentPublicKey"], signedAt));
  }

  private foldClaim(entryId: string, signed: Dict): void {
    const claim = signed["claim"] as Dict | undefined;
    const holderKey = signed["holderKey"];
    if (!claim || !(holderKey instanceof Uint8Array)) {
      return;
    }
    // The claim's signed bindings and numeric fields are validated before the
    // lattice sees them: a claim transplanted under a foreign map key is
    // dropped (ASF-002), and a NaN epoch/bid cannot win every comparison by
    // making the total order lie (ASF-033).
    if (claim["entryId"] !== entryId) {
      return;
    }
    const epoch = wire.claimNumber(claim["epoch"]);
    const bid = wire.claimNumber(claim["bid"]);
    const expires = wire.claimNumber(claim["expiresAtMillis"]);
    if (!Number.isFinite(epoch) || epoch <= 0 || !Number.isFinite(bid)
        || !Number.isFinite(expires) || typeof claim["stamp"] !== "string") {
      return;
    }
    // The proof: peer-signed, or agent-signed under a peer certificate
    // (TECH-SPEC §7.6's two-key rule, QA4 A4-7 phase 3).
    if (!wire.verifyClaimProof(signed, this.now())) {
      return;
    }
    // SPEC §5.6 v0.1.13 (review M-1): a revoked holder takes nothing, whatever
    // the claim's stamp, since a renewal keeps it.
    const certificate = (signed["holderCertificate"] ?? {}) as Dict;
    if (this.revocations.refuses(claim["holder"], certificate["agentPublicKey"], null)) {
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
    this.claims.set(entryId, wire.mergeClaims(this.claims.get(entryId), signed));
    this.onClaim?.(entryId, this.claims.get(entryId)!);
    this.wakeFoldWaiters();
  }
}

/** An empty digest for each revocation stream (SPEC §5.6). */
function revocationDigests(): Dict {
  return Object.fromEntries(revocation.STREAMS.map((stream) => [stream, new Uint8Array()]));
}

/** An HLC stamp's physical milliseconds, or null when it is not a stamp. */
function physicalOrNull(stamp: unknown): number | null {
  try {
    return wire.hlcPhysical(stamp);
  } catch {
    return null;
  }
}

/** The state join (ASF-017), exported so the conformance suite can prove it. */
export function joinStates(previous: Dict, incoming: Dict): Dict {
  const merged: Dict = { ...previous };
  merged["adds"] = unionDots(previous["adds"], incoming["adds"]);
  merged["removes"] = unionDots(previous["removes"], incoming["removes"]);
  if (wire.compareHlc(String(incoming["leaseStamp"] ?? "0:0:"),
      String(previous["leaseStamp"] ?? "0:0:")) > 0) {
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
      seen.set(`${String(d["replica"] ?? "")}\u0000${Number(d["counter"] ?? 0)}`, d);
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
