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
 * speak, from Node's standard library alone.
 */

import { Socket, connect } from "node:net";
import { CborValue, dumps, loads } from "./cbor.js";
import { AgentIdentity, Identity, deriveId, instantIso, parseDurationMillis, parseInstantMillis, spaceIdLocal, verifyAgentCertificateAt, verifySignedGroupAd } from "./identity.js";
import * as revocation from "./revocation.js";
import * as wire from "./wire.js";
import type { Dict } from "./wire.js";

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

export class Peer {
  readonly states = new Map<string, Dict>();
  readonly claims = new Map<string, Dict>();
  /** The founding advertisement this peer joined with, when it joined by GroupID. */
  founding: Dict | null = null;
  private socket: Socket | null = null;
  private pending = Buffer.alloc(0);
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
  }

  private founderId(): string | null {
    if (this.founder !== null) {
      return this.founder;
    }
    const ad = this.founding?.["advertisement"] as Dict | undefined;
    return typeof ad?.["issuer"] === "string" ? ad["issuer"] : null;
  }

  /** Dials the seed and introduces this peer to the group. */
  async connect(host: string, port: number): Promise<void> {
    await this.dial(host, port);
    this.introduce();
    this.pullRevocations();
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
    await this.dial(host, port);
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
      signed = loads(Buffer.from(body));
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
    this.socket?.destroy();
    this.socket = null;
  }

  /** Publishes this peer's leased self-advertisement (spec §5.2). */
  introduce(): void {
    const now = this.now();
    // Whole seconds, as the advertisement has always been stamped.
    const ad = wire.peerAdvertisement(this.group, this.identity, instantIso(now - (now % 1000)));
    const payload = wire.signedPeerAd(ad, this.identity);
    const itemId = `peer:${this.identity.peerId}:${now}`;
    this.send("RUMOR", wire.rumorBody("peers", itemId, 6, payload));
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
    const { entryId, body } = wire.entryDelta(space, this.group, typeName,
      dumps(value), this.identity, agentName, leaseMillis, agent, this.now(), tags);
    // The writer holds its own entry too, folded into the verified local
    // replica before transport, so a local read sees it at once.
    this.foldDelta(loads(Buffer.from((loads(body) as Dict)["payload"] as Uint8Array)) as Dict);
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
    this.send("DIGEST", wire.digestBody({ ads: new Uint8Array() }));
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
      ad = loads(Buffer.from(adBytes)) as Dict;
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

  /** One capability frame to a member (CapabilityPipes.send): a PIPE_DATA envelope addressed to it. */
  sendPipe(to: string, capability: string, payload: Uint8Array): void {
    this.send("PIPE_DATA", dumps({ capability, payload }), to);
  }

  /** A `peers` stream item (PeerNode.SignedPeerAd): kept under its issuer when it verifies. */
  private acceptPeerAd(payload: Uint8Array): void {
    try {
      const signed = loads(Buffer.from(payload)) as Dict;
      const adBytes = signed["adBytes"] as Uint8Array;
      const key = signed["publicKey"] as Uint8Array;
      if (!Identity.verify(key, adBytes, signed["signature"] as Uint8Array)) {
        return;
      }
      const ad = loads(Buffer.from(adBytes)) as Dict;
      if (typeof ad === "object" && ad !== null && ad["issuer"] === deriveId(key)
          && ad["issuer"] !== this.identity.peerId) {
        this.members.set(String(ad["issuer"]), ad);
      }
    } catch {
      // not a peer advertisement
    }
  }

  /** Called after a state folds (the merged state), for spaces and watches. */
  onState: ((dto: Dict) => void) | null = null;
  /** Called after a claim folds (the merged signed claim). */
  onClaim: ((entryId: string, signed: Dict) => void) | null = null;

  /**
   * Anti-entropy pull (spec §5.3): offer an empty digest. The revocation
   * streams ride along: a partner answers only the streams a digest names, so
   * a late joiner learns the group's revocations here.
   */
  pullSpace(space: string): void {
    this.send("DIGEST", wire.digestBody({ [`space:${space}`]: new Uint8Array(),
      ...revocationDigests() }));
  }

  /**
   * Anti-entropy pull of the revocation streams alone (SPEC §5.6): sent once
   * on joining, so revocations issued before this peer arrived apply from its
   * first merge.
   */
  pullRevocations(): void {
    this.send("DIGEST", wire.digestBody(revocationDigests()));
  }

  /** Returns decoded values of known live entries of one schema type. */
  find(typeName: string): Dict[] {
    const results: Dict[] = [];
    for (const dto of this.states.values()) {
      const record = dto["record"] as Dict | undefined;
      if (record && record["type"] === typeName && !dto["completed"]) {
        results.push(loads(Buffer.from(record["payload"] as Uint8Array)) as Dict);
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
      this.pullSpace(space);
      await sleep(300);
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
        const payload = loads(Buffer.from((record["payload"] as Uint8Array) ?? new Uint8Array([0xf6]))) as Dict;
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
        await sleep(settleMillis);
        this.pullSpace(space);
        await sleep(300);
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
      && Buffer.from(signed["holderKey"] as Uint8Array).equals(this.identity.publicRaw));
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

  private dial(host: string, port: number): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const socket = connect({ host, port }, () => resolve());
      socket.on("error", reject);
      socket.on("data", (chunk) => this.onData(typeof chunk === "string" ? Buffer.from(chunk) : chunk));
      this.socket = socket;
    });
  }

  private send(kind: string, body: Buffer, to: string | null = null): void {
    this.sendEnvelope(wire.envelope(this.group, kind, this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now()), body, to));
  }

  private sendEnvelope(env: Dict): void {
    const frame = wire.encodeFrame(env, this.identity);
    const header = Buffer.alloc(4);
    header.writeInt32BE(frame.length);
    this.socket?.write(Buffer.concat([header, frame]));
  }

  private onData(chunk: Buffer): void {
    this.pending = Buffer.concat([this.pending, chunk]);
    while (this.pending.length >= 4) {
      const length = this.pending.readInt32BE(0);
      if (length <= 0 || length > wire.MAX_FRAME_BYTES) {
        // A corrupt or hostile length prefix poisons the whole stream: there
        // is no way to resynchronize, and a non-positive length would loop
        // here forever (ASF-014/016). Drop the connection; leases recover.
        this.pending = Buffer.alloc(0);
        this.socket?.destroy();
        return;
      }
      if (this.pending.length < 4 + length) {
        return;
      }
      const frame = this.pending.subarray(4, 4 + length);
      this.pending = this.pending.subarray(4 + length);
      const env = wire.decodeFrame(Buffer.from(frame));
      if (this.accepts(env)) {
        try {
          this.handle(env);
        } catch {
          // One undecodable frame never stops the peer.
        }
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

  private handle(env: Dict): void {
    wire.hlcObserve(this.identity.peerId, env["stamp"], this.now());
    const kind = env["kind"];
    const body = Buffer.from((env["body"] as Uint8Array) ?? new Uint8Array());
    const sender = env["from"];
    if (typeof sender === "string" && sender !== this.identity.peerId) {
      if (!this.members.has(sender)) {
        this.members.set(sender, {}); // a verified frame is a member heard from
      }
      this.reachable.add(sender);
    }
    if (kind === "PIPE_DATA") {
      const frame = loads(body) as Dict;
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
        this.acceptAd(loads(Buffer.from((rumor["payload"] as Uint8Array) ?? new Uint8Array([0xf6]))));
      } else if (String(rumor["streamId"] ?? "").startsWith("space:")) {
        const delta = loads(Buffer.from(
          (rumor["payload"] as Uint8Array) ?? new Uint8Array([0xf6]))) as Dict;
        this.foldDelta(delta);
      }
    } else if (kind === "PULL_RESP") {
      const resp = loads(body) as Dict;
      const deltas = (resp["deltas"] as Dict) ?? {};
      for (const [stream, deltaBytes] of Object.entries(deltas)) {
        if (revocation.STREAMS.includes(stream) && deltaBytes instanceof Uint8Array
            && deltaBytes.length > 0) {
          for (const signed of (loads(Buffer.from(deltaBytes)) as CborValue[]) ?? []) {
            this.revocations.acceptSigned(stream, signed, this.now());
          }
          continue;
        }
        if (stream === "ads" && deltaBytes instanceof Uint8Array && deltaBytes.length > 0) {
          const delta = loads(Buffer.from(deltaBytes)) as Dict;
          for (const stored of ((delta?.["ads"] as unknown[]) ?? [])) {
            this.acceptAd(stored);
          }
          continue;
        }
        if (!stream.startsWith("space:") || !(deltaBytes instanceof Uint8Array)
            || deltaBytes.length === 0) {
          continue;
        }
        const sync = loads(Buffer.from(deltaBytes)) as Dict;
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
    }
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
