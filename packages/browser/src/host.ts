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
 * The resident host (srad/agentspaces-js.md §3.6 residency `resident`,
 * JS-R-02, JS-R-03, JS-R-07): one `Peer` in a SharedWorker (or a dedicated
 * Worker), its identity and agent key in IndexedDB, the Web Lock
 * `agentspaces:<group>:<peerId>` held for its life, pages attached over
 * ports and served the space verbs, and a tick that does the peer's
 * housekeeping and keeps the claims pages hold alive.
 *
 * The pause rule (JS-R-03): the host runs while at least one attached page
 * is active; when the last page hides (`pagehide`, `freeze`), detaches, or
 * falls silent, the host snapshots its state, stops its tick (so nothing is
 * renewed), and closes its channel cleanly, so the hub sees it leave. A page
 * returning resumes the same peer: it dials again, introduces itself, pulls
 * its spaces, and drops every hold whose lease lapsed while it was away. A
 * claim is renewed only by the tick, so no claim outlives its lease across a
 * pause; a subscription lease runs on the timer port and lapses on time
 * whether or not the host is paused.
 */

import {
  Binder, HttpDialer, Identity, Peer, Space, Template, WsDialer, bytes, capabilities, cbor, parseSeed, platform,
} from "@agentspaces/client";
import type { AgentIdentity, BinderOptions, Bound, Repeating, Residency, Seed, SpaceEvent, Subscription } from "@agentspaces/client";
import { IndexedDbKeyStore, STATE_STORE } from "./idb.js";
import { Held, LockElection } from "./lock.js";
import { OpfsStore } from "./opfs.js";
import {
  Answer, ContentConfig, Envelope, HostConfig, HostState, PortLike, Push, Request, WireEntry, WireManifest, WireProgress,
  agentKeyName, databaseName,
  identityLockName, lockName, packMap, PEER_KEY, PEER_PUB, SNAPSHOT, token, unpackMap,
} from "./protocol.js";

type Dict = { [key: string]: cbor.CborValue };

/** A page attached to the host: its id, whether it is active, and when it last spoke. */
type PageRecord = { id: string; active: boolean; lastBeat: number };

/** A claim a page holds through this host; `keepAlive` ones are renewed by the tick at half-lease. */
type Hold = { space: string; leaseMillis: number; expiresAt: number; keepAlive: boolean };

export type ResidentHostOptions = {
  /** Whether this host runs in a SharedWorker; a dedicated Worker serves one page. */
  shared: boolean;
  /** Where the host reports; `console.info` by default, `null` for silence. */
  log?: ((line: string) => void) | null;
  clock?: () => number;
  /** How long the host waits between dial attempts after a lost or refused resume; 5 s by default. */
  reconnectIntervalMs?: number;
};

export const DEFAULT_TICK_MILLIS = 1000;
export const DEFAULT_LOCK_WAIT_MILLIS = 3000;
export const DEFAULT_SNAPSHOT_MILLIS = 30_000;
export const DEFAULT_PAGE_TIMEOUT_MILLIS = 15_000;
export const DEFAULT_AGENT_NAME = "resident";
/** The host's agent certificate lifetime; the agent re-issues it at half-life. */
export const AGENT_TTL = "PT24H";
/** JS-R-06, as the service host judges it: drifting ticks before the drop, the drift factor, the quiet span that restores. */
export const DRIFT_TICKS = 3;
export const DRIFT_FACTOR = 2;
export const RECOVERY_MILLIS = 60_000;

/** An agent bound in the worker, kept so a drop to visitor duties can close it and a recovery bind it again. */
type Binding = { instance: object; options: Omit<BinderOptions, "agent" | "agentName" | "residency">; bound: Bound };

/**
 * The browser dialers, registered by name rather than through the core's default list: a bundler
 * that prunes side-effect imports (the core's `transport/defaults.js`) would otherwise leave the
 * worker with nothing to dial.
 */
export function registerBrowserDialers(peer: Peer): void {
  if (typeof (globalThis as { WebSocket?: unknown }).WebSocket === "function") {
    peer.registerDialer(new WsDialer("ws"));
    peer.registerDialer(new WsDialer("wss"));
  }
  if (typeof fetch === "function") {
    peer.registerDialer(new HttpDialer("http"));
    peer.registerDialer(new HttpDialer("https"));
  }
}

export class ResidentHost {
  /** Minted at construction: a page that sees a new one knows the worker restarted. */
  readonly instance = token();
  readonly shared: boolean;
  config: HostConfig | null = null;
  peer: Peer | null = null;
  identity: Identity | null = null;
  agent: AgentIdentity | null = null;
  keys: IndexedDbKeyStore | null = null;
  state: IndexedDbKeyStore | null = null;
  /**
   * `resident` while the tick keeps its cadence, `visitor` while it drifts (JS-R-06): a tick later
   * than twice the period three times running suspends the keeper duties (worker-side bindings
   * closed, held claims left to lapse) until sixty seconds of cadence restore them.
   */
  residency: Residency = "resident";
  /** Ticks that arrived later than twice the period, in total. */
  drifts = 0;
  private consecutiveDrifts = 0;
  private lastDriftAt = 0;
  private lastTickAt = 0;
  private cadenceKnown = false;
  /** Paused until a page is active; see the pause rule above. */
  paused = true;
  reason: string | null = "not started";
  connected = false;
  ticks = 0;
  pauses = 0;
  resumes = 0;
  private lock: Held | null = null;
  private starting: Promise<void> | null = null;
  private started = false;
  private resuming: Promise<void> | null = null;
  private retry: unknown = null;
  private tick: Repeating | null = null;
  private lastSnapshot = 0;
  private dirty: unknown = null;
  /** How long after a write, take, or completion the host snapshots; 1 s, coalescing a burst. */
  dirtySnapshotMillis = 1000;
  private nextSub = 1;
  private readonly pages = new Map<PortLike, PageRecord>();
  private readonly spaces = new Map<string, Space>();
  private readonly subscriptions = new Map<number, { subscription: Subscription<unknown>; port: PortLike }>();
  private readonly holds = new Map<string, Hold>();
  /** The content swarm (LB-C-06), when the config asked for it; built at boot over OPFS or memory. */
  content: capabilities.Content | null = null;
  contentStore: string | null = null;
  /** The fetches pages asked for, with the pages to tell. */
  private readonly contentFetches = new Map<string, { fetch: capabilities.Fetch; ports: Set<PortLike>; lastPushed: number }>();
  /** The agents bound in this worker (`bind`), and those a drift suspended. */
  readonly bindings: Binding[] = [];
  readonly suspended: Binding[] = [];
  private readonly resumeListeners: Array<() => void> = [];
  /** The most recent log lines, for pages and operators (a worker's console is hard to reach). */
  readonly recent: string[] = [];
  /** How many recent lines are kept: a ring size, not a cap on anything. */
  recentLines = 200;
  private readonly sink: (line: string) => void;
  private readonly clock: () => number;
  private readonly reconnectIntervalMs: number;

  constructor(options: ResidentHostOptions) {
    this.shared = options.shared;
    this.clock = options.clock ?? Date.now;
    this.reconnectIntervalMs = options.reconnectIntervalMs ?? 5000;
    this.sink = options.log === null ? () => undefined : options.log ?? ((line) => console.info(line));
  }

  private log(line: string): void {
    this.recent.push(`${new Date(this.clock()).toISOString()} ${line}`);
    if (this.recent.length > this.recentLines) {
      this.recent.splice(0, this.recent.length - this.recentLines);
    }
    this.sink(line);
  }

  // ------------------------------------------------------------------ ports

  /** Serves a page's port (a SharedWorker's `onconnect` port, or a dedicated Worker's own scope). */
  attach(port: PortLike): void {
    port.onmessage = (event) => {
      const data = event.data as Envelope | null;
      if (data === null || typeof data !== "object" || typeof data.id !== "number" || typeof data.t !== "string") {
        return; // not ours; a page may share the port with other code
      }
      void this.dispatch(port, data);
    };
    port.start?.();
  }

  private async dispatch(port: PortLike, envelope: Envelope): Promise<void> {
    let answer: Answer;
    try {
      answer = { id: envelope.id, ok: true, value: await this.handle(port, envelope) };
    } catch (e) {
      answer = { id: envelope.id, ok: false, error: e instanceof Error ? e.message : String(e) };
    }
    try {
      port.postMessage(answer);
    } catch (e) {
      this.log(`cannot answer a page: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (envelope.t === "detach") {
      port.close?.(); // after the answer left: the page owns the port until then
    }
  }

  private push(port: PortLike, message: Push): void {
    try {
      port.postMessage(message);
    } catch {
      // a port that cannot take a push is gone; the beat sweep drops it
    }
  }

  private async handle(port: PortLike, request: Request): Promise<unknown> {
    switch (request.t) {
      case "hello":
        return this.hello(port, request.config, request.pageId, request.active);
      case "beat":
      case "activity": {
        const page = this.pages.get(port);
        if (page === undefined) {
          throw new Error("this page is not attached; say hello first");
        }
        page.lastBeat = this.clock();
        page.active = request.active;
        this.onActivity();
        return null;
      }
      case "detach":
        this.detach(port, "detached");
        return null;
      case "status":
        return this.status();
      case "log":
        return [...this.recent];
      case "snapshot":
        await this.saveSnapshot();
        return null;
      case "write": {
        const peer = this.requireRunning();
        this.space(request.space);
        const entryId = peer.writeEntry(request.space, request.schema, unpackMap(request.payload), this.agentName(),
          request.leaseMillis, this.agent, unpackMap(request.tags));
        this.markDirty();
        return entryId;
      }
      case "entries": {
        const space = this.space(request.space);
        return space.entries(new Template(request.schema), request.limit, request.includeTaken)
          .map((entry) => this.wireEntry(entry.entryId, entry.expiresAtMillis, entry.completed, entry.taken));
      }
      case "pull":
        this.space(request.space);
        this.requirePeer().pullSpace(request.space);
        return null;
      case "awaitFold":
        await this.requirePeer().awaitFold(request.millis);
        return null;
      case "take": {
        const peer = this.requireRunning();
        this.space(request.space);
        const entryId = await peer.takeEntry(request.space, request.schema, this.agentName(), request.leaseMillis, 600,
          request.timeoutMillis, this.agent, request.entryId);
        if (entryId !== null) {
          this.holds.set(entryId, { space: request.space, leaseMillis: request.leaseMillis,
            expiresAt: this.claimExpiry(entryId), keepAlive: request.keepAlive });
          this.markDirty();
        }
        return entryId;
      }
      case "complete": {
        const peer = this.requireRunning();
        peer.requireHeld(request.space, request.entryId, this.agent); // before any result is written
        let resultId: string | null = null;
        if (request.result !== null) {
          this.space(request.result.space);
          resultId = peer.writeEntry(request.result.space, request.result.schema, unpackMap(request.result.payload),
            this.agentName(), request.result.leaseMillis, this.agent, unpackMap(request.result.tags));
        }
        peer.completeEntry(request.space, request.entryId, this.agent);
        this.holds.delete(request.entryId);
        this.markDirty();
        return resultId;
      }
      case "renewClaim": {
        const peer = this.requireRunning();
        peer.renewClaim(request.space, request.entryId, request.leaseMillis, this.requireAgent());
        const hold = this.holds.get(request.entryId);
        if (hold !== undefined) {
          hold.leaseMillis = request.leaseMillis;
          hold.expiresAt = this.claimExpiry(request.entryId);
        }
        return null;
      }
      case "renewEntry":
        this.requireRunning().renewEntry(request.space, request.entryId, request.leaseMillis, this.agent);
        return null;
      case "watch": {
        if (!this.pages.has(port)) {
          throw new Error("this page is not attached; say hello first");
        }
        const key = this.nextSub++;
        const subscription = this.space(request.space).watch(new Template(request.schema), (event: SpaceEvent<unknown>) => {
          this.push(port, { ev: "event", sub: key, kind: event.kind,
            entry: this.wireEntry(event.entry.entryId, event.entry.expiresAtMillis, event.entry.completed, event.entry.taken) });
        });
        subscription.on("close", (reason: string) => {
          this.subscriptions.delete(key);
          this.push(port, { ev: "closed", sub: key, reason });
        });
        this.subscriptions.set(key, { subscription, port });
        return key;
      }
      case "watchLease":
        this.subscriptionOf(request.sub).renew(request.leaseMillis);
        return null;
      case "unwatch":
        this.subscriptions.get(request.sub)?.subscription.close("closed");
        return null;
      case "contentPublish": {
        this.requireRunning();
        const manifest = this.requireContent().publish(request.bytes, { name: request.name, mediaType: request.mediaType,
          pieceSize: request.pieceSize ?? undefined });
        this.markDirty();
        return ResidentHost.manifestOf(manifest);
      }
      case "contentFetch": {
        const content = this.requireContent();
        const fetch = content.fetch(request.root);
        if (!fetch.done) {
          let tracked = this.contentFetches.get(request.root);
          if (tracked === undefined) {
            tracked = { fetch, ports: new Set(), lastPushed: -1 };
            this.contentFetches.set(request.root, tracked);
          }
          tracked.ports.add(port);
        }
        return this.progressOf(fetch);
      }
      case "contentRead": {
        const store = this.requireContent().store;
        return store instanceof OpfsStore ? await store.readArtifact(request.root) : store.readAll(request.root);
      }
      case "contentList":
        return this.requireContent().listManifests().map((m) => ResidentHost.manifestOf(m));
      case "contentDescribe": {
        const described = this.requireContent().describe(request.root);
        return described === null ? null : { manifest: ResidentHost.manifestOf(described["manifest"] as { [key: string]: unknown }),
          completeHolders: described["completeHolders"], partialHolders: described["partialHolders"], held: described["held"] };
      }
      default:
        throw new Error(`unknown request ${String((request as { t: unknown }).t)}`);
    }
  }

  private async hello(port: PortLike, config: HostConfig, pageId: string, active: boolean): Promise<HostState> {
    if (this.config !== null && this.config.group !== config.group) {
      throw new Error(`this host serves group ${this.config.group}, not ${config.group}`);
    }
    this.pages.set(port, { id: pageId, active, lastBeat: this.clock() });
    try {
      await this.start(config);
      if (active && this.paused) {
        await this.resume(); // the first dial's failure reaches the page that asked
      }
    } catch (e) {
      this.detach(port, "hello failed");
      throw e;
    }
    this.broadcastState();
    return this.status();
  }

  /** Drops a page: closes its subscriptions and re-judges activity (the last active page's loss pauses the host). */
  detach(port: PortLike, why: string): void {
    const page = this.pages.get(port);
    if (page === undefined) {
      return;
    }
    this.pages.delete(port);
    for (const [key, { subscription, port: owner }] of [...this.subscriptions]) {
      if (owner === port) {
        this.subscriptions.delete(key);
        subscription.close(why);
      }
    }
    port.onmessage = null;
    this.onActivity();
  }

  // ------------------------------------------------------------------ life

  /** Loads (or mints) the identity, takes the Web Lock, builds the peer, restores the snapshot; idempotent. */
  start(config: HostConfig): Promise<void> {
    if (this.starting === null) {
      this.config = config;
      this.starting = this.boot(config).catch((e) => {
        this.starting = null;
        this.config = null;
        throw e;
      });
    }
    return this.starting;
  }

  private async boot(config: HostConfig): Promise<void> {
    const database = config.database ?? databaseName(config.group);
    this.keys = new IndexedDbKeyStore(database);
    this.state = new IndexedDbKeyStore(database, STATE_STORE);
    const agentName = config.agentName ?? DEFAULT_AGENT_NAME;
    const { identity, agentKey } = await LockElection.withLock(identityLockName(config.group), async () => ({
      identity: await this.loadOrCreate(PEER_KEY, PEER_PUB),
      agentKey: await this.loadOrCreate(agentKeyName(agentName), null),
    }));
    this.identity = identity;
    this.agent = identity.renewingSubordinate(agentName, AGENT_TTL, agentKey, this.clock);
    this.lock = await LockElection.acquire(lockName(config.group, identity.peerId),
      config.lockWaitMillis === undefined ? DEFAULT_LOCK_WAIT_MILLIS : config.lockWaitMillis);
    const peer = new Peer(identity, config.group, this.clock);
    registerBrowserDialers(peer);
    peer.timers = platform({ residency: "resident", keys: this.keys }).timers;
    peer.resourceHints["js.residency"] = "resident"; // JS-R-07: what this host is, for operators; never trusted for safety
    this.peer = peer;
    if (config.content !== undefined) {
      await this.buildContent(config.content, config.group, peer);
    }
    await this.restoreSnapshot();
    this.started = true;
    this.reason = "no active page";
    this.log(`agentspaces-browser ${identity.peerId} up in ${config.group} `
      + `(${this.shared ? "shared" : "dedicated"} worker, instance ${this.instance})`);
  }

  /** `peer.key`-style bootstrap over the key store: a stored key, else a minted one saved before use. */
  private async loadOrCreate(privateName: string, publicName: string | null): Promise<Identity> {
    const keys = this.keys!;
    const pkcs8 = await keys.load(privateName);
    const pub = publicName === null ? null : await keys.load(publicName);
    if (pkcs8 !== null) {
      const identity = Identity.fromPkcs8(pkcs8);
      if (publicName !== null && (pub === null || !bytes.equals(pub, identity.publicRaw))) {
        throw new Error(`corrupt key store: ${privateName} does not belong to the public key in ${publicName}`);
      }
      return identity;
    }
    if (pub !== null) {
      throw new Error(`corrupt key store: ${publicName} exists but ${privateName} does not`);
    }
    const identity = Identity.generate();
    await keys.save(privateName, identity.pkcs8());
    if (publicName !== null) {
      await keys.save(publicName, identity.publicRaw);
    }
    return identity;
  }

  private seeds(): Seed[] {
    return (this.config?.seeds ?? []).map((text) => parseSeed(text));
  }

  /** Pauses when no attached page is active, resumes when one is (JS-R-03). */
  private onActivity(): void {
    if (!this.started) {
      return;
    }
    const active = [...this.pages.values()].some((p) => p.active);
    if (active && this.paused) {
      this.resume().catch(() => undefined); // the retry timer carries on
    } else if (!active && !this.paused) {
      this.pause("no active page");
    }
  }

  /**
   * Stops renewing and leaves: snapshots the state, stops the tick (the only renewer of claims),
   * closes every bound agent, and closes the channel with a clean WebSocket close so the hub
   * sees this member go; the identity and the local replica stay for the resume.
   */
  pause(reason: string): void {
    if (this.paused || this.peer === null) {
      return;
    }
    this.paused = true;
    this.reason = reason;
    this.pauses += 1;
    this.clearRetry();
    this.tick?.stop();
    this.tick = null;
    for (const binding of [...this.bindings.splice(0), ...this.suspended.splice(0)]) {
      void binding.bound.close();
    }
    void this.saveSnapshot();
    this.peer.close();
    this.connected = false;
    this.log(`paused: ${reason}`);
    this.broadcastState();
  }

  /** Dials the seeds again as the same peer; a failed dial is retried while a page stays active. */
  resume(): Promise<void> {
    if (!this.paused) {
      return this.resuming ?? Promise.resolve();
    }
    this.paused = false;
    this.reason = null;
    this.resumes += 1;
    const now = this.clock();
    for (const [entryId, hold] of [...this.holds]) {
      if (hold.expiresAt <= now) {
        this.holds.delete(entryId); // lapsed while paused: nothing outlives its lease
      }
    }
    this.resuming = this.dial().finally(() => { this.resuming = null; });
    return this.resuming;
  }

  private async dial(): Promise<void> {
    const peer = this.requirePeer();
    try {
      await peer.connectAny(this.seeds());
    } catch (e) {
      this.connected = false;
      this.log(`dial failed: ${e instanceof Error ? e.message : String(e)}`);
      if (!this.paused) {
        this.scheduleRetry();
      }
      this.broadcastState();
      throw e;
    }
    for (const name of this.spaces.keys()) {
      peer.pullSpace(name);
    }
    this.connected = true;
    this.startTick();
    this.log(`resumed: connected to ${peer.currentSeed()?.host ?? "?"}`);
    this.broadcastState();
    for (const listener of this.resumeListeners) {
      listener();
    }
  }

  private scheduleRetry(): void {
    this.clearRetry();
    this.retry = globalThis.setTimeout(() => {
      this.retry = null;
      if (!this.paused && this.peer !== null && !this.connected) {
        this.dial().catch(() => undefined);
      }
    }, this.reconnectIntervalMs);
  }

  private clearRetry(): void {
    if (this.retry !== null) {
      globalThis.clearTimeout(this.retry as ReturnType<typeof setTimeout>);
      this.retry = null;
    }
  }

  // ------------------------------------------------------------------ tick

  private startTick(): void {
    const peer = this.requirePeer();
    const period = this.config?.tickMillis ?? DEFAULT_TICK_MILLIS;
    this.tick?.stop();
    this.cadenceKnown = false; // a pause is not a drift: the first tick after a start sets the cadence
    this.tick = peer.every(period, () => this.onTick(period));
  }

  /**
   * One tick: lapsed members, an anti-entropy round every ten seconds, the advertisement every
   * five minutes, the sweep that judges EXPIRED and REAPPEARED, the holds, the silent pages, and
   * the periodic snapshot.
   */
  private onTick(period: number): void {
    const peer = this.requirePeer();
    const now = this.clock();
    this.observeCadence(now, period);
    this.ticks += 1;
    peer.expireMembers();
    if (this.ticks % Math.max(1, Math.round(10_000 / period)) === 0) {
      peer.antiEntropyRound();
    }
    if (this.ticks % Math.max(1, Math.round(300_000 / period)) === 0) {
      peer.introduce();
    }
    for (const space of this.spaces.values()) {
      space.sweep();
    }
    if (this.content !== null) {
      this.content.tick();
      this.pushContentProgress();
    }
    this.renewHolds(now);
    this.sweepPages(now);
    const snapshotMillis = this.config?.snapshotMillis ?? DEFAULT_SNAPSHOT_MILLIS;
    if (snapshotMillis > 0 && now - this.lastSnapshot >= snapshotMillis) {
      void this.saveSnapshot();
    }
    this.connected = peer.connected();
  }

  /**
   * JS-R-06, a pure function of the observed tick times (mirroring `ServiceHost.observeCadence`):
   * a tick later than twice the period, three times running, drops the host to visitor duties;
   * sixty seconds without a drift restores them. The first observation after a start only sets
   * the cadence, so a pause never counts as a drift.
   */
  observeCadence(now: number, period: number = this.config?.tickMillis ?? DEFAULT_TICK_MILLIS): void {
    const gap = now - this.lastTickAt;
    const known = this.cadenceKnown;
    this.lastTickAt = now;
    this.cadenceKnown = true;
    if (known && gap > DRIFT_FACTOR * period) {
      this.drifts += 1;
      this.consecutiveDrifts += 1;
      this.lastDriftAt = now;
      if (this.consecutiveDrifts >= DRIFT_TICKS && this.residency !== "visitor") {
        this.log(`tick drifted ${this.consecutiveDrifts} times (last gap ${gap} ms over a ${period} ms period): `
          + "dropping to visitor duties");
        this.setResidency("visitor");
      }
    } else {
      this.consecutiveDrifts = 0;
      if (this.residency === "visitor" && now - this.lastDriftAt >= RECOVERY_MILLIS) {
        this.log("tick cadence recovered for 60 s: resuming resident duties");
        this.setResidency("resident");
      }
    }
  }

  /**
   * Applies a residency change: the hint for the next advertisement (sent at once when the peer
   * is connected, so operators see it), the bindings closed or bound again, the holds left to
   * lapse or renewed again.
   */
  private setResidency(residency: Residency): void {
    this.residency = residency;
    const peer = this.peer;
    if (peer === null) {
      return;
    }
    peer.resourceHints["js.residency"] = residency; // JS-R-07: what this host is now; never trusted for safety
    if (residency === "visitor") {
      for (const binding of this.bindings.splice(0)) {
        this.suspended.push(binding);
        void binding.bound.close();
      }
    } else {
      for (const binding of this.suspended.splice(0)) {
        this.bindings.push({ ...binding, bound: this.binder(binding.options).bind(binding.instance) });
      }
    }
    if (peer.connected()) {
      peer.introduce();
    }
    this.broadcastState();
  }

  /**
   * Renews each keep-alive hold at half its lease while the host is resident; a visitor renews
   * nothing (JS-R-06), and a hold that lapsed or was completed is forgotten.
   */
  private renewHolds(now: number): void {
    const peer = this.requirePeer();
    for (const [entryId, hold] of [...this.holds]) {
      if (hold.expiresAt <= now) {
        this.holds.delete(entryId);
        continue;
      }
      if (!hold.keepAlive || this.residency === "visitor" || hold.expiresAt - now > hold.leaseMillis / 2) {
        continue;
      }
      try {
        peer.renewClaim(hold.space, entryId, hold.leaseMillis, this.requireAgent());
        hold.expiresAt = this.claimExpiry(entryId);
      } catch (e) {
        this.holds.delete(entryId);
        this.log(`hold on ${entryId} not renewed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }

  private sweepPages(now: number): void {
    const timeout = this.config?.pageTimeoutMillis ?? DEFAULT_PAGE_TIMEOUT_MILLIS;
    for (const [port, page] of [...this.pages]) {
      if (now - page.lastBeat > timeout) {
        this.log(`page ${page.id} fell silent for ${now - page.lastBeat} ms: dropping it`);
        this.detach(port, "silent");
        port.close?.();
      }
    }
  }

  // ------------------------------------------------------------------ state

  /** Schedules a snapshot soon after a change, so a worker killed without warning loses little. */
  private markDirty(): void {
    if (this.dirty !== null) {
      return;
    }
    this.dirty = globalThis.setTimeout(() => {
      this.dirty = null;
      void this.saveSnapshot();
    }, this.dirtySnapshotMillis);
  }

  async saveSnapshot(): Promise<void> {
    if (this.peer === null || this.state === null) {
      return;
    }
    this.lastSnapshot = this.clock();
    try {
      await this.state.save(SNAPSHOT, cbor.dumps(this.peer.exportSnapshot()));
    } catch (e) {
      this.log(`snapshot not saved: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  private async restoreSnapshot(): Promise<void> {
    const stored = await this.state!.load(SNAPSHOT);
    if (stored === null) {
      return;
    }
    try {
      this.peer!.restoreSnapshot(cbor.loads(stored) as Dict);
    } catch (e) {
      this.log(`snapshot dropped: ${e instanceof Error ? e.message : String(e)}`);
      await this.state!.remove(SNAPSHOT);
    }
  }

  status(): HostState {
    const pages = [...this.pages.values()];
    return {
      peerId: this.identity?.peerId ?? "", group: this.config?.group ?? "", shared: this.shared,
      instance: this.instance, residency: this.residency, drifts: this.drifts, paused: this.paused,
      connected: this.connected, pages: pages.length, activePages: pages.filter((p) => p.active).length, reason: this.reason,
      contentStore: this.contentStore,
    };
  }

  // ------------------------------------------------------------------ content (LB-C-06)

  /** The swarm over OPFS where this thread can write it, over memory otherwise; ticked by the host. */
  private async buildContent(config: ContentConfig, group: string, peer: Peer): Promise<void> {
    let store: capabilities.PieceStore;
    if ((config.store ?? "opfs") === "opfs") {
      try {
        store = await OpfsStore.open(config.storeName ?? `agentspaces-content:${group}`);
        this.contentStore = "opfs";
      } catch (e) {
        this.log(`content store: OPFS unavailable (${e instanceof Error ? e.message : String(e)}); holding pieces in memory`);
        store = new capabilities.MemoryStore();
        this.contentStore = "memory";
      }
    } else {
      store = new capabilities.MemoryStore();
      this.contentStore = "memory";
    }
    this.content = new capabilities.Content(new capabilities.Pipes(peer), this.space(config.space ?? "content"), store, {
      pieceSize: config.pieceSize, escalateAbove: config.escalateAbove });
    this.log(`content swarm on ${this.contentStore}, ${store.roots().size} roots held`);
  }

  private requireContent(): capabilities.Content {
    if (this.content === null) {
      throw new Error("the content swarm is off in this host; connect with a content block");
    }
    return this.content;
  }

  private progressOf(fetch: capabilities.Fetch): WireProgress {
    const p = fetch.progress();
    return { root: fetch.root, piecesVerified: p.piecesVerified, pieces: p.pieces, bytesReceived: p.bytesReceived,
      bySource: { ...p.bytesBySource }, done: fetch.done, failure: fetch.failure };
  }

  private static manifestOf(m: { [key: string]: unknown }): WireManifest {
    return { root: String(m["root"]), name: (m["name"] as string | null) ?? null, size: Number(m["size"]),
      pieces: Number(m["pieces"]), mediaType: (m["mediaType"] as string | null) ?? null };
  }

  /** On the tick: progress to the pages that asked, a final push and a forget once a fetch ends. */
  private pushContentProgress(): void {
    for (const [root, tracked] of this.contentFetches) {
      const progress = this.progressOf(tracked.fetch);
      if (!progress.done && progress.piecesVerified === tracked.lastPushed) {
        continue; // nothing new: no push
      }
      tracked.lastPushed = progress.piecesVerified;
      for (const port of tracked.ports) {
        this.push(port, { ev: "content", progress });
      }
      if (progress.done) {
        this.contentFetches.delete(root);
      }
    }
  }

  private broadcastState(): void {
    const state = this.status();
    for (const port of this.pages.keys()) {
      this.push(port, { ev: "state", state });
    }
  }

  // ------------------------------------------------------------------ spaces

  /** The host's `Space` by name, pulling it on first use. */
  space(name: string): Space {
    let space = this.spaces.get(name);
    if (space === undefined) {
      const peer = this.requirePeer();
      space = new Space(peer, name, this.agent, this.agentName());
      this.spaces.set(name, space);
      peer.pullSpace(name);
    }
    return space;
  }

  /**
   * A `Binder` over this host's peer and agent, declared with the host's current residency, for
   * agents whose code is loaded in the worker itself (a page cannot send a class across the
   * port). What `bind` returns is closed on pause (`onResume` is the moment to bind again) and
   * while the host drifts (bound again by the host itself on recovery, JS-R-06).
   */
  binder(options: Omit<BinderOptions, "agent" | "agentName" | "residency"> = {}): Binder {
    return new Binder(this.requirePeer(), { ...options, agent: this.agent, agentName: this.agentName(), residency: this.residency });
  }

  /** Binds `instance` through {@link binder}; closed on pause, suspended while drifting, bound again on recovery. */
  bind(instance: object, options: Omit<BinderOptions, "agent" | "agentName" | "residency"> = {}): Bound {
    const bound = this.binder(options).bind(instance);
    this.bindings.push({ instance, options, bound });
    return bound;
  }

  /** How many claims pages hold through this host right now. */
  holdCount(): number {
    return this.holds.size;
  }

  onResume(listener: () => void): void {
    this.resumeListeners.push(listener);
  }

  private stopping: Promise<void> | null = null;

  /** Pauses, drops every page, and releases the lock: the worker is closing; idempotent. */
  stop(): Promise<void> {
    this.stopping ??= (async () => {
      this.pause("stopping");
      for (const port of [...this.pages.keys()]) {
        this.detach(port, "stopping");
        port.close?.();
      }
      this.lock?.release();
      this.lock = null;
    })();
    return this.stopping;
  }

  // ------------------------------------------------------------------ helpers

  private agentName(): string {
    return this.config?.agentName ?? DEFAULT_AGENT_NAME;
  }

  private requirePeer(): Peer {
    if (this.peer === null) {
      throw new Error("the host has not started");
    }
    return this.peer;
  }

  private requireAgent(): AgentIdentity {
    if (this.agent === null) {
      throw new Error("the host has not started");
    }
    return this.agent;
  }

  /** The peer, for verbs that create or extend an obligation; refused while paused (JS-R-03). */
  private requireRunning(): Peer {
    const peer = this.requirePeer();
    if (this.paused) {
      throw new Error(`the host is paused (${this.reason ?? "no reason"}); nothing is written, taken, or renewed until a page is active`);
    }
    return peer;
  }

  private subscriptionOf(key: number): Subscription<unknown> {
    const entry = this.subscriptions.get(key);
    if (entry === undefined) {
      throw new Error(`no subscription ${key}`);
    }
    return entry.subscription;
  }

  /** When the claim this peer holds on `entryId` lapses, as the claim itself says; now when there is none. */
  private claimExpiry(entryId: string): number {
    const claim = this.requirePeer().claims.get(entryId)?.["claim"] as Dict | undefined;
    const expires = Number(claim?.["expiresAtMillis"]);
    return Number.isFinite(expires) ? expires : this.clock();
  }

  /** The record's own payload and tag bytes, so the page decodes exactly what was signed. */
  private wireEntry(entryId: string, expiresAtMillis: number, completed: boolean, taken: boolean): WireEntry {
    const dto = this.requirePeer().states.get(entryId);
    const record = (dto?.["record"] as Dict | undefined) ?? {};
    const payload = record["payload"];
    return {
      entryId,
      payload: payload instanceof Uint8Array ? new Uint8Array(payload) : new Uint8Array([0xf6]),
      tags: packMap((record["tags"] as Dict | undefined) ?? {}),
      issuer: String(record["issuer"] ?? ""),
      expiresAtMillis, completed, taken,
    };
  }
}
