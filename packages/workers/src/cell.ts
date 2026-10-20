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
 * The cell host (srad/agentspaces-js.md §3.8, JS-R-03, JS-R-05, JS-R-07):
 * a Durable Object carrying one core `Peer`. Its identity and its state
 * snapshot live in the object's SQLite storage and come back on every
 * construction, so an evicted or moved cell resumes as the same member; the
 * durable tick is the alarm (reconnect while disconnected, the card
 * refresh, the snapshot, and the next alarm), while an in-memory
 * housekeeping timer runs the per-second duties for as long as the object
 * is live; the one connection is outbound, `wss` to the configured seeds
 * (`ws` under the `dev-local` profile), re-dialed once at once when the
 * socket closes and on each alarm while down. The self-advertisement
 * carries `js.residency=cell`. On eviction nothing runs: every claim and
 * lease the cell held lapses on its own clock, and the next alarm brings
 * the same identity back (the pause rule). Only the public Durable Objects
 * API is used, so one bundle runs on celld, workerd, and Cloudflare.
 *
 * `AgentSpacesConnectorCell` runs the connector runtime over the Workers
 * asset provider; `AgentSpacesCell` binds decorated agents as a member in
 * its own name. Both expose the RPC verbs `fleet()` drives.
 */

import { DurableObject } from "cloudflare:workers";
import { Binder, Peer, Space, Taken, Template, WsDialer, cbor, durationMillis, eq, instantIso, parseDurationMillis,
  social } from "@agentspaces/client";
import type { BinderOptions, Bound, Dialer, Entry, FrameChannel, Seed, WebSocketLike, wire } from "@agentspaces/client";
import { ConnectorRuntime } from "@agentspaces/connect";
import type { ConnectorOptions } from "@agentspaces/connect";
import { CellConfig, DEFAULT_IDLE_MILLIS, cellConfig } from "./config.js";
import { SqliteKeyStore, blobOf, bytesOf, loadOrCreateIdentity } from "./keystore.js";
import { AssetManifest, cardTtl } from "./manifest.js";
import { OnceOptions, once } from "./once.js";
import { WorkersAssetProvider, WorkersProviderOptions } from "./providers.js";
import type { CellEnv, CellStateLike, SqlStorageLike, SqlValue } from "./workers-types.js";

type Dict = wire.Dict;

/** The table the peer's state snapshot lives in, in chunks under `state:<n>`. */
export const STATE_TABLE = "aspace_state";
/** One snapshot chunk; a row holds well under the storage's per-value size. */
export const SNAPSHOT_CHUNK_BYTES = 1024 * 1024;
/** The residency hint every cell advertises (JS-R-07). */
export const RESIDENCY_HINT = "js.residency";

/** What `/status` and `cellStatus()` report. */
export type CellStatus = {
  peerId: string;
  group: string;
  name: string;
  residency: "cell";
  connected: boolean;
  paused: boolean;
  seed: string | null;
  ticks: number;
  alarms: number;
  dials: number;
  reconnects: number;
  members: number;
  entries: number;
  assets: string[];
};

/** An entry as the RPC verbs return it: the record's fields with the payload as a dictionary. */
export type CellEntry = { entryId: string; value: Dict; issuer: string; expiresAtMillis: number; tags: Dict; taken: boolean };

/** Equality conditions a `fleet()` caller sends: field to literal. */
export type Where = { [field: string]: string | number | boolean | null };

function whereTemplate(schema: string, where: Where): Template<Dict> {
  const conditions: { [field: string]: unknown } = {};
  for (const [field, value] of Object.entries(where)) {
    conditions[field] = eq(value);
  }
  return new Template<Dict>(schema, conditions);
}

/** A dialer wrapper that reports whether a dial is in flight, so the alarm never starts a second one. */
class TrackedDialer implements Dialer {
  readonly scheme: string;
  constructor(private readonly inner: Dialer, private readonly track: (dialing: boolean) => void) {
    this.scheme = inner.scheme;
  }

  expand(seed: Seed, resolve: boolean): Promise<Seed[]> {
    return this.inner.expand === undefined ? Promise.resolve([seed]) : this.inner.expand(seed, resolve);
  }

  async dial(seed: Seed): Promise<FrameChannel> {
    this.track(true);
    try {
      return await this.inner.dial(seed);
    } finally {
      this.track(false);
    }
  }
}

export abstract class CellHost<Env extends CellEnv = CellEnv> extends DurableObject<Env> {
  readonly config: CellConfig;
  readonly keys: SqliteKeyStore;
  /** The core peer; constructed in `boot`, before any request or alarm runs. */
  peer!: Peer;
  /** Resolves once the identity and the snapshot are back; every entry point awaits it. */
  protected readonly ready: Promise<void>;
  ticks = 0;
  alarms = 0;
  dials = 0;
  private dialing = false;
  private paused = false;
  private started = false;
  private lastBusyAt = 0;
  private lastSnapshotAt = 0;
  private lastIntroduceAt = 0;
  private housekeeping: { stop(): void } | null = null;
  private readonly spaces = new Map<string, Space>();
  private readonly pulled = new Set<string>();
  private readonly takes = new Map<string, Taken<Dict>>();

  constructor(ctx: CellStateLike, env: Env) {
    // The state as the runtime types it; `CellStateLike` is the slice this package touches.
    super(ctx as ConstructorParameters<typeof DurableObject>[0], env);
    this.config = this.configure(env);
    const sql = this.sql;
    sql.exec(`CREATE TABLE IF NOT EXISTS ${STATE_TABLE} (k TEXT PRIMARY KEY, v BLOB NOT NULL)`);
    this.keys = new SqliteKeyStore(sql);
    this.ready = ctx.blockConcurrencyWhile(() => this.boot());
  }

  /** The configuration; the default reads the `vars` and names the cell after the object. */
  protected configure(env: Env): CellConfig {
    return cellConfig(env, { name: this.ctx.id.name ?? "connector" });
  }

  /** The object's SQLite storage. */
  protected get sql(): SqlStorageLike {
    return this.ctx.storage.sql;
  }

  // ----------------------------------------------------------------- boot

  /** Identity from SQLite (minted on first construction), the peer with its hints, the snapshot restored. */
  private async boot(): Promise<void> {
    const identity = await loadOrCreateIdentity(this.keys);
    this.peer = new Peer(identity, this.config.group);
    this.peer.resourceHints[RESIDENCY_HINT] = "cell";
    if (this.config.invite !== null) {
      this.peer.resourceHints[social.JOIN_HINT] = this.joinCredential(this.config.invite, identity.peerId);
    }
    // The core redials once at once when the socket closes; the alarm owns every later dial.
    this.peer.reconnectWindowMs = 0;
    for (const scheme of ["ws", "wss"] as const) {
      const inner = this.peer.dialers.get(scheme) ?? new WsDialer(scheme, (url, protocols) =>
        new (globalThis as unknown as { WebSocket: new (u: string, p: string[]) => WebSocketLike }).WebSocket(url, protocols));
      this.peer.registerDialer(new TrackedDialer(inner, (dialing) => { this.dialing = dialing; }));
    }
    this.restore();
    await this.onBoot();
  }

  /**
   * The join credential of JS-R-05's `AGENTSPACES_INVITE`: an invite key
   * carrying a delegation is turned into this peer's delegated credential;
   * anything else is carried as given (a credential issued elsewhere).
   */
  private joinCredential(invite: string, peerId: string): string {
    try {
      const key = social.InviteKey.parse(invite);
      if (key.delegation !== null) {
        return social.issueDelegated(key.delegation, key.secret.inviteSeed(), peerId);
      }
    } catch {
      // not an invite key: a credential as issued
    }
    return invite;
  }

  /** A hook after the identity and snapshot are back, before any connection. */
  protected onBoot(): Promise<void> | void {
    return undefined;
  }

  /** Called after each successful dial; `first` on the first of this object's life. */
  protected abstract onConnected(first: boolean): Promise<void> | void;

  /** Called when the cell pauses (`/pause`): stop what renews leases. */
  protected onSuspended(): Promise<void> | void {
    return undefined;
  }

  /** Whether the next alarm should come at the busy cadence; the default is the busy window after `markBusy`. */
  protected busy(): boolean {
    return this.peer.now() - this.lastBusyAt < this.config.busyWindowMillis;
  }

  /** Marks the cell busy: the alarm runs at `tickMillis` for the busy window. */
  protected markBusy(): void {
    this.lastBusyAt = this.peer.now();
  }

  /** The idle alarm cadence; a connector overrides it with the card refresh interval. */
  protected idleMillis(): number {
    return this.config.idleMillis ?? DEFAULT_IDLE_MILLIS;
  }

  protected log(line: string): void {
    this.config.log?.(`cell ${this.config.name}: ${line}`);
  }

  // ---------------------------------------------------------- entry points

  /**
   * Activation and health: `/wake` connects (if not yet) and arms the
   * alarm, `/status` reports, `/pause` closes the connection and stops
   * renewing anything until the next `/wake`.
   */
  async fetch(request: Request): Promise<Response> {
    await this.ready;
    const path = new URL(request.url).pathname;
    try {
      if (path === "/wake") {
        await this.wake();
      } else if (path === "/pause") {
        await this.suspend();
      } else if (path !== "/status" && path !== "/") {
        return new Response(JSON.stringify({ error: `no route ${path}; the cell answers /wake, /status, /pause` }),
          { status: 404, headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify(this.status()), { headers: { "content-type": "application/json" } });
    } catch (e) {
      return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }),
        { status: 500, headers: { "content-type": "application/json" } });
    }
  }

  /** The durable tick: reconnect while down, the subclass's duties, the snapshot, the next alarm. */
  async alarm(): Promise<void> {
    await this.ready;
    this.alarms += 1;
    if (this.paused) {
      return;
    }
    try {
      await this.tick();
    } catch (e) {
      this.log(`alarm failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    await this.scheduleAlarm();
  }

  /** A socket handed to the hibernation API closed: reconnect on the next alarm, soon. */
  async webSocketClose(_ws: unknown, code: number): Promise<void> {
    await this.ready;
    this.log(`socket closed (${code}); reconnecting on the next alarm`);
    await this.scheduleAlarm(this.config.reconnectMillis);
  }

  /** Connects if needed and arms the alarm; idempotent. */
  async wake(): Promise<CellStatus> {
    await this.ready;
    this.paused = false;
    await this.ensureConnected();
    await this.scheduleAlarm();
    return this.status();
  }

  /** The pause rule (JS-R-03): the channel closes, nothing renews; the identity resumes on `wake`. */
  async suspend(): Promise<void> {
    await this.ready;
    this.paused = true;
    await this.onSuspended();
    this.housekeeping?.stop();
    this.housekeeping = null;
    this.takes.clear();
    this.persist();
    this.peer.close();
    await this.ctx.storage.deleteAlarm();
    this.log("paused");
  }

  status(): CellStatus {
    const seed = this.peer.currentSeed();
    return { peerId: this.peer.identity.peerId, group: this.peer.group, name: this.config.name, residency: "cell",
      connected: this.peer.connected(), paused: this.paused,
      seed: seed === null ? null : `${seed.scheme ?? "tcp"}://${seed.host}:${seed.port}${seed.path ?? ""}`,
      ticks: this.ticks, alarms: this.alarms, dials: this.dials, reconnects: this.peer.reconnects,
      members: this.peer.linkedMembers().length, entries: this.peer.states.size, assets: this.assets() };
  }

  /** The assets this cell publishes, for the status; a connector overrides it. */
  protected assets(): string[] {
    return [];
  }

  // ----------------------------------------------------------------- tick

  private async tick(): Promise<void> {
    this.ticks += 1;
    if (!this.peer.connected()) {
      await this.ensureConnected();
    }
    if (this.peer.connected()) {
      const now = this.peer.now();
      if (now - this.lastIntroduceAt >= this.config.introduceMillis) {
        this.peer.introduce();
        this.lastIntroduceAt = now;
      }
      await this.onTick();
    }
    if (this.peer.now() - this.lastSnapshotAt >= this.config.snapshotMillis) {
      this.persist();
    }
  }

  /** The subclass's alarm duties while connected (a connector refreshes its cards). */
  protected onTick(): Promise<void> | void {
    return undefined;
  }

  /** Arms the alarm: the reconnect cadence while down, the busy cadence while busy, the idle one otherwise. */
  protected async scheduleAlarm(delayMillis: number | null = null): Promise<void> {
    if (this.paused) {
      return;
    }
    const delay = delayMillis ?? (!this.peer.connected() ? this.config.reconnectMillis
      : this.busy() ? this.config.tickMillis : this.idleMillis());
    await this.ctx.storage.setAlarm(Date.now() + Math.max(1, delay));
  }

  /** Dials the seeds unless connected or a dial is in flight; true when connected afterwards. */
  protected async ensureConnected(): Promise<boolean> {
    if (this.peer.connected()) {
      return true;
    }
    if (this.dialing) {
      return false;
    }
    try {
      await this.peer.connectAny(this.config.seeds);
      this.dials += 1;
      this.lastIntroduceAt = this.peer.now();
      this.log(`connected to ${this.status().seed} as ${this.peer.identity.peerId}`);
      await this.afterConnect();
      return true;
    } catch (e) {
      this.log(`dial failed: ${e instanceof Error ? e.message : String(e)}`);
      return false;
    }
  }

  private async afterConnect(): Promise<void> {
    this.peer.pullAds();
    for (const space of this.pulled) {
      this.peer.pullSpace(space);
    }
    if (this.housekeeping === null) {
      // Per-second duties while the object is live: lapsed members, an anti-entropy round every
      // ten ticks (ServiceHost's cadence). The durable duties stay on the alarm.
      let n = 0;
      this.housekeeping = this.peer.every(this.config.housekeepingMillis, () => {
        n += 1;
        this.peer.expireMembers();
        if (n % 10 === 0 && this.peer.connected()) {
          this.peer.antiEntropyRound();
        }
      });
    }
    const first = !this.started;
    this.started = true;
    await this.onConnected(first);
  }

  // ------------------------------------------------------------- snapshot

  /** Writes the peer's state snapshot (signed public material only) to SQLite in chunks. */
  persist(): void {
    const bytes = cbor.dumps(this.peer.exportSnapshot());
    const sql = this.sql;
    sql.exec(`DELETE FROM ${STATE_TABLE} WHERE k LIKE 'state:%'`);
    let n = 0;
    for (let offset = 0; offset < bytes.length; offset += SNAPSHOT_CHUNK_BYTES) {
      sql.exec(`INSERT INTO ${STATE_TABLE} (k, v) VALUES (?, ?)`, `state:${String(n).padStart(6, "0")}`,
        blobOf(bytes.subarray(offset, Math.min(bytes.length, offset + SNAPSHOT_CHUNK_BYTES))));
      n += 1;
    }
    this.lastSnapshotAt = this.peer.now();
  }

  /** Restores the snapshot the last persist wrote; every entry is re-verified by the core. */
  private restore(): void {
    const rows = this.sql.exec<{ v: SqlValue }>(`SELECT v FROM ${STATE_TABLE} WHERE k LIKE 'state:%' ORDER BY k`).toArray();
    if (rows.length === 0) {
      return;
    }
    const parts = rows.map((r) => bytesOf(r.v) ?? new Uint8Array());
    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const all = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      all.set(part, offset);
      offset += part.length;
    }
    try {
      this.peer.restoreSnapshot(cbor.loads(all) as Dict);
    } catch (e) {
      this.log(`snapshot not restored: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // --------------------------------------------------------------- spaces

  /** A space handle in this cell's name, pulled on every connection. */
  space(name: string): Space {
    let space = this.spaces.get(name);
    if (space === undefined) {
      space = new Space(this.peer, name, null, this.config.name);
      this.spaces.set(name, space);
    }
    this.pull(name);
    return space;
  }

  /** Registers a space to pull now and after every reconnect. */
  pull(name: string): void {
    if (!this.pulled.has(name)) {
      this.pulled.add(name);
      if (this.peer.connected()) {
        this.peer.pullSpace(name);
      }
    }
  }

  /** `once` over this cell's own storage (JS-C-04). */
  once<T>(invocationId: string, fn: () => T | Promise<T>, options: OnceOptions = {}): Promise<T> {
    return once(this.sql, invocationId, fn, options);
  }

  // --------------------------------------------------------- RPC verbs

  async cellStatus(): Promise<CellStatus> {
    await this.ready;
    return this.status();
  }

  /** Writes one entry of `schema` with `payload`; returns its id (`fleet().space().write`). */
  async cellWrite(space: string, schema: string, payload: Dict, leaseMillis: number, tags: Dict = {}): Promise<string> {
    await this.wake();
    this.markBusy();
    return this.peer.writeEntry(space, schema, payload, this.config.name, leaseMillis, null, tags);
  }

  /** The live entries of `schema` matching `where` (`fleet().space().entries`). */
  async cellEntries(space: string, schema: string, where: Where = {}, limit = 100, includeTaken = true): Promise<CellEntry[]> {
    await this.wake();
    return this.space(space).entries(whereTemplate(schema, where), limit, includeTaken)
      .map((e: Entry<Dict>) => ({ entryId: e.entryId, value: e.value, issuer: e.issuer, expiresAtMillis: e.expiresAtMillis,
        tags: e.tags, taken: e.taken }));
  }

  /** Takes one matching entry under a lease; the take is held here until `cellComplete` or its lease lapses. */
  async cellTake(space: string, schema: string, where: Where, leaseMillis: number, timeoutMillis: number):
      Promise<{ entryId: string; value: Dict } | null> {
    await this.wake();
    this.markBusy();
    const taken = await this.space(space).take(whereTemplate(schema, where), leaseMillis, timeoutMillis);
    if (taken === null) {
      return null;
    }
    this.takes.set(taken.entryId, taken);
    return { entryId: taken.entryId, value: taken.value };
  }

  /** Completes a take this object holds, writing `result` first when given; null when the take is not held. */
  async cellComplete(space: string, entryId: string, resultSchema: string | null = null, result: Dict | null = null,
                     resultLeaseMillis = 3_600_000): Promise<{ held: boolean; resultId: string | null }> {
    await this.wake();
    const taken = this.takes.get(entryId);
    if (taken === undefined) {
      return { held: false, resultId: null };
    }
    this.takes.delete(entryId);
    let resultId: string | null = null;
    if (resultSchema !== null && result !== null) {
      resultId = this.peer.writeEntry(space, resultSchema, result, this.config.name, resultLeaseMillis, null, {});
    }
    this.peer.completeEntry(space, entryId, null);
    return { held: true, resultId };
  }

  /** Renews a take this object holds. */
  async cellRenew(space: string, entryId: string, leaseMillis: number): Promise<boolean> {
    await this.wake();
    const taken = this.takes.get(entryId);
    if (taken === undefined) {
      return false;
    }
    taken.renew(leaseMillis);
    return true;
  }
}

// ------------------------------------------------------------ connector cell

/**
 * The connector cell (JS-C-05): the connector runtime over the Workers
 * asset provider, joined as a non-agent member that publishes no AgentCard,
 * one per deployment under the name `connector` by default. The manifest
 * is the allowlist (JS-C-06, JS-C-07); the cards are appendix F's
 * (JS-C-08). The alarm refreshes the cards at half their TTL while idle and
 * runs at the busy cadence while a query or an invocation was served
 * within the busy window.
 */
export abstract class AgentSpacesConnectorCell<Env extends CellEnv = CellEnv> extends CellHost<Env> {
  provider: WorkersAssetProvider | null = null;
  runtime: ConnectorRuntime | null = null;
  private lastServed = { executed: 0, invoked: 0, refused: 0 };

  /** What to publish and which operations to allow (appendix F). */
  protected abstract manifest(env: Env): AssetManifest;

  /** Options for the provider (a `fetch` for routes, the inline limit, the list page size). */
  protected providerOptions(_env: Env): WorkersProviderOptions {
    return {};
  }

  /** Options for the runtime beyond the spaces and the name: an authorizer, leases, the retention. */
  protected connectorOptions(_env: Env): Partial<ConnectorOptions> {
    return {};
  }

  protected override assets(): string[] {
    return this.runtime?.assets() ?? [];
  }

  protected override idleMillis(): number {
    if (this.config.idleMillis !== null) {
      return this.config.idleMillis;
    }
    const manifest = this.provider?.manifest;
    if (manifest === undefined) {
      return DEFAULT_IDLE_MILLIS;
    }
    return Math.max(1, Math.floor(parseDurationMillis(cardTtl(manifest)) / 2));
  }

  protected override busy(): boolean {
    const runtime = this.runtime;
    if (runtime !== null) {
      const moved = runtime.executed !== this.lastServed.executed || runtime.invoked !== this.lastServed.invoked
        || runtime.refused !== this.lastServed.refused;
      if (moved) {
        this.lastServed = { executed: runtime.executed, invoked: runtime.invoked, refused: runtime.refused };
        this.markBusy();
      }
    }
    return super.busy();
  }

  protected override async onConnected(_first: boolean): Promise<void> {
    if (this.provider === null) {
      this.provider = new WorkersAssetProvider(this.env, this.manifest(this.env), this.providerOptions(this.env));
    }
    await this.provider.refresh();
    if (this.runtime === null) {
      this.runtime = new ConnectorRuntime(this.peer, this.provider, {
        connectorName: this.config.name, dataSpace: this.config.dataSpace, taskSpace: this.config.taskSpace,
        changeSpace: this.config.changeSpace, pollTimeout: this.config.tickMillis,
        log: (line) => this.log(line), ...this.connectorOptions(this.env) });
      for (const space of new Set([this.config.dataSpace, this.config.taskSpace, this.config.changeSpace])) {
        this.pull(space);
      }
      this.runtime.start();
      this.log(`publishing ${this.runtime.assets().join(", ") || "no assets"}`);
    } else {
      this.runtime.refreshCards();
    }
  }

  protected override async onTick(): Promise<void> {
    if (this.provider !== null && this.runtime !== null) {
      await this.provider.refresh();
      this.runtime.refreshCards();
    }
  }

  protected override async onSuspended(): Promise<void> {
    if (this.runtime !== null) {
      await this.runtime.close();
      this.runtime = null;
    }
  }
}

// ---------------------------------------------------------------- agent cell

/**
 * An agent cell (JS-S-05): decorated agents bound on the cell host as a
 * member with its own identity, for a Durable Object that takes work or
 * votes in its own name. The AgentCards are re-published at half their TTL
 * on the alarm.
 */
export abstract class AgentSpacesCell<Env extends CellEnv = CellEnv> extends CellHost<Env> {
  binder: Binder | null = null;
  readonly bound: Bound[] = [];
  private cardsPublishedAt = 0;

  /** The agent instances to bind. */
  protected abstract agents(env: Env): object[];

  /** Options for the binder beyond the residency and the name (an attested agent identity, a vote space). */
  protected binderOptions(_env: Env): Partial<BinderOptions> {
    return {};
  }

  protected override assets(): string[] {
    return this.bound.map((b) => b.name);
  }

  protected override async onConnected(_first: boolean): Promise<void> {
    if (this.binder === null) {
      this.binder = new Binder(this.peer, { residency: "cell", agentName: this.config.name, ...this.binderOptions(this.env) });
      for (const instance of this.agents(this.env)) {
        this.bound.push(this.binder.bind(instance));
      }
      this.cardsPublishedAt = this.peer.now();
      this.log(`bound ${this.bound.map((b) => b.name).join(", ") || "no agents"}`);
    } else {
      this.republishCards();
    }
  }

  protected override busy(): boolean {
    return true; // an agent's take loops are live work: the busy cadence while bound
  }

  protected override onTick(): void {
    if (this.binder !== null && this.peer.now() - this.cardsPublishedAt >= durationMillis(this.binder.cardTtl) / 2) {
      this.republishCards();
    }
  }

  private republishCards(): void {
    for (const bound of this.bound) {
      if (bound.card !== null) {
        const now = this.peer.now();
        const fresh: Dict = { ...bound.card, issued: instantIso(now - (now % 1000)) };
        bound.card = fresh;
        this.peer.publishAd("AgentCard", fresh);
      }
    }
    this.cardsPublishedAt = this.peer.now();
  }

  protected override async onSuspended(): Promise<void> {
    await Promise.allSettled(this.bound.splice(0).map((b) => b.close()));
    this.binder = null;
  }
}
