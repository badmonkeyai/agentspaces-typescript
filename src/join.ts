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
 * The fan-in's runtime (srad/agentspaces-js.md JS-V-08; SPEC §10.3, issue
 * #16), the TypeScript shape of the Java `JoinBinding`, `KeyTickets`, and
 * `JoinTicket`: a subscription per part, the per-key state of which parts
 * have arrived, the seed of that state from the space on start and again for
 * any key met for the first time, the re-read of the parts by key when a key
 * completes, and the "once" rule of the mode. LOCAL keeps an in-memory set;
 * LEASED writes a `JoinTicket` per key and takes it under a lease; ORDERED
 * takes the ticket through the ordered log's Raft client, where the first
 * committed ticket claim per key is the one that fires.
 *
 * A ticket is an ordinary entry of the reserved type
 * `ai.badmonkey.agentspaces.agent.join.JoinTicket#v1`, tagged with the join's
 * name and the key, so a joiner's take template selects its own tickets
 * without decoding the rest; a peer that knows no joins replicates it as any
 * foreign type. The reduce binding serializes on the same tickets.
 */

import type { OrderedLog } from "./capabilities/ordered.js";
import { loads } from "./cbor.js";
import type { Peer } from "./peer.js";
import { Entry, EntryType, REAPPEARED, Space, SpaceEvent, Taken, Template, WRITTEN, entry, schemaOf,
  toPayload } from "./space.js";
import { compareHlc } from "./wire.js";
import type { Dict } from "./wire.js";

// --------------------------------------------------------------- the ticket

/** The wire name of the reserved ticket type (JoinTicket.java). */
export const JOIN_TICKET_TYPE = "ai.badmonkey.agentspaces.agent.join.JoinTicket#v1";
/** The tag carrying the join's (or reduce's) name. */
export const JOIN_TAG = "join";
/** The tag carrying the key. */
export const KEY_TAG = "key";

/**
 * The entry a fleet-wide join or a reduce writes when a key needs serving and
 * takes before it fires: the join's name (`<agent>.<method>` by default) and
 * the case's key, in Java record order.
 */
@entry(JOIN_TICKET_TYPE)
export class JoinTicket {
  constructor(public join = "", public key = "") {}
}

/** How long a committed claim may wait for its record before it is dropped as unresolvable (real time). */
const PENDING_CLAIM_MAX_AGE_MILLIS = 30_000;
const READ_LIMIT = 256;

/** A sleep on the peer's timers, so a fake clock drives it (JS-P-10). */
export function pause(peer: Peer, millis: number): Promise<void> {
  return new Promise((resolve) => peer.timers.setTimeout(resolve, millis));
}

/** The HLC stamp an entry was issued at, as its record carries it; the empty stamp when unknown. */
export function issuedOf(peer: Peer, entryId: string): string {
  const record = peer.states.get(entryId)?.["record"] as Dict | undefined;
  return typeof record?.["issued"] === "string" ? record["issued"] : "";
}

/** A `Taken` over an entry this peer's claim was just decided for, as `Space.take` builds one. */
export function takenOf<T>(space: Space, entryId: string, template: Template<T>, leaseMillis: number): Taken<T> {
  const record = space.peer.states.get(entryId)!["record"] as Dict;
  const payload = loads((record["payload"] as Uint8Array) ?? new Uint8Array([0xf6])) as Dict;
  return new Taken(space, entryId, template.decode(payload), leaseMillis);
}

/**
 * One take under a mode: the space's own claim race, or the ordered log's
 * Raft client (OrderedTakes.take) when a log is given. The caller completes
 * the entry as after any take.
 */
export async function takeThrough<T>(space: Space, ordered: OrderedLog | null, template: Template<T>,
                                     leaseMillis: number, timeoutMillis: number): Promise<Taken<T> | null> {
  if (ordered === null) {
    return space.take(template, leaseMillis, timeoutMillis);
  }
  const entryId = await ordered.take(space.name, template.schema, space.agentName, leaseMillis, timeoutMillis,
    space.agent, (payload, tags) => template.matches(payload, tags));
  return entryId === null ? null : takenOf(space, entryId, template, leaseMillis);
}

/** A map that forgets its eldest entry beyond `max` (KeyTickets.boundedMap). */
export class BoundedMap<V> extends Map<string, V> {
  constructor(private readonly max: number) {
    super();
  }

  override set(key: string, value: V): this {
    super.set(key, value);
    while (this.size > this.max) {
      this.delete(this.keys().next().value!);
    }
    return this;
  }
}

/** A set that forgets its eldest member beyond `max`. */
export class BoundedSet extends Set<string> {
  constructor(private readonly max: number) {
    super();
  }

  override add(value: string): this {
    super.add(value);
    while (this.size > this.max) {
      this.delete(this.keys().next().value!);
    }
    return this;
  }
}

// ------------------------------------------------------------- key tickets

/**
 * The per-key ticket a fan-in or a fold serializes on (KeyTickets in Java),
 * shared by `JoinBinding` and `ReduceBinding`. A ticket is written when a key
 * needs serving, once per writer per ticket lease, and the younger of two
 * tickets written in the same instant is withdrawn, so a duplicate needs a
 * partition and never just a race. Under ORDERED the log's committed claims
 * decide which ticket is the key's first: a participant on the Raft client
 * sees them as the claim deltas gossip delivers, resolves each to its key
 * once the ticket's record is here, and judges them in claim-stamp order,
 * waiting for a claim whose record has not replicated yet so that no key is
 * decided over a ticket this member cannot read.
 */
/**
 * Where committed ticket claims come from in log order: an ordered-log host's `onCommitted`
 * (`OrderedLogHost` in `@agentspaces/ordered`); returns the unsubscribe.
 */
export type CommittedSource = (listener: (entryId: string, claim: Dict) => void) => () => void;

export class KeyTickets {
  private readonly ticketTemplate: Template<JoinTicket>;
  /** When this writer last wrote a ticket for the key. */
  private readonly requested: BoundedMap<number>;
  /** ORDERED: the ticket whose claim committed first for the key. */
  private readonly firstCommitted: BoundedMap<string>;
  /** ORDERED: every committed ticket claim per key, in commit order (the reduce's lock rule). */
  private readonly committed: BoundedMap<string[]>;
  /** ORDERED: committed claims whose record had not replicated here yet. */
  private pendingClaims: Array<{ entryId: string; stamp: string; sinceMillis: number }> = [];
  private readonly resolvedClaims = new BoundedSet(READ_LIMIT * 16);
  private active = false;

  /**
   * @param name             the join's or reduce's name, which the tickets carry
   * @param space            the space the tickets live in
   * @param ticketLeaseMillis the ticket's write lease
   * @param takeLeaseMillis  the ticket's take lease; half of it bounds the ORDERED wait
   * @param ordered          the ordered log's client, or null outside ORDERED
   * @param maxOpen          the bound on remembered keys
   */
  constructor(readonly name: string, readonly space: Space, readonly ticketLeaseMillis: number,
              readonly takeLeaseMillis: number, readonly ordered: OrderedLog | null, maxOpen: number,
              private readonly committedSource: CommittedSource | null = null) {
    this.ticketTemplate = new Template(JoinTicket, {}, { [JOIN_TAG]: name });
    this.requested = new BoundedMap(maxOpen);
    this.firstCommitted = new BoundedMap(maxOpen);
    this.committed = new BoundedMap(maxOpen);
  }

  /** Every ticket of this name. */
  template(): Template<JoinTicket> {
    return this.ticketTemplate;
  }

  /** The tickets of one key. */
  templateFor(key: string): Template<JoinTicket> {
    return new Template(JoinTicket, {}, { [JOIN_TAG]: this.name, [KEY_TAG]: key });
  }

  /** The tags a ticket of this name carries for a key. */
  tags(key: string): Dict {
    return { [JOIN_TAG]: this.name, [KEY_TAG]: key };
  }

  /**
   * ORDERED: starts following the claims the log commits. On a voter host the coordinator's
   * own apply hook (`OrderedLogHost.onCommitted`, the Java `KeyTickets` source) delivers them in
   * log order; a client participant hears them as the space folds the committed claims, which
   * with one ticket per key (what the ticket discipline produces) decides identically.
   */
  start(): void {
    this.active = true;
    if (this.ordered === null) {
      return;
    }
    if (this.committedSource !== null) {
      this.unsubscribe = this.committedSource((entryId, claim) => {
        if (this.active) {
          this.onCommittedClaim(entryId, { claim });
        }
      });
      return;
    }
    const peer = this.space.peer;
    const previous = peer.onClaim;
    peer.onClaim = (entryId, signed) => {
      previous?.(entryId, signed);
      if (this.active) {
        this.onCommittedClaim(entryId, signed);
      }
    };
  }

  private unsubscribe: (() => void) | null = null;

  close(): void {
    this.active = false;
    this.unsubscribe?.();
    this.unsubscribe = null;
  }

  /**
   * Writes a ticket for the key unless this writer wrote one within the
   * ticket lease or another writer's ticket (held or not) is already visible;
   * withdraws its own when an older one exists.
   *
   * @return whether a ticket for the key is live here afterwards, as far as this writer can see
   */
  request(key: string): boolean {
    const now = this.space.peer.now();
    const last = this.requested.get(key);
    if (last !== undefined && now - last < this.ticketLeaseMillis) {
      return true; // this writer already asked; its ticket is live or being served
    }
    this.requested.set(key, now);
    try {
      if (this.space.entries(this.templateFor(key), 1, true).length > 0) {
        return true; // another writer asked first and its ticket replicated here
      }
      const mine = this.space.write(new JoinTicket(this.name, key), this.ticketLeaseMillis, this.tags(key));
      // Two writers that saw the key at the same moment both wrote a ticket
      // before either could see the other's. The later one withdraws: the
      // oldest ticket by issue stamp stands, so a duplicate needs a
      // partition, never just a race.
      let oldest: string | null = null;
      for (const ticket of this.space.entries(this.templateFor(key), READ_LIMIT, true)) {
        if (oldest === null || compareHlc(issuedOf(this.space.peer, ticket.entryId), issuedOf(this.space.peer, oldest)) < 0) {
          oldest = ticket.entryId;
        }
      }
      if (oldest !== null && oldest !== mine) {
        void this.withdraw(mine);
      }
      return true;
    } catch {
      this.requested.delete(key);
      return false;
    }
  }

  /** Withdraws a duplicate ticket this writer wrote: an exact take of its own entry and a bare completion. */
  private async withdraw(entryId: string): Promise<void> {
    const peer = this.space.peer;
    try {
      const held = await peer.takeEntry(this.space.name, JOIN_TICKET_TYPE, this.space.agentName,
        this.takeLeaseMillis, 0, Math.max(100, this.takeLeaseMillis), this.space.agent, entryId);
      if (held !== null) {
        peer.completeEntry(this.space.name, held, this.space.agent);
      }
    } catch {
      // the duplicate stays; a later taker completes it without firing
    }
  }

  /** Forgets that this writer asked for the key, so the next request writes again. */
  forget(key: string): void {
    this.requested.delete(key);
  }

  /** ORDERED: the first committed ticket for the key, if the log has decided it here. */
  decided(key: string): string | null {
    this.resolvePendingClaims();
    return this.firstCommitted.get(key) ?? null;
  }

  /**
   * ORDERED: the entry id of the first committed ticket for the key, waiting
   * up to half the take lease for the committed claims before it to resolve;
   * null when still undecided, which the caller treats as "release and retry".
   */
  async awaitFirstCommitted(key: string): Promise<string | null> {
    const deadline = Date.now() + Math.max(1000, this.takeLeaseMillis / 2);
    for (;;) {
      const firing = this.decided(key);
      if (firing !== null) {
        return firing;
      }
      if (Date.now() >= deadline || !this.active) {
        return null;
      }
      await pause(this.space.peer, 20);
    }
  }

  /**
   * ORDERED: the earliest committed ticket for the key that is still live
   * (claimed or not, but not completed or lapsed), which is the one lock a
   * reduce drains under.
   */
  earliestLive(key: string): string | null {
    this.resolvePendingClaims();
    const order = this.committed.get(key);
    if (order === undefined) {
      return null;
    }
    const peer = this.space.peer;
    while (order.length > 0) {
      const id = order[0]!;
      const state = peer.states.get(id);
      const lease = ((state?.["leaseValue"] ?? (state?.["record"] as Dict | undefined)?.["lease"]) as Dict | undefined);
      if (state !== undefined && !state["completed"] && Number(lease?.["expiresAtMillis"] ?? 0) > peer.now()) {
        return id;
      }
      order.shift(); // completed or lapsed: no longer a lock
    }
    return null;
  }

  /**
   * ORDERED: waits up to half the take lease for the key's committed claims to
   * resolve and returns `earliestLive`, or null when the claim `mine` has not
   * resolved by then (release and retry).
   */
  async awaitEarliestLive(key: string, mine: string): Promise<string | null> {
    const deadline = Date.now() + Math.max(1000, this.takeLeaseMillis / 2);
    for (;;) {
      const earliest = this.earliestLive(key);
      if (earliest !== null && (this.committed.get(key) ?? []).includes(mine)) {
        return earliest;
      }
      if (Date.now() >= deadline || !this.active) {
        return null;
      }
      await pause(this.space.peer, 20);
    }
  }

  private onCommittedClaim(entryId: string, signed: Dict): void {
    const claim = signed["claim"] as Dict | undefined;
    const stamp = typeof claim?.["stamp"] === "string" ? claim["stamp"] : "";
    const mark = `${entryId}:${String(claim?.["epoch"] ?? "")}`;
    if (this.resolvedClaims.has(mark)) {
      return;
    }
    this.resolvedClaims.add(mark);
    this.pendingClaims.push({ entryId, stamp, sinceMillis: Date.now() });
    if (this.pendingClaims.length > READ_LIMIT * 4) {
      this.pendingClaims.shift();
    }
    this.resolvePendingClaims();
  }

  /**
   * Resolves committed claims to keys in stamp order, stopping at the first
   * claim whose record this member has not seen yet so that "the first
   * committed ticket for a key" is never judged over a ticket this member
   * cannot read; a claim whose record never arrives is dropped after
   * `PENDING_CLAIM_MAX_AGE_MILLIS`.
   */
  private resolvePendingClaims(): void {
    if (this.pendingClaims.length === 0) {
      return;
    }
    const now = Date.now();
    const peer = this.space.peer;
    this.pendingClaims.sort((a, b) => compareHlc(a.stamp, b.stamp));
    const rest: typeof this.pendingClaims = [];
    let blocked = false;
    for (const pending of this.pendingClaims) {
      if (blocked) {
        rest.push(pending);
        continue;
      }
      // A completed ticket still answers: the taker may have finished before
      // this member learned of the claim, and the key must still be read.
      const record = peer.states.get(pending.entryId)?.["record"] as Dict | undefined;
      if (record === undefined) {
        if (now - pending.sinceMillis > PENDING_CLAIM_MAX_AGE_MILLIS) {
          continue; // never replicated here; stop blocking the keys behind it
        }
        blocked = true; // not replicated here yet; keep the order and try again later
        rest.push(pending);
        continue;
      }
      const tags = (record["tags"] as Dict | undefined) ?? {};
      const key = tags[KEY_TAG];
      if (record["type"] === JOIN_TICKET_TYPE && tags[JOIN_TAG] === this.name && typeof key === "string") {
        if (!this.firstCommitted.has(key)) {
          this.firstCommitted.set(key, pending.entryId);
        }
        let order = this.committed.get(key);
        if (order === undefined) {
          order = [];
          this.committed.set(key, order);
        }
        if (!order.includes(pending.entryId)) {
          order.push(pending.entryId);
        }
      }
    }
    this.pendingClaims = rest;
  }
}

// ---------------------------------------------------------------- the join

export type JoinMode = "LOCAL" | "LEASED" | "ORDERED";

/**
 * One part as the binder resolved it: its type, its filters, the space it
 * lives in (the join's by default), and where its key is.
 */
export type ResolvedPart = { type: EntryType; space: Space; where: Dict; tags: Dict; keyField: string | null;
  keyTag: string | null; optional: boolean; atLeast: number };

/** What the binder configured. */
export type JoinConfig = { name: string; mode: JoinMode; space: Space; parts: ResolvedPart[]; withinMillis: number;
  maxOpen: number; subscriptionLeaseMillis: number; ticketLeaseMillis: number; takeLeaseMillis: number;
  pollTimeoutMillis: number; ordered: OrderedLog | null; committed?: CommittedSource | null };

/** What a join method receives (`Joined` in Java): the key and, per part type, the parts newest first. */
export class Joined {
  constructor(readonly key: string, private readonly byType: Map<EntryType, unknown[]>,
              private readonly withMeta: Map<EntryType, Entry<unknown>[]> = new Map()) {}

  /** The newest part of a type; throws when none arrived (an optional part: use `find`). */
  get<T>(type: EntryType<T>): T {
    const found = this.byType.get(type) ?? [];
    if (found.length === 0) {
      throw new Error(`no ${typeof type === "string" ? type : type.name} part for key '${this.key}'`);
    }
    return found[0] as T;
  }

  /** The newest part of a type, or null when none arrived. */
  find<T>(type: EntryType<T>): T | null {
    return (this.byType.get(type)?.[0] as T | undefined) ?? null;
  }

  /** Every part of a type, newest first; empty when none arrived. */
  all<T>(type: EntryType<T>): T[] {
    return [...((this.byType.get(type) ?? []) as T[])];
  }

  has(type: EntryType): boolean {
    return (this.byType.get(type)?.length ?? 0) > 0;
  }

  /** The newest part of a type with its metadata (issuer, tags, lease). */
  entry<T>(type: EntryType<T>): Entry<T> {
    const found = this.withMeta.get(type) ?? [];
    if (found.length === 0) {
      throw new Error(`no ${typeof type === "string" ? type : type.name} part for key '${this.key}'`);
    }
    return found[0] as Entry<T>;
  }

  /** Every part with its metadata, by type, newest first. */
  parts(): Map<EntryType, Entry<unknown>[]> {
    return new Map([...this.withMeta].map(([type, entries]) => [type, [...entries]]));
  }
}

type KeyState = { seen: Map<EntryType, Set<string>>; touchedMillis: number };

/**
 * The binder's runtime for one `@spaceJoin` method (JoinBinding in Java).
 * Constructed and started by the `Binder`; the action and the dispatch it is
 * given are the binder's method invocation and return handling.
 */
export class JoinBinding {
  private readonly tickets: KeyTickets;
  private readonly open = new Map<string, KeyState>();
  private readonly fired: BoundedSet;
  private readonly subscriptions: Array<{ close(): void; renew(lease?: number | string | null): void }> = [];
  private readonly repeating: Array<{ stop(): void }> = [];
  private readonly loops: Promise<void>[] = [];
  private running = true;
  private started = false;

  /**
   * @param config   what the binder resolved from the decorator
   * @param action   invokes the agent's method on the bag and returns its result
   * @param dispatch the binder's return handling (entry, Tagged, Motion, null)
   */
  constructor(readonly config: JoinConfig, private readonly action: (joined: Joined) => unknown,
              private readonly dispatch: (result: unknown) => void) {
    if (config.parts.length === 0) {
      throw new Error(`a join needs at least one part: '${config.name}'`);
    }
    if (config.maxOpen <= 0) {
      throw new Error(`maxOpen must be positive: ${config.maxOpen}`);
    }
    if (config.mode === "ORDERED" && config.ordered === null) {
      throw new Error(`join '${config.name}' is ORDERED but no ordered log was given`);
    }
    for (const part of config.parts) {
      if ((part.keyField === null) === (part.keyTag === null)) {
        throw new Error(`a part is keyed by a field or by a tag: ${schemaOf(part.type)}`);
      }
      if (part.atLeast < 1) {
        throw new Error(`a part needs at least one entry: ${schemaOf(part.type)}`);
      }
    }
    this.fired = new BoundedSet(config.maxOpen);
    this.tickets = new KeyTickets(config.name, config.space, config.ticketLeaseMillis, config.takeLeaseMillis,
      config.mode === "ORDERED" ? config.ordered : null, config.maxOpen, config.committed ?? null);
  }

  /** The join's name, as tickets and the card carry it. */
  get name(): string {
    return this.config.name;
  }

  /** Seeds the per-key state from the space, subscribes to every part, and starts the mode's loop. */
  start(): void {
    if (this.started) {
      throw new Error(`join '${this.config.name}' already started`);
    }
    this.started = true;
    this.tickets.start();
    for (const part of this.config.parts) {
      this.seed(part);
    }
    for (const key of this.completeKeys()) {
      this.trigger(key);
    }
    for (const part of this.config.parts) {
      this.subscribe(part);
    }
    const peer = this.config.space.peer;
    const halfLease = Math.max(1, Math.floor(this.config.subscriptionLeaseMillis / 2));
    const sweep = Math.max(1, Math.min(Math.floor(this.config.withinMillis / 4), 30_000));
    this.repeating.push(peer.every(Math.max(250, sweep), () => this.forgetStale()));
    this.repeating.push(peer.every(Math.max(250, halfLease), () => {
      for (const subscription of this.subscriptions) {
        subscription.renew();
      }
    }));
    if (this.config.mode !== "LOCAL") {
      this.loops.push(this.serveTickets());
    }
  }

  async close(): Promise<void> {
    this.running = false;
    for (const handle of this.repeating) {
      handle.stop();
    }
    for (const subscription of this.subscriptions) {
      subscription.close();
    }
    this.tickets.close();
    await Promise.allSettled(this.loops);
  }

  // ------------------------------------------------------------- parts arriving

  private templateOf(part: ResolvedPart): Template<unknown> {
    return new Template(part.type, part.where, part.tags);
  }

  private queryFor(part: ResolvedPart, key: string): Template<unknown> {
    if (part.keyTag !== null) {
      return new Template(part.type, part.where, { ...part.tags, [part.keyTag]: key });
    }
    return new Template(part.type, { ...part.where, [part.keyField!]: (v: unknown) => v != null && String(v) === key },
      part.tags);
  }

  private subscribe(part: ResolvedPart): void {
    const subscription = part.space.notify(this.templateOf(part), (event: SpaceEvent<unknown>) => {
      if (event.kind !== WRITTEN && event.kind !== REAPPEARED) {
        return;
      }
      const key = this.keyOf(part, event.entry.value, event.entry.tags);
      if (key === null) {
        return; // a part carrying no key is ignored
      }
      if (this.record(part, key, event.entry.entryId)) {
        this.trigger(key);
      }
    }, this.config.subscriptionLeaseMillis);
    this.subscriptions.push(subscription);
  }

  private seed(part: ResolvedPart): number {
    let count = 0;
    for (const held of part.space.entries(this.templateOf(part), READ_LIMIT)) {
      const key = this.keyOf(part, held.value, held.tags);
      if (key !== null) {
        this.record(part, key, held.entryId);
        count++;
      }
    }
    return count;
  }

  private keyOf(part: ResolvedPart, value: unknown, tags: Dict): string | null {
    if (part.keyTag !== null) {
      return tags[part.keyTag] === undefined || tags[part.keyTag] === null ? null : String(tags[part.keyTag]);
    }
    const v = toPayload(value as object)[part.keyField!];
    return v === undefined || v === null ? null : String(v);
  }

  /** Records a part under its key; returns whether the key is now complete. */
  private record(part: ResolvedPart, key: string, entryId: string): boolean {
    let state = this.open.get(key);
    if (state === undefined) {
      state = { seen: new Map(), touchedMillis: 0 };
      this.open.set(key, state);
      while (this.open.size > this.config.maxOpen) {
        // Beyond maxOpen the eldest key is forgotten: its parts stay in the space
        // and are found again when a new one arrives.
        this.open.delete(this.open.keys().next().value!);
      }
      // A key met for the first time (or forgotten after `within`): what the
      // space already holds for it counts, so nothing is lost by forgetting,
      // and a late part completes a key the sweep dropped.
      for (const other of this.config.parts) {
        if (other === part) {
          continue;
        }
        for (const held of other.space.entries(this.queryFor(other, key), READ_LIMIT)) {
          this.note(state, other, held.entryId);
        }
      }
    } else {
      // Access order, as the Java map keeps it: a touched key is the youngest.
      this.open.delete(key);
      this.open.set(key, state);
    }
    this.note(state, part, entryId);
    state.touchedMillis = this.config.space.peer.now();
    return this.isComplete(state);
  }

  private note(state: KeyState, part: ResolvedPart, entryId: string): void {
    let seen = state.seen.get(part.type);
    if (seen === undefined) {
      seen = new Set();
      state.seen.set(part.type, seen);
    }
    seen.add(entryId);
  }

  private isComplete(state: KeyState): boolean {
    return this.config.parts.every((part) => part.optional
      || (state.seen.get(part.type)?.size ?? 0) >= part.atLeast);
  }

  private completeKeys(): string[] {
    return [...this.open].filter(([, state]) => this.isComplete(state)).map(([key]) => key);
  }

  // -------------------------------------------------------------------- firing

  private trigger(key: string): void {
    if (this.config.mode !== "LOCAL") {
      this.tickets.request(key);
      return;
    }
    if (this.fired.has(key)) {
      return;
    }
    this.fired.add(key);
    void Promise.resolve().then(async () => {
      try {
        if (!(await this.fire(key))) {
          this.fired.delete(key); // a part lapsed or has not landed: the next part fires it
        }
      } catch {
        this.fired.delete(key);
      }
    });
  }

  /**
   * Invokes the method on the parts as the space holds them now. Returns
   * false, writing nothing, when a required part is no longer readable (its
   * lease lapsed between completion and firing).
   */
  private async fire(key: string): Promise<boolean> {
    const joined = this.assemble(key);
    if (joined === null) {
      return false;
    }
    this.dispatch(await this.action(joined));
    return true;
  }

  /**
   * Fires the key once every required part is readable here, waiting up to
   * the lesser of half the ticket's take lease and five seconds for parts
   * that replicated later than the ticket; false when they never came. The
   * wait stays inside the lease, so a successful firing can still complete
   * the ticket it holds.
   */
  private async fireWhenPartsReadable(key: string): Promise<boolean> {
    const deadline = Date.now() + Math.min(this.config.takeLeaseMillis / 2, 5000);
    for (;;) {
      if (await this.fire(key)) {
        return true;
      }
      if (Date.now() >= deadline || !this.running) {
        return false;
      }
      await pause(this.config.space.peer, 20);
    }
  }

  private assemble(key: string): Joined | null {
    const byType = new Map<EntryType, unknown[]>();
    const withMeta = new Map<EntryType, Entry<unknown>[]>();
    for (const part of this.config.parts) {
      const peer = part.space.peer;
      const entries = part.space.entries(this.queryFor(part, key), READ_LIMIT)
        .sort((a, b) => compareHlc(issuedOf(peer, b.entryId), issuedOf(peer, a.entryId)));
      if (entries.length === 0 && !part.optional) {
        return null;
      }
      if (entries.length > 0) {
        byType.set(part.type, entries.map((e) => e.value));
        withMeta.set(part.type, entries);
      }
    }
    return new Joined(key, byType, withMeta);
  }

  // ------------------------------------------------------ tickets (LEASED, ORDERED)

  private async serveTickets(): Promise<void> {
    const { space, mode } = this.config;
    while (this.running) {
      let taken: Taken<JoinTicket> | null;
      try {
        taken = await takeThrough(space, mode === "ORDERED" ? this.config.ordered : null, this.tickets.template(),
          this.config.takeLeaseMillis, this.config.pollTimeoutMillis);
      } catch {
        if (!this.running) {
          return;
        }
        // ORDERED: a leader election in flight is routine and the next poll resubmits.
        await pause(space.peer, 200);
        continue;
      }
      if (taken === null) {
        continue;
      }
      const key = taken.value.key;
      if (mode === "ORDERED" && (await this.tickets.awaitFirstCommitted(key)) === null) {
        // Undecided: an earlier committed claim for this key has a record this
        // member has not seen yet. Neither fire nor complete; the ticket's take
        // lease lapses, it reappears, and the next taker decides with the
        // record in hand.
        continue;
      }
      const fires = this.shouldFire(key, taken.entryId);
      try {
        if (fires && !(await this.fireWhenPartsReadable(key))) {
          // The ticket was written by a member that saw every part; this member,
          // which won the ticket, may not hold them all yet. Neither fire nor
          // complete: the key is forgotten here, the ticket's take lease lapses,
          // and the ticket reappears for a member that has the parts.
          this.fired.delete(key);
          continue;
        }
        taken.complete();
      } catch {
        if (fires) {
          this.fired.delete(key);
        }
        // The crash idiom: no completion, the ticket's take lease lapses, and
        // the ticket reappears for this joiner or another.
      }
    }
  }

  private shouldFire(key: string, ticket: string): boolean {
    if (this.config.mode === "ORDERED") {
      const firing = this.tickets.decided(key);
      if (firing !== null && firing !== ticket) {
        return false; // a later ticket for a key the log already decided
      }
    }
    if (this.fired.has(key)) {
      return false;
    }
    this.fired.add(key);
    return true;
  }

  // ------------------------------------------------------------- housekeeping

  private forgetStale(): void {
    const cutoff = this.config.space.peer.now() - this.config.withinMillis;
    for (const [key, state] of [...this.open]) {
      if (state.touchedMillis < cutoff) {
        this.open.delete(key); // a key that never completed within the window is forgotten
      }
    }
  }
}
