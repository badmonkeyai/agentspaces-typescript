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
 * The runtime behind `@spaceReduce` (srad/agentspaces-js.md JS-V-09;
 * ISSUE-SpaceReduce §9.3), the TypeScript shape of the Java `ReduceBinding`
 * and `Reductions`: a fold whose accumulator is an entry beside its elements.
 * A step takes one element, invokes the method with the key's current
 * accumulator, and completes the element with the new accumulator as the
 * result, atomically; the previous accumulator is then retired. A
 * `JoinTicket` per key, taken before a drain and re-armed by completion after
 * it, serializes the steps of one key across reducers; under ORDERED every
 * take goes through the ordered log and the log decides the ticket's holder.
 *
 * An accumulator carries the tags `reduce` (the reduce's name), `key`, and
 * `steps`; between a successor's write and the predecessor's retirement two
 * are visible, and `current` returns the one with the highest step count.
 */

import type { OrderedLog } from "./capabilities/ordered.js";
import { BoundedMap, CommittedSource, JoinTicket, KEY_TAG, KeyTickets, issuedOf, takeThrough } from "./join.js";
import { COMPLETED, Entry, EntryType, EXPIRED, REAPPEARED, Space, SpaceEvent, Tagged, Taken, Template, WRITTEN,
  schemaOf, toPayload } from "./space.js";
import { compareHlc } from "./wire.js";
import type { Dict } from "./wire.js";

// --------------------------------------------------------------- reductions

/** The tag naming the reduce an accumulator belongs to. */
export const REDUCE_TAG = "reduce";
/** The tag carrying the accumulator's key. */
export const REDUCE_KEY_TAG = "key";
/** The tag carrying the accumulator's step count. */
export const STEPS_TAG = "steps";
/** The key of a reduce with neither `key` nor `keyTag`: one accumulator for the type. */
export const GLOBAL_KEY = "*";

const READ_LIMIT = 256;
const CURRENT_LIMIT = 8;

/** The template of a reduce's accumulators of one key. */
export function reductionTemplate<A>(type: EntryType<A>, name: string, key: string): Template<A> {
  return new Template(type, {}, { [REDUCE_TAG]: name, [REDUCE_KEY_TAG]: key });
}

/** The step count an accumulator carries; zero when it carries none. */
export function steps(accumulator: Entry<unknown>): number {
  const count = Number(accumulator.tags[STEPS_TAG] ?? 0);
  return Number.isFinite(count) ? count : 0;
}

/** The key's newest accumulator: the one with the highest step count among those visible, or null. */
export function current<A>(space: Space, type: EntryType<A>, name: string, key: string): Entry<A> | null {
  let newest: Entry<A> | null = null;
  for (const candidate of space.entries(reductionTemplate(type, name, key), CURRENT_LIMIT)) {
    if (newest === null || steps(candidate) > steps(newest)) {
      newest = candidate;
    }
  }
  return newest;
}

// ------------------------------------------------------------------ binding

export type ReduceMode = "LEASED" | "ORDERED";

/** What the binder configured. */
export type ReduceConfig = { name: string; mode: ReduceMode; space: Space; elementType: EntryType;
  elementWhere: Dict; elementTags: Dict; accumulatorType: EntryType; keyField: string | null; keyTag: string | null;
  takeLeaseMillis: number; pollTimeoutMillis: number; accumulatorLeaseMillis: number; subscriptionLeaseMillis: number;
  maxOpen: number; ordered: OrderedLog | null; committed?: CommittedSource | null };

/**
 * The binder's runtime for one `@spaceReduce` method. Constructed and started
 * by the `Binder`; the step and the side-output dispatch it is given are the
 * binder's method invocation and return handling.
 */
export class ReduceBinding {
  private readonly tickets: KeyTickets;
  private readonly elementTemplate: Template<unknown>;
  /** Keys with elements to fold, in arrival order. */
  private readonly pending = new Set<string>();
  private wake: (() => void) | null = null;
  /** The accumulators this reducer wrote, by key, for a cheap retirement. */
  private readonly written: BoundedMap<string>;
  /** LEASED: the live tickets of this reduce as the events show them, by key then issue stamp. */
  private readonly liveTickets: BoundedMap<Map<string, string>>;
  private readonly subscriptions: Array<{ close(): void; renew(lease?: number | string | null): void }> = [];
  private readonly repeating: Array<{ stop(): void }> = [];
  private readonly loops: Promise<void>[] = [];
  private running = true;
  private started = false;

  /**
   * @param config      what the binder resolved from the decorator
   * @param step        invokes the agent's method on (accumulator or null, element) and returns its result
   * @param sideOutputs the binder's return handling for a fork's other elements
   */
  constructor(readonly config: ReduceConfig, private readonly step: (accumulator: unknown, element: unknown) => unknown,
              private readonly sideOutputs: (other: unknown) => void) {
    if (config.maxOpen <= 0) {
      throw new Error(`maxOpen must be positive: ${config.maxOpen}`);
    }
    if (config.mode === "ORDERED" && config.ordered === null) {
      throw new Error(`reduce '${config.name}' is ORDERED but no ordered log was given`);
    }
    if (config.accumulatorLeaseMillis < config.takeLeaseMillis) {
      throw new Error(`reduce '${config.name}': accumulatorLease ${config.accumulatorLeaseMillis}ms is shorter than`
        + ` the take lease ${config.takeLeaseMillis}ms`);
    }
    if (config.keyField !== null && config.keyTag !== null) {
      throw new Error(`reduce '${config.name}' names both key and keyTag; choose one`);
    }
    this.elementTemplate = new Template(config.elementType, config.elementWhere, config.elementTags);
    this.written = new BoundedMap(config.maxOpen);
    this.liveTickets = new BoundedMap(config.maxOpen);
    this.tickets = new KeyTickets(config.name, config.space, config.accumulatorLeaseMillis, config.takeLeaseMillis,
      config.mode === "ORDERED" ? config.ordered : null, config.maxOpen, config.committed ?? null);
  }

  /** The reduce's name, as tickets, accumulators, and the card carry it. */
  get name(): string {
    return this.config.name;
  }

  /** Seeds the pending keys from the space, subscribes to the elements and the tickets, and starts the drain. */
  start(): void {
    if (this.started) {
      throw new Error(`reduce '${this.config.name}' already started`);
    }
    this.started = true;
    this.tickets.start();
    this.sweep();
    this.subscriptions.push(this.config.space.notify(this.elementTemplate, (event: SpaceEvent<unknown>) => {
      if (event.kind !== WRITTEN && event.kind !== REAPPEARED) {
        return;
      }
      const key = this.keyOf(event.entry.value, event.entry.tags);
      if (key !== null) {
        this.enqueue(key);
      }
    }, this.config.subscriptionLeaseMillis));
    this.subscriptions.push(this.config.space.notify(this.tickets.template(), (event: SpaceEvent<JoinTicket>) =>
      this.onTicket(event), this.config.subscriptionLeaseMillis));
    const halfLease = Math.max(250, Math.floor(this.config.subscriptionLeaseMillis / 2));
    this.repeating.push(this.config.space.peer.every(halfLease, () => {
      for (const subscription of this.subscriptions) {
        subscription.renew();
      }
    }));
    this.loops.push(this.drain());
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
    this.wake?.();
    await Promise.allSettled(this.loops);
  }

  /** The pending keys, for tests. */
  pendingKeys(): Set<string> {
    return new Set(this.pending);
  }

  // ------------------------------------------------------------ elements arriving

  /**
   * LEASED: follows the tickets of this reduce so a reducer that takes a
   * ticket can tell whether an older one is live for the key, even while that
   * older ticket is claimed. A reappeared ticket is a key to serve, whoever
   * wrote it; a written ticket is not: its writer serves it.
   */
  private onTicket(event: SpaceEvent<JoinTicket>): void {
    const key = event.entry.tags[KEY_TAG];
    if (typeof key !== "string") {
      return;
    }
    if (event.kind === WRITTEN) {
      let live = this.liveTickets.get(key);
      if (live === undefined) {
        live = new Map();
        this.liveTickets.set(key, live);
      }
      live.set(event.entry.entryId, issuedOf(this.config.space.peer, event.entry.entryId));
    } else if (event.kind === COMPLETED || event.kind === EXPIRED) {
      this.liveTickets.get(key)?.delete(event.entry.entryId);
    }
    if (event.kind === REAPPEARED) {
      this.enqueue(key);
    }
  }

  /** LEASED: whether a ticket older than `mine` is live for the key, as far as the events show. */
  private olderTicketLive(key: string, mine: string): boolean {
    const live = this.liveTickets.get(key);
    if (live === undefined || live.size === 0) {
      return false;
    }
    const oldest = [...live].sort((a, b) => compareHlc(a[1], b[1]))[0]![0];
    return oldest !== mine;
  }

  /** Reads every available element and queues its key; returns how many keys are pending. */
  private sweep(): number {
    for (const held of this.config.space.entries(this.elementTemplate, READ_LIMIT, false)) {
      const key = this.keyOf(held.value, held.tags);
      if (key !== null) {
        this.enqueue(key);
      }
    }
    return this.pending.size;
  }

  private enqueue(key: string): void {
    this.pending.add(key);
    this.wake?.();
  }

  private keyOf(value: unknown, tags: Dict): string | null {
    if (this.config.keyTag !== null) {
      const tag = tags[this.config.keyTag];
      return tag === undefined || tag === null ? null : String(tag);
    }
    if (this.config.keyField === null) {
      return GLOBAL_KEY;
    }
    const v = toPayload(value as object)[this.config.keyField];
    return v === undefined || v === null ? null : String(v);
  }

  // --------------------------------------------------------------------- the drain

  private async drain(): Promise<void> {
    while (this.running) {
      if (this.pending.size === 0) {
        await new Promise<void>((resolve) => {
          const timer = this.config.space.peer.timers.setTimeout(() => { this.wake = null; resolve(); },
            this.config.pollTimeoutMillis);
          this.wake = () => { this.config.space.peer.timers.clearTimeout(timer); this.wake = null; resolve(); };
        });
        if (!this.running) {
          return;
        }
        if (this.pending.size === 0) {
          this.sweep(); // an element written while this reducer was down, or an event it missed
          continue;
        }
      }
      const key = this.pending.keys().next().value!;
      this.pending.delete(key);
      try {
        await this.drainKey(key);
      } catch {
        // draining the key failed; its elements reappear by their leases and raise it again
      }
    }
  }

  /**
   * Holds a ticket for the key while folding every available element of the
   * key, then completes it; a later element raises a new ticket. A reducer
   * whose ticket is not the key's oldest live one backs off and completes it
   * bare, so two tickets written in one instant converge on one lock.
   */
  private async drainKey(key: string): Promise<void> {
    const { space } = this.config;
    if (!this.tickets.request(key)) {
      return;
    }
    const ticket = await this.take(this.tickets.templateFor(key));
    if (ticket === null) {
      return; // another reducer holds the key; its events or the sweep raise it again
    }
    const mine = ticket.entryId;
    if (this.config.mode === "ORDERED") {
      const lock = await this.tickets.awaitEarliestLive(key, mine);
      if (lock === null) {
        return; // undecided: the take lease lapses and the ticket reappears, decided
      }
      if (lock !== mine) {
        ticket.complete(); // a duplicate: the earliest live ticket is the lock
        this.tickets.forget(key);
        return;
      }
    } else if (this.olderTicketLive(key, mine)) {
      ticket.complete();
      this.tickets.forget(key);
      return;
    }
    let held = true;
    try {
      while (this.running) {
        // The ticket is the lock only while its take lease holds: check it before
        // every step (and extend it, when this reducer signs as an agent, under
        // LEASED), and when the hold is gone another reducer may own the key and
        // this drain stops without completing anything more.
        try {
          if (this.config.mode === "LEASED" && space.agent !== null) {
            space.peer.renewClaim(space.name, mine, this.config.takeLeaseMillis, space.agent);
          } else {
            space.peer.requireHeld(space.name, mine, space.agent);
          }
        } catch {
          held = false;
          break;
        }
        const element = await this.take(this.elementQuery(key));
        if (element === null) {
          break;
        }
        if (!(await this.fold(key, element))) {
          break; // the method threw: the element reappears by its lease; stop the drain here
        }
      }
    } finally {
      if (held) {
        try {
          ticket.complete();
        } catch {
          // the ticket reappears by its lease
        }
      }
      this.tickets.forget(key);
    }
  }

  /**
   * One step: the method on (current, element), then the element completed
   * with the new accumulator, then the previous accumulator retired and the
   * fork's side outputs written. Returns false when the method threw.
   */
  private async fold(key: string, element: Taken<unknown>): Promise<boolean> {
    const { space, accumulatorType, name } = this.config;
    const before = current(space, accumulatorType, name, key);
    let result: unknown;
    try {
      result = await this.step(before?.value ?? null, element.value);
    } catch {
      return false; // the fold threw for the key; the element's take lease will lapse
    }
    if (result === null || result === undefined) {
      element.complete();
      return true;
    }
    let accumulator: unknown = result;
    const tags: Dict = {};
    let others: unknown[] = [];
    if (Array.isArray(result)) {
      let found: unknown = null;
      const rest: unknown[] = [];
      for (const candidate of result) {
        if (this.isAccumulator(candidate instanceof Tagged ? candidate.value : candidate)) {
          if (found !== null) {
            throw new Error(`${name} returned a fork with two ${schemaOf(accumulatorType)} accumulators`);
          }
          found = candidate;
        } else {
          rest.push(candidate);
        }
      }
      if (found === null) {
        throw new Error(`${name} returned a fork with no ${schemaOf(accumulatorType)} accumulator`);
      }
      accumulator = found;
      others = rest;
    }
    if (accumulator instanceof Tagged) {
      Object.assign(tags, accumulator.tags);
      accumulator = accumulator.value;
    }
    if (!this.isAccumulator(accumulator)) {
      throw new Error(`${name} returned a ${(accumulator as object)?.constructor?.name ?? typeof accumulator};`
        + ` the accumulator is a ${schemaOf(accumulatorType)}`);
    }
    const stepCount = (before === null ? 0 : steps(before)) + 1;
    tags[REDUCE_TAG] = name;
    tags[REDUCE_KEY_TAG] = key;
    tags[STEPS_TAG] = String(stepCount);
    const written = element.complete(accumulator as object, this.config.accumulatorLeaseMillis, tags)!;
    const previous = this.written.get(key) ?? null;
    this.written.set(key, written);
    if (before !== null) {
      await this.retire(key, before, previous);
    }
    for (const other of others) {
      this.sideOutputs(other);
    }
    return true;
  }

  private isAccumulator(value: unknown): boolean {
    if (value === null || typeof value !== "object") {
      return false;
    }
    const type = this.config.accumulatorType;
    if (typeof type !== "string") {
      return value instanceof type;
    }
    try {
      return schemaOf((value as object).constructor as EntryType) === type;
    } catch {
      return false;
    }
  }

  /**
   * Removes the predecessor: an exact take and a bare completion when this
   * reducer wrote it (nobody else races for it, so no settle window), a take
   * under the mode and a bare completion otherwise.
   */
  private async retire(key: string, predecessor: Entry<unknown>, own: string | null): Promise<void> {
    const { space, accumulatorType, name } = this.config;
    try {
      if (own !== null && own === predecessor.entryId) {
        const held = await space.peer.takeEntry(space.name, schemaOf(accumulatorType), space.agentName,
          this.config.takeLeaseMillis, 0, Math.max(100, this.config.pollTimeoutMillis), space.agent, own);
        if (held !== null) {
          space.peer.completeEntry(space.name, held, space.agent);
        }
        return;
      }
      const stale = new Template(accumulatorType, {}, { [REDUCE_TAG]: name, [REDUCE_KEY_TAG]: key,
        [STEPS_TAG]: String(steps(predecessor)) });
      const taken = await this.take(stale);
      taken?.complete();
    } catch {
      // the predecessor stays visible; readers choose the highest steps
    }
  }

  private elementQuery(key: string): Template<unknown> {
    const { elementType, elementWhere, elementTags, keyField, keyTag } = this.config;
    if (keyTag !== null) {
      return new Template(elementType, elementWhere, { ...elementTags, [keyTag]: key });
    }
    if (keyField === null) {
      return this.elementTemplate;
    }
    return new Template(elementType, { ...elementWhere, [keyField]: (v: unknown) => v != null && String(v) === key },
      elementTags);
  }

  private take<T>(template: Template<T>): Promise<Taken<T> | null> {
    return takeThrough(this.config.space, this.config.mode === "ORDERED" ? this.config.ordered : null, template,
      this.config.takeLeaseMillis, this.config.pollTimeoutMillis);
  }
}
