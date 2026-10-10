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
 * The AgentSpace, TypeScript-shaped (L3L4-COVERAGE.md §6.5): entry classes
 * bound to their wire schema, templates over fields and tags with the Java
 * `Matchers` semantics, a `Space` with the layer-3 verbs over a `Peer`,
 * events as an `EventEmitter` and as an async iterator, and the in-flight
 * take in `AsyncLocalStorage`.
 *
 *     @entry("com.acme.Task#v1")
 *     class Task { constructor(public topic = "", public priority = 0) {} }
 *
 *     const space = new Space(peer, "tasks");
 *     space.write(new Task("index", 3), "10m", { region: "eu" });
 *     for (const task of space.readAll(new Template(Task, { priority: gte(3) }, { region: "eu" }))) { ... }
 *     const taken = await space.take(new Template(Task), "1m", "15s");
 *     taken?.complete(new Finding(taken.value.topic, "done"));
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { EventEmitter } from "node:events";

import { CborDouble, CborValue, loads } from "./cbor.js";
import { AgentIdentity, spaceIdLocal } from "./identity.js";
import type { Peer } from "./peer.js";
import type { Dict } from "./wire.js";

// ----------------------------------------------------------------- durations

const UNITS: { [unit: string]: number } = { ns: 1e-6, us: 1e-3, ms: 1, s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 };

/** A duration as milliseconds: a number (millis), `"250ms"`, `"10m"`, or ISO-8601 `"PT5M"`. */
export function durationMillis(value: number | string): number {
  if (typeof value === "number") {
    return value;
  }
  const text = value.trim();
  if (text.toUpperCase().startsWith("PT")) {
    let total = 0;
    for (const [, amount, unit] of text.toUpperCase().matchAll(/([0-9.]+)([HMS])/g)) {
      total += Number(amount) * { H: 3_600_000, M: 60_000, S: 1_000 }[unit as "H" | "M" | "S"]!;
    }
    return Math.floor(total);
  }
  const m = /^([0-9]+)\s*([a-z]+)$/.exec(text);
  if (!m || !(m[2]! in UNITS)) {
    throw new Error(`not a duration: ${value}`);
  }
  return Math.floor(Number(m[1]) * UNITS[m[2]!]!);
}

// ------------------------------------------------------------------- entries

export type Class<T = unknown> = (abstract new (...args: never[]) => T) & { schema?: string };
export type EntryType<T = unknown> = Class<T> | string;

/**
 * Binds a class to its wire schema name: a Java record's binary class name
 * plus `#v1` under the default registry, or the namespace a schema registry
 * assigns. A stage-3 class decorator; the class gains a static `schema`.
 */
export function entry(schema: string) {
  return <C extends Class>(value: C, _context?: ClassDecoratorContext): C => {
    (value as { schema?: string }).schema = schema;
    return value;
  };
}

/** The wire schema name of an `@entry` class, or a schema string passed through. */
export function schemaOf(type: EntryType): string {
  if (typeof type === "string") {
    return type;
  }
  if (!type.schema) {
    throw new TypeError(`${type.name} is not an @entry class and names no schema`);
  }
  return type.schema;
}

/**
 * The wire payload of a value: its own enumerable fields, a fractional
 * number as a float64 (the encoder emits plain numbers as integers).
 */
export function toPayload(value: object): Dict {
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, wireValue(v)]));
}

function wireValue(v: unknown): CborValue {
  if (typeof v === "number" && !Number.isInteger(v)) {
    return new CborDouble(v);
  }
  if (Array.isArray(v)) {
    return v.map(wireValue);
  }
  if (v !== null && typeof v === "object" && !(v instanceof Uint8Array) && !(v instanceof CborDouble)) {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, wireValue(x)]));
  }
  return v as CborValue;
}

/** The decoded CBOR with every `CborDouble` unwrapped, so fields compare as numbers. */
export function plain(value: CborValue): unknown {
  if (value instanceof CborDouble) {
    return value.value;
  }
  if (Array.isArray(value)) {
    return value.map(plain);
  }
  if (value !== null && typeof value === "object" && !(value instanceof Uint8Array)) {
    return Object.fromEntries(Object.entries(value as Dict).map(([k, v]) => [k, plain(v)]));
  }
  return value;
}

/** A value from its wire payload: an instance of the class carrying the payload's fields, or the record itself. */
export function fromPayload<T>(type: EntryType<T>, payload: Dict): T {
  const fields = plain(payload) as Dict;
  if (typeof type === "string") {
    return fields as T;
  }
  const instance = Object.create((type as unknown as { prototype: object }).prototype) as T;
  return Object.assign(instance as object, fields) as T;
}

// ------------------------------------------------------------------ matchers

export type Matcher = (value: unknown) => boolean;
export type Condition = Matcher | unknown;

export const eq = (expected: unknown): Matcher => (v) => v === expected;
export const ne = (unexpected: unknown): Matcher => (v) => v !== unexpected;
const compare = (v: unknown, bound: number | string): number =>
  typeof v === "string" && typeof bound === "string" ? (v < bound ? -1 : v > bound ? 1 : 0) : Number(v) - Number(bound);
export const gt = (bound: number | string): Matcher => (v) => v != null && compare(v, bound) > 0;
export const gte = (bound: number | string): Matcher => (v) => v != null && compare(v, bound) >= 0;
export const lt = (bound: number | string): Matcher => (v) => v != null && compare(v, bound) < 0;
export const lte = (bound: number | string): Matcher => (v) => v != null && compare(v, bound) <= 0;
export const oneOf = (...alternatives: unknown[]): Matcher => (v) => alternatives.includes(v);
export const contains = (fragment: string): Matcher => (v) => typeof v === "string" && v.includes(fragment);
export const isNull = (): Matcher => (v) => v == null;
export const notNull = (): Matcher => (v) => v != null;

const matcher = (spec: Condition): Matcher => typeof spec === "function" ? spec as Matcher : eq(spec);

/**
 * A query: the entry type (an `@entry` class or a schema string), field
 * conditions, and tag conditions. A plain value means equality; a function is
 * a predicate; `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `oneOf`, `contains`,
 * `isNull`, `notNull` are the Java matchers.
 */
export class Template<T = unknown> {
  readonly schema: string;
  readonly where: Array<[string, Matcher]>;
  readonly tags: Array<[string, Matcher]>;

  constructor(readonly type: EntryType<T>, where: { [field: string]: Condition } = {},
              tags: { [tag: string]: Condition } = {}) {
    this.schema = schemaOf(type);
    this.where = Object.entries(where).map(([k, v]) => [k, matcher(v)]);
    this.tags = Object.entries(tags).map(([k, v]) => [k, matcher(v)]);
  }

  matches(payload: Dict, tags: Dict = {}): boolean {
    const fields = plain(payload ?? {}) as Dict;
    return this.where.every(([field, test]) => test(fields[field])) && this.matchesTags(tags);
  }

  matchesTags(tags: Dict): boolean {
    return this.tags.every(([key, test]) => test(tags?.[key]));
  }

  decode(payload: Dict): T {
    return fromPayload(this.type, payload);
  }
}

// --------------------------------------------------------------- the entries

/** An entry as the space holds it: the value and its metadata. */
export type Entry<T> = {
  entryId: string; value: T; tags: Dict; issuer: string;
  expiresAtMillis: number; completed: boolean; taken: boolean;
};

export type EventKind = "WRITTEN" | "TAKEN" | "COMPLETED" | "EXPIRED" | "REAPPEARED";
export const WRITTEN: EventKind = "WRITTEN";
export const TAKEN: EventKind = "TAKEN";
export const COMPLETED: EventKind = "COMPLETED";
/** The write lease lapsed with the entry still open: a leased entry as a timer. */
export const EXPIRED: EventKind = "EXPIRED";
/** A take claim lapsed and the entry is available again. */
export const REAPPEARED: EventKind = "REAPPEARED";

/** What a watch delivers. */
export type SpaceEvent<T> = { kind: EventKind; entry: Entry<T> };

/** A held entry: complete it, with a result or without, or renew it. */
export class Taken<T> {
  constructor(readonly space: Space, readonly entryId: string, readonly value: T,
              readonly leaseMillis: number) {}

  /**
   * Completes the take, writing `result` first (into the take space, or
   * `resultSpace`) so a caller correlating on it sees it with the completion.
   */
  complete(result: object | null = null, lease: number | string = "1h", tags: Dict = {},
           resultSpace: Space | null = null): string | null {
    let resultId: string | null = null;
    if (result !== null) {
      resultId = (resultSpace ?? this.space).write(result, lease, tags);
    }
    this.space.peer.completeEntry(this.space.name, this.entryId, this.space.agent);
    return resultId;
  }

  renew(lease: number | string | null = null): void {
    const millis = lease === null ? this.leaseMillis : durationMillis(lease);
    this.space.peer.renewEntry(this.space.name, this.entryId, millis, this.space.agent);
  }
}

// ------------------------------------------------------ return conventions

/** A result written with tags (`Tagged.of` in Java): `new Tagged(value, { region: "eu" })`. */
export class Tagged<T extends object = object> {
  constructor(readonly value: T, readonly tags: Dict) {}

  static of<T extends object>(value: T, tags: Dict): Tagged<T> {
    return new Tagged(value, tags);
  }
}

/** This peer's contribution to a push-sum epoch, as a return value (`Contribution` in Java). */
export class Contribution {
  constructor(readonly epochId: string, readonly value: number, readonly mode: "avg" | "sum" | "count" | "min" | "max" = "avg") {}
}

/**
 * A vote opened as a return value (`Motion` in Java): the binder proposes it
 * in the vote space (`space`, or the binder's default vote space) once per
 * proposal id, after the take is completed.
 */
export class Motion {
  constructor(readonly proposalId: string, readonly question: string, readonly options: string[],
              readonly quorum: number, readonly space: string | null = null,
              readonly lease: number | string = "1h") {
    if (options.length < 2) {
      throw new Error("a motion needs at least two options");
    }
    if (quorum <= 0) {
      throw new Error("quorum must be positive");
    }
  }
}

const currentTake = new AsyncLocalStorage<Taken<unknown>>();

/**
 * The take a worker method runs under: the binder runs the call inside it,
 * so a listener (a model call's lease renewal, say) finds it without a parameter.
 */
export const TakeContext = {
  current<T = unknown>(): Taken<T> | null {
    return (currentTake.getStore() as Taken<T> | undefined) ?? null;
  },
  run<R>(taken: Taken<unknown>, fn: () => R): R {
    return currentTake.run(taken, fn);
  },
};

// ----------------------------------------------------------------- the space

type Watcher = { template: Template<unknown>; delivered: Set<string>; emit: (event: SpaceEvent<unknown>) => void };

/** A watch handle: an `EventEmitter` of `"event"`, closed with `close()`. */
export class Subscription<T> extends EventEmitter {
  constructor(private readonly space: Space, private readonly key: number) {
    super();
  }

  close(): void {
    this.space.unwatch(this.key);
    this.emit("close");
  }

  /** The events as an async iterator: `for await (const e of space.events(t))`. */
  async *[Symbol.asyncIterator](): AsyncIterableIterator<SpaceEvent<T>> {
    const queue: SpaceEvent<T>[] = [];
    let wake: (() => void) | null = null;
    let closed = false;
    this.on("event", (e: SpaceEvent<T>) => { queue.push(e); wake?.(); });
    this.on("close", () => { closed = true; wake?.(); });
    while (!closed || queue.length > 0) {
      if (queue.length === 0) {
        await new Promise<void>((resolve) => { wake = resolve; });
        wake = null;
        continue;
      }
      yield queue.shift()!;
    }
  }
}

/**
 * One space of the peer's group, by name: the layer-3 verbs over typed
 * entries. `agent` (an `AgentIdentity`) makes every write, take, and
 * completion that agent's own attested record; `agentName` names the
 * peer-signed agent otherwise.
 */
export class Space {
  /** The AUCTION price of an entry; `0` under LEASE_RACE. */
  bidFunction: ((payload: Dict) => number) | null = null;
  private readonly watchers = new Map<number, Watcher>();
  private nextKey = 0;
  private readonly spaceId: string;

  constructor(readonly peer: Peer, readonly name: string,
              readonly agent: AgentIdentity | null = null, readonly agentName = "typescript") {
    this.spaceId = spaceIdLocal(`${peer.group}/${name}`);
    install(peer).push(this);
  }

  private mine(dto: Dict): boolean {
    return ((dto["record"] as Dict | undefined)?.["spaceId"]) === this.spaceId;
  }

  // ---------------------------------------------------------------- verbs

  write(value: object, lease: number | string = "10m", tags: Dict = {}): string {
    const schema = schemaOf(value.constructor as Class);
    return this.peer.writeEntry(this.name, schema, toPayload(value), this.agentName,
      durationMillis(lease), this.agent, tags);
  }

  /** Every live entry matching the template, with its metadata. */
  entries<T>(template: Template<T>, limit = 100, includeTaken = true): Entry<T>[] {
    const now = this.peer.now();
    const found: Entry<T>[] = [];
    for (const [entryId, dto] of this.peer.states) {
      const record = (dto["record"] as Dict | undefined) ?? {};
      if (record["type"] !== template.schema || !this.mine(dto) || dto["completed"]) {
        continue;
      }
      const lease = (record["lease"] as Dict | undefined) ?? {};
      const expires = Number(lease["expiresAtMillis"] ?? 0);
      if (expires <= now) {
        continue;
      }
      const payload = loads(Buffer.from((record["payload"] as Uint8Array) ?? new Uint8Array([0xf6]))) as Dict;
      const tags = (record["tags"] as Dict | undefined) ?? {};
      if (!template.matches(payload, tags)) {
        continue;
      }
      const claim = this.peer.claims.get(entryId)?.["claim"] as Dict | undefined;
      const taken = claim !== undefined && Number(claim["expiresAtMillis"] ?? 0) > now;
      if (taken && !includeTaken) {
        continue;
      }
      found.push({ entryId, value: template.decode(payload), tags: { ...tags }, issuer: String(record["issuer"]),
        expiresAtMillis: expires, completed: false, taken });
      if (found.length >= limit) {
        break;
      }
    }
    return found;
  }

  readAll<T>(template: Template<T>, limit = 100): T[] {
    return this.entries(template, limit).map((e) => e.value);
  }

  /** The first match, waiting up to `timeout` (pulling the space) for one. */
  async read<T>(template: Template<T>, timeout: number | string | null = null): Promise<T | null> {
    const deadline = Date.now() + (timeout === null ? 0 : durationMillis(timeout));
    for (;;) {
      const found = this.entries(template, 1);
      if (found.length > 0) {
        return found[0]!.value;
      }
      if (Date.now() >= deadline) {
        return null;
      }
      this.peer.pullSpace(this.name);
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }

  /** An exclusive take of one matching entry under the space's strategy; the bid function prices it under AUCTION. */
  async take<T>(template: Template<T>, lease: number | string = "1m",
                timeout: number | string = "15s"): Promise<Taken<T> | null> {
    const millis = durationMillis(lease);
    const entryId = await this.peer.takeEntry(this.name, template.schema, this.agentName, millis, 600,
      durationMillis(timeout), this.agent, null, (payload, tags) => template.matches(payload, tags),
      this.bidFunction ?? 0.0);
    if (entryId === null) {
      return null;
    }
    const record = this.peer.states.get(entryId)!["record"] as Dict;
    const payload = loads(Buffer.from((record["payload"] as Uint8Array) ?? new Uint8Array([0xf6]))) as Dict;
    return new Taken(this, entryId, template.decode(payload), millis);
  }

  /**
   * Delivers WRITTEN, TAKEN, and COMPLETED events for matching entries as
   * they fold, once per entry and kind, as `"event"` on the subscription.
   */
  watch<T>(template: Template<T>, listener?: (event: SpaceEvent<T>) => void): Subscription<T> {
    const key = this.nextKey++;
    const subscription = new Subscription<T>(this, key);
    if (listener) {
      subscription.on("event", listener);
    }
    this.watchers.set(key, { template: template as Template<unknown>, delivered: new Set(),
      emit: (e) => subscription.emit("event", e) });
    return subscription;
  }

  /** The matching events as an async iterator, until the subscription is closed. */
  events<T>(template: Template<T>): Subscription<T> {
    return this.watch(template);
  }

  unwatch(key: number): void {
    this.watchers.delete(key);
  }

  // ---------------------------------------------------------------- events

  private deliver(dto: Dict, kind: EventKind, markSuffix: string = kind): void {
    const record = (dto["record"] as Dict | undefined) ?? {};
    const entryId = String(record["entryId"]);
    const payload = loads(Buffer.from((record["payload"] as Uint8Array) ?? new Uint8Array([0xf6]))) as Dict;
    const tags = (record["tags"] as Dict | undefined) ?? {};
    for (const { template, delivered, emit } of [...this.watchers.values()]) {
      if (record["type"] !== template.schema || !template.matches(payload, tags)) {
        continue;
      }
      const mark = `${entryId}:${markSuffix}`;
      if (delivered.has(mark)) {
        continue;
      }
      delivered.add(mark);
      const lease = (record["lease"] as Dict | undefined) ?? {};
      emit({ kind, entry: { entryId, value: template.decode(payload), tags: { ...tags },
        issuer: String(record["issuer"]), expiresAtMillis: Number(lease["expiresAtMillis"] ?? 0),
        completed: kind === COMPLETED, taken: kind === TAKEN } });
    }
  }

  onStateFolded(dto: Dict): void {
    if (!this.mine(dto)) {
      return;
    }
    this.deliver(dto, dto["completed"] ? COMPLETED : WRITTEN);
  }

  onClaimFolded(entryId: string): void {
    const dto = this.peer.states.get(entryId);
    if (dto === undefined || !this.mine(dto) || dto["completed"]) {
      return;
    }
    this.deliver(dto, TAKEN);
  }

  /** EXPIRED once per entry whose write lease lapsed while open; REAPPEARED once per lapsed claim epoch. */
  sweep(): void {
    if (this.watchers.size === 0) {
      return;
    }
    const now = this.peer.now();
    for (const [entryId, dto] of [...this.peer.states]) {
      if (!this.mine(dto) || dto["completed"]) {
        continue;
      }
      const record = (dto["record"] as Dict | undefined) ?? {};
      const lease = (record["lease"] as Dict | undefined) ?? {};
      if (Number(lease["expiresAtMillis"] ?? 0) <= now) {
        this.deliver(dto, EXPIRED);
        continue;
      }
      const claim = this.peer.claims.get(entryId)?.["claim"] as Dict | undefined;
      if (claim !== undefined && Number(claim["expiresAtMillis"] ?? 0) <= now) {
        this.deliver(dto, REAPPEARED, `${REAPPEARED}:${String(claim["epoch"])}`);
      }
    }
  }
}

/** One dispatcher per peer, shared by every Space over it, chained after any earlier hooks. */
function install(peer: Peer): Space[] {
  const holder = peer as unknown as { agentspacesSpaces?: Space[] };
  if (holder.agentspacesSpaces === undefined) {
    const spaces: Space[] = [];
    holder.agentspacesSpaces = spaces;
    const previousState = peer.onState;
    const previousClaim = peer.onClaim;
    peer.onState = (dto) => {
      previousState?.(dto);
      for (const s of [...spaces]) {
        s.onStateFolded(dto);
      }
    };
    peer.onClaim = (entryId, signed) => {
      previousClaim?.(entryId, signed);
      for (const s of [...spaces]) {
        s.onClaimFolded(entryId);
      }
    };
    // EXPIRED and REAPPEARED are judged by the clock, not by a fold; the timer
    // never keeps the process alive on its own.
    setInterval(() => {
      for (const s of [...spaces]) {
        try {
          s.sweep();
        } catch {
          // a watcher that throws does not stop the sweep
        }
      }
    }, 250).unref();
  }
  return holder.agentspacesSpaces;
}
