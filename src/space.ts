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
 * events as an emitter and as an async iterator, and the in-flight take in a
 * context store (AsyncLocalStorage on Node, a synchronous scope elsewhere).
 *
 *     @entry("com.acme.Task#v1")
 *     class Task { constructor(public topic = "", public priority = 0) {} }
 *
 *     const space = new Space(peer, "tasks");
 *     space.write(new Task("index", 3), "10m", { region: "eu" });
 *     for (const task of space.readAll(new Template(Task, { priority: gte(3) }, { region: "eu" }))) { ... }
 *     const taken = await space.take(new Template(Task), "1m", "15s");
 *     taken?.complete(new Finding(taken.value.topic, "done"));
 *
 * Leases (SPEC §7.2, v0.1.35): a renewal never shortens. `Taken.renew` extends the take lease and `Subscription.renew`
 * the subscription's, each to the later of its current expiry and now plus the extension; `peer.renewEntry` does the
 * same for a write, for its issuer alone and only while the entry is present and unexpired. `Taken.release()` gives a
 * taken entry back by letting its take lease lapse, and `peer.cancelEntry` ends a write sooner. Nothing here depends
 * on how the peer replicates: it audits toward members whose cards carry `wire.ae=2` and collects withdrawals by their
 * own lease under `wire.horizon=1`, both on by default (`peer.configureReplication`, docs/replication-by-entry.md).
 */

import { Emitter, contextStore } from "./emitter.js";

import { CborDouble, CborValue, loads, readDocument } from "./cbor.js";
import { AgentIdentity, spaceIdLocal } from "./identity.js";
import { leaseExpiryOf, present } from "./peer.js";
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

/** The schema a template names to read or watch every type in a space (a visitor's view); a take names one type. */
export const ANY_TYPE = "*";

/**
 * A query: the entry type (an `@entry` class or a schema string), field
 * conditions, and tag conditions. A plain value means equality; a function is
 * a predicate; `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `oneOf`, `contains`,
 * `isNull`, `notNull` are the Java matchers. The schema {@link ANY_TYPE} (`"*"`)
 * reads and watches every type; each entry then carries its wire type in
 * `Entry.type` and its value is the plain payload.
 */
export class Template<T = unknown> {
  readonly schema: string;
  readonly where: Array<[string, Matcher]>;
  readonly tags: Array<[string, Matcher]>;

  /**
   * @param filters clauses of the portable grammar (`"priority>=3"`, `"region in eu,us"`),
   *                judged as Java and Python judge them (JS-V-03)
   */
  constructor(readonly type: EntryType<T>, where: { [field: string]: Condition } = {},
              tags: { [tag: string]: Condition } = {}, filters: string[] = []) {
    this.schema = schemaOf(type);
    this.where = [...Object.entries(where).map(([k, v]): [string, Matcher] => [k, matcher(v)]),
      ...filters.map(parseFilter)];
    this.tags = Object.entries(tags).map(([k, v]) => [k, matcher(v)]);
  }

  /** Whether an entry of wire type `type` is in this template's scope. */
  accepts(type: unknown): boolean {
    return this.schema === ANY_TYPE || type === this.schema;
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

// ------------------------------------------------------ the portable filter grammar

const FILTER_OPS = ["!=", "<=", ">=", "=", "<", ">", " in "]; // as they appear in a clause
const NUMBER = /^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/;

/** The string form a value compares under, as Java's String.valueOf and Python's str give it for the wire's types. */
function filterForm(value: unknown): string {
  if (value instanceof CborDouble) {
    return filterForm(value.value);
  }
  if (typeof value === "number" || typeof value === "bigint") {
    return String(value);
  }
  return String(value);
}

/** Numeric when both sides are decimal numbers, else the strings' code-unit order (FieldFilter.compare). */
export function filterCompare(form: string, literal: string): number {
  const f = form.trim();
  const l = literal.trim();
  if (NUMBER.test(f) && NUMBER.test(l)) {
    const a = Number(f);
    const b = Number(l);
    return a < b ? -1 : a > b ? 1 : 0;
  }
  return form < literal ? -1 : form > literal ? 1 : 0;
}

/**
 * One clause of the portable field filter grammar (SPEC §7.2; Java
 * `FieldFilter`): `field op literal` with `=`, `!=`, `<`, `<=`, `>`, `>=`, or
 * `field in a,b,c`. A null value matches `!=` alone; numbers compare
 * numerically; everything else by its string form.
 */
export function parseFilter(clause: string): [string, Matcher] {
  const text = clause.trim();
  // The earliest operator in the clause is the operator; at a tie the longest (so "<="
  // beats "<"), and "!=x" is malformed rather than the field "!".
  let best = -1;
  let bestOp = "";
  for (const op of FILTER_OPS) {
    const at = text.indexOf(op);
    if (at >= 0 && (best < 0 || at < best || (at === best && op.length > bestOp.length))) {
      best = at;
      bestOp = op;
    }
  }
  if (best <= 0) {
    throw new Error(`malformed field filter '${clause}'; use "field=value", "field!=value", "field<value",`
      + ` "field<=value", "field>value", "field>=value", or "field in a,b,c"`);
  }
  const field = text.substring(0, best).trim();
  const literal = text.substring(best + bestOp.length).trim();
  const op = bestOp.trim();
  if (op === "in") {
    const elements = literal.split(",").map((e) => e.trim());
    return [field, (value) => value !== null && value !== undefined
      && elements.some((e) => filterCompare(filterForm(value), e) === 0)];
  }
  return [field, (value) => {
    if (value === null || value === undefined) {
      return op === "!=";
    }
    const c = filterCompare(filterForm(value), literal);
    switch (op) {
      case "=": return c === 0;
      case "!=": return c !== 0;
      case "<": return c < 0;
      case "<=": return c <= 0;
      case ">": return c > 0;
      default: return c >= 0;
    }
  }];
}

// --------------------------------------------------------------- the entries

/** An entry as the space holds it: the value and its metadata. */
export type Entry<T> = {
  entryId: string; value: T; tags: Dict; issuer: string; type: string;
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
   * Throws, writing nothing, when the take no longer holds the entry: its lease
   * lapsed, a better claim that reached this replica after the settle window
   * displaced it, or the entry completed meanwhile (SPEC §7.4, the settle
   * guarantee). The completion checked this before, but only after the result
   * was written, so a displaced take left a second result.
   */
  complete(result: object | null = null, lease: number | string = "1h", tags: Dict = {},
           resultSpace: Space | null = null): string | null {
    this.space.peer.requireHeld(this.space.name, this.entryId, this.space.agent);
    // Rule two of the settle guarantee (SPEC §7.4): the holder this take displaced completed the entry, so this take
    // acknowledges that completion with none of its own result, and throws as a lapsed take does.
    if (this.space.peer.acknowledgeDisplacedCompletion(this.space.name, this.entryId, this.space.agent)) {
      throw new Error(`the take of ${this.entryId} acknowledged a displaced holder's completion; no result written`);
    }
    let resultId: string | null = null;
    if (result !== null) {
      resultId = (resultSpace ?? this.space).write(result, lease, tags);
    }
    this.space.peer.completeEntry(this.space.name, this.entryId, this.space.agent);
    return resultId;
  }

  /**
   * Extends the take lease to at least `lease` from now (the take's own lease again when none is given), as Java's
   * `TakenEntry.renew`: it never shortens the hold, so the new expiry is the later of the current one and now plus
   * `lease` (SPEC §7.2, v0.1.35), and a renewal that would change nothing sends nothing. Throws when the take no
   * longer holds the entry. Before v0.1.35 this renewed the entry's write lease, which only its issuer may renew.
   */
  renew(lease: number | string | null = null): void {
    if (this.released) {
      throw new Error(`the take of ${this.entryId} was released; it holds nothing to renew`);
    }
    const millis = lease === null ? this.leaseMillis : durationMillis(lease);
    this.space.peer.renewClaim(this.space.name, this.entryId, millis, this.space.agent);
  }

  /**
   * Gives the entry back: this take renews it no more and lets its take lease lapse, after which the entry reappears
   * for other takers, as Java's taker does. No shorter lease can travel, since a renewal never shortens and the claim
   * lattice keeps the later of two equal claims' expiries, so the release is the lapse. A caller that wanted it back
   * sooner takes with a shorter lease.
   */
  release(): void {
    this.released = true;
  }

  private released = false;
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

/**
 * A take as a worker method's context hands it out (Java's `TakeContext.renew`, srad/agentspaces-event-loop.md §10.33,
 * I-05): its renewal obeys the binder's end, so a library renewing from inside the method (an LLM stream's keepalive)
 * cannot keep a hung handler's entry past the hold limit, after its agent is unbound, or after a wake found its lease
 * lapsed. A refused renewal renews nothing and does not throw, as Java's; the lease lapses to another taker. Completing
 * and releasing go to the take itself.
 */
class ContextTaken<T> extends Taken<T> {
  constructor(private readonly inner: Taken<T>, private readonly renewable: () => boolean,
              private readonly refused: () => void) {
    super(inner.space, inner.entryId, inner.value, inner.leaseMillis);
  }

  override complete(...args: Parameters<Taken<T>["complete"]>): string | null {
    return this.inner.complete(...args);
  }

  override renew(lease: number | string | null = null): void {
    if (!this.renewable()) {
      this.refused();
      return;
    }
    this.inner.renew(lease);
  }

  override release(): void {
    this.inner.release();
  }
}

/** What the binder says about a running take's renewals: whether they may still renew, and a refusal's count. */
export type TakeGuard = { renewable: () => boolean; refused?: () => void };

const currentTake = contextStore<Taken<unknown>>();

/**
 * The take a worker method runs under: the binder runs the call inside it,
 * so a listener (a model call's lease renewal, say) finds it without a parameter.
 * Run with a guard, the context hands out the take with its renewal under the guard.
 */
export const TakeContext = {
  current<T = unknown>(): Taken<T> | null {
    return (currentTake.get() as Taken<T> | undefined) ?? null;
  },
  run<R>(taken: Taken<unknown>, fn: () => R, guard: TakeGuard | null = null): R {
    const held = guard === null ? taken : new ContextTaken(taken, guard.renewable, guard.refused ?? (() => {}));
    return currentTake.run(held, fn);
  },
};

// ----------------------------------------------------------------- the space

/**
 * One watch: its template, the events it has judged (by entry id, the kinds and claim epochs), and
 * its delivery. HLC round five, 2026-11-08: the space never decodes a judged event again, matched or
 * not, since a record's payload and tags never change, and it forgets an entry's marks when the
 * replica collects the entry.
 */
type Watcher = { template: Template<unknown>; judged: Map<string, Set<string>>; emit: (event: SpaceEvent<unknown>) => void };

/**
 * A watch handle: an emitter of `"event"`, closed with `close()`. A leased
 * subscription (`Space.notify`, JS-V-01) closes itself when its lease lapses
 * unless `renew` extends it; the binder renews at half-lease on the agent's
 * behalf, the shape of the Java `Subscription`.
 */
export class Subscription<T> extends Emitter {
  private expiry: unknown = null;
  private leaseMillis: number | null = null;
  private closed = false;

  constructor(private readonly space: Space, private readonly key: number) {
    super();
  }

  /** Whether the subscription is still delivering. */
  get open(): boolean {
    return !this.closed;
  }

  /**
   * Extends the lease to at least `lease` from now (the same length again when none is given), never shorter (SPEC
   * §7.2, v0.1.35, as a write lease): the subscription lapses at the later of its current expiry and now plus `lease`.
   * A lapsed subscription stays closed.
   */
  renew(lease: number | string | null = null): void {
    if (this.closed) {
      return;
    }
    const millis = lease === null ? this.leaseMillis : durationMillis(lease);
    if (millis === null) {
      return; // a watch without a lease never lapses
    }
    this.leaseMillis = millis;
    const now = this.space.peer.now();
    const until = Math.max(this.expiresAt ?? Number.NEGATIVE_INFINITY, now + millis);
    if (this.expiry !== null && until === this.expiresAt) {
      return; // it already runs that long
    }
    this.expiresAt = until;
    const timers = this.space.peer.timers;
    if (this.expiry !== null) {
      timers.clearTimeout(this.expiry);
    }
    this.expiry = timers.setTimeout(() => {
      this.expiry = null;
      this.close("lapsed");
    }, until - now);
  }

  /** When the subscription lapses, on the peer's clock; null for a watch without a lease. */
  private expiresAt: number | null = null;

  close(reason = "closed"): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    if (this.expiry !== null) {
      this.space.peer.timers.clearTimeout(this.expiry);
      this.expiry = null;
    }
    this.space.unwatch(this.key);
    this.emit("close", reason);
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
    peer.joinSpace(name);
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
      if (!template.accepts(record["type"]) || !this.mine(dto) || !present(dto)) {
        continue;
      }
      const expires = leaseExpiryOf(dto);
      if (expires <= now) {
        continue;
      }
      const raw = this.peer.payloadOf(dto);
      const read = raw === null ? null : readDocument(raw);
      if (read === null) {
        continue; // a block or artifact still on its way, or a value no read can decode (HLC round six, 2026-11-08)
      }
      const payload = read.value as Dict;
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
        type: String(record["type"]), expiresAtMillis: expires, completed: false, taken });
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
    // On the peer's monotonic clock and timers (SPEC v0.1.36 §9.5: waits on the time source), woken by a fold rather
    // than polling every 200 ms; the space is pulled at most once per 600 ms settle window.
    const deadline = this.peer.monotonic() + (timeout === null ? 0 : durationMillis(timeout));
    let pulledAt = Number.NEGATIVE_INFINITY;
    for (;;) {
      const found = this.entries(template, 1);
      if (found.length > 0) {
        return found[0]!.value;
      }
      const now = this.peer.monotonic();
      if (now >= deadline) {
        return null;
      }
      if (now - pulledAt >= 600) {
        pulledAt = now;
        this.peer.pullSpace(this.name);
      }
      await this.peer.awaitFold(Math.min(600, deadline - now));
    }
  }

  /**
   * An exclusive take of one matching entry under the space's strategy; the bid function prices it under AUCTION.
   * The take waits a 600 ms settle window and then up to 300 ms for a last pull to fold before it judges its claim,
   * so its lease must be longer than 900 ms (a shorter one throws a RangeError); leave a margin for late timers.
   */
  async take<T>(template: Template<T>, lease: number | string = "1m",
                timeout: number | string = "15s"): Promise<Taken<T> | null> {
    const millis = durationMillis(lease);
    const entryId = await this.peer.takeEntry(this.name, template.schema, this.agentName, millis, 600,
      durationMillis(timeout), this.agent, null, (payload, tags) => template.matches(payload, tags),
      this.bidFunction ?? 0.0);
    if (entryId === null) {
      return null;
    }
    const payload = loads(this.peer.payloadOf(this.peer.states.get(entryId)!) ?? new Uint8Array([0xf6])) as Dict;
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
    this.watchers.set(key, { template: template as Template<unknown>, judged: new Map(),
      emit: (e) => subscription.emit("event", e) });
    this.peer.loop.wake(SPACE_SWEEP_TASK); // a lapse already past is judged for the new watcher at once
    return subscription;
  }

  /** The matching events as an async iterator, until the subscription is closed. */
  events<T>(template: Template<T>): Subscription<T> {
    return this.watch(template);
  }

  /**
   * The leased push subscription of the Java space (JS-V-01): events reach
   * `listener` as they fold, and the subscription lapses after `lease` unless
   * renewed. A watch that outlives its owner never leaks: the lease ends it.
   */
  notify<T>(template: Template<T>, listener: (event: SpaceEvent<T>) => void,
            lease: number | string = "1h"): Subscription<T> {
    const subscription = this.watch(template, listener);
    subscription.renew(lease);
    return subscription;
  }

  unwatch(key: number): void {
    this.watchers.delete(key);
  }

  // ---------------------------------------------------------------- events

  /**
   * Delivers one event of an entry to every watcher that has not judged it yet. The marks come
   * first: when every watcher has judged the event, the space neither reads nor decodes the payload
   * (HLC round five, 2026-11-08: a live console page spent 95% of its main thread decoding lapsed
   * entries it had already reported).
   */
  private deliver(dto: Dict, kind: EventKind, mark: string = kind): boolean {
    const record = (dto["record"] as Dict | undefined) ?? {};
    const entryId = String(record["entryId"]);
    const judging: Watcher[] = [];
    for (const watcher of this.watchers.values()) {
      if (watcher.template.accepts(record["type"]) && !watcher.judged.get(entryId)?.has(mark)) {
        judging.push(watcher);
      }
    }
    if (judging.length === 0) {
      return true;
    }
    const raw = this.peer.payloadOf(dto);
    if (raw === null) {
      return false; // a referenced payload not here yet: the event waits for a later fold, read or sweep
    }
    const read = readDocument(raw);
    if (read === null) {
      // HLC round six, 2026-11-08: a value no read can decode announces nothing, judged once.
      for (const { judged } of judging) {
        judged.set(entryId, (judged.get(entryId) ?? new Set<string>()).add(mark));
      }
      return true;
    }
    const payload = read.value as Dict;
    const tags = (record["tags"] as Dict | undefined) ?? {};
    for (const { template, judged, emit } of judging) {
      const marks = judged.get(entryId) ?? new Set<string>();
      judged.set(entryId, marks.add(mark));
      if (!template.matches(payload, tags)) {
        continue;
      }
      emit({ kind, entry: { entryId, value: template.decode(payload), tags: { ...tags },
        issuer: String(record["issuer"]), type: String(record["type"]), expiresAtMillis: leaseExpiryOf(dto),
        completed: kind === COMPLETED, taken: kind === TAKEN } });
    }
    return true;
  }

  /**
   * WRITTEN or COMPLETED for a state that folds present or completed. A withdrawn state announces nothing
   * (HLC round five, 2026-11-08) unless it withdraws an entry this replica held present: a cancel then raises
   * EXPIRED, the kind a lapse raises, as Java's ReplicatedSpace and LocalSpace raise it, once per watcher with
   * the sweep's EXPIRED (core cancel events, 2026-11-09).
   */
  onStateFolded(dto: Dict, previous?: Dict): void {
    if (!this.mine(dto)) {
      return;
    }
    if (dto["completed"] || present(dto)) {
      this.deliver(dto, dto["completed"] ? COMPLETED : WRITTEN);
      if (present(dto) && this.watchers.size > 0) {
        sweepBy(this.peer, leaseExpiryOf(dto)); // the lapse is due work: EXPIRED at the lease's end, not on a ticker
      }
    } else if (previous !== undefined && present(previous)) {
      this.deliver(dto, EXPIRED);
    }
  }

  /**
   * TAKEN once per claim epoch while the claim is in force, as Java's ReplicatedSpace fires it (HLC
   * round six, 2026-11-08, R9): a later take of an entry whose earlier take lapsed is heard again, and
   * a claim already expired announces nothing.
   */
  onClaimFolded(entryId: string): void {
    const dto = this.peer.states.get(entryId);
    const claim = this.peer.claims.get(entryId)?.["claim"] as Dict | undefined;
    if (dto === undefined || claim === undefined || !this.mine(dto) || !present(dto)
        || Number(claim["expiresAtMillis"]) <= this.peer.now()) {
      return;
    }
    this.deliver(dto, TAKEN, `${TAKEN}:${String(claim["epoch"])}`);
    if (this.watchers.size > 0) {
      sweepBy(this.peer, Number(claim["expiresAtMillis"])); // REAPPEARED at the claim's lapse
    }
  }

  /** Forgets what every watcher judged of entries the replica collected (SPEC §7.3, HLC round five, 2026-11-08). */
  onCollected(entryIds: string[]): void {
    for (const { judged } of this.watchers.values()) {
      for (const entryId of entryIds) {
        judged.delete(entryId);
      }
    }
  }

  /**
   * EXPIRED once per present entry whose lease (renewed or not) lapsed; REAPPEARED once per lapsed
   * claim epoch. A lapse every watcher already judged costs a lookup and no decode (HLC round five,
   * 2026-11-08).
   */
  sweep(): number | null {
    if (this.watchers.size === 0) {
      return null;
    }
    const now = this.peer.now();
    let next: number | null = null;
    const due = (at: number): void => {
      next = next === null ? at : Math.min(next, at);
    };
    for (const [entryId, dto] of this.peer.states) {
      if (!this.mine(dto) || !present(dto)) {
        continue;
      }
      const expiry = leaseExpiryOf(dto);
      if (expiry <= now) {
        if (!this.deliver(dto, EXPIRED)) {
          due(now + SWEEP_RETRY_MILLIS); // its payload is still on its way: judged again shortly
        }
        continue;
      }
      due(expiry);
      const claim = this.peer.claims.get(entryId)?.["claim"] as Dict | undefined;
      if (claim !== undefined) {
        const lapse = Number(claim["expiresAtMillis"] ?? 0);
        if (lapse <= now) {
          if (!this.deliver(dto, REAPPEARED, `${REAPPEARED}:${String(claim["epoch"])}`)) {
            due(now + SWEEP_RETRY_MILLIS);
          }
        } else {
          due(lapse);
        }
      }
    }
    return next;
  }
}

/** How soon a sweep judges again a lapse whose event waits for its payload. */
const SWEEP_RETRY_MILLIS = 1_000;

/** The name of the space sweep on the peer's loop. */
export const SPACE_SWEEP_TASK = "space-sweep";

/**
 * Brings the peer's space sweep forward to the wall instant `wallMillis` when that is sooner than its deadline (SPEC
 * v0.1.36 §9.5: the space sweep runs when the earliest lapse falls due, and on each fold).
 */
function sweepBy(peer: Peer, wallMillis: number): void {
  if (!Number.isFinite(wallMillis)) {
    return;
  }
  const loop = peer.loop;
  const at = loop.now() + Math.max(0, wallMillis - peer.now());
  const current = loop.dueOf(SPACE_SWEEP_TASK);
  if (current === null || at < current) {
    loop.reschedule(SPACE_SWEEP_TASK, at);
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
    const previousCollected = peer.onCollected;
    peer.onState = (dto, previous) => {
      previousState?.(dto, previous);
      for (const s of [...spaces]) {
        s.onStateFolded(dto, previous);
      }
    };
    peer.onClaim = (entryId, signed) => {
      previousClaim?.(entryId, signed);
      for (const s of [...spaces]) {
        s.onClaimFolded(entryId);
      }
    };
    peer.onCollected = (entryIds) => {
      previousCollected?.(entryIds);
      for (const s of [...spaces]) {
        s.onCollected(entryIds);
      }
    };
    // EXPIRED and REAPPEARED are judged by the clock, not by a fold: due work on the peer's loop at the earliest
    // lapse of any watched entry (SPEC v0.1.36 §9.5; was a 250 ms ticker), brought forward by each fold and by a new
    // watcher, and asked again on a wall step. The loop's timer never keeps the process alive on its own.
    peer.loop.add(SPACE_SWEEP_TASK, (nowMono) => {
      let next: number | null = null;
      for (const s of [...spaces]) {
        try {
          const at = s.sweep();
          if (at !== null) {
            next = next === null ? at : Math.min(next, at);
          }
        } catch {
          // a watcher that throws does not stop the sweep; the space is judged again shortly
          next = Math.min(next ?? Number.POSITIVE_INFINITY, peer.now() + SWEEP_RETRY_MILLIS);
        }
      }
      return next === null ? null : nowMono + Math.max(0, next - peer.now());
    }, null);
  }
  return holder.agentspacesSpaces;
}
