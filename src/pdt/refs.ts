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
 * Refs (srad/agentspaces-pdt.md §3.6, group R, §10.2): a ref is the set of live `PRef` entries with one
 * `name` in one space; its heads are the entries no other live entry of a larger `seq` names as a base,
 * equal roots folded into the entry of the largest `seq`. `deref` returns the single head's value or the
 * deterministic merge of §3.6.1 and never writes; `swap(f)` reads the heads, applies `f`, writes the new
 * nodes (inline on the head up to 32 KiB, else by request), writes a head whose `base` lists the heads
 * read and whose `seq` is one more than their largest, and cancels the superseded heads this writer
 * wrote after a grace of two gossip rounds. In `linear` mode `swap` takes the head with `Space.take` and
 * completes it with the successor, the `@SpaceReduce` pattern.
 *
 * `PRef#v1` in Java field order: v, name, kind, root, base, seq, size, nodes (optional), mode, sealing,
 * keyEpoch (optional), attrs (optional); tags `name` and `root`.
 */

import { compare, utf8 } from "../bytes.js";
import { canonicalMap, dumps, loads } from "../cbor.js";
import { cryptoPort } from "../crypto.js";
import { spaceIdLocal } from "../identity.js";
import type { Peer } from "../peer.js";
import { Space, Subscription, Template, eq } from "../space.js";
import * as wire from "../wire.js";
import type { Dict } from "../wire.js";
import { PBlob } from "./blob.js";
import { PMap, PSet } from "./champ.js";
import * as cids from "./cids.js";
import { links as nodeLinks } from "./nodes.js";
import { NodeStore } from "./store.js";
import type { TreeExchange, TreeFetch } from "./tree.js";
import type { CborValue } from "../cbor.js";
import { PVector } from "./vector.js";

export const PREF_TYPE = "ai.badmonkey.agentspaces.agent.pdt.PRef#v1";
export const VERSION = 1;
export const NAME_TAG = "name", ROOT_TAG = "root";
export const KINDS = new Set(["map", "set", "vector", "blob", "tree"]);
export const MODE_MULTI = "multi", MODE_LINEAR = "linear";
export const SEALING_NONE = "none", SEALING_GROUP_KEY = "group-key", SEALING_SEALED_NODES = "sealed-nodes";
export const MAX_NAME_BYTES = 256;
export const MAX_BASE = 8;
export const INLINE_DELTA_BYTES = 32 * 1024;
export const MAX_ATTRS = 32;
export const MAX_ATTRS_BYTES = 4 * 1024;
export const MAX_MODE_BYTES = 32;
export const MAX_SEQ = 2 ** 53;
export const ISSUED_ATTR = "pdt.issued", ISSUER_ATTR = "pdt.issuer";
export const DEFAULT_HEAD_LEASE_MILLIS = 10 * 60 * 1000;
export const CANCEL_GRACE_MILLIS = 2000;
export const MAX_BASE_STEPS = 64;
export const MAX_ENTRIES = 4096;
const EMPTY_BASE = "";

export type RefKindName = "map" | "set" | "vector" | "blob" | "tree";

export interface PRefFields {
  name: string;
  kind: RefKindName | string;
  root: string;
  base?: string[];
  seq: number;
  size: number;
  nodes?: Uint8Array[] | null;
  mode?: string;
  sealing?: string;
  keyEpoch?: number | null;
  attrs?: { [key: string]: string } | null;
}

/** A `PRef` head in Java field order; the three optional fields are absent when null. */
export function pref(fields: PRefFields): Dict {
  const out: Dict = { v: VERSION, name: fields.name, kind: fields.kind, root: fields.root, base: fields.base ?? [],
    seq: fields.seq, size: fields.size };
  if (fields.nodes != null) {
    out["nodes"] = fields.nodes;
  }
  out["mode"] = fields.mode ?? MODE_MULTI;
  out["sealing"] = fields.sealing ?? SEALING_NONE;
  if (fields.keyEpoch != null) {
    out["keyEpoch"] = fields.keyEpoch;
  }
  if (fields.attrs != null) {
    out["attrs"] = canonicalMap({ ...fields.attrs });
  }
  return out;
}

export function prefTags(head: Dict): Dict {
  return { [NAME_TAG]: head["name"], [ROOT_TAG]: head["root"] };
}

/** The first rule a head breaks, or null (PD-R-01 bounds). */
export function prefViolation(h: Dict): string | null {
  if (h["v"] !== VERSION) {
    return `unsupported PRef version ${String(h["v"])}`;
  }
  const name = h["name"];
  if (typeof name !== "string" || name.length === 0) {
    return "empty name";
  }
  if (utf8(name).length > MAX_NAME_BYTES) {
    return `name longer than ${MAX_NAME_BYTES} bytes`;
  }
  if (typeof h["kind"] !== "string" || !KINDS.has(h["kind"])) {
    return `unknown kind ${String(h["kind"])}`;
  }
  if (typeof h["root"] !== "string" || h["root"].length === 0) {
    return "empty root";
  }
  if (!cids.isCid(h["root"])) {
    return "root is not a CID";
  }
  const base = h["base"] ?? [];
  if (!Array.isArray(base)) {
    return "base is not a list";
  }
  if (base.length > MAX_BASE) {
    return `more than ${MAX_BASE} bases`;
  }
  for (const b of base) {
    if (typeof b !== "string" || b.length === 0) {
      return "empty base root";
    }
    if (!cids.isCid(b)) {
      return "base root is not a CID";
    }
  }
  const seq = h["seq"];
  if (typeof seq !== "number" || seq < 0) {
    return "negative seq";
  }
  if (seq > MAX_SEQ) {
    return `seq above ${MAX_SEQ}`;
  }
  if (typeof h["size"] !== "number" || h["size"] < 0) {
    return "negative size";
  }
  const nodes = h["nodes"];
  if (nodes != null) {
    if (!Array.isArray(nodes)) {
      return "nodes is not a list";
    }
    let total = 0;
    for (const n of nodes) {
      if (!(n instanceof Uint8Array) || n.length === 0) {
        return "empty inline node";
      }
      total += n.length;
    }
    if (total > INLINE_DELTA_BYTES) {
      return `inline nodes larger than ${INLINE_DELTA_BYTES} bytes`;
    }
  }
  for (const field of ["mode", "sealing"]) {
    const v = h[field];
    if (typeof v !== "string" || v.length === 0) {
      return `empty ${field}`;
    }
    if (utf8(v).length > MAX_MODE_BYTES) {
      return `${field} longer than ${MAX_MODE_BYTES} bytes`;
    }
  }
  if (h["keyEpoch"] != null && (typeof h["keyEpoch"] !== "number" || h["keyEpoch"] < 0)) {
    return "negative keyEpoch";
  }
  const attrs = h["attrs"];
  if (attrs != null) {
    if (typeof attrs !== "object" || Array.isArray(attrs) || attrs instanceof Uint8Array) {
      return "attrs is not a map";
    }
    const entries = Object.entries(attrs);
    if (entries.length > MAX_ATTRS) {
      return `more than ${MAX_ATTRS} attrs`;
    }
    let bytes = 0;
    for (const [k, v] of entries) {
      if (typeof v !== "string") {
        return "an attr is not text";
      }
      bytes += utf8(k).length + utf8(v).length;
    }
    if (bytes > MAX_ATTRS_BYTES) {
      return `attrs larger than ${MAX_ATTRS_BYTES} bytes`;
    }
  }
  return null;
}

// ------------------------------------------------------------------ heads

export interface Head {
  root: string;
  base: string[];
  seq: number;
  size: number;
  kind: string;
  mode: string;
  /** The issuing agent id (`<peerId>/<localName>`). */
  issuer: string;
  /** The HLC the head was issued at (the reserved attr of a rewrite, else the entry's own stamp). */
  issued: string;
  entryId: string;
  expiresAtMillis: number;
}

/** Java's AgentId.parse rule: `<peerId>/<localName>`, the slash neither first nor last. */
function agentIdShaped(text: string): boolean {
  const slash = text.indexOf("/");
  return slash > 0 && slash < text.length - 1;
}

function issuerPeer(issuer: string): string {
  const slash = issuer.indexOf("/");
  return slash < 0 ? issuer : issuer.slice(0, slash);
}

/** The merge order (§3.6.1): issued HLC, then issuer peer id bytes, then root. */
export function mergeOrder(a: Head, b: Head): number {
  return wire.compareHlc(a.issued, b.issued) || compare(utf8(issuerPeer(a.issuer)), utf8(issuerPeer(b.issuer)))
    || (a.root < b.root ? -1 : a.root > b.root ? 1 : 0);
}

/** The heads among live entries: not superseded by a base link of a larger seq, equal roots folded. */
export function headsAmong(entries: Head[]): Head[] {
  const supersededBelow = new Map<string, number>();
  for (const head of entries) {
    const by = head.seq >= MAX_SEQ ? Number.POSITIVE_INFINITY : head.seq;
    for (const base of head.base) {
      supersededBelow.set(base, Math.max(supersededBelow.get(base) ?? 0, by));
    }
  }
  const byRoot = new Map<string, Head>();
  for (const head of [...entries].sort(mergeOrder)) {
    const by = supersededBelow.get(head.root);
    if (by !== undefined && by > head.seq) {
      continue;
    }
    const kept = byRoot.get(head.root);
    if (kept === undefined || head.seq > kept.seq) {
      byRoot.set(head.root, head);
    }
  }
  return [...byRoot.values()].sort(mergeOrder);
}

// ------------------------------------------------------------------ kinds

export interface RefKind<T> {
  readonly name: RefKindName;
  empty(store: NodeStore): T;
  load(store: NodeStore, root: string): T;
  root(value: T): string;
  size(value: T): number;
  /** Whether the merge is key-wise (maps, sets, trees) or whole-head (vectors, blobs). */
  byKey: boolean;
  merge3?(mine: T, base: T, theirs: T, onConflict: (key: string) => void): T;
}

export function kindNamed(name: string): RefKind<unknown> {
  switch (name) {
    case "map":
    case "tree":
      return {
        name: name as RefKindName, byKey: true,
        empty: (store) => PMap.empty(store), load: (store, root) => PMap.load(store, root),
        root: (v) => (v as PMap).root(), size: (v) => (v as PMap).count(),
        merge3: (mine, base, theirs, onConflict) => (mine as PMap).merge3(base as PMap, theirs as PMap, (key, _b, _m, t) => {
          onConflict(String(key));
          return t;
        }),
      };
    case "set":
      return {
        name: "set", byKey: true,
        empty: (store) => PSet.empty(store), load: (store, root) => PSet.load(store, root),
        root: (v) => (v as PSet).root(), size: (v) => (v as PSet).count(),
        merge3: (mine, base, theirs, onConflict) => new PSet((mine as PSet).map.merge3((base as PSet).map, (theirs as PSet).map,
          (key, _b, _m, t) => { onConflict(String(key)); return t; })),
      };
    case "vector":
      return {
        name: "vector", byKey: false,
        empty: (store) => PVector.empty(store), load: (store, root) => PVector.load(store, root),
        root: (v) => (v as PVector).root(), size: (v) => (v as PVector).count(),
      };
    case "blob":
      return {
        name: "blob", byKey: false,
        empty: (store) => PBlob.empty(store), load: (store, root) => PBlob.load(store, root),
        root: (v) => (v as PBlob).root, size: (v) => (v as PBlob).size,
      };
    default:
      throw new Error(`unknown ref kind ${name}; one of map, set, vector, blob, tree`);
  }
}

// ------------------------------------------------------------------ the engine

export type ConflictReason = "LATER_HLC" | "WHOLE_HEAD" | "NO_COMMON_BASE" | "MERGE_FUNCTION_FAILED";

export interface PConflict { name: string; key: string | null; winnerRoot: string; loserRoot: string; reason: ConflictReason }

export type MergeFunction<T> = (base: T | null, earlier: T, later: T) => T;

export interface RefsConfig {
  headLeaseMillis: number;
  cancelGraceMillis: number;
  inlineDelta: number;
  loadTimeoutMillis: number;
  follow: "full" | "lazy";
  sealing: string;
  retainVersions: number;
  retainAgeMillis: number;
  takeLeaseMillis: number;
  takeTimeoutMillis: number;
  takeRetries: number;
  modes: { [name: string]: string };
}

export const DEFAULT_CONFIG: RefsConfig = {
  headLeaseMillis: DEFAULT_HEAD_LEASE_MILLIS, cancelGraceMillis: CANCEL_GRACE_MILLIS, inlineDelta: INLINE_DELTA_BYTES,
  loadTimeoutMillis: 10_000, follow: "full", sealing: SEALING_NONE, retainVersions: 64, retainAgeMillis: 60 * 60 * 1000,
  takeLeaseMillis: 60_000, takeTimeoutMillis: 15_000, takeRetries: 3, modes: {},
};

interface Own { entryId: string; root: string; base: string[]; writtenAt: number; lastRenewMillis: number;
  supersededAtMillis: number | null; displaced: boolean }

interface Pending { fetch: TreeFetch; head: Head; base: boolean; timedOut: boolean }

class State {
  readonly spaceId: string;
  readonly template: Template<unknown>;
  readonly own = new Map<string, Own>();
  readonly ownEntries = new Set<string>();
  readonly ownRoots = new Set<string>();
  readonly pinned = new Set<string>();
  readonly heldRoots = new Set<string>();
  readonly known = new Map<string, Head>();
  readonly ignoredEntries = new Set<string>();
  readonly pending = new Map<string, Pending>();
  readonly unloadable = new Set<string>();
  readonly fetchedRoots = new Set<string>();
  readonly recheck = new Map<string, Head>();
  readonly takenEntries = new Set<string>();
  /** Entries whose inline nodes were already offered to the store. */
  readonly inlineTried = new Set<string>();
  readonly versions: { root: string; at: number }[] = [];
  readonly listeners: ((value: unknown, head: Head) => void)[] = [];
  readonly conflictListeners: ((event: PConflict) => void)[] = [];
  lastHeads: Head[] = [];
  previousLive = new Set<string>();
  liveIds = new Set<string>();
  subscription: Subscription<unknown> | null = null;

  constructor(readonly name: string, readonly kind: RefKind<unknown>, readonly space: Space, readonly mode: string) {
    this.spaceId = spaceIdLocal(`${space.peer.group}/${space.name}`);
    this.template = new Template(PREF_TYPE, {}, { [NAME_TAG]: eq(name) });
  }

  linear(): boolean {
    return this.mode === MODE_LINEAR;
  }
}

/** The handle of one ref. */
export class Ref<T = unknown> {
  constructor(private readonly refs: Refs, private readonly state: State) {}

  get name(): string {
    return this.state.name;
  }

  get kind(): RefKindName {
    return this.state.kind.name;
  }

  get mode(): string {
    return this.state.mode;
  }

  get space(): Space {
    return this.state.space;
  }

  /** The value of the single head, or the merge of several; never writes. */
  deref(): Promise<T> {
    return this.refs.deref(this.state) as Promise<T>;
  }

  /** Applies `f` to the current value and publishes the result as a new head. */
  swap(f: (value: T) => T | Promise<T>): Promise<T> {
    return this.refs.swap(this.state, f as (value: unknown) => unknown) as Promise<T>;
  }

  /** Delivers each new head's value once its root is held here. */
  watch(listener: (value: T, head: Head) => void): () => void {
    const wrapped = listener as (value: unknown, head: Head) => void;
    this.state.listeners.push(wrapped);
    return () => {
      const i = this.state.listeners.indexOf(wrapped);
      if (i >= 0) {
        this.state.listeners.splice(i, 1);
      }
    };
  }

  onConflict(listener: (event: PConflict) => void): () => void {
    this.state.conflictListeners.push(listener);
    return () => {
      const i = this.state.conflictListeners.indexOf(listener);
      if (i >= 0) {
        this.state.conflictListeners.splice(i, 1);
      }
    };
  }

  /** The current heads (loadable live entries no live entry supersedes). */
  heads(): Head[] {
    return this.refs.heads(this.state);
  }

  /** Up to `n` earlier versions, newest first, by walking base links over the versions known here. */
  history(n: number): Head[] {
    return this.refs.history(this.state, n);
  }

  /** Any held version as a value. */
  at(root: string): T {
    return this.state.kind.load(this.refs.store, root) as T;
  }
}

export class Refs {
  private readonly states = new Map<string, State>();
  private readonly mergeFunctions = new Map<string, MergeFunction<unknown>>();
  private readonly completeCache = new Map<string, boolean>();
  deltasInline = 0;
  deltasFetched = 0;
  conflicts = 0;
  bytesReceived = 0;
  headsIgnored = 0;
  nodesDropped = 0;
  headsRewritten = 0;
  basesFetched = 0;
  closed = false;

  constructor(readonly peer: Peer, readonly store: NodeStore, readonly exchange: TreeExchange | null,
              readonly config: RefsConfig = DEFAULT_CONFIG) {}

  private now(): number {
    return this.peer.now();
  }

  // ---- held roots

  held(root: string): boolean {
    if (!cids.isCid(root)) {
      return false;
    }
    const cached = this.completeCache.get(root);
    if (cached === true) {
      return true;
    }
    const complete = this.store.complete(root);
    if (complete) {
      this.completeCache.set(root, true);
      if (this.completeCache.size > 4096) {
        this.completeCache.delete(this.completeCache.keys().next().value!);
      }
    }
    return complete;
  }

  /** Forgets cached completeness (after a collection removed nodes). */
  forgetHeld(): void {
    this.completeCache.clear();
  }

  // ---- refs

  ref<T>(space: Space, name: string, kind: string): Ref<T> {
    const key = `${space.name}/${name}`;
    let state = this.states.get(key);
    if (state === undefined) {
      if (utf8(name).length > MAX_NAME_BYTES || name.length === 0) {
        throw new Error(`a ref name is 1 to ${MAX_NAME_BYTES} bytes`);
      }
      state = new State(name, kindNamed(kind), space, this.config.modes[name] ?? MODE_MULTI);
      this.states.set(key, state);
      this.subscribe(state);
      // heads that arrived before the ref existed: their inline deltas are taken and their fetches started now
      for (const head of this.liveEntries(state)) {
        this.onHead(state, head);
      }
    } else if (state.kind.name !== kind) {
      throw new Error(`ref ${name} is a ${state.kind.name}, asked for as a ${kind}`);
    }
    return new Ref<T>(this, state);
  }

  mergeFor<T>(name: string, fn: MergeFunction<T>): void {
    this.mergeFunctions.set(name, fn as MergeFunction<unknown>);
  }

  names(): string[] {
    return [...this.states.values()].map((s) => s.name);
  }

  private subscribe(state: State): void {
    // a watch without a lease: the engine closes it itself, and no timer outlives the peer
    state.subscription = state.space.watch(state.template, (event) => {
      if (this.closed) {
        return;
      }
      const entry = event.entry;
      if (event.kind === "TAKEN") {
        state.takenEntries.add(entry.entryId);
        return;
      }
      if (event.kind === "COMPLETED" || event.kind === "EXPIRED") {
        state.takenEntries.delete(entry.entryId);
        return;
      }
      if (event.kind === "REAPPEARED") {
        state.takenEntries.delete(entry.entryId);
      }
      const dto = this.peer.states.get(entry.entryId);
      if (dto === undefined) {
        return;
      }
      const head = this.toHead(state, dto);
      if (head === null) {
        return;
      }
      this.onHead(state, head);
    });
  }

  /** Offers a head's inline nodes to the store once (PD-X-07): each verified by the CID that reaches it from the root. */
  private acceptInlineOf(state: State, head: Head): void {
    if (state.inlineTried.has(head.entryId) || state.ownEntries.has(head.entryId) || state.ownRoots.has(head.root)) {
      return;
    }
    state.inlineTried.add(head.entryId);
    if (state.inlineTried.size > MAX_ENTRIES) {
      state.inlineTried.delete(state.inlineTried.values().next().value!);
    }
    const dto = this.peer.states.get(head.entryId);
    const payload = dto === undefined ? null : this.peer.payloadOf(dto);
    if (payload === null) {
      return;
    }
    let record: Dict;
    try {
      record = loads(payload) as Dict;
    } catch {
      return;
    }
    const nodes = record["nodes"] as Uint8Array[] | undefined;
    if (nodes === undefined || nodes.length === 0) {
      return;
    }
    const accepted = acceptInline(this.store, head.root, nodes);
    if (accepted.stored > 0) {
      this.deltasInline += 1;
      this.bytesReceived += accepted.bytes;
      this.forgetHeld();
    }
    this.nodesDropped += accepted.dropped;
  }

  private onHead(state: State, head: Head): void {
    const own = state.ownEntries.has(head.entryId) || state.ownRoots.has(head.root);
    this.acceptInlineOf(state, head);
    if (this.held(head.root)) {
      this.arrived(state, head, own);
      return;
    }
    if (this.config.follow === "full" || state.kind.name === "blob") {
      state.recheck.set(head.root, head);
      this.startFetch(state, head);
    }
  }

  private arrived(state: State, head: Head, own: boolean): void {
    if (!own) {
      this.recordVersion(state, head.root);
      this.ensureBases(state, head);
    }
    if (!this.settle(state, head.root)) {
      this.deliver(state, head);
    }
  }

  private deliver(state: State, head: Head): void {
    if (state.listeners.length === 0) {
      return;
    }
    let value: unknown;
    try {
      value = state.kind.load(this.store, head.root);
    } catch {
      return;
    }
    for (const listener of [...state.listeners]) {
      try {
        listener(value, head);
      } catch {
        // a listener's failure is its own
      }
    }
  }

  /** A fetched root arrived: delivers the head that asked for it. */
  private settle(state: State, root: string): boolean {
    const pending = state.pending.get(root);
    if (pending === undefined) {
      return false;
    }
    state.pending.delete(root);
    if (!pending.base) {
      this.deltasFetched += 1;
      this.bytesReceived += pending.fetch.bytesReceived;
      state.fetchedRoots.add(root);
      this.deliver(state, pending.head);
    }
    return true;
  }

  private recordVersion(state: State, root: string): void {
    if (!state.versions.some((v) => v.root === root)) {
      state.versions.push({ root, at: this.now() });
    }
    const now = this.now();
    while (state.versions.length > this.config.retainVersions
           && now - state.versions[0]!.at > this.config.retainAgeMillis) {
      state.versions.shift();
    }
  }

  retainedRoots(state: State): string[] {
    return state.versions.map((v) => v.root).filter((root) => this.held(root));
  }

  // ---- entries and heads

  private toHead(state: State, dto: Dict): Head | null {
    const record = dto["record"] as Dict | undefined;
    if (record === undefined || record === null || record["spaceId"] !== state.spaceId || record["type"] !== PREF_TYPE) {
      return null;
    }
    const payload = this.peer.payloadOf(dto);
    if (payload === null) {
      return null;
    }
    let h: Dict;
    try {
      h = loads(payload) as Dict;
    } catch {
      return null;
    }
    if (typeof h !== "object" || h === null || h["name"] !== state.name || prefViolation(h) !== null) {
      return null;
    }
    const attrs = (h["attrs"] as Dict | null) ?? {};
    // A rewrite carries the original head's stamp and issuer (PD-R-08), so the merge order stays
    // put. As in Java's Refs, the reserved attrs are advisory: a stamp the grammar reads moves the
    // order, a counter above LOGICAL_LIMIT included, and a malformed one leaves the entry's own
    // stamp, which the replica's fold already accepted (HLC canonical stamps, 2026-11-08).
    let issued = String(record["issued"]);
    let issuer = String(record["issuer"]);
    const issuedAttr = attrs[ISSUED_ATTR];
    if (typeof issuedAttr === "string" && wire.decodeHlc(issuedAttr) !== null) {
      issued = issuedAttr;
      const issuerAttr = attrs[ISSUER_ATTR];
      if (typeof issuerAttr === "string" && agentIdShaped(issuerAttr)) {
        issuer = issuerAttr;
      }
    }
    const lease = (record["lease"] as Dict | undefined) ?? {};
    const head: Head = { root: String(h["root"]), base: [...(h["base"] as string[])], seq: Number(h["seq"]), size: Number(h["size"]),
      kind: String(h["kind"]), mode: String(h["mode"]), issuer, issued, entryId: String(record["entryId"]),
      expiresAtMillis: Number(lease["expiresAtMillis"] ?? 0) };
    const known = state.known.get(head.root);
    if (known === undefined || head.seq > known.seq) {
      state.known.set(head.root, { ...head, base: [...new Set([...(known?.base ?? []), ...head.base])] });
    } else {
      known.base = [...new Set([...known.base, ...head.base])];
    }
    if (state.known.size > MAX_ENTRIES) {
      state.known.delete(state.known.keys().next().value!);
    }
    return head;
  }

  /** Whether a state's dot set is live (adds not all removed): a cancelled entry is dead. */
  private static liveDots(dto: Dict): boolean {
    const adds = (dto["adds"] as Dict[] | undefined) ?? [];
    const removes = new Set(((dto["removes"] as Dict[] | undefined) ?? []).map((d) => `${String(d["replica"])}\u0000${Number(d["counter"])}`));
    return adds.some((d) => !removes.has(`${String(d["replica"])}\u0000${Number(d["counter"])}`));
  }

  liveEntries(state: State): Head[] {
    const now = this.now();
    const live: Head[] = [];
    const ids = new Set<string>();
    for (const dto of this.peer.states.values()) {
      const record = dto["record"] as Dict | undefined | null;
      if (record == null || record["spaceId"] !== state.spaceId || record["type"] !== PREF_TYPE || dto["completed"]) {
        continue;
      }
      const lease = (record["lease"] as Dict | undefined) ?? {};
      if (Number(lease["expiresAtMillis"] ?? 0) <= now || !Refs.liveDots(dto)) {
        continue;
      }
      if (((record["tags"] as Dict | undefined) ?? {})[NAME_TAG] !== state.name) {
        continue;
      }
      const head = this.toHead(state, dto);
      if (head === null) {
        continue;
      }
      live.push(head);
      ids.add(head.entryId);
      if (live.length >= MAX_ENTRIES) {
        break;
      }
    }
    state.liveIds = ids;
    return live;
  }

  heads(state: State): Head[] {
    const loadable = this.liveEntries(state).filter((head) => this.loadable(state, head));
    return headsAmong(loadable);
  }

  private loadable(state: State, head: Head): boolean {
    if (this.held(head.root)) {
      return true;
    }
    this.acceptInlineOf(state, head);
    if (this.held(head.root)) {
      return true;
    }
    if (state.ignoredEntries.has(head.entryId) || state.unloadable.has(head.root)) {
      return false;
    }
    this.startFetch(state, head);
    return false;
  }

  /** The heads after waiting (up to the load timeout) for the fetches of live entries not held here. */
  private async loadableHeads(state: State): Promise<Head[]> {
    const live = this.liveEntries(state);
    for (const head of live) {
      if (!this.held(head.root)) {
        this.acceptInlineOf(state, head);
      }
    }
    const waiting = live.filter((head) => !this.held(head.root) && !state.ignoredEntries.has(head.entryId)
      && !state.unloadable.has(head.root));
    for (const head of waiting) {
      this.startFetch(state, head);
    }
    const deadline = this.now() + this.config.loadTimeoutMillis;
    for (const head of waiting) {
      const pending = state.pending.get(head.root);
      if (pending === undefined) {
        continue;
      }
      const left = deadline - this.now();
      if (left > 0 && !pending.fetch.done) {
        await pending.fetch.await(left);
      }
      if (this.held(head.root)) {
        this.settle(state, head.root);
      } else {
        pending.timedOut = true;
        if (state.ignoredEntries.add(head.entryId)) {
          this.headsIgnored += 1;
        }
      }
    }
    return headsAmong(live.filter((head) => this.held(head.root)));
  }

  // ---- fetching

  private startFetch(state: State, head: Head, base = false, haves: string[] | null = null): Pending | null {
    if (this.exchange === null || state.pending.has(head.root) || state.unloadable.has(head.root)) {
      return state.pending.get(head.root) ?? null;
    }
    const fetch = this.exchange.fetchTree(head.root, haves ?? this.retainedRoots(state), [issuerPeer(head.issuer)]);
    const pending: Pending = { fetch, head, base, timedOut: false };
    if (fetch.done) {
      if (fetch.complete) {
        this.forgetHeld();
        return null;
      }
      state.unloadable.add(head.root);
      return null;
    }
    state.pending.set(head.root, pending);
    return pending;
  }

  private ensureBases(state: State, head: Head): void {
    for (const base of head.base) {
      if (this.held(base) || state.pending.has(base) || state.unloadable.has(base)) {
        continue;
      }
      const version = state.known.get(base) ?? { ...head, root: base, base: [], seq: 0 };
      const started = this.startFetch(state, version, true, [head.root, ...this.retainedRoots(state)].filter((r) => this.held(r)));
      if (started !== null) {
        this.basesFetched += 1;
      }
    }
  }

  // ---- reading

  async deref(state: State): Promise<unknown> {
    let heads = await this.loadableHeads(state);
    if (heads.length === 0 && state.linear()) {
      const last = state.lastHeads;
      if (last.length > 0 && last.every((h) => this.held(h.root))) {
        heads = last;
      } else {
        const latest = this.latestHeldVersion(state);
        if (latest !== null) {
          heads = [latest];
        }
      }
    }
    if (heads.length === 0) {
      return state.kind.empty(this.store);
    }
    state.lastHeads = heads;
    return this.materialize(state, heads);
  }

  private latestHeldVersion(state: State): Head | null {
    let best: Head | null = null;
    for (const version of state.known.values()) {
      if (best !== null && (version.seq < best.seq || (version.seq === best.seq && mergeOrder(version, best) <= 0))) {
        continue;
      }
      if (this.held(version.root)) {
        best = version;
      }
    }
    return best;
  }

  private conflict(state: State, event: PConflict): void {
    this.conflicts += 1;
    for (const listener of [...state.conflictListeners]) {
      try {
        listener(event);
      } catch {
        // the listener's failure is its own
      }
    }
  }

  private async materialize(state: State, heads: Head[]): Promise<unknown> {
    if (heads.length === 1) {
      return state.kind.load(this.store, heads[0]!.root);
    }
    const fn = this.mergeFunctions.get(state.name) ?? null;
    const latest = heads[heads.length - 1]!;
    if (fn === null && !state.kind.byKey) {
      for (const other of heads) {
        if (other !== latest) {
          this.conflict(state, { name: state.name, key: null, winnerRoot: latest.root, loserRoot: other.root, reason: "WHOLE_HEAD" });
        }
      }
      return state.kind.load(this.store, latest.root);
    }
    const baseRoot = await this.commonBase(state, heads);
    if (baseRoot === null && fn === null) {
      for (const other of heads) {
        if (other !== latest) {
          this.conflict(state, { name: state.name, key: null, winnerRoot: latest.root, loserRoot: other.root, reason: "NO_COMMON_BASE" });
        }
      }
      return state.kind.load(this.store, latest.root);
    }
    const base = baseRoot === null ? null : baseRoot === EMPTY_BASE ? state.kind.empty(this.store) : state.kind.load(this.store, baseRoot);
    let acc = state.kind.load(this.store, heads[0]!.root);
    for (let i = 1; i < heads.length; i++) {
      const later = heads[i]!, earlier = heads[i - 1]!;
      const laterValue = state.kind.load(this.store, later.root);
      if (fn !== null) {
        try {
          acc = fn(base, acc, laterValue);
          continue;
        } catch {
          this.conflict(state, { name: state.name, key: null, winnerRoot: later.root, loserRoot: earlier.root, reason: "MERGE_FUNCTION_FAILED" });
          if (!state.kind.byKey || baseRoot === null) {
            acc = laterValue;
            continue;
          }
        }
      }
      acc = state.kind.merge3!(acc, base, laterValue, (key) =>
        this.conflict(state, { name: state.name, key, winnerRoot: later.root, loserRoot: earlier.root, reason: "LATER_HLC" }));
    }
    return acc;
  }

  private ancestors(state: State, root: string): Set<string> {
    const seen = new Set<string>();
    const frontier: [string, number][] = [[root, 0]];
    while (frontier.length > 0) {
      const [cid, depth] = frontier.shift()!;
      if (seen.has(cid) || depth >= MAX_BASE_STEPS) {
        continue;
      }
      seen.add(cid);
      const version = state.known.get(cid);
      if (version === undefined) {
        continue;
      }
      for (const base of version.base) {
        if (!seen.has(base)) {
          frontier.push([base, depth + 1]);
        }
      }
    }
    return seen;
  }

  /** The lowest common base by the base-link graph alone (PD-R-06); fetches it from the heads' issuers when not held. */
  private async commonBase(state: State, heads: Head[]): Promise<string | null> {
    if (heads.every((h) => h.base.length === 0)) {
      return EMPTY_BASE;
    }
    const walks = heads.map((h) => this.ancestors(state, h.root));
    const latest = walks[walks.length - 1]!;
    for (const candidate of latest) {
      if (!walks.slice(0, -1).every((w) => w.has(candidate))) {
        continue;
      }
      if (this.held(candidate)) {
        return candidate;
      }
      const version = state.known.get(candidate) ?? { ...heads[heads.length - 1]!, root: candidate, base: [], seq: 0 };
      const haves = heads.map((h) => h.root).filter((r) => this.held(r)).slice(0, 64);
      const pending = this.startFetch(state, version, true, haves);
      if (pending !== null) {
        this.basesFetched += 1;
        await pending.fetch.await(this.config.loadTimeoutMillis);
      }
      if (this.held(candidate)) {
        this.settle(state, candidate);
        return candidate;
      }
      return null;
    }
    return null;
  }

  // ---- writing

  async swap(state: State, f: (value: unknown) => unknown): Promise<unknown> {
    if (this.closed) {
      throw new Error("the refs engine is closed");
    }
    return state.linear() ? this.swapLinear(state, f) : this.swapMulti(state, f);
  }

  private async swapMulti(state: State, f: (value: unknown) => unknown): Promise<unknown> {
    const heads = await this.loadableHeads(state);
    const current = heads.length === 0 ? state.kind.empty(this.store) : await this.materialize(state, heads);
    if (heads.length > 0) {
      state.lastHeads = heads;
    }
    this.store.record();
    let next: unknown;
    let newRoot: string;
    try {
      next = await f(current);
      if (next === null || next === undefined) {
        throw new Error("the swap function returned nothing");
      }
      newRoot = state.kind.root(next);
    } catch (e) {
      this.store.drain();
      throw e;
    }
    const captured = this.store.drain();
    if (heads.length === 1 && heads[0]!.root === newRoot) {
      return next;
    }
    const head = this.head(state, newRoot, next, heads, captured, state.mode);
    this.write(state, head, heads);
    return next;
  }

  private async swapLinear(state: State, f: (value: unknown) => unknown): Promise<unknown> {
    for (let attempt = 0; attempt <= this.config.takeRetries; attempt++) {
      const live = this.liveEntries(state);
      if (live.length === 0 && state.takenEntries.size === 0 && state.lastHeads.length === 0 && state.known.size === 0
          && state.versions.length === 0) {
        return this.swapMulti(state, f);
      }
      const taken = await state.space.take(state.template, this.config.takeLeaseMillis, this.config.takeTimeoutMillis);
      if (taken === null) {
        continue;
      }
      const dto = this.peer.states.get(taken.entryId)!;
      const takenHead = this.toHead(state, dto);
      if (takenHead === null) {
        this.peer.completeEntry(state.space.name, taken.entryId, state.space.agent);
        continue;
      }
      const heads = [takenHead];
      if (!this.held(takenHead.root)) {
        const pending = this.startFetch(state, takenHead);
        if (pending !== null) {
          await pending.fetch.await(this.config.loadTimeoutMillis);
        }
        if (!this.held(takenHead.root)) {
          this.peer.completeEntry(state.space.name, taken.entryId, state.space.agent);
          throw new Error(`the taken head ${takenHead.root} of ${state.name} could not be loaded`);
        }
        this.settle(state, takenHead.root);
      }
      state.lastHeads = heads;
      this.store.record();
      let next: unknown;
      let newRoot: string;
      try {
        next = await f(state.kind.load(this.store, takenHead.root));
        if (next === null || next === undefined) {
          throw new Error("the swap function returned nothing");
        }
        newRoot = state.kind.root(next);
      } catch (e) {
        this.store.drain();
        taken.renew(0);
        throw e;
      }
      const captured = this.store.drain();
      const head = this.head(state, newRoot, next, heads, captured, MODE_LINEAR);
      this.write(state, head, heads);
      this.peer.completeEntry(state.space.name, taken.entryId, state.space.agent);
      state.takenEntries.delete(taken.entryId);
      return next;
    }
    throw new Error(`could not take the head of ${state.name} within ${this.config.takeRetries + 1} attempts`);
  }

  private head(state: State, newRoot: string, next: unknown, heads: Head[], captured: Map<string, Uint8Array>, mode: string): Dict {
    const delta = collectDelta(captured, newRoot);
    let bytes = 0;
    const inline: Uint8Array[] = [];
    for (const node of delta.values()) {
      bytes += node.length;
      inline.push(node);
    }
    const nodes = inline.length > 0 && bytes <= this.config.inlineDelta ? inline : null;
    let base = heads.map((h) => h.root);
    if (base.length > MAX_BASE) {
      base = base.slice(base.length - MAX_BASE);
    }
    const seq = Math.min(Math.max(0, ...heads.map((h) => h.seq)), MAX_SEQ - 1) + 1;
    return pref({ name: state.name, kind: state.kind.name, root: newRoot, base, seq, size: state.kind.size(next), nodes, mode,
      sealing: this.config.sealing });
  }

  private write(state: State, head: Dict, superseded: Head[]): string {
    const violation = prefViolation(head);
    if (violation !== null) {
      throw new Error(`the new head of ${state.name} violates a bound and would be ignored by every reader: ${violation}`);
    }
    const root = String(head["root"]);
    if (state.pinned.add(root)) {
      if (head["nodes"] == null && this.exchange !== null) {
        state.heldRoots.add(root);
        this.exchange.holdTree(root);
      } else {
        this.store.pin(root);
      }
    }
    state.ownRoots.add(root);
    const space = state.space;
    const entryId = this.peer.writeEntry(space.name, PREF_TYPE, head, space.agentName, this.config.headLeaseMillis, space.agent,
      prefTags(head));
    state.ownEntries.add(entryId);
    const now = this.now();
    for (const existing of state.own.values()) {
      if (existing.root === root) {
        existing.displaced = true;
      }
    }
    state.own.set(entryId, { entryId, root, base: [...(head["base"] as string[])], writtenAt: now, lastRenewMillis: now,
      supersededAtMillis: null, displaced: false });
    const oldRoots = new Set(superseded.map((h) => h.root));
    for (const own of state.own.values()) {
      if (oldRoots.has(own.root) && own.supersededAtMillis === null) {
        own.supersededAtMillis = now;
      }
    }
    for (const old of superseded) {
      if (old.root !== root && state.pinned.delete(old.root)) {
        this.unpin(state, old.root);
      }
    }
    this.recordVersion(state, root);
    this.liveEntries(state);
    const mine = state.known.get(root);
    if (mine !== undefined) {
      state.lastHeads = [mine];
    }
    return entryId;
  }

  private unpin(state: State, root: string): void {
    if (state.heldRoots.delete(root) && this.exchange !== null) {
      this.exchange.release(root);
    } else {
      this.store.unpin(root);
    }
  }

  history(state: State, n: number): Head[] {
    const out: Head[] = [];
    const seen = new Set<string>();
    const exclude = new Set(state.lastHeads.map((h) => h.root));
    const start = state.lastHeads.length > 0 ? state.lastHeads : this.heads(state);
    const frontier: string[] = [];
    for (const head of start) {
      frontier.push(...head.base);
    }
    while (frontier.length > 0 && out.length < n) {
      const root = frontier.shift()!;
      if (seen.has(root) || exclude.has(root)) {
        continue;
      }
      seen.add(root);
      const version = state.known.get(root);
      if (version === undefined) {
        continue;
      }
      out.push(version);
      frontier.push(...version.base);
    }
    return out;
  }

  // ---- the tick

  tick(): void {
    if (this.closed) {
      return;
    }
    const now = this.now();
    for (const state of this.states.values()) {
      this.tickState(state, now);
    }
  }

  private tickState(state: State, now: number): void {
    const live = this.liveEntries(state);
    const liveRoots = new Set(live.map((h) => h.root));
    const basesInUse = new Set<string>();
    for (const head of live) {
      for (const b of head.base) {
        basesInUse.add(b);
      }
    }
    for (const [root, head] of [...state.recheck]) {
      state.recheck.delete(root);
      if (this.held(root)) {
        this.arrived(state, head, state.ownRoots.has(root));
      } else if (state.liveIds.has(head.entryId)) {
        this.startFetch(state, head);
      }
    }
    if (this.config.follow === "full") {
      for (const head of live) {
        if (!this.held(head.root) && !state.pending.has(head.root) && !state.unloadable.has(head.root)
            && !state.ignoredEntries.has(head.entryId)) {
          this.acceptInlineOf(state, head);
          if (this.held(head.root)) {
            this.arrived(state, head, state.ownRoots.has(head.root));
          } else {
            this.startFetch(state, head);
          }
        }
      }
    }
    for (const [root, pending] of [...state.pending]) {
      if (this.held(root)) {
        this.forgetHeld();
        this.settle(state, root);
        if (!pending.base) {
          this.recordVersion(state, root);
          this.ensureBases(state, pending.head);
        }
      } else if (pending.fetch.done && !pending.fetch.complete) {
        state.pending.delete(root);
        state.unloadable.add(root);
        if (!pending.base && state.ignoredEntries.add(pending.head.entryId)) {
          this.headsIgnored += 1;
        }
      } else if (!pending.base && !state.liveIds.has(pending.head.entryId) && !basesInUse.has(root)) {
        state.pending.delete(root);
        pending.fetch.cancel();
      }
    }
    for (const id of [...state.ignoredEntries]) {
      if (!state.liveIds.has(id)) {
        state.ignoredEntries.delete(id);
      }
    }
    for (const id of [...state.takenEntries]) {
      if (!state.liveIds.has(id)) {
        state.takenEntries.delete(id);
      }
    }
    for (const root of [...state.unloadable]) {
      if (!liveRoots.has(root) && !basesInUse.has(root)) {
        state.unloadable.delete(root);
      }
    }
    for (const root of [...state.fetchedRoots]) {
      if (!liveRoots.has(root) && !state.pinned.has(root)) {
        state.fetchedRoots.delete(root);
        this.exchange?.release(root);
      }
    }
    const halfLife = this.config.headLeaseMillis / 2;
    const cancellable = this.cancellable(state, live);
    for (const own of [...state.own.values()]) {
      const superseded = cancellable.has(own.root) || (own.displaced && own.base.every((b) => !liveRoots.has(b)));
      if (own.supersededAtMillis === null && superseded) {
        own.supersededAtMillis = now;
      } else if (own.supersededAtMillis !== null && !superseded) {
        own.supersededAtMillis = null;
      }
      if (own.supersededAtMillis !== null) {
        if (now - own.supersededAtMillis >= this.config.cancelGraceMillis) {
          try {
            this.peer.cancelEntry(state.space.name, own.entryId, state.space.agent);
          } catch {
            // already lapsed or gone
          }
          state.own.delete(own.entryId);
          state.ownEntries.delete(own.entryId);
          const rootStillOwn = [...state.own.values()].some((o) => o.root === own.root);
          if (!rootStillOwn && state.pinned.delete(own.root)) {
            this.unpin(state, own.root);
          }
        }
        continue;
      }
      if (now - own.lastRenewMillis >= halfLife) {
        try {
          if (this.peer.states.has(own.entryId) && state.liveIds.has(own.entryId)) {
            this.peer.renewEntry(state.space.name, own.entryId, this.config.headLeaseMillis, state.space.agent);
            own.lastRenewMillis = now;
          } else {
            state.own.delete(own.entryId);
            state.ownEntries.delete(own.entryId);
          }
        } catch {
          // the next tick tries again
        }
      }
    }
    // a lapsed head whose root is held complete here is rewritten under this peer's signature (PD-R-08)
    const candidates = new Set([...state.previousLive, ...state.lastHeads.map((h) => h.root)]);
    state.previousLive = liveRoots;
    for (const root of candidates) {
      const ownRoot = [...state.own.values()].some((o) => o.root === root);
      if (ownRoot || liveRoots.has(root) || basesInUse.has(root)) {
        continue;
      }
      const known = state.known.get(root);
      if (known === undefined || known.expiresAtMillis > now || !this.held(root)) {
        continue;
      }
      this.rewrite(state, known);
    }
  }

  private cancellable(state: State, live: Head[]): Set<string> {
    const loadable: Head[] = [];
    const arriving: Head[] = [];
    for (const head of live) {
      if (this.held(head.root)) {
        loadable.push(head);
      } else if (cids.isCid(head.root) && !state.unloadable.has(head.root)) {
        arriving.push(head);
      }
    }
    const heads = headsAmong(loadable);
    if (heads.length === 0) {
      return new Set();
    }
    const walks = heads.map((h) => this.ancestors(state, h.root));
    const bounds = arriving.map((h) => this.ancestors(state, h.root));
    let lowest: string | null = null;
    for (const candidate of walks[walks.length - 1]!) {
      if (walks.slice(0, -1).every((w) => w.has(candidate)) && bounds.every((w) => w.has(candidate))) {
        lowest = candidate;
        break;
      }
    }
    if (lowest === null) {
      return new Set();
    }
    const below = this.ancestors(state, lowest);
    below.delete(lowest);
    return below;
  }

  private rewrite(state: State, head: Head): void {
    const record = pref({ name: state.name, kind: state.kind.name, root: head.root, base: head.base, seq: head.seq, size: head.size,
      mode: head.mode, sealing: this.config.sealing, attrs: { [ISSUED_ATTR]: head.issued, [ISSUER_ATTR]: head.issuer } });
    if (prefViolation(record) !== null) {
      return;
    }
    state.pinned.add(head.root);
    state.heldRoots.add(head.root);
    this.exchange?.holdTree(head.root);
    if (this.exchange === null) {
      this.store.pin(head.root);
    }
    state.ownRoots.add(head.root);
    let entryId: string;
    try {
      entryId = this.peer.writeEntry(state.space.name, PREF_TYPE, record, state.space.agentName, this.config.headLeaseMillis,
        state.space.agent, prefTags(record));
    } catch {
      if (state.pinned.delete(head.root)) {
        this.unpin(state, head.root);
      }
      return;
    }
    state.ownEntries.add(entryId);
    const now = this.now();
    state.own.set(entryId, { entryId, root: head.root, base: head.base, writtenAt: now, lastRenewMillis: now, supersededAtMillis: null,
      displaced: false });
    this.headsRewritten += 1;
    this.liveEntries(state);
  }

  // ---- collection and stats

  liveRoots(): Set<string> {
    const roots = new Set<string>();
    for (const state of this.states.values()) {
      for (const head of this.liveEntries(state)) {
        roots.add(head.root);
      }
      for (const root of state.pending.keys()) {
        roots.add(root);
      }
      for (const root of state.pinned) {
        roots.add(root);
      }
      for (const v of state.versions) {
        roots.add(v.root);
      }
    }
    return roots;
  }

  refCount(): number {
    return this.states.size;
  }

  headCount(): number {
    let n = 0;
    for (const state of this.states.values()) {
      n += this.heads(state).length;
    }
    return n;
  }

  close(): void {
    this.closed = true;
    for (const state of this.states.values()) {
      state.subscription?.close();
    }
  }
}

// ------------------------------------------------------------------ inline deltas (PD-X-07)

/** The captured nodes reachable from `root`: the exact delta a swap created. */
export function collectDelta(captured: Map<string, Uint8Array>, root: string): Map<string, Uint8Array> {
  const delta = new Map<string, Uint8Array>();
  if (!captured.has(root)) {
    return delta;
  }
  const frontier = [root];
  while (frontier.length > 0) {
    const cid = frontier.shift()!;
    if (delta.has(cid)) {
      continue;
    }
    const bytes = captured.get(cid);
    if (bytes === undefined) {
      continue;
    }
    delta.set(cid, bytes);
    for (const link of linksOrNone(cid, bytes)) {
      if (captured.has(link) && !delta.has(link)) {
        frontier.push(link);
      }
    }
  }
  return delta;
}

function linksOrNone(cid: string, bytes: Uint8Array): string[] {
  try {
    return nodeLinks(bytes, cid);
  } catch {
    return [];
  }
}

export interface Accepted { stored: number; dropped: number; bytes: number }

/** Stores the inline nodes a walk from the root reaches (each verified by the CID that reached it); counts the rest. */
export function acceptInline(store: NodeStore, root: string, nodes: Uint8Array[]): Accepted {
  const byDigest = new Map<string, Uint8Array>();
  const sha256 = cryptoPort().sha256;
  const hex = (d: Uint8Array): string => Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
  for (const node of nodes) {
    if (node.length > 0) {
      const key = hex(sha256(node));
      if (!byDigest.has(key)) {
        byDigest.set(key, node);
      }
    }
  }
  const used = new Set<Uint8Array>();
  const seen = new Set<string>();
  const frontier = [root];
  let stored = 0, bytes = 0;
  while (frontier.length > 0) {
    const cid = frontier.shift()!;
    if (seen.has(cid)) {
      continue;
    }
    seen.add(cid);
    let digest: Uint8Array;
    try {
      digest = cids.parse(cid).digest;
    } catch {
      continue;
    }
    const node = byDigest.get(hex(digest));
    if (node === undefined) {
      continue;
    }
    if (store.has(cid)) {
      used.add(node);
      continue;
    }
    try {
      store.putVerified(cid, node);
    } catch {
      continue;
    }
    used.add(node);
    stored += 1;
    bytes += node.length;
    frontier.push(...linksOrNone(cid, node));
  }
  return { stored, dropped: byDigest.size - used.size + (nodes.length - byDigest.size), bytes };
}

export type { CborValue };
