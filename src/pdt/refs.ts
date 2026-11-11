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
 * keyEpoch (optional), attrs (optional); tags `name` and `root`. A reader takes a head only through
 * {@link decodePRef}, the strict read of the wire encoding (HLC round six, 2026-11-08, F1, F3, R1).
 */

import { compare, equals, utf8 } from "../bytes.js";
import { CborDouble, canonicalMap, dumps, loads, setEntry } from "../cbor.js";
import { cryptoPort } from "../crypto.js";
import { spaceIdLocal } from "../identity.js";
import type { Peer } from "../peer.js";
import { leaseExpiryOf } from "../peer.js";
import { UndecodableError, conform, isAgentId } from "../records.js";
import type { Field, Schema } from "../records.js";
import { Space, Subscription, Template, eq } from "../space.js";
import * as wire from "../wire.js";
import type { Dict } from "../wire.js";
import * as blake3 from "./blake3.js";
import { PBlob } from "./blob.js";
import { PMap, PSet } from "./champ.js";
import * as cids from "./cids.js";
import { DbReader } from "./db.js";
import { VgNode } from "./kinds.js";
import { Link, NodeFormatError, links as nodeLinks } from "./nodes.js";
import * as push from "./push.js";
import { PushReceiver } from "./push.js";
import type { PushConfig } from "./push.js";
import { NodeStore } from "./store.js";
import { TextCodec } from "./text.js";
import { PDT_LEVEL } from "./tree.js";
import type { TreeExchange, TreeFetch } from "./tree.js";
import type { CborValue } from "../cbor.js";
import type { Codec } from "./values.js";
import { PVector } from "./vector.js";

export const PREF_TYPE = "ai.badmonkey.agentspaces.agent.pdt.PRef#v1";
export const VERSION = 1;
/**
 * The record version of a head whose tree holds a node of a kind outside annex H's level-1 set (PDT 2 phase 7, P2-F-06;
 * §6.10.3 rule 8): `db`, `dn`, `rr`, `rv`, or `t`. The schema keeps its twelve fields, so a level-1 reader decodes the
 * record and ignores the head by its version.
 */
export const VERSION_2 = 2;
export const NAME_TAG = "name", ROOT_TAG = "root";
export const KINDS = new Set(["map", "set", "vector", "blob", "tree"]);
/** A DataScript database, a `db` root over `dn` nodes; its heads are always {@link VERSION_2} (P2-D-03). */
export const KIND_DB = "db";
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
/**
 * The reserved attribute naming a head's `vg` node (PDT 2 phase 0, P2-V-01; srad/agentspaces-pdt2.md §3.10,
 * §6.10.3 rule 9): a head is a record every member reads and no writer can gate, so the ancestry rides in
 * `attrs` as text and the `PRef` schema keeps its twelve fields.
 */
export const ANCESTRY_ATTR = "pdt.ancestry";
/** The reserved attributes of a blob head: its BLAKE3 identity and its outboard's root (P2-B-01, §6.10.3 rule 10). */
export const BLAKE3_ATTR = "pdt.blake3", BAO_ATTR = "pdt.bao";
export const DEFAULT_HEAD_LEASE_MILLIS = 10 * 60 * 1000;
export const CANCEL_GRACE_MILLIS = 2000;
export const MAX_BASE_STEPS = 64;
export const MAX_ENTRIES = 4096;
/**
 * The first wait before a root whose fetch failed is fetched again, in milliseconds; each later failure doubles it up to
 * {@link UNLOADABLE_BACKOFF} load timeouts (swarm retries, ROBUSTNESS.md §10.3 E2).
 */
export const RETRY_BASE_MILLIS = 1000;
/** How often a read that waits for an announced push looks again (P2-P-02). */
const PUSH_POLL_MILLIS = 50;
export const UNLOADABLE_BACKOFF = 4;
const EMPTY_BASE = "";

export type RefKindName = "map" | "set" | "vector" | "blob" | "tree" | "db";

export interface PRefFields {
  /** The record version: 1, or {@link VERSION_2} for a head whose tree holds a level-2 kind. */
  v?: number;
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

/**
 * A long field as the wire encoding writes it: an integer, never a float64. A number past 2^53 - 1
 * (a seq saturated at MAX_SEQ) goes out as a bigint, since the codec writes such a number as a
 * double, which every reader refuses for a long (HLC round six, 2026-11-08, F1).
 */
function long(value: number): number | bigint {
  return Number.isSafeInteger(value) ? value : BigInt(value);
}

/** A `PRef` head in Java field order; the three optional fields are absent when null. */
export function pref(fields: PRefFields): Dict {
  const out: Dict = { v: fields.v ?? VERSION, name: fields.name, kind: fields.kind, root: fields.root, base: fields.base ?? [],
    seq: long(fields.seq), size: long(fields.size) };
  if (fields.nodes != null) {
    out["nodes"] = fields.nodes;
  }
  out["mode"] = fields.mode ?? MODE_MULTI;
  out["sealing"] = fields.sealing ?? SEALING_NONE;
  if (fields.keyEpoch != null) {
    out["keyEpoch"] = long(fields.keyEpoch);
  }
  if (fields.attrs != null) {
    out["attrs"] = canonicalMap({ ...fields.attrs });
  }
  return out;
}

export function prefTags(head: Dict): Dict {
  return { [NAME_TAG]: head["name"], [ROOT_TAG]: head["root"] };
}

/** The attrs whose value is an application value (HLC round six, 2026-11-08, R1); every other attr holds text. */
const RESERVED_ATTRS: ReadonlySet<string> = new Set([ISSUED_ATTR, ISSUER_ATTR]);

/** `PRef#v1` as appendix A of the wire encoding lists it, `attrs` aside: {@link decodePRef} reads that field by R1. */
const PREF_FIELDS: readonly Field[] = [["v", "int"], ["name", "String", "nonNull"], ["kind", "String", "nonNull"],
  ["root", "String", "nonNull"], ["base", { listOf: "String" }, "nonNull"], ["seq", "long"], ["size", "long"],
  ["nodes", { listOf: "bytes" }, "omitNull"], ["mode", "String", "nonNull"], ["sealing", "String", "nonNull"],
  ["keyEpoch", "Long", "omitNull"]];
const PREF_RECORD: Schema = { record: "PRef", fields: PREF_FIELDS };

function isMapValue(value: CborValue | undefined): value is Dict {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array)
    && !(value instanceof CborDouble);
}

/**
 * A `PRef` read in the wire encoding (HLC round six, 2026-11-08, F1, F3, R1): the document under the
 * item rules, every field of its declared kind with nothing coerced, `attrs` (when present) a map with
 * text under every key but `pdt.issued` and `pdt.issuer`, which hold any application value, and the
 * whole re-encoding to exactly `bytes`. Throws {@link UndecodableError} (or the codec's RangeError)
 * for anything else, which a reader ignores and counts in `headsIgnored`, as Java's PRef.Attrs does.
 */
export function decodePRef(bytes: Uint8Array): Dict {
  const value = loads(bytes);
  if (!isMapValue(value)) {
    throw new UndecodableError("a PRef is a map");
  }
  const fields: Dict = {};
  for (const key of Object.keys(value)) {
    if (key !== "attrs") {
      setEntry(fields, key, value[key]!);
    }
  }
  const head = conform(fields, PREF_RECORD) as Dict;
  if (Object.hasOwn(value, "attrs")) {
    head["attrs"] = attrsOf(value["attrs"]);
  }
  if (!equals(dumps(head), bytes)) {
    throw new UndecodableError("the PRef is not in the wire encoding's form");
  }
  return head;
}

/** The attrs of {@link decodePRef}: present as a map, never null, in the RFC 8949 key order. */
function attrsOf(value: CborValue | undefined): Dict {
  if (!isMapValue(value)) {
    throw new UndecodableError("attrs are a map, and absent when null");
  }
  const attrs: Dict = {};
  for (const key of Object.keys(value)) {
    const item = value[key]!;
    if (!RESERVED_ATTRS.has(key) && typeof item !== "string") {
      throw new UndecodableError(`the attr ${key} holds no text; only ${ISSUED_ATTR} and ${ISSUER_ATTR} hold anything but text`);
    }
    setEntry(attrs, key, item);
  }
  return canonicalMap(attrs);
}

/**
 * The CID a head names under {@link ANCESTRY_ATTR} when the text is a usable one: a dag-cbor sha2-256 CIDv1
 * in its one base32 form (PDT 2 phase 0, P2-V-02). The attribute is advisory, so any other value reads as a
 * head without ancestry, and nothing is refused or struck.
 */
export function ancestryCid(head: Dict): string | null {
  const attrs = head["attrs"];
  const text = isMapValue(attrs) ? attrs[ANCESTRY_ATTR] : undefined;
  return cids.isCid(text) && cids.parse(text).codec === cids.DAG_CBOR ? text : null;
}

/**
 * The `vg` node of a head from the bytes a store or a fetch returned for {@link ancestryCid}, or null when
 * the head names none, the bytes hash to another CID, or they do not decode as a `vg` node of the head's
 * own root (PDT 2 phase 0, P2-V-02).
 */
export function readAncestry(head: Dict, bytes: Uint8Array): VgNode | null {
  const cid = ancestryCid(head);
  if (cid === null || !cids.verifies(cid, bytes)) {
    return null;
  }
  try {
    const node = VgNode.decode(bytes, cid);
    return node.root === head["root"] ? node : null;
  } catch (e) {
    if (e instanceof NodeFormatError) {
      return null;
    }
    throw e;
  }
}

/**
 * The first rule a head breaks, or null (PD-R-01 bounds). A reader at the PDT feature level 2 (PDT 2 phase 7, P2-F-06)
 * reads `v` 1 and 2 and the kind `db`, whose heads are `v` 2; a reader at level 1 reads `v` 1 heads of the level-1 kinds.
 */
export function prefViolation(h: Dict, level = PDT_LEVEL): string | null {
  if (h["v"] !== VERSION && (level < 2 || h["v"] !== VERSION_2)) {
    return `unsupported PRef version ${String(h["v"])}`;
  }
  if (h["kind"] === KIND_DB && level >= 2 && h["v"] !== VERSION_2) {
    return `a db head is version ${VERSION_2}, found ${String(h["v"])}`;
  }
  const name = h["name"];
  if (typeof name !== "string" || name.length === 0) {
    return "empty name";
  }
  if (utf8(name).length > MAX_NAME_BYTES) {
    return `name longer than ${MAX_NAME_BYTES} bytes`;
  }
  if (typeof h["kind"] !== "string" || !(KINDS.has(h["kind"]) || (level >= 2 && h["kind"] === KIND_DB))) {
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
  // A long arrives as a bigint past 2^53 - 1, so a seq of MAX_SEQ is a bigint here and within the bound.
  const seq = h["seq"];
  if (typeof seq !== "number" && typeof seq !== "bigint") {
    return "seq is no integer";
  }
  if (seq < 0) {
    return "negative seq";
  }
  if (seq > MAX_SEQ) {
    return `seq above ${MAX_SEQ}`;
  }
  const size = h["size"];
  if ((typeof size !== "number" && typeof size !== "bigint") || size < 0) {
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
  const keyEpoch = h["keyEpoch"];
  if (keyEpoch != null && ((typeof keyEpoch !== "number" && typeof keyEpoch !== "bigint") || keyEpoch < 0)) {
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
    // HLC round six, 2026-11-08 (R1): the bound counts the UTF-8 bytes of the keys and the text
    // values; a value under pdt.issued or pdt.issuer that is no text counts nothing.
    let bytes = 0;
    for (const [k, v] of entries) {
      bytes += utf8(k).length + (typeof v === "string" ? utf8(v).length : 0);
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
  /** The bundles the head announces under `pdt.push` (PDT 2 phase 7, P2-P-02); absent or 0 when it announces none. */
  push?: number;
  /**
   * A blob head's BLAKE3 identity and the root of its Bao outboard, from `pdt.blake3` and `pdt.bao` (PDT 2 phase 7,
   * P2-B-01, rule 10): advisory, absent when the head names none or names them in another form. `Pdt.openVerified`
   * reads a window against them.
   */
  blake3?: string;
  bao?: string;
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
  /**
   * The record version of a head over a value (PDT 2 phase 7, §6.10.3 rules 2, 3, 8): 2 for a `db`, for a vector over
   * an `rr` root, and for a ref whose values pass through `PText.codec`; else 1.
   */
  version(value: T): number;
}

/** The options of a ref: the codec of its values (a set's elements), the default CBOR one unless named. */
export interface RefOptions {
  values?: Codec<unknown>;
}

export function kindNamed(name: string, options: RefOptions = {}): RefKind<unknown> {
  const codec = options.values;
  const texts = codec instanceof TextCodec ? VERSION_2 : VERSION;
  switch (name) {
    case "map":
    case "tree":
      return {
        name: name as RefKindName, byKey: true,
        empty: (store) => PMap.empty(store, undefined, codec), load: (store, root) => PMap.load(store, root, undefined, codec),
        root: (v) => (v as PMap).root(), size: (v) => (v as PMap).count(), version: () => texts,
        merge3: (mine, base, theirs, onConflict) => (mine as PMap).merge3(base as PMap, theirs as PMap, (key, _b, _m, t) => {
          onConflict(String(key));
          return t;
        }),
      };
    case "set":
      return {
        name: "set", byKey: true,
        empty: (store) => PSet.empty(store, codec), load: (store, root) => PSet.load(store, root, codec),
        root: (v) => (v as PSet).root(), size: (v) => (v as PSet).count(), version: () => texts,
        merge3: (mine, base, theirs, onConflict) => new PSet((mine as PSet).map.merge3((base as PSet).map, (theirs as PSet).map,
          (key, _b, _m, t) => { onConflict(String(key)); return t; })),
      };
    case "vector":
      return {
        name: "vector", byKey: false,
        empty: (store) => PVector.empty(store, codec), load: (store, root) => PVector.load(store, root, codec),
        root: (v) => (v as PVector).root(), size: (v) => (v as PVector).count(),
        version: (v) => ((v as PVector).relaxed() ? VERSION_2 : texts),
      };
    case "blob":
      return {
        name: "blob", byKey: false,
        empty: (store) => PBlob.empty(store), load: (store, root) => PBlob.load(store, root),
        root: (v) => (v as PBlob).root, size: (v) => (v as PBlob).size, version: () => VERSION,
      };
    case KIND_DB:
      // P2-D-09: this client reads a database through DbReader and writes none
      return {
        name: KIND_DB, byKey: false,
        empty: () => null, load: (store, root) => new DbReader(root, store),
        root: () => {
          throw new Error("a db ref is read-only in this client;"
            + " write db refs with DataScript through agentspaces-datascript");
        },
        size: () => 0, version: () => VERSION_2,
      };
    default:
      throw new Error(`unknown ref kind ${name}; one of map, set, vector, blob, tree, db`);
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
  /** The PDT feature level this engine reads at (P2-F-06): 2 reads `PRef.v` 2 and `db` heads. */
  level: number;
  /** Eager push on the follower's side (PDT 2 phase 7, P2-P-02), or null for off, as Java's default. */
  push: PushConfig | null;
}

export const DEFAULT_CONFIG: RefsConfig = {
  headLeaseMillis: DEFAULT_HEAD_LEASE_MILLIS, cancelGraceMillis: CANCEL_GRACE_MILLIS, inlineDelta: INLINE_DELTA_BYTES,
  loadTimeoutMillis: 10_000, follow: "full", sealing: SEALING_NONE, retainVersions: 64, retainAgeMillis: 60 * 60 * 1000,
  takeLeaseMillis: 60_000, takeTimeoutMillis: 15_000, takeRetries: 3, modes: {}, level: PDT_LEVEL, push: null,
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
  /** Late heads counted, as `entry/cause`, while the entries are live (swarm retries, ROBUSTNESS.md §10.3 E2). */
  readonly lateNoted = new Set<string>();
  readonly pending = new Map<string, Pending>();
  /** Roots whose fetch failed: the failures so far and the clock time the next fetch is due (swarm retries). */
  readonly retries = new Map<string, { failures: number; dueAt: number }>();
  readonly fetchedRoots = new Set<string>();
  readonly recheck = new Map<string, Head>();
  readonly takenEntries = new Set<string>();
  /** Entries whose inline nodes were already offered to the store. */
  readonly inlineTried = new Set<string>();
  readonly versions: { root: string; at: number }[] = [];
  readonly listeners: ((value: unknown, head: Head) => void)[] = [];
  readonly conflictListeners: ((event: PConflict) => void)[] = [];
  /** The `vg` node each version names, by root, from a head's `pdt.ancestry` or a chain link (P2-V-01). */
  readonly ancestry = new Map<string, string>();
  /** The `vg` nodes read, by the root each describes (P2-V-02). */
  readonly chain = new Map<string, VgNode>();
  /** The `vg` nodes whose fetch failed, by CID: the failures so far and when the next ask is due (PDT 2 phase 7 gate). */
  readonly chainMisses = new Map<string, { failures: number; dueAt: number }>();
  /** The `vg` node this writer holds for each of its pinned roots. */
  readonly ownChain = new Map<string, string>();
  /** The outboard root this writer holds for each of its pinned blob roots (P2-B-02). */
  readonly ownOutboards = new Map<string, string>();
  /** The push stream this state follows, or null (P2-P-02). */
  stream: string | null = null;
  lastHeads: Head[] = [];
  previousLive = new Set<string>();
  /** The ids of every entry of the name read last, well formed or not, as Java's State.liveIds holds them. */
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
  /**
   * Heads left out of reads while their roots were still loading, by cause; heads ignored for a fault count in
   * headsIgnored instead (swarm retries, ROBUSTNESS.md §10.3 E2).
   */
  readonly headsLate = { timeout: 0, failedFetch: 0 };
  nodesDropped = 0;
  headsRewritten = 0;
  basesFetched = 0;
  /** Chain nodes fetched for a merge's walk (P2-V-02). */
  chainFetched = 0;
  closed = false;
  /** The follower's side of eager push, or null with push off (P2-P-02). */
  readonly receiver: PushReceiver | null;

  constructor(readonly peer: Peer, readonly store: NodeStore, readonly exchange: TreeExchange | null,
              readonly config: RefsConfig = DEFAULT_CONFIG) {
    this.receiver = config.push !== null && exchange !== null ? new PushReceiver(store, () => this.now(), config.push) : null;
  }

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

  ref<T>(space: Space, name: string, kind: string, options: RefOptions = {}): Ref<T> {
    const key = `${space.name}/${name}`;
    let state = this.states.get(key);
    if (state === undefined) {
      if (utf8(name).length > MAX_NAME_BYTES || name.length === 0) {
        throw new Error(`a ref name is 1 to ${MAX_NAME_BYTES} bytes`);
      }
      if (kind === KIND_DB && this.config.level < 2) {
        throw new Error("a db ref needs the PDT feature level 2; set level: 2 in the PDT options");
      }
      state = new State(name, kindNamed(kind, options), space, this.config.modes[name] ?? MODE_MULTI);
      this.states.set(key, state);
      this.follow(state);
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

  /**
   * Follows a ref's push stream when push is on and the ref is followed fully (P2-P-02): the peer hands each bundle of
   * the stream to the receiver and forwards only the bundles it took. A stream another facade on this peer follows
   * already is left to it, and this ref fetches its deltas as without push.
   */
  private follow(state: State): void {
    if (this.receiver === null || this.config.follow !== "full") {
      return;
    }
    const stream = push.stream(state.space.name, state.name);
    if (this.peer.streamHandlers.has(stream)) {
      return;
    }
    this.receiver.follow(stream);
    const receiver = this.receiver;
    this.peer.streamHandlers.set(stream, (_from, payload) => receiver.onBundle(stream, payload));
    state.stream = stream;
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
      record = decodePRef(payload);
    } catch {
      return; // toHead read this payload already, so only a record replaced since then fails here
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
      if (state.stream !== null && (head.push ?? 0) > 0) {
        // P2-P-02: the bundles that came first are stored now, and a push that completes the root needs no fetch;
        // otherwise the tick waits the push's grace before it fetches
        this.receiver!.expect(state.stream, head.root, head.push!);
        this.forgetHeld();
        if (this.held(head.root)) {
          state.recheck.delete(head.root);
          this.arrived(state, head, own);
        }
        return;
      }
      this.startFetch(state, head);
    }
  }

  /** What a follower does about a root it lacks while a push announced it (P2-P-02): none, wait, or late. */
  private pushWait(state: State, root: string): push.Wait {
    return state.stream === null ? "none" : this.receiver!.check(state.stream, root, this.now());
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
    if (pending.base) {
      // HLC round six, 2026-11-08 (R4): a base counts when its fetch settles, as Java's Refs.settle counts it
      this.basesFetched += 1;
      return true;
    }
    this.deltasFetched += 1;
    this.bytesReceived += pending.fetch.bytesReceived;
    state.fetchedRoots.add(root);
    this.deliver(state, pending.head);
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
      return null; // a payload reference not held yet: read again once it arrives
    }
    let h: Dict | null;
    try {
      h = decodePRef(payload);
    } catch {
      h = null;
    }
    // HLC round six, 2026-11-08 (R3): Java's rule. An undecodable PRef, a bound violation, another
    // ref name, or another kind is no head of this ref, and the entry counts in headsIgnored once.
    if (h === null || prefViolation(h, this.config.level) !== null || h["name"] !== state.name || h["kind"] !== state.kind.name) {
      this.ignore(state, String(record["entryId"]));
      return null;
    }
    const attrs = (h["attrs"] as Dict | undefined) ?? {};
    // A rewrite carries the original head's stamp and issuer (PD-R-08), so the merge order stays
    // put. HLC round four, 2026-11-08 (D2), Java's Refs rule: the reserved attrs are advisory and
    // move together. HLC round six, 2026-11-08 (R1, R2, R5): a pdt.issued that is text, an acceptable
    // stamp, and no further ahead than this reader's wall + MAX_HLC_SKEW_MILLIS +
    // FAR_FUTURE_MARGIN_MILLIS, with a pdt.issuer that is absent or text naming an agent id, replaces
    // the entry's own pair. Any other value under either key, null included, leaves the entry's own
    // stamp and issuer together, both already accepted by the replica's fold, and counts nothing.
    let issued = String(record["issued"]);
    let issuer = String(record["issuer"]);
    const issuedAttr = attrs[ISSUED_ATTR];
    const issuerAttr = attrs[ISSUER_ATTR];
    const stamp = wire.parseHlc(issuedAttr);
    if (stamp !== null && stamp.physical <= this.issuedCeiling()
        && (!Object.hasOwn(attrs, ISSUER_ATTR) || isAgentId(issuerAttr))) {
      issued = issuedAttr as string;
      issuer = typeof issuerAttr === "string" ? issuerAttr : issuer;
    }
    // PDT 2 phase 7 gate: the lease register, which the writer's renewal moves (SPEC §7.3)
    const head: Head = { root: String(h["root"]), base: [...(h["base"] as string[])], seq: Number(h["seq"]), size: Number(h["size"]),
      kind: String(h["kind"]), mode: String(h["mode"]), issuer, issued, entryId: String(record["entryId"]),
      expiresAtMillis: leaseExpiryOf(dto), push: push.announced(attrs) };
    const identity = attrs[BLAKE3_ATTR], bao = attrs[BAO_ATTR];
    if (typeof identity === "string" && /^bafkr4i[a-z2-7]{52}$/.test(identity) && cids.isCid(bao)
        && cids.parse(bao).codec === cids.DAG_CBOR) {
      head.blake3 = identity;
      head.bao = bao;
    }
    // P2-V-02: the vg node a head names, advisory, first seen kept, as Java's state.ancestry
    const vg = ancestryCid(h);
    if (vg !== null && !state.ancestry.has(head.root)) {
      state.ancestry.set(head.root, vg);
      trim(state.ancestry);
    }
    const known = state.known.get(head.root);
    if (known === undefined || head.seq > known.seq) {
      // HLC round six, 2026-11-08 (R4): a later record of a known root lists its own bases first and then
      // the bases the version held, as Java's Refs.toHead joins them, since the base walk visits them in
      // that order and the order picks the common base when two candidates tie.
      state.known.set(head.root, { ...head, base: [...new Set([...head.base, ...(known?.base ?? [])])] });
    } else {
      known.base = [...new Set([...known.base, ...head.base])];
    }
    if (state.known.size > MAX_ENTRIES) {
      state.known.delete(state.known.keys().next().value!);
    }
    return head;
  }

  /** The latest physical time a pdt.issued may carry: this reader's far-future ceiling (R2). */
  private issuedCeiling(): bigint {
    return BigInt(Math.trunc(this.now()) + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_MARGIN_MILLIS);
  }

  /** Counts an entry in headsIgnored once while it stays ignored, as Java's Set.add answers whether it is new. */
  private ignore(state: State, entryId: string): void {
    if (!state.ignoredEntries.has(entryId)) {
      state.ignoredEntries.add(entryId);
      this.headsIgnored += 1;
    }
  }

  /** Counts a live head as late for a cause, once per entry and cause (swarm retries). */
  private late(state: State, entryId: string, cause: "timeout" | "failedFetch"): void {
    const note = `${entryId}/${cause}`;
    if (!state.lateNoted.has(note)) {
      state.lateNoted.add(note);
      this.headsLate[cause] += 1;
    }
  }

  /** Whether a root's fetch failed and its next fetch is not due yet. */
  private backingOff(state: State, root: string): boolean {
    const retry = state.retries.get(root);
    return retry !== undefined && this.now() < retry.dueAt;
  }

  /**
   * Notes a failed fetch (swarm retries, ROBUSTNESS.md §10.3 E2): the next is due after a backoff that doubles with each
   * failure, from {@link RETRY_BASE_MILLIS} up to {@link UNLOADABLE_BACKOFF} load timeouts, with a random spread of up
   * to half, so the members that missed one root do not all ask again together.
   */
  private failed(state: State, root: string): void {
    this.backOff(state.retries, root);
  }

  /** Notes one more failure of `key` in `retries` and sets when its next ask is due, by the rule of {@link failed}. */
  private backOff(retries: Map<string, { failures: number; dueAt: number }>, key: string): void {
    const retry = retries.get(key) ?? { failures: 0, dueAt: 0 };
    retries.set(key, retry);
    retry.failures += 1;
    const cap = Math.max(RETRY_BASE_MILLIS, this.config.loadTimeoutMillis * UNLOADABLE_BACKOFF);
    const wait = Math.min(cap, RETRY_BASE_MILLIS * 2 ** Math.min(retry.failures - 1, 20));
    retry.dueAt = this.now() + wait + Math.random() * wait / 2;
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
      // PDT 2 phase 7 gate: the lease register, which the writer's renewal moves (SPEC §7.3), and not the lease the
      // record was written with, so a renewed head lives on past its first lease
      if (leaseExpiryOf(dto) <= now || !Refs.liveDots(dto)) {
        continue;
      }
      if (((record["tags"] as Dict | undefined) ?? {})[NAME_TAG] !== state.name) {
        continue;
      }
      // HLC round six, 2026-11-08 (R3): every entry of the name read, well formed or not, as Java's
      // liveEntries keeps them, so the tick prunes an ignored entry only once it is gone and an entry
      // ignored while it stays live counts once in headsIgnored.
      ids.add(String(record["entryId"]));
      const head = this.toHead(state, dto);
      if (head === null) {
        continue;
      }
      live.push(head);
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
    if (state.ignoredEntries.has(head.entryId) || this.backingOff(state, head.root)) {
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
      && !this.backingOff(state, head.root));
    for (const head of waiting) {
      this.startFetch(state, head);
    }
    const deadline = this.now() + this.config.loadTimeoutMillis;
    for (const head of waiting) {
      if (!state.pending.has(head.root) && await this.awaitPush(state, head, deadline)) {
        continue;
      }
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
        // swarm retries: the read's wait is the caller's; the fetch goes on and the next read takes the head
        pending.timedOut = true;
        this.late(state, head.entryId, "timeout");
      }
    }
    return headsAmong(live.filter((head) => this.held(head.root)));
  }

  /**
   * Waits, within the read's deadline, for an announced push to complete a root (P2-P-02), and fetches what the push
   * left missing once its grace runs out; true when the root is held. The caller keeps its own deadline: past it the
   * push and the fetch go on, and the next read takes the head (swarm retries, ROBUSTNESS.md §10.2).
   */
  private async awaitPush(state: State, head: Head, deadline: number): Promise<boolean> {
    while (this.pushWait(state, head.root) === "wait" && this.now() < deadline && !this.held(head.root)) {
      await new Promise((resolve) => setTimeout(resolve, PUSH_POLL_MILLIS));
      this.forgetHeld();
    }
    if (this.held(head.root)) {
      return true;
    }
    this.startFetch(state, head);
    return false;
  }

  // ---- fetching

  private startFetch(state: State, head: Head, base = false, haves: string[] | null = null, sources: string[] = []): Pending | null {
    if (this.exchange === null || state.pending.has(head.root) || this.backingOff(state, head.root)) {
      return state.pending.get(head.root) ?? null;
    }
    if (!base && this.pushWait(state, head.root) === "wait") {
      return null; // the announced push has its grace (P2-P-02)
    }
    // a first fetch asks the issuer; a retry, and the fetch after a late push, the other holders of the root, the issuer
    // behind them (swarm retries, P4 and P6)
    const issuer = issuerPeer(head.issuer);
    const late = state.retries.has(head.root) || this.pushWait(state, head.root) === "late";
    const others = late ? this.exchange.holders(head.root).filter((p) => p !== issuer) : [];
    const prefer = [...sources, ...(others.length > 0 ? others : [issuer])];
    const fetch = this.exchange.fetchTree(head.root, haves ?? this.retainedRoots(state), [...new Set(prefer)]);
    const pending: Pending = { fetch, head, base, timedOut: false };
    if (fetch.done) {
      if (fetch.complete) {
        this.forgetHeld();
        return null;
      }
      this.failed(state, head.root);
      return null;
    }
    state.pending.set(head.root, pending);
    return pending;
  }

  /**
   * Fetches the bases of a held head that this engine saw a head of and does not hold, as Java's
   * Refs.ensureBases does (HLC round six, 2026-11-08, R4): a base never seen as a head is fetched by
   * root only when a merge needs it as the common base.
   */
  private ensureBases(state: State, head: Head): void {
    for (const base of head.base) {
      if (this.held(base) || state.pending.has(base) || this.backingOff(state, base) || !cids.isCid(base)) {
        continue;
      }
      const version = state.known.get(base);
      if (version !== undefined) {
        this.startFetch(state, version, true, [head.root, ...this.retainedRoots(state)].filter((r) => this.held(r)));
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

  /** The roots of a root's base walk (see {@link baseWalk}). */
  private ancestors(state: State, root: string): Set<string> {
    return this.baseWalk(state, root).roots;
  }

  /**
   * The roots reachable from a root over base links, breadth first and the root itself first, as Java's
   * Refs.walk walks them: a root first reached at step MAX_BASE_STEPS joins the walk, and the walk follows
   * none of its bases. A version reads its bases from the entries seen and, when no entry of it was seen, from its
   * chain node (PDT 2 phase 7, P2-V-02); a version neither describes ends the walk there, and a chain node the store
   * lacks goes into `wanted` when the caller fetches. HLC round five, 2026-11-08 (E16): the walk is complete when every
   * version on it is described and every version it first reaches at the limit has no base, so the history it walks
   * began at the empty value.
   */
  private baseWalk(state: State, root: string, wanted: Set<string> | null = null): { roots: Set<string>; complete: boolean } {
    const roots = new Set<string>();
    let complete = true;
    const frontier: [string, number][] = [[root, 0]];
    while (frontier.length > 0) {
      const [cid, depth] = frontier.shift()!;
      if (roots.has(cid)) {
        continue;
      }
      roots.add(cid);
      const bases = state.known.get(cid)?.base ?? this.chainNode(state, cid, wanted)?.bases ?? null;
      if (bases === null) {
        complete = false;
        continue;
      }
      if (depth >= MAX_BASE_STEPS) {
        complete &&= bases.length === 0;
        continue;
      }
      this.learnParents(state, cid, bases, wanted);
      for (const base of bases) {
        if (!roots.has(base)) {
          frontier.push([base, depth + 1]);
        }
      }
    }
    return { roots, complete };
  }

  /** The chain node of a version: read before, or read now from the store through the `vg` CID its head or a child names. */
  private chainNode(state: State, root: string, wanted: Set<string> | null): VgNode | null {
    const read = state.chain.get(root);
    if (read !== undefined) {
      return read;
    }
    const cid = state.ancestry.get(root);
    if (cid === undefined) {
      return null;
    }
    const node = this.readChain(cid, wanted);
    if (node === undefined) {
      return null;
    }
    if (node === null || node.root !== root) {
      state.ancestry.delete(root); // a head without a usable ancestry reads from the memory of the versions seen
      return null;
    }
    state.chain.set(root, node);
    trim(state.chain);
    return node;
  }

  /** A `vg` node from the store: undefined when the store lacks it (and it joins `wanted`), null when it is no `vg` node. */
  private readChain(cid: string, wanted: Set<string> | null): VgNode | null | undefined {
    const bytes = this.store.get(cid);
    if (bytes === undefined) {
      wanted?.add(cid);
      return undefined;
    }
    try {
      return VgNode.decode(bytes, cid);
    } catch (e) {
      if (e instanceof NodeFormatError) {
        return null;
      }
      throw e;
    }
  }

  /**
   * Learns which chain node describes each base of a version that neither the entries seen nor an earlier link
   * describe: the version's chain node links one per base, so the links are read and each kept under its base.
   */
  private learnParents(state: State, root: string, bases: readonly string[], wanted: Set<string> | null): void {
    if (bases.every((b) => state.known.has(b) || state.ancestry.has(b) || state.chain.has(b))) {
      return;
    }
    const child = this.chainNode(state, root, wanted);
    for (const link of child?.previous ?? []) {
      const parent = this.readChain(link.cid, wanted);
      if (parent instanceof VgNode && bases.includes(parent.root)) {
        if (!state.ancestry.has(parent.root)) {
          state.ancestry.set(parent.root, link.cid);
        }
        if (!state.chain.has(parent.root)) {
          state.chain.set(parent.root, parent);
        }
      }
    }
  }

  /**
   * The heads' base walks, fetching the chain nodes they reach and the store lacks from the heads' issuers first, then
   * the writer of every version this engine knows and of every chain node read (P2-V-02), one bare batch per round
   * within the load timeout. A head's writer links its base's chain node without holding it, so the base's own writer
   * may alone hold it; a walk that asked the heads' issuers alone merged with no base (chain walk sources, Java's
   * Refs.chainSources, srad/agentspaces-pdt2.md §10.20). The first batch that fails ends the fetching, so a walk with
   * no reachable holder costs one timeout at most. Each node that batch asked for then waits out a backoff before any
   * walk asks for it again (PDT 2 phase 7 gate; swarm retries, ROBUSTNESS.md §10.2), so the reads of a forked ref whose
   * chain node nobody serves pay no timeout each.
   */
  private async chainWalks(state: State, heads: Head[]): Promise<{ roots: Set<string>; complete: boolean }[]> {
    const sources = new Set(heads.map((h) => issuerPeer(h.issuer)));
    for (const version of state.known.values()) {
      sources.add(issuerPeer(version.issuer));
    }
    let fetching = this.exchange !== null;
    for (;;) {
      const wanted = fetching ? new Set<string>() : null;
      const walks = heads.map((h) => this.baseWalk(state, h.root, wanted));
      const now = this.now();
      const due = [...(wanted ?? [])].filter((cid) => (state.chainMisses.get(cid)?.dueAt ?? 0) <= now).slice(0, 256);
      if (due.length === 0) {
        return walks;
      }
      for (const node of state.chain.values()) {
        sources.add(issuerPeer(node.issuer));
      }
      sources.delete(this.peer.identity.peerId);
      const batch = this.exchange!.fetchNodes(due, [...sources]);
      const arrived = await batch.await(this.config.loadTimeoutMillis);
      if (!arrived) {
        batch.cancel();
        fetching = false;
      }
      this.chainFetched += batch.nodesReceived;
      for (const cid of due) {
        if (this.store.has(cid)) {
          state.chainMisses.delete(cid);
        } else {
          this.backOff(state.chainMisses, cid);
        }
      }
      trim(state.chainMisses);
    }
  }

  /**
   * The lowest common base by the base-link graph alone (PD-R-06); fetches it from the heads' issuers when not held.
   * The empty value is the base when every head is a first version, or when the walks share no version and each walk
   * is complete; null when there is no base.
   */
  private async commonBase(state: State, heads: Head[]): Promise<string | null> {
    if (heads.every((h) => h.base.length === 0)) {
      return EMPTY_BASE;
    }
    const walks = await this.chainWalks(state, heads);
    const latest = walks[walks.length - 1]!.roots;
    for (const candidate of latest) {
      if (!walks.slice(0, -1).every((w) => w.roots.has(candidate))) {
        continue;
      }
      if (this.held(candidate)) {
        return candidate;
      }
      const version = state.known.get(candidate) ?? { ...heads[heads.length - 1]!, root: candidate, base: [], seq: 0 };
      const haves = heads.map((h) => h.root).filter((r) => this.held(r)).slice(0, 64);
      // the heads' issuers retain the base (PD-R-06), and so does the writer its chain node names (P2-V-02)
      const writer = state.chain.get(candidate);
      const sources = [...new Set([...heads.map((h) => issuerPeer(h.issuer)), ...(writer ? [issuerPeer(writer.issuer)] : [])])]
        .filter((p) => p !== this.peer.identity.peerId);
      const pending = this.startFetch(state, version, true, haves, sources);
      if (pending !== null) {
        await pending.fetch.await(this.config.loadTimeoutMillis);
      }
      if (this.held(candidate)) {
        this.settle(state, candidate);
        return candidate;
      }
      return null;
    }
    // HLC round five, 2026-11-08 (E16): walks that share no version but are each complete start from
    // the empty value, so the empty value is their shared base and the three-way merge keeps every key
    // of every writer.
    return walks.every((walk) => walk.complete) ? EMPTY_BASE : null;
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
    const attrs: { [key: string]: string } = { [ANCESTRY_ATTR]: this.writeAncestry(state, newRoot, base) };
    if (next instanceof PBlob) {
      Object.assign(attrs, this.writeIdentity(state, next));
    }
    return pref({ v: state.kind.version(next), name: state.name, kind: state.kind.name, root: newRoot, base, seq,
      size: state.kind.size(next), nodes, mode, sealing: this.config.sealing, attrs });
  }

  /**
   * The identity and outboard of a blob version (PDT 2 phase 7, P2-B-01, P2-B-02; Java's Refs on a blob ref): the
   * BLAKE3 identity of its content and the `bo` nodes of its Bao outboard, written beside the blob, linked by no blob
   * node, carried inline by no head (rule 5), and pinned while this writer pins the root.
   */
  private writeIdentity(state: State, value: PBlob): { [key: string]: string } {
    const outboard = blake3.outboard((function* () {
      for (const entry of value.chunks()) {
        yield value.tree.chunk(entry);
      }
    })());
    for (const node of outboard.nodes.values()) {
      this.store.put(node, cids.DAG_CBOR);
    }
    if (state.ownOutboards.get(value.root) !== outboard.root) {
      if (state.ownOutboards.has(value.root)) {
        this.store.unpin(state.ownOutboards.get(value.root)!);
      }
      state.ownOutboards.set(value.root, outboard.root);
      this.store.pin(outboard.root);
    }
    return { [BLAKE3_ATTR]: outboard.identity, [BAO_ATTR]: outboard.root };
  }

  /**
   * Writes the `vg` node of a new version into the store beside its delta and returns its CID for `pdt.ancestry`
   * (PDT 2 phase 7, P2-V-01; Java's Refs.writeAncestry): the root, the bases, this writer, a stamp of now, and a link to
   * the `vg` node of each base that has one, in the order of the bases. No head carries it inline and no value root
   * links it; this writer pins it while it pins the root, and the collector keeps it through `liveRoots`.
   */
  private writeAncestry(state: State, root: string, base: string[]): string {
    const issuer = state.space.agent?.agentId ?? `${this.peer.identity.peerId}/${state.space.agentName}`;
    const previous = base.filter((b) => state.ancestry.has(b)).map((b) => new Link(state.ancestry.get(b)!));
    const node = new VgNode(root, base, issuer, `${Math.trunc(this.now())}:0:${issuer}`, previous);
    const cid = this.store.put(node.encode(), cids.DAG_CBOR);
    state.ancestry.set(root, cid);
    state.chain.set(root, node);
    trim(state.ancestry);
    trim(state.chain);
    if (state.ownChain.get(root) !== cid) {
      if (state.ownChain.has(root)) {
        this.store.unpin(state.ownChain.get(root)!);
      }
      state.ownChain.set(root, cid);
      this.store.pin(cid);
    }
    return cid;
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
    for (const held of [state.ownChain, state.ownOutboards]) {
      const cid = held.get(root);
      if (cid !== undefined) {
        held.delete(root);
        this.store.unpin(cid);
      }
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
    this.receiver?.expire(now);
    this.forgetHeld(); // a push may have completed a root since the last tick
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
        if (this.pushWait(state, root) === "wait") {
          state.recheck.set(root, head); // the announced push has its grace (P2-P-02)
          continue;
        }
        this.startFetch(state, head);
      }
    }
    if (this.config.follow === "full") {
      for (const head of live) {
        // a live head whose fetch failed is fetched again once its backoff ends, with no read needed (swarm retries)
        if (!this.held(head.root) && !state.pending.has(head.root) && !this.backingOff(state, head.root)
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
        this.failed(state, root);
        if (!pending.base) {
          this.late(state, pending.head.entryId, "failedFetch");
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
    for (const note of [...state.lateNoted]) {
      if (!state.liveIds.has(note.slice(0, note.lastIndexOf("/")))) {
        state.lateNoted.delete(note);
      }
    }
    for (const id of [...state.takenEntries]) {
      if (!state.liveIds.has(id)) {
        state.takenEntries.delete(id);
      }
    }
    for (const root of [...state.retries.keys()]) {
      if (!liveRoots.has(root) && !basesInUse.has(root)) {
        state.retries.delete(root);
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
      } else if (cids.isCid(head.root) && !state.retries.has(head.root)) {
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
      mode: head.mode, sealing: this.config.sealing, v: state.kind.version(state.kind.load(this.store, head.root)),
      attrs: { [ISSUED_ATTR]: head.issued, [ISSUER_ATTR]: head.issuer,
        ...(state.ancestry.has(head.root) ? { [ANCESTRY_ATTR]: state.ancestry.get(head.root)! } : {}) } });
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
      for (const held of [...state.ownChain.values(), ...state.ownOutboards.values()]) {
        roots.add(held); // P2-V-01, P2-B-02: the writer holds the chain nodes and outboards it named
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
      if (state.stream !== null) {
        this.peer.streamHandlers.delete(state.stream);
        this.receiver!.unfollow(state.stream);
      }
    }
  }
}

/** Keeps a map of chain knowledge to {@link MAX_ENTRIES}, the oldest first out. */
function trim<V>(map: Map<string, V>): void {
  while (map.size > MAX_ENTRIES) {
    map.delete(map.keys().next().value!);
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
