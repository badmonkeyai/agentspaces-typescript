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
 * The typed readers of the seven level-2 node kinds (PDT 2 phase 0, srad/agentspaces-pdt2.md §3), a port of
 * Java's `ai.badmonkey.agentspaces.pdt.kinds`: each reads its kind through the node codec, checks the rules
 * that span fields, and writes the canonical bytes back. A writer puts `db`, `dn`, `rr`, `rv`, and `t`
 * nodes only under a `PRef.v` 2 head, and reaches `vg` and `bo` nodes only through the attributes
 * `pdt.ancestry` and `pdt.bao` (§6.10.3, rules 1 to 5), so no level-1 reader meets them.
 */

import { compare, utf8 } from "../bytes.js";
import { decodeHlc } from "../wire.js";
import { isAgentId } from "../records.js";
import * as cids from "./cids.js";
import {
  CharId, Datom, Embedded, KIND_BO, KIND_DB, KIND_DN, KIND_KEY, KIND_RR, KIND_RV, KIND_T, KIND_VG, Link, MAX_NODE_BYTES,
  NodeFormatError, TextRun, decode, encode, isLinkShaped, skip,
} from "./nodes.js";
import type { IndexLinks, Node } from "./nodes.js";

/** The most bases a head names, so the most a `vg` node names (PD-R-01). */
const MAX_BASE = 8;

/** Decodes a node of one kind and checks that every key the kind requires is present. */
function decodeKind(bytes: Uint8Array, cid: string | null, kind: string, required: readonly string[]): Node {
  const node = decode(bytes, cid);
  if (node[KIND_KEY] !== kind) {
    throw new NodeFormatError(`kind '${String(node[KIND_KEY])}' where a '${kind}' node belongs`, cid);
  }
  for (const key of required) {
    if (!Object.hasOwn(node, key)) {
      throw new NodeFormatError(`a '${kind}' node lacks '${key}'`, cid);
    }
  }
  return node;
}

/** Builds a typed value, turning the constructor's refusal into a refusal of the node. */
function built<T>(cid: string | null, constructor: () => T): T {
  try {
    return constructor();
  } catch (e) {
    if (e instanceof NodeFormatError) {
      throw e;
    }
    throw new NodeFormatError(e instanceof Error ? e.message : String(e), cid);
  }
}

// ------------------------------------------------------------------ db and dn (P2-D-01)

export interface DbRootFields {
  /** The database schema, a map with keyword keys as their print form, or a spilled link to one. */
  schema: Embedded;
  /** The largest entity id issued, up to 2^53 - 1, the bound of this port's unsigned fields. */
  maxEid: number;
  /** The largest transaction id. */
  maxTx: number;
  /** The branching factor of the indexes, {@link DbRoot.BRANCHING} by decision 2. */
  branching: number;
  eavt: Link;
  aevt: Link;
  avet: Link;
  /** The tail node, or null when every datom sits in the indexes. */
  tail: Link | null;
}

/**
 * The root of a DataScript database, kind `db` (PDT 2 phase 0, P2-D-01; §3.1.1):
 * `{k:"db", v: 1, s: schema, me, mt, bf, i: {aevt, avet, eavt}, t: tail link or null}`. As Java's build
 * pinned it (§10.4, phase 0), `t` is always present and links the `dn` tail whether the tail travels inline
 * on the head or by request, so an inline tail is reachable from the root.
 */
export class DbRoot implements DbRootFields {
  /** The version this release writes and reads. */
  static readonly VERSION = 1;
  /** The branching factor of decision 2. */
  static readonly BRANCHING = 128;

  readonly schema: Embedded;
  readonly maxEid: number;
  readonly maxTx: number;
  readonly branching: number;
  readonly eavt: Link;
  readonly aevt: Link;
  readonly avet: Link;
  readonly tail: Link | null;

  constructor(fields: DbRootFields) {
    ({ schema: this.schema, maxEid: this.maxEid, maxTx: this.maxTx, branching: this.branching, eavt: this.eavt,
      aevt: this.aevt, avet: this.avet, tail: this.tail } = fields);
    if (!(this.eavt instanceof Link) || !(this.aevt instanceof Link) || !(this.avet instanceof Link)
        || !(this.tail === null || this.tail instanceof Link)) {
      throw new RangeError("a db root links its three indexes and its tail or null");
    }
    if (!Number.isSafeInteger(this.maxEid) || !Number.isSafeInteger(this.maxTx) || this.maxEid < 0 || this.maxTx < 0) {
      throw new RangeError("max-eid and max-tx are non-negative integers");
    }
    if (!Number.isSafeInteger(this.branching) || this.branching < 2) {
      throw new RangeError(`a db root's branching factor is at least 2, found ${this.branching}`);
    }
    checkSchema(this.schema.bytes);
  }

  /** The canonical node bytes. */
  encode(): Uint8Array {
    const index: IndexLinks = { aevt: this.aevt, avet: this.avet, eavt: this.eavt };
    return encode({ k: KIND_DB, v: DbRoot.VERSION, s: this.schema, me: this.maxEid, mt: this.maxTx, bf: this.branching,
      i: index, t: this.tail });
  }

  /** Reads a `db` root; refuses another kind, another version, a missing key, or a broken field. */
  static decode(bytes: Uint8Array, cid: string | null = null): DbRoot {
    const node = decodeKind(bytes, cid, KIND_DB, ["v", "s", "me", "mt", "bf", "i", "t"]);
    if (node["v"] !== DbRoot.VERSION) {
      throw new NodeFormatError(`db root version ${String(node["v"])}; this release reads version ${DbRoot.VERSION}`, cid);
    }
    const index = node["i"] as IndexLinks;
    return built(cid, () => new DbRoot({ schema: node["s"] as Embedded, maxEid: node["me"] as number,
      maxTx: node["mt"] as number, branching: node["bf"] as number, eavt: index.eavt, aevt: index.aevt,
      avet: index.avet, tail: node["t"] as Link | null }));
  }
}

/**
 * The schema is a map whose keys are text, the keywords' print forms, or a spilled link to one (PDT 2
 * phase 0, P2-D-01; §3.1.1), so every reader finds the schema it expects.
 */
function checkSchema(item: Uint8Array): void {
  if (isLinkShaped(item)) {
    return;
  }
  if (skip(item, 0) !== item.length) {
    throw new RangeError("a db schema is one CBOR item, found trailing bytes");
  }
  const initial = item[0]!;
  if (initial >> 5 !== 5) {
    throw new RangeError(`a db schema is a map, found CBOR major type ${initial >> 5}`);
  }
  // the item is whole, so a definite map holds its count of entries and an indefinite one ends at the break
  let p = 1;
  let entries = Number.MAX_SAFE_INTEGER;
  const info = initial & 0x1f;
  if (info !== 31) {
    if (info < 24) {
      entries = info;
    } else {
      entries = 0;
      const width = 1 << (info - 24);
      for (let i = 1; i <= width; i++) {
        entries = entries * 256 + item[i]!;
      }
      p = 1 + width;
    }
  }
  for (let i = 0; i < entries && item[p] !== 0xff; i++) {
    if (item[p]! >> 5 !== 3) {
      throw new RangeError(`a db schema's keys are text, found CBOR major type ${item[p]! >> 5}`);
    }
    p = skip(item, skip(item, p));
  }
}

export const EAVT = "eavt", AEVT = "aevt", AVET = "avet", TAIL = "tail";
const INDEXES = new Set([EAVT, AEVT, AVET, TAIL]);

/**
 * A DataScript sorted-set node, kind `dn` (PDT 2 phase 0, P2-D-01; §3.1.1): a leaf `{l: 0, x: index, e}`, a
 * branch `{l >= 1, x, e, c}` whose `e` holds the largest key of each child in the order of `c`, or a tail
 * `{l: 0, x: "tail", e}` with the datoms of one or more transactions in transaction order. The comparator
 * fixed by `x` belongs to the reader of P2-D-09, which checks the order.
 */
export class DnNode {
  readonly datoms: readonly Datom[];
  readonly children: readonly Link[];

  constructor(readonly level: number, readonly index: string, datoms: readonly Datom[], children: readonly Link[]) {
    this.datoms = [...datoms];
    this.children = [...children];
    if (!INDEXES.has(index)) {
      throw new RangeError(`a dn node names index '${index}'; the indexes are eavt, aevt, avet and tail`);
    }
    if (!Number.isSafeInteger(level) || level < 0) {
      throw new RangeError("a dn level is a non-negative integer");
    }
    if (index === TAIL && level !== 0) {
      throw new RangeError(`a tail is a leaf, found level ${level}`);
    }
    if (index === TAIL && datoms.length === 0) {
      throw new RangeError("an empty tail is no node: the db root's 't' is null instead");
    }
    if (level === 0 && children.length > 0) {
      throw new RangeError("a leaf carries no 'c'");
    }
    if (level > 0 && (datoms.length === 0 || children.length !== datoms.length)) {
      throw new RangeError(`a branch holds one link per key, found ${children.length} links for ${datoms.length} keys`);
    }
  }

  static leaf(index: string, datoms: readonly Datom[]): DnNode {
    return new DnNode(0, index, datoms, []);
  }

  static branch(level: number, index: string, datoms: readonly Datom[], children: readonly Link[]): DnNode {
    return new DnNode(level, index, datoms, children);
  }

  /** A tail: the datoms of transactions not yet folded into the indexes. */
  static tail(datoms: readonly Datom[]): DnNode {
    return new DnNode(0, TAIL, datoms, []);
  }

  /** The canonical node bytes; a leaf and a tail carry no `c` key. */
  encode(): Uint8Array {
    const node: Node = { k: KIND_DN, l: this.level, x: this.index, e: [...this.datoms] };
    if (this.level > 0) {
      node["c"] = [...this.children];
    }
    return encode(node);
  }

  /** Reads a `dn` node; refuses another kind, a missing key, or a broken shape rule. */
  static decode(bytes: Uint8Array, cid: string | null = null): DnNode {
    const node = decodeKind(bytes, cid, KIND_DN, ["l", "x", "e"]);
    const level = node["l"] as number;
    if (level > 0 && !Object.hasOwn(node, "c")) {
      throw new NodeFormatError("a 'dn' node lacks 'c': a branch links its children", cid);
    }
    if (level === 0 && Object.hasOwn(node, "c")) {
      throw new NodeFormatError("a leaf carries no 'c'", cid);
    }
    return built(cid, () => new DnNode(level, node["x"] as string, node["e"] as Datom[], (node["c"] ?? []) as Link[]));
  }
}

// ------------------------------------------------------------------ rr and rv (P2-R-01)

/** The branching factor m of §3.7, and its log2. */
const WIDTH = 32, BITS = 5;

/**
 * The root of an RRB vector that still holds a relaxed node, kind `rr` (PDT 2 phase 0, P2-R-01; §3.7):
 * `{k:"rr", n: count, s: shift, r: link or null, t: [tail]}`, the `vr` shape over {@link RvNode} interior
 * nodes. A head whose tree holds an `rr` or `rv` node is `PRef.v` 2 (§6.10.3, rule 2).
 */
export class RrRoot {
  static readonly WIDTH = WIDTH;
  static readonly BITS = BITS;
  readonly tail: readonly Embedded[];

  constructor(readonly count: number, readonly shift: number, readonly trie: Link | null, tail: readonly Embedded[]) {
    this.tail = [...tail];
    if (!Number.isSafeInteger(shift) || shift < BITS || shift % BITS !== 0) {
      throw new RangeError(`an rr shift is a positive multiple of ${BITS}, found ${shift}`);
    }
    if (tail.length > WIDTH) {
      throw new RangeError(`an rr tail holds at most ${WIDTH} elements, found ${tail.length}`);
    }
    if (!Number.isSafeInteger(count) || count < tail.length || (trie === null && count !== tail.length)) {
      throw new RangeError(`an rr count of ${count} does not fit a tail of ${tail.length}${trie === null ? " and no trie" : ""}`);
    }
    if (trie !== null && count === tail.length) {
      // an rv node holds at least one child, so a linked trie holds an element
      throw new RangeError(`an rr root links a trie but its count of ${count} leaves the trie no element`);
    }
  }

  encode(): Uint8Array {
    return encode({ k: KIND_RR, n: this.count, s: this.shift, r: this.trie, t: [...this.tail] });
  }

  static decode(bytes: Uint8Array, cid: string | null = null): RrRoot {
    const node = decodeKind(bytes, cid, KIND_RR, ["n", "s", "r", "t"]);
    return built(cid, () => new RrRoot(node["n"] as number, node["s"] as number, node["r"] as Link | null,
      node["t"] as Embedded[]));
  }
}

/**
 * An interior node of an RRB vector, kind `rv` (PDT 2 phase 0, P2-R-01; §3.7): `{k:"rv", c: [link...],
 * z: [cumulative sizes]}`, with `z` present only on a relaxed node, strictly increasing from above 0.
 */
export class RvNode {
  readonly children: readonly Link[];
  readonly sizes: readonly number[] | null;

  constructor(children: readonly Link[], sizes: readonly number[] | null) {
    this.children = [...children];
    this.sizes = sizes === null ? null : [...sizes];
    if (children.length === 0 || children.length > WIDTH) {
      throw new RangeError(`an rv node holds 1 to ${WIDTH} children, found ${children.length}`);
    }
    if (sizes !== null) {
      if (sizes.length !== children.length) {
        throw new RangeError("an rv size table holds one size per child");
      }
      let previous = 0;
      for (const size of sizes) {
        if (size <= previous) {
          throw new RangeError("an rv size table is strictly increasing from above 0");
        }
        previous = size;
      }
    }
  }

  /** The canonical node bytes; a dense node carries no `z` key. */
  encode(): Uint8Array {
    const node: Node = { k: KIND_RV, c: [...this.children] };
    if (this.sizes !== null) {
      node["z"] = [...this.sizes];
    }
    return encode(node);
  }

  static decode(bytes: Uint8Array, cid: string | null = null): RvNode {
    const node = decodeKind(bytes, cid, KIND_RV, ["c"]);
    return built(cid, () => new RvNode(node["c"] as Link[], (node["z"] ?? null) as number[] | null));
  }
}

// ------------------------------------------------------------------ t (P2-T-01)

/** One character of a leaf: its parent and side, whether it is deleted, and its code point when live. */
interface Char {
  readonly parent: CharId | null;
  readonly left: boolean;
  readonly deleted: boolean;
  readonly codePoint: number;
}

const idKey = (replica: string, counter: number): string => JSON.stringify([replica, counter]);
const nameOf = (id: CharId): string => `${id.replica}:${id.counter}`;

/** The order of character ids: the replica's UTF-8 bytes unsigned, then the counter (§3.9, Java's ID_ORDER). */
function compareIds(a: CharId, b: CharId): number {
  return compare(utf8(a.replica), utf8(b.replica)) || a.counter - b.counter;
}

/** The characters of some runs by id, in id order; refuses a character that appears twice. */
function expand(runs: readonly TextRun[]): Map<string, { id: CharId; char: Char }> {
  if (runs.reduce((total, run) => total + run.length, 0) > TextLeaf.MAX_CHARS) {
    throw new RangeError(`a text leaf holds at most ${TextLeaf.MAX_CHARS} characters, live and deleted`);
  }
  const chars: { id: CharId; char: Char }[] = [];
  const seen = new Set<string>();
  for (const run of runs) {
    const codePoints = [...run.text].map((c) => c.codePointAt(0)!);
    for (let i = 0; i < run.length; i++) {
      const id = new CharId(run.replica, run.counter + i);
      const key = idKey(id.replica, id.counter);
      if (seen.has(key)) {
        throw new RangeError(`character ${nameOf(id)} appears twice`);
      }
      seen.add(key);
      chars.push({ id, char: { parent: i === 0 ? run.parent : new CharId(run.replica, run.counter + i - 1),
        left: i === 0 && run.side === "L", deleted: run.deleted, codePoint: run.deleted ? -1 : codePoints[i]! } });
    }
  }
  chars.sort((x, y) => compareIds(x.id, y.id));
  return new Map(chars.map((entry) => [idKey(entry.id.replica, entry.id.counter), entry]));
}

const sameId = (a: CharId | null, b: CharId | null): boolean =>
  a === b || (a !== null && b !== null && a.replica === b.replica && a.counter === b.counter);

/** The maximal runs of characters in id order. */
function compress(chars: Map<string, { id: CharId; char: Char }>): TextRun[] {
  const out: TextRun[] = [];
  let start: CharId | null = null;
  let first: Char | null = null;
  let last: CharId | null = null;
  let length = 0;
  let text = "";
  const flush = (): void => {
    if (start !== null && first !== null) {
      out.push(new TextRun(start.replica, start.counter, first.parent, first.left ? "L" : "R", length, first.deleted, text));
    }
  };
  for (const { id, char } of chars.values()) {
    const continues = last !== null && first !== null && id.replica === last.replica && id.counter === last.counter + 1
      && sameId(last, char.parent) && !char.left && char.deleted === first.deleted;
    if (!continues) {
      flush();
      start = id;
      first = char;
      length = 0;
      text = "";
    }
    length += 1;
    if (!char.deleted) {
      text += String.fromCodePoint(char.codePoint);
    }
    last = id;
  }
  flush();
  return out;
}

/**
 * The characters in Fugue order: a character's left children, the character, then its right children,
 * same-side siblings in id order; walked with an explicit stack so a long run costs no call depth.
 * Refuses a parent outside the leaf and parents that form a cycle.
 */
function order(chars: Map<string, { id: CharId; char: Char }>): CharId[] {
  const lefts = new Map<string, CharId[]>();
  const rights = new Map<string, CharId[]>();
  const roots: CharId[] = [];
  for (const { id, char } of chars.values()) {
    if (char.parent === null) {
      roots.push(id);
      continue;
    }
    const parentKey = idKey(char.parent.replica, char.parent.counter);
    if (!chars.has(parentKey)) {
      throw new RangeError(`the parent ${nameOf(char.parent)} of ${nameOf(id)} is not in the leaf`);
    }
    // the entries arrive in id order, so each sibling list is already sorted
    const siblings = char.left ? lefts : rights;
    const list = siblings.get(parentKey);
    if (list === undefined) {
      siblings.set(parentKey, [id]);
    } else {
      list.push(id);
    }
  }
  const out: CharId[] = [];
  const stack: [CharId, boolean][] = roots.map((id): [CharId, boolean] => [id, false]).reverse();
  while (stack.length > 0) {
    const [id, emit] = stack.pop()!;
    if (emit) {
      out.push(id);
      continue;
    }
    const key = idKey(id.replica, id.counter);
    for (const right of [...(rights.get(key) ?? [])].reverse()) {
      stack.push([right, false]);
    }
    stack.push([id, true]);
    for (const left of [...(lefts.get(key) ?? [])].reverse()) {
      stack.push([left, false]);
    }
  }
  if (out.length !== chars.size) {
    throw new RangeError("the runs' parents form a cycle that the document root does not reach");
  }
  return out;
}

/**
 * A text leaf, kind `t` (PDT 2 phase 0, P2-T-01; §3.9): a Fugue sequence as runs, `{k:"t", r: [run...],
 * v: 1}`, in the one canonical form Java's build fixed so two replicas holding the same characters write
 * the same bytes: maximal runs sorted by the id of their first character. A writer puts a value that holds
 * text under a `PRef.v` 2 head (§6.10.3, rule 3).
 */
export class TextLeaf {
  static readonly VERSION = 1;
  /**
   * The most characters, live and deleted, one leaf holds: the node byte bound (PDT 2 phase 0, P2-T-01,
   * gate finding G1). A deleted run costs no text bytes, so this caps the tombstones the node bound
   * leaves open, and every reader checks it before it expands a run.
   */
  static readonly MAX_CHARS = MAX_NODE_BYTES;
  readonly runs: readonly TextRun[];

  /** Checks that the runs are the canonical form of their characters and that the parents form a tree. */
  constructor(runs: readonly TextRun[]) {
    this.runs = [...runs];
    const chars = expand(runs);
    const canonical = compress(chars);
    if (canonical.length !== runs.length || canonical.some((run, i) => !sameRun(run, runs[i]!))) {
      throw new RangeError("the runs are not in canonical form: maximal, sorted by id");
    }
    order(chars);
  }

  /** The canonical leaf of some runs, in any order and split anywhere. */
  static of(runs: readonly TextRun[]): TextLeaf {
    return new TextLeaf(compress(expand(runs)));
  }

  /** The union of two leaves: every character of either, deleted when either deleted it (Fugue's merge). */
  union(other: TextLeaf): TextLeaf {
    const merged = expand(this.runs);
    for (const [key, theirs] of expand(other.runs)) {
      const mine = merged.get(key);
      if (mine === undefined) {
        merged.set(key, theirs);
        continue;
      }
      const a = mine.char, b = theirs.char;
      if (!sameId(a.parent, b.parent) || a.left !== b.left || (!a.deleted && !b.deleted && a.codePoint !== b.codePoint)) {
        throw new RangeError(`two leaves disagree on character ${nameOf(mine.id)}`);
      }
      const gone = a.deleted || b.deleted;
      merged.set(key, { id: mine.id, char: { parent: a.parent, left: a.left, deleted: gone, codePoint: gone ? -1 : a.codePoint } });
    }
    const sorted = [...merged.values()].sort((x, y) => compareIds(x.id, y.id));
    return new TextLeaf(compress(new Map(sorted.map((entry) => [idKey(entry.id.replica, entry.id.counter), entry]))));
  }

  /**
   * The characters in Fugue order as pieces (PDT 2 phase 7, P2-T-02, Java's TextLeaf.pieces): characters of one run
   * that sit next to each other in that order, each piece a run whose parent and side are its first character's.
   */
  pieces(): TextRun[] {
    const chars = expand(this.runs);
    const ids = order(chars);
    const out: TextRun[] = [];
    for (let i = 0; i < ids.length;) {
      const start = ids[i]!;
      const first = chars.get(idKey(start.replica, start.counter))!.char;
      let text = "";
      let j = i;
      let last: CharId;
      do {
        last = ids[j]!;
        const c = chars.get(idKey(last.replica, last.counter))!.char;
        if (!c.deleted) {
          text += String.fromCodePoint(c.codePoint);
        }
        j += 1;
      } while (j < ids.length && continuesRun(last, ids[j]!, chars.get(idKey(ids[j]!.replica, ids[j]!.counter))!.char, first.deleted));
      out.push(new TextRun(start.replica, start.counter, first.parent, first.left ? "L" : "R", j - i, first.deleted, text));
      i = j;
    }
    return out;
  }

  /** The live text in Fugue order. */
  text(): string {
    const chars = expand(this.runs);
    let out = "";
    for (const id of order(chars)) {
      const { char } = chars.get(idKey(id.replica, id.counter))!;
      if (!char.deleted) {
        out += String.fromCodePoint(char.codePoint);
      }
    }
    return out;
  }

  encode(): Uint8Array {
    return encode({ k: KIND_T, r: [...this.runs], v: TextLeaf.VERSION });
  }

  /** Reads a `t` node; refuses another kind, another version, a missing key, or runs out of canonical form. */
  static decode(bytes: Uint8Array, cid: string | null = null): TextLeaf {
    const node = decodeKind(bytes, cid, KIND_T, ["r", "v"]);
    if (node["v"] !== TextLeaf.VERSION) {
      throw new NodeFormatError(`text leaf version ${String(node["v"])}; this release reads version ${TextLeaf.VERSION}`, cid);
    }
    return built(cid, () => new TextLeaf(node["r"] as TextRun[]));
  }
}

/** Whether a character continues the run of the one before it: the next counter, its right child, the same flag. */
function continuesRun(last: CharId, id: CharId, c: Char, deleted: boolean): boolean {
  return id.replica === last.replica && id.counter === last.counter + 1 && sameId(last, c.parent) && !c.left && c.deleted === deleted;
}

function sameRun(a: TextRun, b: TextRun): boolean {
  return a.replica === b.replica && a.counter === b.counter && sameId(a.parent, b.parent) && a.side === b.side
    && a.length === b.length && a.deleted === b.deleted && a.text === b.text;
}

// ------------------------------------------------------------------ vg (P2-V-01)

/**
 * A node of the persisted version graph, kind `vg` (PDT 2 phase 0, P2-V-01; §3.10): `{k:"vg", r: root,
 * b: [base roots], i: issuer, t: issued, p: [links to earlier vg nodes]}`. As Java's build pinned it, the
 * roots are CIDs held as text, never links, so a chain reaches the chain alone, and `p` links at most one
 * `vg` node per base, so a merge keeps the lineage of both parents. A head names its node by the attribute
 * `pdt.ancestry`; no value root links one and no head carries one inline (§6.10.3, rule 4).
 */
export class VgNode {
  readonly bases: readonly string[];
  readonly previous: readonly Link[];

  constructor(readonly root: string, bases: readonly string[], readonly issuer: string, readonly issued: string,
      previous: readonly Link[]) {
    this.bases = [...bases];
    this.previous = [...previous];
    if (bases.length > MAX_BASE) {
      throw new RangeError(`a vg node names at most ${MAX_BASE} bases, found ${bases.length}`);
    }
    if (!cids.isCid(root) || !bases.every((base) => cids.isCid(base))) {
      throw new RangeError("a vg node names its root and bases by CID");
    }
    if (previous.length > bases.length) {
      throw new RangeError("a vg node links at most one earlier vg node per base");
    }
    if (!previous.every((link) => link instanceof Link && cids.parse(link.cid).codec === cids.DAG_CBOR)) {
      throw new RangeError("a vg node links earlier vg nodes, which are dag-cbor");
    }
    if (!isAgentId(issuer)) {
      throw new RangeError(`a vg issuer is <peerId>/<localName>, found '${issuer}'`);
    }
    if (decodeHlc(issued) === null) {
      throw new RangeError(`a vg issued stamp is canonical, found '${issued}'`);
    }
  }

  encode(): Uint8Array {
    return encode({ k: KIND_VG, r: this.root, b: [...this.bases], i: this.issuer, t: this.issued, p: [...this.previous] });
  }

  static decode(bytes: Uint8Array, cid: string | null = null): VgNode {
    const node = decodeKind(bytes, cid, KIND_VG, ["r", "b", "i", "t", "p"]);
    return built(cid, () => new VgNode(node["r"] as string, node["b"] as string[], node["i"] as string,
      node["t"] as string, node["p"] as Link[]));
  }
}

// ------------------------------------------------------------------ bo (P2-B-02)

/**
 * A node of a blob's Bao outboard, kind `bo` (PDT 2 phase 0, P2-B-02; §3.5): `{k:"bo", g: 4, n: size,
 * p: parent chaining values, c: [links to child bo nodes]}` over chunk groups of 2^4 BLAKE3 chunks (16 KiB,
 * decision 10), reached only through the attribute `pdt.bao` (§6.10.3, rule 5). The split rule Java's build
 * pinned: `p` is one byte string of the parent pairs in pre-order; a node over at most {@link LEAF_GROUPS}
 * groups (8 MiB, PDT 2 phase 4 measures, P2-Q-PRF-05) is a leaf holding all `groups - 1` parents of its subtree; a larger node cuts its subtree into
 * aligned blocks of `LEAF_GROUPS x FANOUT^(j-1)` groups for the smallest j >= 1 that fits, links one child
 * per block, and holds the parents above the cut. The shape is a function of `n` alone.
 */
export class BoNode {
  /** log2 of the BLAKE3 chunks in one group: 16 chunks of 1 KiB (decision 10). */
  static readonly GROUP_LOG = 4;
  /** The bytes in one chunk group. */
  static readonly GROUP_BYTES = 1024 << 4;
  /** The bytes of one parent pair: two 32-byte chaining values. */
  static readonly PARENT_BYTES = 64;
  /** The most groups a leaf covers: 2^9, 8 MiB in 511 parents, about 32 KiB (the owner's ruling of 2026-11-09). */
  static readonly LEAF_GROUPS = 1 << 9;
  /** The most children an upper node links: 16, so an upper node costs about 1.6 KiB. */
  static readonly FANOUT = 1 << 4;

  readonly parents: Uint8Array;
  readonly children: readonly Link[];

  constructor(readonly size: number, parents: Uint8Array, children: readonly Link[]) {
    this.parents = parents.slice();
    this.children = [...children];
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new RangeError("a bo size is a non-negative integer");
    }
    const groups = BoNode.groups(size);
    const blocks = BoNode.childSizes(size);
    if (children.length !== blocks.length) {
      throw new RangeError(`a bo node over ${groups} groups has ${blocks.length} children, found ${children.length}`);
    }
    const expected = (blocks.length === 0 ? groups : blocks.length) - 1;
    if (parents.length !== expected * BoNode.PARENT_BYTES) {
      throw new RangeError(`a bo node's ${blocks.length === 0 ? `${groups} groups` : `${blocks.length} children`} take `
        + `${expected} parents, found ${parents.length} bytes`);
    }
  }

  /** The chunk groups a blob of `size` bytes holds: at least one, since an empty blob is one empty chunk. */
  static groups(size: number): number {
    return Math.max(1, Math.ceil(size / BoNode.GROUP_BYTES));
  }

  /** The byte counts of the child blocks of a node over `size` bytes, in order; empty for a leaf. */
  static childSizes(size: number): number[] {
    const groups = BoNode.groups(size);
    if (groups <= BoNode.LEAF_GROUPS) {
      return [];
    }
    let block = BoNode.LEAF_GROUPS;
    while (groups > block * BoNode.FANOUT) {
      block *= BoNode.FANOUT;
    }
    const blockBytes = block * BoNode.GROUP_BYTES;
    const sizes: number[] = [];
    for (let start = 0; start < size; start += blockBytes) {
      sizes.push(Math.min(blockBytes, size - start));
    }
    return sizes;
  }

  encode(): Uint8Array {
    return encode({ k: KIND_BO, g: BoNode.GROUP_LOG, n: this.size, p: this.parents, c: [...this.children] });
  }

  /** Reads a `bo` node; refuses another group size, a missing key, or parents and children the size does not imply. */
  static decode(bytes: Uint8Array, cid: string | null = null): BoNode {
    const node = decodeKind(bytes, cid, KIND_BO, ["g", "n", "p", "c"]);
    if (node["g"] !== BoNode.GROUP_LOG) {
      throw new NodeFormatError(`a bo node of group size 2^${String(node["g"])} chunks; this release reads 2^`
        + `${BoNode.GROUP_LOG} (decision 10)`, cid);
    }
    return built(cid, () => new BoNode(node["n"] as number, node["p"] as Uint8Array, node["c"] as Link[]));
  }
}
