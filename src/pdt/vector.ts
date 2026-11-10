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
 * The persistent vector (srad/agentspaces-pdt.md §3.2, PD-V-03, PD-V-04, §10.2): Clojure's trie with a
 * tail. The root is `{k:"vr", n: count, s: shift, r: link or null, t: [tail items]}`, an interior node
 * `{k:"v", c: [links]}`, a leaf `{k:"v", e: [32 items]}`; five index bits per level and the tail
 * outside the trie exactly as `PersistentVector` keeps it (tailoff = n < 32 ? 0 : ((n - 1) >>> 5) << 5),
 * so the layout is a function of the count alone. `conj` and `pop` write one root node until the tail
 * fills or empties; `assocN` copies at most shift / 5 + 1 nodes.
 */

import { concat } from "../bytes.js";
import type { CborValue } from "../cbor.js";
import { RrRoot, RvNode } from "./kinds.js";
import { Embedded, KIND_KEY, KIND_RR, KIND_RV, KIND_V, KIND_VR, Link, NodeFormatError, decode, encode, kindOf } from "./nodes.js";
import { NodeStore } from "./store.js";
import { Codec, Ctx, Flusher, Ref, cborHeader, codecOf, refOf, resolve, sameValue, spill } from "./values.js";

export const WIDTH = 32;
export const BITS = 5;
export const MASK = WIDTH - 1;

export class VecNode {
  cid: string | null = null;

  /**
   * @param sizes the cumulative element counts of a relaxed interior node read from an `rv` node (PDT 2 phase 7,
   *              P2-R-04), one per child; null on a leaf and on a dense node
   */
  constructor(readonly leaf: boolean, public slots: (Ref | VecNode | string)[], public edit: object | null,
              readonly sizes: number[] | null = null) {}

  editable(ctx: Ctx): VecNode {
    if (ctx.owns(this.edit)) {
      return this;
    }
    return new VecNode(this.leaf, [...this.slots], ctx.edit);
  }

  item(i: number): Ref | VecNode | string {
    if (i < 0 || i >= this.slots.length) {
      throw new NodeFormatError(`vector node has ${this.slots.length} slots where index ${i} was expected`, this.cid);
    }
    return this.slots[i]!;
  }

  child(i: number, ctx: Ctx): VecNode {
    const ref = this.item(i);
    if (ref instanceof VecNode) {
      return ref;
    }
    if (typeof ref !== "string") {
      throw new NodeFormatError(`slot ${i} holds an item where a child was expected`, this.cid);
    }
    const loaded = VecNode.decode(ref, ctx.load(ref));
    this.slots[i] = loaded;
    return loaded;
  }

  appended(slot: Ref | VecNode, ctx: Ctx): VecNode {
    const n = this.editable(ctx);
    n.slots.push(slot);
    return n;
  }

  shrunk(ctx: Ctx): VecNode {
    const n = this.editable(ctx);
    n.slots.pop();
    return n;
  }

  withSlot(i: number, slot: Ref | VecNode, ctx: Ctx): VecNode {
    const n = this.editable(ctx);
    n.slots[i] = slot;
    return n;
  }

  encode(flusher: Flusher): Uint8Array {
    if (this.leaf) {
      return encode({ [KIND_KEY]: KIND_V, e: this.slots.map((s) => flusher.embed(s as Ref)) });
    }
    return encode({ [KIND_KEY]: KIND_V, c: this.slots.map((s) => new Link(flusher.cidOf(s as VecNode | string))) });
  }

  static decode(cid: string | null, bytes: Uint8Array): VecNode {
    const n = VecNode.decodeV(cid, bytes);
    if (n.leaf && n.slots.length !== WIDTH) {
      throw new NodeFormatError(`vector leaf with ${n.slots.length} items; a leaf in the trie holds exactly 32`, cid);
    }
    return n;
  }

  /** A `v` node of 1 to 32 slots. */
  private static decodeV(cid: string | null, bytes: Uint8Array): VecNode {
    const node = decode(bytes, cid);
    if (node[KIND_KEY] !== KIND_V) {
      throw new NodeFormatError(`expected a vector node, found kind '${String(node[KIND_KEY])}'`, cid);
    }
    const hasC = Array.isArray(node["c"]);
    const hasE = Array.isArray(node["e"]);
    if (hasC === hasE) {
      throw new NodeFormatError("a vector node holds either 'c' or 'e'", cid);
    }
    const list = (hasC ? node["c"] : node["e"]) as (Link | Embedded)[];
    if (list.length === 0 || list.length > WIDTH) {
      throw new NodeFormatError(`vector node with ${list.length} slots; 1 to 32 expected`, cid);
    }
    const slots = list.map((item) => (item instanceof Link ? item.cid : refOf(item as Embedded)));
    const n = new VecNode(hasE, slots, null);
    n.cid = cid;
    return n;
  }

  /**
   * Reads a node of a relaxed tree at a known level (PDT 2 phase 7, P2-R-04; Java's VecNode.decodeRelaxed): a `v` leaf
   * of 1 to 32 items at level 0, a dense `v` interior node above it, or an `rv` node whose size table describes a
   * relaxed node. It refuses by name an `rv` node without `z`, a size table a radix index reads the same way, a child
   * that holds more elements than its level holds, and a node that does not hold the elements its parent counts under
   * it, so an index and an iteration read the same elements.
   *
   * @param level 0 for a leaf, else the shift of its children's index bits
   * @param count the elements its parent counts under it
   */
  static decodeRelaxed(cid: string, bytes: Uint8Array, level: number, count: number): VecNode {
    const node = kindOf(bytes, cid) === KIND_RV ? VecNode.decodeRv(cid, bytes, level) : VecNode.decodeV(cid, bytes);
    if (node.sizes === null && node.leaf !== (level === 0)) {
      throw new NodeFormatError(`a vector ${node.leaf ? "leaf" : "interior node"} at level ${level}`, cid);
    }
    const width = node.slots.length;
    const capacity = 2 ** level;
    const fits = node.sizes !== null ? node.sizes[width - 1] === count : (width - 1) * capacity < count && count <= width * capacity;
    if (!fits) {
      throw new NodeFormatError(`a vector node of ${width} slots at level ${level} does not hold the ${count} elements its`
        + " parent counts under it", cid);
    }
    return node;
  }

  private static decodeRv(cid: string, bytes: Uint8Array, level: number): VecNode {
    if (level === 0) {
      throw new NodeFormatError("an rv node where a vector leaf belongs", cid);
    }
    const rv = RvNode.decode(bytes, cid);
    if (rv.sizes === null) {
      throw new NodeFormatError("an rv node without z; a dense interior node is a v node", cid);
    }
    const capacity = 2 ** level;
    let previous = 0;
    let dense = true;
    rv.sizes.forEach((size, i) => {
      if (size > MAX_COUNT) {
        throw new NodeFormatError(`an rv size of ${size} passes the 2^31 - 1 elements a vector holds`, cid);
      }
      if (size - previous > capacity) {
        throw new NodeFormatError(`an rv child holds ${size - previous} elements, more than the ${capacity} its level holds`, cid);
      }
      dense &&= i === rv.sizes!.length - 1 || size - previous === capacity;
      previous = size;
    });
    if (dense) {
      throw new NodeFormatError("a size table on a dense node; a dense interior node is a v node", cid);
    }
    const node = new VecNode(false, rv.children.map((link) => link.cid), null, [...rv.sizes]);
    node.cid = cid;
    return node;
  }
}

/** The most elements a vector holds, and the deepest shift a reader reads (P2-R-04). */
const MAX_COUNT = 0x7fffffff;
const MAX_SHIFT = 30;

export function tailoff(n: number): number {
  return n < WIDTH ? 0 : ((n - 1) >>> BITS) << BITS;
}

export function shiftFor(n: number): number {
  const off = tailoff(n);
  let s = BITS;
  while (off > 0 && ((off - 1) >>> s) >= WIDTH) {
    s += BITS;
  }
  return s;
}

export class VecRoot {
  cid: string | null = null;

  /**
   * @param relaxed whether this is the root of an RRB tree read from an `rr` node (PDT 2 phase 7, P2-R-04): its tail
   *                holds 0 to 32 elements whatever the count and its trie may hold relaxed nodes, so it reads through
   *                the size tables, and an edit packs it first (P2-R-03)
   */
  constructor(public n: number, public shift: number, public trie: VecNode | string | null, public tail: Ref[],
              public edit: object | null, readonly relaxed = false) {}

  static empty(): VecRoot {
    return new VecRoot(0, BITS, null, [], null);
  }

  tailoff(): number {
    return this.relaxed ? this.n - this.tail.length : tailoff(this.n);
  }

  private editable(ctx: Ctx): VecRoot {
    if (ctx.owns(this.edit)) {
      return this;
    }
    return new VecRoot(this.n, this.shift, this.trie, [...this.tail], ctx.edit);
  }

  trieNode(ctx: Ctx): VecNode {
    if (this.trie instanceof VecNode) {
      return this.trie;
    }
    if (this.trie === null) {
      throw new NodeFormatError("vector has no trie", this.cid);
    }
    const loaded = VecNode.decode(this.trie, ctx.load(this.trie));
    this.trie = loaded;
    return loaded;
  }

  // ---- reads

  leafFor(i: number, ctx: Ctx): VecNode {
    let node = this.trieNode(ctx);
    for (let level = this.shift; level > 0; level -= BITS) {
      node = node.child((i >>> level) & MASK, ctx);
    }
    return node;
  }

  nth(i: number, ctx: Ctx): Ref {
    if (i < 0 || i >= this.n) {
      throw new RangeError(`index ${i} of a vector of ${this.n}`);
    }
    if (i >= this.tailoff()) {
      return this.tail[i - this.tailoff()]!;
    }
    if (this.relaxed) {
      const { leaf, start } = relaxedLeafAt(this, i, ctx);
      return leaf.item(i - start) as Ref;
    }
    return this.leafFor(i, ctx).item(i & MASK) as Ref;
  }

  /** Items in index order; leaves load on demand. */
  *items(ctx: Ctx): Generator<Ref> {
    if (this.relaxed) {
      if (this.trie !== null) {
        yield* relaxedLeaves(relaxedTrie(this, ctx), ctx);
      }
      yield* this.tail;
      return;
    }
    const off = this.tailoff();
    for (let i = 0; i < off; i += WIDTH) {
      const leaf = this.leafFor(i, ctx);
      for (let j = 0; j < WIDTH; j++) {
        yield leaf.item(j) as Ref;
      }
    }
    for (const item of this.tail) {
      yield item;
    }
  }

  // ---- writes

  /** The leftwise-dense `vr` root of the same elements (P2-R-03), built under a private edit token; this root when dense. */
  packed(ctx: Ctx): VecRoot {
    if (!this.relaxed) {
      return this;
    }
    const edit = new Ctx(ctx.store, {});
    let out = VecRoot.empty();
    for (const item of this.items(ctx)) {
      out = out.conj(item, edit);
    }
    return out;
  }

  conj(item: Ref, ctx: Ctx): VecRoot {
    if (this.relaxed) {
      return this.packed(ctx).conj(item, ctx);
    }
    const off = this.tailoff();
    if (this.n - off < WIDTH) {
      const r = this.editable(ctx);
      r.tail.push(item);
      r.n = this.n + 1;
      return r;
    }
    const tailNode = new VecNode(true, this.tail, ctx.edit);
    const r = this.editable(ctx);
    if (this.trie === null) {
      r.trie = new VecNode(false, [tailNode], ctx.edit);
      r.shift = BITS;
    } else if ((this.n >>> BITS) > (1 << this.shift)) {
      r.trie = new VecNode(false, [this.trie, newPath(this.shift, tailNode, ctx)], ctx.edit);
      r.shift = this.shift + BITS;
    } else {
      r.trie = this.pushTail(this.shift, this.trieNode(ctx), tailNode, ctx);
    }
    r.tail = [item];
    r.n = this.n + 1;
    return r;
  }

  private pushTail(level: number, parent: VecNode, tailNode: VecNode, ctx: Ctx): VecNode {
    const subidx = ((this.n - 1) >>> level) & MASK;
    if (level === BITS) {
      return parent.appended(tailNode, ctx);
    }
    if (subidx < parent.slots.length) {
      const child = parent.child(subidx, ctx);
      const next = this.pushTail(level - BITS, child, tailNode, ctx);
      return next === child ? parent : parent.withSlot(subidx, next, ctx);
    }
    return parent.appended(newPath(level - BITS, tailNode, ctx), ctx);
  }

  pop(ctx: Ctx): VecRoot {
    if (this.n === 0) {
      throw new Error("pop on an empty vector");
    }
    if (this.relaxed) {
      return this.packed(ctx).pop(ctx);
    }
    const off = this.tailoff();
    if (this.n - off > 1) {
      const r = this.editable(ctx);
      r.tail.pop();
      r.n = this.n - 1;
      return r;
    }
    if (this.n === 1) {
      const r = this.editable(ctx);
      r.tail = [];
      r.n = 0;
      r.trie = null;
      r.shift = BITS;
      return r;
    }
    const newTail = [...this.leafFor(this.n - 2, ctx).slots] as Ref[];
    let newTrie = this.popTail(this.shift, this.trieNode(ctx), ctx);
    const r = this.editable(ctx);
    let newShift = this.shift;
    if (newTrie === null) {
      newShift = BITS;
    } else if (this.shift > BITS && newTrie.slots.length === 1) {
      newTrie = newTrie.child(0, ctx);
      newShift = this.shift - BITS;
    }
    r.trie = newTrie;
    r.shift = newShift;
    r.tail = newTail;
    r.n = this.n - 1;
    return r;
  }

  private popTail(level: number, node: VecNode, ctx: Ctx): VecNode | null {
    const subidx = ((this.n - 2) >>> level) & MASK;
    if (level > BITS) {
      const next = this.popTail(level - BITS, node.child(subidx, ctx), ctx);
      if (next === null) {
        return subidx === 0 ? null : node.shrunk(ctx);
      }
      return node.withSlot(subidx, next, ctx);
    }
    return subidx === 0 ? null : node.shrunk(ctx);
  }

  assocN(i: number, item: Ref, ctx: Ctx): VecRoot {
    if (i < 0 || i >= this.n) {
      throw new RangeError(`index ${i} of a vector of ${this.n}`);
    }
    if (this.relaxed) {
      return this.packed(ctx).assocN(i, item, ctx);
    }
    const off = this.tailoff();
    if (i >= off) {
      if (sameValue(this.tail[i - off]!, item)) {
        return this;
      }
      const r = this.editable(ctx);
      r.tail[i - off] = item;
      return r;
    }
    const next = doAssoc(this.shift, this.trieNode(ctx), i, item, ctx);
    if (next === this.trie) {
      return this;
    }
    const r = this.editable(ctx);
    r.trie = next;
    return r;
  }

  // ---- codec

  encode(flusher: Flusher): Uint8Array {
    return encode({ [KIND_KEY]: KIND_VR, n: this.n, s: this.shift,
      r: this.trie === null ? null : new Link(flusher.cidOf(this.trie)), t: this.tail.map((t) => flusher.embed(t)) });
  }

  static decode(cid: string | null, bytes: Uint8Array): VecRoot {
    if (kindOf(bytes, cid) === KIND_RR) {
      return VecRoot.decodeRr(cid, bytes);
    }
    const node = decode(bytes, cid);
    if (node[KIND_KEY] !== KIND_VR) {
      throw new NodeFormatError(`expected a vector root, found kind '${String(node[KIND_KEY])}'`, cid);
    }
    const n = (node["n"] as number | undefined) ?? 0;
    const shift = (node["s"] as number | undefined) ?? BITS;
    if (n > 0x7fffffff || shift < BITS || shift > 30 || shift % BITS !== 0) {
      throw new NodeFormatError(`vector root with count ${n} and shift ${shift}`, cid);
    }
    const trie = node["r"] instanceof Link ? node["r"].cid : null;
    const t = (node["t"] as Embedded[] | undefined) ?? [];
    if (t.length > WIDTH) {
      throw new NodeFormatError(`vector tail of ${t.length} elements`, cid);
    }
    if (t.length !== n - tailoff(n) || (trie === null) !== (tailoff(n) === 0)) {
      throw new NodeFormatError(`vector tail and trie do not match the count ${n}`, cid);
    }
    if (shift !== shiftFor(n)) {
      throw new NodeFormatError(`vector root with shift ${shift} where the count ${n} implies ${shiftFor(n)}`, cid);
    }
    const r = new VecRoot(n, shift, trie, t.map(refOf), null);
    r.cid = cid;
    return r;
  }

  /**
   * Reads an `rr` root (PDT 2 phase 7, P2-R-04): the shape {@link RrRoot} checks, a count a vector can hold, and a
   * shift of at most 30; the nodes below it load on demand through {@link VecNode.decodeRelaxed}.
   */
  private static decodeRr(cid: string | null, bytes: Uint8Array): VecRoot {
    const rr = RrRoot.decode(bytes, cid);
    if (rr.count > MAX_COUNT || rr.shift > MAX_SHIFT) {
      throw new NodeFormatError(`rr root with count ${rr.count} and shift ${rr.shift}`, cid);
    }
    const r = new VecRoot(rr.count, rr.shift, rr.trie === null ? null : rr.trie.cid, rr.tail.map(refOf), null, true);
    r.cid = cid;
    return r;
  }
}

// ------------------------------------------------------------------ relaxed reads (PDT 2 phase 7, P2-R-04)

/** A sub-tree of a relaxed root: a node or its CID at a level, and the elements under it (Java's Rrb.Sub). */
interface Sub { ref: VecNode | string; level: number; count: number }

/** A node at a level, read and checked against the elements its parent counts under it. */
function loadSub(sub: Sub, ctx: Ctx): VecNode {
  return sub.ref instanceof VecNode ? sub.ref : VecNode.decodeRelaxed(sub.ref, ctx.load(sub.ref), sub.level, sub.count);
}

/** The elements under child `j` of a node: from the size table when relaxed, else a full child but the last. */
function childCount(node: VecNode, j: number, level: number, count: number): number {
  if (node.sizes !== null) {
    return node.sizes[j]! - (j === 0 ? 0 : node.sizes[j - 1]!);
  }
  const last = node.slots.length - 1;
  return j < last ? 2 ** level : count - last * 2 ** level;
}

/** Child `j` of a sub-tree, loaded and kept in its parent's slot. */
function kid(sub: Sub, j: number, ctx: Ctx): Sub {
  const node = loadSub(sub, ctx);
  const ref = node.item(j);
  const child: Sub = { ref: ref as VecNode | string, level: sub.level - BITS, count: childCount(node, j, sub.level, sub.count) };
  if (ref instanceof VecNode) {
    return child;
  }
  const loaded = loadSub(child, ctx);
  node.slots[j] = loaded;
  return { ...child, ref: loaded };
}

/** The trie of a relaxed root as a sub-tree, loaded and kept on the root. */
function relaxedTrie(root: VecRoot, ctx: Ctx): Sub {
  const loaded = loadSub({ ref: root.trie!, level: root.shift, count: root.tailoff() }, ctx);
  root.trie = loaded;
  return { ref: loaded, level: root.shift, count: root.tailoff() };
}

/** The child of a node that holds a local index: by radix when dense, by binary search of `z` when relaxed. */
function locate(node: VecNode, level: number, index: number): number {
  if (node.sizes === null) {
    return Math.floor(index / 2 ** level);
  }
  const z = node.sizes;
  let lo = 0, hi = z.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (z[mid]! > index) {
      hi = mid;
    } else {
      lo = mid + 1;
    }
  }
  return lo;
}

/** The elements before child `j` of a node at a level. */
function before(node: VecNode, level: number, j: number): number {
  return node.sizes === null ? j * 2 ** level : j === 0 ? 0 : node.sizes[j - 1]!;
}

/** The leaf of a relaxed root that holds a trie index, and the index of its first element. */
function relaxedLeafAt(root: VecRoot, index: number, ctx: Ctx): { leaf: VecNode; start: number } {
  let at = relaxedTrie(root, ctx);
  let start = 0;
  while (at.level > 0) {
    const node = loadSub(at, ctx);
    const j = locate(node, at.level, index - start);
    start += before(node, at.level, j);
    at = kid(at, j, ctx);
  }
  return { leaf: loadSub(at, ctx), start };
}

function* relaxedLeaves(sub: Sub, ctx: Ctx): Generator<Ref> {
  const node = loadSub(sub, ctx);
  if (sub.level === 0) {
    yield* node.slots as Ref[];
    return;
  }
  for (let j = 0; j < node.slots.length; j++) {
    yield* relaxedLeaves(kid(sub, j, ctx), ctx);
  }
}

function newPath(level: number, node: VecNode, ctx: Ctx): VecNode {
  if (level === 0) {
    return node;
  }
  return new VecNode(false, [newPath(level - BITS, node, ctx)], ctx.edit);
}

function doAssoc(level: number, node: VecNode, i: number, item: Ref, ctx: Ctx): VecNode {
  if (level === 0) {
    if (sameValue(node.slots[i & MASK] as Ref, item)) {
      return node;
    }
    return node.withSlot(i & MASK, item, ctx);
  }
  const subidx = (i >>> level) & MASK;
  const child = node.child(subidx, ctx);
  const next = doAssoc(level - BITS, child, i, item, ctx);
  return next === child ? node : node.withSlot(subidx, next, ctx);
}

/** The CBOR of a spilled array: a definite array of the resolved items. */
export function reassembleArray(root: VecRoot, ctx: Ctx, depth: number): Uint8Array {
  const parts: Uint8Array[] = [cborHeader(4, root.n)];
  for (const item of root.items(ctx)) {
    parts.push(resolve(item, ctx, depth + 1));
  }
  return concat(...parts);
}

export interface VectorDiff { changed: [number, number][]; added: number; removed: number }

/** The typed persistent vector. */
export class PVector<E = CborValue> implements Iterable<E> {
  constructor(readonly raw: VecRoot, readonly ctx: Ctx, readonly codec: Codec<E>) {}

  static empty<E = CborValue>(store: NodeStore, codec?: Codec<E>): PVector<E> {
    return new PVector(VecRoot.empty(), new Ctx(store), codecOf(codec));
  }

  static load<E = CborValue>(store: NodeStore, root: string, codec?: Codec<E>): PVector<E> {
    return new PVector(VecRoot.decode(root, store.load(root)), new Ctx(store), codecOf(codec));
  }

  get store(): NodeStore {
    return this.ctx.store;
  }

  count(): number {
    return this.raw.n;
  }

  /** Whether this vector's root is an `rr` root that still holds a relaxed node (P2-R-03); a head over it is `PRef.v` 2. */
  relaxed(): boolean {
    return this.raw.relaxed;
  }

  /** The leftwise-dense `vr` vector of the same elements, whose root those elements have whatever the history (P2-R-03). */
  packed(): PVector<E> {
    return this.raw.relaxed ? new PVector(this.raw.packed(this.ctx), this.ctx, this.codec) : this;
  }

  isEmpty(): boolean {
    return this.raw.n === 0;
  }

  nth(i: number): E {
    return this.codec.decode(resolve(this.raw.nth(i, this.ctx), this.ctx));
  }

  conj(item: E): PVector<E> {
    return new PVector(this.raw.conj(spill(this.codec.encode(item), this.ctx), this.ctx), this.ctx, this.codec);
  }

  pop(): PVector<E> {
    return new PVector(this.raw.pop(this.ctx), this.ctx, this.codec);
  }

  assocN(i: number, item: E): PVector<E> {
    const next = this.raw.assocN(i, spill(this.codec.encode(item), this.ctx), this.ctx);
    return next === this.raw ? this : new PVector(next, this.ctx, this.codec);
  }

  update(i: number, f: (item: E) => E): PVector<E> {
    return this.assocN(i, f(this.nth(i)));
  }

  /** The root CID; writes the new nodes to the store (PD-V-08). */
  root(): string {
    if (this.raw.cid === null) {
      Flusher.flush(this.raw, this.ctx.store);
    }
    return this.raw.cid!;
  }

  *[Symbol.iterator](): Iterator<E> {
    for (const item of this.raw.items(this.ctx)) {
      yield this.codec.decode(resolve(item, this.ctx));
    }
  }

  toArray(): E[] {
    return [...this];
  }

  editor(): VectorEditor<E> {
    return new VectorEditor(this);
  }

  /** Index ranges whose items differ from `base`, comparing leaves by CID where both are hashed. */
  diff(base: PVector<E>): VectorDiff {
    const common = Math.min(this.count(), base.count());
    const changed: [number, number][] = [];
    let open: [number, number] | null = null;
    for (let i = 0; i < common; i++) {
      let same: boolean;
      // a relaxed vector compares element by element, since its leaves need not align with the other's
      if (!this.raw.relaxed && !base.raw.relaxed && (i & MASK) === 0 && i + WIDTH <= Math.min(this.raw.tailoff(), base.raw.tailoff())) {
        const a = this.raw.leafFor(i, this.ctx), b = base.raw.leafFor(i, base.ctx);
        if (a === b || (a.cid !== null && a.cid === b.cid)) {
          if (open !== null) {
            changed.push(open);
            open = null;
          }
          i += WIDTH - 1;
          continue;
        }
      }
      same = sameValue(this.raw.nth(i, this.ctx), base.raw.nth(i, base.ctx));
      if (!same) {
        if (open === null) {
          open = [i, i + 1];
        } else {
          open[1] = i + 1;
        }
      } else if (open !== null) {
        changed.push(open);
        open = null;
      }
    }
    if (open !== null) {
      changed.push(open);
    }
    return { changed, added: Math.max(0, this.count() - base.count()), removed: Math.max(0, base.count() - this.count()) };
  }

  /** Equality by the packed roots (P2-R-03): two vectors of the same elements are equal whatever their histories. */
  equals(other: PVector<E>): boolean {
    return this.packed().root() === other.packed().root();
  }
}

/** The transient of a `PVector`. */
export class VectorEditor<E> {
  private raw: VecRoot;
  private ctx: Ctx | null;

  constructor(from: PVector<E>, private readonly codec: Codec<E> = from.codec) {
    this.ctx = new Ctx(from.ctx.store, {});
    this.raw = from.raw;
  }

  private live(): Ctx {
    if (this.ctx === null) {
      throw new Error("this editor is done");
    }
    return this.ctx;
  }

  conj(item: E): this {
    const ctx = this.live();
    this.raw = this.raw.conj(spill(this.codec.encode(item), ctx), ctx);
    return this;
  }

  pop(): this {
    const ctx = this.live();
    this.raw = this.raw.pop(ctx);
    return this;
  }

  assocN(i: number, item: E): this {
    const ctx = this.live();
    this.raw = this.raw.assocN(i, spill(this.codec.encode(item), ctx), ctx);
    return this;
  }

  count(): number {
    return this.raw.n;
  }

  done(): PVector<E> {
    const ctx = this.live();
    this.ctx = null;
    return new PVector(this.raw, new Ctx(ctx.store), this.codec);
  }
}
