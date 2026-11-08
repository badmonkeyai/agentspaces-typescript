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
import { Embedded, KIND_KEY, KIND_V, KIND_VR, Link, NodeFormatError, decode, encode } from "./nodes.js";
import { NodeStore } from "./store.js";
import { Codec, Ctx, Flusher, Ref, cborHeader, codecOf, refOf, resolve, sameValue, spill } from "./values.js";

export const WIDTH = 32;
export const BITS = 5;
export const MASK = WIDTH - 1;

export class VecNode {
  cid: string | null = null;

  constructor(readonly leaf: boolean, public slots: (Ref | VecNode | string)[], public edit: object | null) {}

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
    if (hasE && list.length !== WIDTH) {
      throw new NodeFormatError(`vector leaf with ${list.length} items; a leaf in the trie holds exactly 32`, cid);
    }
    const slots = list.map((item) => (item instanceof Link ? item.cid : refOf(item as Embedded)));
    const n = new VecNode(hasE, slots, null);
    n.cid = cid;
    return n;
  }
}

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

  constructor(public n: number, public shift: number, public trie: VecNode | string | null, public tail: Ref[],
              public edit: object | null) {}

  static empty(): VecRoot {
    return new VecRoot(0, BITS, null, [], null);
  }

  tailoff(): number {
    return tailoff(this.n);
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
    return this.leafFor(i, ctx).item(i & MASK) as Ref;
  }

  /** Items in index order; leaves load on demand. */
  *items(ctx: Ctx): Generator<Ref> {
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

  conj(item: Ref, ctx: Ctx): VecRoot {
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
      if ((i & MASK) === 0 && i + WIDTH <= Math.min(this.raw.tailoff(), base.raw.tailoff())) {
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

  equals(other: PVector<E>): boolean {
    return this.root() === other.root();
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
