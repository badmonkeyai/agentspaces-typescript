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
 * The persistent map and set (srad/agentspaces-pdt.md §3.2, PD-V-01, PD-V-02, PD-V-04, PD-V-05,
 * PD-V-07, PD-V-09, §10.2): a CHAMP trie with 32-way nodes. The hash of a key is sha2-256 of its CBOR
 * bytes; level d reads bits 5d..5d+4 of the digest as a big-endian bit string. A node is
 * `{k:"m", d: datamap, n: nodemap, e: [k0, v0, ...] in slot order, c: [links] in slot order}` with
 * `cnt` on the root only; after a removal a child with one entry and no children inlines into its
 * parent, so a key set has one layout whatever the order of operations. Past level 51 keys sit in a
 * collision node `{k:"mc", e: [...]}` sorted by key bytes. A `PSet` is a `PMap` whose values are null.
 *
 * Values never change the receiver: `assoc` and `dissoc` return new values that share every untouched
 * node; `editor()` returns a transient that edits the nodes it created in place and returns, from
 * `done()`, a value whose new nodes are exactly the batch's final path set. New nodes stay unhashed
 * until `root()` needs the CID (PD-V-08), and then every new node is written once.
 */

import { compare, concat } from "../bytes.js";
import type { CborValue } from "../cbor.js";
import { Embedded, KIND_KEY, KIND_M, KIND_MC, Link, NodeFormatError, decode } from "./nodes.js";
import { NodeStore } from "./store.js";
import { Codec, Ctx, Flusher, Ref, bytesEqual, checkKey, codecOf, equalHashed, hashKey, refOf, resolve, sameValue,
  spill } from "./values.js";

export const COLLISION_LEVEL = 52;
const WIDTH = 32;

export interface Change { added: boolean; removed: boolean; replaced: boolean; before?: Ref }

function bitCount(n: number): number {
  n = n - ((n >>> 1) & 0x55555555);
  n = (n & 0x33333333) + ((n >>> 2) & 0x33333333);
  return (((n + (n >>> 4)) & 0x0f0f0f0f) * 0x01010101) >>> 24;
}

function trailingZeros(n: number): number {
  if (n === 0) {
    return 32;
  }
  let count = 0;
  while ((n & 1) === 0) {
    n >>>= 1;
    count += 1;
  }
  return count;
}

/** The slot of a digest at a level: five bits, big-endian, bit 0 the most significant bit of byte 0. */
export function slotIndex(digest: Uint8Array, level: number): number {
  const first = level * 5;
  let idx = 0;
  for (let i = 0; i < 5; i++) {
    const bit = first + i;
    const v = bit < digest.length * 8 ? (digest[bit >>> 3]! >>> (7 - (bit & 7))) & 1 : 0;
    idx = (idx << 1) | v;
  }
  return idx;
}

const bit = (slot: number): number => (1 << slot) >>> 0;

export class ChampNode {
  cid: string | null = null;
  cnt = -1;

  constructor(readonly collision: boolean, public datamap: number, public nodemap: number,
              public keys: Uint8Array[], public values: Ref[], public children: (ChampNode | string)[],
              public edit: object | null) {}

  static empty(): ChampNode {
    return new ChampNode(false, 0, 0, [], [], [], null);
  }

  private dataIndex(b: number): number {
    return bitCount((this.datamap & (b - 1)) >>> 0);
  }

  private nodeIndex(b: number): number {
    return bitCount((this.nodemap & (b - 1)) >>> 0);
  }

  singleEntry(): boolean {
    return this.keys.length === 1 && this.children.length === 0;
  }

  // ---- reads

  child(i: number, level: number, ctx: Ctx): ChampNode {
    const ref = this.children[i]!;
    if (ref instanceof ChampNode) {
      return ref;
    }
    const loaded = ChampNode.load(ref, level, ctx);
    this.children[i] = loaded;
    return loaded;
  }

  static load(cid: string, level: number, ctx: Ctx): ChampNode {
    const node = ChampNode.decode(cid, ctx.load(cid), false);
    node.verifyAt(level);
    return node;
  }

  static loadRoot(cid: string, bytes: Uint8Array): ChampNode {
    const node = ChampNode.decode(cid, bytes, true);
    node.verifyAt(0);
    return node;
  }

  /** Refuses a node whose layout contradicts its level (a lazily loaded node is checked on arrival). */
  verifyAt(level: number): void {
    if (this.collision && level < COLLISION_LEVEL) {
      throw new NodeFormatError(`collision node at level ${level}; keys collide only past level ${COLLISION_LEVEL - 1}`, this.cid);
    }
    if (!this.collision && level >= COLLISION_LEVEL) {
      throw new NodeFormatError(`map node at level ${level}; keys past level ${COLLISION_LEVEL - 1} sit in a collision node`, this.cid);
    }
    if (this.collision) {
      return;
    }
    let remaining = this.datamap;
    for (let i = 0; i < this.keys.length; i++) {
      const slot = trailingZeros(remaining);
      remaining = (remaining & (remaining - 1)) >>> 0;
      const named = slotIndex(hashKey(this.keys[i]!), level);
      if (named !== slot) {
        throw new NodeFormatError(`entry ${i} sits in slot ${slot} at level ${level} where its key digest names slot ${named}`, this.cid);
      }
    }
  }

  find(digest: Uint8Array, level: number, key: Uint8Array, ctx: Ctx): Ref | undefined {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    let node: ChampNode = this;
    for (;;) {
      if (node.collision) {
        for (let i = 0; i < node.keys.length; i++) {
          if (bytesEqual(node.keys[i]!, key)) {
            return node.values[i];
          }
        }
        return undefined;
      }
      const b = bit(slotIndex(digest, level));
      if ((node.datamap & b) !== 0) {
        const i = node.dataIndex(b);
        return bytesEqual(node.keys[i]!, key) ? node.values[i] : undefined;
      }
      if ((node.nodemap & b) !== 0) {
        level += 1;
        node = node.child(node.nodeIndex(b), level, ctx);
        continue;
      }
      return undefined;
    }
  }

  /** Entries in slot order, depth first. */
  *entries(level: number, ctx: Ctx): Generator<[Uint8Array, Ref]> {
    if (this.collision) {
      for (let i = 0; i < this.keys.length; i++) {
        yield [this.keys[i]!, this.values[i]!];
      }
      return;
    }
    let di = 0, ni = 0;
    for (let slot = 0; slot < WIDTH; slot++) {
      const b = bit(slot);
      if ((this.datamap & b) !== 0) {
        yield [this.keys[di]!, this.values[di]!];
        di += 1;
      } else if ((this.nodemap & b) !== 0) {
        yield* this.child(ni, level + 1, ctx).entries(level + 1, ctx);
        ni += 1;
      }
    }
  }

  // ---- writes

  private editable(ctx: Ctx): ChampNode {
    if (ctx.owns(this.edit)) {
      return this;
    }
    return new ChampNode(this.collision, this.datamap, this.nodemap, [...this.keys], [...this.values], [...this.children], ctx.edit);
  }

  assoc(digest: Uint8Array, level: number, key: Uint8Array, value: Ref, ctx: Ctx, change: Change): ChampNode {
    if (this.collision) {
      return this.assocCollision(key, value, ctx, change);
    }
    const b = bit(slotIndex(digest, level));
    if ((this.datamap & b) !== 0) {
      const i = this.dataIndex(b);
      if (bytesEqual(this.keys[i]!, key)) {
        if (sameValue(this.values[i]!, value)) {
          return this;
        }
        change.replaced = true;
        change.before = this.values[i];
        const n = this.editable(ctx);
        n.values[i] = value;
        return n;
      }
      const otherDigest = hashKey(this.keys[i]!);
      const sub = mergeTwo(this.keys[i]!, this.values[i]!, otherDigest, key, value, digest, level + 1, ctx);
      change.added = true;
      const n = this.editable(ctx);
      n.removeEntryAt(i);
      n.datamap = (n.datamap & ~b) >>> 0;
      n.nodemap = (n.nodemap | b) >>> 0;
      n.children.splice(n.nodeIndex(b), 0, sub);
      return n;
    }
    if ((this.nodemap & b) !== 0) {
      const i = this.nodeIndex(b);
      const child = this.child(i, level + 1, ctx);
      const next = child.assoc(digest, level + 1, key, value, ctx, change);
      if (!(change.added || change.removed || change.replaced) || next === child) {
        return this;
      }
      const n = this.editable(ctx);
      n.children[i] = next;
      return n;
    }
    change.added = true;
    const n = this.editable(ctx);
    n.datamap = (n.datamap | b) >>> 0;
    n.insertEntryAt(n.dataIndex(b), key, value);
    return n;
  }

  private assocCollision(key: Uint8Array, value: Ref, ctx: Ctx, change: Change): ChampNode {
    let pos = 0;
    while (pos < this.keys.length) {
      const order = compare(this.keys[pos]!, key);
      if (order === 0) {
        if (sameValue(this.values[pos]!, value)) {
          return this;
        }
        change.replaced = true;
        change.before = this.values[pos];
        const n = this.editable(ctx);
        n.values[pos] = value;
        return n;
      }
      if (order > 0) {
        break;
      }
      pos += 1;
    }
    change.added = true;
    const n = this.editable(ctx);
    n.insertEntryAt(pos, key, value);
    return n;
  }

  dissoc(digest: Uint8Array, level: number, key: Uint8Array, ctx: Ctx, change: Change): ChampNode {
    if (this.collision) {
      for (let i = 0; i < this.keys.length; i++) {
        if (bytesEqual(this.keys[i]!, key)) {
          change.removed = true;
          change.before = this.values[i];
          const n = this.editable(ctx);
          n.removeEntryAt(i);
          return n;
        }
      }
      return this;
    }
    const b = bit(slotIndex(digest, level));
    if ((this.datamap & b) !== 0) {
      const i = this.dataIndex(b);
      if (!bytesEqual(this.keys[i]!, key)) {
        return this;
      }
      change.removed = true;
      change.before = this.values[i];
      const n = this.editable(ctx);
      n.removeEntryAt(i);
      n.datamap = (n.datamap & ~b) >>> 0;
      return n;
    }
    if ((this.nodemap & b) !== 0) {
      const i = this.nodeIndex(b);
      const child = this.child(i, level + 1, ctx);
      const next = child.dissoc(digest, level + 1, key, ctx, change);
      if (!change.removed) {
        return this;
      }
      const n = this.editable(ctx);
      if (next.singleEntry()) {
        n.children.splice(i, 1);
        n.nodemap = (n.nodemap & ~b) >>> 0;
        n.datamap = (n.datamap | b) >>> 0;
        n.insertEntryAt(n.dataIndex(b), next.keys[0]!, next.values[0]!);
        return n;
      }
      n.children[i] = next;
      return n;
    }
    return this;
  }

  private insertEntryAt(i: number, key: Uint8Array, value: Ref): void {
    this.keys.splice(i, 0, key);
    this.values.splice(i, 0, value);
  }

  private removeEntryAt(i: number): void {
    this.keys.splice(i, 1);
    this.values.splice(i, 1);
  }

  // ---- codec

  encode(flusher: Flusher): Uint8Array {
    const entries: Embedded[] = [];
    for (let i = 0; i < this.keys.length; i++) {
      entries.push(new Embedded(this.keys[i]!));
      entries.push(flusher.embed(this.values[i]!));
    }
    if (this.collision) {
      return encodeNode({ [KIND_KEY]: KIND_MC, e: entries });
    }
    const links: Link[] = this.children.map((child) => new Link(flusher.cidOf(child)));
    const node: import("./nodes.js").Node = { [KIND_KEY]: KIND_M, d: this.datamap, n: this.nodemap, e: entries, c: links };
    if (this.cnt >= 0) {
      node["cnt"] = this.cnt;
    }
    return encodeNode(node);
  }

  static decode(cid: string | null, bytes: Uint8Array, root: boolean): ChampNode {
    const node = decode(bytes, cid);
    const kind = node[KIND_KEY];
    if (kind !== KIND_M && kind !== KIND_MC) {
      throw new NodeFormatError(`expected a map node, found kind '${String(kind)}'`, cid);
    }
    const e = (node["e"] as Embedded[] | undefined) ?? [];
    if (e.length % 2 !== 0) {
      throw new NodeFormatError(`entry list has an odd length ${e.length}`, cid);
    }
    const keys: Uint8Array[] = [];
    const values: Ref[] = [];
    for (let i = 0; i < e.length / 2; i++) {
      const key = e[2 * i]!.bytes;
      if (isLinkItem(key)) {
        throw new NodeFormatError(`entry ${i} has a bare link item as its key; keys never spill`, cid);
      }
      keys.push(key);
      values.push(refOf(e[2 * i + 1]!));
    }
    if ("cnt" in node && !root) {
      throw new NodeFormatError("'cnt' on a node that is not a map root", cid);
    }
    if (kind === KIND_MC) {
      for (let i = 1; i < keys.length; i++) {
        if (compare(keys[i - 1]!, keys[i]!) >= 0) {
          throw new NodeFormatError("collision node keys out of order", cid);
        }
      }
      const n = new ChampNode(true, 0, 0, keys, values, [], null);
      n.cid = cid;
      return n;
    }
    const d = (node["d"] as number | undefined) ?? 0;
    const nm = (node["n"] as number | undefined) ?? 0;
    if (d > 0xffffffff || nm > 0xffffffff) {
      throw new NodeFormatError("datamap or nodemap above 32 bits", cid);
    }
    if ((d & nm) !== 0) {
      throw new NodeFormatError("datamap and nodemap share a slot", cid);
    }
    if (bitCount(d) !== keys.length) {
      throw new NodeFormatError(`datamap names ${bitCount(d)} slots for ${keys.length} entries`, cid);
    }
    const c = (node["c"] as Link[] | undefined) ?? [];
    if (bitCount(nm) !== c.length) {
      throw new NodeFormatError(`nodemap names ${bitCount(nm)} slots for ${c.length} children`, cid);
    }
    const n = new ChampNode(false, d >>> 0, nm >>> 0, keys, values, c.map((l) => l.cid), null);
    if (typeof node["cnt"] === "number") {
      n.cnt = node["cnt"];
    }
    n.cid = cid;
    return n;
  }
}

import { encode as encodeNode, isLinkShaped as isLinkItem } from "./nodes.js";

function mergeTwo(k1: Uint8Array, v1: Ref, d1: Uint8Array, k2: Uint8Array, v2: Ref, d2: Uint8Array,
                  level: number, ctx: Ctx): ChampNode {
  if (level >= COLLISION_LEVEL) {
    const firstLower = compare(k1, k2) < 0;
    return new ChampNode(true, 0, 0, firstLower ? [k1, k2] : [k2, k1], firstLower ? [v1, v2] : [v2, v1], [], ctx.edit);
  }
  const i1 = slotIndex(d1, level);
  const i2 = slotIndex(d2, level);
  if (i1 !== i2) {
    const firstLower = i1 < i2;
    return new ChampNode(false, (bit(i1) | bit(i2)) >>> 0, 0, firstLower ? [k1, k2] : [k2, k1],
      firstLower ? [v1, v2] : [v2, v1], [], ctx.edit);
  }
  const sub = mergeTwo(k1, v1, d1, k2, v2, d2, level + 1, ctx);
  return new ChampNode(false, 0, bit(i1), [], [], [sub], ctx.edit);
}

/** The CBOR of a spilled map's entries: an indefinite map in canonical key order (shorter key first, then bytewise). */
export function reassembleMap(root: ChampNode, ctx: Ctx, depth: number): Uint8Array {
  const entries = [...root.entries(0, ctx)];
  entries.sort((a, b) => a[0].length - b[0].length || compare(a[0], b[0]));
  const parts: Uint8Array[] = [Uint8Array.of(0xbf)];
  for (const [key, value] of entries) {
    parts.push(key, resolve(value, ctx, depth + 1));
  }
  parts.push(Uint8Array.of(0xff));
  return concat(...parts);
}

// ------------------------------------------------------------------ the raw map

/** The map over raw CBOR keys and value references: what `PMap`, the editor, the diff, and the merge share. */
export class RawMap {
  constructor(readonly root: ChampNode, readonly ctx: Ctx) {}

  static empty(store: NodeStore): RawMap {
    const root = ChampNode.empty();
    root.cnt = 0;
    return new RawMap(root, new Ctx(store));
  }

  static load(store: NodeStore, cid: string): RawMap {
    return new RawMap(ChampNode.loadRoot(cid, store.load(cid)), new Ctx(store));
  }

  get(key: Uint8Array): Ref | undefined {
    return this.root.find(hashKey(key), 0, key, this.ctx);
  }

  count(): number {
    return this.root.cnt;
  }

  assoc(key: Uint8Array, value: Uint8Array): RawMap {
    checkKey(key);
    const change: Change = { added: false, removed: false, replaced: false };
    const next = this.root.assoc(hashKey(key), 0, key, spill(value, this.ctx), this.ctx, change);
    if (next === this.root) {
      return this;
    }
    next.cnt = this.root.cnt + (change.added ? 1 : 0);
    return new RawMap(next, this.ctx);
  }

  dissoc(key: Uint8Array): RawMap {
    const change: Change = { added: false, removed: false, replaced: false };
    const next = this.root.dissoc(hashKey(key), 0, key, this.ctx, change);
    if (next === this.root) {
      return this;
    }
    next.cnt = this.root.cnt - 1;
    return new RawMap(next, this.ctx);
  }

  *entries(): Generator<[Uint8Array, Ref]> {
    yield* this.root.entries(0, this.ctx);
  }

  /** Writes the new nodes and returns the root CID; the delta is what `store.record()` saw. */
  rootCid(): string {
    if (this.root.cid === null) {
      Flusher.flush(this.root, this.ctx.store);
    }
    return this.root.cid!;
  }

  editor(): RawEditor {
    return new RawEditor(this);
  }
}

/** A transient over a raw map: in place on nodes it created, a copy of every other node. */
export class RawEditor {
  private root: ChampNode;
  private cnt: number;
  private ctx: Ctx | null;

  constructor(from: RawMap) {
    this.ctx = new Ctx(from.ctx.store, {});
    this.root = from.root;
    this.cnt = from.root.cnt;
  }

  private live(): Ctx {
    if (this.ctx === null) {
      throw new Error("this editor is done");
    }
    return this.ctx;
  }

  /** The editor's context, for reading values it holds. */
  get context(): Ctx {
    return this.live();
  }

  get(key: Uint8Array): Ref | undefined {
    return this.root.find(hashKey(key), 0, key, this.live());
  }

  assoc(key: Uint8Array, value: Uint8Array): this {
    checkKey(key);
    const ctx = this.live();
    const change: Change = { added: false, removed: false, replaced: false };
    this.root = this.root.assoc(hashKey(key), 0, key, spill(value, ctx), ctx, change);
    if (change.added) {
      this.cnt += 1;
    }
    return this;
  }

  dissoc(key: Uint8Array): this {
    const ctx = this.live();
    const change: Change = { added: false, removed: false, replaced: false };
    this.root = this.root.dissoc(hashKey(key), 0, key, ctx, change);
    if (change.removed) {
      this.cnt -= 1;
    }
    return this;
  }

  count(): number {
    return this.cnt;
  }

  done(): RawMap {
    const ctx = this.live();
    this.ctx = null;
    if (this.root.edit === ctx.edit) {
      this.root.cnt = this.cnt;
    } else if (this.root.cnt !== this.cnt) {
      // the root was never copied (no change touched it) yet the count moved: a fresh root carries it
      this.root = new ChampNode(this.root.collision, this.root.datamap, this.root.nodemap, [...this.root.keys],
        [...this.root.values], [...this.root.children], null);
      this.root.cnt = this.cnt;
    }
    return new RawMap(this.root, new Ctx(ctx.store));
  }
}

// ------------------------------------------------------------------ diff and merge

export interface RawChange { key: Uint8Array; before: Ref | undefined; after: Ref | undefined }

function keyString(key: Uint8Array): string {
  let s = "";
  for (const b of key) {
    s += String.fromCharCode(b);
  }
  return s;
}

/** The entries of `mine` that differ from `base`, descending only into subtrees whose CIDs differ (PD-V-07). */
export function rawDiff(mine: RawMap, base: RawMap): RawChange[] {
  const out: RawChange[] = [];
  diffNodes(mine.root, base.root, 0, mine.ctx, base.ctx, out);
  return out;
}

function sameNode(a: ChampNode | string, b: ChampNode | string): boolean {
  if (a === b) {
    return true;
  }
  const ca = typeof a === "string" ? a : a.cid;
  const cb = typeof b === "string" ? b : b.cid;
  return ca !== null && ca === cb;
}

function diffNodes(a: ChampNode, b: ChampNode, level: number, actx: Ctx, bctx: Ctx, out: RawChange[]): void {
  if (sameNode(a, b)) {
    return;
  }
  if (a.collision || b.collision) {
    const bEntries = new Map<string, [Uint8Array, Ref]>();
    for (const [k, v] of b.entries(level, bctx)) {
      bEntries.set(keyString(k), [k, v]);
    }
    for (const [k, v] of a.entries(level, actx)) {
      const key = keyString(k);
      const was = bEntries.get(key);
      bEntries.delete(key);
      if (was === undefined) {
        out.push({ key: k, before: undefined, after: v });
      } else if (!equalHashed(v, was[1]) && !sameValue(v, was[1])) {
        out.push({ key: k, before: was[1], after: v });
      }
    }
    for (const [k, v] of bEntries.values()) {
      out.push({ key: k, before: v, after: undefined });
    }
    return;
  }
  let adi = 0, ani = 0, bdi = 0, bni = 0;
  for (let slot = 0; slot < WIDTH; slot++) {
    const bt = bit(slot);
    const aData = (a.datamap & bt) !== 0, aNode = (a.nodemap & bt) !== 0;
    const bData = (b.datamap & bt) !== 0, bNode = (b.nodemap & bt) !== 0;
    const ak = aData ? a.keys[adi]! : null, av = aData ? a.values[adi]! : null;
    const bk = bData ? b.keys[bdi]! : null, bv = bData ? b.values[bdi]! : null;
    const ac = aNode ? a.child(ani, level + 1, actx) : null;
    const bc = bNode ? b.child(bni, level + 1, bctx) : null;
    if (aData) adi += 1;
    if (aNode) ani += 1;
    if (bData) bdi += 1;
    if (bNode) bni += 1;
    if (ak !== null && bk !== null) {
      if (bytesEqual(ak, bk)) {
        if (!sameValue(av!, bv!) && !equalHashed(av!, bv!)) {
          out.push({ key: ak, before: bv!, after: av! });
        }
      } else {
        out.push({ key: bk, before: bv!, after: undefined });
        out.push({ key: ak, before: undefined, after: av! });
      }
    } else if (ak !== null && bc !== null) {
      let found = false;
      for (const [k, v] of bc.entries(level + 1, bctx)) {
        if (bytesEqual(k, ak)) {
          found = true;
          if (!sameValue(av!, v) && !equalHashed(av!, v)) {
            out.push({ key: ak, before: v, after: av! });
          }
        } else {
          out.push({ key: k, before: v, after: undefined });
        }
      }
      if (!found) {
        out.push({ key: ak, before: undefined, after: av! });
      }
    } else if (ac !== null && bk !== null) {
      let found = false;
      for (const [k, v] of ac.entries(level + 1, actx)) {
        if (bytesEqual(k, bk)) {
          found = true;
          if (!sameValue(v, bv!) && !equalHashed(v, bv!)) {
            out.push({ key: k, before: bv!, after: v });
          }
        } else {
          out.push({ key: k, before: undefined, after: v });
        }
      }
      if (!found) {
        out.push({ key: bk, before: bv!, after: undefined });
      }
    } else if (ac !== null && bc !== null) {
      diffNodes(ac, bc, level + 1, actx, bctx, out);
    } else if (ak !== null) {
      out.push({ key: ak, before: undefined, after: av! });
    } else if (bk !== null) {
      out.push({ key: bk, before: bv!, after: undefined });
    } else if (ac !== null) {
      for (const [k, v] of ac.entries(level + 1, actx)) {
        out.push({ key: k, before: undefined, after: v });
      }
    } else if (bc !== null) {
      for (const [k, v] of bc.entries(level + 1, bctx)) {
        out.push({ key: k, before: v, after: undefined });
      }
    }
  }
}

export type RawResolver = (key: Uint8Array, base: Uint8Array | null, mine: Uint8Array | null, theirs: Uint8Array | null)
  => Uint8Array | null;

/** The key-wise three-way merge (§3.6.1, PD-V-09): keys changed on one side take that side; both sides ask the resolver. */
export function rawMerge3(mine: RawMap, base: RawMap, theirs: RawMap, resolver: RawResolver): RawMap {
  const mineDiff = rawDiff(mine, base);
  const theirDiff = rawDiff(theirs, base);
  const byKey = new Map<string, RawChange>();
  for (const change of mineDiff) {
    byKey.set(keyString(change.key), change);
  }
  const editor = mine.editor();
  for (const theirChange of theirDiff) {
    const myChange = byKey.get(keyString(theirChange.key));
    if (myChange === undefined) {
      if (theirChange.after === undefined) {
        editor.dissoc(theirChange.key);
      } else {
        editor.assoc(theirChange.key, resolve(theirChange.after, theirs.ctx));
      }
      continue;
    }
    const sameOutcome = myChange.after === undefined || theirChange.after === undefined
      ? myChange.after === theirChange.after
      : equalHashed(myChange.after, theirChange.after) || sameValue(myChange.after, theirChange.after);
    if (sameOutcome) {
      continue;
    }
    const kept = resolver(theirChange.key,
      myChange.before === undefined ? null : resolve(myChange.before, base.ctx),
      myChange.after === undefined ? null : resolve(myChange.after, mine.ctx),
      theirChange.after === undefined ? null : resolve(theirChange.after, theirs.ctx));
    if (kept === null) {
      editor.dissoc(theirChange.key);
    } else {
      editor.assoc(theirChange.key, kept);
    }
  }
  return editor.done();
}

// ------------------------------------------------------------------ PMap and PSet

export interface Diff<K, V> { added: [K, V][]; removed: [K, V][]; changed: [K, V, V][] }

export type Resolver<K, V> = (key: K, base: V | undefined, mine: V | undefined, theirs: V | undefined) => V | undefined;

/** The typed persistent map over codecs; `PMap.empty` and `PMap.load` are the entry points. */
export class PMap<K = CborValue, V = CborValue> implements Iterable<[K, V]> {
  constructor(readonly raw: RawMap, readonly keyCodec: Codec<K>, readonly valueCodec: Codec<V>) {}

  static empty<K = CborValue, V = CborValue>(store: NodeStore, keys?: Codec<K>, values?: Codec<V>): PMap<K, V> {
    return new PMap(RawMap.empty(store), codecOf(keys), codecOf(values));
  }

  static load<K = CborValue, V = CborValue>(store: NodeStore, root: string, keys?: Codec<K>, values?: Codec<V>): PMap<K, V> {
    return new PMap(RawMap.load(store, root), codecOf(keys), codecOf(values));
  }

  get store(): NodeStore {
    return this.raw.ctx.store;
  }

  get(key: K): V | undefined {
    const ref = this.raw.get(this.keyCodec.encode(key));
    return ref === undefined ? undefined : this.valueCodec.decode(resolve(ref, this.raw.ctx));
  }

  has(key: K): boolean {
    return this.raw.get(this.keyCodec.encode(key)) !== undefined;
  }

  count(): number {
    return this.raw.count();
  }

  isEmpty(): boolean {
    return this.count() === 0;
  }

  /** The root CID; writes the new nodes to the store (PD-V-08). */
  root(): string {
    return this.raw.rootCid();
  }

  assoc(key: K, value: V): PMap<K, V> {
    const next = this.raw.assoc(this.keyCodec.encode(key), this.valueCodec.encode(value));
    return next === this.raw ? this : new PMap(next, this.keyCodec, this.valueCodec);
  }

  dissoc(key: K): PMap<K, V> {
    const next = this.raw.dissoc(this.keyCodec.encode(key));
    return next === this.raw ? this : new PMap(next, this.keyCodec, this.valueCodec);
  }

  update(key: K, f: (value: V | undefined) => V): PMap<K, V> {
    return this.assoc(key, f(this.get(key)));
  }

  /** Updates a nested path of plain maps and arrays inside a value; a missing level becomes a map. */
  updateIn(path: (K | string | number)[], f: (value: unknown) => unknown): PMap<K, V> {
    if (path.length === 0) {
      throw new Error("updateIn needs a path");
    }
    const [head, ...rest] = path as [K, ...(string | number)[]];
    if (rest.length === 0) {
      return this.assoc(head, f(this.get(head)) as V);
    }
    const current = this.get(head);
    return this.assoc(head, updatePath(current ?? {}, rest, f) as V);
  }

  keys(): K[] {
    const out: K[] = [];
    for (const [k] of this) {
      out.push(k);
    }
    return out;
  }

  *[Symbol.iterator](): Iterator<[K, V]> {
    for (const [k, v] of this.raw.entries()) {
      yield [this.keyCodec.decode(k), this.valueCodec.decode(resolve(v, this.raw.ctx))];
    }
  }

  toMap(): Map<K, V> {
    return new Map(this);
  }

  editor(): Editor<K, V> {
    return new Editor(this.raw.editor(), this.keyCodec, this.valueCodec);
  }

  /** Keys added, removed, and changed since `base`, visiting only subtrees whose CIDs differ. */
  diff(base: PMap<K, V>): Diff<K, V> {
    const out: Diff<K, V> = { added: [], removed: [], changed: [] };
    for (const change of rawDiff(this.raw, base.raw)) {
      const key = this.keyCodec.decode(change.key);
      if (change.before === undefined) {
        out.added.push([key, this.valueCodec.decode(resolve(change.after!, this.raw.ctx))]);
      } else if (change.after === undefined) {
        out.removed.push([key, this.valueCodec.decode(resolve(change.before, base.raw.ctx))]);
      } else {
        out.changed.push([key, this.valueCodec.decode(resolve(change.before, base.raw.ctx)),
          this.valueCodec.decode(resolve(change.after, this.raw.ctx))]);
      }
    }
    return out;
  }

  /** The three-way merge of §3.6.1 with `resolver` called once per key both sides changed differently. */
  merge3(base: PMap<K, V>, other: PMap<K, V>, resolver: Resolver<K, V>): PMap<K, V> {
    const raw = rawMerge3(this.raw, base.raw, other.raw, (key, b, m, t) => {
      const kept = resolver(this.keyCodec.decode(key), b === null ? undefined : this.valueCodec.decode(b),
        m === null ? undefined : this.valueCodec.decode(m), t === null ? undefined : this.valueCodec.decode(t));
      return kept === undefined ? null : this.valueCodec.encode(kept);
    });
    return new PMap(raw, this.keyCodec, this.valueCodec);
  }

  equals(other: PMap<K, V>): boolean {
    return this.root() === other.root();
  }
}

function updatePath(value: unknown, path: (string | number)[], f: (v: unknown) => unknown): unknown {
  if (path.length === 0) {
    return f(value);
  }
  const [head, ...rest] = path as [string | number, ...(string | number)[]];
  if (Array.isArray(value) && typeof head === "number") {
    const copy = [...value];
    copy[head] = updatePath(value[head], rest, f);
    return copy;
  }
  const map = (value !== null && typeof value === "object" && !(value instanceof Uint8Array)) ? { ...(value as object) } : {};
  (map as { [k: string]: unknown })[String(head)] = updatePath((map as { [k: string]: unknown })[String(head)], rest, f);
  return map;
}

/** The transient of a `PMap` (PD-V-05). */
export class Editor<K, V> {
  constructor(private readonly raw: RawEditor, readonly keyCodec: Codec<K>, readonly valueCodec: Codec<V>) {}

  get(key: K): V | undefined {
    const ref = this.raw.get(this.keyCodec.encode(key));
    return ref === undefined ? undefined : this.valueCodec.decode(resolve(ref, this.raw.context));
  }

  assoc(key: K, value: V): this {
    this.raw.assoc(this.keyCodec.encode(key), this.valueCodec.encode(value));
    return this;
  }

  dissoc(key: K): this {
    this.raw.dissoc(this.keyCodec.encode(key));
    return this;
  }

  count(): number {
    return this.raw.count();
  }

  done(): PMap<K, V> {
    return new PMap(this.raw.done(), this.keyCodec, this.valueCodec);
  }
}

/** A set: a map whose values are null (PD-V-02). */
export class PSet<E = CborValue> implements Iterable<E> {
  constructor(readonly map: PMap<E, null>) {}

  static empty<E = CborValue>(store: NodeStore, codec?: Codec<E>): PSet<E> {
    return new PSet(PMap.empty<E, null>(store, codec, nullCodec));
  }

  static load<E = CborValue>(store: NodeStore, root: string, codec?: Codec<E>): PSet<E> {
    return new PSet(PMap.load<E, null>(store, root, codec, nullCodec));
  }

  contains(item: E): boolean {
    return this.map.has(item);
  }

  conj(item: E): PSet<E> {
    const next = this.map.assoc(item, null);
    return next === this.map ? this : new PSet(next);
  }

  disj(item: E): PSet<E> {
    const next = this.map.dissoc(item);
    return next === this.map ? this : new PSet(next);
  }

  count(): number {
    return this.map.count();
  }

  root(): string {
    return this.map.root();
  }

  *[Symbol.iterator](): Iterator<E> {
    for (const [k] of this.map) {
      yield k;
    }
  }

  toSet(): Set<E> {
    return new Set(this);
  }

  equals(other: PSet<E>): boolean {
    return this.root() === other.root();
  }
}

const nullCodec: Codec<null> = { encode: () => Uint8Array.of(0xf6), decode: () => null };
