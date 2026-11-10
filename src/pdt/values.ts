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
 * What the persistent values share (srad/agentspaces-pdt.md §3.1, PD-N-05, PD-V-08, §10.2): the codec
 * that turns application keys and values into embedded CBOR items, the value-slot references a node
 * holds (inline bytes, a spilled `x` node, a spilled sub-map or sub-vector, a spilled blob, or the CID
 * of one not yet loaded), the spill rule, the reassembly of a spilled value, and the flusher that
 * hashes and writes every new node once when a root is needed.
 *
 * Spill: an embedded value above 1 KiB goes to its own `{k:"x", v}` node; above 4 KiB an indefinite
 * map becomes a CHAMP sub-tree, a definite array a vector, and a byte string a blob; the value slot
 * then holds the 41-byte link item. A bare link item is never an application key or value.
 */

import { concat } from "../bytes.js";
import type { CborValue } from "../cbor.js";
import { dumps, loads } from "../cbor.js";
import { cryptoPort } from "../crypto.js";
import * as blob from "./blob.js";
import { ChampNode, reassembleMap } from "./champ.js";
import * as cids from "./cids.js";
import { chunksOf } from "./fastcdc.js";
import { TextLeaf } from "./kinds.js";
import { Embedded as EmbeddedItem, KIND_B, KIND_KEY, KIND_M, KIND_T, KIND_VR, KIND_X, Link, MAX_DEPTH, MAX_NODE_BYTES,
  NodeFormatError, decode, encode, isLinkShaped, kindOf, linkItem, skip, spilledLink } from "./nodes.js";
import type { Embedded } from "./nodes.js";
import { NodeStore } from "./store.js";
import { PText } from "./text.js";
import { VecNode, VecRoot, reassembleArray } from "./vector.js";

export const VALUE_LIMIT = 1024;
export const TREE_LIMIT = 4096;
export const MAX_X_VALUE = MAX_NODE_BYTES - 7;

/** Turns a value into the CBOR item a node embeds, and back. */
export interface Codec<T> {
  encode(value: T): Uint8Array;
  decode(bytes: Uint8Array): T;
}

/** The default codec: the client's CBOR, the form the Java `CborCodec` gives the same values. */
export const cborCodec: Codec<CborValue> = {
  encode: (value) => dumps(value),
  decode: (bytes) => loads(bytes),
};

export function codecOf<T>(codec?: Codec<T>): Codec<T> {
  return codec ?? (cborCodec as unknown as Codec<T>);
}

/** A spilled value held out of line in an `x` node. */
export class XNode {
  cid: string | null;
  constructor(readonly value: Uint8Array, cid: string | null = null) {
    this.cid = cid;
  }
}

/** A spilled byte string held as a blob tree. */
export class BlobNode {
  cid: string | null = null;
  constructor(readonly content: Uint8Array) {}
}

/**
 * A text value held out of line, kind `t` (PDT 2 phase 7, P2-T-02, Java's TextNode): a value in the text form of
 * `PText` above 1 KiB spills to a node holding the canonical bytes of the same leaf, and reads back as the value it
 * was. The node bytes are made eagerly, so a text whose node would pass the 1 MiB node bound is refused on the way in.
 */
export class TextNode {
  cid: string | null = null;
  readonly node: Uint8Array;
  constructor(readonly value: Uint8Array) {
    this.node = PText.fromWire(value).encode();
  }
}

/** A value slot: inline CBOR, a spilled node in memory, or the CID of a spilled node. */
export type Ref = Uint8Array | XNode | BlobNode | TextNode | OrderedNode | ChampNode | VecRoot | string;

/**
 * The context of a read or write: the store, the transient token that owns editable nodes, and whether the tree keeps
 * the level-1 kinds, as an escalated payload does (PDT 2 phase 7; §6.10.3, rule 7), so no text spills to a `t` node.
 */
export class Ctx {
  constructor(readonly store: NodeStore, readonly edit: object | null = null, readonly levelOne = false) {}

  owns(token: object | null): boolean {
    return token !== null && token === this.edit;
  }

  /** The bytes of a node, from the store; throws `NodeUnavailableError` when absent. */
  load(cid: string): Uint8Array {
    return this.store.load(cid);
  }
}

export function checkKey(key: Uint8Array): void {
  if (isLinkShaped(key)) {
    throw new Error("a key must not be a bare link item (CBOR tag 42 over a CID): a link item in a map node names a"
      + " spilled node (PD-N-05); hold a CID as text");
  }
}

/** The reference a decoded value slot stands for: the inline bytes, or the CID of the spilled node. */
export function refOf(item: Embedded): Ref {
  const spilled = spilledLink(item.bytes);
  return spilled ?? item.bytes;
}

/** The CID a reference names once hashed, or null for inline bytes and unflushed nodes. */
export function cidOf(ref: Ref): string | null {
  if (typeof ref === "string") {
    return ref;
  }
  if (ref instanceof Uint8Array) {
    return null;
  }
  return ref.cid;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/** Whether two slots hold the same value without hashing: equal inline bytes, equal spilled content, or the same node. */
export function sameValue(a: Ref, b: Ref): boolean {
  if (a === b) {
    return true;
  }
  if (a instanceof Uint8Array && b instanceof Uint8Array) {
    return bytesEqual(a, b);
  }
  if (a instanceof XNode && b instanceof XNode) {
    return bytesEqual(a.value, b.value);
  }
  if (a instanceof BlobNode && b instanceof BlobNode) {
    return bytesEqual(a.content, b.content);
  }
  if (a instanceof TextNode && b instanceof TextNode) {
    return bytesEqual(a.value, b.value);
  }
  const ca = cidOf(a), cb = cidOf(b);
  return ca !== null && ca === cb;
}

/** Equality after hashing: inline bytes by content, everything else by CID. */
export function equalHashed(a: Ref, b: Ref): boolean {
  if (a instanceof Uint8Array) {
    return b instanceof Uint8Array && bytesEqual(a, b);
  }
  const ca = cidOf(a), cb = cidOf(b);
  return ca !== null && ca === cb;
}

// ------------------------------------------------------------------ spilling

function headerLength(info: number): number {
  return info < 24 ? 1 : 1 + (1 << (info - 24));
}

/** The reference for an application value's CBOR: inline, or the spilled node (PD-N-05). */
export function spill(cbor: Uint8Array, ctx: Ctx): Ref {
  if (isLinkShaped(cbor)) {
    throw new Error("a value must not be a bare link item (CBOR tag 42 over a CID): a link item in a value slot names a"
      + " spilled node (PD-N-05); hold a CID as text");
  }
  if (cbor.length <= VALUE_LIMIT) {
    return cbor;
  }
  if (!ctx.levelOne && PText.isText(cbor)) {
    return new TextNode(cbor);
  }
  const major = cbor[0]! >> 5;
  const info = cbor[0]! & 0x1f;
  if (cbor.length > TREE_LIMIT) {
    if (major === 5 && info === 31) {
      return canonicalKeys(cbor) ? subMap(cbor, ctx) : subOrdered(cbor, ctx);
    }
    if (major === 4 && info !== 31) {
      return subVector(cbor, ctx);
    }
    if (major === 2 && info !== 31) {
      return new BlobNode(cbor.subarray(headerLength(info)));
    }
  }
  if (cbor.length > MAX_X_VALUE) {
    throw new Error(`a value of ${cbor.length} CBOR bytes exceeds the ${MAX_X_VALUE} bytes an x node can hold under the`
      + " 1 MiB node bound (PD-N-04)");
  }
  return new XNode(cbor);
}

function subMap(cbor: Uint8Array, ctx: Ctx): ChampNode {
  let root = ChampNode.empty();
  let count = 0;
  let p = 1;
  while (p < cbor.length && cbor[p] !== 0xff) {
    const keyEnd = skip(cbor, p);
    const valueEnd = skip(cbor, keyEnd);
    const key = cbor.subarray(p, keyEnd);
    const value = cbor.subarray(keyEnd, valueEnd);
    checkKey(key);
    const change = { added: false, removed: false, replaced: false };
    root = root.assoc(hashKey(key), 0, key, spill(value, ctx), ctx, change);
    if (change.added) {
      count += 1;
    }
    p = valueEnd;
  }
  root.cnt = count;
  return root;
}

/**
 * Whether an indefinite map's keys come in canonical order (shorter first, then bytewise), the
 * order the Java codec gives a map and a CHAMP reassembly restores.
 */
export function canonicalKeys(cbor: Uint8Array): boolean {
  let p = 1;
  let previous: Uint8Array | null = null;
  while (p < cbor.length && cbor[p] !== 0xff) {
    const keyEnd = skip(cbor, p);
    const key = cbor.subarray(p, keyEnd);
    if (previous !== null && compareKeys(previous, key) >= 0) {
      return false;
    }
    previous = key;
    p = skip(cbor, keyEnd);
  }
  return true;
}

function compareKeys(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) {
    return a.length - b.length;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return a[i]! - b[i]!;
    }
  }
  return 0;
}

/**
 * A spilled map in its written order (the Java ordered-map spill of phase 4, srad/agentspaces-pdt.md
 * 10.2): an `x` node whose value links the `vr` of its keys and values; the vector is hashed first.
 */
export class OrderedNode {
  cid: string | null = null;
  constructor(readonly items: VecRoot) {}
}

function subOrdered(cbor: Uint8Array, ctx: Ctx): OrderedNode {
  let items = VecRoot.empty();
  let p = 1;
  while (p < cbor.length && cbor[p] !== 0xff) {
    const keyEnd = skip(cbor, p);
    const valueEnd = skip(cbor, keyEnd);
    const key = cbor.subarray(p, keyEnd);
    checkKey(key);
    items = items.conj(spill(key, ctx), ctx);
    items = items.conj(spill(cbor.subarray(keyEnd, valueEnd), ctx), ctx);
    p = valueEnd;
  }
  return new OrderedNode(items);
}

function subVector(cbor: Uint8Array, ctx: Ctx): VecRoot {
  const info = cbor[0]! & 0x1f;
  let p = 1;
  let n: number;
  if (info < 24) {
    n = info;
  } else {
    const width = 1 << (info - 24);
    n = 0;
    for (let i = 0; i < width; i++) {
      n = n * 256 + cbor[p++]!;
    }
  }
  let root = VecRoot.empty();
  for (let i = 0; i < n; i++) {
    const end = skip(cbor, p);
    root = root.conj(spill(cbor.subarray(p, end), ctx), ctx);
    p = end;
  }
  return root;
}

/** The sha2-256 digest of a key's CBOR bytes: the CHAMP hash (§10.2). */
export function hashKey(key: Uint8Array): Uint8Array {
  return keyHasher(key);
}

const keyHasher = (key: Uint8Array): Uint8Array => cryptoPort().sha256(key);

// ------------------------------------------------------------------ resolving

export function byteString(raw: Uint8Array): Uint8Array {
  return concat(cborHeader(2, raw.length), raw);
}

export function cborHeader(major: number, value: number): Uint8Array {
  const m = major << 5;
  if (value < 24) {
    return Uint8Array.of(m | value);
  }
  if (value < 0x100) {
    return Uint8Array.of(m | 24, value);
  }
  if (value < 0x10000) {
    return Uint8Array.of(m | 25, value >>> 8, value & 0xff);
  }
  return Uint8Array.of(m | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

/** The CBOR bytes a value slot stands for, loading spilled nodes through the context. */
export function resolve(ref: Ref, ctx: Ctx, depth = 0): Uint8Array {
  if (ref instanceof Uint8Array) {
    return ref;
  }
  if (ref instanceof BlobNode) {
    return byteString(ref.content);
  }
  if (depth > MAX_DEPTH) {
    throw new NodeFormatError(`spilled values nested deeper than ${MAX_DEPTH} levels`, cidOf(ref));
  }
  if (ref instanceof XNode) {
    return isLinkShaped(ref.value) ? resolveLinked(spilledLink(ref.value)!, ctx, depth + 1) : ref.value;
  }
  if (ref instanceof TextNode) {
    return ref.value;
  }
  if (ref instanceof OrderedNode) {
    return reassembleOrdered(ref.items, ctx, depth);
  }
  if (ref instanceof ChampNode) {
    return reassembleMap(ref, ctx, depth);
  }
  if (ref instanceof VecRoot) {
    return reassembleArray(ref, ctx, depth);
  }
  const cid = ref;
  const bytes = ctx.load(cid);
  if (cids.parse(cid).codec === cids.RAW) {
    return byteString(bytes);
  }
  const kind = kindOf(bytes, cid);
  switch (kind) {
    case KIND_X: {
      const value = decodeX(cid, bytes).value;
      return isLinkShaped(value) ? resolveLinked(spilledLink(value)!, ctx, depth + 1) : value;
    }
    case KIND_M:
      return reassembleMap(ChampNode.loadRoot(cid, bytes), ctx, depth);
    case KIND_VR:
      return reassembleArray(VecRoot.decode(cid, bytes), ctx, depth);
    case KIND_B:
      return byteString(blob.PBlob.load(ctx.store, cid).bytes());
    case KIND_T:
      if (ctx.levelOne) {
        throw new NodeFormatError("a level-one tree holds no text node (rule 7)", cid);
      }
      return PText.toWire(TextLeaf.decode(bytes, cid));
    default:
      throw new NodeFormatError(`a spilled value cannot be a node of kind '${kind}'`, cid);
  }
}

/**
 * The value an `x` envelope links (phase 4, 10.2): an ordered map when the linked node is a `vr`
 * (`bf`, the items in order, `ff`), a byte string when it is a chunk or a `b` node.
 */
function resolveLinked(cid: string, ctx: Ctx, depth: number): Uint8Array {
  if (depth > MAX_DEPTH) {
    throw new NodeFormatError(`spilled values nested deeper than ${MAX_DEPTH} levels`, cid);
  }
  const bytes = ctx.load(cid);
  if (cids.parse(cid).codec === cids.RAW) {
    return byteString(bytes);
  }
  const kind = kindOf(bytes, cid);
  switch (kind) {
    case KIND_VR:
      return reassembleOrdered(VecRoot.decode(cid, bytes), ctx, depth);
    case KIND_B:
      return byteString(blob.PBlob.load(ctx.store, cid).bytes());
    default:
      throw new NodeFormatError(`an x envelope links a node of kind '${kind}'`, cid);
  }
}

function reassembleOrdered(root: VecRoot, ctx: Ctx, depth: number): Uint8Array {
  if (root.n % 2 !== 0) {
    throw new NodeFormatError(`an ordered-map envelope links a vector of ${root.n} items; keys and values pair up`,
      cidOf(root));
  }
  const parts: Uint8Array[] = [Uint8Array.of(0xbf)];
  for (let i = 0; i < root.n; i++) {
    parts.push(resolve(root.nth(i, ctx), ctx, depth + 1));
  }
  parts.push(Uint8Array.of(0xff));
  return concatBytes(parts);
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const part of parts) {
    n += part.length;
  }
  const out = new Uint8Array(n);
  let p = 0;
  for (const part of parts) {
    out.set(part, p);
    p += part.length;
  }
  return out;
}

// ------------------------------------------------------------------ payload trees (group E)

/**
 * A space payload as a tree (srad/agentspaces-pdt.md PD-E-02, the Java `PayloadTree.write`): the
 * spill rules over the whole CBOR item, a bare value or a single chunk under an `x` envelope, so a
 * root is always a dag-cbor node. Returns the root and the nodes written.
 */
export function writePayload(cbor: Uint8Array, store: NodeStore): { root: string; nodes: Map<string, Uint8Array> } {
  if (cbor.length === 0) {
    throw new Error("an empty payload is not a CBOR item");
  }
  const ctx = new Ctx(store, null, true);
  const spilled = spill(cbor, ctx);
  const flusher = new Flusher(store);
  let root: string;
  if (spilled instanceof Uint8Array) {
    root = flusher.cidOf(new XNode(spilled));
  } else if (spilled instanceof BlobNode) {
    const blobCid = flusher.cidOf(spilled);
    root = cids.parse(blobCid).codec === cids.RAW ? flusher.cidOf(new XNode(linkItem(blobCid))) : blobCid;
  } else {
    root = flusher.cidOf(spilled);
  }
  if (flusher.fresh.size > 0) {
    store.putAll(flusher.fresh);
  }
  return { root, nodes: flusher.fresh };
}

/** The payload bytes `writePayload` was given, from the root (the Java `PayloadTree.read`). */
export function readPayload(root: string, ctx: Ctx): Uint8Array {
  if (cids.parse(root).codec !== cids.DAG_CBOR) {
    throw new NodeFormatError("a payload root is a dag-cbor node", root);
  }
  const kind = kindOf(ctx.load(root), root);
  if (kind !== KIND_X && kind !== KIND_M && kind !== KIND_VR && kind !== KIND_B) {
    throw new NodeFormatError(`a payload root is an x, m, vr, or b node, not '${kind}'`, root);
  }
  return resolve(root, ctx.levelOne ? ctx : new Ctx(ctx.store, ctx.edit, true));
}

export function decodeX(cid: string, bytes: Uint8Array): XNode {
  const node = decode(bytes, cid);
  if (node[KIND_KEY] !== KIND_X) {
    throw new NodeFormatError(`expected a spill node, found kind '${String(node[KIND_KEY])}'`, cid);
  }
  const v = node["v"] as Embedded | undefined;
  if (v === undefined) {
    throw new NodeFormatError("spill node has no 'v'", cid);
  }
  return new XNode(v.bytes, cid);
}

function encodeX(x: XNode): Uint8Array {
  return encode({ [KIND_KEY]: KIND_X, v: new EmbeddedItem(x.value) });
}

// ------------------------------------------------------------------ flushing

/**
 * Hashes and writes every node reachable from a value's new nodes, once, skipping nodes the store
 * holds; returns the fresh nodes by CID (the exact delta of the batch, PD-V-05, PD-V-08).
 */
export class Flusher {
  readonly fresh = new Map<string, Uint8Array>();

  constructor(readonly store: NodeStore) {}

  static flush(root: ChampNode | VecRoot, store: NodeStore): Map<string, Uint8Array> {
    const flusher = new Flusher(store);
    flusher.cidOf(root);
    if (flusher.fresh.size > 0) {
      store.putAll(flusher.fresh);
    }
    return flusher.fresh;
  }

  /** The CID of a reference, encoding and recording the node (and its new descendants) when unhashed. */
  cidOf(ref: Ref | VecRoot | ChampNode | VecNode): string {
    if (typeof ref === "string") {
      return ref;
    }
    if (ref instanceof Uint8Array) {
      throw new Error("inline bytes have no CID");
    }
    if (ref.cid !== null) {
      return ref.cid;
    }
    let cid: string;
    if (ref instanceof BlobNode) {
      cid = this.writeBlob(ref);
    } else if (ref instanceof XNode) {
      cid = this.put(encodeX(ref), cids.DAG_CBOR);
    } else if (ref instanceof TextNode) {
      cid = this.put(ref.node, cids.DAG_CBOR);
    } else if (ref instanceof OrderedNode) {
      cid = this.put(encodeX(new XNode(linkItem(this.cidOf(ref.items)))), cids.DAG_CBOR);
    } else {
      cid = this.put((ref as ChampNode | VecRoot | VecNode).encode(this), cids.DAG_CBOR);
    }
    ref.cid = cid;
    return cid;
  }

  /** The embedded item of a value slot: the inline bytes, or the link item of the spilled node. */
  embed(ref: Ref): EmbeddedItem {
    if (ref instanceof Uint8Array) {
      return new EmbeddedItem(ref);
    }
    return new EmbeddedItem(linkItem(this.cidOf(ref)));
  }

  link(ref: ChampNode | VecRoot | VecNode | string): Link {
    return new Link(this.cidOf(ref as Ref));
  }

  put(bytes: Uint8Array, codec: number): string {
    const cid = cids.of(bytes, codec);
    if (!this.fresh.has(cid) && !this.store.has(cid)) {
      this.fresh.set(cid, bytes);
    }
    return cid;
  }

  private writeBlob(b: BlobNode): string {
    const level: blob.Entry[] = [];
    for (const chunk of chunksOf(b.content)) {
      level.push({ cid: this.put(chunk, cids.RAW), length: chunk.length });
    }
    if (level.length === 0) {
      return this.put(new Uint8Array(), cids.RAW);
    }
    let current = level;
    let height = 0;
    while (current.length > 1) {
      height += 1;
      const next: blob.Entry[] = [];
      for (const entries of blob.group(current)) {
        let under = 0;
        for (const e of entries) {
          under += e.length;
        }
        next.push({ cid: this.put(blob.encodeNode(height, entries), cids.DAG_CBOR), length: under });
      }
      current = next;
    }
    return current[0]!.cid;
  }
}
