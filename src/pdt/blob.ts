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
 * Blobs (srad/agentspaces-pdt.md §3.3, PD-B-02, PD-B-03, PD-B-07, §10.2): a prolly tree over FastCDC
 * chunks. A chunk is a raw node (codec 0x55) named by its sha2-256; a blob of zero or one chunk is that
 * chunk. Interior nodes are `{k:"b", h: height, c: [links], z: [bytes under each child]}`; a node
 * closes after an entry whose digest's first four bytes, read big-endian unsigned, are below
 * `0x08000000` (average fanout 32), with at least 4 and at most 256 entries, levels repeating until one
 * node remains. A reader seeks by the `z` sums and verifies every chunk's length against its entry.
 */

import { concat } from "../bytes.js";
import * as cids from "./cids.js";
import * as fastcdc from "./fastcdc.js";
import { KIND_B, KIND_KEY, Link, MAX_DEPTH, NodeFormatError, decode, encode } from "./nodes.js";
import { NodeStore } from "./store.js";

export const BOUNDARY = 0x08000000;
export const MIN_FANOUT = 4;
export const MAX_FANOUT = 256;

export interface Entry { cid: string; length: number }

export interface Located { cid: string; start: number; length: number }

/** Whether an entry closes a node: its digest's first four bytes read below the boundary. */
export function boundary(cid: string): boolean {
  const d = cids.parse(cid).digest;
  const prefix = ((d[0]! << 24) >>> 0) + (d[1]! << 16) + (d[2]! << 8) + d[3]!;
  return prefix < BOUNDARY;
}

/** Groups one level's entries into the nodes of the level above. */
export function group(level: Entry[]): Entry[][] {
  const nodes: Entry[][] = [];
  let current: Entry[] = [];
  for (const entry of level) {
    current.push(entry);
    if (current.length >= MAX_FANOUT || (current.length >= MIN_FANOUT && boundary(entry.cid))) {
      nodes.push(current);
      current = [];
    }
  }
  if (current.length > 0) {
    nodes.push(current);
  }
  return nodes;
}

export function encodeNode(height: number, entries: Entry[]): Uint8Array {
  return encode({ [KIND_KEY]: KIND_B, h: height, c: entries.map((e) => new Link(e.cid)), z: entries.map((e) => e.length) });
}

/** The CID of the empty blob: the empty raw chunk. */
export function emptyRoot(): string {
  return cids.of(new Uint8Array(), cids.RAW);
}

interface Built { root: string; height: number; writtenBytes: number; writtenNodes: number }

/** Builds the interior levels over chunk entries, writing only nodes the store lacks. */
export function build(chunks: Entry[], store: NodeStore): Built {
  if (chunks.length === 0) {
    const root = store.put(new Uint8Array(), cids.RAW);
    return { root, height: 0, writtenBytes: 0, writtenNodes: 0 };
  }
  let level = chunks;
  let height = 0, writtenBytes = 0, writtenNodes = 0;
  while (level.length > 1) {
    height += 1;
    const next: Entry[] = [];
    for (const entries of group(level)) {
      const bytes = encodeNode(height, entries);
      const cid = cids.of(bytes, cids.DAG_CBOR);
      if (!store.has(cid)) {
        store.putVerified(cid, bytes);
        writtenBytes += bytes.length;
        writtenNodes += 1;
      }
      let under = 0;
      for (const e of entries) {
        under += e.length;
      }
      next.push({ cid, length: under });
    }
    level = next;
  }
  return { root: level[0]!.cid, height, writtenBytes, writtenNodes };
}

interface BNode { links: string[]; sizes: number[]; height: number }

function decodeB(cid: string, bytes: Uint8Array): BNode {
  const node = decode(bytes, cid);
  if (node[KIND_KEY] !== KIND_B) {
    throw new NodeFormatError(`kind '${String(node[KIND_KEY])}' where a blob node was expected`, cid);
  }
  const links = ((node["c"] as Link[] | undefined) ?? []).map((l) => l.cid);
  const sizes = (node["z"] as number[] | undefined) ?? [];
  if (links.length === 0 || links.length !== sizes.length) {
    throw new NodeFormatError(`blob node with ${links.length} links and ${sizes.length} sizes`, cid);
  }
  const height = node["h"];
  if (typeof height !== "number" || height < 1) {
    throw new NodeFormatError("blob node without a height", cid);
  }
  let total = 0;
  for (const z of sizes) {
    total += z;
    if (!Number.isSafeInteger(total)) {
      throw new NodeFormatError("blob node byte counts overflow", cid);
    }
  }
  return { links, sizes, height };
}

/** The tree of a held blob root: size, chunks, seeking, and verified chunk reads. */
export class BlobTree {
  private chunkList: Entry[] | null;

  private constructor(readonly store: NodeStore, readonly root: string, readonly size: number, readonly height: number,
                      chunks: Entry[] | null) {
    this.chunkList = chunks;
  }

  static open(store: NodeStore, root: string): BlobTree {
    const bytes = store.get(root);
    if (bytes === undefined) {
      throw new NodeFormatError("blob root is not in the store", root);
    }
    if (cids.parse(root).codec === cids.RAW) {
      return new BlobTree(store, root, bytes.length, 0, bytes.length === 0 ? [] : [{ cid: root, length: bytes.length }]);
    }
    const node = decodeB(root, bytes);
    return new BlobTree(store, root, node.sizes.reduce((a, b) => a + b, 0), node.height, null);
  }

  private load(cid: string, under: number): BNode {
    const bytes = this.store.get(cid);
    if (bytes === undefined) {
      throw new NodeFormatError("blob node is not in the store", cid);
    }
    const node = decodeB(cid, bytes);
    const held = node.sizes.reduce((a, b) => a + b, 0);
    if (held !== under) {
      throw new NodeFormatError(`blob node holds ${held} bytes where its parent claims ${under}`, cid);
    }
    return node;
  }

  /** The chunk entries in order (walks the tree once). */
  chunks(): Entry[] {
    if (this.chunkList === null) {
      const leaves: Entry[] = [];
      this.collect(this.root, this.size, leaves, 1);
      this.chunkList = leaves;
    }
    return this.chunkList;
  }

  private collect(cid: string, under: number, leaves: Entry[], depth: number): void {
    if (cids.parse(cid).codec === cids.RAW) {
      leaves.push({ cid, length: under });
      return;
    }
    if (depth > MAX_DEPTH) {
      throw new NodeFormatError(`tree deeper than ${MAX_DEPTH} levels`, cid);
    }
    const node = this.load(cid, under);
    node.links.forEach((link, i) => this.collect(link, node.sizes[i]!, leaves, depth + 1));
  }

  /** The chunk holding byte `offset`, by descending the `z` sums without loading leaves. */
  seek(offset: number): Located {
    if (offset < 0 || offset >= this.size) {
      throw new RangeError(`offset ${offset} outside a blob of ${this.size} bytes`);
    }
    let cid = this.root, start = 0, under = this.size, depth = 1;
    while (cids.parse(cid).codec !== cids.RAW) {
      if (depth > MAX_DEPTH) {
        throw new NodeFormatError(`tree deeper than ${MAX_DEPTH} levels`, cid);
      }
      const node = this.load(cid, under);
      let i = 0;
      while (i < node.sizes.length - 1 && offset >= start + node.sizes[i]!) {
        start += node.sizes[i]!;
        i += 1;
      }
      cid = node.links[i]!;
      under = node.sizes[i]!;
      depth += 1;
    }
    return { cid, start, length: under };
  }

  /** A chunk's bytes, checked against the length the tree claims. */
  chunk(entry: Entry): Uint8Array {
    const bytes = this.store.get(entry.cid);
    if (bytes === undefined) {
      throw new NodeFormatError("chunk is not in the store", entry.cid);
    }
    if (bytes.length !== entry.length) {
      throw new NodeFormatError(`chunk of ${bytes.length} bytes where the tree claims ${entry.length}`, entry.cid);
    }
    return bytes;
  }
}

/** Chunks bytes and writes the chunks the store lacks; returns the entries and the bytes written. */
function writeChunks(data: Uint8Array, store: NodeStore): { entries: Entry[]; written: number; count: number } {
  const entries: Entry[] = [];
  let written = 0, count = 0;
  for (const chunk of fastcdc.chunksOf(data)) {
    const cid = cids.of(chunk, cids.RAW);
    if (!store.has(cid)) {
      store.putVerified(cid, chunk);
      written += chunk.length;
      count += 1;
    }
    entries.push({ cid, length: chunk.length });
  }
  return { entries, written, count };
}

/**
 * A persistent blob: immutable bytes under a root, read by range with on-demand chunk loads, and
 * edited by `append` and `splice`, which re-chunk from the chunk holding the first changed byte and
 * reuse every chunk the store already holds.
 */
export class PBlob {
  private constructor(readonly store: NodeStore, readonly tree: BlobTree,
                      readonly writtenBytes: number, readonly writtenChunks: number, readonly writtenNodeBytes: number) {}

  static empty(store: NodeStore): PBlob {
    return PBlob.of(new Uint8Array(), store);
  }

  /** The blob of bytes: chunks and interior nodes written, those already held skipped. */
  static of(data: Uint8Array, store: NodeStore): PBlob {
    const chunks = writeChunks(data, store);
    const built = build(chunks.entries, store);
    return new PBlob(store, BlobTree.open(store, built.root), chunks.written + built.writtenBytes, chunks.count, built.writtenBytes);
  }

  /** A held blob by root. */
  static load(store: NodeStore, root: string): PBlob {
    return new PBlob(store, BlobTree.open(store, root), 0, 0, 0);
  }

  get root(): string {
    return this.tree.root;
  }

  get size(): number {
    return this.tree.size;
  }

  chunks(): Entry[] {
    return this.tree.chunks();
  }

  /** Verified bytes of `[offset, offset + length)`, loading only the path and the chunks of the range. */
  read(offset: number, length: number): Uint8Array {
    if (offset < 0 || length < 0 || offset + length > this.size) {
      throw new RangeError(`range ${offset}+${length} outside a blob of ${this.size} bytes`);
    }
    const parts: Uint8Array[] = [];
    let at = offset, left = length;
    while (left > 0) {
      const located = this.tree.seek(at);
      const chunk = this.tree.chunk({ cid: located.cid, length: located.length });
      const from = at - located.start;
      const take = Math.min(left, chunk.length - from);
      parts.push(chunk.subarray(from, from + take));
      at += take;
      left -= take;
    }
    return concat(...parts);
  }

  /** Every byte, verified chunk by chunk. */
  bytes(): Uint8Array {
    return concat(...this.chunks().map((e) => this.tree.chunk(e)));
  }

  append(data: Uint8Array): PBlob {
    return this.splice(this.size, 0, data);
  }

  /**
   * The blob with `removeLength` bytes at `offset` replaced by `insert`. Chunks before the first changed
   * byte keep their cuts (a cut depends on its own chunk alone), so only the tail is chunked again,
   * and the result equals chunking the whole content from scratch.
   */
  splice(offset: number, removeLength: number, insert: Uint8Array): PBlob {
    if (offset < 0 || removeLength < 0 || offset + removeLength > this.size) {
      throw new RangeError(`splice ${offset}+${removeLength} outside a blob of ${this.size} bytes`);
    }
    const old = this.chunks();
    const kept: Entry[] = [];
    let start = 0, k = 0;
    // every whole chunk strictly before the first changed byte stays, except the last one, whose cut
    // depended on end of stream and may move now that bytes follow it (a chunk that closed at MAX keeps)
    while (k < old.length && start + old[k]!.length <= offset
           && !(k === old.length - 1 && old[k]!.length < fastcdc.MAX_SIZE)) {
      kept.push(old[k]!);
      start += old[k]!.length;
      k += 1;
    }
    const tailOld = concat(...old.slice(k).map((e) => this.tree.chunk(e)));
    const cutAt = offset - start;
    const tail = concat(tailOld.subarray(0, cutAt), insert, tailOld.subarray(cutAt + removeLength));
    const chunks = writeChunks(tail, this.store);
    const built = build([...kept, ...chunks.entries], this.store);
    return new PBlob(this.store, BlobTree.open(this.store, built.root), chunks.written + built.writtenBytes, chunks.count,
      built.writtenBytes);
  }
}
