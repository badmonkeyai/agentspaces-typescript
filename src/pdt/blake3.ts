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
 * BLAKE3 blob identities and Bao outboards (PDT 2 phase 0, P2-B-02; srad/agentspaces-pdt2.md §3.5), a port of
 * Java's `Blake3` and `BaoOutboard`. A blob's identity is the BLAKE3 hash of its whole content as a CIDv1 of
 * codec `raw` over multihash 0x1e, so two publishers of one file share one identity whatever their chunking;
 * the hash is `@noble/hashes/blake3` (§3.5). An outboard needs the chaining values of subtrees, which the
 * library keeps private, so this module also carries the BLAKE3 compression function and computes the
 * chaining value of a 16 KiB chunk group and of a parent as the BLAKE3 specification defines them; the root
 * a tree of those values reaches equals the library's digest, which the tests check at every boundary.
 */

import { blake3 } from "@noble/hashes/blake3.js";

import * as cids from "./cids.js";
import { BoNode } from "./kinds.js";
import { Link } from "./nodes.js";

/** The bytes of a BLAKE3 hash and of a chaining value. */
export const DIGEST_BYTES = 32;
/** The multihash code of BLAKE3. */
export const MULTIHASH = 0x1e;
/** The bytes of one BLAKE3 chunk. */
export const CHUNK_BYTES = 1024;

const BLOCK_BYTES = 64;
const CHUNKS_PER_GROUP = 2 ** BoNode.GROUP_LOG;
const CHUNK_START = 1, CHUNK_END = 2, PARENT = 4, ROOT = 8;
const IV = Uint32Array.of(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);
const PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/** The message word order of each of the seven rounds, flattened. */
const SCHEDULE = ((): Uint8Array => {
  const out = new Uint8Array(7 * 16);
  for (let i = 0; i < 16; i++) {
    out[i] = i;
  }
  for (let r = 1; r < 7; r++) {
    for (let i = 0; i < 16; i++) {
      out[r * 16 + i] = out[(r - 1) * 16 + PERMUTATION[i]!]!;
    }
  }
  return out;
})();

/** The BLAKE3 hash of bytes, by `@noble/hashes` (§3.5). */
export function digest(data: Uint8Array): Uint8Array {
  return blake3(data);
}

/** The identity CID of a BLAKE3 hash: `0x01 0x55 0x1e 0x20` and the digest, base32, so it starts `bafkr4i`. */
export function identity(hash: Uint8Array): string {
  if (hash.length !== DIGEST_BYTES) {
    throw new RangeError(`a BLAKE3 identity names a 32-byte hash, found ${hash.length}`);
  }
  const binary = new Uint8Array(4 + DIGEST_BYTES);
  binary.set([0x01, cids.RAW, MULTIHASH, DIGEST_BYTES], 0);
  binary.set(hash, 4);
  return "b" + cids.base32Lower(binary);
}

/**
 * The chaining value of a group's chunks as a non-root subtree, the value a parent above the group combines.
 *
 * @param data       the group's bytes, any length up to a whole number of chunks plus a remainder
 * @param firstChunk the blob-wide index of the group's first chunk
 */
export function groupCv(data: Uint8Array, firstChunk: number): Uint8Array {
  return toBytes(subtree(data, 0, data.length, firstChunk, false));
}

/** The chaining value of a parent, or the hash of the whole tree when it is the root. */
export function parent(left: Uint8Array, right: Uint8Array, root: boolean): Uint8Array {
  return toBytes(parentWords(toWords(left), toWords(right), root));
}

function subtree(data: Uint8Array, offset: number, length: number, firstChunk: number, root: boolean): Uint32Array {
  const chunks = Math.max(1, Math.ceil(length / CHUNK_BYTES));
  if (chunks === 1) {
    return chunk(data, offset, length, firstChunk, root);
  }
  const leftChunks = highestOneBit(chunks - 1);
  const leftBytes = leftChunks * CHUNK_BYTES;
  const left = subtree(data, offset, leftBytes, firstChunk, false);
  const right = subtree(data, offset + leftBytes, length - leftBytes, firstChunk + leftChunks, false);
  return parentWords(left, right, root);
}

/** The largest power of two at most `n`, for n >= 1, exact up to 2^53 (BLAKE3's left subtree is the largest below the count). */
function highestOneBit(n: number): number {
  let bit = 1;
  while (bit * 2 <= n) {
    bit *= 2;
  }
  return bit;
}

function chunk(data: Uint8Array, offset: number, length: number, counter: number, root: boolean): Uint32Array {
  let cv: Uint32Array = IV;
  const blocks = Math.max(1, Math.ceil(length / BLOCK_BYTES));
  const block = new Uint32Array(16);
  for (let b = 0; b < blocks; b++) {
    const blockLength = Math.min(BLOCK_BYTES, length - b * BLOCK_BYTES);
    block.fill(0);
    const start = offset + b * BLOCK_BYTES;
    for (let i = 0; i < blockLength; i++) {
      block[i >>> 2]! |= data[start + i]! << ((i & 3) << 3);
    }
    const flags = (b === 0 ? CHUNK_START : 0) | (b === blocks - 1 ? CHUNK_END | (root ? ROOT : 0) : 0);
    cv = compress(cv, block, counter, blockLength, flags);
  }
  return cv;
}

function parentWords(left: Uint32Array, right: Uint32Array, root: boolean): Uint32Array {
  const block = new Uint32Array(16);
  block.set(left, 0);
  block.set(right, 8);
  return compress(IV, block, 0, BLOCK_BYTES, PARENT | (root ? ROOT : 0));
}

/** The first eight words of the BLAKE3 compression of one block: the next chaining value. */
function compress(cv: Uint32Array, m: Uint32Array, counter: number, blockLength: number, flags: number): Uint32Array {
  let s0 = cv[0]! | 0, s1 = cv[1]! | 0, s2 = cv[2]! | 0, s3 = cv[3]! | 0;
  let s4 = cv[4]! | 0, s5 = cv[5]! | 0, s6 = cv[6]! | 0, s7 = cv[7]! | 0;
  let s8 = IV[0]! | 0, s9 = IV[1]! | 0, s10 = IV[2]! | 0, s11 = IV[3]! | 0;
  let s12 = counter | 0, s13 = Math.floor(counter / 0x100000000) | 0, s14 = blockLength | 0, s15 = flags | 0;
  for (let r = 0; r < 7 * 16; r += 16) {
    // columns
    s0 = (s0 + s4 + m[SCHEDULE[r]!]!) | 0; s12 ^= s0; s12 = (s12 >>> 16) | (s12 << 16); s8 = (s8 + s12) | 0; s4 ^= s8; s4 = (s4 >>> 12) | (s4 << 20);
    s0 = (s0 + s4 + m[SCHEDULE[r + 1]!]!) | 0; s12 ^= s0; s12 = (s12 >>> 8) | (s12 << 24); s8 = (s8 + s12) | 0; s4 ^= s8; s4 = (s4 >>> 7) | (s4 << 25);
    s1 = (s1 + s5 + m[SCHEDULE[r + 2]!]!) | 0; s13 ^= s1; s13 = (s13 >>> 16) | (s13 << 16); s9 = (s9 + s13) | 0; s5 ^= s9; s5 = (s5 >>> 12) | (s5 << 20);
    s1 = (s1 + s5 + m[SCHEDULE[r + 3]!]!) | 0; s13 ^= s1; s13 = (s13 >>> 8) | (s13 << 24); s9 = (s9 + s13) | 0; s5 ^= s9; s5 = (s5 >>> 7) | (s5 << 25);
    s2 = (s2 + s6 + m[SCHEDULE[r + 4]!]!) | 0; s14 ^= s2; s14 = (s14 >>> 16) | (s14 << 16); s10 = (s10 + s14) | 0; s6 ^= s10; s6 = (s6 >>> 12) | (s6 << 20);
    s2 = (s2 + s6 + m[SCHEDULE[r + 5]!]!) | 0; s14 ^= s2; s14 = (s14 >>> 8) | (s14 << 24); s10 = (s10 + s14) | 0; s6 ^= s10; s6 = (s6 >>> 7) | (s6 << 25);
    s3 = (s3 + s7 + m[SCHEDULE[r + 6]!]!) | 0; s15 ^= s3; s15 = (s15 >>> 16) | (s15 << 16); s11 = (s11 + s15) | 0; s7 ^= s11; s7 = (s7 >>> 12) | (s7 << 20);
    s3 = (s3 + s7 + m[SCHEDULE[r + 7]!]!) | 0; s15 ^= s3; s15 = (s15 >>> 8) | (s15 << 24); s11 = (s11 + s15) | 0; s7 ^= s11; s7 = (s7 >>> 7) | (s7 << 25);
    // diagonals
    s0 = (s0 + s5 + m[SCHEDULE[r + 8]!]!) | 0; s15 ^= s0; s15 = (s15 >>> 16) | (s15 << 16); s10 = (s10 + s15) | 0; s5 ^= s10; s5 = (s5 >>> 12) | (s5 << 20);
    s0 = (s0 + s5 + m[SCHEDULE[r + 9]!]!) | 0; s15 ^= s0; s15 = (s15 >>> 8) | (s15 << 24); s10 = (s10 + s15) | 0; s5 ^= s10; s5 = (s5 >>> 7) | (s5 << 25);
    s1 = (s1 + s6 + m[SCHEDULE[r + 10]!]!) | 0; s12 ^= s1; s12 = (s12 >>> 16) | (s12 << 16); s11 = (s11 + s12) | 0; s6 ^= s11; s6 = (s6 >>> 12) | (s6 << 20);
    s1 = (s1 + s6 + m[SCHEDULE[r + 11]!]!) | 0; s12 ^= s1; s12 = (s12 >>> 8) | (s12 << 24); s11 = (s11 + s12) | 0; s6 ^= s11; s6 = (s6 >>> 7) | (s6 << 25);
    s2 = (s2 + s7 + m[SCHEDULE[r + 12]!]!) | 0; s13 ^= s2; s13 = (s13 >>> 16) | (s13 << 16); s8 = (s8 + s13) | 0; s7 ^= s8; s7 = (s7 >>> 12) | (s7 << 20);
    s2 = (s2 + s7 + m[SCHEDULE[r + 13]!]!) | 0; s13 ^= s2; s13 = (s13 >>> 8) | (s13 << 24); s8 = (s8 + s13) | 0; s7 ^= s8; s7 = (s7 >>> 7) | (s7 << 25);
    s3 = (s3 + s4 + m[SCHEDULE[r + 14]!]!) | 0; s14 ^= s3; s14 = (s14 >>> 16) | (s14 << 16); s9 = (s9 + s14) | 0; s4 ^= s9; s4 = (s4 >>> 12) | (s4 << 20);
    s3 = (s3 + s4 + m[SCHEDULE[r + 15]!]!) | 0; s14 ^= s3; s14 = (s14 >>> 8) | (s14 << 24); s9 = (s9 + s14) | 0; s4 ^= s9; s4 = (s4 >>> 7) | (s4 << 25);
  }
  return Uint32Array.of(s0 ^ s8, s1 ^ s9, s2 ^ s10, s3 ^ s11, s4 ^ s12, s5 ^ s13, s6 ^ s14, s7 ^ s15);
}

function toWords(bytes: Uint8Array): Uint32Array {
  if (bytes.length !== DIGEST_BYTES) {
    throw new RangeError(`a chaining value holds 32 bytes, found ${bytes.length}`);
  }
  const words = new Uint32Array(8);
  for (let i = 0; i < DIGEST_BYTES; i++) {
    words[i >>> 2]! |= bytes[i]! << ((i & 3) << 3);
  }
  return words;
}

function toBytes(words: Uint32Array): Uint8Array {
  const out = new Uint8Array(DIGEST_BYTES);
  for (let i = 0; i < DIGEST_BYTES; i++) {
    out[i] = words[i >>> 2]! >>> ((i & 3) << 3);
  }
  return out;
}

// ------------------------------------------------------------------ the outboard

/** An outboard: the attribute values `pdt.bao` (root) and `pdt.blake3` (identity), and every `bo` node by CID. */
export interface Outboard {
  readonly root: string;
  readonly identity: string;
  readonly size: number;
  /** Every `bo` node by CID, children before their parent and the root last. */
  readonly nodes: ReadonlyMap<string, Uint8Array>;
}

/**
 * Reads a blob's bytes, in pieces of any size, and builds its identity and outboard in one pass that holds
 * one 16 KiB group and one 32-byte chaining value per group, so a 10 GiB blob costs about 20 MiB.
 */
export function outboard(pieces: Iterable<Uint8Array>): Outboard {
  const hasher = blake3.create();
  const groupCvs: Uint8Array[] = [];
  const group = new Uint8Array(BoNode.GROUP_BYTES);
  let filled = 0;
  let size = 0;
  for (const piece of pieces) {
    hasher.update(piece);
    size += piece.length;
    for (let at = 0; at < piece.length;) {
      const n = Math.min(group.length - filled, piece.length - at);
      group.set(piece.subarray(at, at + n), filled);
      filled += n;
      at += n;
      if (filled === group.length) {
        groupCvs.push(groupCv(group, groupCvs.length * CHUNKS_PER_GROUP));
        filled = 0;
      }
    }
  }
  if (filled > 0 || groupCvs.length === 0) {
    groupCvs.push(groupCv(group.subarray(0, filled), groupCvs.length * CHUNKS_PER_GROUP));
  }
  const nodes = new Map<string, Uint8Array>();
  const root = build(groupCvs, 0, size, nodes).cid;
  return { root, identity: identity(hasher.digest()), size, nodes };
}

/** Builds the node over the groups from `firstGroup` that hold `size` bytes; returns its CID and chaining value. */
function build(groupCvs: Uint8Array[], firstGroup: number, size: number, nodes: Map<string, Uint8Array>):
    { cid: string; cv: Uint8Array } {
  const blocks = BoNode.childSizes(size);
  const leaves: Uint8Array[] = [];
  const children: Link[] = [];
  if (blocks.length === 0) {
    leaves.push(...groupCvs.slice(firstGroup, firstGroup + BoNode.groups(size)));
  } else {
    let next = firstGroup;
    for (const block of blocks) {
      const child = build(groupCvs, next, block, nodes);
      children.push(new Link(child.cid));
      leaves.push(child.cv);
      next += BoNode.groups(block);
    }
  }
  const parents = new Uint8Array((leaves.length - 1) * BoNode.PARENT_BYTES);
  const cv = preOrder(leaves, 0, leaves.length, parents, { at: 0 });
  const bytes = new BoNode(size, parents, children).encode();
  const cid = cids.of(bytes, cids.DAG_CBOR);
  nodes.set(cid, bytes);
  return { cid, cv };
}

/**
 * Writes the parent pairs over `leaves[from, to)` in pre-order and returns the subtree's chaining value.
 * BLAKE3 puts the largest power of two strictly below the count on the left; an upper node's leaves are
 * whole aligned blocks, so the same rule applies to them.
 */
function preOrder(leaves: Uint8Array[], from: number, to: number, parents: Uint8Array, cursor: { at: number }): Uint8Array {
  if (to - from === 1) {
    return leaves[from]!;
  }
  const at = cursor.at;
  cursor.at += BoNode.PARENT_BYTES;
  const mid = from + highestOneBit(to - from - 1);
  const left = preOrder(leaves, from, mid, parents, cursor);
  const right = preOrder(leaves, mid, to, parents, cursor);
  parents.set(left, at);
  parents.set(right, at + DIGEST_BYTES);
  return parent(left, right, false);
}
