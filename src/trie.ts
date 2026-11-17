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
 * The fingerprinted trie of SPEC annex I.6 (v0.1.35, `wire.ae=2`; srad/replication-by-entry.md §3.1, RE-L-01): the
 * audited set of one space as slots keyed on the nibbles of SHA-256(entry id), with the canonical shape, the leaf and
 * inner preimages, the 16-byte fingerprints and the stream hash every implementation computes alike.
 *
 * The trie holds the audited set only: a slot is an entry id with its audited lines (the state line, the claim line,
 * and the lines the replica acknowledges, each standing as itself). The caller decides which lines a slot has (a
 * lapsed entry's state and claim lines are left out, an id with a control character never enters), so this module
 * knows nothing of states, claims or clocks, and the conformance checker drives it from the vectors alone.
 *
 * The tree is mutable, unlike Java's persistent one, since this client keeps one replica per space and never shares a
 * snapshot across threads. A change invalidates the cached fingerprints on its path only, and a fingerprint is
 * computed the first time it is asked, so a batch of changes hashes only the nodes of the final tree.
 */

import { compare, utf8 } from "./bytes.js";
import { cryptoPort } from "./crypto.js";

/** The leaf threshold T: a node of at most this many slots is a leaf. */
export const LEAF_MAX = 32;
/** Nibbles in a path at most; a node at this depth is a leaf whatever its count. */
export const PATH_MAX = 64;
/** Bytes of an inner node's preimage: sixteen children of a 16-byte fingerprint and an 8-byte count. */
export const NODES_BYTES = 384;
/** Bytes of a fingerprint: the first 16 bytes of the SHA-256 of a preimage. */
export const FINGERPRINT_BYTES = 16;

const EMPTY = new Uint8Array(0);
const LF = 0x0a;

/** Whether text holds U+0000 to U+001F or U+007F, the characters annex I.6 keeps out of the audited set. */
export function hasControl(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

/** The key of an entry id: SHA-256 of its UTF-8 bytes (annex I.6, *The key and the path*). */
export function keyOf(id: string): Uint8Array {
  return cryptoPort().sha256(utf8(id));
}

/** Nibble `i` of a key, the high four bits of byte i/2 first. */
export function nibbleAt(key: Uint8Array, i: number): number {
  const b = key[i >> 1]!;
  return (i & 1) === 0 ? b >> 4 : b & 0x0f;
}

/** Whether a key begins with a path of nibbles. */
export function keyStartsWith(key: Uint8Array, path: Uint8Array): boolean {
  for (let i = 0; i < path.length; i++) {
    if (nibbleAt(key, i) !== path[i]) {
      return false;
    }
  }
  return true;
}

/** The first 16 bytes of the SHA-256 of a preimage. */
export function fingerprintOf(preimage: Uint8Array): Uint8Array {
  return cryptoPort().sha256(preimage).slice(0, FINGERPRINT_BYTES);
}

/**
 * The entry id a line names: the text between `e:` or `c:` and the last `=`, since a state hash is hex and a claim
 * hash holds no `=`. Null for a line of another shape.
 */
export function entryIdOf(line: string): string | null {
  if (line.length < 4 || line.charAt(1) !== ":" || (line.charAt(0) !== "e" && line.charAt(0) !== "c")) {
    return null;
  }
  const eq = line.lastIndexOf("=");
  return eq <= 2 ? null : line.substring(2, eq);
}

/** What one replica holds under one entry id, as the audited set reads it (annex I.6, *The audited set*). */
export interface SlotHolding {
  /** The hash the state line names when a state is held, a tombstone included. */
  state: string | null;
  /** The hash the claim line names when a claim is held. */
  claim: string | null;
  /** The state line a tag-sharded replica remembered when it dropped the entry; counts only with no state held. */
  dropped?: string | null;
  /** Whether a held, present entry's write lease has lapsed by this replica's clock. */
  lapsed: boolean;
  /** The lines this replica acknowledges for the id, each standing as itself. */
  acks: Iterable<string>;
}

/**
 * The audited lines of one slot: the state line (or a remembered dropped line) and the claim line unless a held state
 * has lapsed, and every acknowledged line, each once; none at all for an id holding a control character.
 */
export function slotLines(id: string, holding: SlotHolding): string[] {
  if (hasControl(id)) {
    return [];
  }
  const out = new Set<string>();
  if (!(holding.lapsed && holding.state !== null)) {
    const hash = holding.state ?? holding.dropped ?? null;
    if (hash !== null) {
      out.add(`e:${id}=${hash}`);
    }
    if (holding.claim !== null) {
      out.add(`c:${id}=${holding.claim}`);
    }
  }
  for (const ack of holding.acks) {
    out.add(ack);
  }
  return [...out].filter((line) => !hasControl(line));
}

/** Lines as UTF-8, each once, sorted by unsigned bytes: the order of a leaf's preimage. */
function sortedLineBytes(lines: Iterable<string>): Uint8Array[] {
  const seen = new Set<string>();
  const out: Uint8Array[] = [];
  for (const line of lines) {
    if (!seen.has(line)) {
      seen.add(line);
      out.push(utf8(line));
    }
  }
  return out.sort(compare);
}

/** Lines joined by one LF with none after the last: a leaf's preimage. */
function joinLines(lines: Uint8Array[]): Uint8Array {
  if (lines.length === 0) {
    return EMPTY;
  }
  let size = lines.length - 1;
  for (const line of lines) {
    size += line.length;
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (let i = 0; i < lines.length; i++) {
    if (i > 0) {
      out[at++] = LF;
    }
    out.set(lines[i]!, at);
    at += lines[i]!.length;
  }
  return out;
}

/** One node an audit reads: its count, whether it is inner, its preimage, and its fingerprint (null when empty). */
export interface AuditNode {
  readonly count: number;
  readonly inner: boolean;
  readonly preimage: Uint8Array;
  readonly fingerprint: Uint8Array | null;
  /**
   * The UTF-8 bytes of every line under the node, each with one LF: the leaf preimage of all of them is one byte
   * shorter. Known without a walk, so a partner never gathers lines it could not send (a DoS bound, adversarial
   * review of 2026-11-15). Exact because every audited line names its own slot's id, so no two slots share a line.
   */
  readonly bytes: number;
}

const EMPTY_NODE: AuditNode = { count: 0, inner: false, preimage: EMPTY, fingerprint: null, bytes: 0 };

/** One slot: an entry id, its key, its audited lines, each once, and their UTF-8 bytes with one LF each. */
interface Slot {
  readonly id: string;
  readonly key: Uint8Array;
  readonly lines: readonly string[];
  readonly bytes: number;
}

/** A node of the stored tree: a leaf holds its slots, an inner node its sixteen children. */
class TrieNode {
  count = 0;
  /** The bytes of the lines under the node, as {@link AuditNode.bytes}. */
  bytes = 0;
  slots: Map<string, Slot> | null = new Map();
  children: (TrieNode | undefined)[] | null = null;
  /** The cached preimage and fingerprint, cleared on every change under this node. */
  preimage: Uint8Array | null = null;
  fingerprint: Uint8Array | null = null;

  invalidate(): void {
    this.preimage = null;
    this.fingerprint = null;
  }
}

/**
 * One space's audited set as the trie of annex I.6. Stores its tree in the canonical shape (a leaf at 32 slots or
 * fewer or at 64 nibbles, an inner node otherwise), so a node it stores answers for its path directly; a path below a
 * stored leaf is answered from that leaf's slots, which the annex allows (an implementation may store its tree in any
 * form that answers the same fingerprints).
 */
export class HashTrie {
  private root = new TrieNode();
  private hash: Uint8Array | null = null;
  /** Every slot by id, so a lookup or a replacement costs no walk. */
  private readonly byId = new Map<string, Slot>();

  /** The number of slots, the count of the root. */
  get size(): number {
    return this.root.count;
  }

  /** The ids of every slot, in no particular order. */
  ids(): IterableIterator<string> {
    return this.byId.keys();
  }

  /** The lines of a slot, sorted by UTF-8 bytes, or undefined when the trie holds none for the id. */
  get(id: string): readonly string[] | undefined {
    return this.byId.get(id)?.lines;
  }

  /**
   * Sets the audited lines of an entry id; no lines removes its slot. A caller filters what is audited (a lapsed
   * state, a control character) before it calls this; an id with a control character is refused here too, so no
   * caller can make a leaf preimage name two sets.
   */
  put(id: string, lines: Iterable<string>): void {
    const kept = hasControl(id) ? [] : [...new Set([...lines].filter((line) => line.length > 0 && !hasControl(line)))];
    if (kept.length === 0) {
      this.remove(id);
      return;
    }
    const encoded = kept.map((line) => ({ line, bytes: utf8(line) })).sort((a, b) => compare(a.bytes, b.bytes));
    const sorted = encoded.map(({ line }) => line);
    const before = this.byId.get(id);
    if (before !== undefined && before.lines.length === sorted.length
        && before.lines.every((line, i) => line === sorted[i])) {
      return; // nothing changes, so no fingerprint is lost
    }
    const bytes = encoded.reduce((sum, { bytes: b }) => sum + b.length + 1, 0);
    const slot: Slot = { id, key: before?.key ?? keyOf(id), lines: sorted, bytes };
    this.byId.set(id, slot);
    this.hash = null;
    this.insert(this.root, slot, 0, bytes - (before?.bytes ?? 0));
  }

  /**
   * Whether this trie holds a line under a path: the slot of the id the line names begins with the path and lists
   * the line. It reads one slot, so an asker compares a partner's lines in proportion to the answer, never to its own
   * set under the path (adversarial review of 2026-11-15: a member of a million entries spent 2.7 s per round
   * gathering and sorting its whole set to compare one small partner's root of lines).
   */
  holdsLine(id: string, line: string, path: Uint8Array): boolean {
    const slot = this.byId.get(id);
    return slot !== undefined && keyStartsWith(slot.key, path) && slot.lines.includes(line);
  }

  /** Removes an entry id's slot; nothing when there is none. */
  remove(id: string): void {
    const slot = this.byId.get(id);
    if (slot === undefined) {
      return;
    }
    this.byId.delete(id);
    this.hash = null;
    this.removeFrom(this.root, slot, 0);
  }

  /** Returns whether the slot was new under this node; `delta` is the change in its lines' bytes. */
  private insert(node: TrieNode, slot: Slot, depth: number, delta: number): boolean {
    node.invalidate();
    node.bytes += delta;
    if (node.slots !== null) {
      const existed = node.slots.has(slot.id);
      node.slots.set(slot.id, slot);
      if (!existed) {
        node.count += 1;
        if (node.count > LEAF_MAX && depth < PATH_MAX) {
          this.split(node, depth);
        }
      }
      return existed;
    }
    const c = nibbleAt(slot.key, depth);
    let child = node.children![c];
    if (child === undefined) {
      child = new TrieNode();
      node.children![c] = child;
    }
    const existed = this.insert(child, slot, depth + 1, delta);
    if (!existed) {
      node.count += 1;
    }
    return existed;
  }

  /** Splits a leaf past T on its next nibble, and any child that is still past T, so the shape stays canonical. */
  private split(node: TrieNode, depth: number): void {
    const children: (TrieNode | undefined)[] = new Array(16).fill(undefined);
    for (const slot of node.slots!.values()) {
      const c = nibbleAt(slot.key, depth);
      let child = children[c];
      if (child === undefined) {
        child = new TrieNode();
        children[c] = child;
      }
      child.slots!.set(slot.id, slot);
      child.count += 1;
      child.bytes += slot.bytes;
    }
    node.slots = null;
    node.children = children;
    node.invalidate();
    for (const child of children) {
      if (child !== undefined && child.count > LEAF_MAX && depth + 1 < PATH_MAX) {
        this.split(child, depth + 1);
      }
    }
  }

  private removeFrom(node: TrieNode, slot: Slot, depth: number): boolean {
    if (node.slots !== null) {
      if (!node.slots.delete(slot.id)) {
        return false;
      }
      node.count -= 1;
      node.bytes -= slot.bytes;
      node.invalidate();
      return true;
    }
    const c = nibbleAt(slot.key, depth);
    const child = node.children![c];
    if (child === undefined || !this.removeFrom(child, slot, depth + 1)) {
      return false;
    }
    if (child.count === 0) {
      node.children![c] = undefined;
    }
    node.count -= 1;
    node.bytes -= slot.bytes;
    node.invalidate();
    if (node.count <= LEAF_MAX) {
      // The children are canonical already, so the node becomes one leaf of everything under it.
      const slots = new Map<string, Slot>();
      collect(node, slots);
      node.children = null;
      node.slots = slots;
    }
    return true;
  }

  /**
   * The node at a path (one nibble per byte, at most 64), as an audit reads it: empty, a leaf with its lines, or an
   * inner node with its 384-byte preimage.
   */
  node(path: Uint8Array): AuditNode {
    let node = this.root;
    let depth = 0;
    while (depth < path.length && node.slots === null) {
      const child = node.children![path[depth]!];
      if (child === undefined) {
        return EMPTY_NODE;
      }
      node = child;
      depth += 1;
    }
    if (depth < path.length) {
      // Below a stored leaf: the slots of the leaf whose keys begin with the path, which is a leaf too.
      const under: Slot[] = [];
      for (const slot of node.slots!.values()) {
        if (keyStartsWith(slot.key, path)) {
          under.push(slot);
        }
      }
      if (under.length === 0) {
        return EMPTY_NODE;
      }
      const preimage = joinLines(sortedLineBytes(under.flatMap((slot) => slot.lines)));
      return { count: under.length, inner: false, preimage, fingerprint: fingerprintOf(preimage),
        bytes: under.reduce((sum, slot) => sum + slot.bytes, 0) };
    }
    if (node.count === 0) {
      return EMPTY_NODE;
    }
    return { count: node.count, inner: node.slots === null, preimage: preimageOf(node), fingerprint: fingerprintOfNode(node),
      bytes: node.bytes };
  }

  /**
   * Every line under a path, sorted and joined as a leaf's preimage, whatever the node's kind there; null when the
   * lines pass `maxBytes`, so a partner never gathers and sorts lines it cannot send.
   */
  lines(path: Uint8Array, maxBytes = Number.POSITIVE_INFINITY): Uint8Array | null {
    let node = this.root;
    let depth = 0;
    while (depth < path.length && node.slots === null) {
      const child = node.children![path[depth]!];
      if (child === undefined) {
        return EMPTY;
      }
      node = child;
      depth += 1;
    }
    const lines: string[] = [];
    let size = 0;
    const visit = (at: TrieNode): boolean => {
      if (at.slots !== null) {
        for (const slot of at.slots.values()) {
          if (depth < path.length && !keyStartsWith(slot.key, path)) {
            continue;
          }
          for (const line of slot.lines) {
            lines.push(line);
            size += line.length + 1;
            if (size > maxBytes + 1) {
              return false;
            }
          }
        }
        return true;
      }
      for (const child of at.children!) {
        if (child !== undefined && !visit(child)) {
          return false;
        }
      }
      return true;
    };
    if (!visit(node)) {
      return null;
    }
    const joined = joinLines(sortedLineBytes(lines));
    return joined.length > maxBytes ? null : joined;
  }

  /** The stream hash: the whole SHA-256 of the root's preimage; of zero bytes for an empty space. */
  streamHash(): Uint8Array {
    if (this.hash === null) {
      this.hash = cryptoPort().sha256(this.root.count === 0 ? EMPTY : preimageOf(this.root));
    }
    return this.hash;
  }
}

/** Gathers every slot under a node. */
function collect(node: TrieNode, into: Map<string, Slot>): void {
  if (node.slots !== null) {
    for (const [id, slot] of node.slots) {
      into.set(id, slot);
    }
    return;
  }
  for (const child of node.children!) {
    if (child !== undefined) {
      collect(child, into);
    }
  }
}

/** A stored node's preimage, cached until a change under it. */
function preimageOf(node: TrieNode): Uint8Array {
  if (node.preimage !== null) {
    return node.preimage;
  }
  let preimage: Uint8Array;
  if (node.slots !== null) {
    preimage = joinLines(sortedLineBytes([...node.slots.values()].flatMap((slot) => slot.lines)));
  } else {
    preimage = new Uint8Array(NODES_BYTES);
    const view = new DataView(preimage.buffer);
    node.children!.forEach((child, c) => {
      if (child !== undefined && child.count > 0) {
        preimage.set(fingerprintOfNode(child), c * 24);
        view.setBigUint64(c * 24 + 16, BigInt(child.count));
      }
    });
  }
  node.preimage = preimage;
  return preimage;
}

function fingerprintOfNode(node: TrieNode): Uint8Array {
  if (node.fingerprint === null) {
    node.fingerprint = fingerprintOf(preimageOf(node));
  }
  return node.fingerprint;
}

/** The count of child `c` in an inner preimage, or -1 past what a safe integer holds. */
export function childCount(nodes: Uint8Array, c: number): number {
  const count = new DataView(nodes.buffer, nodes.byteOffset, nodes.byteLength).getBigUint64(c * 24 + 16);
  return count > BigInt(Number.MAX_SAFE_INTEGER) ? -1 : Number(count);
}

/** The fingerprint of child `c` in an inner preimage. */
export function childFingerprint(nodes: Uint8Array, c: number): Uint8Array {
  return nodes.subarray(c * 24, c * 24 + FINGERPRINT_BYTES);
}
