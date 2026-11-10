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
 * A text that merges (PDT 2 phase 7, P2-C-01, P2-T-02, P2-T-03, P2-T-05; srad/agentspaces-pdt2.md §3.9), a port of
 * Java's `PText`: a Fugue sequence of characters with ids, edited by one replica at a time, stored as a `t` leaf of
 * runs. Positions and lengths count code points, as the runs do.
 *
 * An insert hangs the new characters as the right child of the live character before the position when it has no
 * right children, else as the left child of the next character in Fugue order (deleted ones included); each further
 * character is the right child of the one before it. A replica numbers its characters from one more than the largest
 * counter it holds, so typing at the cursor extends one run. A delete keeps the ids and drops the text. `merge` is the
 * union, which every replica computes alike.
 *
 * As a value a text is the wire encoding of its leaf's map, `{k:"t", r:[run...], v:1}`, the map indefinite as every
 * embedded item is (rule S8); `PText.codec` writes and reads exactly that form, and a ref whose values pass through it
 * writes `PRef.v` 2 heads (§6.10.3, rule 3).
 */

import { equals, utf8 } from "../bytes.js";
import { dumps, loads } from "../cbor.js";
import type { CborValue } from "../cbor.js";
import { cryptoPort } from "../crypto.js";
import * as cids from "./cids.js";
import { TextLeaf } from "./kinds.js";
import { CharId, TextRun } from "./nodes.js";
import type { Codec } from "./values.js";

/** One piece of the text in Fugue order; `lastHasRight` tells whether its last character has a right child. */
interface Piece {
  readonly replica: string;
  readonly counter: number;
  readonly length: number;
  readonly deleted: boolean;
  readonly text: string;
  readonly parent: CharId | null;
  readonly left: boolean;
  readonly lastHasRight: boolean;
}

const visible = (p: Piece): number => (p.deleted ? 0 : p.length);

/** The UTF-16 offset of code point `k` of a text. */
function offset(text: string, k: number): number {
  let at = 0;
  for (let i = 0; i < k; i++) {
    at += text.codePointAt(at)! > 0xffff ? 2 : 1;
  }
  return at;
}

function head(p: Piece, k: number): Piece {
  return { ...p, length: k, text: p.deleted ? "" : p.text.slice(0, offset(p.text, k)), lastHasRight: true };
}

function tail(p: Piece, k: number): Piece {
  return { replica: p.replica, counter: p.counter + k, length: p.length - k, deleted: p.deleted,
    text: p.deleted ? "" : p.text.slice(offset(p.text, k)), parent: new CharId(p.replica, p.counter + k - 1), left: false,
    lastHasRight: p.lastHasRight };
}

const codePoints = (text: string): number => {
  let n = 0;
  for (const _ of text) {
    n += 1;
  }
  return n;
};

/** The first bytes of every text value: an indefinite map whose first key `k` holds `"t"`. */
const TEXT_PREFIX = Uint8Array.of(0xbf, 0x61, 0x6b, 0x61, 0x74);

export class PText {
  /** The characters one text holds at most, live and deleted: the leaf bound. */
  static readonly MAX_CHARS = TextLeaf.MAX_CHARS;
  /** The length of a replica id {@link replicaOf} derives. */
  static readonly REPLICA_LENGTH = 8;

  private readonly live: number;
  private readonly chars: number;
  private readonly next: number;

  private constructor(readonly replica: string, private readonly pieces: readonly Piece[], private cached: TextLeaf | null) {
    if (typeof replica !== "string" || replica.length === 0) {
      throw new RangeError("a replica is non-empty text");
    }
    let live = 0, all = 0, top = -1;
    for (const p of pieces) {
      live += visible(p);
      all += p.length;
      if (p.replica === replica) {
        top = Math.max(top, p.counter + p.length - 1);
      }
    }
    this.live = live;
    this.chars = all;
    this.next = top + 1;
  }

  /** The empty text, edited by a replica. */
  static empty(replica: string): PText {
    return new PText(replica, [], null);
  }

  /** The text of a leaf, edited by a replica. */
  static of(leaf: TextLeaf, replica: string): PText {
    const byReplica = new Map<string, TextRun[]>();
    const rightParents = new Set<string>();
    for (const run of leaf.runs) {
      const list = byReplica.get(run.replica) ?? [];
      list.push(run);
      byReplica.set(run.replica, list);
      if (run.parent !== null && run.side === "R") {
        rightParents.add(`${run.parent.replica}\u0000${run.parent.counter}`);
      }
    }
    const pieces: Piece[] = leaf.pieces().map((p) => {
      const last = p.counter + p.length - 1;
      // runs of one replica sort by counter, so the run holding `last` is the last one starting at or before it
      const runs = byReplica.get(p.replica)!;
      let lo = 0, hi = runs.length - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >>> 1;
        if (runs[mid]!.counter <= last) {
          lo = mid;
        } else {
          hi = mid - 1;
        }
      }
      const run = runs[lo]!;
      const inside = last < run.counter + run.length - 1;
      return { replica: p.replica, counter: p.counter, length: p.length, deleted: p.deleted, text: p.text, parent: p.parent,
        left: p.side === "L", lastHasRight: inside || rightParents.has(`${p.replica}\u0000${last}`) };
    });
    return new PText(replica, pieces, leaf);
  }

  /**
   * The replica id of an agent (P2-T-02): the first five bytes of the SHA-256 of its id's text, as eight lower-case
   * base32 characters.
   */
  static replicaOf(agentId: string): string {
    return cids.base32Lower(cryptoPort().sha256(utf8(agentId)).subarray(0, 5));
  }

  /** The codec of texts edited by a replica: the value form of the leaf, read strictly. */
  static codec(replica: string): TextCodec {
    return new TextCodec(PText.empty(replica).replica);
  }

  /** The value form of a leaf: the wire encoding of `{k:"t", r:[run...], v:1}`. */
  static toWire(leaf: TextLeaf): Uint8Array {
    return dumps({ k: "t", r: leaf.runs.map((run): CborValue => [run.replica, run.counter,
      run.parent === null ? null : [run.parent.replica, run.parent.counter], run.side, run.length, run.deleted, run.text]),
    v: TextLeaf.VERSION });
  }

  /**
   * The leaf of a text value, read strictly: exactly the keys `k`, `r`, `v`, runs in canonical form, and bytes that
   * are the value form of the leaf they read as. Throws RangeError otherwise.
   */
  static fromWire(cbor: Uint8Array): TextLeaf {
    let map: CborValue;
    try {
      map = loads(cbor);
    } catch (e) {
      throw new RangeError(`a text value is one CBOR map in the wire encoding: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (typeof map !== "object" || map === null || Array.isArray(map) || map instanceof Uint8Array
        || Object.keys(map).join(",") !== "k,r,v" || (map as { [k: string]: CborValue })["k"] !== "t"
        || !Array.isArray((map as { [k: string]: CborValue })["r"]) || (map as { [k: string]: CborValue })["v"] !== TextLeaf.VERSION) {
      throw new RangeError('a text value is {k:"t", r:[run...], v:1}');
    }
    const runs = ((map as { [k: string]: CborValue })["r"] as CborValue[]).map((item) => {
      if (!Array.isArray(item) || item.length !== 7 || typeof item[0] !== "string" || typeof item[1] !== "number"
          || typeof item[3] !== "string" || typeof item[4] !== "number" || typeof item[5] !== "boolean"
          || typeof item[6] !== "string") {
        throw new RangeError("a text run is [replica, counter, parent, side, length, deleted, text]");
      }
      const p = item[2];
      let parent: CharId | null = null;
      if (Array.isArray(p) && p.length === 2 && typeof p[0] === "string" && typeof p[1] === "number") {
        parent = new CharId(p[0], p[1]);
      } else if (p !== null) {
        throw new RangeError("a run's parent is [replica, counter] or null");
      }
      return new TextRun(item[0], item[1], parent, item[3] as "L" | "R", item[4], item[5], item[6]);
    });
    const leaf = new TextLeaf(runs);
    if (!equals(PText.toWire(leaf), cbor)) {
      throw new RangeError("the bytes are not the value form of the text they read as");
    }
    return leaf;
  }

  /** Whether a value's CBOR is a text in its value form: the spill and the map merge treat such a value as text. */
  static isText(cbor: Uint8Array): boolean {
    if (cbor.length < TEXT_PREFIX.length || !TEXT_PREFIX.every((b, i) => cbor[i] === b)) {
      return false;
    }
    try {
      PText.fromWire(cbor);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * The union of two text values, or null when they disagree on a character or when the union would pass the 1 MiB
   * node bound as a `t` node, so the resolver decides the key on every replica alike.
   */
  static union(a: Uint8Array, b: Uint8Array): Uint8Array | null {
    try {
      const merged = PText.fromWire(a).union(PText.fromWire(b));
      merged.encode(); // the node encoding refuses a leaf over the node bound
      return PText.toWire(merged);
    } catch {
      return null;
    }
  }

  // ------------------------------------------------------------------ reads

  /** The live characters, in code points. */
  length(): number {
    return this.live;
  }

  toString(): string {
    return this.pieces.map((p) => p.text).join("");
  }

  /** Every character id in Fugue order, deleted ones included. */
  order(): CharId[] {
    const out: CharId[] = [];
    for (const p of this.pieces) {
      for (let i = 0; i < p.length; i++) {
        out.push(new CharId(p.replica, p.counter + i));
      }
    }
    return out;
  }

  /** The canonical leaf of the characters, maximal runs in id order. */
  leaf(): TextLeaf {
    if (this.cached === null) {
      this.cached = TextLeaf.of(this.pieces.map((p) => new TextRun(p.replica, p.counter, p.parent, p.left ? "L" : "R", p.length,
        p.deleted, p.text)));
    }
    return this.cached;
  }

  /** Equality by the leaf: the same characters, ids, and deletions, whatever the replica. */
  equals(other: PText): boolean {
    return equals(this.leaf().encode(), other.leaf().encode());
  }

  // ------------------------------------------------------------------ writes

  /** This text edited by another replica. */
  withReplica(other: string): PText {
    return new PText(other, this.pieces, this.cached);
  }

  /** The text with characters inserted before a position (0 to `length()`). */
  insert(pos: number, text: string): PText {
    if (!Number.isSafeInteger(pos) || pos < 0 || pos > this.live) {
      throw new RangeError(`position ${pos} of a text of ${this.live}`);
    }
    const k = codePoints(text);
    if (k === 0) {
      return this;
    }
    if (k > PText.MAX_CHARS - this.chars) {
      throw new RangeError(`a text holds at most ${PText.MAX_CHARS} characters, live and deleted`);
    }
    const out: Piece[] = [];
    if (pos === 0) {
      // the document root: a right child while the text is empty, else a left child of the first character
      const first = this.pieces[0];
      out.push(this.fresh(k, text, first === undefined ? null : new CharId(first.replica, first.counter), first !== undefined));
      out.push(...this.pieces);
      return this.edited(out);
    }
    const i = this.visibleIndex(pos - 1);
    const off = pos - 1 - this.visibleBefore(i);
    const p = this.pieces[i]!;
    out.push(...this.pieces.slice(0, i));
    if (off < p.length - 1) {
      // the character before the position has a right child, the next one of its piece
      const rest = tail(p, off + 1);
      out.push(head(p, off + 1), this.fresh(k, text, new CharId(rest.replica, rest.counter), true), rest);
    } else if (!p.lastHasRight && p.replica === this.replica && p.counter + p.length === this.next) {
      // this replica's last character, with no right child: the run goes on
      out.push({ ...p, length: p.length + k, deleted: false, text: p.text + text, lastHasRight: false });
    } else if (!p.lastHasRight) {
      out.push({ ...p, lastHasRight: true }, this.fresh(k, text, new CharId(p.replica, p.counter + p.length - 1), false));
    } else {
      const following = this.pieces[i + 1]!;
      out.push(p, this.fresh(k, text, new CharId(following.replica, following.counter), true));
    }
    out.push(...this.pieces.slice(i + 1));
    return this.edited(out);
  }

  /** The text with `len` live characters deleted from `pos`. */
  delete(pos: number, len: number): PText {
    if (!Number.isSafeInteger(pos) || !Number.isSafeInteger(len) || pos < 0 || len < 0 || pos + len > this.live) {
      throw new RangeError(`range [${pos}, ${pos + len}) of a text of ${this.live}`);
    }
    if (len === 0) {
      return this;
    }
    const out: Piece[] = [];
    let at = 0;
    const end = pos + len;
    for (const p of this.pieces) {
      const from = Math.max(pos, at) - at;
      const to = Math.min(end, at + visible(p)) - at;
      at += visible(p);
      if (p.deleted || from >= to) {
        out.push(p);
        continue;
      }
      let rest = p;
      if (from > 0) {
        out.push(head(rest, from));
        rest = tail(rest, from);
      }
      if (to - from < rest.length) {
        out.push({ ...head(rest, to - from), deleted: true, text: "" }, tail(rest, to - from));
      } else {
        out.push({ ...rest, deleted: true, text: "" });
      }
    }
    return this.edited(out);
  }

  /** The union of two texts (P2-T-03), edited by this text's replica; throws RangeError when they disagree on a character. */
  merge(other: PText): PText {
    return PText.of(this.leaf().union(other.leaf()), this.replica);
  }

  private fresh(k: number, text: string, parent: CharId | null, left: boolean): Piece {
    return { replica: this.replica, counter: this.next, length: k, deleted: false, text, parent, left, lastHasRight: false };
  }

  private edited(out: Piece[]): PText {
    return new PText(this.replica, out, null);
  }

  private visibleIndex(position: number): number {
    let at = 0;
    for (let i = 0; i < this.pieces.length; i++) {
      const v = visible(this.pieces[i]!);
      if (position < at + v) {
        return i;
      }
      at += v;
    }
    throw new RangeError(`position ${position} of a text of ${this.live}`);
  }

  private visibleBefore(index: number): number {
    let at = 0;
    for (let i = 0; i < index; i++) {
      at += visible(this.pieces[i]!);
    }
    return at;
  }
}

/** The codec {@link PText.codec} returns; a ref whose values pass through it writes `PRef.v` 2 heads (§6.10.3, rule 3). */
export class TextCodec implements Codec<PText> {
  constructor(readonly replica: string) {}

  encode(value: PText): Uint8Array {
    return PText.toWire(value.leaf());
  }

  decode(bytes: Uint8Array): PText {
    return PText.of(PText.fromWire(bytes), this.replica);
  }
}
