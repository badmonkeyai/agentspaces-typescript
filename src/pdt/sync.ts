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
 * Store reconciliation (PDT 2 phase 7, P2-C-01, P2-K-01, P2-K-02, P2-K-04, P2-K-05, P2-F-01; srad/agentspaces-pdt2.md
 * §3.6), a port of Java's `tree.sync`: the negentropy v1 protocol byte for byte with 64-bit varints, RIBLT symbols
 * under a SipHash-2-4 session key, the set of CIDs as sketch items (each digest at timestamp 0), the holder's answer
 * to a sketch `TREE_WANT`, and the asker's session.
 *
 * Bounds (P2-K-04, P2-Q-SEC-04): a sketch is at most {@link MAX_SKETCH_BYTES}, a session at most {@link MAX_ROUNDS}
 * rounds, a holder runs at most {@link RIBLT_SESSIONS} RIBLT sessions of {@link MAX_RIBLT_SYMBOLS} symbols, and a RIBLT
 * stream that peels more ids than it has symbols codes no set and is refused. A malformed message throws RangeError
 * naming the fault, which the caller drops and counts.
 */

import { compare } from "../bytes.js";
import { cryptoPort } from "../crypto.js";
import * as cids from "./cids.js";

// ------------------------------------------------------------------ negentropy (P2-K-01)

/** The version byte of protocol v1. */
export const PROTOCOL_VERSION = 0x61;
/** The bytes of an id. */
export const ID_SIZE = 32;
/** The bytes of a fingerprint. */
export const FINGERPRINT_SIZE = 16;
/** The smallest frame size limit other than 0. */
export const MIN_FRAME_SIZE_LIMIT = 4096;
const BUCKETS = 16;
const FRAME_MARGIN = 200;
const MODE_SKIP = 0n, MODE_FINGERPRINT = 1n, MODE_ID_LIST = 2n;
/** The timestamp of the infinite bound, 2^63 - 1. */
const INFINITY = (1n << 63n) - 1n;

/** One element of a set: a timestamp in [0, 2^63 - 1) and a 32-byte id. */
export interface Item { readonly timestamp: bigint; readonly id: Uint8Array }

/** A byte buffer that grows. */
class Out {
  private bytes = new Uint8Array(256);
  length = 0;

  push(b: number): void {
    this.reserve(1);
    this.bytes[this.length++] = b;
  }

  write(data: Uint8Array): void {
    this.reserve(data.length);
    this.bytes.set(data, this.length);
    this.length += data.length;
  }

  private reserve(n: number): void {
    if (this.length + n > this.bytes.length) {
      const grown = new Uint8Array(Math.max(this.bytes.length * 2, this.length + n));
      grown.set(this.bytes.subarray(0, this.length));
      this.bytes = grown;
    }
  }

  result(): Uint8Array {
    return this.bytes.slice(0, this.length);
  }
}

/** Writes a varint: base 128, most significant group first, the top bit set on every byte but the last. */
export function writeVarInt(out: { push(b: number): void }, value: bigint | number): void {
  let v = BigInt(value);
  if (v < 0n) {
    throw new RangeError(`a varint is not negative, got ${v}`);
  }
  const groups: number[] = [];
  do {
    groups.push(Number(v & 0x7fn));
    v >>= 7n;
  } while (v !== 0n);
  for (let i = groups.length - 1; i >= 0; i--) {
    out.push(i === 0 ? groups[i]! : groups[i]! | 0x80);
  }
}

/** A cursor over a message; every fault is a RangeError naming it. */
export class Reader {
  private at = 0;

  constructor(private readonly bytes: Uint8Array) {}

  remaining(): number {
    return this.bytes.length - this.at;
  }

  next(): number {
    if (this.at >= this.bytes.length) {
      throw new RangeError("the message ends prematurely");
    }
    return this.bytes[this.at++]!;
  }

  take(n: number): Uint8Array {
    if (n > this.remaining()) {
      throw new RangeError("the message ends prematurely");
    }
    const out = this.bytes.slice(this.at, this.at + n);
    this.at += n;
    return out;
  }

  varInt(): bigint {
    let value = 0n;
    for (;;) {
      const b = this.next();
      if (value > (INFINITY >> 7n)) {
        throw new RangeError("a varint passes 63 bits");
      }
      value = (value << 7n) | BigInt(b & 0x7f);
      if ((b & 0x80) === 0) {
        return value;
      }
    }
  }
}

/** A sealed, sorted set of items: by timestamp, then by id as unsigned bytes. */
export class Storage {
  private constructor(readonly timestamps: bigint[], readonly ids: Uint8Array, readonly size: number) {}

  /** Seals a set of items in any order; refuses a duplicate. */
  static of(items: Iterable<Item>): Storage {
    const sorted = [...items].sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : compare(a.id, b.id)));
    const ids = new Uint8Array(sorted.length * ID_SIZE);
    sorted.forEach((item, i) => {
      if (item.id.length !== ID_SIZE) {
        throw new RangeError(`an id is ${ID_SIZE} bytes, got ${item.id.length}`);
      }
      if (item.timestamp < 0n || item.timestamp >= INFINITY) {
        throw new RangeError(`a timestamp is in [0, 2^63 - 1), got ${item.timestamp}`);
      }
      if (i > 0 && sorted[i - 1]!.timestamp === item.timestamp && compare(sorted[i - 1]!.id, item.id) === 0) {
        throw new RangeError("duplicate item");
      }
      ids.set(item.id, i * ID_SIZE);
    });
    return new Storage(sorted.map((item) => item.timestamp), ids, sorted.length);
  }

  id(index: number): Uint8Array {
    return this.ids.slice(index * ID_SIZE, (index + 1) * ID_SIZE);
  }

  /** Whether item `index` sorts before a bound: an id that starts with the bound's prefix does not. */
  private before(index: number, bound: Bound): boolean {
    const ts = this.timestamps[index]!;
    if (ts !== bound.timestamp) {
      return ts < bound.timestamp;
    }
    const at = index * ID_SIZE;
    return compare(this.ids.subarray(at, at + bound.prefix.length), bound.prefix) < 0;
  }

  /** The first index in `[begin, end)` whose item does not sort before the bound, else `end`. */
  lowerBound(begin: number, end: number, bound: Bound): number {
    let lo = begin, hi = end;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.before(mid, bound)) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return lo;
  }

  /** The first 16 bytes of sha-256 over the 256-bit little-endian sum of the ids in `[begin, end)` and the varint count. */
  fingerprint(begin: number, end: number): Uint8Array {
    const sum = new Uint8Array(ID_SIZE);
    for (let i = begin; i < end; i++) {
      const at = i * ID_SIZE;
      let carry = 0;
      for (let b = 0; b < ID_SIZE; b++) {
        const s = sum[b]! + this.ids[at + b]! + carry;
        sum[b] = s & 0xff;
        carry = s >> 8;
      }
    }
    const input = new Out();
    input.write(sum);
    writeVarInt(input, end - begin);
    return cryptoPort().sha256(input.result()).slice(0, FINGERPRINT_SIZE);
  }
}

/** A range's upper bound: a timestamp and an id prefix of at most 32 bytes. */
interface Bound { readonly timestamp: bigint; readonly prefix: Uint8Array }

const boundOf = (timestamp: bigint): Bound => ({ timestamp, prefix: new Uint8Array(0) });

/**
 * One side of a negentropy session (Java's Negentropy, the reference implementation's v1 byte for byte). The
 * initiator calls {@link initiate} once and then `reconcile(reply, have, need)` until it returns null; the responder
 * answers each message with `reconcile(query)`. A frame size limit of 0 means none, else at least
 * {@link MIN_FRAME_SIZE_LIMIT}; a message then stops 200 bytes short of it and closes with a fingerprint of the rest.
 */
export class Negentropy {
  private initiator = false;
  private lastTimestampIn = 0n;
  private lastTimestampOut = 0n;

  constructor(private readonly storage: Storage, private readonly frameSizeLimit: number) {
    if (frameSizeLimit !== 0 && frameSizeLimit < MIN_FRAME_SIZE_LIMIT) {
      throw new RangeError(`frameSizeLimit is 0 or at least ${MIN_FRAME_SIZE_LIMIT}, got ${frameSizeLimit}`);
    }
  }

  /** The initiator's first message: the whole set split into ranges. */
  initiate(): Uint8Array {
    if (this.initiator) {
      throw new Error("already initiated");
    }
    this.initiator = true;
    const out = new Out();
    out.push(PROTOCOL_VERSION);
    this.splitRange(0, this.storage.size, boundOf(INFINITY), out);
    return out.result();
  }

  /** The responder's answer to a message, or the initiator's next message (null when done) with `have` and `need`. */
  reconcile(query: Uint8Array): Uint8Array;
  reconcile(reply: Uint8Array, have: Uint8Array[], need: Uint8Array[]): Uint8Array | null;
  reconcile(message: Uint8Array, have?: Uint8Array[], need?: Uint8Array[]): Uint8Array | null {
    if (this.initiator !== (have !== undefined)) {
      throw new Error(this.initiator ? "the initiator reconciles with have and need lists" : "the responder reconciles without lists");
    }
    const out = this.answer(message, have ?? null, need ?? null);
    return this.initiator && out.length === 1 ? null : out;
  }

  private answer(query: Uint8Array, have: Uint8Array[] | null, need: Uint8Array[] | null): Uint8Array {
    const input = new Reader(query);
    this.lastTimestampIn = 0n;
    this.lastTimestampOut = 0n;
    const full = new Out();
    full.push(PROTOCOL_VERSION);
    const version = input.next();
    if (version < 0x60 || version > 0x6f) {
      throw new RangeError(`invalid negentropy protocol version byte 0x${version.toString(16)}`);
    }
    if (version !== PROTOCOL_VERSION) {
      if (this.initiator) {
        throw new RangeError(`unsupported negentropy protocol version ${version - 0x60}`);
      }
      return full.result();
    }
    const size = this.storage.size;
    let prevBound = boundOf(0n);
    let prevIndex = 0;
    let skip = false;
    while (input.remaining() > 0) {
      const o = new Out();
      const currBound = this.decodeBound(input);
      const mode = input.varInt();
      const lower = prevIndex;
      let upper = this.storage.lowerBound(prevIndex, size, currBound);
      if (mode === MODE_SKIP) {
        skip = true;
      } else if (mode === MODE_FINGERPRINT) {
        const theirs = input.take(FINGERPRINT_SIZE);
        if (compare(theirs, this.storage.fingerprint(lower, upper)) !== 0) {
          if (skip) {
            skip = false;
            this.encodeBound(prevBound, o);
            writeVarInt(o, MODE_SKIP);
          }
          this.splitRange(lower, upper, currBound, o);
        } else {
          skip = true;
        }
      } else if (mode === MODE_ID_LIST) {
        const count = input.varInt();
        if (count > BigInt(Math.floor(input.remaining() / ID_SIZE))) {
          throw new RangeError(`an id list of ${count} ids runs past the message`);
        }
        const theirs = new Map<string, Uint8Array>();
        for (let i = 0n; i < count; i++) {
          const id = input.take(ID_SIZE);
          if (this.initiator) {
            theirs.set(hex(id), id);
          }
        }
        if (this.initiator) {
          skip = true;
          for (let i = lower; i < upper; i++) {
            const id = this.storage.id(i);
            if (!theirs.delete(hex(id))) {
              have!.push(id);
            }
          }
          need!.push(...theirs.values());
        } else {
          if (skip) {
            skip = false;
            this.encodeBound(prevBound, o);
            writeVarInt(o, MODE_SKIP);
          }
          const ids = new Out();
          let listed = 0;
          let endBound = currBound;
          for (let i = lower; i < upper; i++) {
            if (this.exceeded(full.length + ids.length)) {
              endBound = { timestamp: this.storage.timestamps[i]!, prefix: this.storage.id(i) };
              upper = i; // the rest of the range goes into the closing fingerprint
              break;
            }
            ids.write(this.storage.id(i));
            listed += 1;
          }
          this.encodeBound(endBound, o);
          writeVarInt(o, MODE_ID_LIST);
          writeVarInt(o, listed);
          o.write(ids.result());
          full.write(o.result());
          o.length = 0;
        }
      } else {
        throw new RangeError(`unexpected mode ${mode}`);
      }
      if (this.exceeded(full.length + o.length)) {
        const rest = this.storage.fingerprint(upper, size);
        this.encodeBound(boundOf(INFINITY), full);
        writeVarInt(full, MODE_FINGERPRINT);
        full.write(rest);
        break;
      }
      full.write(o.result());
      prevIndex = upper;
      prevBound = currBound;
    }
    return full.result();
  }

  private splitRange(lower: number, upper: number, upperBound: Bound, o: Out): void {
    const count = upper - lower;
    if (count < BUCKETS * 2) {
      this.encodeBound(upperBound, o);
      writeVarInt(o, MODE_ID_LIST);
      writeVarInt(o, count);
      for (let i = lower; i < upper; i++) {
        o.write(this.storage.id(i));
      }
      return;
    }
    const perBucket = Math.floor(count / BUCKETS);
    const withExtra = count % BUCKETS;
    let curr = lower;
    for (let bucket = 0; bucket < BUCKETS; bucket++) {
      const bucketSize = perBucket + (bucket < withExtra ? 1 : 0);
      const fingerprint = this.storage.fingerprint(curr, curr + bucketSize);
      curr += bucketSize;
      this.encodeBound(curr === upper ? upperBound : this.minimalBound(curr - 1, curr), o);
      writeVarInt(o, MODE_FINGERPRINT);
      o.write(fingerprint);
    }
  }

  /** The shortest bound that separates item `prev` from item `curr`. */
  private minimalBound(prev: number, curr: number): Bound {
    const ts = this.storage.timestamps;
    if (ts[curr] !== ts[prev]) {
      return boundOf(ts[curr]!);
    }
    const ids = this.storage.ids;
    let shared = 0;
    while (shared < ID_SIZE && ids[prev * ID_SIZE + shared] === ids[curr * ID_SIZE + shared]) {
      shared += 1;
    }
    return { timestamp: ts[curr]!, prefix: ids.slice(curr * ID_SIZE, curr * ID_SIZE + shared + 1) };
  }

  private exceeded(bytes: number): boolean {
    return this.frameSizeLimit !== 0 && bytes > this.frameSizeLimit - FRAME_MARGIN;
  }

  private decodeBound(input: Reader): Bound {
    const timestamp = this.decodeTimestamp(input);
    const length = input.varInt();
    if (length > BigInt(ID_SIZE)) {
      throw new RangeError(`bound key too long: ${length} bytes`);
    }
    return { timestamp, prefix: input.take(Number(length)) };
  }

  private decodeTimestamp(input: Reader): bigint {
    const coded = input.varInt();
    let timestamp = coded === 0n ? INFINITY : coded - 1n;
    if (this.lastTimestampIn === INFINITY || timestamp === INFINITY) {
      this.lastTimestampIn = INFINITY;
      return INFINITY;
    }
    if (timestamp >= INFINITY - this.lastTimestampIn) {
      throw new RangeError("a bound's timestamp passes 2^63 - 1");
    }
    timestamp += this.lastTimestampIn;
    this.lastTimestampIn = timestamp;
    return timestamp;
  }

  private encodeBound(bound: Bound, out: Out): void {
    if (bound.timestamp === INFINITY) {
      this.lastTimestampOut = INFINITY;
      writeVarInt(out, 0);
    } else {
      const offset = bound.timestamp - this.lastTimestampOut;
      this.lastTimestampOut = bound.timestamp;
      writeVarInt(out, offset + 1n);
    }
    writeVarInt(out, bound.prefix.length);
    out.write(bound.prefix);
  }
}

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

// ------------------------------------------------------------------ RIBLT (P2-K-05)

const MASK64 = (1n << 64n) - 1n;
const MULTIPLIER = 0xda942042e4dd58b5n;
/** An index past this ends a mapping. */
const LAST_INDEX = 2 ** 62;

const rotl = (x: bigint, b: bigint): bigint => ((x << b) | (x >> (64n - b))) & MASK64;

function littleEndian(bytes: Uint8Array, at: number, n: number): bigint {
  let value = 0n;
  for (let b = n - 1; b >= 0; b--) {
    value = (value << 8n) | BigInt(bytes[at + b]!);
  }
  return value;
}

/** One coded symbol as it travels: the XOR of the ids mapped to it, the XOR of their checksums, and their count. */
export interface Symbol { readonly sum: Uint8Array; readonly checksum: bigint; readonly count: number }

/** The indexes one id maps to, in order, with the sign it carries in a decoder. */
class Mapping {
  state: bigint;
  index = 0;

  constructor(readonly id: Uint8Array, readonly checksum: bigint, readonly sign: number) {
    this.state = checksum;
  }

  advance(): void {
    this.state = (this.state * MULTIPLIER) & MASK64;
    const x = Number(this.state >> 11n) * 2048;
    const step = Math.max(1, Math.ceil((this.index + 1.5) * (2 ** 32 / Math.sqrt(x + 1) - 1)));
    const next = this.index + step;
    this.index = next >= LAST_INDEX ? Number.POSITIVE_INFINITY : Math.trunc(next);
  }
}

/** A binary heap of mappings by their next index. */
class Heap {
  private readonly items: Mapping[] = [];

  get size(): number {
    return this.items.length;
  }

  peek(): Mapping | undefined {
    return this.items[0];
  }

  push(m: Mapping): void {
    const a = this.items;
    a.push(m);
    for (let i = a.length - 1; i > 0;) {
      const parent = (i - 1) >> 1;
      if (a[parent]!.index <= a[i]!.index) {
        break;
      }
      [a[parent], a[i]] = [a[i]!, a[parent]!];
      i = parent;
    }
  }

  pop(): Mapping {
    const a = this.items;
    const top = a[0]!;
    const last = a.pop()!;
    if (a.length > 0) {
      a[0] = last;
      for (let i = 0; ;) {
        const l = 2 * i + 1, r = l + 1;
        let least = i;
        if (l < a.length && a[l]!.index < a[least]!.index) {
          least = l;
        }
        if (r < a.length && a[r]!.index < a[least]!.index) {
          least = r;
        }
        if (least === i) {
          break;
        }
        [a[least], a[i]] = [a[i]!, a[least]!];
        i = least;
      }
    }
    return top;
  }
}

/** A symbol a decoder works on: the remote symbol less the local one, so its count may be negative. */
class Cell {
  readonly sum = new Uint8Array(ID_SIZE);
  checksum = 0n;
  count = 0;

  xor(id: Uint8Array, checksum: bigint, delta: number): void {
    for (let i = 0; i < ID_SIZE; i++) {
      this.sum[i]! ^= id[i]!;
    }
    this.checksum ^= checksum;
    this.count += delta;
  }

  empty(): boolean {
    return this.count === 0 && this.checksum === 0n && this.sum.every((b) => b === 0);
  }
}

function checkedKey(key: Uint8Array): Uint8Array {
  if (key.length !== Riblt.KEY_BYTES) {
    throw new RangeError(`a session key is ${Riblt.KEY_BYTES} bytes, got ${key.length}`);
  }
  return key.slice();
}

/** Produces the coded symbols of a set, index after index. */
class Encoder {
  private readonly queue = new Heap();
  produced = 0;

  constructor(key: Uint8Array, ids: Iterable<Uint8Array>) {
    const k = checkedKey(key);
    for (const id of ids) {
      if (id.length !== ID_SIZE) {
        throw new RangeError(`an id is ${ID_SIZE} bytes, got ${id.length}`);
      }
      this.queue.push(new Mapping(id, Riblt.sipHash24(k, id), 1));
    }
  }

  next(count: number): Symbol[] {
    const out: Symbol[] = [];
    for (let n = 0; n < count; n++) {
      const cell = new Cell();
      const at = this.produced++;
      while (this.queue.size > 0 && this.queue.peek()!.index === at) {
        const m = this.queue.pop();
        cell.xor(m.id, m.checksum, 1);
        m.advance();
        if (m.index !== Number.POSITIVE_INFINITY) {
          this.queue.push(m);
        }
      }
      out.push({ sum: cell.sum, checksum: cell.checksum, count: cell.count });
    }
    return out;
  }
}

/** Subtracts the local set's symbols from a remote stream and peels the difference out. */
class Decoder {
  private readonly key: Uint8Array;
  private readonly local: Encoder;
  private readonly cells: Cell[] = [];
  private readonly recovered = new Heap();
  private readonly remote: Uint8Array[] = [];
  private readonly mine: Uint8Array[] = [];

  constructor(key: Uint8Array, ids: Iterable<Uint8Array>) {
    this.key = checkedKey(key);
    this.local = new Encoder(this.key, ids);
  }

  /**
   * Adds the next remote symbol and peels what it frees. Throws RangeError when the stream peels more ids than it has
   * symbols, which no coding of a set does (PDT 2 phase 5 adversary, P2-Q-SEC-04); the decoder is then unusable.
   */
  add(remote: Symbol): void {
    const mine = this.local.next(1)[0]!;
    const cell = new Cell();
    cell.xor(remote.sum, remote.checksum, remote.count);
    cell.xor(mine.sum, mine.checksum, -mine.count);
    const at = this.cells.length;
    while (this.recovered.size > 0 && this.recovered.peek()!.index === at) {
      const m = this.recovered.pop();
      cell.xor(m.id, m.checksum, -m.sign);
      m.advance();
      if (m.index !== Number.POSITIVE_INFINITY) {
        this.recovered.push(m);
      }
    }
    this.cells.push(cell);
    this.peel(at);
  }

  private peel(start: number): void {
    const pending = [start];
    while (pending.length > 0) {
      const cell = this.cells[pending.pop()!]!;
      if ((cell.count !== 1 && cell.count !== -1) || Riblt.sipHash24(this.key, cell.sum) !== cell.checksum) {
        continue;
      }
      if (this.remote.length + this.mine.length >= this.cells.length) {
        throw new RangeError(`the stream peels more ids than its ${this.cells.length} symbols`);
      }
      const m = new Mapping(cell.sum.slice(), cell.checksum, cell.count);
      (m.sign === 1 ? this.remote : this.mine).push(m.id);
      while (m.index < this.cells.length) {
        this.cells[m.index]!.xor(m.id, m.checksum, -m.sign);
        pending.push(m.index);
        m.advance();
      }
      if (m.index !== Number.POSITIVE_INFINITY) {
        this.recovered.push(m);
      }
    }
  }

  /** Whether the difference is decoded: symbol 0, which every id maps to, is empty. */
  decoded(): boolean {
    return this.cells.length > 0 && this.cells[0]!.empty();
  }

  symbols(): number {
    return this.cells.length;
  }

  /** The ids the remote side holds and this side lacks, decoded so far. */
  remoteOnly(): Uint8Array[] {
    return [...this.remote];
  }

  /** The ids this side holds and the remote side lacks, decoded so far. */
  localOnly(): Uint8Array[] {
    return [...this.mine];
  }
}

/**
 * Rateless invertible Bloom lookup tables (Java's Riblt): an id maps to symbol 0 and then to the indexes a generator
 * seeded by its SipHash-2-4 checksum draws with the density of α = 0.5; every port computes the same doubles.
 */
export const Riblt = {
  /** The leading byte of a RIBLT sketch (P2-F-01). */
  ENCODING: 0x62,
  KEY_BYTES: 16,
  /** Reply statuses: send more symbols; decoded, the two lists follow; the difference does not fit. */
  MORE: 0,
  DECODED: 1,
  TOO_MANY: 2,
  Encoder,
  Decoder,

  /** SipHash-2-4 of a message under a 16-byte key, as an unsigned 64-bit value. */
  sipHash24(key: Uint8Array, message: Uint8Array): bigint {
    const k0 = littleEndian(key, 0, 8), k1 = littleEndian(key, 8, 8);
    const v = [k0 ^ 0x736f6d6570736575n, k1 ^ 0x646f72616e646f6dn, k0 ^ 0x6c7967656e657261n, k1 ^ 0x7465646279746573n];
    const round = (): void => {
      v[0] = (v[0]! + v[1]!) & MASK64; v[1] = rotl(v[1]!, 13n) ^ v[0]; v[0] = rotl(v[0], 32n);
      v[2] = (v[2]! + v[3]!) & MASK64; v[3] = rotl(v[3]!, 16n) ^ v[2];
      v[0] = (v[0] + v[3]) & MASK64; v[3] = rotl(v[3], 21n) ^ v[0];
      v[2] = (v[2] + v[1]) & MASK64; v[1] = rotl(v[1], 17n) ^ v[2]; v[2] = rotl(v[2], 32n);
    };
    const whole = message.length - (message.length % 8);
    for (let at = 0; at < whole; at += 8) {
      const m = littleEndian(message, at, 8);
      v[3]! ^= m;
      round();
      round();
      v[0]! ^= m;
    }
    const last = ((BigInt(message.length) << 56n) | littleEndian(message, whole, message.length - whole)) & MASK64;
    v[3]! ^= last;
    round();
    round();
    v[0]! ^= last;
    v[2]! ^= 0xffn;
    for (let i = 0; i < 4; i++) {
      round();
    }
    return (v[0]! ^ v[1]! ^ v[2]! ^ v[3]!) & MASK64;
  },

  /** The wire form of symbols: the sum, the checksum as 8 little-endian bytes, and the count as a negentropy varint. */
  writeSymbols(symbols: Iterable<Symbol>): Uint8Array {
    const out = new Out();
    for (const s of symbols) {
      writeSymbol(out, s);
    }
    return out.result();
  },

  readSymbol(input: Reader): Symbol {
    const sum = input.take(ID_SIZE);
    let checksum = 0n;
    for (let b = 0; b < 8; b++) {
      checksum |= BigInt(input.next()) << BigInt(8 * b);
    }
    const count = input.varInt();
    if (count > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new RangeError("a symbol count passes 2^53 - 1");
    }
    return { sum, checksum, count: Number(count) };
  },
};

function writeSymbol(out: Out, s: Symbol): void {
  out.write(s.sum);
  for (let b = 0; b < 8; b++) {
    out.push(Number((s.checksum >> BigInt(8 * b)) & 0xffn));
  }
  writeVarInt(out, s.count);
}

// ------------------------------------------------------------------ the set (P2-K-02)

/**
 * A set of CIDs as sketch items (Java's SketchSet): the id of a CID is its 32-byte digest and every item stands at
 * timestamp 0, so one root is one item everywhere whatever its holding says; a raw and a dag-cbor CID of one digest
 * are one item, and a text that is no canonical CID is left out.
 */
export class SketchSet {
  private constructor(private readonly byDigest: Map<string, string>, readonly ids: Uint8Array[], readonly storage: Storage) {}

  static of(list: Iterable<string>): SketchSet {
    const byDigest = new Map<string, string>();
    const ids: Uint8Array[] = [];
    for (const cid of list) {
      if (!cids.isCid(cid)) {
        continue;
      }
      const digest = cids.parse(cid).digest;
      const key = hex(digest);
      if (!byDigest.has(key)) {
        byDigest.set(key, cid);
        ids.push(digest);
      }
    }
    return new SketchSet(byDigest, ids, Storage.of(ids.map((id) => ({ timestamp: 0n, id }))));
  }

  get size(): number {
    return this.ids.length;
  }

  /** The CID this set holds for an id, or null. */
  cid(id: Uint8Array): string | null {
    return this.byDigest.get(hex(id)) ?? null;
  }
}

// ------------------------------------------------------------------ the holder (P2-K-02, P2-K-04)

/** The largest sketch one message carries (P2-K-04). */
export const MAX_SKETCH_BYTES = 64 * 1024;
/** The rounds one session takes at most (P2-K-04). */
export const MAX_ROUNDS = 64;
/** The symbols one RIBLT session streams at most. */
export const MAX_RIBLT_SYMBOLS = 16_384;
/** RIBLT sessions a holder runs at once, and how long one may idle. */
export const RIBLT_SESSIONS = 4;
export const RIBLT_IDLE_MILLIS = 30_000;
const SET_CACHE_MILLIS = 10_000;
const SESSIONS_COUNTED = 1024;
const REASON_OVER_BUDGET = 2;

/** What a holder does with one sketch: answer it, refuse it with a `REJECT` reason, or drop and count it. */
export type Answer = { kind: "reply"; sketch: Uint8Array } | { kind: "refusal"; reason: number; why: string }
  | { kind: "dropped"; why: string };

/**
 * The holder's side of a reconciliation (Java's SketchServer): it answers a sketch with a reply over the set its
 * source gives, chosen by the leading byte (negentropy's version bytes, or {@link Riblt.ENCODING}); a sketch past
 * {@link MAX_SKETCH_BYTES} or of another encoding is dropped by name; one asker's session, named by its request id,
 * takes at most {@link MAX_ROUNDS} rounds and is then refused with reason 2.
 */
export class SketchServer {
  private cached: { at: number; set: SketchSet } | null = null;
  private readonly rounds = new Map<string, number>();
  private readonly riblt = new Map<string, { decoder: Decoder; used: number }>();

  constructor(private readonly source: () => Iterable<string>, private readonly clock: () => number) {}

  private set(now: number): SketchSet {
    if (this.cached === null || now - this.cached.at >= SET_CACHE_MILLIS) {
      this.cached = { at: now, set: SketchSet.of(this.source()) };
    }
    return this.cached.set;
  }

  answer(from: string, req: number, sketch: Uint8Array, budget: number): Answer {
    if (sketch.length === 0) {
      return { kind: "dropped", why: "an empty sketch" };
    }
    if (sketch.length > MAX_SKETCH_BYTES) {
      return { kind: "dropped", why: `a sketch of ${sketch.length} bytes passes ${MAX_SKETCH_BYTES}` };
    }
    const encoding = sketch[0]!;
    const negentropy = encoding >= 0x60 && encoding <= 0x6f && encoding !== Riblt.ENCODING;
    if (!negentropy && encoding !== Riblt.ENCODING) {
      return { kind: "dropped", why: `unknown sketch encoding 0x${encoding.toString(16)}` };
    }
    const round = `${from}|${req}`;
    const taken = this.rounds.get(round) ?? 0;
    if (taken >= MAX_ROUNDS) {
      return { kind: "refusal", reason: REASON_OVER_BUDGET, why: `a session takes at most ${MAX_ROUNDS} rounds` };
    }
    this.rounds.delete(round);
    this.rounds.set(round, taken + 1);
    if (this.rounds.size > SESSIONS_COUNTED) {
      this.rounds.delete(this.rounds.keys().next().value!);
    }
    const limit = Math.max(MIN_FRAME_SIZE_LIMIT, Math.min(budget, MAX_SKETCH_BYTES));
    const now = this.clock();
    try {
      if (negentropy) {
        return { kind: "reply", sketch: new Negentropy(this.set(now).storage, limit).reconcile(sketch) };
      }
      return this.ribltAnswer(from, sketch, limit, now);
    } catch (e) {
      return { kind: "dropped", why: e instanceof Error ? e.message : String(e) };
    }
  }

  private ribltAnswer(from: string, sketch: Uint8Array, limit: number, now: number): Answer {
    const input = new Reader(sketch);
    input.next();
    const key = input.take(Riblt.KEY_BYTES);
    const start = input.varInt();
    const count = input.varInt();
    if (count > BigInt(Math.floor(input.remaining() / (ID_SIZE + 9)))) {
      throw new RangeError(`${count} symbols run past the sketch`);
    }
    const symbols: Symbol[] = [];
    for (let i = 0n; i < count; i++) {
      symbols.push(Riblt.readSymbol(input));
    }
    if (input.remaining() !== 0) {
      throw new RangeError(`${input.remaining()} bytes trail the symbols`);
    }
    const name = `${from}|${hex(key)}`;
    for (const [n, s] of this.riblt) {
      if (now - s.used > RIBLT_IDLE_MILLIS) {
        this.riblt.delete(n);
      }
    }
    let session = this.riblt.get(name);
    if (session === undefined) {
      if (start !== 0n) {
        return { kind: "dropped", why: `a RIBLT stream starts at index 0, got index ${start}` };
      }
      if (this.riblt.size >= RIBLT_SESSIONS) {
        return { kind: "refusal", reason: REASON_OVER_BUDGET, why: `this holder runs ${RIBLT_SESSIONS} RIBLT sessions already` };
      }
      session = { decoder: new Decoder(key, this.set(now).ids), used: now };
      this.riblt.set(name, session);
    }
    session.used = now;
    if (start !== BigInt(session.decoder.symbols())) {
      return { kind: "dropped", why: `the next RIBLT symbol is index ${session.decoder.symbols()}, got index ${start}` };
    }
    try {
      for (const symbol of symbols) {
        session.decoder.add(symbol);
      }
    } catch (forged) {
      this.riblt.delete(name); // a decoder that peeled a forged stream holds nothing usable
      return { kind: "dropped", why: forged instanceof Error ? forged.message : String(forged) };
    }
    const out = new Out();
    out.push(Riblt.ENCODING);
    if (!session.decoder.decoded()) {
      if (session.decoder.symbols() <= MAX_RIBLT_SYMBOLS) {
        out.push(Riblt.MORE);
        return { kind: "reply", sketch: out.result() };
      }
      out.push(Riblt.TOO_MANY);
    } else {
      const askerOnly = session.decoder.remoteOnly(), holderOnly = session.decoder.localOnly();
      if (3 + 20 + (askerOnly.length + holderOnly.length) * ID_SIZE > limit) {
        out.push(Riblt.TOO_MANY);
      } else {
        out.push(Riblt.DECODED);
        writeVarInt(out, askerOnly.length);
        askerOnly.forEach((id) => out.write(id));
        writeVarInt(out, holderOnly.length);
        holderOnly.forEach((id) => out.write(id));
      }
    }
    this.riblt.delete(name);
    return { kind: "reply", sketch: out.result() };
  }
}

// ------------------------------------------------------------------ the asker (P2-K-02, P2-K-03)

/** The outcome of a session: CIDs this member holds and the holder lacks, and CIDs the holder holds and it lacks. */
export interface Outcome {
  readonly have: string[];
  /** Each the dag-cbor CID of a digest that came back, since a sketch carries digests only. */
  readonly need: string[];
  readonly rounds: number;
  readonly bytesSent: number;
  readonly bytesReceived: number;
  /** `negentropy`, `riblt`, or `riblt,negentropy` after a fallback. */
  readonly encoding: string;
  /** Rounds sent again after their answer was late past the round's timer (swarm retries, ROBUSTNESS.md §10.2). */
  readonly retries: number;
}

/** What a session needs from the exchange. */
export interface Fabric {
  nowMillis(): number;
  /** A fresh request id. */
  nextReq(): number;
  /** Sends a sketch want to the holder; returns the bytes it took. */
  send(to: string, req: number, sketch: Uint8Array): number;
}

/** The RIBLT symbols one query carries at most, so it stays within {@link MAX_SKETCH_BYTES}. */
export const SYMBOLS_PER_QUERY = Math.floor((MAX_SKETCH_BYTES - 64) / (ID_SIZE + 8 + 10));
const MIN_SYMBOL_CAP = 64;
/** The floor of a round's timer, and how many times a session starts again after a round whose answer never came. */
export const ROUND_TIMEOUT_MILLIS = 10_000;
export const ROUND_RETRIES = 3;
const RETRY_BASE_MILLIS = 1000;

/**
 * The asker's side of a reconciliation (Java's SketchSession): every round a sketch `TREE_WANT` under one request id,
 * every answer a `TREE_END` of reason 5. With an expected difference of 0 it runs negentropy; with `d` it streams RIBLT
 * symbols under a fresh random key and falls back to negentropy on {@link Riblt.TOO_MANY} or at its symbol cap.
 *
 * Lateness is normal (swarm retries, ROBUSTNESS.md §10.2): a round's timer is the larger of
 * {@link ROUND_TIMEOUT_MILLIS} and eight observed round trips; when it fires the session starts again by negentropy
 * under a new request id after a backoff of 1, 2, 4 s with a random spread, so an answer to the lost round can never
 * be read as the answer to a later one, and it fails after {@link ROUND_RETRIES} such starts, on a refusal, after
 * {@link MAX_ROUNDS} rounds, or on an answer outside its grammar.
 */
export class SketchSession {
  readonly outcome: Promise<Outcome>;
  private resolve!: (o: Outcome) => void;
  private reject!: (e: Error) => void;
  private done = false;
  req: number;
  private have: Uint8Array[] = [];
  private need: Uint8Array[] = [];
  private negentropy: Negentropy | null = null;
  private encoder: Encoder | null = null;
  private key: Uint8Array | null = null;
  private encoding: string | null = null;
  private rounds = 0;
  private retries = 0;
  private bytesSent = 0;
  private bytesReceived = 0;
  private sentAt = 0;
  private srtt = -1;
  private resumeAt: number | null = null;

  constructor(readonly holder: string, private readonly set: SketchSet, private readonly expected: number,
              private readonly fabric: Fabric, private readonly random: () => number = Math.random) {
    if (expected < 0) {
      throw new RangeError("the expected difference is at least 0");
    }
    this.req = fabric.nextReq();
    this.outcome = new Promise((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
  }

  /** The RIBLT symbols this session streams before it falls back to negentropy. */
  symbolCap(): number {
    return Math.min(MAX_RIBLT_SYMBOLS, Math.max(MIN_SYMBOL_CAP, 2 * this.expected));
  }

  start(): void {
    if (this.expected > 0) {
      this.encoding = "riblt";
      this.key = cryptoPort().randomBytes(Riblt.KEY_BYTES);
      this.encoder = new Encoder(this.key, this.set.ids);
      this.sendSymbols(Math.min(this.symbolCap(), Math.ceil(this.expected * 1.4)));
    } else {
      this.startNegentropy();
    }
  }

  private startNegentropy(): void {
    this.encoding = this.encoding === null ? "negentropy" : this.encoding.endsWith("negentropy") ? this.encoding
      : `${this.encoding},negentropy`;
    this.encoder = null;
    this.have = [];
    this.need = [];
    this.negentropy = new Negentropy(this.set.storage, MAX_SKETCH_BYTES);
    this.send(this.negentropy.initiate());
  }

  private sendSymbols(count: number): void {
    const n = Math.min(Math.max(count, 1), SYMBOLS_PER_QUERY);
    const out = new Out();
    out.push(Riblt.ENCODING);
    out.write(this.key!);
    writeVarInt(out, this.encoder!.produced);
    writeVarInt(out, n);
    for (const s of this.encoder!.next(n)) {
      writeSymbol(out, s);
    }
    this.send(out.result());
  }

  private send(sketch: Uint8Array): void {
    if (this.rounds >= MAX_ROUNDS) {
      this.fail(`no agreement within ${MAX_ROUNDS} rounds`);
      return;
    }
    this.rounds += 1;
    this.sentAt = this.fabric.nowMillis();
    this.bytesSent += this.fabric.send(this.holder, this.req, sketch);
  }

  /** Takes a `TREE_END` of reason 5; returns whether it belongs to this session. */
  onEnd(from: string, req: number, reply: Uint8Array, bytes: number): boolean {
    if (from !== this.holder || req !== this.req || this.done || this.resumeAt !== null) {
      return false;
    }
    const rtt = this.fabric.nowMillis() - this.sentAt;
    this.srtt = this.srtt < 0 ? rtt : (this.srtt * 7 + rtt) / 8;
    this.bytesReceived += bytes;
    if (reply.length === 0) {
      this.fail("an empty answer");
      return true;
    }
    try {
      if (this.encoder !== null) {
        this.onRiblt(reply);
      } else {
        this.onNegentropy(reply);
      }
    } catch (e) {
      this.fail(`an answer outside its grammar: ${e instanceof Error ? e.message : String(e)}`);
    }
    return true;
  }

  private onNegentropy(reply: Uint8Array): void {
    if (reply[0] !== PROTOCOL_VERSION) {
      throw new RangeError(`a negentropy round answered with 0x${reply[0]!.toString(16)}`);
    }
    const next = this.negentropy!.reconcile(reply, this.have, this.need);
    if (next !== null) {
      this.send(next);
    } else {
      this.complete();
    }
  }

  private onRiblt(reply: Uint8Array): void {
    const input = new Reader(reply);
    if (input.next() !== Riblt.ENCODING) {
      throw new RangeError("a RIBLT round answered with another encoding");
    }
    const status = input.next();
    if (status === Riblt.MORE) {
      if (this.encoder!.produced >= this.symbolCap()) {
        this.startNegentropy();
      } else {
        this.sendSymbols(Math.min(this.symbolCap() - this.encoder!.produced, Math.max(8, Math.floor(this.expected / 4))));
      }
    } else if (status === Riblt.TOO_MANY) {
      this.startNegentropy();
    } else if (status === Riblt.DECODED) {
      readIds(input, this.have);
      readIds(input, this.need);
      if (input.remaining() !== 0) {
        throw new RangeError(`${input.remaining()} bytes trail the lists`);
      }
      this.complete();
    } else {
      throw new RangeError(`unknown RIBLT status ${status}`);
    }
  }

  /** Takes a tree `REJECT` for the root `""`: the holder does not reconcile (reason 3) or ended the session (2). */
  onReject(from: string, reason: number): boolean {
    if (from !== this.holder || this.done) {
      return false;
    }
    this.fail(`${from.slice(0, 10)} refused the round with REJECT reason ${reason}`);
    return true;
  }

  /** Starts again when a round's answer is late past its timer, after a backoff; fails after the last retry. */
  tick(now: number): void {
    if (this.done) {
      return;
    }
    if (this.resumeAt !== null) {
      if (now >= this.resumeAt) {
        this.resumeAt = null;
        this.req = this.fabric.nextReq();
        this.rounds = 0;
        this.startNegentropy();
      }
      return;
    }
    const timer = Math.max(ROUND_TIMEOUT_MILLIS, this.srtt > 0 ? 8 * this.srtt : 0);
    if (now - this.sentAt <= timer) {
      return;
    }
    if (this.retries >= ROUND_RETRIES) {
      this.fail(`no answer within ${timer} ms, ${ROUND_RETRIES} times`);
      return;
    }
    this.retries += 1;
    const wait = RETRY_BASE_MILLIS * 2 ** (this.retries - 1);
    this.resumeAt = now + wait + this.random() * wait / 2;
  }

  private complete(): void {
    const have: string[] = [];
    for (const id of this.have) {
      const cid = this.set.cid(id);
      if (cid === null) {
        this.fail("the holder named a have id this member does not hold");
        return;
      }
      have.push(cid);
    }
    const need = this.need.map((id) => cids.ofDigest(id, cids.DAG_CBOR));
    this.done = true;
    this.resolve({ have: [...new Set(have)], need: [...new Set(need)], rounds: this.rounds, bytesSent: this.bytesSent,
      bytesReceived: this.bytesReceived, encoding: this.encoding!, retries: this.retries });
  }

  private fail(why: string): void {
    if (!this.done) {
      this.done = true;
      this.reject(new Error(`reconciling with ${this.holder.slice(0, 10)}: ${why}`));
    }
  }

  get finished(): boolean {
    return this.done;
  }
}

function readIds(input: Reader, into: Uint8Array[]): void {
  const count = input.varInt();
  if (count > BigInt(Math.floor(input.remaining() / ID_SIZE))) {
    throw new RangeError(`${count} ids run past the answer`);
  }
  for (let i = 0n; i < count; i++) {
    into.push(input.take(ID_SIZE));
  }
}
