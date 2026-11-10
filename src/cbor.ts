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
 * CBOR (RFC 8949) codec for the AgentSpaces wire encoding (HLC round six, 2026-11-08, owner rulings
 * F2 and F3): the image of Java's CborCodec encoder, so every value has exactly one encoding and a
 * receiver can refuse any document that is not that encoding. The rules (S1 to S12):
 * <ul>
 *   <li>A document holds exactly one item, nested at most 64 containers deep (the two-element array
 *       inside a decimal counts as one, as Jackson counts it).</li>
 *   <li>Every head is in its shortest form. An integer a Java long holds is a plain integer; one
 *       outside is a tag 2 or 3 bignum over the magnitude's BigInteger.toByteArray bytes.</li>
 *   <li>A decimal is tag 4 over [exponent, mantissa], normalized: no trailing decimal zero in the
 *       mantissa, zero as [0, 0], the exponent within -(2^31-1) to 2^31-1.</li>
 *   <li>A float is a float64 (0xFB) or a float32 (0xFA), and a NaN is only the one Java's
 *       constants hold. The decoder refuses a half float.</li>
 *   <li>A text of up to 3996 UTF-16 units is one definite string; a longer one is indefinite in
 *       Jackson's exact chunks. Every text is well-formed UTF-8.</li>
 *   <li>Byte strings and arrays are definite; maps are indefinite (0xBF..0xFF) with unique text
 *       keys. Only false, true and null stand as simple values. No other tag appears.</li>
 * </ul>
 *
 * <p>Values. A {@code number} encodes as an integer when it is a safe integer and as a float64
 * otherwise; {@link CborDouble} keeps an integral double a double and {@link CborFloat32} keeps a
 * float32. An integer past the safe range decodes as a {@code bigint}, a bignum as a {@code bigint},
 * and a decimal as an exact {@link CborDecimal}, so every value an application receives re-encodes
 * to the identical bytes (F2). A map decodes as a plain object that remembers the order its keys
 * arrived in, and re-encodes in that order, since a JS object would otherwise put integer-like keys
 * first; {@link canonicalMap} marks a map whose keys the encoder sorts (wire v3, ISSUE-CanonicalMaps).
 */

import { compare, concat, fromHex, toHex, utf8 } from "./bytes.js";

/**
 * Strict UTF-8 for CBOR text (HLC round four, 2026-11-08, D3): an overlong sequence, a surrogate
 * encoded in UTF-8, or any other invalid byte throws, and a leading byte order mark stays in the
 * text. Every text then has exactly one spelling.
 */
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function strictText(data: Uint8Array, start: number, end: number): string {
  try {
    return STRICT_UTF8.decode(data.subarray(start, end));
  } catch {
    throw new RangeError(`CBOR text at offset ${start} is not valid shortest-form UTF-8`);
  }
}

/**
 * The most UTF-16 units Jackson's CBORGenerator writes as one definite text string
 * (MAX_LONG_STRING_CHARS); it writes a longer string as an indefinite-length string of chunks of
 * at most this many units each (HLC round five, 2026-11-08, E8).
 */
const JACKSON_CHUNK_UNITS = 3996;

/** Wraps a number that must encode as a CBOR float64 (e.g. an AUCTION bid). */
export class CborDouble {
  constructor(readonly value: number) {}
}

/**
 * A float32, the item Java writes for a {@code float}: it encodes as 0xFA and decodes back as itself,
 * so a value Java wrote as a float re-encodes to its own bytes (HLC round six, 2026-11-08, F2). The
 * value is rounded to the nearest float32.
 */
export class CborFloat32 extends CborDouble {
  constructor(value: number) {
    super(Math.fround(value));
  }
}

/** A decimal's exponent bound: a Java BigDecimal's scale, negated, without the wrap of -2^31. */
const EXPONENT_LIMIT = 2 ** 31 - 1;

/**
 * A decimal fraction, CBOR tag 4 over [exponent, mantissa], worth mantissa * 10^exponent: the item
 * Java writes for a BigDecimal (HLC round six, 2026-11-08, F2). It is exact and normalized when built,
 * trailing decimal zeros moved from the mantissa into the exponent and zero held as [0, 0], so two
 * decimals of one value hold the same fields and encode to the same bytes. As a {@link CborDouble}
 * its `value` is the nearest double, which a filter compares.
 */
export class CborDecimal extends CborDouble {
  /** The power of ten, within -(2^31-1) to 2^31-1. */
  readonly exponent: number;
  /** The mantissa, not divisible by ten unless zero: a number when it is a safe integer, else a bigint. */
  readonly mantissa: number | bigint;

  /**
   * @param exponent the power of ten, an integer
   * @param mantissa the integer the power of ten scales
   * @throws RangeError when the normalized exponent leaves -(2^31-1) to 2^31-1
   */
  constructor(exponent: number, mantissa: number | bigint) {
    if (!Number.isSafeInteger(exponent) || (typeof mantissa === "number" && !Number.isSafeInteger(mantissa))) {
      throw new RangeError(`a decimal needs an integer exponent and mantissa: ${exponent}, ${mantissa}`);
    }
    let m = BigInt(mantissa);
    let e = exponent;
    if (m === 0n) {
      e = 0;
    } else {
      while (m % 10n === 0n) {
        m /= 10n;
        e += 1;
      }
    }
    if (e < -EXPONENT_LIMIT || e > EXPONENT_LIMIT) {
      throw new RangeError(`a decimal's exponent must lie within -(2^31-1) to 2^31-1: ${e}`);
    }
    super(Number(`${m}e${e}`));
    this.exponent = e;
    this.mantissa = integer(m);
  }
}

export type CborValue =
  | null
  | boolean
  | number
  | bigint
  | CborDouble
  | string
  | Uint8Array
  | CborValue[]
  | { [key: string]: CborValue };

/**
 * What {@link dumps} writes: every value {@link loads} returns, and a JavaScript `Map` with text keys
 * at any depth, written as an indefinite map in the order its entries were set, integer-like keys
 * included, as Python writes a dict and Ruby a Hash (HLC round seven, 2026-11-08). Before, the
 * encoder wrote a Map as the empty map `BF FF`.
 */
export type CborWritable =
  | CborValue
  | ReadonlyMap<string, CborWritable>
  | readonly CborWritable[]
  | { readonly [key: string]: CborWritable };

/**
 * The longest bignum byte string, a leading zero included (HLC round seven, 2026-11-08, S9): Jackson's
 * StreamReadConstraints read no longer number, alone or as a decimal's mantissa, so the decoder refuses
 * one and the encoder writes none.
 */
const MAX_BIGNUM_BYTES = 1000;

function head(major: number, value: number): Uint8Array {
  if (value < 24) {
    return Uint8Array.of((major << 5) | value);
  }
  if (value < 0x100) {
    return Uint8Array.of((major << 5) | 24, value);
  }
  if (value < 0x10000) {
    const b = new Uint8Array(3);
    b[0] = (major << 5) | 25;
    new DataView(b.buffer).setUint16(1, value, false);
    return b;
  }
  if (value < 0x100000000) {
    const b = new Uint8Array(5);
    b[0] = (major << 5) | 26;
    new DataView(b.buffer).setUint32(1, value, false);
    return b;
  }
  const b = new Uint8Array(9);
  b[0] = (major << 5) | 27;
  new DataView(b.buffer).setBigUint64(1, BigInt(value), false);
  return b;
}

const SAFE_MAX = BigInt(Number.MAX_SAFE_INTEGER);
const LONG_MIN = -(1n << 63n);
const LONG_MAX = (1n << 63n) - 1n;

/** A shortest head for an unsigned argument up to 2^64 - 1. */
function headBig(major: number, value: bigint): Uint8Array {
  if (value <= SAFE_MAX) {
    return head(major, Number(value));
  }
  const b = new Uint8Array(9);
  b[0] = (major << 5) | 27;
  new DataView(b.buffer).setBigUint64(1, value, false);
  return b;
}

/** Narrows an integer to a number when it is safe, else keeps the bigint. */
function integer(value: bigint): number | bigint {
  return value >= -SAFE_MAX && value <= SAFE_MAX ? Number(value) : value;
}

/** Maps whose keys {@link dumps} writes in the RFC 8949 order (see {@link canonicalMap}). */
const SORTED_MAPS = new WeakSet<object>();

/** Maps the decoder built, each with its keys in the order they arrived. */
const ARRIVAL_ORDER = new WeakMap<object, readonly string[]>();

/** The RFC 8949 §4.2.1 key order: shorter UTF-8 first, then bytewise unsigned. */
function canonicalKeyOrder(keys: string[]): string[] {
  return keys.map((key) => ({ key, bytes: utf8(key) }))
    .sort((a, b) => a.bytes.length - b.bytes.length || compare(a.bytes, b.bytes))
    .map(({ key }) => key);
}

/**
 * A copy of a map-valued field whose entries {@link dumps} writes in canonical order (shorter UTF-8
 * key first, then bytewise; RFC 8949 §4.2.1), the order the Java codec writes every map in as of
 * wire v3 (ISSUE-CanonicalMaps). The encoder sorts when it writes, since a JS object puts
 * integer-like keys first whatever order they were set in (HLC round six, 2026-11-08: a tag "10"
 * beside a tag "b" signed the wrong bytes). Apply it to maps a signature covers (tags, costHints,
 * spaceBindings, resourceHints, parameters, access, digests); never to an object standing for a record.
 */
export function canonicalMap(value: { [key: string]: CborValue }): { [key: string]: CborValue } {
  // Built in that order too, so a copy of it (a spread, Object.fromEntries) keeps the order wherever
  // a JS object can hold it, every key but an integer-like one.
  const out: { [key: string]: CborValue } = {};
  for (const key of canonicalKeyOrder(Object.keys(value))) {
    setEntry(out, key, value[key]!);
  }
  SORTED_MAPS.add(out);
  return out;
}

/**
 * Sets `key` as an own enumerable property of `map`, whatever the key: an assignment of "__proto__"
 * would set the object's prototype instead and lose the entry, where Java's Map holds it as any
 * other key (HLC round six, 2026-11-08, P2).
 */
export function setEntry(map: { [key: string]: CborValue }, key: string, value: CborValue): void {
  Object.defineProperty(map, key, { value, enumerable: true, writable: true, configurable: true });
}

/** The keys of `map` in the order {@link dumps} writes them. */
function keysOf(map: object): string[] {
  const own = Object.keys(map);
  if (SORTED_MAPS.has(map)) {
    return canonicalKeyOrder(own);
  }
  const arrived = ARRIVAL_ORDER.get(map);
  if (arrived === undefined) {
    return own;
  }
  // Keys still held keep their arrival order; keys set since then follow, as a Map appends them.
  const kept = arrived.filter((key) => Object.prototype.hasOwnProperty.call(map, key));
  const known = new Set(arrived);
  return kept.concat(own.filter((key) => !known.has(key)));
}

/**
 * Encodes a value in the wire encoding (HLC round six, 2026-11-08). A text string over 3996 UTF-16
 * units goes out as Jackson writes it: an indefinite-length string whose chunks hold 3996 units
 * each, one fewer when a chunk would end on the first half of a surrogate pair, and then the rest.
 * Throws RangeError for what the encoding cannot hold: a text with a lone surrogate, a Map key that is
 * not text, and a bignum past 1000 bytes.
 */
export function dumps(value: CborWritable): Uint8Array {
  const parts: Uint8Array[] = [];
  encode(value, parts);
  return concat(...parts);
}

const NULL = Uint8Array.of(0xf6);
const TRUE = Uint8Array.of(0xf5);
const FALSE = Uint8Array.of(0xf4);
const MAP_START = Uint8Array.of(0xbf);
const BREAK = Uint8Array.of(0xff);
const TEXT_START = Uint8Array.of(0x7f);
/** The only NaNs the encoding holds, Java's Double.NaN and Float.NaN (HLC round six, 2026-11-08, S10). */
const NAN64 = Uint8Array.of(0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0);
const NAN32 = Uint8Array.of(0xfa, 0x7f, 0xc0, 0, 0);

function float64(value: number): Uint8Array {
  if (Number.isNaN(value)) {
    return NAN64;
  }
  const b = new Uint8Array(9);
  b[0] = 0xfb;
  new DataView(b.buffer).setFloat64(1, value, false);
  return b;
}

function float32(value: number): Uint8Array {
  if (Number.isNaN(value)) {
    return NAN32;
  }
  const b = new Uint8Array(5);
  b[0] = 0xfa;
  new DataView(b.buffer).setFloat32(1, value, false);
  return b;
}

function encode(value: CborWritable, out: Uint8Array[]): void {
  if (value === null || value === undefined) {
    out.push(NULL);
  } else if (value === true) {
    out.push(TRUE);
  } else if (value === false) {
    out.push(FALSE);
  } else if (value instanceof CborDecimal) {
    encodeDecimal(value, out);
  } else if (value instanceof CborFloat32) {
    out.push(float32(value.value));
  } else if (value instanceof CborDouble) {
    out.push(float64(value.value));
  } else if (typeof value === "bigint") {
    encodeInteger(value, out);
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      // A fraction, -0, or a magnitude past 2^53 (Infinity and NaN included) is a float64 (0xFB),
      // as the Java and Python codecs encode a double; an integral value that must stay a float
      // is wrapped in CborDouble, since the number alone cannot say so.
      out.push(float64(value));
    } else {
      out.push(value >= 0 ? head(0, value) : head(1, -1 - value));
    }
  } else if (value instanceof Uint8Array) {
    out.push(head(2, value.length), value);
  } else if (typeof value === "string") {
    encodeText(value, out);
  } else if (Array.isArray(value)) {
    out.push(head(4, value.length));
    for (const item of value as readonly CborWritable[]) {
      encode(item, out);
    }
  } else if (value instanceof Map) {
    out.push(MAP_START);
    for (const [key, item] of value as ReadonlyMap<unknown, CborWritable>) {
      if (typeof key !== "string") {
        throw new RangeError(`a map key is text, not ${typeof key}`);
      }
      encodeText(key, out);
      encode(item, out);
    }
    out.push(BREAK);
  } else {
    // An indefinite-length map in the order keysOf gives: an object stands for a Java record
    // (declared component order) as often as for a map, so the encoder sorts only a canonicalMap.
    out.push(MAP_START);
    const map = value as { readonly [key: string]: CborWritable };
    for (const key of keysOf(map)) {
      encodeText(key, out);
      encode(map[key], out);
    }
    out.push(BREAK);
  }
}

const TAG_BIGNUM = Uint8Array.of(0xc2);
const TAG_NEGATIVE_BIGNUM = Uint8Array.of(0xc3);
const TAG_DECIMAL_PAIR = Uint8Array.of(0xc4, 0x82);

/**
 * An integer: a plain integer under its shortest head when a Java long holds it, else a bignum as
 * Jackson writes a BigInteger, tag 2 for a positive value and tag 3 for a negative one, over
 * BigInteger.toByteArray of the magnitude (HLC round six, 2026-11-08, S4 and S9).
 */
function encodeInteger(value: bigint, out: Uint8Array[]): void {
  if (value >= 0n && value <= LONG_MAX) {
    out.push(headBig(0, value));
    return;
  }
  if (value < 0n && value >= LONG_MIN) {
    out.push(headBig(1, -1n - value));
    return;
  }
  const negative = value < 0n;
  let digits = (negative ? -value : value).toString(16);
  if (digits.length % 2 !== 0) {
    digits = `0${digits}`;
  }
  if (parseInt(digits.substring(0, 2), 16) >= 0x80) {
    digits = `00${digits}`;
  }
  const bytes = fromHex(digits);
  if (bytes.length > MAX_BIGNUM_BYTES) {
    throw new RangeError(`a bignum holds at most ${MAX_BIGNUM_BYTES} bytes (S9)`);
  }
  out.push(negative ? TAG_NEGATIVE_BIGNUM : TAG_BIGNUM, head(2, bytes.length), bytes);
}

/** A decimal as tag 4 over [exponent, mantissa], both integers under the rules of {@link encodeInteger}. */
function encodeDecimal(value: CborDecimal, out: Uint8Array[]): void {
  out.push(TAG_DECIMAL_PAIR);
  encodeInteger(BigInt(value.exponent), out);
  encodeInteger(BigInt(value.mantissa), out);
}

/** Matches a UTF-16 surrogate standing alone, which no UTF-8 can carry. */
const LONE_SURROGATE = /\p{Cs}/u;

/** The UTF-16 unit lengths of Jackson's chunks of a text past {@link JACKSON_CHUNK_UNITS} units. */
function jacksonChunks(text: string): number[] {
  const lengths: number[] = [];
  let start = 0;
  while (text.length - start > JACKSON_CHUNK_UNITS) {
    let end = start + JACKSON_CHUNK_UNITS;
    const last = text.charCodeAt(end - 1);
    if (last >= 0xd800 && last <= 0xdbff) {
      end -= 1; // Jackson never splits a surrogate pair between two chunks
    }
    lengths.push(end - start);
    start = end;
  }
  lengths.push(text.length - start);
  return lengths;
}

/** A text string as Jackson's CBORGenerator writes it (see {@link dumps}). */
function encodeText(text: string, out: Uint8Array[]): void {
  if (LONE_SURROGATE.test(text)) {
    throw new RangeError("a text holding a lone surrogate has no UTF-8 encoding");
  }
  if (text.length <= JACKSON_CHUNK_UNITS) {
    const encoded = utf8(text);
    out.push(head(3, encoded.length), encoded);
    return;
  }
  out.push(TEXT_START);
  let start = 0;
  for (const length of jacksonChunks(text)) {
    const chunk = utf8(text.slice(start, start + length));
    out.push(head(3, chunk.length), chunk);
    start += length;
  }
  out.push(BREAK);
}

/**
 * Decodes exactly one CBOR item in the wire encoding, or throws RangeError (HLC round six,
 * 2026-11-08, S1 to S12). Whatever this returns re-encodes through {@link dumps} to the bytes given:
 * a document in any other form (a longer head, a definite map, an indefinite array or byte string,
 * other text chunks, a duplicate or non-text key, a half float, another NaN, an unassigned simple
 * value, a tag other than 2, 3 and 4, a bignum a long holds, a decimal not normalized, a byte after
 * the item, a 65th level) is refused.
 */
export function loads(data: Uint8Array): CborValue {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const [value, end] = decode(data, view, 0, 0);
  if (end !== data.length) {
    throw new RangeError(`trailing bytes after CBOR item at offset ${end}`);
  }
  return value;
}

/**
 * The value an application document holds, or null when the bytes are no document in the wire
 * encoding (HLC round six, 2026-11-08, section 3.1). An entry whose payload is unreadable stays
 * replicated, since its signature covers the payload's bytes, and every read skips its value.
 */
export function readDocument(bytes: Uint8Array): { value: CborValue } | null {
  try {
    return { value: loads(bytes) };
  } catch {
    return null;
  }
}

function need(data: Uint8Array, offset: number, count: number): void {
  if (offset + count > data.length) {
    throw new RangeError("truncated CBOR item");
  }
}

/** The most nested containers a document holds (ASF-018); the decoder refuses the 65th level. */
const MAX_DEPTH = 64;

function enter(depth: number, offset: number): void {
  if (depth >= MAX_DEPTH) {
    throw new RangeError(`CBOR nesting past ${MAX_DEPTH} levels at offset ${offset}`);
  }
}

/** A head's argument at `offset` (just past the initial byte) and the offset after it; null for indefinite. */
function argument(data: Uint8Array, view: DataView, initial: number, offset: number): [bigint | null, number] {
  const info = initial & 0x1f;
  let value: bigint;
  let width: number;
  if (info < 24) {
    return [BigInt(info), offset];
  } else if (info === 24) {
    need(data, offset, 1);
    value = BigInt(data[offset]!);
    width = 1;
  } else if (info === 25) {
    need(data, offset, 2);
    value = BigInt(view.getUint16(offset, false));
    width = 2;
  } else if (info === 26) {
    need(data, offset, 4);
    value = BigInt(view.getUint32(offset, false));
    width = 4;
  } else if (info === 27) {
    need(data, offset, 8);
    value = view.getBigUint64(offset, false);
    width = 8;
  } else if (info === 31) {
    return [null, offset];
  } else {
    throw new RangeError(`reserved CBOR head 0x${initial.toString(16)} at offset ${offset - 1}`);
  }
  // S3: the fewest bytes that hold the argument.
  const floor = width === 1 ? 24n : 1n << BigInt(width * 4);
  if (value < floor) {
    throw new RangeError(`a CBOR head longer than its argument needs at offset ${offset - 1}`);
  }
  return [value, offset + width];
}

/** A definite length that fits the document, or a throw. */
function length(data: Uint8Array, value: bigint, offset: number): number {
  if (value > BigInt(data.length - offset)) {
    throw new RangeError("truncated CBOR item");
  }
  return Number(value);
}

/** One item at `offset`, `depth` containers deep: its value and the offset after it. */
function decode(data: Uint8Array, view: DataView, offset: number, depth: number): [CborValue, number] {
  const initial = data[offset];
  if (initial === undefined) {
    throw new RangeError("truncated CBOR");
  }
  const major = initial >> 5;
  const start = offset;
  offset += 1;
  if (major === 7) {
    switch (initial) {
      case 0xf4:
        return [false, offset];
      case 0xf5:
        return [true, offset];
      case 0xf6:
        return [null, offset];
      case 0xfa: {
        need(data, offset, 4);
        const value = view.getFloat32(offset, false);
        if (Number.isNaN(value) && view.getUint32(offset, false) !== 0x7fc00000) {
          throw new RangeError(`a float32 NaN other than 7FC00000 at offset ${start}`);
        }
        return [new CborFloat32(value), offset + 4];
      }
      case 0xfb: {
        need(data, offset, 8);
        const value = view.getFloat64(offset, false);
        if (Number.isNaN(value) && view.getBigUint64(offset, false) !== 0x7ff8000000000000n) {
          throw new RangeError(`a float64 NaN other than 7FF8000000000000 at offset ${start}`);
        }
        return [new CborDouble(value), offset + 8];
      }
      case 0xf9:
        throw new RangeError(`a half-precision float at offset ${start}`);
      case 0xff:
        throw new RangeError(`a break outside an indefinite item at offset ${start}`);
      default:
        throw new RangeError(`the CBOR simple value 0x${initial.toString(16)} at offset ${start}`);
    }
  }
  const [arg, after] = argument(data, view, initial, offset);
  offset = after;
  if (arg === null) {
    if (major === 3) {
      return indefiniteText(data, view, offset);
    }
    if (major === 5) {
      return map(data, view, offset, depth, start);
    }
    throw new RangeError(`an indefinite-length item of major type ${major} at offset ${start}`);
  }
  switch (major) {
    case 0:
      if (arg > LONG_MAX) {
        throw new RangeError(`an integer past a Java long at offset ${start}; the encoding writes it as a bignum`);
      }
      return [integer(arg), offset];
    case 1:
      if (arg > LONG_MAX) {
        throw new RangeError(`an integer past a Java long at offset ${start}; the encoding writes it as a bignum`);
      }
      return [integer(-1n - arg), offset];
    case 2: {
      const n = length(data, arg, offset);
      // A plain copy even when the caller passed a Node Buffer (whose slice is a view).
      return [Uint8Array.prototype.slice.call(data, offset, offset + n), offset + n];
    }
    case 3: {
      const n = length(data, arg, offset);
      const text = strictText(data, offset, offset + n);
      if (text.length > JACKSON_CHUNK_UNITS) {
        throw new RangeError(`a definite text past ${JACKSON_CHUNK_UNITS} UTF-16 units at offset ${start}`);
      }
      return [text, offset + n];
    }
    case 4: {
      enter(depth, start);
      const n = length(data, arg, offset);
      const items: CborValue[] = [];
      for (let i = 0; i < n; i++) {
        const [item, next] = decode(data, view, offset, depth + 1);
        items.push(item);
        offset = next;
      }
      return [items, offset];
    }
    case 5:
      throw new RangeError(`a definite-length map at offset ${start}; the encoding writes every map indefinite`);
    default:
      return tagged(data, view, start, arg, offset, depth);
  }
}

/**
 * An indefinite-length map at `offset` (just past 0xBF): unique text keys, each value an item. The
 * map remembers the order its keys arrived in, which {@link dumps} keeps. A null prototype keeps
 * hostile "__proto__"/"constructor" keys plain own properties (ASF-034).
 */
function map(data: Uint8Array, view: DataView, offset: number, depth: number, start: number): [CborValue, number] {
  enter(depth, start);
  const result: { [key: string]: CborValue } = Object.create(null);
  const order: string[] = [];
  for (;;) {
    const initial = data[offset];
    if (initial === undefined) {
      throw new RangeError("truncated CBOR");
    }
    if (initial === 0xff) {
      ARRIVAL_ORDER.set(result, order);
      return [result, offset + 1];
    }
    if (initial >> 5 !== 3) {
      throw new RangeError(`a map key at offset ${offset} is no text string`);
    }
    const [key, afterKey] = decode(data, view, offset, depth + 1);
    const name = key as string;
    if (Object.prototype.hasOwnProperty.call(result, name)) {
      throw new RangeError(`the map key ${JSON.stringify(name)} occurs twice at offset ${offset}`);
    }
    const [item, afterValue] = decode(data, view, afterKey, depth + 1);
    result[name] = item;
    order.push(name);
    offset = afterValue;
  }
}

/**
 * The item a tag head at `start` encloses, its content starting at `offset` (HLC round six,
 * 2026-11-08, S9). Only these decode:
 * - tag 2 or 3, a bignum: an integer outside a Java long (see {@link bignum});
 * - tag 4, a decimal: a two-element array, itself a nesting level, of an integer exponent within
 *   -(2^31-1) to 2^31-1 and an integer or bignum mantissa, normalized: a {@link CborDecimal}.
 */
function tagged(data: Uint8Array, view: DataView, start: number, tag: bigint, offset: number,
                depth: number): [CborValue, number] {
  if (tag === 2n || tag === 3n) {
    return bignum(data, view, start, tag === 3n, offset);
  }
  if (tag !== 4n) {
    throw new RangeError(`this wire refuses CBOR tag ${tag} at offset ${start}; only tags 2, 3 and 4 decode`);
  }
  if (data[offset] !== 0x82) {
    throw new RangeError(`CBOR tag 4 at offset ${start} encloses no two-element array`);
  }
  enter(depth, offset);
  offset += 1;
  const exponentHead = data[offset];
  if (exponentHead === undefined || exponentHead >> 5 > 1) {
    throw new RangeError(`the exponent of CBOR tag 4 at offset ${start} is no plain integer`);
  }
  const [exponent, afterExponent] = decode(data, view, offset, depth + 1);
  const mantissaHead = data[afterExponent];
  let mantissa: number | bigint;
  let next: number;
  if (mantissaHead === 0xc2 || mantissaHead === 0xc3) {
    [mantissa, next] = bignum(data, view, afterExponent, mantissaHead === 0xc3, afterExponent + 1);
  } else if (mantissaHead !== undefined && mantissaHead >> 5 <= 1) {
    [mantissa, next] = decode(data, view, afterExponent, depth + 1) as [number | bigint, number];
  } else {
    throw new RangeError(`the mantissa of CBOR tag 4 at offset ${start} is neither an integer nor a bignum`);
  }
  const e = Number(exponent);
  const m = BigInt(mantissa);
  if (e < -EXPONENT_LIMIT || e > EXPONENT_LIMIT) {
    throw new RangeError(`the exponent of CBOR tag 4 at offset ${start} leaves -(2^31-1) to 2^31-1`);
  }
  if (m === 0n ? e !== 0 : m % 10n === 0n) {
    throw new RangeError(`the decimal at offset ${start} is not normalized`);
  }
  return [new CborDecimal(e, m), next];
}

/**
 * A bignum's content at `offset`: a definite byte string under its shortest head holding
 * BigInteger.toByteArray of the magnitude (first byte below 0x80, a leading zero only before a byte
 * of 0x80 or above), a magnitude past what a Java long holds. Tag 2 reads it as the value and tag 3
 * as its negation, as Jackson reads them (HLC round six, 2026-11-08, S9).
 */
function bignum(data: Uint8Array, view: DataView, start: number, negative: boolean,
                offset: number): [bigint, number] {
  const initial = data[offset];
  if (initial === undefined || initial >> 5 !== 2 || (initial & 0x1f) === 31) {
    throw new RangeError(`the bignum at offset ${start} encloses no definite byte string`);
  }
  const [arg, after] = argument(data, view, initial, offset + 1);
  const n = length(data, arg!, after);
  if (n > MAX_BIGNUM_BYTES) {
    throw new RangeError(`the bignum at offset ${start} holds more than ${MAX_BIGNUM_BYTES} bytes (S9)`);
  }
  const bytes = data.subarray(after, after + n);
  if (n === 0 || bytes[0]! >= 0x80 || (n > 1 && bytes[0] === 0 && bytes[1]! < 0x80)) {
    throw new RangeError(`the bignum at offset ${start} is not BigInteger.toByteArray of its magnitude`);
  }
  const magnitude = BigInt(`0x${toHex(bytes)}`);
  if (magnitude <= (negative ? LONG_MAX + 1n : LONG_MAX)) {
    throw new RangeError(`the bignum at offset ${start} holds a value a Java long holds`);
  }
  return [negative ? -magnitude : magnitude, after + n];
}

/**
 * The text of an indefinite-length text string whose chunks start at `offset`, and the offset after
 * its break (HLC round six, 2026-11-08, S6): each chunk a definite text string of valid UTF-8 under
 * its shortest head, the whole past 3996 UTF-16 units, cut exactly where Jackson cuts it.
 */
function indefiniteText(data: Uint8Array, view: DataView, offset: number): [string, number] {
  const start = offset - 1;
  const chunks: string[] = [];
  for (;;) {
    const initial = data[offset];
    if (initial === undefined) {
      throw new RangeError("truncated CBOR");
    }
    if (initial === 0xff) {
      offset += 1;
      break;
    }
    if (initial >> 5 !== 3 || (initial & 0x1f) === 31) {
      throw new RangeError(`an indefinite-length CBOR text string holds a chunk at offset ${offset} that is no definite text string`);
    }
    const [arg, after] = argument(data, view, initial, offset + 1);
    const n = length(data, arg!, after);
    chunks.push(strictText(data, after, after + n));
    offset = after + n;
  }
  const text = chunks.join("");
  const expected = jacksonChunks(text);
  if (text.length <= JACKSON_CHUNK_UNITS || expected.length !== chunks.length
      || expected.some((units, i) => chunks[i]!.length !== units)) {
    throw new RangeError(`the indefinite text at offset ${start} is not in Jackson's chunks`);
  }
  return [text, offset];
}
