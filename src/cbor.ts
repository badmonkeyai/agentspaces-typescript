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
 * CBOR (RFC 8949) codec matching the Java side's Jackson encoding byte for
 * byte, proven by the cross-language golden vectors shared with the Python
 * client. Encoding rules (wire v2 canonical form, SPEC v0.1.10 §9,
 * TECH-SPEC §1.1): objects are indefinite-length maps (0xBF..0xFF) with keys
 * in insertion order, arrays are definite-length (0x80..0x9B), text and byte
 * strings are definite with minimal heads, integers are minimal width, null
 * fields are emitted as 0xF6 (never omitted), and doubles are 64-bit (0xFB).
 *
 * <p>Numbers. JavaScript has one number type and Java has several, and
 * signatures cover the bytes, so this codec keeps the distinction explicit
 * in both directions:
 * <ul>
 *   <li>A {@code number} encodes as an integer (major 0/1) and must be a safe
 *       integer; wrap a value in {@link CborDouble} to emit a float64. The
 *       decoder returns every float (0xFA/0xFB) as a {@link CborDouble}, so
 *       {@code dumps(loads(x))} reproduces {@code x} for the float64 arrays
 *       in aggregate frames and for claim bids alike.</li>
 *   <li>A Java {@code long} outside Number.MAX_SAFE_INTEGER (an aggregate
 *       roster token, for instance) decodes as a {@code bigint} and a
 *       {@code bigint} encodes as a minimal-width major 0/1 integer, so
 *       int64 values round-trip byte-exactly instead of losing precision or
 *       throwing. A bigint inside the safe range encodes identically to the
 *       equivalent number and decodes back as a number.</li>
 * </ul>
 */

/** Wraps a number that must encode as a CBOR double (e.g. an AUCTION bid). */
export class CborDouble {
  constructor(readonly value: number) {}
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

function head(major: number, value: number): Buffer {
  if (value < 24) {
    return Buffer.from([(major << 5) | value]);
  }
  if (value < 0x100) {
    return Buffer.from([(major << 5) | 24, value]);
  }
  if (value < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(value, 1);
    return b;
  }
  if (value < 0x100000000) {
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(value, 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = (major << 5) | 27;
  b.writeBigUInt64BE(BigInt(value), 1);
  return b;
}

const UINT64_MAX = (1n << 64n) - 1n;
const SAFE_MAX = BigInt(Number.MAX_SAFE_INTEGER);

/** A minimal-width head for an unsigned argument up to 2^64 - 1. */
function headBig(major: number, value: bigint): Buffer {
  if (value <= SAFE_MAX) {
    return head(major, Number(value));
  }
  if (value > UINT64_MAX) {
    throw new RangeError(`integer does not fit in 64 bits: ${value}`);
  }
  const b = Buffer.alloc(9);
  b[0] = (major << 5) | 27;
  b.writeBigUInt64BE(value, 1);
  return b;
}

/** Narrows a decoded integer to a number when it is safe, else keeps the bigint. */
function integer(value: bigint): number | bigint {
  return value >= -SAFE_MAX && value <= SAFE_MAX ? Number(value) : value;
}

/** Encodes a value the way the Java codec encodes its equivalent. */
export function dumps(value: CborValue): Buffer {
  const parts: Buffer[] = [];
  encode(value, parts);
  return Buffer.concat(parts);
}

function encode(value: CborValue, out: Buffer[]): void {
  if (value === null || value === undefined) {
    out.push(Buffer.from([0xf6]));
  } else if (value === true) {
    out.push(Buffer.from([0xf5]));
  } else if (value === false) {
    out.push(Buffer.from([0xf4]));
  } else if (value instanceof CborDouble) {
    const b = Buffer.alloc(9);
    b[0] = 0xfb;
    b.writeDoubleBE(value.value, 1);
    out.push(b);
  } else if (typeof value === "bigint") {
    // int64 beyond the safe range (an aggregate roster token, a Java long).
    out.push(value >= 0n ? headBig(0, value) : headBig(1, -1n - value));
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError(`not a safe integer: ${value}; wrap doubles in CborDouble`);
    }
    out.push(value >= 0 ? head(0, value) : head(1, -1 - value));
  } else if (value instanceof Uint8Array) {
    out.push(head(2, value.length), Buffer.from(value));
  } else if (typeof value === "string") {
    const encoded = Buffer.from(value, "utf-8");
    out.push(head(3, encoded.length), encoded);
  } else if (Array.isArray(value)) {
    // Definite-length arrays: the canonical form as of wire v2, matching the
    // Java codec (RFC 8949 deterministic-encoding preference). Maps stay
    // indefinite, matching Java's streaming object encoder.
    out.push(head(4, value.length));
    for (const item of value) {
      encode(item, out);
    }
  } else {
    out.push(Buffer.from([0xbf]));
    for (const [key, item] of Object.entries(value)) {
      encode(key, out);
      encode(item, out);
    }
    out.push(Buffer.from([0xff]));
  }
}

/**
 * Decodes exactly one CBOR item; trailing bytes are refused so malformed or
 * smuggled input is loud, never silently tolerated (ASF-042).
 */
export function loads(data: Buffer): CborValue {
  const [value, end] = decode(data, 0);
  if (end !== data.length) {
    throw new RangeError(`trailing bytes after CBOR item at offset ${end}`);
  }
  return value;
}

function need(data: Buffer, offset: number, count: number): void {
  if (offset + count > data.length) {
    throw new RangeError("truncated CBOR item");
  }
}

/** Deepest container nesting accepted; hostile deep nesting overflows the stack. */
const MAX_DEPTH = 64;

function decode(data: Buffer, offset: number, depth = 0): [CborValue, number] {
  if (depth > MAX_DEPTH) {
    throw new RangeError("CBOR nesting too deep");
  }
  const initial = data[offset];
  if (initial === undefined) {
    throw new RangeError("truncated CBOR");
  }
  const major = initial >> 5;
  const info = initial & 0x1f;
  offset += 1;

  // Major 7 carries simple values and floats, never a length head.
  if (major === 7) {
    switch (info) {
      case 20:
        return [false, offset];
      case 21:
        return [true, offset];
      case 22:
      case 23:
        return [null, offset];
      case 26:
        // Re-encoded as float64; Java never emits float32 on this wire.
        return [new CborDouble(data.readFloatBE(offset)), offset + 4];
      case 27:
        // Preserved as CborDouble so re-encoding stays byte-identical, which
        // signature verification of decoded claims depends on.
        return [new CborDouble(data.readDoubleBE(offset)), offset + 8];
      default:
        throw new RangeError(`unsupported CBOR simple value 0x${initial.toString(16)}`);
    }
  }

  let length: number | null;
  if (info === 31) {
    length = null; // indefinite
  } else if (info < 24) {
    length = info;
  } else if (info === 24) {
    length = data[offset];
    offset += 1;
  } else if (info === 25) {
    length = data.readUInt16BE(offset);
    offset += 2;
  } else if (info === 26) {
    length = data.readUInt32BE(offset);
    offset += 4;
  } else if (info === 27) {
    need(data, offset, 8);
    const big = data.readBigUInt64BE(offset);
    offset += 8;
    if (major === 0) {
      return [integer(big), offset];
    }
    if (major === 1) {
      return [integer(-1n - big), offset];
    }
    if (big > SAFE_MAX) {
      // A string or container this long cannot exist in an 8 MiB frame.
      throw new RangeError("uint64 length beyond safe integer range");
    }
    length = Number(big);
  } else {
    throw new RangeError(`unsupported CBOR head 0x${initial.toString(16)}`);
  }

  switch (major) {
    case 0:
      return [length as number, offset];
    case 1:
      return [-1 - (length as number), offset];
    case 2:
      need(data, offset, length as number);
      return [Uint8Array.prototype.slice.call(data, offset, offset + (length as number)),
        offset + (length as number)];
    case 3:
      need(data, offset, length as number);
      return [data.toString("utf-8", offset, offset + (length as number)),
        offset + (length as number)];
    case 4: {
      const items: CborValue[] = [];
      if (length === null) {
        while (data[offset] !== 0xff) {
          const [item, next] = decode(data, offset, depth + 1);
          items.push(item);
          offset = next;
        }
        return [items, offset + 1];
      }
      for (let i = 0; i < length; i++) {
        const [item, next] = decode(data, offset, depth + 1);
        items.push(item);
        offset = next;
      }
      return [items, offset];
    }
    case 5: {
      // A null prototype keeps hostile "__proto__"/"constructor" keys as plain
      // own properties instead of prototype pollution (ASF-034).
      const result: { [key: string]: CborValue } = Object.create(null);
      const entry = (): void => {
        const [key, afterKey] = decode(data, offset, depth + 1);
        const [item, afterValue] = decode(data, afterKey, depth + 1);
        result[String(key)] = item;
        offset = afterValue;
      };
      if (length === null) {
        while (data[offset] !== 0xff) {
          entry();
        }
        return [result, offset + 1];
      }
      for (let i = 0; i < length; i++) {
        entry();
      }
      return [result, offset];
    }
    default:
      throw new RangeError(`unsupported CBOR major ${major}`);
  }
}
