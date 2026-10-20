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
 * Byte helpers over plain `Uint8Array` (srad/agentspaces-js.md JS-P-03): the
 * portable core uses these in place of Node's `Buffer`, so it loads in
 * browsers, Workers, Deno, and Bun as it does on Node.
 */

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8");
const HEX = "0123456789abcdef";
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** UTF-8 bytes of a string. */
export function utf8(text: string): Uint8Array {
  return ENCODER.encode(text);
}

/** A string from UTF-8 bytes (invalid sequences become U+FFFD, as Buffer does). */
export function fromUtf8(bytes: Uint8Array, start = 0, end = bytes.length): string {
  return DECODER.decode(bytes.subarray(start, end));
}

/** Lowercase hex. */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += HEX[b >> 4] + HEX[b & 15];
  }
  return out;
}

/** Bytes from hex; refuses odd lengths and non-hex characters. */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("not a hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

/** Standard base64 with padding. */
export function toBase64(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  if (i < bytes.length) {
    const n = (bytes[i] << 16) | ((i + 1 < bytes.length ? bytes[i + 1] : 0) << 8);
    out += B64[n >> 18] + B64[(n >> 12) & 63]
      + (i + 1 < bytes.length ? B64[(n >> 6) & 63] : "=") + "=";
  }
  return out;
}

/** Bytes from standard or URL-safe base64, padded or not. */
export function fromBase64(text: string): Uint8Array {
  const clean = text.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/]*$/.test(clean) || clean.length % 4 === 1) {
    throw new Error("not a base64 string");
  }
  const out = new Uint8Array(Math.floor(clean.length * 3 / 4));
  let bits = 0;
  let value = 0;
  let index = 0;
  for (const ch of clean) {
    value = (value << 6) | B64.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (value >> bits) & 0xff;
    }
  }
  return out;
}

/** URL-safe base64 without padding. */
export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** One array holding every part in order. */
export function concat(...parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const p of parts) {
    length += p.length;
  }
  const out = new Uint8Array(length);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Bytewise equality. */
export function equals(a: Uint8Array, b: Uint8Array): boolean {
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

/** Unsigned bytewise comparison, shorter prefix first (Buffer.compare's order). */
export function compare(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) {
      return a[i] < b[i] ? -1 : 1;
    }
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

/** A copy of the bytes as a plain Uint8Array (never a Buffer or a view into one). */
export function copy(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

/** Four-byte big-endian signed length prefix, the stream bindings' framing. */
export function int32be(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setInt32(0, value, false);
  return out;
}

/** Reads a four-byte big-endian signed integer. */
export function readInt32be(bytes: Uint8Array, offset = 0): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getInt32(offset, false);
}

/** Cryptographically strong random bytes from the platform (WebCrypto `getRandomValues`). */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65536) {
    globalThis.crypto.getRandomValues(out.subarray(offset, Math.min(length, offset + 65536)));
  }
  return out;
}

/** A random RFC 4122 version 4 UUID. */
export function randomUuid(): string {
  if (typeof globalThis.crypto.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = toHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
