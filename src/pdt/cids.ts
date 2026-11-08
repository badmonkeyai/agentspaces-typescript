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
 * CIDs of the persistent data structures (srad/agentspaces-pdt.md §3.1, PD-N-02, §10.2): CIDv1 in the
 * multibase `b` form (RFC 4648 base32, lower case, unpadded) over `0x01`, the codec, `0x12 0x20`, and the
 * sha2-256 digest. Codec `0x71` (dag-cbor) names every structured node and `0x55` (raw) names a blob chunk.
 * A content-swarm artifact root is also `b...` with codec `0x55`, so `parse(ref).codec` is what tells a
 * PDT root from a flat artifact root.
 */

import { cryptoPort } from "../crypto.js";

export const DAG_CBOR = 0x71;
export const RAW = 0x55;
/** The binary CID: version, codec, multihash code, length, digest. */
export const BINARY_LENGTH = 36;
/** The text CID: `b` plus 58 base32 characters. */
export const TEXT_LENGTH = 59;

const B32 = "abcdefghijklmnopqrstuvwxyz234567";
const B32_INDEX = new Map<string, number>([...B32].map((ch, i) => [ch, i]));

export interface Parsed {
  codec: number;
  digest: Uint8Array;
}

export function base32Lower(data: Uint8Array): string {
  let out = "", buffer = 0, bits = 0;
  for (const b of data) {
    buffer = ((buffer << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += B32[(buffer >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += B32[(buffer << (5 - bits)) & 0x1f];
  }
  return out;
}

export function base32Decode(text: string): Uint8Array {
  const out: number[] = [];
  let buffer = 0, bits = 0;
  for (const ch of text) {
    const value = B32_INDEX.get(ch);
    if (value === undefined) {
      throw new Error(`not a base32 character: ${ch}`);
    }
    buffer = ((buffer << 5) | value) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if ((buffer & ((1 << bits) - 1)) !== 0) {
    throw new Error("base32 padding bits are not zero");
  }
  return Uint8Array.from(out);
}

/** The CID of bytes under a codec. */
export function of(bytes: Uint8Array, codec: number): string {
  return ofDigest(cryptoPort().sha256(bytes), codec);
}

/** The CID of a digest under a codec. */
export function ofDigest(digest: Uint8Array, codec: number): string {
  if (codec !== DAG_CBOR && codec !== RAW) {
    throw new Error(`unknown codec 0x${codec.toString(16)}`);
  }
  if (digest.length !== 32) {
    throw new Error(`a sha2-256 digest has 32 bytes, got ${digest.length}`);
  }
  const bin = new Uint8Array(BINARY_LENGTH);
  bin.set([0x01, codec, 0x12, 0x20], 0);
  bin.set(digest, 4);
  return "b" + base32Lower(bin);
}

/** The binary form (36 bytes) of a text CID. */
export function binary(cid: string): Uint8Array {
  const parsed = parse(cid);
  const bin = new Uint8Array(BINARY_LENGTH);
  bin.set([0x01, parsed.codec, 0x12, 0x20], 0);
  bin.set(parsed.digest, 4);
  return bin;
}

/** The text CID of a binary CID; refuses an unknown codec or multihash (PD-N-04). */
export function fromBinary(bin: Uint8Array): string {
  if (bin.length !== BINARY_LENGTH) {
    throw new Error(`a binary CID has ${BINARY_LENGTH} bytes, got ${bin.length}`);
  }
  if (bin[0] !== 0x01) {
    throw new Error(`unknown CID version ${bin[0]}`);
  }
  if (bin[1] !== DAG_CBOR && bin[1] !== RAW) {
    throw new Error(`unknown codec 0x${bin[1]!.toString(16)}`);
  }
  if (bin[2] !== 0x12 || bin[3] !== 0x20) {
    throw new Error("unknown multihash; only sha2-256 is read");
  }
  return "b" + base32Lower(bin);
}

/** Parses a text CID into its codec and digest; throws on anything else. */
export function parse(cid: string): Parsed {
  if (typeof cid !== "string" || cid.length !== TEXT_LENGTH || cid[0] !== "b") {
    throw new Error(`not a CID: ${String(cid).slice(0, 80)}`);
  }
  const bin = base32Decode(cid.slice(1));
  if (bin.length !== BINARY_LENGTH || bin[0] !== 0x01 || bin[2] !== 0x12 || bin[3] !== 0x20) {
    throw new Error(`not a sha2-256 CIDv1: ${cid}`);
  }
  if (bin[1] !== DAG_CBOR && bin[1] !== RAW) {
    throw new Error(`unknown codec 0x${bin[1]!.toString(16)} in ${cid}`);
  }
  return { codec: bin[1]!, digest: bin.subarray(4) };
}

/** Whether a string is a well-formed CID of either codec. */
export function isCid(cid: unknown): cid is string {
  if (typeof cid !== "string") {
    return false;
  }
  try {
    parse(cid);
    return true;
  } catch {
    return false;
  }
}

/** Whether a CID names a raw chunk. */
export function isRaw(cid: string): boolean {
  return parse(cid).codec === RAW;
}

/** Whether `bytes` hash to the CID's digest. */
export function verifies(cid: string, bytes: Uint8Array): boolean {
  const parsed = parse(cid);
  const digest = cryptoPort().sha256(bytes);
  for (let i = 0; i < 32; i++) {
    if (digest[i] !== parsed.digest[i]) {
      return false;
    }
  }
  return true;
}
