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
 * The reader of the `dcz` field of an intra-chunk delta (PDT 2 phase 7, P2-C-01, P2-Z-01, P2-Z-04, P2-F-02;
 * srad/agentspaces-pdt2.md §3.8), a port of Java's `Dcz.decode`: a leading format byte (`d` zstd; `v` VCDIFF is
 * reserved and refused by name), the 40-byte RFC 9842 header (the skippable-frame magic `5e 2a 4d 18 20 00 00 00` and
 * the base's sha-256), and exactly one zstd frame (RFC 8878) with the base as a raw-content dictionary.
 *
 * The reader trusts no size it has not checked (P2-Q-SEC-05, decision 4 of §10.12). Before it decompresses it reads
 * the frame header and refuses, each by name, a frame without a content size, a content size or a window past
 * {@link MAX_OUTPUT}, a dictionary id, a reserved header bit, and anything after the one frame; it then decompresses
 * into the declared size. It also refuses a base past the chunk bound and a base that starts with the zstd dictionary
 * magic, which zstd would load as a formatted dictionary. The caller verifies the result against the chunk's CID.
 *
 * The portable core holds no zstd: a host installs a {@link ZstdPort} (the Node entry installs one over `node:zlib`),
 * and without one every frame is refused by name, so its chunk travels whole.
 */

import { cryptoPort } from "../crypto.js";

/** The format byte of a zstd frame (P2-F-02). */
export const ZSTD = 0x64;
/** The format byte reserved for a VCDIFF frame (P2-Z-05), which this release does not read. */
export const VCDIFF = 0x76;
/** The most bytes a frame may rebuild and the widest window it may declare: the chunk bound of PD-B-01. */
export const MAX_OUTPUT = 256 * 1024;
/** The format byte and the RFC 9842 header before the zstd frame. */
export const HEADER_BYTES = 1 + 8 + 32;

const DCZ_MAGIC = [0x5e, 0x2a, 0x4d, 0x18, 0x20, 0x00, 0x00, 0x00];
const ZSTD_MAGIC = 0xfd2fb528;
const DICTIONARY_MAGIC = 0xec30a437;
/** A zstd frame's magic, header descriptor, and at least one block header byte. */
const MIN_ZSTD_BYTES = 6;

/** Decompresses one zstd frame with a raw-content dictionary into at most `size` bytes; throws on any fault. */
export interface ZstdPort {
  decompress(frame: Uint8Array, dictionary: Uint8Array, size: number): Uint8Array;
}

let installed: ZstdPort | null = null;

/** Installs the zstd a host provides, or none. */
export function installZstd(port: ZstdPort | null): void {
  installed = port;
}

/** The zstd installed, or null. */
export function zstdPort(): ZstdPort | null {
  return installed;
}

/** Rebuilds the chunk a field writes over its base; throws RangeError naming the rule the field breaks. */
export function decode(base: Uint8Array, field: Uint8Array): Uint8Array {
  if (field.length < HEADER_BYTES + MIN_ZSTD_BYTES) {
    throw refused(`a field of ${field.length} bytes holds no format byte, RFC 9842 header, and zstd frame`);
  }
  if (field[0] === VCDIFF) {
    throw refused("a VCDIFF frame (format byte 'v', P2-Z-05), which this release does not read");
  }
  if (field[0] !== ZSTD) {
    throw refused(`unknown format byte 0x${field[0]!.toString(16).padStart(2, "0")}; this release reads 'd' (zstd)`);
  }
  if (!DCZ_MAGIC.every((b, i) => field[1 + i] === b)) {
    throw refused("no RFC 9842 dcz header after the format byte");
  }
  if (base.length > MAX_OUTPUT) {
    throw refused(`a base of ${base.length} bytes is past the chunk bound of ${MAX_OUTPUT} bytes`);
  }
  if (base.length >= 4 && littleEndian32(base, 0) === DICTIONARY_MAGIC) {
    throw refused("a base that starts with the zstd dictionary magic loads as no raw dictionary");
  }
  const digest = cryptoPort().sha256(base);
  if (!digest.every((b, i) => field[1 + DCZ_MAGIC.length + i] === b)) {
    throw refused("the frame names another base than the one held");
  }
  const size = contentSize(field);
  if (frameEnd(field) !== field.length) {
    throw refused("the field holds more than one zstd frame");
  }
  const port = installed;
  if (port === null) {
    throw refused("zstd is not available on this platform");
  }
  let out: Uint8Array;
  try {
    out = port.decompress(field.subarray(HEADER_BYTES), base, size);
  } catch (e) {
    throw refused(`the field is not one zstd frame that opens over the base: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (out.length !== size) {
    throw refused(`the frame wrote ${out.length} bytes where its header declared ${size}`);
  }
  return out;
}

function littleEndian32(bytes: Uint8Array, at: number): number {
  return (bytes[at]! | (bytes[at + 1]! << 8) | (bytes[at + 2]! << 16) | (bytes[at + 3]! << 24)) >>> 0;
}

/** The content size the zstd frame header declares, after the bound checks of the module comment. */
function contentSize(field: Uint8Array): number {
  const at = HEADER_BYTES;
  if (littleEndian32(field, at) !== ZSTD_MAGIC) {
    throw refused("no zstd frame after the RFC 9842 header");
  }
  const descriptor = field[at + 4]!;
  const singleSegment = (descriptor & 0x20) !== 0;
  if ((descriptor & 0x08) !== 0) {
    throw refused("the zstd frame header sets its reserved bit");
  }
  if ((descriptor & 0x03) !== 0) {
    throw refused("the zstd frame names a dictionary id; a base is a raw dictionary with none");
  }
  let p = at + 5;
  let window = -1;
  if (!singleSegment) {
    const w = field[p++]!;
    const windowBase = 2 ** (10 + (w >>> 3));
    window = windowBase + (windowBase / 8) * (w & 0x07);
  }
  const sizeBytes = [singleSegment ? 1 : 0, 2, 4, 8][descriptor >>> 6]!;
  if (sizeBytes === 0) {
    throw refused("the zstd frame declares no content size");
  }
  if (p + sizeBytes > field.length) {
    throw refused("the zstd frame header is cut short");
  }
  let size = 0;
  for (let i = 0; i < sizeBytes; i++) {
    size += field[p + i]! * 2 ** (8 * i);
  }
  if (sizeBytes === 2) {
    size += 256;
  }
  if (size > MAX_OUTPUT) {
    throw refused(`a content size of ${size} bytes is past the chunk bound of ${MAX_OUTPUT} bytes`);
  }
  if (singleSegment) {
    window = size;
  }
  if (window > MAX_OUTPUT) {
    throw refused(`a window of ${window} bytes is past the bound of ${MAX_OUTPUT} bytes`);
  }
  return size;
}

/**
 * Where the first zstd frame of the field ends (RFC 8878 §3.1.1): after its header, its blocks up to the one that sets
 * the last-block bit, and the checksum when the header asks for one. Refuses a frame cut short.
 */
function frameEnd(field: Uint8Array): number {
  const at = HEADER_BYTES;
  const descriptor = field[at + 4]!;
  const singleSegment = (descriptor & 0x20) !== 0;
  let p = at + 5 + (singleSegment ? 0 : 1) + [singleSegment ? 1 : 0, 2, 4, 8][descriptor >>> 6]!;
  for (;;) {
    if (p + 3 > field.length) {
      throw refused("the zstd frame is cut short");
    }
    const header = field[p]! | (field[p + 1]! << 8) | (field[p + 2]! << 16);
    p += 3;
    const type = (header >>> 1) & 0x03;
    if (type === 3) {
      throw refused("the zstd frame holds a block of the reserved type");
    }
    p += type === 1 ? 1 : header >>> 3;
    if (p > field.length) {
      throw refused("the zstd frame is cut short");
    }
    if ((header & 1) !== 0) {
      break;
    }
  }
  return p + ((descriptor & 0x04) !== 0 ? 4 : 0);
}

function refused(why: string): RangeError {
  return new RangeError(`dcz: ${why}`);
}
