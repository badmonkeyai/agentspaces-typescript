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
 * The content-defined chunker (srad/agentspaces-pdt.md §3.3, PD-B-01, §10.2): FastCDC in the per-byte
 * form with normalized chunking level 2 and cut-point skipping. Minimum 16 KiB, average 64 KiB,
 * maximum 256 KiB. `GEAR[i]` is the big-endian uint64 of the first 8 bytes of sha256 of the single
 * byte `i`; the rolling hash is `h = (h << 1) + GEAR[b]` over unsigned 64 bits, kept here as two
 * 32-bit halves; MaskS = `0xFFFFC00000000000` before the average size and MaskL = `0xFFFC000000000000`
 * after it. A chunk ends at index `i` when, after folding byte `i` into `h`, `(h & mask) == 0`, else
 * at the maximum; a run of at most the minimum is one chunk. The Java, Python, and TypeScript
 * chunkers cut `pdt_fastcdc_cuts` at the same offsets.
 */

import { cryptoPort } from "../crypto.js";

export const MIN_SIZE = 16 * 1024;
export const AVG_SIZE = 64 * 1024;
export const MAX_SIZE = 256 * 1024;
/** The high 32 bits of MaskS and MaskL; the low 32 bits of both are zero. */
const MASK_S_HI = 0xffffc000;
const MASK_L_HI = 0xfffc0000;

let gearHi: Uint32Array | null = null;
let gearLo: Uint32Array | null = null;

function gear(): [Uint32Array, Uint32Array] {
  if (gearHi === null || gearLo === null) {
    gearHi = new Uint32Array(256);
    gearLo = new Uint32Array(256);
    const sha256 = cryptoPort().sha256;
    for (let i = 0; i < 256; i++) {
      const digest = sha256(Uint8Array.of(i));
      const view = new DataView(digest.buffer, digest.byteOffset, digest.byteLength);
      gearHi[i] = view.getUint32(0, false);
      gearLo[i] = view.getUint32(4, false);
    }
  }
  return [gearHi, gearLo];
}

/** The gear table as 64-bit values, for tests and tools. */
export function gearTable(): bigint[] {
  const [hi, lo] = gear();
  return Array.from({ length: 256 }, (_, i) => (BigInt(hi[i]!) << 32n) | BigInt(lo[i]!));
}

/** The length of the first chunk of `data[offset, offset + length)`. */
export function cut(data: Uint8Array, offset: number, length: number): number {
  if (offset < 0 || length < 0 || offset + length > data.length) {
    throw new RangeError(`range ${offset}+${length} outside ${data.length} bytes`);
  }
  let n = length;
  if (n <= MIN_SIZE) {
    return n;
  }
  let normal = AVG_SIZE;
  if (n >= MAX_SIZE) {
    n = MAX_SIZE;
  } else if (n <= normal) {
    normal = n;
  }
  const [gHi, gLo] = gear();
  let hi = 0, lo = 0;
  let i = MIN_SIZE;
  for (; i < normal; i++) {
    const b = data[offset + i]!;
    const shiftedHi = ((hi << 1) | (lo >>> 31)) >>> 0;
    const shiftedLo = (lo << 1) >>> 0;
    const sum = shiftedLo + gLo[b]!;
    lo = sum >>> 0;
    hi = (shiftedHi + gHi[b]! + (sum > 0xffffffff ? 1 : 0)) >>> 0;
    if ((hi & MASK_S_HI) === 0) {
      return i;
    }
  }
  for (; i < n; i++) {
    const b = data[offset + i]!;
    const shiftedHi = ((hi << 1) | (lo >>> 31)) >>> 0;
    const shiftedLo = (lo << 1) >>> 0;
    const sum = shiftedLo + gLo[b]!;
    lo = sum >>> 0;
    hi = (shiftedHi + gHi[b]! + (sum > 0xffffffff ? 1 : 0)) >>> 0;
    if ((hi & MASK_L_HI) === 0) {
      return i;
    }
  }
  return i;
}

/** The cut points (chunk end offsets) of a byte array, in order. */
export function cuts(data: Uint8Array): number[] {
  const out: number[] = [];
  let offset = 0;
  while (offset < data.length) {
    offset += cut(data, offset, data.length - offset);
    out.push(offset);
  }
  return out;
}

/** The chunks of a byte array, as views into it. */
export function chunksOf(data: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  let start = 0;
  for (const end of cuts(data)) {
    out.push(data.subarray(start, end));
    start = end;
  }
  return out;
}
