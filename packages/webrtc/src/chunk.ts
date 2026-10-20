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
 * The data-channel chunk of SRAD srad/agentspaces-js.md appendix B (JS-W-05, JS-F-01): one flags
 * byte (`0x00` final, `0x01` more) then 1 to `C` payload bytes, `C = min(16 KiB, maxMessageSize) -
 * 1`. A frame is the concatenation of consecutive payloads up to the first final chunk; nothing
 * carries a length, an index, or a checksum, because the channel is ordered and reliable and DTLS
 * authenticates every record. The byte-for-byte twin of the Java `Chunks` class.
 */

export const CHUNK_CEILING = 16 * 1024;
export const FINAL = 0x00;
export const MORE = 0x01;
/** The reassembly bound (JS-W-05): a frame over this closes the connection. */
export const MAX_FRAME = 8 * 1024 * 1024;

/** `C`: the payload bytes one chunk may carry for a remote advertising `maxMessageSize`. */
export function payloadCapacity(remoteMaxMessageSize: number): number {
  const message = remoteMaxMessageSize <= 0 ? CHUNK_CEILING : Math.min(CHUNK_CEILING, remoteMaxMessageSize);
  if (message < 2) {
    throw new RangeError(`maxMessageSize too small for one chunk: ${remoteMaxMessageSize}`);
  }
  return message - 1;
}

/**
 * The `ceil(n / C)` chunks of a frame of `n` bytes, `C = capacity`; an empty frame has no chunk.
 * Inputs are validated before any copy: a capacity below 1, or a frame longer than `maxFrame`, is
 * rejected naming the bound, so the slicing below stays obviously in range
 * (`offset + take <= frame.length`). One `subarray` view and one copy per chunk; no concatenation.
 */
export function split(frame: Uint8Array, capacity: number, maxFrame = MAX_FRAME): Uint8Array[] {
  if (!(frame instanceof Uint8Array)) {
    throw new TypeError("frame must be a Uint8Array");
  }
  if (!Number.isInteger(capacity) || capacity < 1) {
    throw new RangeError(`chunk capacity must be a positive integer, not ${capacity}`);
  }
  if (frame.length > maxFrame) {
    throw new RangeError(`frame of ${frame.length} bytes exceeds the ${maxFrame}-byte bound`);
  }
  const out: Uint8Array[] = [];
  let offset = 0;
  while (offset < frame.length) {
    const take = Math.min(capacity, frame.length - offset); // offset + take <= frame.length
    const chunk = new Uint8Array(1 + take);
    chunk[0] = offset + take < frame.length ? MORE : FINAL;
    chunk.set(frame.subarray(offset, offset + take), 1);
    out.push(chunk);
    offset += take;
  }
  return out;
}

/** A chunk the receiver must close the connection on, with `END(3)`. */
export class ProtocolViolation extends Error {}

/** Reassembles frames from consecutive chunks, bounded by `maxFrame` and `C + 1` per chunk. */
export class Reassembler {
  private readonly parts: Uint8Array[] = [];
  private pending = 0;

  constructor(private readonly maxFrame: number, private readonly capacity: number) {}

  /** Bytes of an unfinished frame held, for tests. */
  pendingBytes(): number {
    return this.pending;
  }

  /**
   * The frame the chunk completes, or null while more chunks are due. Every violation (`END(3)` to
   * the sender) discards any partial frame first, so the reassembler is reusable.
   */
  accept(message: Uint8Array): Uint8Array | null {
    if (message.length < 2) {
      throw this.violation("chunk with an empty payload");
    }
    if (message.length > this.capacity + 1) {
      throw this.violation(`chunk of ${message.length} bytes exceeds C + 1 = ${this.capacity + 1}`);
    }
    const flags = message[0];
    if (flags !== FINAL && flags !== MORE) {
      throw this.violation(`chunk flags 0x${flags!.toString(16)}`);
    }
    const payload = message.subarray(1); // length - 1, in 1..capacity
    if (this.pending + payload.length > this.maxFrame) {
      throw this.violation(`frame exceeds ${this.maxFrame} bytes`);
    }
    if (flags === FINAL && this.parts.length === 0) {
      return payload.slice(); // single-chunk frame: one copy, independent of the channel buffer
    }
    this.parts.push(payload.slice());
    this.pending += payload.length;
    if (flags === MORE) {
      return null;
    }
    const frame = new Uint8Array(this.pending);
    let offset = 0;
    for (const part of this.parts) {
      frame.set(part, offset);
      offset += part.length;
    }
    this.parts.length = 0;
    this.pending = 0;
    return frame;
  }

  private violation(message: string): ProtocolViolation {
    this.parts.length = 0; // discard any partial frame: a violation resets the reassembler
    this.pending = 0;
    return new ProtocolViolation(message);
  }
}
