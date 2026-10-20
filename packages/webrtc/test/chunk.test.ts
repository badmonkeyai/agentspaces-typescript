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

import assert from "node:assert/strict";
import test from "node:test";
import * as chunk from "../src/chunk.js";

const MAX = chunk.MAX_FRAME;

function reassemble(chunks: Uint8Array[], capacity: number): Uint8Array {
  const r = new chunk.Reassembler(MAX, capacity);
  let out: Uint8Array | null = chunks.length === 0 ? new Uint8Array() : null;
  for (const c of chunks) {
    assert.equal(out, null);
    out = r.accept(c);
  }
  return out!;
}

test("capacity is min(16 KiB, maxMessageSize) - 1 (JS-W-05)", () => {
  assert.equal(chunk.payloadCapacity(0), 16 * 1024 - 1);
  assert.equal(chunk.payloadCapacity(65536), 16 * 1024 - 1);
  assert.equal(chunk.payloadCapacity(1200), 1199);
  assert.equal(chunk.payloadCapacity(2), 1);
  assert.throws(() => chunk.payloadCapacity(1), RangeError);
});

test("split rejects bad inputs before copying", () => {
  assert.throws(() => chunk.split(new Uint8Array(4), 0, MAX), RangeError);
  assert.throws(() => chunk.split(new Uint8Array(MAX + 1), 10, MAX), /exceeds/);
  assert.equal(chunk.split(new Uint8Array(MAX), 16383, MAX).length > 0, true);
  assert.equal(chunk.split(new Uint8Array(0), 10, MAX).length, 0);
  assert.equal(chunk.split(new Uint8Array(1), 1, MAX).length, 1);
});

test("a frame sends ceil(n / C) chunks at every boundary and reassembles", () => {
  const capacity = chunk.payloadCapacity(0);
  for (const n of [0, 1, capacity - 1, capacity, capacity + 1, 2 * capacity, 2 * capacity + 1]) {
    const frame = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      frame[i] = (i * 31 + 7) & 0xff;
    }
    const chunks = chunk.split(frame, capacity, MAX);
    assert.equal(chunks.length, n === 0 ? 0 : Math.ceil(n / capacity));
    chunks.forEach((c, i) => {
      assert.equal(c[0], i === chunks.length - 1 ? chunk.FINAL : chunk.MORE);
      assert.ok(c.length >= 2 && c.length <= capacity + 1);
    });
    assert.deepEqual(reassemble(chunks, capacity), frame);
  }
});

test("a FINAL then MORE stream starts a fresh frame", () => {
  const r = new chunk.Reassembler(MAX, 16);
  assert.deepEqual(r.accept(mk(chunk.FINAL, "one")), enc("one"));
  assert.equal(r.accept(mk(chunk.MORE, "two-")), null);
  assert.deepEqual(r.accept(mk(chunk.FINAL, "three")), enc("two-three"));
});

test("a malformed chunk or oversize frame is a violation and resets state", () => {
  const capacity = chunk.payloadCapacity(0);
  const r = new chunk.Reassembler(4 * capacity, capacity);
  assert.throws(() => r.accept(new Uint8Array([chunk.FINAL])), /empty payload/);
  assert.throws(() => r.accept(new Uint8Array([0x02, 1])), /flags/);
  assert.throws(() => r.accept(new Uint8Array(capacity + 2)), /C \+ 1/);
  assert.equal(r.accept(mk(chunk.MORE, "partial")), null);
  assert.ok(r.pendingBytes() > 0);
  assert.throws(() => r.accept(new Uint8Array([0x7f, 1])), chunk.ProtocolViolation);
  assert.equal(r.pendingBytes(), 0);
  assert.deepEqual(r.accept(mk(chunk.FINAL, "clean")), enc("clean"));
});

test("an accumulated-size overflow is refused at the bound", () => {
  const capacity = chunk.payloadCapacity(0);
  const r = new chunk.Reassembler(4 * capacity, capacity);
  const full = new Uint8Array(capacity + 1);
  full[0] = chunk.MORE;
  for (let i = 0; i < 4; i++) {
    assert.equal(r.accept(full), null);
  }
  assert.throws(() => r.accept(new Uint8Array([chunk.FINAL, 1])), /exceeds/);
  assert.equal(r.pendingBytes(), 0);
});

test("a randomized round trip at many sizes and capacities", () => {
  let seed = 99;
  const rand = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (let i = 0; i < 400; i++) {
    const capacity = 1 + Math.floor(rand() * 4096);
    const n = Math.floor(rand() * 50_000);
    const frame = new Uint8Array(n);
    for (let j = 0; j < n; j++) {
      frame[j] = Math.floor(rand() * 256);
    }
    assert.deepEqual(reassemble(chunk.split(frame, capacity, MAX), capacity), frame);
  }
});

function mk(flags: number, payload: string): Uint8Array {
  const bytes = enc(payload);
  const out = new Uint8Array(1 + bytes.length);
  out[0] = flags;
  out.set(bytes, 1);
  return out;
}

function enc(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
