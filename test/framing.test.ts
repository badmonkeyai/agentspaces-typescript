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
 * The low-level copy sites of the transports at their boundaries: the tcp
 * length-prefixed framing (a frame arriving in many small reads costs
 * bounded copying; frames split across reads and packed into one read are
 * both exact; a hostile prefix drops the connection), and the exchange batch
 * codec (every bound judged before a copy, on both the encoder and the decoder).
 */

import assert from "node:assert/strict";
import { createServer, connect, Server, Socket } from "node:net";
import test from "node:test";

import { decodeBatch, encodeBatch } from "../src/transport/http.js";
import { TcpChannel } from "../src/node/tcp.js";
import { MAX_FRAME_BYTES } from "../src/wire.js";
import { int32be, concat } from "../src/bytes.js";

/** A listening server handing its accepted socket to a TcpChannel, and a client socket to feed it. */
async function pair(): Promise<{ channel: TcpChannel; client: Socket; server: Server; frames: Uint8Array[]; closed: Promise<string> }> {
  const frames: Uint8Array[] = [];
  let channel!: TcpChannel;
  let resolveClosed!: (reason: string) => void;
  const closed = new Promise<string>((r) => { resolveClosed = r; });
  const accepted = new Promise<void>((ready) => {
    const server = createServer((socket) => {
      channel = new TcpChannel(socket, "test");
      channel.onFrame((f) => frames.push(f));
      channel.onClose(resolveClosed);
      ready();
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      const client = connect(port, "127.0.0.1");
      client.once("connect", () => { (pair as unknown as { last: unknown }).last = { client, server }; });
    });
    (pair as unknown as { srv: Server }).srv = server;
  });
  await accepted;
  // Wait for the client's connect event to have fired.
  while ((pair as unknown as { last?: { client: Socket; server: Server } }).last === undefined) {
    await new Promise((r) => setTimeout(r, 5));
  }
  const { client, server } = (pair as unknown as { last: { client: Socket; server: Server } }).last;
  (pair as unknown as { last: unknown }).last = undefined;
  return { channel, client, server, frames, closed };
}

function write(client: Socket, bytes: Uint8Array, chunk: number): Promise<void> {
  return new Promise((resolve) => {
    let offset = 0;
    const step = (): void => {
      if (offset >= bytes.length) {
        resolve();
        return;
      }
      const end = Math.min(bytes.length, offset + chunk);
      client.write(bytes.subarray(offset, end), () => { offset = end; setImmediate(step); });
    };
    step();
  });
}

async function until(condition: () => boolean, millis: number): Promise<void> {
  const deadline = Date.now() + millis;
  while (!condition()) {
    if (Date.now() > deadline) {
      throw new Error("condition not met in time");
    }
    await new Promise((r) => setTimeout(r, 5));
  }
}

test("a frame of the largest size arriving in small reads is delivered exactly, with bounded copying", async () => {
  const { client, server, frames } = await pair();
  try {
    const frame = new Uint8Array(MAX_FRAME_BYTES);
    for (let i = 0; i < frame.length; i += 4099) {
      frame[i] = (i >> 3) & 0xff;
    }
    const started = Date.now();
    await write(client, concat(int32be(frame.length), frame), 16 * 1024); // 512 reads at least
    await until(() => frames.length === 1, 20_000);
    const elapsed = Date.now() - started;
    assert.equal(frames[0].length, frame.length);
    assert.ok(frames[0].every((b, i) => b === frame[i]), "bytes exact");
    assert.ok(elapsed < 10_000, `an 8 MiB frame in 16 KiB reads took ${elapsed} ms (quadratic copying would take far longer)`);
  } finally {
    client.destroy();
    server.close();
  }
});

test("frames split across reads at the prefix and packed several to a read are both exact", async () => {
  const { client, server, frames } = await pair();
  try {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array(70_000).fill(7);
    const c = new Uint8Array([9]);
    const stream = concat(int32be(a.length), a, int32be(b.length), b, int32be(c.length), c);
    // Reads of 2 bytes split every prefix; then the whole rest in one read.
    await write(client, stream.subarray(0, 6), 2);
    await write(client, stream.subarray(6), stream.length);
    await until(() => frames.length === 3, 5000);
    assert.deepEqual([...frames[0]], [1, 2, 3]);
    assert.equal(frames[1].length, 70_000);
    assert.deepEqual([...frames[2]], [9]);
  } finally {
    client.destroy();
    server.close();
  }
});

test("a hostile length prefix drops the connection rather than looping or allocating (ASF-014/016)", async () => {
  for (const bad of [0, -1, MAX_FRAME_BYTES + 1, 0x7fffffff]) {
    const { client, server, frames, closed } = await pair();
    try {
      await write(client, concat(int32be(bad), new Uint8Array(8)), 12);
      const reason = await Promise.race([closed, new Promise<string>((r) => setTimeout(() => r("still open"), 3000))]);
      assert.notEqual(reason, "still open", `prefix ${bad} dropped the connection`);
      assert.equal(frames.length, 0);
    } finally {
      client.destroy();
      server.close();
    }
  }
});

test("the exchange batch codec judges every bound before copying, on both sides", () => {
  const frames = [new Uint8Array([1]), new Uint8Array(65_536).fill(2), new Uint8Array(MAX_FRAME_BYTES)];
  const decoded = decodeBatch(encodeBatch(frames));
  assert.equal(decoded.length, 3);
  assert.equal(decoded[2].length, MAX_FRAME_BYTES);
  assert.deepEqual([...decoded[0]], [1]);
  assert.deepEqual(decodeBatch(encodeBatch([])), []);
  assert.throws(() => encodeBatch([new Uint8Array(0)]), /1 to/);
  assert.throws(() => encodeBatch([new Uint8Array(MAX_FRAME_BYTES + 1)]), /1 to/);
  assert.throws(() => encodeBatch(Array.from({ length: 65 }, () => new Uint8Array(1))), /frames in one body/);
  assert.throws(() => encodeBatch([new Uint8Array(MAX_FRAME_BYTES), new Uint8Array(MAX_FRAME_BYTES)]), /exceeds/);
  for (const length of [0, -1, -2147483648, 2147483647, MAX_FRAME_BYTES + 1, 5]) {
    assert.throws(() => decodeBatch(concat(int32be(length), new Uint8Array(4))), /bad frame length/, `length ${length}`);
  }
  assert.throws(() => decodeBatch(new Uint8Array([0, 0, 1])), /truncated/);
  assert.throws(() => decodeBatch(concat(int32be(4), new Uint8Array(3))), /bad frame length/);
  assert.throws(() => decodeBatch(new Uint8Array(9 * 1024 * 1024 + 1)), /body exceeds/);
  const many = concat(...Array.from({ length: 65 }, () => concat(int32be(1), new Uint8Array([1]))));
  assert.throws(() => decodeBatch(many), /frames in one body/);
});
