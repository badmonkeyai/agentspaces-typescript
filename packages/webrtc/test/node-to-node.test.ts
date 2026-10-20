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
import type { FrameChannel } from "@agentspaces/client";
import { WebRtcBinding, loadRtc } from "../src/binding.js";

/**
 * Two bindings in one Node process over node-datachannel's polyfill (JS-W-02, JS-W-04, JS-W-05):
 * an in-memory signalling fabric stands in for the fleet's relay, the channel opens on host
 * candidates, and the frames cross chunked and attested. Skips when node-datachannel is absent.
 */

type Handler = (from: string, payload: Uint8Array) => void;

/** A fake Peer: the two bindings' pipe handlers wired to each other, delivery on a microtask. */
class FakeFabric {
  private readonly handlers = new Map<string, Handler>();

  peer(id: string) {
    const handlers = this.handlers;
    return {
      identity: { peerId: id },
      endpoints: [] as unknown[],
      connected: () => false,
      introduce: () => undefined,
      pipeHandlers: { set: (cap: string, h: Handler) => handlers.set(id + "|" + cap, h) } as unknown as Map<string, Handler>,
      reachable: new Set<string>(["A", "B"].filter((x) => x !== id)),
      registerDialer: () => undefined,
      acceptChannel: () => undefined,
      relayMembers: () => [],
      sendPipeOrRelay: (to: string, cap: string, payload: Uint8Array): boolean => {
        const h = handlers.get(to + "|" + cap);
        if (h === undefined) {
          return false;
        }
        queueMicrotask(() => h(id, payload));
        return true;
      },
    } as never;
  }
}

test("two node-datachannel bindings open a channel and exchange chunked frames", async (t) => {
  try {
    await loadRtc();
  } catch {
    t.skip("node-datachannel is not installed");
    return;
  }
  const fabric = new FakeFabric();
  const options = { dialTimeoutMillis: 20_000 };
  let accepted!: FrameChannel;
  const acceptor = new Promise<FrameChannel>((resolve) => {
    void WebRtcBinding.install(fabric.peer("B"), options, (channel) => {
      accepted = channel;
      resolve(channel);
    });
  });
  const aliceBinding = await WebRtcBinding.install(fabric.peer("A"), options);
  const [toBob, fromAlice] = await Promise.all([aliceBinding.connect("B"), acceptor]);
  assert.equal(toBob.attestedPeer(), "B");
  assert.equal(fromAlice.attestedPeer(), "A");
  assert.ok(toBob.remote.startsWith("sig/"));
  assert.ok(!toBob.remote.includes("192.")); // JS-W-13: no candidate address on the channel's name

  const atBob: Uint8Array[] = [];
  const atAlice: Uint8Array[] = [];
  fromAlice.onFrame((f) => atBob.push(f));
  toBob.onFrame((f) => atAlice.push(f));
  const small = new TextEncoder().encode("hello");
  const big = new Uint8Array(200_000);
  for (let i = 0; i < big.length; i++) {
    big[i] = (i * 37 + 11) & 0xff;
  }
  toBob.send(small);
  toBob.send(big);
  fromAlice.send(new TextEncoder().encode("pong"));

  await waitFor(() => atBob.length >= 2 && atAlice.length >= 1, 15_000);
  assert.deepEqual(atBob[0], small);
  assert.deepEqual(atBob[1], big);
  assert.deepEqual(atAlice[0], new TextEncoder().encode("pong"));
  assert.ok(aliceBinding.counters.chunksSent >= 1 + Math.ceil(big.length / 16383));
  assert.equal(aliceBinding.counters.sessionsOpened, 1);

  toBob.close();
  accepted.close();
  aliceBinding.close();
});

async function waitFor(condition: () => boolean, millis: number): Promise<void> {
  const deadline = Date.now() + millis;
  while (!condition()) {
    if (Date.now() > deadline) {
      throw new Error("timed out");
    }
    await new Promise((r) => setTimeout(r, 25));
  }
}
