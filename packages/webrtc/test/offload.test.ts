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
 * The relay offload (SRAD srad/agentspaces-js.md JS-W-11, JS-Q-PRF-03, JS-Q-REL-08) on
 * node-datachannel: the core's `onRelayed` observation stands in as a fake peer that reports the
 * relayed-frame count per member; past the threshold the binding dials the member's `webrtc`
 * endpoint, hands the open channel to the peer as a link, and counts; a dial that cannot complete
 * fails at the dial bound, leaves the relay path as it was, and is not retried before the backoff.
 * Skips when node-datachannel is absent.
 */

type Handler = (from: string, payload: Uint8Array) => void;
type Relayed = (member: string, frames: number) => void;

/** A fake Peer over an in-memory signalling fabric, with the relayed observation and the link adoption recorded. */
class FakeFabric {
  private readonly handlers = new Map<string, Handler>();
  readonly relayedListeners = new Map<string, Relayed[]>();
  readonly adopted = new Map<string, FrameChannel[]>();

  peer(id: string, members: { [peer: string]: { [key: string]: unknown } }) {
    const handlers = this.handlers;
    const listeners: Relayed[] = [];
    this.relayedListeners.set(id, listeners);
    const adopted: FrameChannel[] = [];
    this.adopted.set(id, adopted);
    return {
      identity: { peerId: id },
      endpoints: [] as unknown[],
      members: new Map(Object.entries(members)),
      connected: () => false,
      introduce: () => undefined,
      pipeHandlers: { set: (cap: string, h: Handler) => handlers.set(id + "|" + cap, h) } as unknown as Map<string, Handler>,
      reachable: new Set<string>(),
      registerDialer: () => undefined,
      acceptChannel: (channel: FrameChannel) => adopted.push(channel),
      onRelayed: (listener: Relayed) => listeners.push(listener),
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

  /** What the core would do on each frame a relay carried for the pair: tell the binding the count. */
  relayed(id: string, member: string, frames: number): void {
    for (const listener of this.relayedListeners.get(id) ?? []) {
      listener(member, frames);
    }
  }
}

const BOB_AD = { endpoints: [{ transport: "webrtc", address: "sig", priority: 0 }] };

test("past the threshold the binding dials the member, adopts the channel as a link, and counts (JS-W-11, JS-Q-PRF-03)", async (t) => {
  try {
    await loadRtc();
  } catch {
    t.skip("node-datachannel is not installed");
    return;
  }
  const fabric = new FakeFabric();
  const options = { dialTimeoutMillis: 20_000, offloadFramesPerMinute: 30 };
  let accepted: FrameChannel | null = null;
  const bobBinding = await WebRtcBinding.install(fabric.peer("B", {}), options, (channel) => { accepted = channel; });
  const aliceBinding = await WebRtcBinding.install(fabric.peer("A", { B: BOB_AD }), options);
  for (let i = 1; i <= 30; i++) {
    fabric.relayed("A", "B", i); // thirty is not more than thirty
  }
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(aliceBinding.counters.offloadAttempts, 0);
  fabric.relayed("A", "B", 31);
  fabric.relayed("A", "B", 32); // a second report while the dial is pending does not dial again
  await waitFor(() => fabric.adopted.get("A")!.length === 1 && accepted !== null, 15_000);
  assert.equal(aliceBinding.counters.offloadAttempts, 1);
  assert.equal(aliceBinding.counters.offloadOpened, 1);
  assert.equal(aliceBinding.counters.offloadFailed, 0);
  assert.equal(aliceBinding.counters.sessionsOpened, 1);
  const toBob = fabric.adopted.get("A")![0];
  assert.equal(toBob.attestedPeer(), "B");
  // The link carries the pair's frames from here on; the relay would carry none.
  const atBob: Uint8Array[] = [];
  (accepted as unknown as FrameChannel).onFrame((f) => atBob.push(f));
  toBob.send(new TextEncoder().encode("direct"));
  await waitFor(() => atBob.length === 1, 5_000);
  assert.deepEqual(atBob[0], new TextEncoder().encode("direct"));
  // Nothing dials a member without a webrtc endpoint, nor one already reachable.
  fabric.relayed("A", "C", 100);
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(aliceBinding.counters.offloadAttempts, 1);
  toBob.close();
  (accepted as unknown as FrameChannel).close();
  aliceBinding.close();
  bobBinding.close();
});

test("a dial that cannot complete fails at the dial bound, keeps the relay path, and is not retried before the backoff (JS-Q-REL-08)", async (t) => {
  try {
    await loadRtc();
  } catch {
    t.skip("node-datachannel is not installed");
    return;
  }
  const fabric = new FakeFabric();
  // Bob has no binding: the offer finds no handler, nothing answers, and the dial times out.
  const options = { dialTimeoutMillis: 400, offloadFramesPerMinute: 30, offloadRetryMillis: 600 };
  const aliceBinding = await WebRtcBinding.install(fabric.peer("A", { B: BOB_AD }), options);
  const started = Date.now();
  fabric.relayed("A", "B", 31);
  await waitFor(() => aliceBinding.counters.offloadFailed === 1, 5_000);
  assert.ok(Date.now() - started < 15_000, "fell back within the dial bound");
  assert.equal(aliceBinding.counters.offloadAttempts, 1);
  assert.equal(aliceBinding.counters.failed["timeout"], 1);
  assert.equal(fabric.adopted.get("A")!.length, 0, "the relay path is as it was");
  assert.equal(aliceBinding.pendingSessions(), 0);
  // Heavy traffic inside the backoff earns no second dial ...
  for (let i = 32; i < 60; i++) {
    fabric.relayed("A", "B", i);
  }
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(aliceBinding.counters.offloadAttempts, 1);
  // ... and once it has passed, one more.
  await new Promise((r) => setTimeout(r, 650));
  fabric.relayed("A", "B", 60);
  await waitFor(() => aliceBinding.counters.offloadAttempts === 2, 1_000);
  await waitFor(() => aliceBinding.counters.offloadFailed === 2, 5_000);
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
