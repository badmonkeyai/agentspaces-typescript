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
 * The cell's dialer wrapper under concurrent seed dials (owner decision 3 of 2026-11-23): a dial stays "in flight"
 * until every concurrent dial has settled, so the alarm cannot start a second join over the first, and only the
 * channel that is the peer's link reports a lost link, so the losers of a round neither re-arm the alarm nor move
 * the redial table.
 */

import assert from "node:assert/strict";
import test from "node:test";
import { MemoryChannel } from "@agentspaces/client";
import type { Dialer, FrameChannel, Seed } from "@agentspaces/client";
import { DialTracker, TrackedDialer } from "../src/tracked.js";

/** A dialer whose dials answer only when the test says, one deferred per seed host. */
function heldDialer(): { dialer: Dialer; answer: Map<string, { ok: (c: FrameChannel) => void; fail: (e: Error) => void }> } {
  const answer = new Map<string, { ok: (c: FrameChannel) => void; fail: (e: Error) => void }>();
  return { answer, dialer: { scheme: "ws", dial: (seed: Seed) => new Promise<FrameChannel>((ok, fail) => {
    answer.set(seed.host, { ok, fail });
  }) } };
}

test("a dial stays in flight until every concurrent dial has settled, across the cell's ws and wss dialers", async () => {
  const tracker = new DialTracker();
  const ws = heldDialer();
  const wss = heldDialer();
  const a = new TrackedDialer(ws.dialer, tracker, () => undefined, () => null);
  const b = new TrackedDialer(wss.dialer, tracker, () => undefined, () => null);
  const one = a.dial({ host: "one", port: 1 }).catch(() => null);
  const two = a.dial({ host: "two", port: 1 }).catch(() => null);
  const three = b.dial({ host: "three", port: 1 }).catch(() => null);
  assert.equal(tracker.dialing, true);
  ws.answer.get("one")!.fail(new Error("refused"));
  await one;
  assert.equal(tracker.dialing, true, "a refused seed while another is still being dialled is no idle dialer");
  ws.answer.get("two")!.ok(MemoryChannel.pair("two", "d:two")[0]);
  await two;
  assert.equal(tracker.dialing, true, "the wss dial is still out");
  wss.answer.get("three")!.fail(new Error("refused"));
  await three;
  assert.equal(tracker.dialing, false);
});

test("only the channel that is the peer's link reports its end; a round's losers and an early drop do not", async () => {
  const tracker = new DialTracker();
  const held = heldDialer();
  const ended: number[] = [];
  let link: FrameChannel | null = null;
  const dialer = new TrackedDialer(held.dialer, tracker, (linkedAt) => { ended.push(linkedAt); }, () => link);
  const [winner] = MemoryChannel.pair("w", "d:w");
  const [loser] = MemoryChannel.pair("l", "d:l");
  const w = dialer.dial({ host: "w", port: 1 });
  const l = dialer.dial({ host: "l", port: 1 });
  held.answer.get("w")!.ok(winner);
  held.answer.get("l")!.ok(loser);
  await Promise.all([w, l]);
  link = winner; // the peer adopted the winner
  loser.close(); // and closed the loser, as another seed answered first
  assert.deepEqual(ended, [], "a losing dial is no lost link");
  winner.close();
  assert.equal(ended.length, 1, "the link's end is reported");
  link = null; // the peer's own close listener runs after the dialer's
  const [early] = MemoryChannel.pair("e", "d:e");
  const e = dialer.dial({ host: "e", port: 1 });
  held.answer.get("e")!.ok(early);
  await e;
  early.close(); // dropped before the peer adopted it: the alarm the join's caller arms covers it
  assert.equal(ended.length, 1);
});
