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
 * The verbs of srad/agentspaces-js.md phase 3 at the visitor residency:
 * the leased push subscription (JS-V-01), the fold-driven take that pulls at
 * most once per settle window (JS-V-02, JS-Q-PRF-01), and MAJORITY_GOSSIP's
 * preference epochs (JS-V-04).
 */

import assert from "node:assert/strict";
import test from "node:test";

import { dumps } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import { Space, Template, entry } from "../src/space.js";
import { ChannelEvents, FrameChannel } from "../src/transport.js";
import * as vote from "../src/vote.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const GROUP = "verbs-residency-group";

class Task {
  constructor(public topic = "", public priority = 0) {}
}
entry("com.acme.Task#v1")(Task);

/** A peer on an in-memory channel whose sent frames are decoded and kept. */
function peerWithChannel(): { peer: Peer; sent: Dict[]; events: ChannelEvents } {
  const peer = new Peer(Identity.generate(), GROUP);
  const events = new ChannelEvents();
  const sent: Dict[] = [];
  const channel: FrameChannel = { scheme: "mem", remote: "mem", attestedPeer: () => null,
    send: (f) => { const env = wire.decodeFrame(f); if (env) sent.push(env); },
    onFrame: (r) => events.onFrame(r), onClose: (l) => events.onClose(l), close: () => events.close("closed") };
  peer.registerDialer({ scheme: "mem", dial: async () => channel });
  return { peer, sent, events };
}

test("a leased subscription lapses unless renewed, and the binder's renewal keeps it (JS-V-01)", async () => {
  const { peer } = peerWithChannel();
  await peer.connectAny([{ host: "x", port: 1, scheme: "mem" }]);
  const space = new Space(peer, "tasks");
  const seen: string[] = [];
  const short = space.notify(new Template(Task), (e) => seen.push(e.entry.value.topic), 150);
  const renewed = space.notify(new Template(Task), () => undefined, 150);
  const closes: string[] = [];
  short.on("close", (reason: string) => closes.push(reason));
  space.write(new Task("one", 1));
  assert.deepEqual(seen, ["one"]);
  await new Promise((r) => setTimeout(r, 100));
  renewed.renew();
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(short.open, false, "the unrenewed subscription lapsed");
  assert.deepEqual(closes, ["lapsed"]);
  assert.equal(renewed.open, true, "the renewed one is still open");
  space.write(new Task("two", 1));
  assert.deepEqual(seen, ["one"], "a lapsed subscription delivers nothing");
  renewed.close();
  assert.equal(renewed.open, false);
  peer.close();
});

test("a waiting take pulls at most once per settle window and wakes on a fold (JS-V-02, JS-Q-PRF-01)", async () => {
  const { peer, sent, events } = peerWithChannel();
  await peer.connectAny([{ host: "x", port: 1, scheme: "mem" }]);
  const other = new Peer(Identity.generate(), GROUP);
  const space = new Space(peer, "tasks");
  const digestsBefore = sent.filter((e) => e["kind"] === "DIGEST").length;
  const started = Date.now();
  const taking = space.take(new Template(Task), "1m", "10s");
  // While nothing folds, the take waits: a settle window (600 ms) passes with one DIGEST per window.
  await new Promise((r) => setTimeout(r, 1300));
  const digestsWhileWaiting = sent.filter((e) => e["kind"] === "DIGEST").length - digestsBefore;
  assert.ok(digestsWhileWaiting >= 2 && digestsWhileWaiting <= 3, `one pull per settle window, saw ${digestsWhileWaiting}`);
  // The entry folds from another peer's rumor: the take wakes at once and claims it.
  const { body } = wire.entryDelta("tasks", GROUP, "com.acme.Task#v1", dumps({ topic: "index", priority: 5 }),
    other.identity, "writer", 600_000);
  events.deliver(wire.encodeFrame(wire.envelope(GROUP, "RUMOR", other.identity.peerId,
    wire.hlcNow(other.identity.peerId), body, peer.identity.peerId), other.identity));
  const taken = await taking;
  assert.ok(taken !== null, "taken after the fold");
  assert.equal(taken!.value.topic, "index");
  assert.ok(Date.now() - started < 5000, "the take did not wait for its timeout");
  taken!.complete();
  peer.close();
  other.close();
});

test("MAJORITY_GOSSIP casts over the vote's preference epochs and reads the leader (JS-V-04)", () => {
  const started = new Map<string, number>();
  const aggregate = {
    start: (epochId: string, value: number) => { started.set(epochId, value); },
    estimate: (epochId: string) => started.get(epochId) ?? null,
  };
  vote.castPreference(aggregate, "lunch", ["pizza", "sushi", "salad"], "sushi");
  assert.deepEqual([...started.entries()],
    [["vote:lunch:pizza", 0], ["vote:lunch:sushi", 1], ["vote:lunch:salad", 0]], "VoteCapability.epoch names");
  assert.equal(vote.leader(aggregate, "lunch", ["pizza", "sushi", "salad"]), "sushi");
  assert.equal(vote.leader(aggregate, "dinner", ["a"]), null);
});
