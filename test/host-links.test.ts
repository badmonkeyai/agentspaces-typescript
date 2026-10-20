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
 * A peer that accepts connections (srad/agentspaces-js.md JS-R-04, the
 * serving half of the core): over the in-memory transport, a hub with two
 * dial-only members relays each one's rumors to the other, answers a DIGEST
 * in `ReplicatedSpace`'s formats with exactly what the asker lacks, relays a
 * PING_REQ and vouches for the target, keeps one session per link, forgets a
 * member whose advertisement lapsed, and loses nothing when a link ends.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { dumps, loads } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import { MemoryNetwork, settle } from "../src/transport/mem.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";

const GROUP = "zHubGroup";
const TASK = "com.acme.Task#v1";

/** A hub listening on `hub:1` and `n` dial-only members connected to it. */
async function fleet(n: number, auth: "session" | "signed" = "session"): Promise<{ hub: Peer; members: Peer[]; net: MemoryNetwork; stop: () => void }> {
  const net = new MemoryNetwork();
  const hub = new Peer(Identity.generate(), GROUP);
  hub.channelAuth = auth;
  hub.endpoints.push({ transport: "mem", address: "hub:1", priority: 0 });
  const closeListener = await net.listen("hub:1", (channel) => hub.acceptChannel(channel));
  hub.pullSpace("tasks"); // the hub serves the space it registered
  const members: Peer[] = [];
  for (let i = 0; i < n; i++) {
    const member = new Peer(Identity.generate(), GROUP);
    member.channelAuth = auth;
    member.registerDialer(net.dialer());
    await member.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    members.push(member);
  }
  await settle();
  return { hub, members, net, stop: () => { closeListener(); hub.close(); members.forEach((m) => m.close()); } };
}

test("a hub relays one member's writes to the other and both see the hub's endpoint (JS-R-04)", async () => {
  const { hub, members: [a, b], stop } = await fleet(2);
  try {
    assert.equal(hub.inbound.size, 2);
    assert.ok(hub.reachable.has(a.identity.peerId) && hub.reachable.has(b.identity.peerId), "both heard on their links");
    assert.deepEqual(hub.linkedMembers().sort(), [a.identity.peerId, b.identity.peerId].sort());
    const id = a.writeEntry("tasks", TASK, { topic: "relayed" }, "a");
    await settle();
    assert.ok(hub.states.has(id), "the hub folded the write");
    assert.ok(b.states.has(id), "the hub forwarded the rumor to the other link");
    assert.equal(hub.rumorsForwarded >= 1, true);
    assert.equal(a.states.size, 1, "the origin never received its own rumor twice as new state");
    const ad = b.members.get(hub.identity.peerId);
    assert.equal(JSON.stringify(ad?.["endpoints"]), JSON.stringify([{ transport: "mem", address: "hub:1", priority: 0 }]));
    assert.ok(a.members.has(b.identity.peerId), "the peers stream travelled through the hub");
  } finally {
    stop();
  }
});

test("a DIGEST in ReplicatedSpace's format is answered with exactly what the asker lacks", async () => {
  const { hub, members: [a], net, stop } = await fleet(2);
  try {
    const first = a.writeEntry("tasks", TASK, { topic: "one" }, "a");
    await settle();
    // A late member pulls with an empty digest and receives the entry.
    const late = new Peer(Identity.generate(), GROUP);
    late.registerDialer(net.dialer());
    await late.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    late.pullSpace("tasks");
    await settle();
    assert.ok(late.states.has(first), "the empty digest pulled everything");
    assert.ok(hub.pullsAnswered >= 1, "the hub answered the pull (the view pulls of connectAny count too)");
    // The hub's own digest sent back to it names everything it holds: nothing to send, no PULL_RESP.
    const digest = hub.spaceDigest("tasks");
    assert.match(new TextDecoder().decode(digest), new RegExp(`^e:${first}=[0-9a-f]{1,8}\\n$`));
    assert.equal(hub.spaceDeltaFor("tasks", digest).length, 0);
    // A digest naming the entry at another hash (a stale completion flag) gets the entry again.
    const stale = new TextEncoder().encode(`e:${first}=deadbeef\n`);
    const delta = loads(hub.spaceDeltaFor("tasks", stale)) as Dict;
    assert.equal((delta["states"] as Dict[]).length, 1);
    // A refused-and-acknowledged line (ASF-047) stops the re-offer.
    const acked = new TextEncoder().encode(`a:e:${first}=${new TextDecoder().decode(digest).split("=")[1].trim()}\n`);
    assert.equal(hub.spaceDeltaFor("tasks", acked).length, 0);
    // The ads stream: the hub answers with the cards the asker's hashed digest does not name.
    late.pullAds();
    await settle();
    assert.ok(hub.adsDigest().length >= 32);
    late.close();
  } finally {
    stop();
  }
});

test("a PING_REQ through the hub pings the target and vouches for it to the asker (SWIM indirect probe)", async () => {
  const { hub, members: [a, b], stop } = await fleet(2);
  try {
    const acks: Dict[] = [];
    // Observe what A receives by tapping its frame handler through the public counters: an ACK
    // addressed to A with onBehalf set is what the relay produces.
    const seen = new Promise<Dict>((resolve) => {
      const previous = (a as unknown as { handle(env: Dict, link: unknown): void }).handle;
      (a as unknown as { handle(env: Dict, link: unknown): void }).handle = function (env: Dict, link: unknown) {
        if (env["kind"] === "ACK") {
          const ack = loads(env["body"] as Uint8Array) as Dict;
          acks.push(ack);
          if (ack["onBehalf"] !== null) {
            resolve(ack);
          }
        }
        return previous.call(this, env, link);
      };
    });
    (a as unknown as { send(kind: string, body: Uint8Array, to: string | null): void })
      .send("PING_REQ", dumps({ target: b.identity.peerId, nonce: 77 }), hub.identity.peerId);
    const ack = await Promise.race([seen, new Promise<null>((r) => setTimeout(() => r(null), 2000))]);
    assert.ok(ack !== null, "A heard the vouching ACK");
    assert.equal(Number(ack!["nonce"]), 77);
    assert.equal(ack!["onBehalf"], b.identity.peerId);
    assert.equal(hub.pingsRelayed, 1);
  } finally {
    stop();
  }
});

test("each link keeps its own session and a closed link drops only its member (SPEC §5.6)", async () => {
  const { hub, members: [a, b], stop } = await fleet(2, "session");
  try {
    await settle(8);
    const links = [...hub.inbound.values()];
    assert.equal(links.length, 2);
    assert.ok(links.every((l) => l.session !== null && l.session.established() !== null), "a session per link");
    assert.notEqual(links[0].session!.remote, links[1].session!.remote);
    assert.ok(hub.sessionFramesSent > 0, "frames to the links travel tagged");
    a.close();
    await settle();
    assert.equal(hub.inbound.size, 1);
    assert.ok(!hub.reachable.has(a.identity.peerId), "A is no longer reachable");
    assert.ok(hub.reachable.has(b.identity.peerId), "B still is");
    const id = b.writeEntry("tasks", TASK, { topic: "after" }, "b");
    await settle();
    assert.ok(hub.states.has(id), "the remaining link still folds");
  } finally {
    stop();
  }
});

test("a member whose advertisement lapsed and who is on no link is forgotten (expireMembers)", async () => {
  let now = Date.now();
  const hub = new Peer(Identity.generate(), GROUP, () => now);
  const ghost = Identity.generate();
  const ad = wire.peerAdvertisement(GROUP, ghost, new Date(now - 11 * 60_000).toISOString(), "PT10M");
  (hub as unknown as { acceptPeerAd(payload: Uint8Array): void }).acceptPeerAd(wire.signedPeerAd(ad, ghost));
  assert.ok(hub.members.has(ghost.peerId));
  assert.deepEqual(hub.expireMembers(), [ghost.peerId]);
  assert.ok(!hub.members.has(ghost.peerId));
  // A member heard on a link stays, lapsed advertisement or not.
  const { hub: hub2, members: [a], stop } = await fleet(1);
  try {
    const old = wire.peerAdvertisement(GROUP, a.identity, new Date(Date.now() - 11 * 60_000).toISOString(), "PT10M");
    (hub2 as unknown as { acceptPeerAd(payload: Uint8Array): void }).acceptPeerAd(wire.signedPeerAd(old, a.identity));
    assert.deepEqual(hub2.expireMembers(), []);
  } finally {
    stop();
    hub.close();
  }
});

test("an anti-entropy round sends the hub's full digests to one linked member and pulls what it lacks", async () => {
  const { hub, members: [a], stop } = await fleet(1);
  try {
    // A member holds an entry the hub never saw (written before a link existed: simulate by a direct fold).
    const other = new Peer(Identity.generate(), GROUP);
    const id = other.writeEntry("tasks", TASK, { topic: "elsewhere" }, "o");
    (a as unknown as { fold(dto: Dict): void }).fold(other.states.get(id)!);
    a.pullSpace("tasks"); // a member serves the spaces it registered, as a Java member does
    await settle();
    assert.ok(a.states.has(id) && !hub.states.has(id));
    const partner = hub.antiEntropyRound();
    assert.equal(partner, a.identity.peerId);
    await settle();
    assert.ok(hub.states.has(id), "the member answered the hub's digest with the entry");
    other.close();
  } finally {
    stop();
  }
});

test("a late joiner pulls the membership view and learns a member whose introduction it never saw (SPEC §5.2 view stream)", async () => {
  const { hub, members: [a], net, stop } = await fleet(1);
  try {
    assert.ok(hub.viewDigest().length > 0);
    // A member that never saw A's introduction (it joined after) learns A from the hub's view delta.
    const late = new Peer(Identity.generate(), GROUP);
    late.registerDialer(net.dialer());
    await late.connectAny([{ host: "hub", port: 1, scheme: "mem" }]); // connectAny pulls the view
    await settle();
    assert.ok(late.members.has(a.identity.peerId), "A's signed advertisement came in the view delta");
    assert.ok(late.members.has(hub.identity.peerId), "the hub's own advertisement too");
    // The view digest names what it holds, so a second pull brings nothing new.
    const delta = hub.viewDeltaFor(late.viewDigest());
    assert.equal(delta.length, 0);
    late.close();
  } finally {
    stop();
  }
});

test("the core counts the frames a relay carries for each pair in a sliding minute and tells an observer (JS-W-11)", async () => {
  const { hub, members: [a, b], stop } = await fleet(2);
  try {
    // The hub advertises no RELAY role, so A is told it has one; the relay path is then the one
    // sendPipeOrRelay takes for a member A is not linked to.
    a.members.set(hub.identity.peerId, { ...a.members.get(hub.identity.peerId), roles: ["RELAY"] });
    b.pipeHandlers.set("aspace:cap/test", () => undefined);
    const atA: [string, number][] = [];
    const atB: [string, number][] = [];
    a.onRelayed((member, frames) => atA.push([member, frames]));
    b.onRelayed((member, frames) => atB.push([member, frames]));
    for (let i = 0; i < 3; i++) {
      assert.ok(a.sendPipeOrRelay(b.identity.peerId, "aspace:cap/test", new TextEncoder().encode("x" + i)));
    }
    await settle();
    assert.deepEqual(atA, [[b.identity.peerId, 1], [b.identity.peerId, 2], [b.identity.peerId, 3]], "the sender counts the frames it relayed to B");
    assert.deepEqual(atB, [[a.identity.peerId, 1], [a.identity.peerId, 2], [a.identity.peerId, 3]], "the target counts the frames relayed from A");
    assert.equal(a.relayedWithInLastMinute(b.identity.peerId), 3);
    assert.equal(b.relayedWithInLastMinute(a.identity.peerId), 3);
    assert.equal(hub.relayedWithInLastMinute(a.identity.peerId), 0, "a forwarder holds a link to both ends and counts nothing");
    assert.equal(a.relayedWithInLastMinute("zNobody"), 0);
  } finally {
    stop();
  }
});

test("the relayed window is a sliding minute on the peer's clock (JS-W-11)", async () => {
  let now = 1_700_000_000_000;
  const net = new MemoryNetwork();
  const hub = new Peer(Identity.generate(), GROUP, () => now);
  hub.endpoints.push({ transport: "mem", address: "hub:2", priority: 0 });
  const closeListener = await net.listen("hub:2", (channel) => hub.acceptChannel(channel));
  const a = new Peer(Identity.generate(), GROUP, () => now);
  a.registerDialer(net.dialer());
  await a.connectAny([{ host: "hub", port: 2, scheme: "mem" }]);
  await settle();
  try {
    a.members.set(hub.identity.peerId, { ...a.members.get(hub.identity.peerId), roles: ["RELAY"] });
    const counts: number[] = [];
    a.onRelayed((_member, frames) => counts.push(frames));
    a.sendPipeOrRelay("zFar", "aspace:cap/test", new Uint8Array([1]));
    now += 30_000;
    a.sendPipeOrRelay("zFar", "aspace:cap/test", new Uint8Array([2]));
    now += 30_000; // the first stamp is now a minute old and leaves the window
    a.sendPipeOrRelay("zFar", "aspace:cap/test", new Uint8Array([3]));
    assert.deepEqual(counts, [1, 2, 2]);
    assert.equal(a.relayedWithInLastMinute("zFar"), 2);
    now += 60_000;
    assert.equal(a.relayedWithInLastMinute("zFar"), 0);
    // The memory of windows is a cache: past its size the least recently relayed-with member is dropped.
    a.relayedMemory = 2;
    a.sendPipeOrRelay("zFar", "aspace:cap/test", new Uint8Array([4]));
    a.sendPipeOrRelay("zNear", "aspace:cap/test", new Uint8Array([5]));
    a.sendPipeOrRelay("zNext", "aspace:cap/test", new Uint8Array([6]));
    assert.equal(a.relayedWithInLastMinute("zFar"), 0, "evicted");
    assert.equal(a.relayedWithInLastMinute("zNear"), 1);
    assert.equal(a.relayedWithInLastMinute("zNext"), 1);
  } finally {
    closeListener();
    hub.close();
    a.close();
  }
});

test("a RELAY_FRAME is forwarded to a linked member, unwrapped by its target, and its origin is heard but not reachable (SPEC §5.4)", async () => {
  const { hub, members: [a, b], stop } = await fleet(2);
  try {
    const seen: string[] = [];
    b.pipeHandlers.set("aspace:cap/test", (from, payload) => seen.push(`${from}:${new TextDecoder().decode(payload)}`));
    // A is not linked to B; the hub advertises no RELAY role in this fleet, so A addresses the hub explicitly.
    const inner = wire.encodeFrame(wire.envelope(GROUP, "PIPE_DATA", a.identity.peerId,
      wire.hlcNow(a.identity.peerId), dumps({ capability: "aspace:cap/test", payload: new TextEncoder().encode("hi") }),
      b.identity.peerId), a.identity);
    (a as unknown as { send(kind: string, body: Uint8Array, to: string): void })
      .send("RELAY_FRAME", wire.relayFrameBody(b.identity.peerId, inner), hub.identity.peerId);
    await settle();
    assert.equal(hub.relayedForwarded, 1);
    assert.equal(b.relayedIn, 1);
    assert.deepEqual(seen, [`${a.identity.peerId}:hi`]);
    assert.ok(b.members.has(a.identity.peerId), "the origin is heard");
    assert.ok(!b.reachable.has(a.identity.peerId), "but not reachable: an answer must take the relay");
    // A nested relay is refused, and one for a member nobody links is dropped.
    const nested = wire.encodeFrame(wire.envelope(GROUP, "RELAY_FRAME", a.identity.peerId,
      wire.hlcNow(a.identity.peerId), wire.relayFrameBody(b.identity.peerId, inner), b.identity.peerId), a.identity);
    (a as unknown as { send(kind: string, body: Uint8Array, to: string): void })
      .send("RELAY_FRAME", wire.relayFrameBody(b.identity.peerId, nested), hub.identity.peerId);
    (a as unknown as { send(kind: string, body: Uint8Array, to: string): void })
      .send("RELAY_FRAME", wire.relayFrameBody("zNobody", inner), hub.identity.peerId);
    await settle();
    assert.equal(hub.relayedForwarded, 2);
    assert.equal(b.relayedIn, 1, "the nested relay was refused");
    assert.equal(seen.length, 1);
  } finally {
    stop();
  }
});
