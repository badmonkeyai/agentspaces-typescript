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
 * Replication by entry between TypeScript members (SPEC annex I.6, §5.2, v0.1.35; srad/replication-by-entry.md
 * RE-L-01, RE-L-07): the form per partner from its current card, the audit and the fetch by id, the budgeted
 * get-space and its continuation, the hashed round of v0.1.17, the fallback from a stale card, the probe hashes, and a
 * member with the hints off that behaves as a 0.6.0 member. Every peer runs on the in-memory network; a member that
 * should miss frames drops them at its own send, so the repair is the audit's, not a rumor's.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Identity } from "../src/identity.js";
import { AE_HINT, HASHES_HINT, HORIZON_HINT, Peer } from "../src/peer.js";
import { MemoryNetwork, settle } from "../src/transport/mem.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";

const GROUP = "zReplicationByEntry";
const TASK = "com.acme.Task#v1";

/** A peer that can drop the frames it sends, and records what it sent. */
class TestPeer extends Peer {
  drop: ((kind: string, to: string | null) => boolean) | null = null;
  readonly sent: { kind: string; body: Uint8Array; to: string | null }[] = [];

  protected override send(kind: string, body: Uint8Array, to: string | null = null, scope: "all" | "dial" = "all"): void {
    if (this.drop?.(kind, to)) {
      return;
    }
    this.sent.push({ kind, body, to });
    super.send(kind, body, to, scope);
  }

  /** The bodies of one kind sent since `from`, decoded. */
  bodies(kind: string, from = 0): Dict[] {
    return this.sent.slice(from).filter((f) => f.kind === kind).map((f) => wire.decodeBody({ kind, body: f.body })!);
  }
}

async function fleet(n: number, configure: (member: TestPeer, i: number) => void = () => undefined):
    Promise<{ hub: TestPeer; members: TestPeer[]; net: MemoryNetwork; join: (c: TestPeer) => Promise<void>; stop: () => void }> {
  const net = new MemoryNetwork();
  const hub = new TestPeer(Identity.generate(), GROUP);
  hub.endpoints.push({ transport: "mem", address: "hub:1", priority: 0 });
  const closeListener = await net.listen("hub:1", (channel) => hub.acceptChannel(channel));
  hub.pullSpace("tasks");
  const members: TestPeer[] = [];
  const join = async (member: TestPeer): Promise<void> => {
    member.registerDialer(net.dialer());
    await member.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    await settle();
    hub.introduce(); // the hub's card reaches the member as a peers rumor
    await settle();
  };
  for (let i = 0; i < n; i++) {
    const member = new TestPeer(Identity.generate(), GROUP);
    configure(member, i);
    await join(member);
    members.push(member);
  }
  await settle();
  return { hub, members, net, join, stop: () => { closeListener(); hub.close(); members.forEach((m) => m.close()); } };
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

/** Settles until `done` holds or the generous ceiling passes; returns the milliseconds it took. */
async function until(done: () => boolean, ceilingMillis = 10_000): Promise<number> {
  const start = Date.now();
  while (!done()) {
    if (Date.now() - start > ceilingMillis) {
      throw new Error(`not converged within ${ceilingMillis} ms`);
    }
    await settle();
  }
  return Date.now() - start;
}

test("members advertise wire.hashes=1, wire.ae=2 and wire.horizon=1, and read each other's cards", async () => {
  const { hub, members: [b], stop } = await fleet(1);
  try {
    const card = b.members.get(hub.identity.peerId)!["resourceHints"] as Dict;
    assert.equal(card[HASHES_HINT], "1");
    assert.equal(card[AE_HINT], "2");
    assert.equal(card[HORIZON_HINT], "1");
    assert.equal(b.formToward(hub.identity.peerId), "ae");
    assert.equal(hub.formToward(b.identity.peerId), "ae");
  } finally {
    stop();
  }
});

test("a missed write is repaired by the audit and a fetch by id, with no text digest of the space on the wire", async () => {
  const { hub, members: [b], stop } = await fleet(1);
  try {
    b.pullSpace("tasks");
    for (let i = 0; i < 300; i++) {
      hub.writeEntry("tasks", TASK, { n: i }, "hub");
    }
    await until(() => b.states.size === 300);
    hub.drop = (kind) => kind === "RUMOR"; // the next writes never reach b by rumor
    const missed = [0, 1, 2].map((i) => hub.writeEntry("tasks", TASK, { n: 1000 + i }, "hub"));
    hub.drop = null;
    await settle();
    assert.ok(missed.every((id) => !b.states.has(id)));
    const mark = b.sent.length;
    const hubMark = hub.sent.length;
    b.antiEntropyRound();
    const millis = await until(() => missed.every((id) => b.states.has(id)));
    assert.equal(b.lastFormToward(hub.identity.peerId), "ae");
    assert.equal(hex(b.spaceTrie("tasks").streamHash()), hex(hub.spaceTrie("tasks").streamHash()));
    const asked = b.bodies("DIGEST", mark);
    assert.ok(asked.every((d) => d["digests"] === null), "no text digest went from the asker");
    assert.deepEqual(asked.flatMap((d) => Object.values((d["ids"] ?? {}) as Dict).flat()).sort(), [...missed].sort());
    const signals = b.trieAudit.signals();
    assert.equal(signals.idsFetched, 3);
    assert.ok(signals.requestsSent >= 1, "the asker descended below the root");
    assert.ok(hub.trieAudit.signals().rootsAnswered >= 1);
    const bytes = b.sent.slice(mark).reduce((n, f) => n + f.body.length, 0)
      + hub.sent.slice(hubMark).filter((f) => f.to === b.identity.peerId && (f.kind === "DIGEST" || f.kind === "PULL_RESP"))
        .reduce((n, f) => n + f.body.length, 0);
    console.log(`audit of 303 entries, 3 missed: repaired in ${millis} ms, ${bytes} body bytes both ways`);
  } finally {
    stop();
  }
});

test("a round between equal replicas carries hashes alone and draws no answer", async () => {
  const { hub, members: [b], stop } = await fleet(1);
  try {
    b.pullSpace("tasks");
    for (let i = 0; i < 50; i++) {
      hub.writeEntry("tasks", TASK, { n: i }, "hub");
    }
    await until(() => b.states.size === 50);
    const hubMark = hub.sent.length;
    const mark = b.sent.length;
    b.antiEntropyRound();
    await settle(8);
    const opening = b.bodies("DIGEST", mark);
    assert.equal(opening.length, 1);
    assert.ok(opening[0]!["hashes"] !== undefined && opening[0]!["digests"] === null);
    assert.equal(hub.sent.slice(hubMark).filter((f) => f.to === b.identity.peerId
      && (f.kind === "DIGEST" || f.kind === "PULL_RESP")).length, 0, "the partner answered nothing");
  } finally {
    stop();
  }
});

test("a budgeted get-space joins a large space in bounded answers, continued by the audit", async () => {
  const { hub, join, stop } = await fleet(0);
  const late = new TestPeer(Identity.generate(), GROUP);
  try {
    const padding = "x".repeat(2000);
    for (let i = 0; i < 400; i++) {
      hub.writeEntry("tasks", TASK, { n: i, padding }, "hub");
    }
    late.auditBudget = 16 * 1024;
    await join(late);
    assert.equal(late.seedPeer, hub.identity.peerId);
    const start = Date.now();
    late.pullSpace("tasks");
    const millis = await until(() => late.states.size === 400, 30_000);
    const answers = hub.sent.filter((f) => f.kind === "PULL_RESP" && (f.to === late.identity.peerId || f.to === null));
    const largest = Math.max(...answers.map((f) => f.body.length));
    assert.ok(answers.length > 10, `${answers.length} answers`);
    assert.ok(largest <= 16 * 1024 + 4096, `the largest answer was ${largest} bytes`);
    assert.equal(hex(late.spaceTrie("tasks").streamHash()), hex(hub.spaceTrie("tasks").streamHash()));
    console.log(`budgeted join of 400 x 2 KB at 16 KiB: ${answers.length} answers, largest ${largest} B, `
      + `${millis} ms (${Date.now() - start} ms wall)`);
  } finally {
    late.close();
    stop();
  }
});

test("a member with the hints off behaves as 0.6.0, and a mixed pair converges both ways", async () => {
  const { hub, members: [old], stop } = await fleet(1, (member) => {
    member.audit = false;
    member.horizon = "legacy";
  });
  try {
    const card = hub.members.get(old.identity.peerId)!["resourceHints"] as Dict;
    assert.equal(card[AE_HINT], undefined);
    assert.equal(card[HASHES_HINT], undefined);
    assert.equal(card[HORIZON_HINT], undefined);
    assert.equal(hub.formToward(old.identity.peerId), "text");
    old.pullSpace("tasks");
    await settle();
    // The old member's round is today's full text digest, byte for byte.
    const mark = old.sent.length;
    old.antiEntropyRound();
    await settle();
    const round = old.sent.slice(mark).filter((f) => f.kind === "DIGEST");
    assert.equal(round.length, 1);
    assert.equal(hex(round[0]!.body), hex(wire.digestBody(old.fullDigests())));
    // Writes each side missed are repaired: the old member by its text round, the hub by a text round toward it.
    hub.drop = (kind) => kind === "RUMOR";
    const fromHub = hub.writeEntry("tasks", TASK, { n: 1 }, "hub");
    hub.drop = null;
    old.drop = (kind) => kind === "RUMOR";
    const fromOld = old.writeEntry("tasks", TASK, { n: 2 }, "old");
    old.drop = null;
    old.antiEntropyRound();
    hub.antiEntropyRound();
    await until(() => old.states.has(fromHub) && hub.states.has(fromOld));
    assert.equal(hub.lastFormToward(old.identity.peerId), "text");
    const toOld = hub.sent.filter((f) => f.to === old.identity.peerId && (f.kind === "DIGEST" || f.kind === "PULL_RESP"));
    for (const f of toOld) {
      const body = wire.decodeBody({ kind: f.kind, body: f.body })!;
      for (const field of ["tree", "ids", "budget", "remainder", "hashes", "want"]) {
        assert.equal(body[field], undefined, `${field} went toward a member without the hint`);
      }
    }
    // A tree from a sender that read a stale card is dropped and counted, as a member without the hint drops it.
    (old as unknown as { onDigest(from: string, d: Dict): void }).onDigest(hub.identity.peerId,
      { digests: null, tree: { "space:tasks": [{ path: new Uint8Array(0), count: 3 }] } });
    assert.equal(old.trieAudit.refusals()["lacks-hint"], 1);
  } finally {
    stop();
  }
});

test("a hinted member that holds a stale card falls back to the text form within the round", async () => {
  const { hub, members: [b], stop } = await fleet(1);
  try {
    b.pullSpace("tasks");
    await settle(); // the pull's answer lands before the write it must not carry
    hub.drop = (kind) => kind === "RUMOR";
    const missed = hub.writeEntry("tasks", TASK, { n: 1 }, "hub");
    hub.drop = null;
    await settle();
    assert.equal(b.states.has(missed), false);
    // b reads the hub's card as wire.hashes=1 alone (a card from before the hint); the hub reads b's as wire.ae=2.
    b.aePeers.delete(hub.identity.peerId);
    assert.equal(b.formToward(hub.identity.peerId), "hashes");
    b.antiEntropyRound();
    await until(() => b.states.has(missed));
    assert.equal(b.trieAudit.refusals()["text-fallback"], 1, "the root came back for a text round and was pulled by text");
  } finally {
    stop();
  }
});

test("the hashed round of v0.1.17: hashes, a want, the text of the streams that differ", async () => {
  const { hub, members: [b], stop } = await fleet(1);
  try {
    b.pullSpace("tasks");
    await settle(); // the pull's answer lands before the write it must not carry
    hub.drop = (kind) => kind === "RUMOR";
    const missed = hub.writeEntry("tasks", TASK, { n: 1 }, "hub");
    hub.drop = null;
    await settle();
    assert.equal(b.states.has(missed), false);
    b.aePeers.delete(hub.identity.peerId); // each reads the other's card as wire.hashes=1 alone
    hub.aePeers.delete(b.identity.peerId);
    b.antiEntropyRound();
    await until(() => b.states.has(missed));
    assert.equal(b.lastFormToward(hub.identity.peerId), "hashes");
    assert.equal(hub.pacing.wantsSent, 1);
    assert.equal(b.pacing.wantsReceived, 1);
    const want = hub.bodies("DIGEST").find((d) => d["want"] !== undefined)!;
    assert.deepEqual(want["want"], ["space:tasks"]);
    assert.equal(want["tree"], undefined, "no root toward a member read as hashes alone");
  } finally {
    stop();
  }
});

test("a probe's differing hashes draw hashes back, and one targeted round once its rounds backed off", async () => {
  const { hub, members: [b], stop } = await fleet(1);
  try {
    b.pullSpace("tasks");
    hub.writeEntry("tasks", TASK, { n: 1 }, "hub");
    await until(() => b.states.size === 1);
    const ping = (hashes: Dict): void => {
      const env = wire.envelope(GROUP, "PING", b.identity.peerId, wire.hlcNow(b.identity.peerId, Date.now()),
        wire.probeBody("PING", 7, null, hashes), hub.identity.peerId);
      (hub as unknown as { onFrame(f: Uint8Array, l: null): void }).onFrame(wire.encodeFrame(env, b.identity), null);
    };
    const probeOf = (peer: Peer): Dict => (peer as unknown as { probeDigests(t: boolean): { hashes: Dict } })
      .probeDigests(true).hashes;
    let mark = hub.sent.length;
    ping(probeOf(b));
    const acks = hub.bodies("ACK", mark);
    assert.equal(acks.length, 1);
    assert.equal(hex((acks[0]!["hashes"] as Dict)["space:tasks"] as Uint8Array), hex(hub.spaceTrie("tasks").streamHash()),
      "toward a member on wire.ae=2 the space's hash is its trie's");
    assert.equal(hub.pacing.probeRounds, 0, "equal hashes open no round");
    const differing = { ...probeOf(b), "space:tasks": new Uint8Array(32) };
    mark = hub.sent.length;
    ping(differing);
    assert.equal(hub.pacing.probeRounds, 0, "a peer whose own rounds have not backed off opens none from a probe");
    (hub as unknown as { quietSince: number }).quietSince = Date.now() - 5_000; // four quiet rounds of one second
    ping(differing);
    ping(differing);
    assert.equal(hub.pacing.probeRounds, 1, "one round per period at most");
    assert.equal(hub.bodies("DIGEST", mark).filter((d) => d["hashes"] !== undefined).length, 1);
  } finally {
    stop();
  }
});

test("a fetch answer that names a stream the asker never asked is folded as before but books nothing", async () => {
  const { hub, members: [b], stop } = await fleet(1);
  try {
    b.pullSpace("tasks");
    const resp = wire.pullRespBody({}, { "space:tasks": 2 });
    const env = wire.envelope(GROUP, "PULL_RESP", hub.identity.peerId, wire.hlcNow(hub.identity.peerId, Date.now()),
      resp, b.identity.peerId);
    (b as unknown as { onFrame(f: Uint8Array, l: null): void }).onFrame(wire.encodeFrame(env, hub.identity), null);
    await settle();
    assert.equal(b.trieAudit.signals().fetchQueued, 0);
  } finally {
    stop();
  }
});
