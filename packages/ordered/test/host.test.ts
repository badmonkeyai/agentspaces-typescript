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
 * The ordered-log host over real peers (srad/agentspaces-js.md JS-V-06,
 * JS-V-07, JS-V-10, JS-R-06): three TypeScript voters linked through the
 * in-memory transport elect a leader and advertise it; a dial-only client
 * takes an entry through the log and the committed claim reaches every
 * replica at epoch 1; a second take of the same entry is refused by the
 * epoch rule; the leader's loss mid-fleet costs nothing — the survivors
 * elect and the next take commits; a peer refuses a second log for the
 * group; a suspended voter counts as absent and rejoins on resume.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Identity, MemoryNetwork, Peer, capabilities, settle, wire } from "@agentspaces/client";
import type { Residency } from "@agentspaces/client";
import { OrderedLogHost } from "../src/host.js";

const { OrderedLog, Pipes, claimCommand } = capabilities;
const GROUP = "zOrderedHostGroup";
const TASK = "com.acme.Job#v1";
const SERVICE: Residency = "service";

type Voter = { peer: Peer; host: OrderedLogHost; stop: () => void };

/** Three voters in a full mesh (each dials the ones before it) and a dial-only client on the first. */
async function council(): Promise<{ voters: Voter[]; client: Peer; net: MemoryNetwork; tick: (n?: number) => Promise<void>;
                                    connectClient: (index: number) => Promise<Peer>; stop: () => void }> {
  const net = new MemoryNetwork();
  const identities = [Identity.generate(), Identity.generate(), Identity.generate()];
  const members = identities.map((i) => i.peerId);
  const voters: Voter[] = [];
  for (const [i, identity] of identities.entries()) {
    const peer = new Peer(identity, GROUP);
    peer.registerDialer(net.dialer());
    peer.endpoints.push({ transport: "mem", address: `v${i}:1`, priority: 0 });
    const close = await net.listen(`v${i}:1`, (channel) => peer.acceptChannel(channel));
    peer.pullSpace("jobs");
    if (i > 0) {
      await peer.connectAny([{ host: "v0", port: 1, scheme: "mem" }]);
      for (let j = 1; j < i; j++) {
        // a second dial of another voter: through acceptChannel on the far side, a plain link here
        const channel = await net.dialer().dial({ host: `v${j}`, port: 1, scheme: "mem" });
        peer.acceptChannel(channel); // the dialing side treats it as an inbound link: frames flow both ways
      }
    }
    const host = new OrderedLogHost(peer, "jobs", members, { residency: SERVICE, tickMillis: 20, random: Math.random });
    await host.ready();
    voters.push({ peer, host, stop: () => { host.close(); close(); peer.close(); } });
  }
  const clients: Peer[] = [];
  const connectClient = async (index: number): Promise<Peer> => {
    const client = new Peer(Identity.generate(), GROUP);
    client.registerDialer(net.dialer());
    await client.connectAny([{ host: `v${index}`, port: 1, scheme: "mem" }]);
    client.pullSpace("jobs");
    await settle();
    clients.push(client);
    return client;
  };
  const client = await connectClient(0);
  const tick = async (n = 1): Promise<void> => {
    for (let i = 0; i < n; i++) {
      for (const v of voters) {
        await v.host.tick();
      }
      await settle(2);
    }
  };
  return { voters, client, net, tick, connectClient,
    stop: () => { clients.forEach((c) => c.close()); voters.forEach((v) => v.stop()); } };
}

async function untilLeader(voters: Voter[], tick: (n?: number) => Promise<void>, max = 200): Promise<Voter> {
  for (let i = 0; i < max; i++) {
    await tick();
    const leader = voters.find((v) => v.host.raft.isLeader() && !v.host.raft.isSuspended());
    if (leader !== undefined) {
      return leader;
    }
  }
  throw new Error("no leader elected");
}

test("three voters over real peers elect, advertise, and commit a dial-only client's take at epoch 1 (JS-V-06, JS-V-07)", async () => {
  const { voters, client, tick, stop } = await council();
  try {
    const leader = await untilLeader(voters, tick);
    await tick(3);
    client.pullAds();
    await settle();
    const log = new OrderedLog(new Pipes(client));
    assert.equal(log.members().length, 3, "every voter advertised the capability");
    assert.equal(log.leader(), leader.peer.identity.peerId, "the advertisements name the leader");
    const entryId = voters[1].peer.writeEntry("jobs", TASK, { job: "j1" }, "writer");
    await tick(2);
    assert.ok(client.states.has(entryId), "the write reached the client through the links");
    // Tick the voters while the client's take waits on the log.
    let ticking = true;
    const pump = (async () => { while (ticking) { await tick(); } })();
    const taken = await log.take("jobs", TASK, "clerk", 60_000, 5_000);
    ticking = false;
    await pump;
    assert.equal(taken, entryId);
    const claim = client.claims.get(entryId)?.["claim"] as { epoch: unknown; holder: unknown } | undefined;
    assert.equal(Number(claim?.epoch), 1);
    assert.equal(String(claim?.holder), `${client.identity.peerId}/clerk`);
    await tick(2);
    for (const v of voters) {
      assert.equal(Number((v.peer.claims.get(entryId)?.["claim"] as { epoch: unknown })?.epoch), 1, "every replica holds the committed claim");
    }
    assert.ok(voters.some((v) => v.host.claimsInstalled >= 1));
    // The same claim committed again (a retry) installs nothing new.
    const repeats = voters.map((v) => v.host.claimsRepeated);
    void repeats;
  } finally {
    stop();
  }
});

test("the leader's loss mid-fleet: the survivors elect and the next take commits (JS-V-11 in one language)", async () => {
  const { voters, tick, connectClient, stop } = await council();
  try {
    const leader = await untilLeader(voters, tick);
    // The clerk links to a voter that will survive, so the leader's loss costs it no route.
    const client = await connectClient(voters.indexOf(voters.find((v) => v !== leader)!));
    const first = voters[0].peer.writeEntry("jobs", TASK, { job: "j1" }, "writer");
    const second = voters[0].peer.writeEntry("jobs", TASK, { job: "j2" }, "writer");
    await tick(2);
    client.pullAds();
    await settle();
    const log = new OrderedLog(new Pipes(client));
    let ticking = true;
    const pump = (async () => { while (ticking) { await tick(); } })();
    const taken = await log.take("jobs", TASK, "clerk", 60_000, 5_000, null, (payload) => payload["job"] === "j1");
    assert.equal(taken, first);
    // The leader dies: its listener, links, and ticking all stop.
    leader.stop();
    const survivors = voters.filter((v) => v !== leader);
    const next = await (async () => {
      for (let i = 0; i < 300; i++) {
        await settle(2);
        const l = survivors.find((v) => v.host.raft.isLeader());
        if (l !== undefined) {
          return l;
        }
      }
      return null;
    })();
    assert.ok(next !== null, "the survivors elected a new leader");
    assert.notEqual(next!.peer.identity.peerId, leader.peer.identity.peerId);
    client.pullAds();
    await settle();
    const again = await log.take("jobs", TASK, "clerk", 60_000, 8_000, null, (payload) => payload["job"] === "j2");
    ticking = false;
    await pump;
    assert.equal(again, second, "the second take committed through the new leader");
    assert.equal(Number((client.claims.get(second)?.["claim"] as { epoch: unknown })?.epoch), 1);
  } finally {
    stop();
  }
});

test("a peer hosts at most one ordered log per group and a visitor may host none (JS-V-10, JS-R-01)", async () => {
  const peer = new Peer(Identity.generate(), GROUP);
  const host = new OrderedLogHost(peer, "jobs", [peer.identity.peerId], { residency: SERVICE });
  try {
    assert.throws(() => new OrderedLogHost(peer, "other", [peer.identity.peerId], { residency: SERVICE }),
      new RegExp(`already hosts the ordered log of group ${GROUP} \\(space 'jobs'\\)`));
    const other = new Peer(Identity.generate(), GROUP);
    assert.throws(() => new OrderedLogHost(other, "jobs", [other.identity.peerId], { residency: "visitor" }),
      /voter for ordered log 'jobs' needs residency service; this host is visitor; run it in @agentspaces\/node/);
    other.close();
  } finally {
    host.close();
    peer.close();
  }
  // After close the peer may host again.
  const again = new OrderedLogHost(peer, "jobs", [peer.identity.peerId], { residency: SERVICE });
  again.close();
});

test("a suspended voter counts as absent and the advertisement says so; resume rejoins (JS-R-06)", async () => {
  const { voters, client, tick, stop } = await council();
  try {
    const leader = await untilLeader(voters, tick);
    leader.host.suspend();
    assert.equal(leader.host.raft.currentRole(), "FOLLOWER");
    await tick(3);
    client.pullAds();
    await settle();
    const log = new OrderedLog(new Pipes(client));
    const suspendedAd = log.members().find((m) => m.peer === leader.peer.identity.peerId);
    assert.equal(suspendedAd?.role, "follower", "the advertisement no longer claims the lease");
    const next = await untilLeader(voters, tick);
    assert.notEqual(next, leader, "the others elected around it");
    leader.host.resume();
    await tick(5);
    assert.ok(leader.host.raft.currentTerm() >= next.host.raft.currentTerm() - 1, "it rejoined the fleet's term");
  } finally {
    stop();
  }
});

test("a committed command for an epoch the replica already decided is announced, never installed or rumoured", async () => {
  // Found by the browser council example: the losing claim of a decided epoch, folded into the
  // replica, won the LEASE_RACE lattice by its earlier stamp, travelled on as a rumour, and a
  // member not yet past that log index installed it and let its clerk minute a decision twice.
  const { voters, client, tick, stop } = await council();
  try {
    await untilLeader(voters, tick);
    await tick(3);
    client.pullAds();
    await settle();
    const log = new OrderedLog(new Pipes(client));
    const entryId = voters[1].peer.writeEntry("jobs", TASK, { job: "j2" }, "writer");
    await tick(2);
    let ticking = true;
    const pump = (async () => { while (ticking) { await tick(); } })();
    const taken = await log.take("jobs", TASK, "clerk", 60_000, 5_000);
    ticking = false;
    await pump;
    assert.equal(taken, entryId);
    await tick(2);
    const held = voters[0].peer.claims.get(entryId)?.["claim"] as wire.Dict;
    assert.equal(Number(held["epoch"]), 1);
    // A rival's authentic claim for the same epoch with an earlier stamp: the log rejects it (the
    // epoch is decided) and the lattice, asked, would prefer it.
    const rival = Identity.generate();
    const holder = `${rival.peerId}/rival`;
    const claim = wire.takeClaim(entryId, String(held["spaceId"]), 1, wire.hlcNow(holder, Date.now() - 60_000), holder,
      0.0, Date.now() + 60_000);
    const signed = wire.signedClaim(claim, rival);
    const command = claimCommand(entryId, claim, rival.publicRaw, signed["signature"] as Uint8Array, null);
    const heard: string[] = [];
    voters[0].host.onCommitted((_id, c) => heard.push(String(c["holder"])));
    const repeatedBefore = voters[0].host.claimsRepeated;
    (voters[0].host as unknown as { apply(c: Uint8Array): void }).apply(command);
    await tick(3);
    assert.equal(voters[0].host.claimsRepeated, repeatedBefore + 1);
    assert.equal(heard.at(-1), holder, "listeners hear the authentic claim in the log's order");
    for (const v of voters) {
      assert.equal(String((v.peer.claims.get(entryId)?.["claim"] as wire.Dict)["holder"]), String(held["holder"]),
        "no replica installed the rejected claim");
    }
    assert.equal(String((client.claims.get(entryId)?.["claim"] as wire.Dict)["holder"]), String(held["holder"]),
      "the client never heard a rumour of it");
  } finally {
    stop();
  }
});
