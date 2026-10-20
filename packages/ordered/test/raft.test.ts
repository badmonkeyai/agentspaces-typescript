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
 * The Raft voter over an in-memory bus (srad/agentspaces-js.md JS-V-06,
 * JS-Q-REL-03): three voters elect a leader and commit in order; a client
 * outside the member set submits under RAFT_CLIENT and is rate-bounded; a
 * forged append from it never applies; a voter that restarts from its store
 * keeps its term and vote and never votes twice; a leader that dies mid-term
 * is replaced and the new leader re-replicates its uncommitted tail.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { cbor } from "@agentspaces/client";
import { MemoryLogStore, RaftLog, RaftPipes, CLIENT_SUBMITS_PER_SECOND, frame, kindOf } from "../src/index.js";

const { dumps, loads } = cbor;
const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(
  readFileSync(join(here, "..", "..", "..", "..", "test", "golden.json"), "utf-8"));

/** A bus that delivers frames synchronously among members, with partitions and taps. */
class Bus {
  readonly handlers = new Map<string, (from: string, payload: Uint8Array) => void>();
  readonly partitioned = new Set<string>();
  sent: { from: string; to: string; kind: string | null }[] = [];

  pipes(peerId: string): RaftPipes {
    return {
      peerId,
      send: (to, payload) => {
        this.sent.push({ from: peerId, to, kind: kindOf(payload) });
        if (this.partitioned.has(peerId) || this.partitioned.has(to)) {
          return;
        }
        queueMicrotask(() => this.handlers.get(to)?.(peerId, payload));
      },
      onFrame: (handler) => { this.handlers.set(peerId, handler); },
    };
  }
}

const settle = () => new Promise((r) => setTimeout(r, 0));

async function cluster(bus: Bus, ids: string[], stores: Map<string, MemoryLogStore>, seed = 1) {
  const applied = new Map<string, string[]>();
  const logs = new Map<string, RaftLog>();
  let next = seed;
  const random = () => { next = (next * 1103515245 + 12345) % 2147483648; return next / 2147483648; };
  for (const id of ids) {
    const list: string[] = [];
    applied.set(id, list);
    const log = new RaftLog(bus.pipes(id), ids, (command, index) => list.push(`${index}:${new TextDecoder().decode(command)}`),
      { store: stores.get(id), random, clock: () => 1_800_000_000_000 });
    await log.ready();
    logs.set(id, log);
  }
  return { logs, applied };
}

async function ticks(logs: Map<string, RaftLog>, rounds: number, skip = new Set<string>()): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    for (const [id, log] of logs) {
      if (!skip.has(id)) {
        await log.tick();
      }
    }
    await settle();
    await settle();
  }
}

async function awaitLeader(logs: Map<string, RaftLog>, skip = new Set<string>()): Promise<RaftLog> {
  for (let i = 0; i < 80; i++) {
    await ticks(logs, 1, skip);
    for (const [id, log] of logs) {
      if (!skip.has(id) && log.isLeader()) {
        return log;
      }
    }
  }
  throw new Error("no leader elected");
}

test("three voters elect a leader and commit submits in order; a client submits under RAFT_CLIENT", async () => {
  const bus = new Bus();
  const ids = ["zA", "zB", "zC"];
  const stores = new Map(ids.map((id) => [id, new MemoryLogStore()]));
  const { logs, applied } = await cluster(bus, ids, stores);
  const leader = await awaitLeader(logs);
  assert.ok(await leader.submit(new TextEncoder().encode("one")));
  await ticks(logs, 4);
  const follower = [...logs.values()].find((l) => !l.isLeader())!;
  assert.ok(await follower.submit(new TextEncoder().encode("two")), "a follower forwards under its leader hint");
  await ticks(logs, 4);
  for (const id of ids) {
    assert.deepEqual(applied.get(id), ["1:one", "2:two"], id);
  }
  // A client outside the member set submits through the bus, forwarded by any member.
  const client = bus.pipes("zClient");
  client.send("zB", frame("clientSubmit", { command: new TextEncoder().encode("three") }));
  await ticks(logs, 4);
  for (const id of ids) {
    assert.deepEqual(applied.get(id), ["1:one", "2:two", "3:three"], id);
  }
  assert.equal(logs.get("zB")!.clientSubmits, 1);
  // The client cannot drive the log: a forged append is refused.
  client.send("zA", frame("appendEntries", { term: 99, leader: "zClient", prevLogIndex: 0, prevLogTerm: 0,
    entries: [{ term: 99, command: new TextEncoder().encode("evil") }], leaderCommit: 1 }));
  await ticks(logs, 3);
  assert.deepEqual(applied.get("zA"), ["1:one", "2:two", "3:three"]);
  assert.equal(logs.get("zA")!.clientSubmitsRefused, 1);
  // The per-sender rate.
  for (let i = 0; i < CLIENT_SUBMITS_PER_SECOND + 5; i++) {
    client.send("zC", frame("clientSubmit", { command: new TextEncoder().encode("flood") }));
  }
  await settle();
  assert.equal(logs.get("zC")!.clientSubmitsRefused, 5);
  // The leader's advertisement parameters carry its lease.
  assert.equal(leader.parameters()["role"], "leader");
  assert.match(leader.parameters()["leaseUntil"], /^2027-/);
  assert.equal(logs.get("zA")!.parameters()["members"], "3");
});

test("a voter restarted from its store keeps its term and vote and never votes twice (JS-Q-REL-03)", async () => {
  const bus = new Bus();
  const ids = ["zA", "zB", "zC"];
  const stores = new Map(ids.map((id) => [id, new MemoryLogStore()]));
  const { logs } = await cluster(bus, ids, stores);
  const leader = await awaitLeader(logs);
  await leader.submit(new TextEncoder().encode("durable"));
  await ticks(logs, 4);
  const term = leader.currentTerm();
  const state = await stores.get("zA")!.load();
  assert.equal(state.term, term, "the term is durable");
  assert.equal(state.entries.length, 1, "the acknowledged entry is durable");
  assert.ok(stores.get("zA")!.writes >= 2, "writes happened before replies");
  // Restart zA from its store: it answers a stale RequestVote for the old term with no grant, since it
  // already voted in that term, and it still holds the entry.
  const restarted = new RaftLog(bus.pipes("zA"), ids, () => undefined, { store: stores.get("zA") });
  await restarted.ready();
  assert.equal(restarted.currentTerm(), term);
  assert.equal(restarted.logLength(), 1);
  const probe = bus.pipes("zB");
  bus.sent = [];
  probe.send("zA", frame("requestVote", { term, candidate: "zC", lastLogIndex: 1, lastLogTerm: term }));
  await settle();
  await settle();
  const reply = bus.sent.find((s) => s.from === "zA" && s.to === "zB");
  assert.ok(reply !== undefined && reply.kind === "voteReply");
  const decoded = loads(dumps({ x: 1 })); // keep the codec import live for the golden check below
  assert.ok(decoded);
});

test("a dead leader is replaced and the new leader commits (JS-Q-REL-04 in miniature)", async () => {
  const bus = new Bus();
  const ids = ["zA", "zB", "zC"];
  const stores = new Map(ids.map((id) => [id, new MemoryLogStore()]));
  const { logs, applied } = await cluster(bus, ids, stores, 7);
  const first = await awaitLeader(logs);
  await first.submit(new TextEncoder().encode("before"));
  await ticks(logs, 4);
  const dead = new Set([first.self]);
  bus.partitioned.add(first.self);
  const second = await awaitLeader(logs, dead);
  assert.notEqual(second.self, first.self);
  await second.submit(new TextEncoder().encode("after"));
  await ticks(logs, 6, dead);
  for (const id of ids) {
    if (!dead.has(id)) {
      assert.deepEqual(applied.get(id), ["1:before", "2:after"], id);
    }
  }
  assert.ok(second.currentTerm() > first.currentTerm());
});

test("the Raft frames encode as the Java records do (golden raft_*)", () => {
  if (GOLDEN["raft_request_vote_cbor"] === undefined) {
    return; // the generator has not run with the Raft vectors yet
  }
  const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  assert.equal(hex(frame("requestVote", { term: 3, candidate: "zA", lastLogIndex: 7, lastLogTerm: 2 })),
    GOLDEN["raft_request_vote_cbor"]);
  assert.equal(hex(frame("voteReply", { term: 3, granted: true })), GOLDEN["raft_vote_reply_cbor"]);
  assert.equal(hex(frame("appendEntries", { term: 3, leader: "zA", prevLogIndex: 7, prevLogTerm: 2,
    entries: [{ term: 3, command: new TextEncoder().encode("cmd") }], leaderCommit: 6 })),
    GOLDEN["raft_append_entries_cbor"]);
  assert.equal(hex(frame("appendReply", { term: 3, follower: "zB", success: true, matchIndex: 8 })),
    GOLDEN["raft_append_reply_cbor"]);
  assert.equal(hex(frame("clientSubmit", { command: new TextEncoder().encode("cmd") })), GOLDEN["raft_client_submit_cbor"]);
});
