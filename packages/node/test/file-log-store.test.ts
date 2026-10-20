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
 * The file log store (srad/agentspaces-js.md JS-V-06): term, vote, and
 * entries survive a fresh instance; an append at an earlier index replaces
 * the tail; a torn tail record is dropped and trimmed; and a voter built
 * over it restarts with its vote intact (the port of the Java
 * `RaftLogStoreTest`).
 */

import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { RaftLog } from "@agentspaces/ordered";
import type { RaftPipes } from "@agentspaces/ordered";
import { FileLogStore } from "../src/file-log-store.js";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

test("term, vote, and entries survive a fresh instance; an earlier append replaces the tail", async () => {
  const dir = mkdtempSync(join(tmpdir(), "aspace-log-"));
  try {
    const store = new FileLogStore(dir);
    assert.deepEqual(await store.load(), { term: 0, votedFor: null, entries: [] });
    await store.saveTermVote(3, "zVoter");
    await store.append(1, [{ term: 1, command: utf8("one") }, { term: 2, command: utf8("two") }]);
    await store.append(3, [{ term: 3, command: utf8("three") }]);
    const again = new FileLogStore(dir);
    const state = await again.load();
    assert.equal(state.term, 3);
    assert.equal(state.votedFor, "zVoter");
    assert.deepEqual(state.entries.map((e) => [e.term, new TextDecoder().decode(e.command)]), [[1, "one"], [2, "two"], [3, "three"]]);
    await again.append(2, [{ term: 4, command: utf8("TWO") }]);
    const third = await new FileLogStore(dir).load();
    assert.deepEqual(third.entries.map((e) => [e.term, new TextDecoder().decode(e.command)]), [[1, "one"], [4, "TWO"]]);
    await again.truncateFrom(1);
    assert.deepEqual((await new FileLogStore(dir).load()).entries, []);
    await new FileLogStore(dir).saveTermVote(5, null);
    assert.equal((await new FileLogStore(dir).load()).votedFor, null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a torn tail record is dropped on load and the file trimmed to the last whole record", async () => {
  const dir = mkdtempSync(join(tmpdir(), "aspace-log-"));
  try {
    const store = new FileLogStore(dir);
    await store.append(1, [{ term: 1, command: utf8("whole") }]);
    const path = join(dir, "entries");
    const whole = statSync(path).size;
    appendFileSync(path, Buffer.from([0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 9, 1, 2])); // a record cut short
    const state = await new FileLogStore(dir).load();
    assert.equal(state.entries.length, 1);
    assert.equal(statSync(path).size, whole);
    // A corrupt whole record (bad CRC) is dropped too.
    const bytes = readFileSync(path);
    bytes[bytes.length - 1] ^= 0xff;
    rmSync(path);
    appendFileSync(path, bytes);
    assert.equal((await new FileLogStore(dir).load()).entries.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** A pair of voters on a bus of one loop: the vote one casts is written before its reply. */
class Bus {
  private readonly handlers = new Map<string, (from: string, payload: Uint8Array) => void>();
  pipes(peerId: string): RaftPipes {
    return {
      peerId,
      send: (to, payload) => { queueMicrotask(() => this.handlers.get(to)?.(peerId, payload)); },
      onFrame: (handler) => { this.handlers.set(peerId, handler); },
    };
  }
}

test("a voter restarted from its file store keeps its vote and does not vote twice in the term", async () => {
  const dir = mkdtempSync(join(tmpdir(), "aspace-log-"));
  try {
    const bus = new Bus();
    const store = new FileLogStore(dir);
    const voter = new RaftLog(bus.pipes("zB"), ["zA", "zB", "zC"], () => undefined, { store, tickMillis: 10 });
    await voter.ready();
    // A candidate asks for the vote; the reply follows the durable write.
    const replies: Uint8Array[] = [];
    bus.pipes("zA").onFrame((_from, payload) => replies.push(payload));
    const { frame } = await import("@agentspaces/ordered");
    (voter as unknown as { onFrame(from: string, payload: Uint8Array): Promise<void> })
      .onFrame("zA", frame("requestVote", { term: 1, candidate: "zA", lastLogIndex: 0, lastLogTerm: 0 }));
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(replies.length, 1);
    // The term bump and the vote are two durable writes, both before the reply.
    assert.equal(store.writes, 2, "the term and the vote were durable before the reply");
    assert.deepEqual(await new FileLogStore(dir).load(), { term: 1, votedFor: "zA", entries: [] });
    const restarted = new RaftLog(bus.pipes("zB"), ["zA", "zB", "zC"], () => undefined, { store: new FileLogStore(dir), tickMillis: 10 });
    await restarted.ready();
    assert.equal(restarted.currentTerm(), 1);
    replies.length = 0;
    const other: Uint8Array[] = [];
    bus.pipes("zC").onFrame((_from, payload) => other.push(payload));
    (restarted as unknown as { onFrame(from: string, payload: Uint8Array): Promise<void> })
      .onFrame("zC", frame("requestVote", { term: 1, candidate: "zC", lastLogIndex: 0, lastLogTerm: 0 }));
    await new Promise((r) => setTimeout(r, 50));
    const { loads } = (await import("@agentspaces/client")).cbor;
    const reply = loads(other[0]) as { voteReply: { granted: boolean } };
    assert.equal(reply.voteReply.granted, false, "the durable vote for zA holds after the restart");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
