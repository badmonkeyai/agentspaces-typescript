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
 * The leader's lease card and lease guard (SPEC v0.1.36 §8; event-loop parity, .parity-wt/PARITY-typescript.md):
 * `leaseUntil` holds still between publications and is renewed at a role or term change and at half the lease, so the
 * card is not republished on every tick; a leader that sent no heartbeat for the minimum election timeout (wedged), or
 * whose advertised lease ran out, stands down before it submits or commits. On injected clocks: no sleep.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { MemoryLogStore, RaftLog, RaftPipes, kindOf } from "../src/index.js";

class Bus {
  readonly handlers = new Map<string, (from: string, payload: Uint8Array) => void>();
  readonly down = new Set<string>();

  pipes(peerId: string): RaftPipes {
    return {
      peerId,
      send: (to, payload) => {
        void kindOf(payload);
        if (!this.down.has(peerId) && !this.down.has(to)) {
          queueMicrotask(() => this.handlers.get(to)?.(peerId, payload));
        }
      },
      onFrame: (handler) => { this.handlers.set(peerId, handler); },
    };
  }
}

const settle = () => new Promise((r) => setTimeout(r, 0));

async function cluster(clock: { wall: number; mono: number }) {
  const bus = new Bus();
  const ids = ["zA", "zB", "zC"];
  let next = 7;
  const random = () => { next = (next * 1103515245 + 12345) % 2147483648; return next / 2147483648; };
  const logs = new Map<string, RaftLog>();
  for (const id of ids) {
    const log = new RaftLog(bus.pipes(id), ids, () => undefined, { store: new MemoryLogStore(), random,
      clock: () => clock.wall, monotonic: () => clock.mono, tickMillis: 1000 });
    await log.ready();
    logs.set(id, log);
  }
  return { bus, logs };
}

async function tickAll(logs: Map<string, RaftLog>, clock: { wall: number; mono: number }, millis = 1000) {
  clock.wall += millis;
  clock.mono += millis;
  for (const log of logs.values()) {
    await log.tick();
  }
  await settle();
  await settle();
}

async function leaderOf(logs: Map<string, RaftLog>, clock: { wall: number; mono: number }): Promise<RaftLog> {
  for (let i = 0; i < 40; i++) {
    await tickAll(logs, clock);
    const leader = [...logs.values()].find((l) => l.isLeader());
    if (leader !== undefined) {
      return leader;
    }
  }
  throw new Error("no leader");
}

test("the leader's leaseUntil holds between ticks and is renewed at half the lease", async () => {
  const clock = { wall: 1_800_000_000_000, mono: 0 };
  const { logs } = await cluster(clock);
  const leader = await leaderOf(logs, clock);
  const issuedAt = clock.wall;
  const first = leader.parameters()["leaseUntil"]!;
  const until = Date.parse(first);
  assert.ok(until - issuedAt >= 5_000, "five to nine base periods");
  let changedAt: number | null = null;
  let unchangedTicks = 0;
  while (changedAt === null && clock.wall < until) {
    await tickAll(logs, clock);
    if (leader.parameters()["leaseUntil"] !== first) {
      changedAt = clock.wall;
    } else {
      unchangedTicks += 1;
    }
  }
  assert.ok(unchangedTicks >= 2, `held still for ${unchangedTicks} ticks`);
  assert.ok(changedAt !== null && changedAt >= issuedAt + (until - issuedAt) / 2, "renewed at half the lease, not before");
  assert.ok(leader.isLeader(), "a leader that keeps its heartbeat and its card keeps its role");
});

test("a wedged leader stands down at its last heartbeat plus the minimum election timeout, before it acts", async () => {
  const clock = { wall: 1_800_000_000_000, mono: 0 };
  const { logs } = await cluster(clock);
  const leader = await leaderOf(logs, clock);
  await tickAll(logs, clock);
  assert.ok(leader.isLeader());
  // The leader's runtime stalls 6 s (more than five base periods) with no heartbeat out; nothing else moves.
  clock.mono += 6_000;
  assert.equal(await leader.submit(new TextEncoder().encode("late")), false, "no leader, no hint: refused");
  assert.equal(leader.isLeader(), false);
  assert.equal(leader.leaseStepDowns, 1);
});

test("a leader stands down once the lease its last card advertised has run out", async () => {
  // Judged on the monotonic clock, as Java's lease guard is: the leader keeps its heartbeat (ticks), but its card is
  // never published again (nobody reads parameters()), so the lease its followers read runs out.
  const clock = { wall: 1_800_000_000_000, mono: 0 };
  const { logs } = await cluster(clock);
  const leader = await leaderOf(logs, clock);
  const until = Date.parse(leader.parameters()["leaseUntil"]!);
  const span = until - clock.wall;
  let ticked = 0;
  while (leader.isLeader() && ticked < 20) {
    clock.wall += 1000;
    clock.mono += 1000;
    await leader.tick(); // a heartbeat a base period: never silent
    ticked += 1;
  }
  assert.equal(leader.isLeader(), false);
  assert.equal(leader.leaseStepDowns, 1);
  assert.ok(ticked * 1000 >= span, `stood down at the lease's end (${ticked} s into a ${span} ms lease), not before`);
});

test("a wall step either way neither deposes the leader nor stalls its lease card", async () => {
  // SPEC v0.1.36 §9.5: local periods on the monotonic clock. Before, the half-lease and the lease guard read the wall:
  // a step back an hour held the card still for that hour (its followers read a lapsed lease), and a step forward
  // deposed a healthy leader.
  for (const step of [-3_600_000, 3_600_000]) {
    const clock = { wall: 1_800_000_000_000, mono: 0 };
    const { logs } = await cluster(clock);
    const leader = await leaderOf(logs, clock);
    leader.parameters();
    clock.wall += step;
    let lapsedTicks = 0;
    for (let i = 0; i < 12; i++) {
      await tickAll(logs, clock);
      assert.ok(leader.isLeader(), `still the leader ${i + 1} s after a ${step} ms step`);
      const until = Date.parse(leader.parameters()["leaseUntil"]!); // the host publishes what changed
      if (until <= clock.wall || until > clock.wall + 10_000) {
        lapsedTicks += 1; // a card whose lease a reader with this wall clock would judge lapsed, or absurdly long
      }
    }
    assert.equal(leader.leaseStepDowns, 0, `no stand-down on a ${step} ms step`);
    assert.equal(lapsedTicks, 0, `the card followed the step at once (${step} ms)`);
  }
});
