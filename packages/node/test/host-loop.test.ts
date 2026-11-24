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
 * The service host on due work (SPEC v0.1.36 §9.5; .parity-wt/PARITY-typescript.md): an idle host wakes for its
 * anti-entropy round every 10 s and its advertisement every 5 min by time, not on a 1 s ticker; a host that carries a
 * duty (a Raft voter) runs at its period; the loop is watched. On virtual time: no sleep.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Identity, VirtualTime, Watchdog } from "@agentspaces/client";
import { ANTI_ENTROPY_MILLIS, ServiceHost } from "../src/host.js";

const GROUP = "zHostLoop";

function hostOn(time: VirtualTime): { host: ServiceHost; rounds: () => number; intros: () => number } {
  const host = new ServiceHost(Identity.generate(), GROUP, { tickMillis: 1000, log: null, clock: time.wall });
  host.peer.timers = time;
  host.peer.watchdog = new Watchdog(time);
  let rounds = 0;
  let intros = 0;
  const peer = host.peer as unknown as { antiEntropyRound(): string | null; introduce(): void };
  peer.antiEntropyRound = () => { rounds += 1; return null; };
  peer.introduce = () => { intros += 1; };
  return { host, rounds: () => rounds, intros: () => intros };
}

test("an idle host paces anti-entropy and its advertisement by time and wakes rarely", async () => {
  const time = new VirtualTime();
  const { host, rounds, intros } = hostOn(time);
  await host.start();
  const startIntros = intros();
  const before = time.runs;
  await time.advanceAsync(10 * 60_000, 1_000); // the host's tick is async: let its continuations run
  assert.equal(rounds(), (10 * 60_000) / ANTI_ENTROPY_MILLIS, "a round every 10 s");
  assert.equal(intros() - startIntros, 2, "the advertisement every 5 minutes");
  const wakes = time.runs - before;
  // Before: a 1 s setInterval, 600 ticks in ten minutes. Now: the rounds, the watchdog's 2 s check, the backstop.
  assert.ok(host.ticks <= 70, `the host ran ${host.ticks} times in ten minutes`);
  assert.ok(wakes < 600, `${wakes} timer runs`);
  assert.deepEqual(host.loopHealth().overdue, []);
  await host.stop();
});

test("a host that carries a duty runs it at its period, and stops running it at stop", async () => {
  const time = new VirtualTime();
  const { host } = hostOn(time);
  await host.start();
  let duty = 0;
  host.addDuty({ tick: () => { duty += 1; }, suspend: () => undefined, resume: () => undefined });
  await time.advanceAsync(10_000, 100);
  assert.ok(duty >= 10 && duty <= 11, `the duty ran ${duty} times in 10 s at a 1 s period`);
  assert.equal(host.residency, "service", "an on-time period is no drift");
  await host.stop();
  const ran = duty;
  await time.advanceAsync(10_000, 100);
  assert.equal(duty, ran);
});

test("the cadence rule reads the monotonic clock: wall steps are no drift and do not hold back the recovery",
  async () => {
    const time = new VirtualTime();
    const { host } = hostOn(time);
    await host.start();
    const states: string[] = [];
    host.addDuty({ tick: () => undefined, suspend: () => states.push("suspend"), resume: () => states.push("resume") });
    await time.advanceAsync(5_000, 100);
    for (let i = 0; i < 4; i++) {
      time.stepWall(5_000); // NTP steps forward, a tick apart: each read as a 6 s gap on the wall
      await time.advanceAsync(1_000, 100);
    }
    assert.equal(host.drifts, 0, "a wall step is no late tick");
    assert.equal(host.residency, "service");
    // A real drift (three late ticks), then the wall steps back an hour: the 60 s recovery is still 60 s.
    for (let i = 0; i < 3; i++) {
      host.observeCadence(host.peer.monotonic() + 3_000 * (i + 1)); // the runtime stalled three periods running
    }
    assert.equal(host.residency, "visitor");
    time.stepWall(-3_600_000);
    await time.advanceAsync(70_000, 100);
    assert.equal(host.residency, "service", "recovered after 60 s on time, whatever the wall did");
    await host.stop();
  });
