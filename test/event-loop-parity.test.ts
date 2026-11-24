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
 * Event-loop parity for the TypeScript peer (SPEC v0.1.36 §5.2, §7.4, §9.5; srad/agentspaces-event-loop.md;
 * .parity-wt/PARITY-typescript.md): virtual time, due work and the watchdog, the space sweep at the earliest lapse,
 * the resume after a wall step, the bounded relay table under the targeted relay, self-advertisement item ids, and
 * the settle guarantee's second rule paired from any frames with the displaced holder's re-offer. Every test runs on
 * virtual time: no sleep, no real timer.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { dumps, loads } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import { DISPLACED_PULL_MAX, LINK_ANSWER_MILLIS, LINK_QUIET_MILLIS, MAX_RELAYS, Peer, RELAY_HOLD_MILLIS, REOFFER_MAX,
  SEED_DIALS_IN_FLIGHT_MAX, SEED_STAGGER_MILLIS, horizonKindOf, leaseExpiryOf } from "../src/peer.js";
import { collectionHorizon } from "../src/horizon.js";
import type { TimerPort } from "../src/platform.js";
import { EXPIRED, Space, TakeContext, Taken, Template, entry } from "../src/space.js";
import { DueLoop, VirtualTime, Watchdog, WallStepDetector, flushMicrotasks } from "../src/time.js";
import { Aggregate, Settle } from "../src/capabilities/aggregate.js";
import { Pipes } from "../src/capabilities/pipes.js";
import { Binder, Bound, ON_ESTIMATE_DEFAULT_SETTLE_MILLIS, onEstimate, spaceTake } from "../src/agents.js";
import { TtlFloor, TtlFloorError } from "../src/ttl.js";
import { REDIAL_SPREAD, REDIAL_TABLE_MILLIS, RedialTable } from "../src/redial.js";
import type { FrameChannel } from "../src/transport.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import { MemoryChannel, MemoryNetwork, settle } from "../src/transport/mem.js";
import "../src/node/index.js";

const GROUP = "zTsEventLoop";
const MINUTE = 60_000;
const TASK = "com.acme.LoopTask#v1";

@entry("com.acme.LoopTask#v1")
class LoopTask {
  constructor(public job = 0) {}
}

// ---------------------------------------------------------------------------------------------------- virtual time

test("virtual time runs each due timer at its own instant, in order, and a wall step moves only the wall", () => {
  const time = new VirtualTime(1_000_000, 0);
  const seen: string[] = [];
  time.setTimeout(() => seen.push(`b@${time.now()}`), 200);
  time.setTimeout(() => {
    seen.push(`a@${time.now()}`);
    time.setTimeout(() => seen.push(`c@${time.now()}`), 50); // scheduled by a run, inside the span
  }, 100);
  const tick = time.every(300, () => seen.push(`e@${time.now()}`));
  time.advance(650);
  assert.deepEqual(seen, ["a@100", "c@150", "b@200", "e@300", "e@600"]);
  assert.equal(time.now(), 650);
  assert.equal(time.wall(), 1_000_650);
  tick.stop();
  time.stepWall(-5_000);
  assert.equal(time.now(), 650, "a wall step leaves the monotonic clock");
  assert.equal(time.wall(), 995_650);
  assert.equal(time.pending(), 0);
});

test("the wall-step detector sees a step either way and ignores the clocks moving together", () => {
  const time = new VirtualTime();
  const steps = new WallStepDetector(time.wall, () => time.now());
  time.advance(10_000);
  assert.equal(steps.look(), 0);
  time.stepWall(900);
  assert.equal(steps.look(), 0, "under a second is a slew, not a step");
  time.stepWall(45_000);
  assert.equal(steps.look(), 45_000);
  time.stepWall(-3_000);
  assert.equal(steps.look(), -3_000);
});

// ------------------------------------------------------------------------------------------------------- due work

test("due work: a task runs at its deadline and not before, a wake runs it at once, and an idle loop sleeps", () => {
  const time = new VirtualTime();
  const loop = new DueLoop(time, { wall: time.wall });
  const runs: number[] = [];
  loop.add("t", (now) => {
    runs.push(now);
    return now + 10_000;
  }, time.now() + 10_000);
  time.advance(9_999);
  assert.equal(runs.length, 0);
  time.advance(1);
  assert.equal(runs.length, 1);
  loop.wake("t");
  time.advance(0);
  assert.equal(runs.length, 2, "a wake runs the task at once");
  const before = time.runs;
  time.advance(60_000);
  assert.equal(runs.length, 8, "every 10 s from the wake: six more runs");
  assert.ok(time.runs - before <= 8, `one timer wake per run, no ticker (${time.runs - before})`);
  const health = loop.health();
  assert.equal(health.failures, 0);
  assert.equal(health.missedWakes, 0);
  assert.deepEqual(health.overdue, []);
  loop.stop();
});

test("due work: a task that throws is run again after the retry and the loop keeps its other tasks", () => {
  const time = new VirtualTime();
  const lines: string[] = [];
  const loop = new DueLoop(time, { wall: time.wall, log: (line) => lines.push(line) });
  let failing = 0;
  let steady = 0;
  loop.add("failing", (now) => {
    failing += 1;
    if (failing < 3) {
      throw new Error("boom");
    }
    return now + 5_000;
  });
  loop.add("steady", (now) => {
    steady += 1;
    return now + 1_000;
  });
  time.advance(3_000);
  assert.equal(failing, 3, "two failures retried after 1 s each, then a clean run");
  assert.equal(steady, 4);
  assert.equal(loop.health().failures, 2);
  assert.equal(lines.length, 2);
  loop.stop();
});

test("due work: a wall step asks every task again, and the watchdog re-arms a loop that lost its timer", () => {
  const time = new VirtualTime();
  // A timer port that drops the third timer the loop arms: a lost wake.
  let armed = 0;
  const lossy: TimerPort = {
    now: () => time.now(),
    setTimeout: (fn, millis) => (++armed === 4 ? null : time.setTimeout(fn, millis)),
    clearTimeout: (handle) => time.clearTimeout(handle),
    every: (period, fn) => time.every(period, fn),
  };
  const steps: number[] = [];
  const loop = new DueLoop(lossy, { wall: time.wall, onWallStep: (step) => steps.push(step) });
  let runs = 0;
  loop.add("expiry", (now) => {
    runs += 1;
    return now + 30_000;
  }, time.now() + 30_000);
  const dog = new Watchdog(time);
  dog.watch(loop);
  time.advance(30_000);
  assert.equal(runs, 1);
  time.advance(10_000);
  time.stepWall(5_000); // an NTP step forward: the task anchored to a wall expiry is asked again
  time.advance(2_000);
  assert.deepEqual(steps, [5_000]);
  assert.equal(runs, 2, "the step made the task due at once (seen by the watchdog's tick)");
  // The loop's next timer was the lossy one: nothing would run it.
  time.advance(40_000);
  assert.ok(loop.health().reinitialised >= 1, "the watchdog re-armed the loop");
  assert.ok(runs >= 3, `the due task ran after the re-arm (${runs})`);
  dog.unwatch(loop);
  loop.stop();
});

// ------------------------------------------------------------------------------------------ the space sweep as due work

/** A peer on virtual time whose sends are captured. */
class TimedPeer extends Peer {
  readonly sent: Array<{ kind: string; body: Uint8Array; to: string | null }> = [];

  constructor(readonly time: VirtualTime, identity: Identity = Identity.generate()) {
    super(identity, GROUP, time.wall);
    this.timers = time;
    this.watchdog = new Watchdog(time);
  }

  protected override send(kind: string, body: Uint8Array, to: string | null = null): void {
    this.sent.push({ kind, body, to });
  }

  rumors(): Dict[] {
    return this.sent.filter((s) => s.kind === "RUMOR").map((s) => loads(s.body) as Dict);
  }
}

test("the space sweep is due work: EXPIRED at the lease's end, and an idle watched space wakes rarely", () => {
  const time = new VirtualTime();
  const peer = new TimedPeer(time);
  const space = new Space(peer, "jobs");
  const events: string[] = [];
  space.watch(new Template(LoopTask), (e) => {
    if (e.kind === EXPIRED) {
      events.push(`${e.kind}@${time.wall()}`);
    }
  });
  const expiresAt = time.wall() + 5 * MINUTE;
  space.write(new LoopTask(1), 5 * MINUTE);
  const before = time.runs;
  time.advance(5 * MINUTE - 1);
  assert.deepEqual(events, []);
  time.advance(1);
  assert.deepEqual(events, [`${EXPIRED}@${expiresAt}`], "EXPIRED at the lapse, not a tick later");
  // Before: a 250 ms ticker, 1,200 runs in five minutes. Now: the lapse, the watchdog's 2 s check, and the backstop.
  const wakes = time.runs - before;
  assert.ok(wakes < 200, `an idle watched space woke ${wakes} times in five minutes`);
  assert.equal(peer.loop.health().missedWakes, 0);
  peer.close();
});

test("tombstone collection is due work: a withdrawal goes at its horizon, and the collector does not tick every second",
  () => {
    const time = new VirtualTime();
    const peer = new TimedPeer(time);
    new Space(peer, "jobs");
    const id = peer.writeEntry("jobs", TASK, { job: 1 }, "w", MINUTE);
    peer.cancelEntry("jobs", id);
    const dto = peer.states.get(id)!;
    // The legacy horizon of a withdrawal: its expiry plus max(two longest leases, the drift floor).
    const horizonAt = collectionHorizon(horizonKindOf(dto), leaseExpiryOf(dto), MINUTE, "legacy");
    const runsBefore = peer.loop.health().runs;
    time.advance(horizonAt - time.wall() - MINUTE);
    assert.ok(peer.states.has(id), "kept until its horizon");
    time.advance(2 * MINUTE);
    assert.equal(peer.states.has(id), false, "collected at its horizon");
    const runs = peer.loop.health().runs - runsBefore;
    assert.ok(runs < 30, `${runs} loop runs until the horizon (a 1 s ticker ran about 700)`);
    peer.close();
  });

test("a peer that closes and opens again keeps its due work (a resident host's pause and resume)", () => {
  const time = new VirtualTime();
  const peer = new TimedPeer(time);
  const space = new Space(peer, "jobs");
  const expired: string[] = [];
  space.watch(new Template(LoopTask), (e) => {
    if (e.kind === EXPIRED) {
      expired.push(e.entry.entryId);
    }
  });
  const id = space.write(new LoopTask(1), 2 * MINUTE);
  peer.close(); // paused: nothing runs while closed
  time.advance(5 * MINUTE);
  assert.deepEqual(expired, []);
  assert.equal(peer.loop.health().running, false);
  peer.acceptChannel(recordingChannel()); // open again: the lapse already past runs at once
  time.advance(0);
  assert.deepEqual(expired, [id]);
  assert.equal(peer.loop.health().running, true);
  peer.close();
});

// ------------------------------------------------------------------------------------------------------- resume

/** A channel that records what is sent on it. */
function recordingChannel(): FrameChannel & { frames: Uint8Array[] } {
  const frames: Uint8Array[] = [];
  return {
    frames, scheme: "mem", remote: "mem:test",
    attestedPeer: () => null,
    send: (frame) => frames.push(frame),
    onFrame: () => undefined,
    onClose: () => undefined,
    close: () => undefined,
  };
}

test("a forward wall step longer than the member TTL (a suspend) re-introduces the peer at once", () => {
  const time = new VirtualTime();
  const peer = new Peer(Identity.generate(), GROUP, time.wall);
  peer.timers = time;
  peer.watchdog = new Watchdog(time);
  const channel = recordingChannel();
  peer.acceptChannel(channel);
  const introduced = channel.frames.length;
  time.advance(10_000);
  time.stepWall(20_000); // a short step: every deadline asked again, no resume
  time.advance(2_000);
  assert.equal(peer.resumes, 0);
  time.stepWall(45 * MINUTE); // the laptop slept 45 minutes: the monotonic clock did not count it
  time.advance(2_000);
  assert.equal(peer.resumes, 1);
  assert.ok(channel.frames.length > introduced, "the self-advertisement went out on the link at once");
  peer.close();
});

// --------------------------------------------------------------------------------------------- the relay table

test("PING_REQ relays are bounded by time and size, and a target with no route is not flooded", () => {
  const time = new VirtualTime();
  const peer = new TimedPeer(time);
  const relay = peer as unknown as { onPingReq(from: string, request: Dict): void };
  const target = Identity.generate().peerId;
  // No link to the target and no dialed channel: the PING would have gone to every link.
  relay.onPingReq(Identity.generate().peerId, { target, nonce: 1 });
  assert.equal(peer.pingReqsUnroutable, 1);
  assert.equal(peer.sent.length, 0);
  // Holding the target's link (the member a dial-only peer names in relay.via), a dead target never answers.
  const link = peer.acceptChannel(recordingChannel());
  link.peers.add(target);
  peer.sent.length = 0;
  for (let i = 0; i < MAX_RELAYS + 500; i++) {
    relay.onPingReq(Identity.generate().peerId, { target, nonce: i });
    time.advance(1);
  }
  assert.ok(peer.relaysInFlight <= MAX_RELAYS, `${peer.relaysInFlight} relays held`);
  assert.equal(peer.sent.filter((s) => s.kind === "PING").length, MAX_RELAYS + 500, "every request relayed once");
  time.advance(RELAY_HOLD_MILLIS + 1);
  relay.onPingReq(Identity.generate().peerId, { target, nonce: 99_999 });
  assert.equal(peer.relaysInFlight, 1, "past their hold the unanswered relays are forgotten");
  assert.ok(peer.relaysExpired >= MAX_RELAYS + 500);
  peer.close();
});

// --------------------------------------------------------------------------------------- self-advertisement ids

test("two self-advertisements in one millisecond travel under distinct, increasing item ids", () => {
  const time = new VirtualTime();
  const peer = new TimedPeer(time);
  peer.introduce();
  peer.resourceHints["relay.via"] = Identity.generate().peerId; // a changed advertisement, the same millisecond
  peer.introduce();
  const ids = peer.rumors().filter((r) => r["streamId"] === "peers").map((r) => String(r["itemId"]));
  assert.equal(ids.length, 2);
  assert.notEqual(ids[0], ids[1]);
  const millis = ids.map((id) => Number(id.substring(id.lastIndexOf(":") + 1)));
  assert.equal(millis[1], millis[0] + 1);
  peer.close();
});

// ------------------------------------------------------------------- the settle guarantee's second rule, paired

/** A member of a race on shared virtual time: its rumors are captured, `deliver` hands it another's. */
class Member extends TimedPeer {
  readonly space: Space;
  private counter = 0;

  constructor(time: VirtualTime) {
    super(time);
    this.space = new Space(this, "tasks");
  }

  deliver(sender: Peer, body: Uint8Array): void {
    const stamp = `${this.time.wall()}:${this.counter++}:${sender.identity.peerId}`;
    (this as unknown as { onFrame(frame: Uint8Array): void }).onFrame(wire.encodeFrame(
      wire.envelope(GROUP, "RUMOR", sender.identity.peerId, stamp, body, this.identity.peerId), sender.identity));
  }

  claimAt(id: string, stampMillis: number): Dict {
    const spaceId = String((this.states.get(id)!["record"] as Dict)["spaceId"]);
    const worker = this.identity.agent("worker");
    return wire.signedClaim(wire.takeClaim(id, spaceId, 1, `${stampMillis}:0:${worker}`, worker, 0.0,
      this.time.wall() + 10 * MINUTE), this.identity, null);
  }

  hold(id: string, signed: Dict): void {
    this.restoreSnapshot({ group: GROUP, states: [], claims: { [id]: signed } });
  }
}

/** A writer, a winner `b` (the earlier claim), and a displaced holder `c` that completed under its later claim. */
function settleRace() {
  const time = new VirtualTime();
  const a = new Member(time);
  const b = new Member(time);
  const c = new Member(time);
  const id = a.writeEntry("tasks", TASK, { job: 1 }, "w", 30 * MINUTE);
  for (const r of a.sent.filter((s) => s.kind === "RUMOR")) {
    b.deliver(a, r.body);
    c.deliver(a, r.body);
  }
  const now = time.wall();
  const bClaim = b.claimAt(id, now);
  const cClaim = c.claimAt(id, now + 10);
  b.hold(id, bClaim);
  c.hold(id, cClaim);
  c.sent.length = 0;
  c.completeEntry("tasks", id); // c never heard of b's claim: it did the work
  const completion = loads(c.rumors()[0]!["payload"] as Uint8Array) as Dict;
  const stateOnly = wire.rumorBody("space:tasks", `d:${id}`, 6,
    encodeDelta({ state: completion["state"], claimEntry: null, claim: null }));
  const claimOnly = wire.rumorBody("space:tasks", `c:${id}:x`, 6, wire.claimDelta(id, cClaim));
  return { time, a, b, c, id, bClaim, cClaim, stateOnly, claimOnly, writerBodies: a.sent.map((s) => s.body) };
}

/** A space delta as a completion's rumor carries it. */
function encodeDelta(delta: Dict): Uint8Array {
  return dumps(delta);
}

for (const order of ["claim first", "completion first"] as const) {
  test(`rule two: the winner pairs a displaced claim and its completion from different frames (${order})`, () => {
    const { b, c, id, stateOnly, claimOnly } = settleRace();
    if (order === "claim first") {
      b.deliver(c, claimOnly);
      assert.equal(b.knowsDisplacedCompletion(id), false);
      b.deliver(c, stateOnly);
    } else {
      b.deliver(c, stateOnly);
      assert.equal(b.knowsDisplacedCompletion(id), false, "a completion alone proves nothing");
      b.deliver(c, claimOnly);
    }
    assert.equal(b.knowsDisplacedCompletion(id), true);
    assert.notEqual(b.states.get(id)!["completed"], true, "the displaced completion itself stays dropped");
    b.sent.length = 0;
    const taken = new Taken(b.space, id, { job: 1 }, MINUTE);
    assert.throws(() => taken.complete(new LoopTask(2)), /acknowledged a displaced holder's completion/);
    assert.equal(b.states.get(id)!["completed"], true, "b completed under its own claim, with no result");
    assert.equal(b.rumors().filter((r) => String(r["itemId"]).startsWith("d:")).length, 1);
    assert.equal(b.rumors().length, 1, "no result entry went out");
    assert.equal(b.displacedAcknowledged, 1);
    assert.equal(b.duplicateCompletions, 0);
    b.close();
    c.close();
  });
}

test("rule two: a winner that already did the work counts the late displaced completion once as a duplicate", () => {
  const { b, c, id, stateOnly, claimOnly } = settleRace();
  b.completeEntry("tasks", id);
  b.deliver(c, claimOnly);
  b.deliver(c, stateOnly);
  b.deliver(c, stateOnly);
  assert.equal(b.duplicateCompletions, 1);
  assert.equal(b.displacedAcknowledged, 0);
  b.close();
  c.close();
});

test("rule two: a revoked or forged displaced completion is no evidence", () => {
  const { b, c, id, claimOnly, stateOnly } = settleRace();
  const forged = loads(stateOnly) as Dict;
  const delta = loads(forged["payload"] as Uint8Array) as Dict;
  const state = { ...(delta["state"] as Dict), stateSig: new Uint8Array(64) };
  b.deliver(c, claimOnly);
  b.deliver(c, wire.rumorBody("space:tasks", `d:${id}:f`, 6, encodeDelta({ state, claimEntry: null, claim: null })));
  assert.equal(b.knowsDisplacedCompletion(id), false);
  b.close();
  c.close();
});

test("the displaced holder re-offers its claim at once, then only on a stale offer after 1, 2, 4 s ..., six in all", () => {
  const { time, a, b, c, id, bClaim, writerBodies } = settleRace();
  c.sent.length = 0;
  c.deliver(b, wire.rumorBody("space:tasks", `c:${id}:b`, 6, wire.claimDelta(id, bClaim)));
  const offers = () => c.rumors().filter((r) => String(r["itemId"]).startsWith(`c:${id}:`)).length;
  assert.equal(offers(), 1, "offered at once when it adopts the better claim");
  const stale = () => {
    for (const body of writerBodies) {
      c.deliver(a, body); // the writer still offers the entry present: it has not heard of the completion
    }
  };
  time.advance(500);
  stale();
  assert.equal(offers(), 1, "no sooner than 1 s after the first");
  time.advance(600);
  stale();
  assert.equal(offers(), 2);
  time.advance(1_000);
  stale();
  assert.equal(offers(), 2, "the second backoff is 2 s");
  time.advance(1_100);
  stale();
  assert.equal(offers(), 3);
  for (let i = 0; i < 20; i++) {
    time.advance(20_000);
    stale();
  }
  assert.equal(offers(), REOFFER_MAX);
  assert.equal(c.displacedReoffers, REOFFER_MAX);
  time.advance(60 * MINUTE);
  stale();
  assert.equal(offers(), REOFFER_MAX, "nothing runs when idle, and the spent line is gone");
  a.close();
  b.close();
  c.close();
});

// --------------------------------------------------------------------------------------------- push-sum timing

type Internals = { handle(env: Dict): void };

/** Members on one virtual clock whose addressed frames are handed straight to their peer. */
class AggPeer extends Peer {
  static readonly all = new Map<string, AggPeer>();

  constructor(readonly time: VirtualTime) {
    super(Identity.generate(), GROUP, time.wall);
    this.timers = time;
    this.watchdog = new Watchdog(time);
    AggPeer.all.set(this.identity.peerId, this);
  }

  protected override send(kind: string, body: Uint8Array, to: string | null = null): void {
    const env = wire.envelope(this.group, kind, this.identity.peerId, wire.hlcNow(this.identity.peerId, this.now()),
      body, to);
    const targets = to !== null ? [AggPeer.all.get(to)!]
      : [...AggPeer.all.values()].filter((p) => p !== this && p.time === this.time);
    for (const target of targets) {
      if (target !== undefined && target.accepts(env)) {
        (target as unknown as Internals).handle(env);
      }
    }
  }
}

/** Pipes that count the aggregate frames they send. */
class CountingPipes extends Pipes {
  sent = 0;

  override send(to: string, capabilityType: string, payload: Uint8Array, via: string[] | null = null): void {
    this.sent += 1;
    super.send(to, capabilityType, payload, via);
  }
}

test("push-sum: a round a second, a span settles on silence at its last move plus the span, quiet epochs share "
  + "nothing, and an idle epoch is forgotten after an hour", async () => {
  const time = new VirtualTime();
  const a = new AggPeer(time);
  const b = new AggPeer(time);
  a.introduce();
  b.introduce();
  const pipesA = new CountingPipes(a);
  const aggA = new Aggregate(pipesA);
  const aggB = new Aggregate(new Pipes(b));
  aggA.start("load", 10);
  aggB.start("load", 30);
  aggA.run();
  aggB.run();
  const fired: Array<{ value: number; at: number }> = [];
  aggA.onEstimate((e) => e === "load", Settle.after("10s", 0.001), (e) => fired.push({ value: e.value, at: time.now() }));
  const start = time.now();
  time.advance(999);
  assert.equal(pipesA.sent, 0, "no round before a second has passed");
  time.advance(1);
  assert.ok(pipesA.sent > 0, "the first round at one second");
  time.advance(5_000);
  aggB.close(); // B stops sharing: A hears nothing more
  const silentFrom = time.now();
  await time.advanceAsync(30_000);
  assert.equal(fired.length, 1, "settled once, on silence");
  assert.ok(Math.abs(fired[0]!.value - 20) < 0.5, `the fleet mean (${fired[0]!.value})`);
  assert.ok(fired[0]!.at - start <= silentFrom - start + 11_000, "within the span of the last move");
  // A's estimate no longer moves: after the quiet span it shares nothing, and after an hour it forgets the epoch.
  time.advance(31_000);
  const before = pipesA.sent;
  time.advance(10_000);
  assert.equal(pipesA.sent, before, "a quiet epoch shares nothing");
  assert.ok(aggA.quietRounds > 0);
  time.advance(61 * MINUTE);
  assert.equal(aggA.knownEpochIds().size, 0, "forgotten after the retention");
  assert.ok(aggA.evicted >= 1);
  aggA.close();
  a.close();
  b.close();
});

test("push-sum: the count form reads ticks as rounds of one second", async () => {
  const time = new VirtualTime();
  const solo = new AggPeer(time);
  const agg = new Aggregate(new Pipes(solo));
  agg.start("solo", 7);
  const fired: number[] = [];
  agg.onEstimate((e) => e === "solo", Settle.after(5, 0.01), () => fired.push(time.now()));
  const start = time.now();
  agg.run();
  await time.advanceAsync(10_000);
  assert.equal(fired.length, 1);
  assert.ok(fired[0]! - start >= 5_000 && fired[0]! - start <= 7_000, `settled after ${fired[0]! - start} ms`);
  agg.close();
  solo.close();
});

// ------------------------------------------------------------------------------------------------- the TTL floor

test("the TTL floor warns once under 60 s, passes a registered default and a reasoned override, refuses when strict",
  () => {
    const lines: string[] = [];
    const floor = new TtlFloor({ log: (line) => lines.push(line), overrides: { "binder.A.m.lease": "a 20 s SLA" } });
    assert.equal(floor.check("binder.B.m.lease", 60_000), false, "60 s is the floor itself");
    assert.equal(floor.check("binder.B.m.lease", 20_000), true);
    floor.check("binder.B.m.lease", 20_000);
    assert.equal(lines.length, 1, "warned once per key");
    assert.equal(floor.check("binder.C.m.lease", 30_000, "orderedTake.lease"), true);
    assert.equal(lines.length, 1, "the registered default passes silently");
    floor.check("binder.A.m.lease", 20_000);
    assert.deepEqual(floor.findings.map((f) => f.outcome), ["warned", "override"]);
    const strict = new TtlFloor({ strict: true, log: null });
    assert.throws(() => strict.check("binder.B.m.lease", 20_000), TtlFloorError);
    assert.doesNotThrow(() => strict.check("binder.C.m.lease", 30_000, "orderedTake.lease"));
    assert.throws(() => new TtlFloor({ overrides: { "x": " " } }), /needs a reason/);
  });

class ShortLeases {
  @spaceTake(LoopTask, "jobs", { lease: "20s" })
  handle(_task: LoopTask): void {}
}

test("the binder judges every lease member of its verbs against the floor at bind", () => {
  const time = new VirtualTime();
  const peer = new TimedPeer(time);
  const strict = new Binder(peer, { publishCard: false, residency: "service",
    ttlFloor: new TtlFloor({ strict: true, log: null }) });
  assert.throws(() => strict.bind(new ShortLeases()), /binder\.ShortLeases\.handle\.lease = 20000 ms/);
  const lenient = new Binder(peer, { publishCard: false, residency: "service", ttlFloor: new TtlFloor({ log: null }) });
  const bound = lenient.bind(new ShortLeases());
  assert.deepEqual(lenient.ttlFloor.findings.map((f) => `${f.key}:${f.outcome}`),
    ["binder.ShortLeases.handle.lease:warned"]);
  void bound.close();
  peer.close();
});

test("an ordered take's lease is renewed at half the lease while its handler runs, and stops at the hold limit",
  async () => {
    const time = new VirtualTime();
    const writer = new Member(time);
    const holder = new Member(time);
    const id = writer.writeEntry("tasks", TASK, { job: 3 }, "w", 30 * MINUTE);
    for (const r of writer.sent.filter((s) => s.kind === "RUMOR")) {
      holder.deliver(writer, r.body);
    }
    holder.hold(id, holder.claimAt(id, time.wall()));
    const binder = new Binder(holder, { publishCard: false, residency: "service", holdLimit: "50s" });
    const bound = { running: true };
    const taken = new Taken(holder.space, id, { job: 3 }, 20_000);
    const renew = (binder as unknown as { renewWhileRunning(b: unknown, t: Taken<unknown>): { stop(): void } })
      .renewWhileRunning(bound, taken);
    const expiry = () => Number((holder.claims.get(id)!["claim"] as Dict)["expiresAtMillis"]);
    time.advance(10_000);
    assert.equal(binder.takeRenewals, 1, "renewed at half the 20 s lease");
    assert.ok(expiry() >= time.wall() + 20_000 - 1);
    time.advance(30_000);
    assert.equal(binder.takeRenewals, 4);
    time.advance(20_000);
    assert.equal(binder.holdLimitStops, 1, "the hold limit stops the renewals; the entry will lapse to another clerk");
    const renewals = binder.takeRenewals;
    time.advance(60_000);
    assert.equal(binder.takeRenewals, renewals);
    renew.stop();
    writer.close();
    holder.close();
  });

// ------------------------------------------------------------------ spirit review (2026-11-23): mixed-group seams
// Interactions the first pass did not name: who a probe's ACK reaches, what relay.via names after a failover, and a
// suspend that lands while the peer backs off between dials. Every test runs on virtual time or microtask delivery.

/** A hub listening at `address` on `net`, signed frames, on real microtask delivery. */
async function memHub(net: MemoryNetwork, address: string): Promise<{ hub: Peer; stop: () => void }> {
  const hub = new Peer(Identity.generate(), GROUP);
  hub.channelAuth = "signed";
  const unlisten = await net.listen(address, (channel) => hub.acceptChannel(channel));
  return { hub, stop: () => { unlisten(); hub.close(); } };
}

/** The ACKs a peer handles, captured in front of its handler. */
function tapAcks(peer: Peer): Array<{ from: string; nonce: number; onBehalf: unknown }> {
  const acks: Array<{ from: string; nonce: number; onBehalf: unknown }> = [];
  const internals = peer as unknown as { handle(env: Dict, ...rest: unknown[]): void };
  const previous = internals.handle;
  internals.handle = function (env: Dict, ...rest: unknown[]) {
    if (env["kind"] === "ACK") {
      const ack = loads(env["body"] as Uint8Array) as Dict;
      acks.push({ from: String(env["from"]), nonce: Number(ack["nonce"]), onBehalf: ack["onBehalf"] });
    }
    return previous.call(this, env, ...rest);
  };
  return acks;
}

test("a PING relayed through the seed is answered back through the seed, to the prober (SPEC v0.1.36 §5.2)",
  async () => {
    const net = new MemoryNetwork();
    const { hub, stop } = await memHub(net, "hub:1");
    const [a, b] = [new Peer(Identity.generate(), GROUP), new Peer(Identity.generate(), GROUP)];
    try {
      for (const p of [a, b]) {
        p.channelAuth = "signed";
        p.registerDialer(net.dialer());
        await p.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
      }
      await settle(8);
      b.seedPeer ??= hub.identity.peerId; // the seed carries b's frames to every other member (SPEC §5.4)
      assert.equal(b.relayFor(a.identity.peerId), hub.identity.peerId);
      const bAcks = tapAcks(b);
      const hubAcks = tapAcks(hub);
      // b probes a through the seed (a Java prober with a relay path does the same): a RELAY_FRAME carries the PING.
      b.sendAddressed("PING", wire.pingBody(4242), a.identity.peerId);
      await settle(8);
      assert.deepEqual(bAcks.filter((x) => x.nonce === 4242).map((x) => x.from), [a.identity.peerId],
        "the prober heard the target's own ACK under its nonce");
      assert.equal(hubAcks.length, 0, "the seed, which never asked, was not answered");
      assert.equal(a.probesAnsweredRelayed, 1);
    } finally {
      a.close();
      b.close();
      stop();
    }
  });

test("a direct PING is answered to its prober on its link, not on every link the hub holds", async () => {
  const net = new MemoryNetwork();
  const { hub, stop } = await memHub(net, "hub:1");
  const [a, b] = [new Peer(Identity.generate(), GROUP), new Peer(Identity.generate(), GROUP)];
  try {
    for (const p of [a, b]) {
      p.channelAuth = "signed";
      p.registerDialer(net.dialer());
      await p.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    }
    await settle(8);
    const aAcks = tapAcks(a);
    const bAcks = tapAcks(b);
    (a as unknown as { send(kind: string, body: Uint8Array, to: string | null): void })
      .send("PING", wire.pingBody(77), hub.identity.peerId);
    await settle(8);
    assert.deepEqual(aAcks.map((x) => [x.from, x.nonce]), [[hub.identity.peerId, 77]]);
    assert.equal(bAcks.length, 0, "a bystander on another link hears no ACK");
  } finally {
    a.close();
    b.close();
    stop();
  }
});

/** A peer on virtual time that records the relay.via each self-advertisement carried. */
class ViaPeer extends Peer {
  readonly vias: Array<string | undefined> = [];

  constructor(readonly time: VirtualTime) {
    super(Identity.generate(), GROUP, time.wall);
    this.timers = time;
    this.watchdog = new Watchdog(time);
    this.channelAuth = "signed";
  }

  override introduce(): void {
    this.vias.push(this.resourceHints["relay.via"]);
    super.introduce();
  }
}

test("a failover to another seed withdraws a relay.via naming the old seed before the first advertisement", async () => {
  const net = new MemoryNetwork();
  const one = await memHub(net, "one:1");
  const two = await memHub(net, "two:1");
  const time = new VirtualTime(Date.now()); // the hubs run on the real clock: their frames must not look far off
  const a = new ViaPeer(time);
  a.registerDialer(net.dialer());
  try {
    await a.connectAny([{ host: "one", port: 1, scheme: "mem" }, { host: "two", port: 1, scheme: "mem" }]);
    await settle(8);
    // The seed's addressed frame names it; a test sends one if the handshake did not.
    if (a.seedPeer === null) {
      (one.hub as unknown as { send(kind: string, body: Uint8Array, to: string | null): void })
        .send("PING", wire.pingBody(1), a.identity.peerId);
      await settle(8);
    }
    assert.equal(a.resourceHints["relay.via"], one.hub.identity.peerId);
    time.advance(30_000); // a link of some age: its end is no quick drop
    a.vias.length = 0;
    one.stop(); // the first seed goes; the close signal fails over to the second
    await settle(12);
    assert.ok(a.connected(), "failed over");
    assert.ok(a.vias.length >= 1, "the peer introduced itself on the new link");
    assert.ok(a.vias.every((via) => via !== one.hub.identity.peerId),
      `no advertisement after the failover names the old seed (${JSON.stringify(a.vias)})`);
    assert.equal(a.relayViaCleared, 1);
    // The new seed's first addressed frame names it.
    (two.hub as unknown as { send(kind: string, body: Uint8Array, to: string | null): void })
      .send("PING", wire.pingBody(2), a.identity.peerId);
    await settle(8);
    assert.equal(a.resourceHints["relay.via"], two.hub.identity.peerId);
  } finally {
    a.close();
    two.stop();
  }
});

test("a seed the transport attests is named in relay.via at the dial", async () => {
  const net = new MemoryNetwork();
  const { hub, stop } = await memHub(net, "hub:1");
  const attesting = net.dialer();
  const time = new VirtualTime();
  const a = new ViaPeer(time);
  a.registerDialer({ ...attesting, dial: async (seed, options) => {
    const channel = await attesting.dial(seed, options) as unknown as { attested: string | null };
    channel.attested = hub.identity.peerId;
    return channel as unknown as FrameChannel;
  } });
  try {
    await a.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    assert.equal(a.vias[0], hub.identity.peerId, "the first advertisement already names the attested seed");
  } finally {
    a.close();
    stop();
  }
});

test("a suspend while backing off between dials dials at once on the wake, not after the rest of the pause",
  async () => {
    const net = new MemoryNetwork();
    let seed = await memHub(net, "hub:1");
    const time = new VirtualTime();
    const a = new ViaPeer(time);
    a.registerDialer(net.dialer());
    try {
      await a.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
      time.advance(30_000);
      seed.stop(); // the seed goes: one round of dials is refused and the peer pauses before the next
      await settle(12);
      assert.equal(a.connected(), false);
      assert.ok(net.refused >= 1, "the round was refused");
      seed = await memHub(net, "hub:1"); // the seed is back while the laptop sleeps
      time.advance(1_000); // inside the pause (5 s at least)
      await settle(4);
      assert.equal(a.connected(), false, "still pausing");
      time.stepWall(45 * MINUTE); // the lid opens: the wall moved 45 minutes, the monotonic clock did not
      time.advance(2_000); // the watchdog's tick sees the step
      await settle(12);
      assert.ok(a.connected(), "the resume dialled at once");
      assert.equal(a.resumes, 1);
      assert.equal(a.resumeRedials, 1);
    } finally {
      a.close();
      seed.stop();
    }
  });

test("a peer closed while it pauses between dials re-dials again when it connects later", async () => {
  const net = new MemoryNetwork();
  let seed = await memHub(net, "hub:1");
  const time = new VirtualTime();
  const a = new ViaPeer(time);
  a.registerDialer(net.dialer());
  try {
    await a.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    time.advance(30_000);
    seed.stop();
    await settle(12);
    a.close(); // closed in the pause
    seed = await memHub(net, "hub:1");
    await a.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    time.advance(30_000);
    seed.stop();
    seed = await memHub(net, "hub:1");
    await settle(12);
    assert.ok(a.connected(), "the lost link was re-dialled: the closed pause left no reconnect in progress");
  } finally {
    a.close();
    seed.stop();
  }
});

test("a dial-only peer asked to relay a probe reaches the target through its seed, and vouches back", async () => {
  const net = new MemoryNetwork();
  const { hub, stop } = await memHub(net, "hub:1");
  const [a, b] = [new Peer(Identity.generate(), GROUP), new Peer(Identity.generate(), GROUP)];
  try {
    for (const p of [a, b]) {
      p.channelAuth = "signed";
      p.registerDialer(net.dialer());
      await p.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    }
    await settle(8);
    a.seedPeer ??= hub.identity.peerId;
    b.seedPeer ??= hub.identity.peerId;
    const hubAcks = tapAcks(hub);
    // The hub stands in for a Java prober whose escalated round picked a, a dial-only member, as a random relay.
    (hub as unknown as { send(kind: string, body: Uint8Array, to: string | null): void })
      .send("PING_REQ", dumps({ target: b.identity.peerId, nonce: 91 }), a.identity.peerId);
    await settle(12);
    assert.deepEqual(hubAcks.filter((x) => x.nonce === 91).map((x) => [x.from, x.onBehalf]),
      [[a.identity.peerId, b.identity.peerId]], "a vouched for b to the asker");
    assert.equal(a.relaysInFlight, 0, "the relay was answered and forgotten");
  } finally {
    a.close();
    b.close();
    stop();
  }
});

test("a watchdog tick that comes back 30 s late is a resume where the monotonic clock counted the suspend", () => {
  // A runtime whose monotonic clock counts a suspend (some browsers' performance.now()) shows no wall step: the
  // watchdog's own tick comes back late instead. The watchdog's clock is driven by hand; the peer's loop is virtual.
  let mono = 0;
  const port: TimerPort = {
    setTimeout: () => null, clearTimeout: () => undefined, now: () => mono,
    every: () => ({ lastDriftMillis: 0, lateRuns: 0, stop: () => undefined }),
  };
  const dog = new Watchdog(port);
  const time = new VirtualTime();
  const peer = new Peer(Identity.generate(), GROUP, time.wall);
  peer.timers = time;
  peer.watchdog = dog;
  const channel = recordingChannel();
  peer.acceptChannel(channel);
  const introduced = channel.frames.length;
  dog.checkAll();
  mono += 2_000;
  dog.checkAll();
  mono += 20_000; // a 20 s stall: late, but within the keepalive bound
  dog.checkAll();
  assert.equal(peer.resumes, 0);
  mono += 45 * MINUTE; // the lid was shut 45 minutes and this clock counted it; the wall moved with it (no step)
  time.advance(0);
  dog.checkAll();
  assert.equal(dog.lateWakes, 1, "the 20 s stall was no late wake");
  assert.equal(peer.lateWakeResumes, 1);
  assert.equal(peer.resumes, 1);
  assert.ok(channel.frames.length > introduced, "the self-advertisement went out at once");
  assert.equal(peer.loop.health().lateWakes, 1, "the loop heard the late wake once");
  peer.close();
});

// ------------------------------------------------------------------------------ round 2a: the owner's three rulings
// Owner decisions of 2026-11-23: (1) the dead-seed rule for every dial-only client, (2) dial-only peers answer their
// seed's DIGEST, (3) the §7.4 re-offer backoff on monotonic time. A laptop wake during a reconnect pause is covered by
// "a suspend while backing off between dials ..." above.

/** The kinds of the frames a channel's far end reads, decoded fully signed. */
function readKinds(channel: FrameChannel): string[] {
  const kinds: string[] = [];
  channel.onFrame((frame) => kinds.push(String(wire.decodeFrameDetailed(frame, {})?.env?.["kind"] ?? "?")));
  return kinds;
}

test("dead-seed rule: a seed silent for 45 s is pinged, and one that does not answer is left for the next seed "
  + "within the ping timeout", async () => {
  const net = new MemoryNetwork();
  const kinds: string[][] = [];
  await net.listen("dead:1", (channel) => { kinds.push(readKinds(channel)); }); // accepts, reads, never writes, no FIN
  const live = await memHub(net, "live:1");
  const time = new VirtualTime(Date.now()); // the live hub runs on the real clock: frames must not look far off
  const a = new ViaPeer(time);
  a.registerDialer(net.dialer());
  const pings = (): number => kinds.flat().filter((k) => k === "PING").length;
  try {
    await a.connectAny([{ host: "dead", port: 1, scheme: "mem" }, { host: "live", port: 1, scheme: "mem" }]);
    await settle(4);
    assert.equal(a.currentSeed()?.host, "dead");
    time.advance(LINK_QUIET_MILLIS - 1);
    await settle(4);
    assert.equal(pings(), 0, "not asked before 45 s of silence");
    time.advance(1);
    await settle(4);
    assert.equal(pings(), 1, "asked at 45 s");
    assert.equal(a.seedPings, 1);
    time.advance(LINK_ANSWER_MILLIS - 1);
    await settle(4);
    assert.ok(a.connected());
    assert.equal(a.currentSeed()?.host, "dead", "kept while the ping may still be answered");
    assert.equal(a.linksSilent, 0);
    time.advance(1);
    await settle(4);
    assert.equal(a.linksSilent, 0, "the verdict waits one turn for a frame already arrived");
    time.advance(1);
    await settle(12);
    assert.equal(a.linksSilent, 1, "unanswered for the ping timeout: the seed is lost");
    assert.ok(a.connected(), "failed over at once, with no backoff");
    assert.equal(a.currentSeed()?.host, "live");
    assert.equal(a.reconnects, 1);
    assert.equal(pings(), 1, "one PING, no retry storm");
  } finally {
    a.close();
    live.stop();
  }
});

test("dead-seed rule: the ping timeout is 2 s, and a frame read in the verdict's turn keeps the seed", async () => {
  assert.equal(LINK_QUIET_MILLIS, 45_000, "1.5 x the 30 s keepalive bound");
  assert.equal(LINK_ANSWER_MILLIS, 2_000, "the ping timeout a prober gives each PING (SPEC §9.4), as Python's");
  const net = new MemoryNetwork();
  const far: FrameChannel[] = [];
  await net.listen("slow:1", (channel) => { far.push(channel); readKinds(channel); }); // writes only when told
  const time = new VirtualTime(Date.now());
  const a = new ViaPeer(time);
  a.registerDialer(net.dialer());
  try {
    await a.connectAny([{ host: "slow", port: 1, scheme: "mem" }]);
    await settle(4);
    time.advance(LINK_QUIET_MILLIS);
    await settle(4);
    assert.equal(a.seedPings, 1);
    time.advance(LINK_ANSWER_MILLIS); // the timer falls due in the same turn the seed's answer arrives
    far[0].send(new Uint8Array([0xa0])); // any frame read off the link is hearing the seed
    await settle(4);
    time.advance(1);
    await settle(4);
    assert.equal(a.linksSilent, 0, "a frame read before the verdict keeps the seed");
    assert.ok(a.connected());
    assert.equal(a.reconnects, 0);
  } finally {
    a.close();
  }
});

test("dead-seed rule: a seed that answers the PING is kept, and asked again only after 45 s more of silence",
  async () => {
    const net = new MemoryNetwork();
    const { hub, stop } = await memHub(net, "hub:1");
    const time = new VirtualTime(Date.now());
    const a = new ViaPeer(time);
    a.registerDialer(net.dialer());
    try {
      await a.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
      await settle(8);
      const acks = tapAcks(a);
      time.advance(LINK_QUIET_MILLIS);
      await settle(8);
      assert.equal(a.seedPings, 1);
      assert.deepEqual(acks.map((x) => x.from), [hub.identity.peerId], "the seed answered to its prober");
      time.advance(LINK_ANSWER_MILLIS);
      await settle(8);
      assert.ok(a.connected());
      assert.equal(a.linksSilent, 0, "an answering seed is kept");
      assert.equal(a.reconnects, 0);
      time.advance(LINK_QUIET_MILLIS - LINK_ANSWER_MILLIS - 1); // 45 s after the ACK, less a millisecond
      await settle(8);
      assert.equal(a.seedPings, 1, "the ACK counts as hearing the seed");
      time.advance(1);
      await settle(8);
      assert.equal(a.seedPings, 2, "one PING per 45 s on a quiet link");
      assert.equal(a.linksSilent, 0);
    } finally {
      a.close();
      stop();
    }
  });

/** A dial-only peer whose RUMORs are lost on its only link while `lose` is set. */
class LossyPeer extends Peer {
  lose = false;

  protected override send(kind: string, body: Uint8Array, to: string | null = null,
                          scope: "all" | "dial" = "all"): void {
    if (this.lose && kind === "RUMOR") {
      return;
    }
    super.send(kind, body, to, scope);
  }
}

test("a dial-only peer answers its seed's DIGEST, so its own rumor lost on its only link is repaired", async () => {
  const net = new MemoryNetwork();
  const { hub, stop } = await memHub(net, "hub:1");
  hub.pullSpace("tasks"); // the seed replicates the space
  const a = new LossyPeer(Identity.generate(), GROUP);
  a.channelAuth = "signed";
  a.registerDialer(net.dialer());
  try {
    await a.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    await settle(8);
    a.lose = true;
    const id = a.writeEntry("tasks", TASK, { job: 7 }); // written, never pulled: the space is joined only
    await settle(8);
    a.lose = false;
    assert.equal(hub.states.has(id), false, "the write's rumor was lost on the link");
    const answered = a.pullsAnswered;
    assert.equal(hub.antiEntropyRound(), a.identity.peerId, "the seed's round goes to its only link");
    await settle(16);
    assert.ok(a.pullsAnswered > answered, "the dial-only peer answered the seed's DIGEST");
    assert.ok(hub.states.has(id), "the seed holds the entry the lost rumor carried");
  } finally {
    a.close();
    stop();
  }
});

test("the re-offer backoff is judged on the monotonic clock: a wall step either way neither hastens nor holds it",
  () => {
    const { time, a, b, c, id, bClaim, writerBodies } = settleRace();
    c.sent.length = 0;
    c.deliver(b, wire.rumorBody("space:tasks", `c:${id}:b`, 6, wire.claimDelta(id, bClaim)));
    const offers = () => c.rumors().filter((r) => String(r["itemId"]).startsWith(`c:${id}:`)).length;
    const stale = () => {
      for (const body of writerBodies) {
        c.deliver(a, body);
      }
    };
    assert.equal(offers(), 1);
    time.advance(500);
    time.stepWall(4 * MINUTE); // forward: on the wall the 1 s backoff has long passed
    stale();
    assert.equal(offers(), 1, "a forward wall step does not bring the next offer forward");
    time.advance(600);
    stale();
    assert.equal(offers(), 2, "offered 1 s after the first on the monotonic clock");
    time.stepWall(-5 * MINUTE); // back: on the wall the 2 s backoff would now run five minutes more
    time.advance(2_100);
    stale();
    assert.equal(offers(), 3, "a backward wall step does not hold the next offer back");
    a.close();
    b.close();
    c.close();
  });

// ------------------------------------------------------------------- round 2b part 1: the redial table, seeds at once
// Owner decisions of 2026-11-23: (1) one redial table everywhere, 5, 10, 20, 30 s then wrap to 5 s, a spread of
// +/-10%, reset by a link that succeeded and by a wake that redials at once; (3) the seeds dialled at once, the first
// to answer winning. Every test runs on virtual time or microtask delivery.

test("redial table: 5, 10, 20, 30 s then wrap to 5 s, each wait within +/-10%, and a reset goes back to the first", () => {
  assert.deepEqual([...REDIAL_TABLE_MILLIS], [5_000, 10_000, 20_000, 30_000]);
  assert.equal(REDIAL_SPREAD, 0.1);
  const exact = new RedialTable(() => 0.5); // the middle of the spread: the table's own values
  assert.deepEqual(Array.from({ length: 9 }, () => exact.next()),
    [5_000, 10_000, 20_000, 30_000, 5_000, 10_000, 20_000, 30_000, 5_000]);
  assert.equal(exact.position, 1);
  exact.reset();
  assert.equal(exact.position, 0);
  assert.equal(exact.next(), 5_000);
  const scaled = new RedialTable(() => 0.5);
  assert.deepEqual(Array.from({ length: 5 }, () => scaled.next(100)), [100, 200, 400, 600, 100],
    "a shorter first wait keeps the table's shape");
  assert.equal(new RedialTable(() => 0).next(), 4_500, "the low edge is 10% under");
  const top = new RedialTable(() => 1 - Number.EPSILON).next();
  assert.ok(top < 5_500 && top > 5_499.99, `the high edge is 10% over, exclusive: ${top}`);
  const sampled = new RedialTable();
  let low = Infinity;
  let high = 0;
  for (let i = 0; i < 4_000; i++) {
    const base = REDIAL_TABLE_MILLIS[sampled.position]!;
    const ratio = sampled.next() / base;
    assert.ok(ratio >= 0.9 && ratio < 1.1, `a wait ${ratio} of its table value`);
    low = Math.min(low, ratio);
    high = Math.max(high, ratio);
  }
  assert.ok(low < 0.92 && high > 1.08, `the spread is used both ways (${low}, ${high}), so peers do not redial in step`);
});

/** A dialer over `net` that notes the virtual instant of every dial it starts. */
function notingDialer(net: MemoryNetwork, time: VirtualTime, dials: number[]) {
  const inner = net.dialer();
  return { ...inner, dial: (seed: Parameters<typeof inner.dial>[0], context?: Parameters<typeof inner.dial>[1]) => {
    dials.push(time.now());
    return inner.dial(seed, context);
  } };
}

/** Advances to `wait` after `from`, checking that the next dial comes exactly then and not a millisecond before. */
async function expectDialAfter(time: VirtualTime, dials: number[], from: number, wait: number): Promise<void> {
  const before = dials.length;
  time.advance(from + wait - 1 - time.now());
  await settle(8);
  assert.equal(dials.length, before, `no dial before ${wait} ms`);
  time.advance(1);
  await settle(8);
  assert.equal(dials.length, before + 1, `a dial at ${wait} ms`);
  assert.equal(dials.at(-1), from + wait);
}

test("redial table: refused rounds wait 5, 10, 20, 30 s then 5 s again, and a link that held resets the table",
  async () => {
    const net = new MemoryNetwork();
    let seed = await memHub(net, "hub:1");
    const time = new VirtualTime(Date.now()); // the hub runs on the real clock
    const a = new ViaPeer(time);
    a.redialTable = new RedialTable(() => 0.5);
    const dials: number[] = [];
    a.registerDialer(notingDialer(net, time, dials));
    try {
      const start = time.now();
      await a.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
      time.advance(30_000); // a link of some age: its end is no quick drop
      seed.stop();
      await settle(12);
      assert.equal(a.connected(), false);
      assert.deepEqual(dials, [start, start + 30_000], "the lost link is redialled at once");
      for (const wait of [5_000, 10_000, 20_000, 30_000, 5_000]) {
        await expectDialAfter(time, dials, dials.at(-1)!, wait);
      }
      assert.equal(a.redialTable.position, 2, "wrapped once: the pause now running is the 10 s");
      seed = await memHub(net, "hub:1");
      await expectDialAfter(time, dials, dials.at(-1)!, 10_000);
      assert.ok(a.connected(), "the seed answered the next round");
      time.advance(30_000); // the link holds: it succeeded
      seed.stop();
      await settle(12);
      assert.equal(dials.at(-1), time.now(), "redialled at once");
      assert.equal(a.connected(), false);
      await expectDialAfter(time, dials, dials.at(-1)!, 5_000); // the table starts again from its first wait
    } finally {
      a.close();
      seed.stop();
    }
  });

test("redial table: a seed that drops each link at once is redialled at 5, 10, 20, 30 s then 5 s, never in a loop",
  async () => {
    const net = new MemoryNetwork();
    const time = new VirtualTime(Date.now());
    const accepted: number[] = [];
    await net.listen("drop:1", (channel) => { accepted.push(time.now()); channel.close(); });
    const a = new ViaPeer(time);
    a.redialTable = new RedialTable(() => 0.5);
    const dials: number[] = [];
    a.registerDialer(notingDialer(net, time, dials));
    try {
      const start = time.now();
      await a.connectAny([{ host: "drop", port: 1, scheme: "mem" }]);
      await settle(12);
      assert.equal(a.connected(), false);
      assert.deepEqual(dials, [start]);
      for (const wait of [5_000, 10_000, 20_000, 30_000, 5_000]) {
        await expectDialAfter(time, dials, dials.at(-1)!, wait);
      }
      assert.deepEqual(accepted, dials, "every dial was accepted and dropped");
      assert.equal(a.reconnects, 0, "a link dropped before it settled is no reconnect");
    } finally {
      a.close();
    }
  });

test("redial table: a wake while backing off redials at once and the next wait is the first again", async () => {
  const net = new MemoryNetwork();
  const seed = await memHub(net, "hub:1");
  const time = new VirtualTime(Date.now());
  const a = new ViaPeer(time);
  a.redialTable = new RedialTable(() => 0.5);
  const dials: number[] = [];
  a.registerDialer(notingDialer(net, time, dials));
  try {
    await a.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    time.advance(30_000);
    seed.stop();
    await settle(12);
    for (const wait of [5_000, 10_000]) {
      await expectDialAfter(time, dials, dials.at(-1)!, wait);
    }
    assert.equal(a.redialTable.position, 3, "the pause now running is the 20 s, and the next would be 30 s");
    const count = dials.length;
    time.advance(1_000);
    time.stepWall(45 * MINUTE); // the lid opens: the wall moved 45 minutes, the monotonic clock did not
    time.advance(2_000); // the watchdog's tick sees the step
    await settle(12);
    assert.equal(a.resumes, 1);
    assert.equal(dials.length, count + 1, "the wake redialled at once");
    await expectDialAfter(time, dials, dials.at(-1)!, 5_000);
  } finally {
    a.close();
  }
});

test("lost seed last: the seed whose link just ended is dialled last, behind another seed that answers", async () => {
  const net = new MemoryNetwork();
  const one = await memHub(net, "one:1");
  const two = await memHub(net, "two:1");
  const time = new VirtualTime(Date.now());
  const a = new ViaPeer(time);
  a.registerDialer(net.dialer());
  try {
    await a.connectAny([{ host: "one", port: 1, scheme: "mem" }, { host: "two", port: 1, scheme: "mem" }]);
    assert.equal(a.currentSeed()?.host, "one", "the memory network answers in the order dialled");
    time.advance(30_000);
    a.currentChannel()!.close(); // as the dead-seed verdict closes a seed that still accepts dials
    await settle(12);
    assert.ok(a.connected());
    assert.equal(a.currentSeed()?.host, "two", "one, the lost seed, came last and was never dialled");
    a.currentChannel()!.close(); // now two's link ends at once: two is the lost seed, and one goes first
    await settle(12);
    assert.equal(a.connected(), false, "a quick drop waits the table");
    time.advance(5_500);
    await settle(12);
    assert.equal(a.currentSeed()?.host, "one");
    assert.ok(a.connected());
    one.stop();
    time.advance(30_000);
    await settle(12);
    assert.ok(a.connected(), "the lost seed is taken when no other answers");
    assert.equal(a.currentSeed()?.host, "two");
  } finally {
    a.close();
    two.stop();
  }
});

test("lost seed last: a seed that drops a reconnect before it settles is the one dialled last next, so a live seed is reached",
  async () => {
    const net = new MemoryNetwork();
    await net.listen("drop:1", (channel) => channel.close()); // accepts each dial and drops it at once
    const live = await memHub(net, "live:1");
    const time = new VirtualTime(Date.now());
    const a = new ViaPeer(time);
    a.redialTable = new RedialTable(() => 0.5);
    a.registerDialer(net.dialer());
    try {
      await a.connectAny([{ host: "drop", port: 1, scheme: "mem" }, { host: "live", port: 1, scheme: "mem" }]);
      await settle(12);
      time.advance(5_000); // drop answered first and dropped: dialled last, live answers the next round first
      await settle(12);
      assert.ok(a.connected());
      assert.equal(a.currentSeed()?.host, "live");
      time.advance(30_000);
      a.currentChannel()!.close(); // live's link ends after it held: live goes last, and drop answers first
      await settle(12);
      assert.equal(a.connected(), false, "drop won the round and dropped the link before the round settled");
      time.advance(5_500);
      await settle(12);
      assert.ok(a.connected(), "drop is now the lost seed, dialled last, so live becomes the link");
      assert.equal(a.currentSeed()?.host, "live");
    } finally {
      a.close();
      live.stop();
    }
  });

// ------------------------------------------------------------ harmonization (2026-11-23): one rule set in every client
// Owner decisions of 2026-11-23, identical in every client: (1) the redial table resets only when a link that held at
// least 5 s ends, or on a wake; a shorter link is a failed round and waits the next step; (2) the seeds are dialled in
// list order 250 ms apart (RFC 8305), a refusal starting the next at once, the first to answer winning, late channels
// closed, the seed just lost last; (3) a wake with the link up PINGs the seed under the dead-seed rule. Virtual time.

type DialMode = "up" | "refuse" | "silent";

/**
 * A dialer over `net` whose seeds each answer, refuse or stay silent as `modes` says (up by default), noting each dial
 * as [host, virtual instant]; a silent dial's answer waits in `silent` for the test to give it a channel.
 */
function scriptedDialer(net: MemoryNetwork, time: VirtualTime, modes: Map<string, DialMode>) {
  const inner = net.dialer();
  const dials: Array<[string, number]> = [];
  const instants: number[] = [];
  const silent: Array<{ host: string; answer: (channel: FrameChannel) => void }> = [];
  const dialer = { scheme: "mem", dial: (seed: Parameters<typeof inner.dial>[0], context?: Parameters<typeof inner.dial>[1]) => {
    dials.push([seed.host, time.now()]);
    instants.push(time.now());
    const mode = modes.get(seed.host) ?? "up";
    if (mode === "refuse") {
      return Promise.reject(new Error(`${seed.host} refused`));
    }
    if (mode === "silent") {
      return new Promise<FrameChannel>((answer) => { silent.push({ host: seed.host, answer }); });
    }
    return inner.dial(seed, context);
  } };
  return { dialer, dials, instants, silent };
}

const mem = (host: string) => ({ host, port: 1, scheme: "mem" });

test("harmonized redial: a link that held 4 s waits the next step; one that held 6 s resets the table and redials at once",
  async () => {
    const net = new MemoryNetwork();
    const seed = await memHub(net, "hub:1");
    const time = new VirtualTime(Date.now()); // the hub runs on the real clock
    const a = new ViaPeer(time);
    a.redialTable = new RedialTable(() => 0.5);
    const modes = new Map<string, DialMode>();
    const { dialer, dials, instants } = scriptedDialer(net, time, modes);
    a.registerDialer(dialer);
    try {
      await a.connectAny([mem("hub")]);
      time.advance(30_000);
      modes.set("hub", "refuse");
      a.currentChannel()!.close(); // a link that held: redialled at once, and refused
      await settle(12);
      assert.equal(instants.at(-1), time.now());
      await expectDialAfter(time, instants, time.now(), 5_000); // refused again: the table moved on
      modes.set("hub", "up");
      await expectDialAfter(time, instants, time.now(), 10_000);
      assert.ok(a.connected());
      assert.equal(a.redialTable.position, 2, "the next step is the 20 s");
      time.advance(4_000); // the link holds 4 s and ends
      a.currentChannel()!.close();
      await settle(12);
      const count = dials.length;
      assert.equal(a.connected(), false, "a 4 s link is a failed round: no redial at once");
      await expectDialAfter(time, instants, time.now(), 20_000);
      assert.equal(dials.length, count + 1);
      assert.ok(a.connected());
      assert.equal(a.redialTable.position, 3, "the 4 s link did not reset the table");
      time.advance(6_000); // the link holds 6 s and ends
      a.currentChannel()!.close();
      await settle(12);
      assert.equal(instants.at(-1), time.now(), "a 6 s link held: redialled at once");
      assert.ok(a.connected());
      assert.equal(a.redialTable.position, 0, "and the table is back at its first step");
      a.currentChannel()!.close(); // this new link ends at once: the wait is the first step, 5 s
      await settle(12);
      await expectDialAfter(time, instants, time.now(), 5_000);
    } finally {
      a.close();
      seed.stop();
    }
  });

test("seed stagger: a silent first seed costs 250 ms, and its late connection is closed", async () => {
  const net = new MemoryNetwork();
  const live = await memHub(net, "live:1");
  const time = new VirtualTime(Date.now());
  const a = new ViaPeer(time);
  const modes = new Map<string, DialMode>([["black", "silent"]]);
  const { dialer, dials, silent } = scriptedDialer(net, time, modes);
  a.registerDialer(dialer);
  try {
    assert.equal(SEED_STAGGER_MILLIS, 250, "RFC 8305's connection attempt delay");
    const t0 = time.now();
    let joined = false;
    void a.connectAny([mem("black"), mem("live")]).then(() => { joined = true; });
    await settle(8);
    assert.deepEqual(dials, [["black", t0]], "the first seed listed is dialled first, alone");
    time.advance(SEED_STAGGER_MILLIS - 1);
    await settle(8);
    assert.equal(dials.length, 1, "the next seed waits its 250 ms");
    assert.equal(joined, false);
    time.advance(1);
    await settle(8);
    assert.deepEqual(dials, [["black", t0], ["live", t0 + SEED_STAGGER_MILLIS]]);
    assert.ok(joined, "joined 250 ms in, not after the silent seed's connect timeout");
    assert.equal(a.currentSeed()?.host, "live");
    const [late] = MemoryChannel.pair("black:1", "dial:black:1");
    silent[0]!.answer(late);
    await settle(4);
    assert.ok(late.events.closed, "the late connection is closed");
    assert.equal(a.lateSeedChannels, 1);
    assert.equal(a.currentSeed()?.host, "live", "and never becomes the link");
  } finally {
    a.close();
    live.stop();
  }
});

test("seed stagger: a refused dial starts the next at once, and the seeds after the winner are never dialled",
  async () => {
    const net = new MemoryNetwork();
    const one = await memHub(net, "one:1");
    const two = await memHub(net, "two:1");
    const time = new VirtualTime(Date.now());
    const a = new ViaPeer(time);
    const { dialer, dials } = scriptedDialer(net, time, new Map([["gone", "refuse" as DialMode]]));
    a.registerDialer(dialer);
    try {
      const t0 = time.now();
      await a.connectAny([mem("gone"), mem("one"), mem("two")]);
      assert.deepEqual(dials, [["gone", t0], ["one", t0]], "the refusal started the next seed at the same instant");
      assert.equal(a.currentSeed()?.host, "one", "with every seed up, the first listed that answers wins");
      time.advance(10 * SEED_STAGGER_MILLIS);
      await settle(8);
      assert.equal(dials.length, 2, "the stagger was cancelled: two is never dialled");
      assert.equal(a.seedDials, 2);
    } finally {
      a.close();
      one.stop();
      two.stop();
    }
  });

test("seed stagger: the seed just lost is dialled last, 250 ms behind, and taken when the one before it is silent",
  async () => {
    const net = new MemoryNetwork();
    const one = await memHub(net, "one:1");
    const two = await memHub(net, "two:1");
    const time = new VirtualTime(Date.now());
    const a = new ViaPeer(time);
    const modes = new Map<string, DialMode>();
    const { dialer, dials, silent } = scriptedDialer(net, time, modes);
    a.registerDialer(dialer);
    try {
      await a.connectAny([mem("one"), mem("two")]);
      assert.equal(a.currentSeed()?.host, "one");
      time.advance(30_000);
      modes.set("two", "silent");
      a.currentChannel()!.close(); // one's link ends after it held: one is the lost seed
      await settle(8);
      const lostAt = time.now();
      assert.deepEqual(dials.slice(1), [["two", lostAt]], "the other seed first, the lost one not yet");
      time.advance(SEED_STAGGER_MILLIS);
      await settle(12);
      assert.deepEqual(dials.slice(1), [["two", lostAt], ["one", lostAt + SEED_STAGGER_MILLIS]],
        "the lost seed last, one stagger behind");
      assert.ok(a.connected());
      assert.equal(a.currentSeed()?.host, "one", "taken back when the seed before it stays silent");
      const [late] = MemoryChannel.pair("two:1", "dial:two:1");
      silent[0]!.answer(late);
      await settle(4);
      assert.ok(late.events.closed, "two's late connection is closed");
      assert.equal(a.currentSeed()?.host, "one");
    } finally {
      a.close();
      one.stop();
      two.stop();
    }
  });

test("wake while linked: the seed is PINGed and, silent for the 2 s ping timeout, left at once for the next seed",
  async () => {
    const net = new MemoryNetwork();
    const kinds: string[][] = [];
    await net.listen("dead:1", (channel) => { kinds.push(readKinds(channel)); }); // accepts, never writes, no FIN
    const live = await memHub(net, "live:1");
    const time = new VirtualTime(Date.now());
    const a = new ViaPeer(time);
    a.redialTable = new RedialTable(() => 0.5);
    a.redialTable.position = 3; // an earlier outage left the table on its 30 s step
    a.registerDialer(net.dialer());
    const pings = (): number => kinds.flat().filter((k) => k === "PING").length;
    try {
      await a.connectAny([mem("dead"), mem("live")]);
      await settle(4);
      assert.equal(a.currentSeed()?.host, "dead");
      time.advance(500); // a young link: its end would be a quick drop
      time.stepWall(45 * MINUTE); // the lid opens: the wall moved 45 minutes, the monotonic clock did not
      time.advance(2_000); // the watchdog's tick sees the step
      await settle(8);
      assert.equal(a.resumes, 1);
      assert.equal(a.wakePings, 1);
      assert.equal(pings(), 1, "the wake PINGed the seed rather than dropping the link");
      assert.equal(a.redialTable.position, 0, "the wake reset the table");
      assert.equal(a.currentSeed()?.host, "dead", "the link stays while the PING may be answered");
      const askedAt = a.loop.dueOf("seed-link")! - LINK_ANSWER_MILLIS;
      time.advance(askedAt + LINK_ANSWER_MILLIS - 1 - time.now());
      await settle(8);
      assert.equal(a.linksSilent, 0);
      assert.equal(a.currentSeed()?.host, "dead");
      time.advance(1);
      await settle(4);
      time.advance(1); // the verdict waits one turn for a frame already arrived
      await settle(12);
      assert.equal(a.linksSilent, 1, "no answer within the ping timeout: the seed is dead");
      assert.ok(a.connected(), "failed over at once, though the link was young");
      assert.equal(a.currentSeed()?.host, "live");
      assert.equal(a.reconnects, 1);
      assert.equal(pings(), 1);
    } finally {
      a.close();
      live.stop();
    }
  });

test("wake while linked: a seed that answers the PING keeps the link, with no redial", async () => {
  const net = new MemoryNetwork();
  const time = new VirtualTime(Date.now());
  // The hub reads the same virtual wall, so the step that wakes the peer moves the hub's clock with it, as one real
  // clock would; a hub on the real clock would drop frames stamped 45 minutes ahead.
  const hub = new Peer(Identity.generate(), GROUP, time.wall);
  hub.timers = time;
  hub.watchdog = new Watchdog(time);
  hub.channelAuth = "signed";
  const unlisten = await net.listen("hub:1", (channel) => hub.acceptChannel(channel));
  const stop = (): void => { unlisten(); hub.close(); };
  const a = new ViaPeer(time);
  const modes = new Map<string, DialMode>();
  const { dialer, dials } = scriptedDialer(net, time, modes);
  a.registerDialer(dialer);
  try {
    await a.connectAny([mem("hub")]);
    await settle(8);
    const acks = tapAcks(a);
    const channel = a.currentChannel();
    time.advance(1_000);
    time.stepWall(45 * MINUTE);
    time.advance(2_000);
    await settle(8);
    assert.equal(a.resumes, 1);
    assert.equal(a.wakePings, 1);
    assert.deepEqual(acks.map((x) => x.from), [hub.identity.peerId], "the seed answered the wake's PING");
    time.advance(3 * LINK_ANSWER_MILLIS);
    await settle(8);
    assert.equal(a.linksSilent, 0);
    assert.equal(a.currentChannel(), channel, "the same link: a PING costs one frame where a redial costs a handshake");
    assert.equal(dials.length, 1, "no redial");
    assert.equal(a.reconnects, 0);
  } finally {
    a.close();
    stop();
  }
});

test("seed stagger: at most 16 dials are in flight, and a failure starts the next at once (as Rust, Python and Ruby)",
  async () => {
    const time = new VirtualTime(Date.now());
    const a = new ViaPeer(time);
    const dials: Array<[string, number]> = [];
    const pending: Array<(e: Error) => void> = [];
    a.registerDialer({ scheme: "mem", dial: (seed: { host: string }) => {
      dials.push([seed.host, time.now()]);
      return new Promise<FrameChannel>((_answer, refuse) => { pending.push(refuse); });
    } } as never);
    try {
      assert.equal(SEED_DIALS_IN_FLIGHT_MAX, 16);
      const seeds = Array.from({ length: 20 }, (_, i) => mem(`s${i}`));
      void a.connectAny(seeds).catch(() => undefined);
      await settle(8);
      for (let i = 0; i < 20; i++) {
        time.advance(SEED_STAGGER_MILLIS);
        await settle(4);
      }
      assert.equal(dials.length, 16, "the 17th waits for a slot");
      const freed = time.now();
      pending[0]!(new Error("s0 timed out"));
      await settle(8);
      assert.deepEqual(dials[16], ["s16", freed], "a failure starts the next at once");
      assert.equal(dials.length, 17);
      time.advance(10 * SEED_STAGGER_MILLIS);
      await settle(8);
      assert.equal(dials.length, 17, "still 16 in flight: no more starts");
    } finally {
      a.close();
      pending.forEach((refuse) => refuse(new Error("closed")));
    }
  });

test("wake while linked: a PING already waiting is not sent again, and becomes the wake's (as Rust, Python and Ruby)",
  async () => {
    const net = new MemoryNetwork();
    const kinds: string[][] = [];
    await net.listen("dead:1", (channel) => { kinds.push(readKinds(channel)); }); // accepts, never writes, no FIN
    const live = await memHub(net, "live:1");
    const time = new VirtualTime(Date.now());
    const a = new ViaPeer(time);
    a.registerDialer(net.dialer());
    const pings = (): number => kinds.flat().filter((k) => k === "PING").length;
    try {
      await a.connectAny([mem("dead"), mem("live")]);
      await settle(4);
      time.advance(LINK_QUIET_MILLIS);
      await settle(8);
      assert.equal(pings(), 1, "the quiet seed is asked");
      const asked = a.loop.dueOf("seed-link")! - LINK_ANSWER_MILLIS;
      time.advance(500);
      (a as unknown as { onWallStep(ms: number): void }).onWallStep(45 * MINUTE);
      await settle(8);
      assert.equal(a.resumes, 1);
      assert.equal(pings(), 1, "the PING waiting is not sent again");
      assert.equal(a.wakePings, 0);
      assert.equal(a.loop.dueOf("seed-link"), asked + LINK_ANSWER_MILLIS, "judged on the PING waiting");
      time.advance(asked + LINK_ANSWER_MILLIS - time.now());
      await settle(4);
      time.advance(1); // the verdict waits one turn for a frame already arrived
      await settle(12);
      assert.equal(a.linksSilent, 1);
      assert.equal(a.currentSeed()?.host, "live", "failed over at once");
    } finally {
      a.close();
      live.stop();
    }
  });

// ------------------------------------------------------------- round 2b part 2 (2026-11-23): the owner's five decisions
// (1) a winner's targeted anti-entropy toward the holders its claim displaced (Java ReplicatedSpace.displacedPulls,
// owner decision 4 of phase 6); (2) the drift items for TypeScript (an unruled @onEstimate waits 8 s; a renewal from
// inside a handler obeys the binder's end, I-05); (4) the counter names; (5) C05, a wake re-checks every running take
// against its wall-time lease. Virtual time throughout; the relayed round runs on an in-memory hub.

/** Hands `to` a frame of any kind from `from`, addressed to it, as its link would. */
function hand(from: Peer, to: Peer, kind: string, body: Uint8Array): void {
  (to as unknown as { onFrame(frame: Uint8Array): void }).onFrame(wire.encodeFrame(
    wire.envelope(GROUP, kind, from.identity.peerId, wire.hlcNow(from.identity.peerId, to.now()), body,
      to.identity.peerId), from.identity));
}

/** The frames of one kind a captured peer sent to one member. */
function sentTo(peer: TimedPeer, kind: string, to: Peer): Array<{ kind: string; body: Uint8Array; to: string | null }> {
  return peer.sent.filter((s) => s.kind === kind && s.to === to.identity.peerId);
}

test("targeted round: a winner pulls its displaced holder at once, with no periodic round, and pairs the completion",
  () => {
    const { time, a, b, c, id, claimOnly } = settleRace();
    b.sent.length = 0;
    c.sent.length = 0;
    b.deliver(c, claimOnly); // b learns of c's claim, which its own displaces; c's completion is still c's alone
    assert.equal(b.knowsDisplacedCompletion(id), false);
    time.advance(0); // the loop's turn: nobody runs a periodic round (antiEntropyRound) on these peers
    const digests = sentTo(b, "DIGEST", c);
    assert.equal(digests.length, 1, "one targeted round, at once, to the displaced holder");
    assert.equal(b.displacedPullRounds, 1);
    hand(b, c, "DIGEST", digests[0]!.body);
    const answers = sentTo(c, "PULL_RESP", b);
    assert.equal(answers.length, 1, "the displaced holder answers with what the winner lacks");
    hand(c, b, "PULL_RESP", answers[0]!.body);
    assert.equal(b.knowsDisplacedCompletion(id), true, "paired within one targeted round");
    time.advance(MINUTE);
    assert.equal(sentTo(b, "DIGEST", c).length, 1, "the completion known, the rounds end");
    a.close();
    b.close();
    c.close();
  });

test("targeted round: with no answer, rounds at 0, 1, 3, 7, 15 and 31 s, six in all, then nothing", () => {
  const { time, a, b, c, claimOnly } = settleRace();
  b.sent.length = 0;
  b.deliver(c, claimOnly);
  const start = time.now();
  const at: number[] = [];
  let seen = 0;
  for (let t = 0; t <= 2 * MINUTE; t += 100) {
    time.advance(t === 0 ? 0 : 100);
    const n = sentTo(b, "DIGEST", c).length;
    for (; seen < n; seen++) {
      at.push(time.now() - start);
    }
  }
  assert.deepEqual(at, [0, 1_000, 3_000, 7_000, 15_000, 31_000]);
  assert.equal(b.displacedPullRounds, DISPLACED_PULL_MAX);
  a.close();
  b.close();
  c.close();
});

test("targeted round: a holder displaced in two spaces is asked for both in one round (cross-client review)", () => {
  // Java's antiEntropyWith digests every stream, and Ruby sends one DIGEST per space; a round that named only the last
  // entry's space left the other space's displaced completion to a random partner pick.
  const time = new VirtualTime();
  const a = new Member(time);
  const b = new Member(time);
  const c = new Member(time);
  for (const p of [a, b, c]) {
    new Space(p, "jobs");
  }
  const spaces = ["tasks", "jobs"];
  const ids = spaces.map((name, i) => a.writeEntry(name, TASK, { job: i }, "w", 30 * MINUTE));
  for (const r of a.sent.filter((s) => s.kind === "RUMOR")) {
    b.deliver(a, r.body);
    c.deliver(a, r.body);
  }
  const now = time.wall();
  const cClaims = ids.map((id) => {
    b.hold(id, b.claimAt(id, now));
    const cClaim = c.claimAt(id, now + 10);
    c.hold(id, cClaim);
    return cClaim;
  });
  b.sent.length = 0;
  ids.forEach((id, i) => b.deliver(c, wire.rumorBody(`space:${spaces[i]}`, `c:${id}:x`, 6,
    wire.claimDelta(id, cClaims[i]!))));
  time.advance(0);
  const named = new Set(sentTo(b, "DIGEST", c).flatMap((d) =>
    Object.keys(((loads(d.body) as Dict)["digests"] ?? {}) as Dict)));
  assert.deepEqual([...named].sort(), ["space:jobs", "space:tasks"], "both spaces in the round");
  assert.equal(b.displacedPullRounds, 1, "one round toward the holder, as Java counts it");
  a.close();
  b.close();
  c.close();
});

test("targeted round: a winner whose claim lapsed, or that completed the entry, asks no more", () => {
  const { time, a, b, c, id, claimOnly } = settleRace();
  b.sent.length = 0;
  b.deliver(c, claimOnly);
  time.advance(0);
  b.completeEntry("tasks", id); // b did the work itself: its take is closed
  time.advance(MINUTE);
  assert.equal(sentTo(b, "DIGEST", c).length, 1, "only the round before the completion");
  a.close();
  b.close();
  c.close();
});

/** A peer on virtual time whose rumors can be dropped before they leave. */
class MutePeer extends ViaPeer {
  mute = false;

  protected override send(kind: string, body: Uint8Array, to: string | null = null,
                          scope: "all" | "dial" = "all"): void {
    if (this.mute && kind === "RUMOR") {
      return;
    }
    super.send(kind, body, to, scope);
  }
}

/** A take claim of `peer`'s worker on `id`, stamped at `stampMillis`, expiring `leaseMillis` from now. */
function workerClaim(peer: Peer, id: string, stampMillis: number, leaseMillis = 10 * MINUTE): Dict {
  const spaceId = String((peer.states.get(id)!["record"] as Dict)["spaceId"]);
  const worker = peer.identity.agent("worker");
  return wire.signedClaim(wire.takeClaim(id, spaceId, 1, `${stampMillis}:0:${worker}`, worker, 0.0,
    peer.now() + leaseMillis), peer.identity, null);
}

test("targeted round through the seed: a dial-only winner reaches the displaced holder in a RELAY_FRAME, and the "
  + "holder's answer comes back the same way", async () => {
  const net = new MemoryNetwork();
  const { hub, stop } = await memHub(net, "hub:1");
  const time = new VirtualTime(Date.now()); // the hub runs on the real clock: frames must not look far off
  const b = new MutePeer(time);
  const c = new MutePeer(time);
  try {
    for (const p of [b, c]) {
      p.registerDialer(net.dialer());
      new Space(p, "tasks");
      await p.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    }
    await settle(8);
    b.seedPeer ??= hub.identity.peerId;
    c.seedPeer ??= hub.identity.peerId;
    const id = b.writeEntry("tasks", TASK, { job: 9 }, "w", 30 * MINUTE);
    await settle(8);
    assert.ok(c.states.has(id), "the seed carried the write to the other member");
    const now = time.wall();
    const bClaim = workerClaim(b, id, now);
    const cClaim = workerClaim(c, id, now + 10);
    b.restoreSnapshot({ group: GROUP, states: [], claims: { [id]: bClaim } });
    c.restoreSnapshot({ group: GROUP, states: [], claims: { [id]: cClaim } });
    c.mute = true;
    c.completeEntry("tasks", id); // the completion never leaves c: the holder is its only source (SPEC §11a.4)
    c.mute = false;
    await settle(8);
    assert.notEqual(b.states.get(id)!["completed"], true, "the completion stayed on c");
    (b as unknown as { foldClaim(id: string, signed: Dict): void }).foldClaim(id, cClaim);
    assert.equal(b.knowsDisplacedCompletion(id), false);
    const relayed = b.relayedFrames;
    time.advance(0);
    await settle(16);
    assert.equal(b.displacedPullRounds, 1);
    assert.ok(b.relayedFrames > relayed, "the DIGEST went through the seed in a RELAY_FRAME");
    assert.ok(c.relayedFrames > 0, "the holder's PULL_RESP went back through the seed too");
    assert.equal(b.knowsDisplacedCompletion(id), true, "the winner pairs the displaced holder's completion");
  } finally {
    b.close();
    c.close();
    stop();
  }
});

/** A writer and a holder whose worker holds `id` on a claim expiring `leaseMillis` from now, and a binder over it. */
function heldTake(leaseMillis: number, holdLimit: string | null = null) {
  const time = new VirtualTime();
  const writer = new Member(time);
  const holder = new Member(time);
  const id = writer.writeEntry("tasks", TASK, { job: 5 }, "w", 30 * MINUTE);
  for (const r of writer.sent.filter((s) => s.kind === "RUMOR")) {
    holder.deliver(writer, r.body);
  }
  holder.hold(id, workerClaim(holder, id, time.wall(), leaseMillis));
  const binder = new Binder(holder, { publishCard: false, residency: "service", holdLimit });
  const expiry = (): number => Number((holder.claims.get(id)!["claim"] as Dict)["expiresAtMillis"]);
  let release!: () => void;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { time, writer, holder, id, binder, expiry, release, released };
}

/** Runs a handler through the binder's take path (the shared action-and-completion of both take verbs). */
function runTake(binder: Binder, bound: Bound, verb: "spaceTake" | "orderedTake", taken: Taken<unknown>,
                 handler: () => Promise<unknown>): Promise<void> {
  const internals = binder as unknown as { finishTake(...args: unknown[]): Promise<void> };
  return internals.finishTake(bound, {}, handler, { verb, space: "tasks" }, taken.space, taken);
}

test("I-05: a handler renewing through its TakeContext every 100 ms still lapses past a 2 s hold limit", async () => {
  const { time, writer, holder, id, binder, expiry, release, released } = heldTake(1_000, "2s");
  const bound = new Bound("worker");
  const startWall = time.wall();
  const taken = new Taken(holder.space, id, { job: 5 }, 1_000);
  const done = runTake(binder, bound, "orderedTake", taken, async () => {
    const context = TakeContext.current()!; // an LLM stream's keepalive holds the context and renews through it
    const keepalive = holder.every(100, () => context.renew(1_000));
    await released;
    keepalive.stop();
    return null;
  });
  time.advance(1_900);
  assert.ok(expiry() >= time.wall() + 800, "renewed while under the limit");
  time.advance(1_100);
  assert.ok(binder.contextRenewalsRefused > 0, "the context's renewals are refused past the limit");
  assert.ok(expiry() <= startWall + 2_000 + 1_000, `the hold ends at the limit plus one lease (${expiry() - startWall})`);
  time.advance(2_000);
  assert.ok(expiry() < time.wall(), "the entry lapses to another taker though the handler still renews");
  holder.sent.length = 0;
  release();
  await done;
  assert.equal(holder.rumors().filter((r) => String(r["itemId"]).startsWith("d:")).length, 0, "no late completion");
  assert.equal(binder.lateResults, 1);
  writer.close();
  holder.close();
});

test("I-05: an unbound agent's handler renews no more through its TakeContext (@spaceTake)", async () => {
  const { time, writer, holder, id, binder, expiry, release, released } = heldTake(1_000);
  const bound = new Bound("worker");
  const taken = new Taken(holder.space, id, { job: 5 }, 1_000);
  const done = runTake(binder, bound, "spaceTake", taken, async () => {
    const context = TakeContext.current()!;
    const keepalive = holder.every(100, () => context.renew(1_000));
    await released;
    keepalive.stop();
    return null;
  });
  time.advance(1_500);
  assert.ok(expiry() >= time.wall() + 800, "a bound agent's context renews");
  assert.equal(binder.contextRenewalsRefused, 0);
  bound.running = false; // unbound while the handler runs
  const at = expiry();
  time.advance(3_000);
  assert.ok(binder.contextRenewalsRefused > 0);
  assert.ok(expiry() <= at + 100, "renewed no more after the unbind");
  assert.ok(expiry() < time.wall());
  release();
  await done;
  writer.close();
  holder.close();
});

test("C05: a wall step that outlasts the lease makes the running take late at once: no renewal, no result", async () => {
  const { time, writer, holder, id, binder, release, released } = heldTake(20_000);
  const bound = new Bound("worker");
  const taken = new Taken(holder.space, id, { job: 5 }, 20_000);
  let context: Taken<unknown> | null = null;
  const done = runTake(binder, bound, "orderedTake", taken, async () => {
    context = TakeContext.current();
    await released;
    return new LoopTask(6);
  });
  time.advance(1_000);
  time.stepWall(2 * MINUTE); // the laptop slept two minutes; the monotonic clock did not count it
  time.advance(2_000); // the watchdog's next look sees the step
  assert.equal(binder.lateTakes, 1, "judged against the wall-time lease at once");
  assert.equal(binder.holdLimitStops, 0, "no hold limit: a sleep is no hung handler");
  time.advance(30_000);
  assert.equal(binder.takeRenewals, 0, "the binder's renewer stopped, before its first half-lease");
  context!.renew();
  assert.equal(binder.contextRenewalsRefused, 1, "the context's renewal stopped too");
  holder.sent.length = 0;
  release();
  await done;
  assert.equal(binder.lateResults, 1);
  assert.equal(holder.rumors().length, 0, "the late result is neither written nor completed");
  writer.close();
  holder.close();
});

test("C05: a wall step inside the lease renews the take at once, and the hold limit stays on the monotonic clock",
  async () => {
    const { time, writer, holder, id, binder, expiry, release, released } = heldTake(2 * MINUTE, "50s");
    const bound = new Bound("worker");
    const taken = new Taken(holder.space, id, { job: 5 }, 2 * MINUTE);
    const done = runTake(binder, bound, "orderedTake", taken, async () => {
      await released;
      return null;
    });
    time.advance(1_000);
    time.stepWall(MINUTE); // past the 50 s limit on the wall, not on the monotonic clock
    time.advance(2_000);
    assert.equal(binder.lateTakes, 0);
    assert.equal(binder.holdLimitStops, 0, "the hold limit does not count the sleep");
    assert.equal(binder.takeRenewals, 1, "renewed at once on the wake");
    assert.ok(expiry() >= time.wall() + 2 * MINUTE - 2_000, "renewed for a full lease at the wake");
    holder.sent.length = 0;
    release();
    await done;
    assert.equal(binder.lateResults, 0);
    assert.equal(holder.rumors().filter((r) => String(r["itemId"]).startsWith("d:")).length, 1, "completed");
    writer.close();
    holder.close();
  });

test("C05: a late wake (a suspend the monotonic clock counted) re-checks the running takes too", async () => {
  const { time, writer, holder, id, binder, release, released } = heldTake(20_000);
  const bound = new Bound("worker");
  const taken = new Taken(holder.space, id, { job: 5 }, 20_000);
  const done = runTake(binder, bound, "spaceTake", taken, async () => {
    await released;
    return null;
  });
  time.stepWall(30_000); // the lease ran out on the wall; this host's monotonic clock counted the suspend as well
  (holder as unknown as { onLateWake(ms: number): void }).onLateWake(30_000);
  assert.equal(binder.lateTakes, 1);
  release();
  await done;
  assert.equal(binder.lateResults, 1);
  writer.close();
  holder.close();
});

class Settler {
  readonly fired: number[] = [];

  constructor(private readonly time: VirtualTime) {}

  @onEstimate({ epochs: "solo" })
  unruled(): null {
    this.fired.push(this.time.now());
    return null;
  }
}

class AtOnce {
  readonly fired: number[] = [];

  constructor(private readonly time: VirtualTime) {}

  @onEstimate({ epochs: "solo", settle: "PT0S" })
  atOnce(): null {
    this.fired.push(this.time.now());
    return null;
  }
}

test("@onEstimate with no rule settles after 8 s, as Java's default; settle PT0S is the explicit fire-at-once",
  async () => {
    const time = new VirtualTime();
    const solo = new AggPeer(time);
    const agg = new Aggregate(new Pipes(solo));
    const unruled = new Settler(time);
    const atOnce = new AtOnce(time);
    const binder = new Binder(solo, { publishCard: false, aggregate: agg });
    const bounds = [binder.bind(unruled), binder.bind(atOnce)];
    const start = time.now();
    agg.start("solo", 7);
    agg.run();
    await time.advanceAsync(ON_ESTIMATE_DEFAULT_SETTLE_MILLIS - 1_000);
    assert.equal(unruled.fired.length, 0, "not settled before 8 s");
    assert.equal(atOnce.fired.length, 1, "PT0S fires on the first round");
    assert.ok(atOnce.fired[0]! - start <= 2_000);
    await time.advanceAsync(4_000);
    assert.equal(unruled.fired.length, 1);
    assert.ok(unruled.fired[0]! - start >= ON_ESTIMATE_DEFAULT_SETTLE_MILLIS, `settled after ${unruled.fired[0]! - start} ms`);
    for (const bound of bounds) {
      bound.running = false;
    }
    agg.close();
    solo.close();
  });

test("the redial and seed counters read under the names every client shares", () => {
  const peer = new Peer(Identity.generate(), GROUP);
  const counters = { seedPings: peer.seedPings, wakePings: peer.wakePings, linksSilent: peer.linksSilent,
    resumes: peer.resumes, seedDials: peer.seedDials, lateSeedChannels: peer.lateSeedChannels };
  assert.deepEqual(counters, { seedPings: 0, wakePings: 0, linksSilent: 0, resumes: 0, seedDials: 0,
    lateSeedChannels: 0 });
  peer.close();
});
