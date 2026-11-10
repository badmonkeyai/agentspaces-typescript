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
 * Core cancel events, 2026-11-09 (SPEC §7.2, v0.1.32 draft note): a cancel withdraws the entry on every
 * member and raises EXPIRED, the kind a lapse raises, once on each member that held the entry, the
 * cancelling one included, as Java's ReplicatedSpace and LocalSpace raise it. A redelivered cancel raises
 * nothing more, a cancel and a lapse raise one EXPIRED between them, completion dominates a concurrent
 * cancel, and a holder whose replica merged the withdrawal cannot complete.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import type { Repeating, TimerPort } from "../src/platform.js";
import { COMPLETED, EXPIRED, Space, TAKEN, Template, WRITTEN } from "../src/space.js";
import type { EventKind, SpaceEvent } from "../src/space.js";
import { MemoryNetwork, settle } from "../src/transport/mem.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const GROUP = "zTsCancel";
const NOW = 1_800_000_000_000;
const TASK = "com.acme.Task#v1";
const MINUTE = 60_000;

/** Timers the test runs by hand. */
class ManualTimers implements TimerPort {
  setTimeout(): unknown {
    return null;
  }

  clearTimeout(): void {
    // nothing is scheduled to clear
  }

  every(): Repeating {
    return { lastDriftMillis: 0, lateRuns: 0, stop: () => {} };
  }
}

/** A member on a shared settable clock: its rumors land in `rumors`, and `deliver` hands it another's. */
class Member extends Peer {
  readonly rumors: Uint8Array[] = [];
  readonly space: Space;
  readonly events: SpaceEvent<unknown>[] = [];
  private frameCounter = 0;

  constructor(private readonly clock: { millis: number }, manualTimers = true) {
    super(Identity.generate(), GROUP, () => clock.millis);
    if (manualTimers) {
      this.timers = new ManualTimers();
    }
    this.space = new Space(this, "tasks");
    this.space.watch(new Template(TASK), (event) => this.events.push(event));
  }

  protected override send(kind: string, body: Uint8Array): void {
    if (kind === "RUMOR") {
      this.rumors.push(body);
    }
  }

  /** Signs a frame as `sender` and hands it to this member's reader. */
  deliver(sender: Member, body: Uint8Array): void {
    const stamp = `${this.clock.millis}:${this.frameCounter++}:${sender.identity.peerId}`;
    (this as unknown as { onFrame(frame: Uint8Array): void }).onFrame(wire.encodeFrame(
      wire.envelope(GROUP, "RUMOR", sender.identity.peerId, stamp, body, this.identity.peerId), sender.identity));
  }

  /** Hands every rumor `sender` sent since `from` to this member. */
  hear(sender: Member, from = 0): void {
    for (const body of sender.rumors.slice(from)) {
      this.deliver(sender, body);
    }
  }

  count(kind: EventKind, entryId: string): number {
    return this.events.filter((e) => e.kind === kind && e.entry.entryId === entryId).length;
  }

  kinds(): EventKind[] {
    return this.events.map((e) => e.kind);
  }
}

function gone(member: Member, entryId: string): void {
  assert.deepEqual(member.space.entries(new Template(TASK)), [], "no entry to read");
  assert.equal(member.find(TASK).some((dto) => (dto["record"] as Dict)["entryId"] === entryId), false);
}

/** A writer `a` and a member `b` holding a's entry, on one clock. */
function pair(leaseMillis = 30 * MINUTE): { clock: { millis: number }; a: Member; b: Member; id: string } {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const b = new Member(clock);
  const id = a.writeEntry("tasks", TASK, { job: 1 }, "w", leaseMillis);
  b.hear(a);
  assert.equal(b.count(WRITTEN, id), 1);
  return { clock, a, b, id };
}

/** Gives `holder` a live claim on `id`, as a won take leaves it, and hands the claim to `others`. */
function holdClaim(holder: Member, id: string, ...others: Member[]): void {
  const spaceId = String((holder.states.get(id)!["record"] as Dict)["spaceId"]);
  const worker = holder.identity.agent("worker");
  const claim = wire.signedClaim(wire.takeClaim(id, spaceId, 1, `${NOW}:0:${worker}`, worker, 0.0,
    NOW + 10 * MINUTE), holder.identity, null);
  holder.restoreSnapshot({ group: GROUP, states: [], claims: { [id]: claim } });
  for (const other of others) {
    other.restoreSnapshot({ group: GROUP, states: [], claims: { [id]: claim } });
  }
}

test("a cancel raises EXPIRED once at every member over the memory network, the cancelling one at once", async () => {
  const net = new MemoryNetwork();
  const hub = new Peer(Identity.generate(), GROUP);
  hub.endpoints.push({ transport: "mem", address: "hub:9", priority: 0 });
  const closeListener = await net.listen("hub:9", (channel) => hub.acceptChannel(channel));
  const [a, b] = [new Peer(Identity.generate(), GROUP), new Peer(Identity.generate(), GROUP)];
  const heard = new Map<Peer, SpaceEvent<unknown>[]>();
  const spaces = new Map<Peer, Space>();
  try {
    for (const member of [hub, a, b]) {
      const space = new Space(member, "tasks");
      const events: SpaceEvent<unknown>[] = [];
      space.watch(new Template(TASK), (event) => events.push(event));
      heard.set(member, events);
      spaces.set(member, space);
    }
    for (const member of [a, b]) {
      member.registerDialer(net.dialer());
      await member.connectAny([{ host: "hub", port: 9, scheme: "mem" }]);
    }
    const id = a.writeEntry("tasks", TASK, { job: 1 }, "w", 30 * MINUTE);
    await settle();
    for (const member of [hub, a, b]) {
      assert.deepEqual(heard.get(member)!.map((e) => e.kind), [WRITTEN]);
    }

    a.cancelEntry("tasks", id);
    assert.deepEqual(heard.get(a)!.map((e) => e.kind), [WRITTEN, EXPIRED], "the cancelling member hears it at once");
    await settle();

    for (const member of [hub, a, b]) {
      const events = heard.get(member)!;
      assert.deepEqual(events.map((e) => e.kind), [WRITTEN, EXPIRED]);
      assert.equal(events[1]!.entry.entryId, id);
      assert.deepEqual(events[1]!.entry.value, { job: 1 });
      assert.equal(events[1]!.entry.issuer, a.identity.agent("w"));
      assert.deepEqual(spaces.get(member)!.entries(new Template(TASK)), []);
    }
  } finally {
    closeListener();
    [hub, a, b].forEach((p) => p.close());
  }
});

test("a redelivered cancel raises no second EXPIRED, and a second cancel sends nothing", () => {
  const { a, b, id } = pair();
  const sent = a.rumors.length;
  a.cancelEntry("tasks", id);
  b.hear(a, sent);
  b.hear(a, sent); // the same rumor again
  const cancelled = a.states.get(id)!;
  b.restoreSnapshot({ group: GROUP, states: [cancelled], claims: {} }); // and the state by anti-entropy
  a.cancelEntry("tasks", id);
  assert.equal(a.rumors.length, sent + 1, "a cancel of a withdrawn entry sends nothing");
  b.space.sweep();
  for (const member of [a, b]) {
    assert.deepEqual(member.kinds(), [WRITTEN, EXPIRED]);
    gone(member, id);
  }
});

test("a cancel and a lapse raise one EXPIRED between them, in either order", () => {
  const lapsedFirst = pair(MINUTE);
  lapsedFirst.clock.millis = NOW + 2 * MINUTE;
  lapsedFirst.a.space.sweep();
  lapsedFirst.b.space.sweep();
  const sent = lapsedFirst.a.rumors.length;
  lapsedFirst.a.cancelEntry("tasks", lapsedFirst.id);
  lapsedFirst.b.hear(lapsedFirst.a, sent);
  for (const member of [lapsedFirst.a, lapsedFirst.b]) {
    assert.equal(member.count(EXPIRED, lapsedFirst.id), 1, "the lapse, then the cancel");
  }

  const cancelledFirst = pair(MINUTE);
  const before = cancelledFirst.a.rumors.length;
  cancelledFirst.a.cancelEntry("tasks", cancelledFirst.id);
  cancelledFirst.b.hear(cancelledFirst.a, before);
  cancelledFirst.clock.millis = NOW + 2 * MINUTE;
  cancelledFirst.a.space.sweep();
  cancelledFirst.b.space.sweep();
  for (const member of [cancelledFirst.a, cancelledFirst.b]) {
    assert.equal(member.count(EXPIRED, cancelledFirst.id), 1, "the cancel, then the lapse");
  }

  const unswept = pair(MINUTE);
  unswept.clock.millis = NOW + 2 * MINUTE; // lapsed, but no sweep ran before the cancel merged
  const mark = unswept.a.rumors.length;
  unswept.a.cancelEntry("tasks", unswept.id);
  unswept.b.hear(unswept.a, mark);
  unswept.a.space.sweep();
  unswept.b.space.sweep();
  for (const member of [unswept.a, unswept.b]) {
    assert.equal(member.count(EXPIRED, unswept.id), 1, "the cancel of a lapsed, unswept entry");
  }
});

test("a holder whose replica merged the withdrawal cannot complete, and hears EXPIRED once", () => {
  const { a, b, id } = pair();
  holdClaim(b, id, a);
  const sent = a.rumors.length;
  a.cancelEntry("tasks", id);
  b.hear(a, sent);
  assert.throws(() => b.completeEntry("tasks", id), /live claim/);
  for (const member of [a, b]) {
    assert.equal(member.count(EXPIRED, id), 1);
    assert.equal(member.count(COMPLETED, id), 0);
    gone(member, id);
  }
});

test("a cancel that folds during the taker's settle window leaves the take empty", async () => {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const b = new Member(clock, false); // real timers: the take waits out its settle window
  try {
    const id = a.writeEntry("tasks", TASK, { job: 1 }, "w", 30 * MINUTE);
    b.hear(a);
    const claimed = b.rumors.length;
    const taking = b.takeEntry("tasks", TASK, "worker", MINUTE, 200, 600);
    while (b.rumors.length === claimed) {
      await new Promise((resolve) => setTimeout(resolve, 5)); // until b sent its claim
    }
    const sent = a.rumors.length;
    a.cancelEntry("tasks", id);
    b.hear(a, sent);
    assert.equal(await taking, null, "the take found the entry withdrawn");
    assert.equal(b.count(TAKEN, id), 0);
    assert.equal(b.count(EXPIRED, id), 1);
  } finally {
    b.close();
    a.close();
  }
});

test("a completion racing a cancel ends completed on both members with one EXPIRED at the canceller only", () => {
  const { a, b, id } = pair();
  holdClaim(b, id, a);
  const fromA = a.rumors.length;
  const fromB = b.rumors.length;
  b.completeEntry("tasks", id);
  a.cancelEntry("tasks", id);
  a.hear(b, fromB);
  b.hear(a, fromA);
  for (const member of [a, b]) {
    assert.equal(member.count(COMPLETED, id), 1, "completion dominates");
    assert.equal(member.states.get(id)!["completed"], true);
    gone(member, id);
  }
  assert.equal(a.count(EXPIRED, id), 1, "the canceller merged its own withdrawal first");
  assert.equal(b.count(EXPIRED, id), 0, "the holder completed first");
});

test("a cancel of an entry completed here raises nothing and sends nothing", () => {
  const { a, b, id } = pair();
  holdClaim(b, id, a);
  const fromB = b.rumors.length;
  b.completeEntry("tasks", id);
  a.hear(b, fromB);
  const completed = a.states.get(id);
  const sent = a.rumors.length;
  a.cancelEntry("tasks", id);
  assert.equal(a.rumors.length, sent, "nothing goes out");
  assert.equal(a.states.get(id), completed, "the holder's completion stays the state a holds");
  assert.deepEqual(a.kinds(), [WRITTEN, TAKEN, COMPLETED]);
});

test("a member that learns of an entry only withdrawn hears nothing", () => {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const late = new Member(clock);
  const id = a.writeEntry("tasks", TASK, { job: 1 }, "w", 30 * MINUTE);
  a.cancelEntry("tasks", id);
  late.restoreSnapshot({ group: GROUP, states: [a.states.get(id)!], claims: {} });
  late.hear(a); // the write, then the cancel
  assert.ok(late.states.has(id), "the late member holds the tombstone");
  assert.deepEqual(late.events, [], "a withdrawn entry learned late is history");
});

test("a cancel that another member signs withdraws nothing and raises nothing", () => {
  // Only the entry's issuer may cancel it (SPEC §11a.4, core cancel events, 2026-11-09).
  const { clock, a, b, id } = pair();
  const written = a.states.get(id)!;
  const forged = wire.signState({ ...written, removes: written["adds"] }, b.identity, null, clock.millis);
  for (const member of [a, b]) {
    member.restoreSnapshot({ group: GROUP, states: [forged], claims: {} });
    assert.equal(member.count(EXPIRED, id), 0, "no EXPIRED");
    assert.deepEqual(member.space.entries(new Template(TASK)).map((entry) => entry.entryId), [id], "the entry stays");
  }
});
