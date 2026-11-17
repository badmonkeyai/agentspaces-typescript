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
 * The Layer 3 rules of v0.1.35 in this client (srad/replication-by-entry.md RE-H-02 to RE-H-04, RE-T-06, decisions
 * 21 and 22): renewal is issuer-only, needs the entry present and unexpired, and never shortens, for writes, takes and
 * subscriptions; the per-entry horizon engages after three fully hinted rounds and one maximum lease plus the grace,
 * disengages at once, and applies only to withdrawals whose writers this replica vouches for; a withdrawal never goes
 * before the drift floor; a re-offered collected tombstone is acknowledged and the line forgotten after its hold, under
 * a per-space bound; a lapsed entry leaves the audited set; and an entry first learned completed raises COMPLETED alone.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { dumps, loads } from "../src/cbor.js";
import { Identity, spaceIdLocal } from "../src/identity.js";
import { MAX_REFUSED_ACK, Peer, leaseExpiryOf } from "../src/peer.js";
import type { Repeating, TimerPort } from "../src/platform.js";
import { Space, Taken, Template, entry } from "../src/space.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const GROUP = "zTsRenewHorizon";
const NOW = 1_800_000_000_000;
const TASK = "com.acme.HorizonTask#v1";
const MINUTE = 60_000;

@entry(TASK)
class HorizonTask {
  constructor(public n = 0, public job = 0) {}
}

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
  private frameCounter = 0;

  constructor(private readonly clock: { millis: number }, configure: (m: Member) => void = () => undefined) {
    super(Identity.generate(), GROUP, () => clock.millis);
    this.timers = new ManualTimers();
    configure(this);
    this.space = new Space(this, "tasks");
  }

  protected override send(kind: string, body: Uint8Array): void {
    if (kind === "RUMOR") {
      this.rumors.push(body);
    }
  }

  /** Signs a RUMOR as `sender` and hands it to this member's reader. */
  deliver(sender: Peer, body: Uint8Array): void {
    const stamp = `${this.clock.millis}:${this.frameCounter++}:${sender.identity.peerId}`;
    (this as unknown as { onFrame(frame: Uint8Array): void }).onFrame(wire.encodeFrame(
      wire.envelope(GROUP, "RUMOR", sender.identity.peerId, stamp, body, this.identity.peerId), sender.identity));
  }

  /** Hands this member a PULL_RESP from `sender` carrying `deltas`. */
  answer(sender: Peer, deltas: Dict): void {
    const stamp = `${this.clock.millis}:${this.frameCounter++}:${sender.identity.peerId}`;
    (this as unknown as { onFrame(frame: Uint8Array): void }).onFrame(wire.encodeFrame(
      wire.envelope(GROUP, "PULL_RESP", sender.identity.peerId, stamp, wire.pullRespBody(deltas),
        this.identity.peerId), sender.identity));
  }

  /** Hands this member `other`'s current card, as the peers stream would. */
  meet(other: Peer): void {
    const ad = (other as unknown as { selfAd(): Dict }).selfAd();
    this.deliver(other, wire.rumorBody("peers", `peer:${other.identity.peerId}:${this.clock.millis}`, 6,
      wire.signedPeerAd(ad, other.identity)));
  }

  /** Delivers every rumor `from` sent since `mark`. */
  receive(from: Member, mark = 0): void {
    for (const body of from.rumors.slice(mark)) {
      this.deliver(from, body);
    }
  }
}

test("a renewal never shortens, sends nothing when unchanged, and counts the call that would have shortened", () => {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const id = a.writeEntry("tasks", TASK, { n: 1 }, "w", 10 * MINUTE);
  const sent = a.rumors.length;
  a.renewEntry("tasks", id, 2 * MINUTE);
  assert.equal(leaseExpiryOf(a.states.get(id)!), NOW + 10 * MINUTE);
  assert.equal(a.rumors.length, sent, "nothing went out");
  assert.equal(a.renewShortenings, 1);
  a.renewEntry("tasks", id, 0);
  assert.equal(leaseExpiryOf(a.states.get(id)!), NOW + 10 * MINUTE, "a renewal for zero leaves the lease");
  clock.millis = NOW + MINUTE;
  a.renewEntry("tasks", id, 30 * MINUTE);
  assert.equal(leaseExpiryOf(a.states.get(id)!), NOW + 31 * MINUTE);
  assert.equal(a.rumors.length, sent + 1);
});

test("a renewal needs the issuer, an entry still present, and a lease not yet lapsed", () => {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const b = new Member(clock);
  const id = a.writeEntry("tasks", TASK, { n: 1 }, "w", MINUTE);
  b.receive(a);
  assert.throws(() => b.renewEntry("tasks", id, MINUTE), /not by this peer/);
  clock.millis = NOW + MINUTE;
  assert.throws(() => a.renewEntry("tasks", id, MINUTE), /lapsed/);
  clock.millis = NOW;
  const other = a.writeEntry("tasks", TASK, { n: 2 }, "w", MINUTE);
  a.cancelEntry("tasks", other);
  assert.throws(() => a.renewEntry("tasks", other, MINUTE), /no longer present/);
});

/** A claim on `id` by `member`'s agent at epoch 1, expiring at `expiry`. */
function claimBy(member: Member, id: string, expiry: number): Dict {
  const spaceId = String((member.states.get(id)!["record"] as Dict)["spaceId"]);
  const worker = member.identity.agent("worker");
  return wire.signedClaim(wire.takeClaim(id, spaceId, 1, `${NOW}:0:${worker}`, worker, 0.0, expiry), member.identity, null);
}

test("a take's renewal extends the take lease, keeps its epoch, never shortens, and a released take renews nothing", () => {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const b = new Member(clock);
  const id = a.writeEntry("tasks", TASK, { job: 1 }, "w", 30 * MINUTE);
  b.receive(a);
  b.restoreSnapshot({ group: GROUP, states: [], claims: { [id]: claimBy(b, id, NOW + 10 * MINUTE) } });
  const taken = new Taken(b.space, id, { job: 1 }, MINUTE);
  taken.renew(MINUTE);
  assert.equal((b.claims.get(id)!["claim"] as Dict)["expiresAtMillis"], NOW + 10 * MINUTE, "never shorter");
  taken.renew(20 * MINUTE);
  const claim = b.claims.get(id)!["claim"] as Dict;
  assert.equal(claim["expiresAtMillis"], NOW + 20 * MINUTE);
  assert.equal(Number(claim["epoch"]), 1, "the same take");
  assert.equal(leaseExpiryOf(b.states.get(id)!), NOW + 30 * MINUTE, "the write lease is the issuer's, untouched");
  taken.release();
  assert.throws(() => taken.renew(MINUTE), /released/);
});

test("a subscription's renewal never shortens its lease", () => {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const subscription = a.space.notify(new Template(HorizonTask), () => undefined, 10 * MINUTE);
  const until = (): number => (subscription as unknown as { expiresAt: number }).expiresAt;
  assert.equal(until(), NOW + 10 * MINUTE);
  subscription.renew(MINUTE);
  assert.equal(until(), NOW + 10 * MINUTE);
  clock.millis = NOW + 5 * MINUTE;
  subscription.renew(20 * MINUTE);
  assert.equal(until(), NOW + 25 * MINUTE);
});

test("the per-entry horizon engages after three hinted rounds and one maximum lease, and disengages at once", () => {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const b = new Member(clock);
  a.meet(b);
  a.collectTombstones();
  assert.equal(a.horizonModeOf("tasks"), "WAITING");
  for (let round = 0; round < 3; round++) {
    clock.millis += 1_000;
    a.collectTombstones();
  }
  assert.equal(a.horizonModeOf("tasks"), "SETTLING", "three fully hinted rounds engage it");
  clock.millis += 5 * MINUTE; // no lease observed yet: the wait is the grace alone
  a.collectTombstones();
  assert.equal(a.horizonModeOf("tasks"), "PER_ENTRY");
  const c = new Member(clock, (m) => { m.horizon = "legacy"; });
  a.meet(c);
  a.collectTombstones();
  assert.equal(a.horizonModeOf("tasks"), "LEGACY", "a member without the hint disengages it at the first judgement");
  assert.equal(a.replicationStatus().horizon[spaceIdLocal(`${GROUP}/tasks`)]!.disengagements, 1);
});

/** A member whose view is hinted and whose per-entry horizon is in force, with a longest lease of one hour. */
function inForce(): { clock: { millis: number }; a: Member; b: Member } {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const b = new Member(clock);
  a.meet(b);
  a.writeEntry("tasks", TASK, { n: 0 }, "w", 60 * MINUTE); // the longest lease the space has seen
  for (let round = 0; round < 4; round++) {
    a.collectTombstones();
    clock.millis += 1_000;
  }
  clock.millis += 65 * MINUTE;
  a.collectTombstones();
  assert.equal(a.horizonModeOf("tasks"), "PER_ENTRY");
  return { clock, a, b };
}

test("under the per-entry horizon a withdrawal by a vouched writer goes at L + 10 min, not L + 2 x maxLease", () => {
  const { clock, a } = inForce();
  const id = a.writeEntry("tasks", TASK, { n: 1 }, "w", MINUTE);
  const expiry = clock.millis + MINUTE;
  a.cancelEntry("tasks", id);
  clock.millis = expiry + 10 * MINUTE - 1;
  a.collectTombstones();
  assert.ok(a.states.has(id), "the drift floor holds it ten minutes past its own expiry");
  clock.millis = expiry + 10 * MINUTE;
  a.collectTombstones();
  assert.equal(a.states.has(id), false);
});

test("a withdrawal by a writer only lately in view keeps the legacy horizon", () => {
  const { clock, a } = inForce();
  const late = new Member(clock);
  a.meet(late); // hinted, but in view for less than one maximum lease and the grace
  const id = late.writeEntry("tasks", TASK, { n: 1 }, "w", MINUTE);
  const expiry = clock.millis + MINUTE;
  late.cancelEntry("tasks", id);
  a.receive(late);
  assert.ok(a.states.has(id));
  clock.millis = expiry + 11 * MINUTE;
  a.collectTombstones();
  assert.ok(a.states.has(id), "this replica cannot vouch for what that writer renewed out of its sight");
  clock.millis = expiry + 120 * MINUTE;
  a.collectTombstones();
  assert.equal(a.states.has(id), false, "collected at L + 2 x maxLease");
});

test("under the legacy rule a withdrawal keeps the drift floor though two leases are shorter", () => {
  const clock = { millis: NOW };
  const a = new Member(clock, (m) => { m.horizon = "legacy"; });
  const id = a.writeEntry("tasks", TASK, { n: 1 }, "w", 30_000);
  a.cancelEntry("tasks", id);
  clock.millis = NOW + 30_000 + 2 * 30_000;
  a.collectTombstones();
  assert.ok(a.states.has(id), "two maximum leases have passed, the drift floor has not");
  clock.millis = NOW + 30_000 + 10 * MINUTE;
  a.collectTombstones();
  assert.equal(a.states.has(id), false);
});

test("a re-offered collected tombstone is acknowledged at the door, stands in the audited set, and is forgotten", () => {
  const clock = { millis: NOW };
  const a = new Member(clock, (m) => { m.horizon = "legacy"; });
  const b = new Member(clock);
  const id = a.writeEntry("tasks", TASK, { n: 1 }, "w", 30_000);
  a.cancelEntry("tasks", id);
  b.receive(a);
  clock.millis = NOW + 30_000 + 10 * MINUTE;
  a.collectTombstones();
  assert.equal(a.states.has(id), false);
  const line = `e:${id}=`;
  // A lagging member offers the withdrawn state again, in its answer to a round.
  a.answer(b, { "space:tasks": dumps({ states: [b.states.get(id)!], claims: {} }) });
  assert.equal(a.states.has(id), false, "the door refused it");
  assert.equal(a.collectedReoffersAcknowledged, 1);
  const text = new TextDecoder().decode(a.spaceDigest("tasks"));
  assert.ok(text.includes(`a:${line}`), "the text digest names it as acknowledged");
  const trie = a.spaceTrie("tasks");
  assert.ok(trie.get(id)!.some((l) => l.startsWith(line)), "the audited set holds it as the line itself");
  clock.millis += 5 * MINUTE;
  a.collectTombstones();
  assert.equal(new TextDecoder().decode(a.spaceDigest("tasks")).includes(`a:${line}`), false, "forgotten after the hold");
  assert.equal(a.spaceTrie("tasks").get(id), undefined);
});

test("R7's bound is per space: one space's refusals never push another's acknowledgements out", () => {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const ack = a as unknown as { acknowledgeLine(line: string, spaceId: string): void; acknowledgedLines(s: string): string };
  const busy = spaceIdLocal(`${GROUP}/busy`);
  const quiet = spaceIdLocal(`${GROUP}/quiet`);
  ack.acknowledgeLine("e:q1=1", quiet);
  for (let i = 0; i <= MAX_REFUSED_ACK; i++) {
    ack.acknowledgeLine(`e:b${i}=1`, busy);
  }
  assert.equal(ack.acknowledgedLines("busy").split("\n").filter((l) => l.length > 0).length, MAX_REFUSED_ACK);
  assert.equal(ack.acknowledgedLines("quiet"), "a:e:q1=1\n");
  assert.equal(ack.acknowledgedLines("busy").includes("a:e:b0=1\n"), false, "the least recently refused went first");
});

test("a present entry whose lease lapsed leaves the audited set and stays in the text digest", () => {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const id = a.writeEntry("tasks", TASK, { n: 1 }, "w", 1_000);
  assert.equal(a.spaceTrie("tasks").size, 1);
  clock.millis = NOW + 1_000;
  assert.equal(a.spaceTrie("tasks").size, 0);
  assert.ok(new TextDecoder().decode(a.spaceDigest("tasks")).includes(`e:${id}=`));
});

test("an entry first learned completed raises COMPLETED and never WRITTEN (decision 21)", () => {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const b = new Member(clock);
  const late = new Member(clock);
  const id = a.writeEntry("tasks", TASK, { job: 1 }, "w", 30 * MINUTE);
  b.receive(a);
  b.restoreSnapshot({ group: GROUP, states: [], claims: { [id]: claimBy(b, id, NOW + 10 * MINUTE) } });
  const mark = b.rumors.length;
  new Taken(b.space, id, { job: 1 }, MINUTE).complete();
  const kinds: string[] = [];
  late.space.watch(new Template(HorizonTask), (event) => kinds.push(event.kind));
  late.receive(b, mark);
  assert.deepEqual(kinds, ["COMPLETED"]);
});

test("a budgeted answer keeps RE-I-06's order: present before tombstones, newest first, the first item always", () => {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const answer = a as unknown as { boundedSpaceDelta(space: string, text: Uint8Array | null, ids: string[] | null,
    budget: number, first: boolean): { delta: Uint8Array; left: number } };
  const old = a.writeEntry("tasks", TASK, { n: 1 }, "w", 30 * MINUTE);
  clock.millis += 1_000;
  const replaced = a.writeEntry("tasks", TASK, { n: 2 }, "w", 30 * MINUTE);
  clock.millis += 1_000;
  const newest = a.writeEntry("tasks", TASK, { n: 3, padding: "p".repeat(4000) }, "w", 30 * MINUTE);
  a.cancelEntry("tasks", replaced); // a replacement's cancel: the tombstone must not travel before the live states
  const ids = [replaced, old, newest];
  const whole = answer.boundedSpaceDelta("tasks", null, ids, 1 << 20, true);
  const order = ((loads(whole.delta) as Dict)["states"] as Dict[]).map((s) => (s["record"] as Dict)["entryId"]);
  assert.deepEqual(order, [newest, old, replaced], "present states newest first, then the tombstone");
  assert.equal(whole.left, 0);
  const tight = answer.boundedSpaceDelta("tasks", null, ids, 100, true);
  const carried = ((loads(tight.delta) as Dict)["states"] as Dict[]).map((s) => (s["record"] as Dict)["entryId"]);
  assert.deepEqual(carried, [newest], "the first item travels alone though it passes the budget");
  assert.equal(tight.left, 2);
  assert.equal(answer.boundedSpaceDelta("tasks", null, ids, 100, false).left, 3, "only an answer's first item is exempt");
});
