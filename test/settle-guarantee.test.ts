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
 * The settle guarantee, SPEC §7.4 (v0.1.35, 2026-11-15), as it binds this client. A take wins an entry only
 * while every rival claim reaches it within the settle window. A claim that arrives later can displace a take
 * that already won its window, and a holder that learns of the better claim before it completes MUST NOT
 * complete: `Taken.complete` throws, and neither its result nor its completion goes out. Before, the
 * completion refused, but only after the result had been written.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import type { Repeating, TimerPort } from "../src/platform.js";
import { entry, Space, Taken } from "../src/space.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const GROUP = "zTsSettle";
const NOW = 1_800_000_000_000;
const TASK = "com.acme.SettleTask#v1";
const MINUTE = 60_000;

@entry("com.acme.SettleOutcome#v1")
class Outcome {
  constructor(public note = "") {}
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

  constructor(private readonly clock: { millis: number }) {
    super(Identity.generate(), GROUP, () => clock.millis);
    this.timers = new ManualTimers();
    this.space = new Space(this, "tasks");
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
}

/** A claim on `id` by `member`'s agent at epoch 1, stamped at `stampMillis`. */
function claimBy(member: Member, id: string, stampMillis: number): Dict {
  const spaceId = String((member.states.get(id)!["record"] as Dict)["spaceId"]);
  const worker = member.identity.agent("worker");
  return wire.signedClaim(wire.takeClaim(id, spaceId, 1, `${stampMillis}:0:${worker}`, worker, 0.0,
    NOW + 10 * MINUTE), member.identity, null);
}

/** A writer `a`, a taker `b` that won its window with a claim stamped 10 ms after NOW, and a rival `c`. */
function race(): { clock: { millis: number }; b: Member; c: Member; id: string; taken: Taken<Dict> } {
  const clock = { millis: NOW };
  const a = new Member(clock);
  const b = new Member(clock);
  const c = new Member(clock);
  const id = a.writeEntry("tasks", TASK, { job: 1 }, "w", 30 * MINUTE);
  for (const body of a.rumors) {
    b.deliver(a, body);
    c.deliver(a, body);
  }
  b.restoreSnapshot({ group: GROUP, states: [], claims: { [id]: claimBy(b, id, NOW + 10) } });
  return { clock, b, c, id, taken: new Taken(b.space, id, { job: 1 }, MINUTE) };
}

test("a take displaced by an earlier claim after its window writes no result and does not complete", () => {
  const { b, c, id, taken } = race();
  // The earlier claim arrives after b's window.
  b.deliver(c, wire.rumorBody("space:tasks", `c:${id}`, 6, wire.claimDelta(id, claimBy(c, id, NOW))));
  assert.notEqual((b.claims.get(id)!["claim"] as Dict)["holder"], b.identity.agent("worker"), "displaced");
  const sent = b.rumors.length;
  assert.throws(() => taken.complete(new Outcome("done by b")), /live claim/);
  assert.equal(b.rumors.length, sent, "neither a result nor a completion went out");
  assert.notEqual(b.states.get(id)!["completed"], true);
});

test("a take whose claim lapsed writes no result", () => {
  const { clock, b, id, taken } = race();
  clock.millis = NOW + 10 * MINUTE + 1;
  const sent = b.rumors.length;
  assert.throws(() => taken.complete(new Outcome("late")), /live claim/);
  assert.equal(b.rumors.length, sent);
  assert.notEqual(b.states.get(id)!["completed"], true);
});

test("a take that still holds writes its result and completes", () => {
  const { b, id, taken } = race();
  const sent = b.rumors.length;
  assert.notEqual(taken.complete(new Outcome("done by b")), null);
  assert.equal(b.rumors.length, sent + 2, "the result, then the completion");
  assert.equal(b.states.get(id)!["completed"], true);
});
