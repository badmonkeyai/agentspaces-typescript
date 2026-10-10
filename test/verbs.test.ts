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
 * The 0.3.0 return conventions and cues from TypeScript (L3L4-COVERAGE.md
 * §6.5, ISSUE-WorkflowVerbs, ISSUE-Motion, ISSUE-Propose, issue #16): a
 * tagged result, the fork, a motion opening a vote, the propose cue once per
 * key, and the LOCAL join firing once per key when every required part is
 * present.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Binder, Joined, agent, part, propose, spaceJoin, spaceNotify, spaceTake } from "../src/agents.js";
import { canonicalMap, dumps, loads } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import { Motion, Space, Tagged, Template, entry } from "../src/space.js";
import * as vote from "../src/vote.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";

const GROUP = "zTypeScriptVerbs";

@entry("com.acme.Claim#v1")
class Claim {
  constructor(public claimId = "", public amount = 0) {}
}

@entry("com.acme.Fraud#v1")
class Fraud {
  constructor(public claimId = "", public score = 0) {}
}

@entry("com.acme.Coverage#v1")
class Coverage {
  constructor(public claimId = "", public covered = false) {}
}

@entry("com.acme.Assessment#v1")
class Assessment {
  constructor(public claimId = "", public verdict = "") {}
}

type Internals = { fold(dto: Dict): void; foldClaim(entryId: string, signed: Dict): void; send(kind: string, body: Buffer): void };

class StubPeer extends Peer {
  constructor() {
    super(Identity.generate(), GROUP);
    const self = this as unknown as Internals;
    self.send = (kind: string, body: Buffer) => {
      if (kind === "RUMOR") {
        const rumor = loads(body) as Dict;
        if (String(rumor["streamId"] ?? "").startsWith("space:")) {
          const delta = loads(Buffer.from(rumor["payload"] as Uint8Array)) as Dict;
          if (delta["claimEntry"] && typeof delta["claim"] === "object" && delta["claim"] !== null) {
            self.foldClaim(String(delta["claimEntry"]), delta["claim"] as Dict);
          }
          if (delta["state"] !== null && typeof delta["state"] === "object") {
            self.fold(delta["state"] as Dict);
          }
        }
      }
    };
  }

  override pullSpace(_space: string): void {}
  override pullRevocations(): void {}
}

function foldFrom(other: Peer, space: string, schema: string, payload: Dict, into: Peer, tags: Dict = {}): void {
  const { body } = wire.entryDelta(space, GROUP, schema, dumps(payload), other.identity, "writer", 600_000,
    null, into.now(), tags);
  const delta = loads(Buffer.from((loads(body) as Dict)["payload"] as Uint8Array)) as Dict;
  (into as unknown as Internals).fold(delta["state"] as Dict);
}

const sleep = (millis: number) => new Promise((resolve) => setTimeout(resolve, millis));

async function until(timeoutMillis: number, condition: () => boolean): Promise<boolean> {
  const deadline = Date.now() + timeoutMillis;
  while (Date.now() < deadline) {
    if (condition()) {
      return true;
    }
    await sleep(50);
  }
  return condition();
}

@agent("assessor")
class Assessor {
  @spaceNotify(Claim, "claims", { produces: Assessment })
  tag(claim: Claim): Tagged<Assessment> {
    return new Tagged(new Assessment(claim.claimId, "tagged"), { region: "eu" });
  }

  @spaceTake(Claim, "intake", { pollTimeout: "300ms", resultSpace: "fanout" })
  fork(claim: Claim): object[] {
    return [new Fraud(claim.claimId, 1), new Coverage(claim.claimId, true)];
  }

  @spaceTake(Claim, "motions", { pollTimeout: "300ms" })
  move(claim: Claim): Motion {
    return new Motion(`claim:${claim.claimId}`, `pay ${claim.claimId}?`, ["yes", "no"], 2);
  }
}

test("tagged, fork, and motion returns dispatch as Java does", async () => {
  const peer = new StubPeer();
  const other = new StubPeer();
  const bound = new Binder(peer, { publishCard: false, voteSpace: "votes" }).bind(new Assessor());
  try {
    foldFrom(other, "claims", "com.acme.Claim#v1", { claimId: "c1", amount: 5 }, peer);
    assert.ok(await until(5_000, () => new Space(peer, "claims").entries(new Template(Assessment)).length > 0));
    const e = new Space(peer, "claims").entries(new Template(Assessment))[0]!;
    assert.equal(e.value.verdict, "tagged");
    assert.deepEqual(e.tags, { region: "eu" });
    foldFrom(other, "intake", "com.acme.Claim#v1", { claimId: "c2", amount: 7 }, peer);
    assert.ok(await until(10_000, () => new Space(peer, "fanout").readAll(new Template(Fraud)).length > 0
      && new Space(peer, "fanout").readAll(new Template(Coverage)).length > 0));
    assert.ok([...peer.states.values()].some((dto) => dto["completed"]));
    foldFrom(other, "motions", "com.acme.Claim#v1", { claimId: "c3", amount: 9 }, peer);
    assert.ok(await until(10_000, () => vote.proposals(peer.states).has("claim:c3")));
    assert.equal(vote.proposals(peer.states).get("claim:c3")!.question, "pay c3?");
  } finally {
    await bound.close();
  }
});

@agent("lead")
class Lead {
  readonly asked: string[] = [];

  @propose(Claim, "claims", "votes", ["approve", "deny"], 2, { prefix: "claim:", key: "claimId" })
  ask(claim: Claim): string | null {
    this.asked.push(claim.claimId);
    return claim.amount === 0 ? null : `approve claim ${claim.claimId}?`;
  }
}

test("a propose cue opens one vote per key", async () => {
  const peer = new StubPeer();
  const other = new StubPeer();
  const lead = new Lead();
  const bound = new Binder(peer, { publishCard: false }).bind(lead);
  try {
    foldFrom(other, "claims", "com.acme.Claim#v1", { claimId: "c1", amount: 5 }, peer);
    assert.ok(await until(5_000, () => vote.proposals(peer.states).has("claim:c1")));
    const proposal = vote.proposals(peer.states).get("claim:c1")!;
    assert.equal(proposal.question, "approve claim c1?");
    assert.deepEqual(proposal.options, ["approve", "deny"]);
    assert.equal(proposal.quorum, 2);
    foldFrom(other, "claims", "com.acme.Claim#v1", { claimId: "c1", amount: 6 }, peer);
    foldFrom(other, "claims", "com.acme.Claim#v1", { claimId: "c2", amount: 0 }, peer);
    await sleep(300);
    assert.deepEqual(lead.asked, ["c1", "c2"]);
    assert.deepEqual([...vote.proposals(peer.states).keys()], ["claim:c1"]);
  } finally {
    await bound.close();
  }
});

@agent("assembler")
class Assembler {
  readonly fired: string[] = [];

  @spaceJoin("intake", "claimId", [part(Fraud), part(Coverage), part(Claim, { optional: true })],
    { resultSpace: "assessments", produces: Assessment })
  assemble(j: Joined): Assessment {
    this.fired.push(j.key);
    const verdict = j.get(Coverage).covered && j.get(Fraud).score < 5 ? "pay" : "hold";
    return new Assessment(j.key, verdict + (j.has(Claim) ? "" : " (no claim)"));
  }
}

test("a local join fires once per key when every required part is present", async () => {
  const peer = new StubPeer();
  const other = new StubPeer();
  const assembler = new Assembler();
  const bound = new Binder(peer, { publishCard: false }).bind(assembler);
  try {
    foldFrom(other, "intake", "com.acme.Fraud#v1", { claimId: "c1", score: 1 }, peer);
    await sleep(200);
    assert.deepEqual(assembler.fired, []);
    foldFrom(other, "intake", "com.acme.Coverage#v1", { claimId: "c1", covered: true }, peer);
    assert.ok(await until(5_000, () => new Space(peer, "assessments").readAll(new Template(Assessment)).length > 0));
    assert.deepEqual(new Space(peer, "assessments").readAll(new Template(Assessment))[0], new Assessment("c1", "pay (no claim)"));
    foldFrom(other, "intake", "com.acme.Claim#v1", { claimId: "c1", amount: 3 }, peer);
    foldFrom(other, "intake", "com.acme.Coverage#v1", { claimId: "c2", covered: false }, peer);
    foldFrom(other, "intake", "com.acme.Fraud#v1", { claimId: "c2", score: 9 }, peer);
    assert.ok(await until(5_000, () => new Space(peer, "assessments").readAll(new Template(Assessment)).length === 2));
    await sleep(200);
    assert.deepEqual([...assembler.fired].sort(), ["c1", "c2"]);
    const verdicts = Object.fromEntries(new Space(peer, "assessments").readAll(new Template(Assessment))
      .map((a) => [a.claimId, a.verdict]));
    assert.deepEqual(verdicts, { c1: "pay (no claim)", c2: "hold (no claim)" });
  } finally {
    await bound.close();
  }
});

test("canonical map order sorts keys by UTF-8 length then bytes (wire version 3)", () => {
  assert.equal(wire.WIRE_VERSION, 3);
  assert.deepEqual(Object.keys(canonicalMap({ region: "eu", b: "1", aa: "2", a: "3", "é": "4" })),
    ["a", "b", "aa", "é", "region"]);
  // A tagged record's signed view carries its tags in that order, whatever order they were given.
  const view = wire.signView("e", "s", "T#v1", new Uint8Array(), "i", "1-0-i", null, { zz: "1", a: "2" });
  assert.deepEqual(Object.keys(view["tags"] as Dict), ["a", "zz"]);
});

// -------------------------------------------- notify kinds, contribution, produces

import { Aggregate, Pipes } from "../src/capabilities/index.js";
import { COMPLETED, Contribution, EXPIRED, REAPPEARED, WRITTEN } from "../src/space.js";

@agent("watcher")
class Watcher {
  readonly kinds: string[] = [];

  @spaceNotify(Claim, "timers", { on: [WRITTEN, EXPIRED, REAPPEARED, COMPLETED] })
  seen(claim: Claim): null {
    this.kinds.push(claim.claimId);
    return null;
  }
}

test("a notify reacts to several kinds including EXPIRED and REAPPEARED", async () => {
  const peer = new StubPeer();
  const other = new StubPeer();
  const watcher = new Watcher();
  const kinds: string[] = [];
  const space = new Space(peer, "timers");
  space.watch(new Template(Claim), (e) => kinds.push(`${e.kind}:${e.entry.value.claimId}`));
  const bound = new Binder(peer, { publishCard: false }).bind(watcher);
  try {
    const { body } = wire.entryDelta("timers", GROUP, "com.acme.Claim#v1", dumps({ claimId: "t1", amount: 1 }),
      other.identity, "writer", 400, null, peer.now());
    (peer as unknown as Internals).fold((loads(Buffer.from((loads(body) as Dict)["payload"] as Uint8Array)) as Dict)["state"] as Dict);
    assert.ok(await until(3_000, () => kinds.includes("EXPIRED:t1")));
    await sleep(600);
    assert.equal(kinds.filter((k) => k === "EXPIRED:t1").length, 1);
    foldFrom(other, "timers", "com.acme.Claim#v1", { claimId: "t2", amount: 2 }, peer);
    // The claim must still be live when the settle window (600 ms + 300 ms)
    // closes, or the take refuses an already-lapsed claim; it lapses soon after.
    const taken = await space.take(new Template(Claim, { claimId: "t2" }), "1500ms", "3s");
    assert.ok(taken !== null);
    assert.ok(await until(3_000, () => kinds.includes("REAPPEARED:t2")));
    await sleep(600);
    assert.equal(kinds.filter((k) => k === "REAPPEARED:t2").length, 1);
    assert.ok(await until(3_000, () => watcher.kinds.filter((k) => k === "t2").length === 2)); // WRITTEN and REAPPEARED
  } finally {
    await bound.close();
  }
});

@agent("sensor")
class Sensor {
  @spaceTake(Claim, "readings", { pollTimeout: "300ms", produces: [Fraud, Coverage] })
  sense(claim: Claim): Contribution {
    return new Contribution("load", claim.amount);
  }
}

test("a contribution return starts the epoch and produces names the card types", async () => {
  const peer = new StubPeer();
  const other = new StubPeer();
  const aggregate = new Aggregate(new Pipes(peer));
  const bound = new Binder(peer, { aggregate }).bind(new Sensor());
  try {
    assert.deepEqual(bound.card!["produces"], ["com.acme.Fraud#v1", "com.acme.Coverage#v1"]);
    foldFrom(other, "readings", "com.acme.Claim#v1", { claimId: "r1", amount: 12 }, peer);
    assert.ok(await until(10_000, () => aggregate.knownEpochIds().has("load")));
    assert.ok([...peer.states.values()].some((dto) => dto["completed"]));
  } finally {
    await bound.close();
  }
});
