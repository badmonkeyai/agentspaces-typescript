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
 * Layers 3 and 4 from TypeScript without a socket (L3L4-COVERAGE.md §6.5):
 * the space verbs over entry classes, templates on fields and tags, events
 * from the fold, the decorated agent over a stubbed peer, ballots and
 * decisions. Deltas a second peer would send are folded directly.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Binder, agent, ballot, bidFunction, onDecision, spaceNotify, spaceTake } from "../src/agents.js";
import type { Decision, Proposal } from "../src/agents.js";
import { dumps, loads } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import { COMPLETED, Space, TAKEN, TakeContext, Template, WRITTEN, contains, entry, gte, notNull, oneOf }
  from "../src/space.js";
import * as vote from "../src/vote.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";

const GROUP = "zTypeScriptLayer34";

@entry("com.acme.Task#v1")
class Task {
  constructor(public topic = "", public priority = 0) {}
}

@entry("com.acme.Finding#v1")
class Finding {
  constructor(public topic = "", public summary = "") {}
}

@entry("com.acme.Verdict#v1")
class Verdict {
  constructor(public proposalId = "", public winner = "") {}
}

type Internals = { fold(dto: Dict): void; foldClaim(entryId: string, signed: Dict): void; send(kind: string, body: Buffer): void };

/** A peer whose sends are captured and whose own deltas fold locally. */
class StubPeer extends Peer {
  readonly sent: Array<[string, Buffer]> = [];

  constructor() {
    super(Identity.generate(), GROUP);
    const self = this as unknown as Internals;
    self.send = (kind: string, body: Buffer) => {
      this.sent.push([kind, body]);
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

  foldAllFrom(other: StubPeer): void {
    for (const [kind, body] of other.sent) {
      if (kind === "RUMOR") {
        const rumor = loads(body) as Dict;
        if (String(rumor["streamId"] ?? "").startsWith("space:")) {
          const delta = loads(Buffer.from(rumor["payload"] as Uint8Array)) as Dict;
          if (delta["state"] !== null && typeof delta["state"] === "object") {
            (this as unknown as Internals).fold(delta["state"] as Dict);
          }
        }
      }
    }
    other.sent.length = 0;
  }
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

test("templates match fields and tags with the Java matcher semantics", () => {
  const t = new Template(Task, { priority: gte(3), topic: contains("index") }, { region: oneOf("eu", "uk") });
  assert.equal(t.schema, "com.acme.Task#v1");
  assert.ok(t.matches({ topic: "indexing", priority: 3 }, { region: "eu" }));
  assert.ok(!t.matches({ topic: "indexing", priority: 2 }, { region: "eu" }));
  assert.ok(!t.matches({ topic: "indexing", priority: 3 }, { region: "us" }));
  assert.ok(new Template(Task, {}, { region: notNull() }).matches({}, { region: "x" }));
  assert.ok(!new Template(Task, {}, { region: notNull() }).matches({}, {}));
  assert.ok(new Template(Task, { topic: "exact" }).matches({ topic: "exact" }));
  assert.ok(new Template(Task, { priority: (p: unknown) => (p as number) % 2 === 1 }).matches({ priority: 3 }));
});

test("tags ride inside the signed record and filter reads", async () => {
  const writer = new StubPeer();
  const reader = new StubPeer();
  const space = new Space(writer, "tasks");
  space.write(new Task("eu-task", 1), "10m", { region: "eu" });
  space.write(new Task("us-task", 2), "10m", { region: "us" });
  reader.foldAllFrom(writer);
  assert.equal(reader.states.size, 2);
  const view = new Space(reader, "tasks");
  assert.deepEqual(view.readAll(new Template(Task, {}, { region: "eu" })).map((t) => t.topic), ["eu-task"]);
  assert.deepEqual(view.readAll(new Template(Task, {}, { region: notNull() })).map((t) => t.topic).sort(),
    ["eu-task", "us-task"]);
  assert.equal((await view.read(new Template(Task, { priority: 2 })))!.topic, "us-task");
  assert.ok(view.entries(new Template(Task))[0]!.value instanceof Task);
  // A tampered tag breaks the signature and the record is dropped.
  const { body } = wire.entryDelta("tasks", GROUP, "com.acme.Task#v1", dumps({ topic: "t", priority: 1 }),
    writer.identity, "writer", 60_000, null, undefined, { region: "eu" });
  const state = (loads(Buffer.from((loads(body) as Dict)["payload"] as Uint8Array)) as Dict)["state"] as Dict;
  (state["record"] as Dict)["tags"] = { region: "us" };
  (reader as unknown as Internals).fold(state);
  assert.equal(reader.states.size, 2);
});

test("a take completes with a result in the take space and the context is set", async () => {
  const peer = new StubPeer();
  const other = new StubPeer();
  foldFrom(other, "tasks", "com.acme.Task#v1", { topic: "index", priority: 5 }, peer);
  const space = new Space(peer, "tasks");
  const events: string[] = [];
  space.watch(new Template(Task), (e) => events.push(e.kind));
  const taken = await space.take(new Template(Task, { priority: gte(5) }), "1m", "3s");
  assert.ok(taken !== null && taken.value.topic === "index");
  assert.equal(TakeContext.current(), null);
  TakeContext.run(taken, () => assert.equal(TakeContext.current(), taken));
  const resultId = taken.complete(new Finding("index", "done"));
  assert.ok(resultId !== null && peer.states.has(resultId));
  assert.equal(peer.states.get(taken.entryId)!["completed"], true);
  assert.equal(space.readAll(new Template(Finding))[0]!.summary, "done");
  assert.deepEqual(space.readAll(new Template(Task)), []);
  assert.deepEqual(events, [TAKEN, COMPLETED]);
  assert.equal(await space.take(new Template(Task), "1m", "1s"), null);
});

test("a watch delivers each entry once per kind, and as an async iterator", async () => {
  const peer = new StubPeer();
  const other = new StubPeer();
  const space = new Space(peer, "tasks");
  const seen: string[] = [];
  const sub = space.watch(new Template(Task, {}, { region: "eu" }), (e) => seen.push(`${e.kind}:${e.entry.value.topic}`));
  const iterated: string[] = [];
  const events = space.events(new Template(Task));
  const consumer = (async () => {
    for await (const e of events) {
      iterated.push(e.entry.value.topic);
    }
  })();
  foldFrom(other, "tasks", "com.acme.Task#v1", { topic: "a", priority: 1 }, peer, { region: "eu" });
  foldFrom(other, "tasks", "com.acme.Task#v1", { topic: "b", priority: 1 }, peer, { region: "us" });
  const first = [...peer.states.values()].find((dto) =>
    (loads(Buffer.from((dto["record"] as Dict)["payload"] as Uint8Array)) as Dict)["topic"] === "a")!;
  (peer as unknown as Internals).fold({ ...first });
  assert.deepEqual(seen, ["WRITTEN:a"]);
  sub.close();
  foldFrom(other, "tasks", "com.acme.Task#v1", { topic: "c", priority: 1 }, peer, { region: "eu" });
  assert.deepEqual(seen, ["WRITTEN:a"]);
  await sleep(20);
  events.close();
  await consumer;
  assert.deepEqual(iterated, ["a", "b", "c"]);
});

@agent("researcher", { description: "Researches topics", goals: ["research"] })
class Researcher {
  readonly seen: string[] = [];
  readonly audited: string[] = [];

  @spaceTake(Task, "tasks", { lease: "1m", pollTimeout: "500ms", where: { priority: gte(1) }, produces: Finding })
  research(task: Task): Finding {
    this.seen.push(task.topic);
    assert.ok(TakeContext.current() !== null);
    return new Finding(task.topic, "researched " + task.topic);
  }

  @spaceNotify(Finding, "tasks")
  audit(finding: Finding): null {
    this.audited.push(finding.summary);
    return null;
  }

  @bidFunction(Task, "tasks")
  price(task: Task): number {
    return task.priority > 3 ? 1.0 : 10.0;
  }
}

test("a decorated agent takes, notifies, bids, and publishes its card", async () => {
  const peer = new StubPeer();
  const other = new StubPeer();
  const binder = new Binder(peer, { agent: peer.identity.renewingSubordinate("ts-worker", "PT24H") });
  const researcher = new Researcher();
  const bound = binder.bind(researcher);
  try {
    const card = bound.card!;
    assert.ok(String(card["agent"]).endsWith("/ts-worker"));
    assert.equal(card["description"], "Researches topics");
    assert.deepEqual([...(card["consumes"] as string[])].sort(), ["com.acme.Finding#v1", "com.acme.Task#v1"]);
    assert.deepEqual(card["produces"], ["com.acme.Finding#v1"]);
    assert.deepEqual(card["spaceBindings"], { "com.acme.Task#v1": "tasks" });
    assert.deepEqual((card["actions"] as Dict[]).map((a) => a["name"]), ["audit", "research"]);
    assert.ok(card["agentCertificate"] !== undefined);
    const ads = peer.sent.filter(([kind, body]) => kind === "RUMOR" && (loads(body) as Dict)["streamId"] === "ads");
    assert.equal(ads.length, 1);
    const stored = loads(Buffer.from((loads(ads[0]![1]) as Dict)["payload"] as Uint8Array)) as Dict;
    assert.equal(stored["adType"], "AgentCard");
    foldFrom(other, "tasks", "com.acme.Task#v1", { topic: "crdts", priority: 5 }, peer);
    assert.ok(await until(10_000, () => researcher.audited.length === 1));
    assert.deepEqual(researcher.audited, ["researched crdts"]);
    assert.deepEqual(researcher.seen, ["crdts"]);
    assert.deepEqual(new Space(peer, "tasks").readAll(new Template(Finding)).map((f) => f.summary), ["researched crdts"]);
    const claim = [...peer.claims.values()][0]!["claim"] as Dict;
    assert.equal(wire.claimNumber(claim["bid"]), 1.0);
    const done = [...peer.states.values()].find((dto) => dto["completed"])!;
    assert.ok(String(done["signer"]).endsWith("/ts-worker"));
  } finally {
    await bound.close();
  }
});

@agent("panelist", { description: "Votes", goals: ["decide"] })
class Panelist {
  readonly decided: string[] = [];

  @ballot("votes", { prefix: "rel:" })
  judge(proposal: Proposal): string | null {
    return proposal.question.includes("ship") ? "yes" : null;
  }

  @onDecision("votes", { prefix: "rel:", resultSpace: "ledger", produces: Verdict })
  record(decision: Decision): Verdict {
    this.decided.push(decision.proposalId);
    return new Verdict(decision.proposalId, decision.winner);
  }
}

test("a ballot casts once per proposal and a decision fires once at quorum", async () => {
  const peer = new StubPeer();
  const other = new StubPeer();
  const panelist = new Panelist();
  const bound = new Binder(peer, { publishCard: false }).bind(panelist);
  try {
    vote.propose(other, "votes", "rel:1", "ship 1.0?", ["yes", "no"], 2);
    peer.foldAllFrom(other);
    vote.propose(other, "votes", "ops:2", "ship?", ["yes", "no"], 1);
    peer.foldAllFrom(other);
    assert.ok(await until(5_000, () => vote.tally(peer.states, "rel:1").get("yes") === 1));
    assert.deepEqual(vote.ballots(peer.states, "ops:2"), []);
    assert.equal(vote.decision(peer.states, "rel:1"), null);
    vote.cast(other, "votes", "rel:1", "no");
    peer.foldAllFrom(other);
    assert.ok(await until(5_000, () => panelist.decided.length === 1));
    const decided = vote.decision(peer.states, "rel:1")!;
    assert.equal(decided.winner, "no");
    assert.deepEqual([...decided.tally.entries()].sort(), [["no", 1], ["yes", 1]]);
    assert.ok(await until(5_000, () => new Space(peer, "ledger").readAll(new Template(Verdict)).length === 1));
    assert.equal(new Space(peer, "ledger").readAll(new Template(Verdict))[0]!.winner, "no");
    for (const dto of [...peer.states.values()]) {
      (peer as unknown as Internals).fold({ ...dto });
    }
    await sleep(100);
    assert.deepEqual(panelist.decided, ["rel:1"]);
    vote.propose(other, "votes", "rel:2", "hold?", ["yes", "no"], 1);
    peer.foldAllFrom(other);
    await sleep(100);
    assert.deepEqual(vote.ballots(peer.states, "rel:2"), []);
  } finally {
    await bound.close();
  }
});
