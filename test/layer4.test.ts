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
 * Layer 4 from TypeScript without a socket (L3L4-COVERAGE.md §6.5): the
 * capability pipes between peers on an in-memory network, push-sum and
 * rosters, the hashing embedder matching Java, semantic queries local and
 * remote, remote actions through a bound agent, and the estimate decorator.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Binder, agent, onEstimate, spaceTake } from "../src/agents.js";
import { Aggregate, HashingEmbedder, Pipes, Semantic, Settle, actions, invoke, javaHash } from "../src/capabilities/index.js";
import type { Estimate } from "../src/capabilities/index.js";
import { dumps, loads } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import { Space, Template, entry } from "../src/space.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";

const GROUP = "zTypeScriptLayer4";

@entry("com.acme.Task#v1")
class Task {
  constructor(public topic = "", public priority = 0) {}
}

@entry("com.acme.Finding#v1")
class Finding {
  constructor(public topic = "", public summary = "") {}
}

@entry("com.acme.Report#v1")
class Report {
  constructor(public epoch = "", public value = 0) {}
}

type Internals = { fold(dto: Dict): void; foldClaim(entryId: string, signed: Dict): void;
  handle(env: Dict): void; send(kind: string, body: Buffer, to?: string | null): void };

/** Peers by id; an addressed frame goes to its peer, a rumor to every other. */
class Network {
  readonly peers = new Map<string, NetPeer>();
}

class NetPeer extends Peer {
  constructor(readonly network: Network) {
    super(Identity.generate(), GROUP);
    network.peers.set(this.identity.peerId, this);
    const self = this as unknown as Internals;
    self.send = (kind: string, body: Buffer, to: string | null = null) => {
      const env = wire.envelope(this.group, kind, this.identity.peerId,
        wire.hlcNow(this.identity.peerId, this.now()), body, to);
      const targets = to !== null ? [network.peers.get(to)!]
        : [...network.peers.values()].filter((p) => p.identity.peerId !== this.identity.peerId);
      for (const target of targets) {
        if (target.accepts(env)) {
          (target as unknown as Internals).handle(env);
        }
      }
      if (kind === "RUMOR" && to === null) {
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

function fleet(n = 2): NetPeer[] {
  const network = new Network();
  const peers = Array.from({ length: n }, () => new NetPeer(network));
  for (const p of peers) {
    p.introduce();
  }
  return peers;
}

test("push-sum converges to the fleet mean and rosters count members", () => {
  const [a, b] = fleet() as [NetPeer, NetPeer];
  assert.deepEqual([...a.members.keys()], [b.identity.peerId]);
  const aggA = new Aggregate(new Pipes(a));
  const aggB = new Aggregate(new Pipes(b));
  aggA.start("load", 10);
  aggB.start("load", 30);
  aggA.start("n", 0, "count");
  aggB.start("n", 0, "count");
  aggA.start("peak", 10, "max");
  aggB.start("peak", 30, "max");
  aggA.start("total", 10, "sum");
  aggB.start("total", 30, "sum");
  assert.equal(aggA.estimate("load"), null);
  for (let i = 0; i < 12; i++) {
    aggA.tick();
    aggB.tick();
  }
  assert.ok(Math.abs(aggA.estimate("load")! - 20) < 0.01 && Math.abs(aggB.estimate("load")! - 20) < 0.01);
  assert.equal(aggA.estimate("n"), 2);
  assert.equal(aggB.estimate("peak"), 30);
  assert.ok(Math.abs(aggA.estimate("total")! - 40) < 0.05);
  const frame = loads(dumps(wire.aggregateShareFrame("load", 5, 0.5))) as Dict;
  assert.equal(wire.claimNumber((frame["share"] as Dict)["weight"]), 0.5);
});

test("awaitSettled and onEstimate fire on the tick", async () => {
  const [a, b] = fleet() as [NetPeer, NetPeer];
  const aggA = new Aggregate(new Pipes(a));
  const aggB = new Aggregate(new Pipes(b));
  aggA.start("load", 10);
  aggB.start("load", 30);
  const fired: Estimate[] = [];
  const close = aggA.onEstimate((e) => e === "load", Settle.after(2, 0.01), (e) => fired.push(e));
  aggA.run(20);
  aggB.run(20);
  try {
    const settled = await aggA.awaitSettled("load", Settle.after(2, 0.01), 10_000);
    assert.ok(settled !== null && Math.abs(settled - 20) < 0.5);
    assert.ok(await until(5_000, () => fired.length === 1));
    await sleep(150);
    assert.equal(fired.length, 1);
    assert.ok(fired[0]!.epochId === "load" && fired[0]!.ticks >= 3);
    assert.equal(await aggA.awaitSettled("missing", Settle.FIRST, 200), null);
  } finally {
    close();
    aggA.close();
    aggB.close();
  }
});

test("the hashing embedder matches Java", () => {
  assert.equal(javaHash("hello"), 99162322);
  assert.equal(javaHash(""), 0);
  assert.equal(javaHash("polygenelubricants"), -2147483648);
  const e = new HashingEmbedder();
  const v = e.embed("Researches topics research com.acme.Task#v1");
  assert.equal(v.length, 256);
  assert.ok(Math.abs(v.reduce((acc, x) => acc + x * x, 0) - 1) < 1e-9);
  assert.deepEqual(e.embed(null), new Array(256).fill(0));
  assert.equal(e.embed("hello")[99162322 % 256], 1);
});

@agent("researcher", { description: "Researches topics and writes findings", goals: ["research", "summarize"] })
class Researcher {
  @spaceTake(Task, "tasks", { lease: "30s", pollTimeout: "300ms", produces: Finding, description: "Researches one topic" })
  research(task: Task): Finding {
    return new Finding(task.topic, "researched " + task.topic);
  }
}

test("semantic queries rank cards locally and fetch them remotely", async () => {
  const [a, b] = fleet() as [NetPeer, NetPeer];
  const semA = new Semantic(new Pipes(a));
  const semB = new Semantic(new Pipes(b));
  const bound = new Binder(a).bind(new Researcher());
  try {
    assert.deepEqual(semA.query("research topics findings").map((m) => m.ad["agent"]), [bound.card!["agent"]]);
    assert.ok(semB.query("research topics")[0]!.score > 0.2);
    assert.deepEqual(semA.query("quantum chromodynamics"), []);
    const c = new NetPeer(a.network);
    c.introduce();
    a.introduce();
    b.introduce();
    const semC = new Semantic(new Pipes(c));
    assert.deepEqual(semC.query("research topics"), []);
    const hits = await semC.remoteQuery("research topics", 5, 2_000);
    assert.deepEqual(hits.map((m) => m.ad["agent"]), [bound.card!["agent"]]);
    assert.equal(c.cards()[0]!["id"], bound.card!["id"]);
  } finally {
    await bound.close();
  }
});

test("a remote action from a card is invoked through the task space", async () => {
  const [a, b] = fleet() as [NetPeer, NetPeer];
  const bound = new Binder(a).bind(new Researcher());
  try {
    const found = actions(b);
    assert.deepEqual(found.map((x) => [x.name, x.consumes, x.produces, x.space]),
      [["research", "com.acme.Task#v1", "com.acme.Finding#v1", "tasks"]]);
    assert.equal(found[0]!.description, "Researches one topic");
    const result = await invoke(b, found[0]!, new Task("crdts", 2), { resultType: Finding, timeoutMillis: 15_000 });
    assert.deepEqual(result, new Finding("crdts", "researched crdts"));
    const second = await invoke(b, found[0]!, new Task("raft", 1), { resultType: Finding, timeoutMillis: 15_000 });
    assert.deepEqual(second, new Finding("raft", "researched raft"));
  } finally {
    await bound.close();
  }
});

@agent("supervisor")
class Supervisor {
  readonly reports: Estimate[] = [];

  @onEstimate({ epochs: "load", ticks: 2, tolerance: 0.01, resultSpace: "reports", produces: Report })
  settled(estimate: Estimate): Report {
    this.reports.push(estimate);
    return new Report(estimate.epochId, estimate.value);
  }
}

test("the estimate decorator reacts once when the epoch settles", async () => {
  const [a, b] = fleet() as [NetPeer, NetPeer];
  const aggA = new Aggregate(new Pipes(a));
  const aggB = new Aggregate(new Pipes(b));
  const supervisor = new Supervisor();
  const bound = new Binder(a, { publishCard: false, aggregate: aggA }).bind(supervisor);
  try {
    aggA.start("load", 10);
    aggB.start("load", 30);
    aggA.run(20);
    aggB.run(20);
    assert.ok(await until(10_000, () => new Space(b, "reports").readAll(new Template(Report)).length > 0));
    const report = new Space(b, "reports").readAll(new Template(Report))[0]!;
    assert.ok(report.epoch === "load" && Math.abs(report.value - 20) < 0.5);
    await sleep(150);
    assert.equal(supervisor.reports.length, 1);
  } finally {
    await bound.close();
    aggA.close();
    aggB.close();
  }
});

// ---------------------------------------------------------- hardening (2026-10-09)

test("shares go only to members that advertise the aggregate", () => {
  const [a, b] = fleet() as [NetPeer, NetPeer];
  const bystander = new NetPeer(a.network); // a member with no aggregate
  bystander.introduce();
  a.introduce();
  b.introduce();
  const aggA = new Aggregate(new Pipes(a));
  const aggB = new Aggregate(new Pipes(b));
  assert.deepEqual(aggA.participants(), [b.identity.peerId]);
  assert.ok(new Pipes(a).members().includes(bystander.identity.peerId));
  aggA.start("load", 10);
  aggB.start("load", 30);
  for (let i = 0; i < 40; i++) {
    aggA.tick();
    aggB.tick();
  }
  assert.ok(Math.abs(aggA.estimate("load")! - 20) < 0.01 && Math.abs(aggB.estimate("load")! - 20) < 0.01);
  assert.ok(!new Aggregate(new Pipes(bystander), false).knownEpochIds().has("load"));
});

test("a node nobody pushes to does not settle, and a lone node does", async () => {
  const [a, b, c] = fleet(3) as [NetPeer, NetPeer, NetPeer];
  const aggA = new Aggregate(new Pipes(a));
  const aggB = new Aggregate(new Pipes(b));
  const aggC = new Aggregate(new Pipes(c));
  // A pushes to B, B and C push to each other: nobody ever pushes to A.
  aggA.participants = () => [b.identity.peerId];
  aggB.participants = () => [c.identity.peerId];
  aggC.participants = () => [b.identity.peerId];
  aggA.start("load", 10);
  aggB.start("load", 30);
  aggC.start("load", 20);
  const firedA: number[] = [];
  const firedB: number[] = [];
  aggA.onEstimate((e) => e === "load", Settle.after(2, 0.01), (e) => firedA.push(e.value));
  aggB.onEstimate((e) => e === "load", Settle.after(2, 0.01), (e) => firedB.push(e.value));
  for (let i = 0; i < 30; i++) {
    aggA.tick();
    aggB.tick();
    aggC.tick();
  }
  assert.equal(aggA.estimate("load"), 10); // the hazard: stable by construction, far from the fleet
  assert.ok(await until(2_000, () => firedB.length === 1));
  assert.deepEqual(firedA, []);
  const lone = new NetPeer(new Network());
  const agg = new Aggregate(new Pipes(lone));
  agg.start("load", 12.5);
  const fired: number[] = [];
  agg.onEstimate((e) => e === "load", Settle.after(2, 0.01), (e) => fired.push(e.value));
  for (let i = 0; i < 5; i++) {
    agg.tick();
  }
  assert.ok(await until(2_000, () => fired.length === 1));
  assert.deepEqual(fired, [12.5]);
});
