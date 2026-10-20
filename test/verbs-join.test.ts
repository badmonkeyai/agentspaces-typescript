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
 * `@spaceJoin` in its three modes (srad/agentspaces-js.md JS-V-08) and the
 * residency judge (JS-R-01), the behaviours of the Java AgentBinderJoinTest
 * and JoinBindingPartLagTest ported: the newest part of each type, a
 * forgotten or evicted key found again in the space, two LEASED joiners
 * firing once through one ticket, a crashed firing retried from the
 * reappeared ticket, a ticket taken before a part is readable firing once
 * the part arrives, a ticket whose part never arrives released by its lease
 * and never completed, and the bind-time refusals naming the verb, the
 * residency, and the package.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Binder, Joined, agent, part, spaceJoin } from "../src/agents.js";
import { JoinTicket, JOIN_TAG, KEY_TAG } from "../src/join.js";
import { Space, Template, entry } from "../src/space.js";
import type { Dict } from "../src/wire.js";
import { NetPeer, fleet, sleep, until } from "./ordered-fleet.js";

const GROUP = "zTsJoin";

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
  constructor(public claimId = "", public score = 0, public covered = false, public note = "") {}
}

const assessments = (peer: NetPeer): Assessment[] => new Space(peer, "intake").readAll(new Template(Assessment), 50);
const tickets = (peer: NetPeer): JoinTicket[] => new Space(peer, "intake").readAll(new Template(JoinTicket), 50);

@agent("forgetful")
class Forgetful {
  readonly fired: string[] = [];

  @spaceJoin("intake", "claimId", [part(Fraud), part(Coverage)], { within: "200ms", maxOpen: 2 })
  assemble(j: Joined): Assessment {
    this.fired.push(j.key);
    return new Assessment(j.key, j.get(Fraud).score, j.get(Coverage).covered, String(j.all(Fraud).length));
  }
}

test("a LOCAL join fires with the newest part, and a forgotten or evicted key is found again in the space", async () => {
  const [peer] = fleet(GROUP, 1) as [NetPeer];
  const intake = new Space(peer, "intake");
  const forgetful = new Forgetful();
  const bound = new Binder(peer, { publishCard: false }).bind(forgetful);
  try {
    intake.write(new Fraud("slow", 1), "1h");
    await sleep(700);                                       // past `within`: the key is forgotten
    intake.write(new Fraud("e1", 1), "1h");
    intake.write(new Fraud("e2", 1), "1h");
    intake.write(new Fraud("e3", 1), "1h");                 // beyond maxOpen: the eldest is evicted
    intake.write(new Fraud("n", 10), "1h");
    intake.write(new Fraud("n", 20), "1h");                 // the newest Fraud wins
    intake.write(new Coverage("slow", true), "1h");         // the forgotten key's last part
    intake.write(new Coverage("e1", true), "1h");           // the evicted key's last part
    intake.write(new Coverage("n", true), "1h");
    assert.ok(await until(5000, () => forgetful.fired.length === 3), `fired ${forgetful.fired}`);
    await sleep(300);
    assert.deepEqual([...forgetful.fired].sort(), ["e1", "n", "slow"]);
    const n = assessments(peer).find((a) => a.claimId === "n")!;
    assert.equal(n.score, 20, "the newest Fraud");
    assert.equal(n.note, "2", "all() carries every Fraud of the key");
  } finally {
    await bound.close();
    peer.close();
  }
});

@agent("leased")
class Leased {
  invocations = 0;
  constructor(private crashesLeft = 0) {}

  @spaceJoin("intake", "claimId", [part(Fraud), part(Coverage)],
    { mode: "LEASED", takeLease: "3s", pollTimeout: "100ms" })
  assemble(j: Joined): Assessment {
    this.invocations++;
    if (this.crashesLeft-- > 0) {
      throw new Error("simulated crash");
    }
    return new Assessment(j.key, j.get(Fraud).score, j.get(Coverage).covered);
  }
}

@agent("crasher")
class Crasher extends Leased {
  @spaceJoin("intake", "claimId", [part(Fraud), part(Coverage)],
    { mode: "LEASED", takeLease: "1500ms", pollTimeout: "100ms" })
  override assemble(j: Joined): Assessment {
    return super.assemble(j);
  }
}

test("two LEASED joiners fire once through one ticket, and a crashed firing retries from the reappeared ticket", async () => {
  const [a, b] = fleet(GROUP, 2) as [NetPeer, NetPeer];
  const first = new Leased();
  const second = new Leased();
  const boundA = new Binder(a, { publishCard: false, residency: "resident" }).bind(first);
  const boundB = new Binder(b, { publishCard: false, residency: "resident" }).bind(second);
  try {
    new Space(a, "intake").write(new Fraud("c1", 1), "1h");
    new Space(a, "intake").write(new Coverage("c1", true), "1h");
    assert.ok(await until(10_000, () => assessments(a).length > 0), "the join fired");
    await sleep(1000);
    // Both joiners saw the key complete; the later ticket withdrew, so one firing is
    // the rule and a second one needs a partition (SPEC §10.3: LEASED is once per
    // lease race per ticket, at least once fleet-wide).
    const firings = first.invocations + second.invocations;
    assert.ok(firings >= 1 && firings <= 2, `at least once, and once absent a partition: ${firings}`);
    assert.equal(assessments(a).length, firings);
    assert.ok(await until(5000, () => tickets(a).length === 0 && tickets(b).length === 0), "every ticket completed");
  } finally {
    await boundA.close();
    await boundB.close();
  }
  // A firing that throws leaves the ticket to lapse and reappear: the join retries.
  const crasher = new Crasher(1);
  const boundC = new Binder(a, { publishCard: false, residency: "resident" }).bind(crasher);
  try {
    new Space(a, "intake").write(new Fraud("c2", 2), "1h");
    new Space(a, "intake").write(new Coverage("c2", true), "1h");
    assert.ok(await until(15_000, () => assessments(a).some((x) => x.claimId === "c2")), "retried after the crash");
    assert.equal(crasher.invocations, 2, "crashed once, then retried from the reappeared ticket");
  } finally {
    await boundC.close();
    a.close();
    b.close();
  }
});

@agent("lagger")
class Lagger {
  readonly fired: string[] = [];
  constructor(private readonly takeLease: string) {}

  @spaceJoin("intake", "claimId", [part(Fraud), part(Coverage)],
    { mode: "LEASED", takeLease: "30s", pollTimeout: "100ms" })
  assemble(j: Joined): Assessment {
    this.fired.push(j.key);
    return new Assessment(j.key, j.get(Fraud).score, j.get(Coverage).covered);
  }
}

@agent("lagger")
class ShortLagger extends Lagger {
  @spaceJoin("intake", "claimId", [part(Fraud), part(Coverage)],
    { mode: "LEASED", takeLease: "2s", pollTimeout: "100ms" })
  override assemble(j: Joined): Assessment {
    return super.assemble(j);
  }
}

/** Another member saw both parts and wrote the ticket; here, Coverage has not landed. */
function writeLaggingCase(from: NetPeer, key: string): string {
  const intake = new Space(from, "intake");
  intake.write(new Fraud(key, 1), "1h");
  intake.write(new Coverage(key, true), "1h");
  return intake.write(new JoinTicket("lagger.assemble", key), "10m", { [JOIN_TAG]: "lagger.assemble", [KEY_TAG]: key });
}

test("a ticket taken before a part is readable fires once the part arrives (the part-lag wait)", async () => {
  const [a, b] = fleet(GROUP, 2) as [NetPeer, NetPeer];
  a.network.hold(a, "com.acme.Coverage#v1");
  const lagger = new Lagger("30s");
  const bound = new Binder(a, { publishCard: false, residency: "resident" }).bind(lagger);
  try {
    const ticketId = writeLaggingCase(b, "k1");
    await sleep(1500);
    assert.deepEqual(lagger.fired, [], "nothing fires while a required part is not readable");
    assert.ok(a.claims.has(ticketId), "the ticket was taken and is being held for the part");
    a.network.release(a);                                     // the part replicates
    assert.ok(await until(10_000, () => lagger.fired.length === 1), "fired once the part landed");
    assert.ok(await until(5000, () => assessments(a).length === 1));
    assert.ok(await until(5000, () => tickets(a).length === 0), "the ticket completed");
    await sleep(300);
    assert.deepEqual(lagger.fired, ["k1"], "once");
  } finally {
    await bound.close();
    a.close();
    b.close();
  }
});

test("a ticket whose part never arrives is released by its lease, not completed", async () => {
  const [a, b] = fleet(GROUP, 2) as [NetPeer, NetPeer];
  a.network.hold(a, "com.acme.Coverage#v1");
  const lagger = new ShortLagger("2s");                     // a short lease: the wait stays inside it (1 s)
  const bound = new Binder(a, { publishCard: false, residency: "resident" }).bind(lagger);
  try {
    const ticketId = writeLaggingCase(b, "k2");
    await sleep(4500);                                        // several lease lapses and retakes
    assert.deepEqual(lagger.fired, [], "nothing fires while the part is missing");
    assert.equal(a.states.get(ticketId)!["completed"], false, "released by its lease every time, never completed");
    assert.ok(Number((a.claims.get(ticketId)!["claim"] as Dict)["epoch"]) >= 2, "retaken after each lapse");
    // Once the part lands the ticket is taken again and the key fires. Had the taker
    // completed it without firing, there would be no ticket left and the key would be lost.
    a.network.release(a);
    assert.ok(await until(10_000, () => lagger.fired.length === 1));
    assert.ok(await until(5000, () => tickets(a).length === 0), "the ticket completed");
    await sleep(500);
    assert.deepEqual(lagger.fired, ["k2"], "once");
  } finally {
    await bound.close();
    a.close();
    b.close();
  }
});

@agent("ordered")
class Ordered {
  @spaceJoin("intake", "claimId", [part(Fraud), part(Coverage)], { mode: "ORDERED" })
  assemble(_j: Joined): null {
    return null;
  }
}

@agent("local")
class Local {
  @spaceJoin("intake", "claimId", [part(Fraud), part(Coverage)])
  assemble(_j: Joined): null {
    return null;
  }
}

test("joins are judged at bind time: the residency, the ordered log, and the part keys (JS-R-01)", async () => {
  const [peer] = fleet(GROUP, 1) as [NetPeer];
  try {
    assert.throws(() => new Binder(peer, { publishCard: false }).bind(new Leased()),
      /@spaceJoin LEASED at leased\.assemble needs residency resident or service or cell; this host is visitor; run it in @agentspaces\/browser, @agentspaces\/node, or @agentspaces\/workers/);
    assert.throws(() => new Binder(peer, { publishCard: false, residency: "resident" }).bind(new Ordered()),
      /@spaceJoin ORDERED at ordered\.assemble needs an ordered log: new Binder\(peer, \{ ordered: new OrderedLog/);
    assert.throws(() => new Binder(peer, { publishCard: false, residency: "visitor" }).bind(new Ordered()),
      /@spaceJoin ORDERED at ordered\.assemble needs residency resident or service or cell/);
    assert.throws(() => spaceJoin("intake", "claimId", [part(Fraud, { key: "a", keyTag: "b" })]),
      /names both key and keyTag/);
    assert.throws(() => spaceJoin("intake", "claimId", [part(Fraud)], { mode: "SOMEDAY" as never }), /mode must be/);
    const bound = new Binder(peer, { publishCard: false }).bind(new Local()); // LOCAL is a visitor's verb
    await bound.close();
    const service = new Binder(peer, { publishCard: false, residency: "service" }).bind(new Leased());
    await service.close();
  } finally {
    peer.close();
  }
});
