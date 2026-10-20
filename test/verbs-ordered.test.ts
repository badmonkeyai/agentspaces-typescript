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
 * `@orderedTake` through the Raft client over a real three-voter log
 * (srad/agentspaces-js.md JS-V-07), and the ORDERED modes of `@spaceJoin`
 * (JS-V-08) and `@spaceReduce` (JS-V-09): claims go through the log, the
 * holder signs (an attested agent with its own key and certificate), a claim
 * installs only at `epoch == committed + 1`, so two workers complete each
 * entry exactly once; a visitor binds `@orderedTake` and a binder without a
 * log refuses it at bind time (JS-R-01).
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Binder, BinderOptions, Joined, agent, orderedTake, part, spaceJoin, spaceReduce } from "../src/agents.js";
import { OrderedLog, claimCommand } from "../src/capabilities/ordered.js";
import { Pipes } from "../src/capabilities/pipes.js";
import { Identity, spaceIdLocal } from "../src/identity.js";
import { JoinTicket } from "../src/join.js";
import { current } from "../src/reduce.js";
import { Space, Template, entry } from "../src/space.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import { NetPeer, OrderedFleet, fleet, sleep, until } from "./ordered-fleet.js";

const GROUP = "zTsOrdered";

@entry("com.acme.Order#v1")
class Order {
  constructor(public id = "", public region = "", public cents = 0) {}
}

@entry("com.acme.Receipt#v1")
class Receipt {
  constructor(public id = "", public by = "") {}
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
  constructor(public claimId = "", public score = 0) {}
}

@entry("com.acme.Payment#v1")
class Payment {
  constructor(public account = "", public cents = 0) {}
}

@entry("com.acme.Balance#v1")
class Balance {
  constructor(public account = "", public cents = 0, public payments = 0) {}
}

@agent("clerk")
class Clerk {
  readonly confirmed: string[] = [];
  constructor(readonly tag: string) {}

  @orderedTake(Order, "orders", { lease: "30s", pollTimeout: "1s", resultSpace: "receipts", where: { region: "eu" },
    produces: Receipt, description: "Confirms an EU order" })
  confirm(order: Order): Receipt {
    this.confirmed.push(order.id);
    return new Receipt(order.id, this.tag);
  }
}

/** Three voters, a writer, and `clients` more peers, with the log elected and advertised. */
async function orderedFleet(clients: number): Promise<{ peers: NetPeer[]; voters: NetPeer[]; writer: NetPeer;
  clients: NetPeer[]; log: OrderedFleet; close(): Promise<void> }> {
  const peers = fleet(GROUP, 4 + clients);
  const voters = peers.slice(0, 3);
  const writer = peers[3]!;
  const log = new OrderedFleet(voters, "orders");
  await log.start();
  return { peers, voters, writer, clients: peers.slice(4), log,
    close: async () => { await log.stop(); for (const p of peers) { p.close(); } } };
}

const orderedBinder = (peer: NetPeer, options: Omit<BinderOptions, "ordered"> = {}): Binder =>
  new Binder(peer, { publishCard: false, ordered: new OrderedLog(new Pipes(peer)), ...options });

test("two workers complete each entry exactly once through the log, and a duplicate generation is refused (JS-V-07)", async () => {
  const f = await orderedFleet(2);
  const [c1, c2] = f.clients as [NetPeer, NetPeer];
  const first = new Clerk("one");
  const second = new Clerk("two");
  const bound1 = new Binder(c1, { ordered: new OrderedLog(new Pipes(c1)), agentName: "clerk" }).bind(first);
  const bound2 = orderedBinder(c2, { agentName: "clerk" }).bind(second);
  try {
    const orders = new Space(f.writer, "orders");
    const eu1 = orders.write(new Order("eu-1", "eu", 10), "10m");
    const eu2 = orders.write(new Order("eu-2", "eu", 20), "10m");
    const us1 = orders.write(new Order("us-1", "us", 30), "10m");
    const receipts = new Space(f.writer, "receipts");
    assert.ok(await until(30_000, () => receipts.readAll(new Template(Receipt), 10).length === 2), "both EU orders confirmed");
    await sleep(1500);
    const confirmed = [...first.confirmed, ...second.confirmed].sort();
    assert.deepEqual(confirmed, ["eu-1", "eu-2"], "each entry once, fleet-wide");
    assert.equal(orders.readAll(new Template(Receipt), 10).length, 0, "results go to the result space");
    assert.equal(f.writer.claims.has(us1), false, "the field filter left the US order alone");
    for (const id of [eu1, eu2]) {
      const claim = f.writer.claims.get(id)!["claim"] as Dict;
      assert.equal(Number(claim["epoch"]), 1, "the first generation");
      assert.ok(String(claim["holder"]).endsWith("/clerk"), "the holder the binder names");
      assert.equal(f.writer.states.get(id)!["completed"], true, "completed by the committed holder");
      assert.ok(f.log.installed.includes(`${id}:1`), "installed by the log's appliers");
    }
    // A worker whose claim lost the generation submitted the same epoch: the appliers
    // refused it as not the next generation, and it took nothing.
    for (const refused of f.log.rejected) {
      assert.ok(f.log.installed.includes(refused), `${refused} was refused because the log had decided it`);
    }
    const action = (bound1.card!["actions"] as Dict[]).find((a) => a["name"] === "confirm")!;
    assert.equal(action["kind"], "ordered-take");
    assert.equal(action["description"], "Confirms an EU order");
    assert.deepEqual(action["produces"], ["com.acme.Receipt#v1"]);
    assert.equal((bound1.card!["spaceBindings"] as Dict)["com.acme.Order#v1"], "orders");
  } finally {
    await bound1.close();
    await bound2.close();
    await f.close();
  }
});

test("an attested agent signs its ordered claim with its own key and completes as itself (signsAsHolder)", async () => {
  const f = await orderedFleet(1);
  const [c] = f.clients as [NetPeer];
  const holder = c.identity.renewingSubordinate("clerk", "PT24H", Identity.generate(), c.now);
  const clerk = new Clerk("attested");
  const bound = orderedBinder(c, { agent: holder }).bind(clerk);
  try {
    const id = new Space(f.writer, "orders").write(new Order("eu-3", "eu", 5), "10m");
    assert.ok(await until(30_000, () => f.writer.states.get(id)?.["completed"] === true), "completed through the log");
    const signed = f.writer.claims.get(id)!;
    assert.equal((signed["claim"] as Dict)["holder"], holder.agentId, "the agent is the holder");
    assert.ok(signed["holderCertificate"] !== undefined && signed["holderCertificate"] !== null,
      "the claim carries the certificate that lets the agent's own signature verify");
    assert.deepEqual(clerk.confirmed, ["eu-3"]);
    // The completion the agent published is agent-signed (SPEC §11a.4): a peer-signed
    // completion on an attested claim would not have installed at the writer above.
    assert.equal(c.states.get(id)!["signer"], holder.agentId, "the completion is the agent's own");
    assert.ok(c.states.get(id)!["stateCertificate"] !== undefined, "and carries the certificate covering it");
  } finally {
    await bound.close();
    await f.close();
  }
});

test("a claim installs only at epoch == committed + 1: a duplicate or a jump is refused and its sender holds nothing", async () => {
  const f = await orderedFleet(2);
  const [c1, c2] = f.clients as [NetPeer, NetPeer];
  try {
    const id = new Space(f.writer, "orders").write(new Order("eu-9", "eu", 9), "10m");
    const log1 = new OrderedLog(new Pipes(c1));
    assert.equal(await log1.take("orders", "com.acme.Order#v1", "clerk", 30_000, 15_000), id, "c1 holds generation 1");
    const spaceId = spaceIdLocal(`${GROUP}/orders`);
    const holder = c2.identity.agent("clerk");
    const submit = (epoch: number) => {
      const now = c2.now();
      const claim = wire.takeClaim(id, spaceId, epoch, wire.hlcNow(holder, now), holder, 0.0, now + 30_000);
      const signed = wire.signedClaim(claim, c2.identity, null);
      f.log.submitFrom(c2, claimCommand(id, claim, c2.identity.publicRaw, signed["signature"] as Uint8Array, null));
    };
    submit(1);                                                 // the generation the log already decided
    submit(3);                                                 // a generation beyond the next
    assert.ok(await until(10_000, () => f.log.rejected.includes(`${id}:1`) && f.log.rejected.includes(`${id}:3`)),
      `refused: ${f.log.rejected}`);
    await sleep(500);
    assert.equal(String((f.writer.claims.get(id)!["claim"] as Dict)["holder"]), c1.identity.agent("clerk"),
      "the committed holder stands everywhere");
    assert.throws(() => c2.completeEntry("orders", id), /exact live claim/, "c2 cannot complete what it never held");
    c1.completeEntry("orders", id);
    assert.ok(await until(5000, () => f.writer.states.get(id)?.["completed"] === true));
  } finally {
    await f.close();
  }
});

@agent("joiner")
class OrderedJoiner {
  invocations = 0;

  @spaceJoin("intake", "claimId", [part(Fraud), part(Coverage)],
    { mode: "ORDERED", takeLease: "10s", pollTimeout: "1s", resultSpace: "assessments" })
  assemble(j: Joined): Assessment {
    this.invocations++;
    return new Assessment(j.key, j.get(Fraud).score);
  }
}

test("an ORDERED join fires once fleet-wide through a ticket the log decides (JS-V-08)", async () => {
  const f = await orderedFleet(2);
  const [j1, j2] = f.clients as [NetPeer, NetPeer];
  const first = new OrderedJoiner();
  const second = new OrderedJoiner();
  const bound1 = orderedBinder(j1, { residency: "resident" }).bind(first);
  const bound2 = orderedBinder(j2, { residency: "resident" }).bind(second);
  try {
    const intake = new Space(f.writer, "intake");
    intake.write(new Fraud("c1", 3), "1h");
    intake.write(new Coverage("c1", true), "1h");
    const assessments = new Space(f.writer, "assessments");
    assert.ok(await until(30_000, () => assessments.readAll(new Template(Assessment), 10).length >= 1), "fired");
    await sleep(2000);
    assert.equal(first.invocations + second.invocations, 1, "exactly once: the log decided the ticket");
    assert.deepEqual(assessments.readAll(new Template(Assessment), 10), [new Assessment("c1", 3)]);
    assert.ok(await until(10_000, () => intake.readAll(new Template(JoinTicket), 10).length === 0), "the ticket completed");
  } finally {
    await bound1.close();
    await bound2.close();
    await f.close();
  }
});

@agent("teller")
class OrderedTeller {
  @spaceReduce(Payment, Balance, "ledger", { key: "account", mode: "ORDERED", lease: "10s", pollTimeout: "1s",
    accumulatorLease: "1h" })
  apply(balance: Balance | null, payment: Payment): Balance {
    return new Balance(payment.account, (balance?.cents ?? 0) + payment.cents, (balance?.payments ?? 0) + 1);
  }
}

test("an ORDERED reduce takes its ticket and its elements through the log (JS-V-09)", async () => {
  const f = await orderedFleet(1);
  const [r] = f.clients as [NetPeer];
  const bound = orderedBinder(r, { residency: "resident" }).bind(new OrderedTeller());
  try {
    const ledger = new Space(f.writer, "ledger");
    ledger.write(new Payment("acct-a", 2), "1h");
    ledger.write(new Payment("acct-a", 3), "1h");
    const mine = new Space(r, "ledger");
    assert.ok(await until(40_000, () => current(mine, Balance, "teller.apply", "acct-a")?.value.payments === 2), "folded");
    assert.deepEqual(current(mine, Balance, "teller.apply", "acct-a")!.value, new Balance("acct-a", 5, 2));
    assert.ok(f.log.installed.length >= 3, "the ticket and both elements were claimed through the log");
    assert.ok(await until(10_000, () => ledger.readAll(new Template(JoinTicket), 10).length === 0), "the ticket completed");
  } finally {
    await bound.close();
    await f.close();
  }
});

test("@orderedTake binds at the visitor residency, and a binder without a log refuses it naming the fix (JS-R-01)", async () => {
  const [peer] = fleet(GROUP, 1) as [NetPeer];
  try {
    assert.throws(() => new Binder(peer, { publishCard: false }).bind(new Clerk("x")),
      /@orderedTake at clerk\.confirm needs an ordered log: new Binder\(peer, \{ ordered: new OrderedLog\(new Pipes\(peer\)\) \}\)/);
    const visitor = new Binder(peer, { publishCard: false, residency: "visitor", ordered: new OrderedLog(new Pipes(peer)) })
      .bind(new Clerk("visitor"));
    assert.equal(visitor.running, true, "the Raft client is a visitor's verb");
    await visitor.close();
  } finally {
    peer.close();
  }
});
