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
 * `@spaceReduce` (srad/agentspaces-js.md JS-V-09), the behaviours of the Java
 * AgentBinderReduceTest ported: a running total per key folding every
 * element once and leaving one accumulator per key, the first step seeing
 * null, a null return consuming the element and leaving the accumulator, a
 * fork carrying the accumulator atomically and the side outputs after it, a
 * step that throws letting the element reappear and be folded once more,
 * elements written before bind, the bound on remembered keys, an idle key
 * lapsing with its ticket and starting again from null, and the bind-time
 * refusals naming the method (and, for the residency, the verb, the
 * residency, and the package: JS-R-01).
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Binder, Joined, agent, part, spaceJoin, spaceReduce } from "../src/agents.js";
import { BoundedMap, JoinTicket } from "../src/join.js";
import { current, steps } from "../src/reduce.js";
import { EXPIRED, Space, Tagged, Template, entry } from "../src/space.js";
import type { Dict } from "../src/wire.js";
import { NetPeer, fleet, sleep, until } from "./ordered-fleet.js";

const GROUP = "zTsReduce";

@entry("com.acme.Payment#v1")
class Payment {
  constructor(public account = "", public cents = 0) {}
}

@entry("com.acme.Balance#v1")
class Balance {
  constructor(public account = "", public cents = 0, public payments = 0) {}
}

@entry("com.acme.Alert#v1")
class Alert {
  constructor(public account = "", public cents = 0) {}
}

const ledger = (peer: NetPeer): Space => new Space(peer, "ledger");
const balance = (peer: NetPeer, name: string, key: string): Balance | null =>
  current(ledger(peer), Balance, name, key)?.value ?? null;
const resident = (peer: NetPeer): Binder => new Binder(peer, { publishCard: false, residency: "resident" });

@agent("teller")
class Teller {
  readonly seen: Array<Balance | null> = [];

  @spaceReduce(Payment, Balance, "ledger", { key: "account", lease: "2s", pollTimeout: "100ms", accumulatorLease: "1h" })
  apply(balance: Balance | null, payment: Payment): Balance {
    this.seen.push(balance);
    return new Balance(payment.account, (balance?.cents ?? 0) + payment.cents, (balance?.payments ?? 0) + 1);
  }
}

test("a running total per key folds every element once and leaves one accumulator per key", async () => {
  const [peer] = fleet(GROUP, 1) as [NetPeer];
  const teller = new Teller();
  const bound = new Binder(peer, { residency: "resident" }).bind(teller);
  try {
    for (let i = 0; i < 3; i++) {
      ledger(peer).write(new Payment("acct-a", 5), "1h");
      ledger(peer).write(new Payment("acct-b", 50), "1h");
    }
    assert.ok(await until(40_000, () => balance(peer, "teller.apply", "acct-a")?.payments === 3
      && balance(peer, "teller.apply", "acct-b")?.payments === 3), "every element folded");
    assert.deepEqual(balance(peer, "teller.apply", "acct-a"), new Balance("acct-a", 15, 3));
    assert.deepEqual(balance(peer, "teller.apply", "acct-b"), new Balance("acct-b", 150, 3));
    assert.equal(steps(current(ledger(peer), Balance, "teller.apply", "acct-a")!), 3);
    assert.equal(teller.seen[0], null, "the first step sees null");
    assert.ok(await until(5000, () => ledger(peer).readAll(new Template(Balance), 20).length === 2),
      "retired predecessors are gone");
    assert.equal(ledger(peer).readAll(new Template(Payment), 20).length, 0, "every element completed");
    assert.ok(await until(5000, () => ledger(peer).readAll(new Template(JoinTicket), 20).length === 0),
      "no ticket outlives a drain");
    const action = (bound.card!["actions"] as Dict[]).find((a) => a["name"] === "apply")!;
    assert.equal(action["kind"], "reduce");
    assert.deepEqual(action["consumes"], ["com.acme.Payment#v1"]);
    assert.deepEqual(action["produces"], ["com.acme.Balance#v1"]);
  } finally {
    await bound.close();
    peer.close();
  }
});

@agent("picky")
class Picky {
  @spaceReduce(Payment, Balance, "ledger", { key: "account", lease: "2s", pollTimeout: "100ms" })
  apply(balance: Balance | null, payment: Payment): Balance | null {
    if (payment.cents === 0) {
      return null;
    }
    return new Balance(payment.account, (balance?.cents ?? 0) + payment.cents, (balance?.payments ?? 0) + 1);
  }
}

test("a null return consumes the element and leaves the accumulator", async () => {
  const [peer] = fleet(GROUP, 1) as [NetPeer];
  const bound = resident(peer).bind(new Picky());
  try {
    ledger(peer).write(new Payment("acct-c", 7), "1h");
    ledger(peer).write(new Payment("acct-c", 0), "1h");
    assert.ok(await until(20_000, () => ledger(peer).readAll(new Template(Payment), 20).length === 0),
      "both elements consumed");
    await sleep(300);
    assert.deepEqual(balance(peer, "picky.apply", "acct-c"), new Balance("acct-c", 7, 1));
  } finally {
    await bound.close();
    peer.close();
  }
});

@agent("alerting")
class Alerting {
  @spaceReduce(Payment, Balance, "ledger", { key: "account", lease: "2s", pollTimeout: "100ms", produces: Alert })
  apply(balance: Balance | null, payment: Payment): unknown {
    const next = new Balance(payment.account, (balance?.cents ?? 0) + payment.cents, (balance?.payments ?? 0) + 1);
    return next.cents > 100 ? [new Tagged(next, { region: "eu" }), new Alert(payment.account, next.cents)] : next;
  }
}

test("a fork carries the accumulator atomically and the side outputs after it", async () => {
  const [peer] = fleet(GROUP, 1) as [NetPeer];
  const bound = new Binder(peer, { residency: "resident" }).bind(new Alerting());
  try {
    ledger(peer).write(new Payment("acct-d", 120), "1h");
    assert.ok(await until(20_000, () => ledger(peer).readAll(new Template(Alert), 20).length === 1));
    assert.deepEqual(ledger(peer).readAll(new Template(Alert), 20), [new Alert("acct-d", 120)]);
    const now = current(ledger(peer), Balance, "alerting.apply", "acct-d")!;
    assert.deepEqual(now.value, new Balance("acct-d", 120, 1));
    assert.deepEqual(now.tags, { region: "eu", reduce: "alerting.apply", key: "acct-d", steps: "1" },
      "the Tagged tags merge beneath the binder's");
    const action = (bound.card!["actions"] as Dict[]).find((a) => a["name"] === "apply")!;
    assert.deepEqual(action["produces"], ["com.acme.Balance#v1", "com.acme.Alert#v1"]);
  } finally {
    await bound.close();
    peer.close();
  }
});

@agent("flaky")
class Flaky {
  calls = 0;

  @spaceReduce(Payment, Balance, "ledger", { key: "account", lease: "1500ms", pollTimeout: "100ms" })
  apply(balance: Balance | null, payment: Payment): Balance {
    if (this.calls++ === 0) {
      throw new Error("simulated failure");
    }
    return new Balance(payment.account, (balance?.cents ?? 0) + payment.cents, (balance?.payments ?? 0) + 1);
  }
}

test("a step that throws lets the element reappear and it is folded once", async () => {
  const [peer] = fleet(GROUP, 1) as [NetPeer];
  const flaky = new Flaky();
  const bound = resident(peer).bind(flaky);
  try {
    ledger(peer).write(new Payment("acct-e", 3), "1h");
    assert.ok(await until(20_000, () => balance(peer, "flaky.apply", "acct-e")?.cents === 3), "folded after the retry");
    assert.equal(flaky.calls, 2);
    assert.equal(balance(peer, "flaky.apply", "acct-e")!.payments, 1, "once");
  } finally {
    await bound.close();
    peer.close();
  }
});

test("elements written before bind are folded", async () => {
  const [peer] = fleet(GROUP, 1) as [NetPeer];
  ledger(peer).write(new Payment("acct-f", 12), "1h");
  const bound = resident(peer).bind(new Teller());
  try {
    assert.ok(await until(20_000, () => balance(peer, "teller.apply", "acct-f")?.cents === 12));
  } finally {
    await bound.close();
    peer.close();
  }
});

@agent("small")
class Small {
  @spaceReduce(Payment, Balance, "ledger", { key: "account", lease: "2s", pollTimeout: "100ms", maxOpen: 2 })
  apply(balance: Balance | null, payment: Payment): Balance {
    return new Balance(payment.account, (balance?.cents ?? 0) + payment.cents, (balance?.payments ?? 0) + 1);
  }
}

test("the bound on remembered keys forgets the eldest, and a forgotten key's predecessor is still retired", async () => {
  const map = new BoundedMap<number>(2);
  map.set("a", 1).set("b", 2).set("c", 3);
  assert.deepEqual([...map.keys()], ["b", "c"], "the eldest is forgotten beyond the bound");
  const [peer] = fleet(GROUP, 1) as [NetPeer];
  const bound = resident(peer).bind(new Small());
  try {
    for (const account of ["acct-a", "acct-b", "acct-c"]) {
      ledger(peer).write(new Payment(account, 1), "1h");
    }
    assert.ok(await until(30_000, () => ["acct-a", "acct-b", "acct-c"]
      .every((k) => balance(peer, "small.apply", k)?.payments === 1)));
    ledger(peer).write(new Payment("acct-a", 1), "1h"); // acct-a's handle was forgotten beyond maxOpen
    assert.ok(await until(20_000, () => balance(peer, "small.apply", "acct-a")?.payments === 2));
    assert.ok(await until(5000, () => ledger(peer).readAll(new Template(Balance), 20).length === 3),
      "one accumulator per key: the predecessor was retired by a take");
  } finally {
    await bound.close();
    peer.close();
  }
});

@agent("short")
class Short {
  @spaceReduce(Payment, Balance, "ledger", { key: "account", lease: "1500ms", pollTimeout: "100ms", accumulatorLease: "2500ms" })
  apply(balance: Balance | null, payment: Payment): Balance {
    return new Balance(payment.account, (balance?.cents ?? 0) + payment.cents, (balance?.payments ?? 0) + 1);
  }
}

test("an idle key lapses with its ticket and starts again from null", async () => {
  const [peer] = fleet(GROUP, 1) as [NetPeer];
  const lapsed: Balance[] = [];
  const watch = ledger(peer).notify(new Template(Balance), (e) => { if (e.kind === EXPIRED) lapsed.push(e.entry.value); }, "1h");
  const bound = resident(peer).bind(new Short());
  try {
    ledger(peer).write(new Payment("acct-g", 4), "1h");
    assert.ok(await until(20_000, () => balance(peer, "short.apply", "acct-g")?.cents === 4));
    assert.ok(await until(5000, () => ledger(peer).readAll(new Template(JoinTicket), 20).length === 0),
      "no ticket outlives a drain");
    assert.ok(await until(10_000, () => lapsed.length === 1), "the accumulator's lease is the key's idle timeout");
    assert.deepEqual(lapsed, [new Balance("acct-g", 4, 1)]);
    assert.equal(balance(peer, "short.apply", "acct-g"), null);
    ledger(peer).write(new Payment("acct-g", 1), "1h");
    assert.ok(await until(20_000, () => balance(peer, "short.apply", "acct-g")?.cents === 1), "from null again");
    assert.equal(balance(peer, "short.apply", "acct-g")!.payments, 1);
  } finally {
    watch.close();
    await bound.close();
    peer.close();
  }
});

@agent("nocoordinator")
class NoCoordinator {
  @spaceReduce(Payment, Balance, "ledger", { key: "account", mode: "ORDERED" })
  apply(_b: Balance | null, _p: Payment): null {
    return null;
  }
}

@agent("clash")
class NameClash {
  @spaceJoin("ledger", "account", [part(Payment), part(Alert)], { name: "shared" })
  assemble(_j: Joined): null {
    return null;
  }

  @spaceReduce(Payment, Balance, "ledger", { key: "account", name: "shared" })
  fold(_b: Balance | null, _p: Payment): null {
    return null;
  }
}

@agent("tooshort")
class LeaseTooShort {
  @spaceReduce(Payment, Balance, "ledger", { key: "account", lease: "1m", accumulatorLease: "10s" })
  apply(_b: Balance | null, _p: Payment): null {
    return null;
  }
}

test("refusals at bind time name the method, and the residency refusal names the verb, the residency, and the package", () => {
  const [peer] = fleet(GROUP, 1) as [NetPeer];
  try {
    assert.throws(() => new Binder(peer, { publishCard: false }).bind(new Teller()),
      /@spaceReduce LEASED at teller\.apply needs residency resident or service or cell; this host is visitor; run it in @agentspaces\/browser, @agentspaces\/node, or @agentspaces\/workers/);
    assert.throws(() => resident(peer).bind(new NoCoordinator()),
      /@spaceReduce ORDERED at nocoordinator\.apply needs an ordered log/);
    assert.throws(() => resident(peer).bind(new NameClash()),
      /named 'shared' like another join or reduce on this agent; tickets would collide/);
    assert.throws(() => resident(peer).bind(new LeaseTooShort()),
      /@spaceReduce at tooshort\.apply: accumulatorLease 10s is shorter than the take lease 1m/);
    assert.throws(() => spaceReduce(Payment, Balance, "ledger", { key: "account", keyTag: "acct" }),
      /names both key and keyTag/);
    assert.throws(() => spaceReduce(Payment, Balance, "ledger", { mode: "LOCAL" as never }), /mode must be/);
  } finally {
    peer.close();
  }
});
