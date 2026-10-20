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
 * The service host (srad/agentspaces-js.md JS-R-04, JS-R-06, JS-R-07) over
 * real sockets: a tcp hub two dial-only Node peers relay through, its
 * advertisement carrying the bound endpoint and `js.residency=service`, a
 * late member served by anti-entropy, the drift rule dropping to visitor
 * duties and recovering, and a stop that closes the listener so a later dial
 * is refused.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Identity, Peer } from "@agentspaces/client";
import "@agentspaces/client/node";
import { DRIFT_TICKS, RECOVERY_MILLIS, ServiceHost } from "../src/host.js";

const GROUP = "zNodeHostGroup";
const TASK = "com.acme.Task#v1";
const sleep = (millis: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, millis));

async function until(condition: () => boolean, millis = 5000): Promise<void> {
  const deadline = Date.now() + millis;
  while (!condition()) {
    if (Date.now() > deadline) {
      throw new Error("condition not met in time");
    }
    await sleep(25);
  }
}

test("a tcp hub relays between dial-only peers and advertises its endpoint and residency (JS-R-04, JS-R-07)", async () => {
  const host = new ServiceHost(Identity.generate(), GROUP, {
    tickMillis: 50, listeners: [{ scheme: "tcp", bind: "127.0.0.1:0" }], spaces: ["tasks"], log: null,
  });
  await host.start();
  const address = host.addresses.get("tcp")!;
  const [h, p] = [address.substring(0, address.lastIndexOf(":")), Number(address.substring(address.lastIndexOf(":") + 1))];
  const a = new Peer(Identity.generate(), GROUP);
  const b = new Peer(Identity.generate(), GROUP);
  try {
    await a.connect(h, p);
    await b.connect(h, p);
    await until(() => host.peer.inbound.size === 2);
    const id = a.writeEntry("tasks", TASK, { topic: "over tcp" }, "a");
    await until(() => b.states.has(id));
    assert.ok(host.peer.states.has(id));
    await until(() => b.members.get(host.peer.identity.peerId)?.["endpoints"] !== undefined);
    const ad = b.members.get(host.peer.identity.peerId)!;
    assert.equal(JSON.stringify(ad["endpoints"]), JSON.stringify([{ transport: "tcp", address, priority: 0 }]));
    assert.equal((ad["resourceHints"] as { [k: string]: string })["js.residency"], "service");
    // A late member pulls the space from the hub.
    const late = new Peer(Identity.generate(), GROUP);
    await late.connect(h, p);
    late.pullSpace("tasks");
    await until(() => late.states.has(id));
    assert.ok(host.peer.pullsAnswered >= 1);
    late.close();
    await until(() => host.ticks >= 3);
  } finally {
    a.close();
    b.close();
    await host.stop();
  }
  await assert.rejects(new Peer(Identity.generate(), GROUP).connect(h, p), /no seed answered/);
});

test("a host whose tick drifts three times drops to visitor duties and recovers after 60 s of cadence (JS-R-06)", async () => {
  let now = 1_000_000;
  const host = new ServiceHost(Identity.generate(), GROUP, { tickMillis: 1000, log: null, clock: () => now });
  const events: string[] = [];
  host.addDuty({ suspend: () => events.push("suspend"), resume: () => events.push("resume") });
  host.observeCadence(now); // the first tick establishes the cadence
  (host as unknown as { ticks: number }).ticks = 1;
  for (let i = 0; i < DRIFT_TICKS - 1; i++) {
    now += 2500;
    host.observeCadence(now);
    assert.equal(host.residency, "service", `${i + 1} drift(s) is not yet a drop`);
  }
  now += 2500;
  host.observeCadence(now);
  assert.equal(host.residency, "visitor");
  assert.deepEqual(events, ["suspend"]);
  // A duty added while degraded starts suspended.
  host.addDuty({ suspend: () => events.push("suspend-late"), resume: () => events.push("resume-late") });
  assert.deepEqual(events, ["suspend", "suspend-late"]);
  // Good ticks for less than a minute keep it a visitor; a minute restores it.
  for (let i = 0; i < 59; i++) {
    now += 1000;
    host.observeCadence(now);
  }
  assert.equal(host.residency, "visitor");
  now += 1000;
  host.observeCadence(now);
  assert.equal(host.residency, "service");
  assert.deepEqual(events, ["suspend", "suspend-late", "resume", "resume-late"]);
  assert.equal(host.drifts, DRIFT_TICKS);
  assert.ok(RECOVERY_MILLIS === 60_000);
});

test("a hub with no seeds introduces itself to whoever connects, and stop drains within its bound", async () => {
  const host = new ServiceHost(Identity.generate(), GROUP, {
    tickMillis: 50, listeners: [{ scheme: "tcp", bind: "127.0.0.1:0" }], log: null, drainMillis: 2000,
  });
  await host.start();
  const address = host.addresses.get("tcp")!;
  const port = Number(address.substring(address.lastIndexOf(":") + 1));
  const a = new Peer(Identity.generate(), GROUP);
  await a.connect("127.0.0.1", port);
  await until(() => a.members.has(host.peer.identity.peerId));
  const started = Date.now();
  await host.stop();
  await host.stop(); // idempotent
  assert.ok(Date.now() - started < 2000);
  await until(() => !a.connected(), 3000);
  a.close();
});
