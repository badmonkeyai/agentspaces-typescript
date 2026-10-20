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
 * The client README's "How to use AI with AgentSpaces" section, verbatim:
 * every documentation snippet is cut from checked-in code that runs under
 * the gate (FEATURES.md section 15, item 18). The lines between each pair of
 * `// readme:` markers are the snippet the README shows, with the imports
 * elided; `until` and `seedOf` are the two helpers. Every peer runs in this
 * process over real loopback sockets on free ports, through the
 * `agentspaces-node` service host, with no network and no model key.
 *
 *     npm run build && node --test build/test/readme.test.js    (from packages/node)
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Binder, Identity, Peer, Seed, Space, Template, agent, capabilities, entry, orderedTake, parseSeed, spaceTake }
  from "@agentspaces/client";
import { OrderedLogHost } from "@agentspaces/ordered";
import { ServiceHost } from "../src/host.js";

const { OrderedLog, Pipes } = capabilities;
const GROUP = "zReadmeGroup";

async function until(condition: () => boolean, millis = 10_000): Promise<void> {
  const deadline = Date.now() + millis;
  while (!condition()) {
    if (Date.now() > deadline) {
      throw new Error("condition not met in time");
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

/** The tcp seed a started host listens on. */
const seedOf = (host: ServiceHost): Seed => parseSeed(host.addresses.get("tcp")!, 7500, null);

// readme: begin types
@entry("com.acme.Task#v1")
class Task { constructor(public topic = "", public priority = 0) {} }

@entry("com.acme.Finding#v1")
class Finding { constructor(public topic = "", public summary = "") {} }
// readme: end types

test("README 1: an agent on one peer takes what another peer writes, through a Node service host", async () => {
  const open: Array<{ close(): unknown }> = [];
  try {
    // readme: begin agent
    @agent("summarizer", { description: "Summarizes tasks" })
    class Summarizer {
      @spaceTake(Task, "tasks", { lease: "30s", pollTimeout: "1s", produces: Finding })
      summarize(task: Task): Finding { return new Finding(task.topic, `summary of ${task.topic}`); }
    }

    const hub = new ServiceHost(Identity.generate(), GROUP, {         // the agentspaces-node service host
      tickMillis: 50, listeners: [{ scheme: "tcp", bind: "127.0.0.1:0" }], spaces: ["tasks"], log: null });
    await hub.start();

    const worker = new Peer(Identity.generate(), GROUP);              // peer one: the agent
    await worker.connectAny([seedOf(hub)]);
    const bound = new Binder(worker, { agentName: "summarizer" }).bind(new Summarizer());

    const writer = new Peer(Identity.generate(), GROUP);              // peer two: writes, then reads the result
    await writer.connectAny([seedOf(hub)]);
    const tasks = new Space(writer, "tasks");
    tasks.write(new Task("tuple spaces", 1), "10m");
    const finding = await tasks.read(new Template(Finding), "30s");  // the agent's return value is the next entry
    assert.equal(finding?.summary, "summary of tuple spaces");
    // readme: end agent
    open.push(bound, worker, writer, { close: () => hub.stop() });
  } finally {
    for (const o of open) {
      await o.close();
    }
  }
});

test("README 2: a crashed worker's take reappears and a second worker finishes it", async () => {
  const open: Array<{ close(): unknown }> = [];
  try {
    // readme: begin crash
    @agent("doomed")
    class Doomed {
      @spaceTake(Task, "tasks", { lease: "2s", pollTimeout: "1s" })
      hang(_task: Task): Promise<Finding> { return new Promise(() => undefined); }   // never returns
    }
    @agent("rescuer")
    class Rescuer {
      @spaceTake(Task, "tasks", { lease: "30s", pollTimeout: "1s", produces: Finding })
      finish(task: Task): Finding { return new Finding(task.topic, "finished by the rescuer"); }
    }

    const hub = new ServiceHost(Identity.generate(), GROUP, {
      tickMillis: 50, listeners: [{ scheme: "tcp", bind: "127.0.0.1:0" }], spaces: ["tasks"], log: null });
    await hub.start();
    const doomed = new Peer(Identity.generate(), GROUP);
    await doomed.connectAny([seedOf(hub)]);
    new Binder(doomed, { agentName: "doomed" }).bind(new Doomed());

    const writer = new Peer(Identity.generate(), GROUP);
    await writer.connectAny([seedOf(hub)]);
    const tasks = new Space(writer, "tasks");
    const events: string[] = [];
    tasks.watch(new Template(Task), (e) => events.push(e.kind));
    tasks.write(new Task("resilient", 1), "10m");
    await until(() => events.includes("TAKEN"));                      // the doomed worker holds the task
    doomed.close();                                                    // and dies mid-take
    await until(() => events.includes("REAPPEARED"));                 // its 2 s lease lapsed: the task is back

    const rescuer = new Peer(Identity.generate(), GROUP);
    await rescuer.connectAny([seedOf(hub)]);
    rescuer.pullSpace("tasks");
    const bound = new Binder(rescuer, { agentName: "rescuer" }).bind(new Rescuer());
    const finding = await tasks.read(new Template(Finding), "30s");
    assert.equal(finding?.summary, "finished by the rescuer");
    // readme: end crash
    open.push(bound, rescuer, writer, { close: () => hub.stop() });
  } finally {
    for (const o of open) {
      await o.close();
    }
  }
});

test("README 3: two clerks confirm every order exactly once through an ordered log of two Node voters", async () => {
  const open: Array<{ close(): unknown }> = [];
  try {
    // readme: begin ordered
    @agent("clerk")
    class Clerk {
      readonly confirmed: string[] = [];
      constructor(readonly name: string) {}

      @orderedTake(Task, "orders", { lease: "30s", pollTimeout: "1s", resultSpace: "receipts", produces: Finding })
      confirm(order: Task): Finding {
        this.confirmed.push(order.topic);
        return new Finding(order.topic, `confirmed by ${this.name}`);
      }
    }

    const identities = [Identity.generate(), Identity.generate()];  // two Node voters: a log needs a majority
    const members = identities.map((i) => i.peerId);
    const voters: ServiceHost[] = [];
    for (const [i, identity] of identities.entries()) {
      const host = new ServiceHost(identity, GROUP, { tickMillis: 50, spaces: ["orders", "receipts"], log: null,
        listeners: [{ scheme: "tcp", bind: "127.0.0.1:0" }], seeds: i === 0 ? [] : [seedOf(voters[0])] });
      const log = new OrderedLogHost(host.peer, "orders", members, { residency: "service", tickMillis: 50 });
      await log.ready();
      host.addDuty(log);                                               // the voter ticks with its host
      await host.start();
      voters.push(host);
    }

    const clerks = [new Clerk("one"), new Clerk("two")];
    const peers: Peer[] = [];
    const bounds = [];
    for (const clerk of clerks) {                                      // two workers racing for the same orders
      const peer = new Peer(Identity.generate(), GROUP);
      await peer.connectAny([seedOf(voters[0])]);
      bounds.push(new Binder(peer, { ordered: new OrderedLog(new Pipes(peer)), agentName: "clerk" }).bind(clerk));
      peers.push(peer);
    }
    const writer = new Peer(Identity.generate(), GROUP);
    await writer.connectAny([seedOf(voters[0])]);
    const orders = new Space(writer, "orders");
    for (const id of ["o-1", "o-2", "o-3"]) {
      orders.write(new Task(id, 1), "10m");
    }
    const receipts = new Space(writer, "receipts");
    await until(() => receipts.readAll(new Template(Finding), 10).length === 3, 30_000);
    const confirmed = [...clerks[0].confirmed, ...clerks[1].confirmed].sort();
    assert.deepEqual(confirmed, ["o-1", "o-2", "o-3"]);               // each order once, fleet-wide
    // readme: end ordered
    open.push(...bounds, ...peers, writer, ...voters.map((v) => ({ close: () => v.stop() })));
  } finally {
    for (const o of open) {
      await o.close();
    }
  }
});
