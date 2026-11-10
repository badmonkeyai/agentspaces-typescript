# How to use AI with AgentSpaces

Written for: TypeScript and JavaScript developers who build with @agentspaces/client.

At the end of this section you will have run three fleets inside one Node
process, over real loopback sockets, with no Java, no network, and no model
key: a decorated agent on one peer that completes work a second peer writes
through an `agentspaces-node` service host; a worker that dies in the middle
of a take, whose task reappears on its own and is finished by a worker that
joins later; and two workers that confirm every order exactly once through an
ordered log kept by two Node voters. Each snippet is the body of one test in
`packages/node/test/readme.test.ts`, verbatim with the imports elided;
`until(condition)` and `seedOf(host)` are the test's two helpers. Run them
with `npm run build` at the client root, then
`cd packages/node && npm run build && node --test build/test/readme.test.js`.

## 1. Build an agent and hand it work from another peer

An `@entry` class names its wire schema, and an `@agent` class carries one
decorated method per verb. The `ServiceHost` is the `@agentspaces/node`
service host: it listens on `tcp`, serves anti-entropy, and relays rumors
between the dial-only peers that connect to it. (`readme.test.ts`, "README 1")

```ts
@entry("com.acme.Task#v1")
class Task { constructor(public topic = "", public priority = 0) {} }

@entry("com.acme.Finding#v1")
class Finding { constructor(public topic = "", public summary = "") {} }

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
```

The two peers share the space and nothing else: the writer never learns the
worker's address, and the worker's return value is written and the task
completed under the same signed claim. The same decorated classes bind in a
browser tab through `@agentspaces/browser` and in a Durable Object through
`@agentspaces/workers`; the host changes and the agent stays the same.

## 2. A crashed worker's take reappears

A worker that takes a task and never finishes dies mid-take when its peer
closes. The writer's `watch` sees the `TAKEN` event, then `REAPPEARED` once
the two-second lease lapses on the clock, and a rescuer bound afterwards
finishes the task. No retry logic exists anywhere in this code.
(`readme.test.ts`, "README 2")

```ts
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
```

## 3. Exactly once, through an ordered log of Node voters

Two service hosts each carry an `OrderedLogHost`, a Raft voter byte-identical
to the Java one, as a duty their tick drives. Two clerks bind `@orderedTake`
with the Raft client (`new OrderedLog(new Pipes(peer))`), so each claim goes
through the log and installs only at the next generation of its entry: three
orders, three receipts, and each order confirmed by exactly one clerk. The
same clerks would join a desk of Java voters unchanged, which
`NodeVoterDeskTest` in the core proves. (`readme.test.ts`, "README 3")

```ts
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
```
