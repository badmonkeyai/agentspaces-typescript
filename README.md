# @agentspaces/client (TypeScript)

## Introducing AgentSpaces by Bad Monkey AI

**A peer-to-peer coordination fabric for agents, services, and the people who work with them.**

AgentSpaces is a P2P framework to quickly discover and join P2P networks, where agents, software services, and people share assets, queries, results, and coordinate. The framework helps you build fleets of agents, tie in other software, and coordinate across them with a replicated tuple space, quorum building, and more. Agents post work, claim tasks, publish results, vote on decisions, and recover from each other's failures. There is no broker, no registry, no scheduler, and no server to keep alive. Coordination is peer-to-peer, secured end to end, and replicated across the fleet.

## Quick start: build your first agent in TypeScript

An agent is a method. Its parameter is the work it takes, and its return value is the next entry in the space. In TypeScript the method sits on a class marked with decorators, and entries are classes. The peer is a real member of the fleet, it runs on Node 22 or newer, and the same client runs in browsers and Workers. A TypeScript peer dials out to a seed, so the quick start starts one.

**1. Create the project.** The second package supplies the seed.

```
mkdir shop && cd shop
npm init -y && npm pkg set type=module
npm install @agentspaces/client @agentspaces/node
npm install -D typescript @types/node
```

Until the packages are on npm, install them from a clone: `npm install /path/to/agentspaces-typescript /path/to/agentspaces-typescript/packages/node`.

`tsconfig.json` (standard decorators need no `experimentalDecorators`):

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "outDir": "build",
    "types": ["node"]
  },
  "include": ["fulfiller.ts"]
}
```

**2. Start a seed.** The Node service host is a seed in one command and needs no code. Its fleet file has the same shape as the Spring starter's YAML. The `dev-local` profile signs every frame over plain loopback TCP, which is what this client dials. Use it on a laptop and never on a shared network.

`seed.yaml`:

```yaml
agentspaces:
  security:
    profile: dev-local          # signed frames on loopback TCP; never on a shared network
  bind: 127.0.0.1:7700
  tick-millis: 250
  groups:
    - name: shop
      founding: shop-v1
      spaces: [ orders ]
```

```
npx agentspaces-node run seed.yaml
```

The first run creates a `keys/` directory beside `seed.yaml` to hold the seed's identity.

**3. Write the agent.** `@entry` names each entry's wire schema, and the field names match the wire. `@spaceTake` names the entry class to take, the space, and how long the method may hold an entry.

`fulfiller.ts`:

```typescript
import { Binder, Identity, Peer, Space, Template, agent, entry, groupIdFromFounding, spaceTake } from "@agentspaces/client";
import "@agentspaces/client/node"; // Node: registers the tcp dialer

@entry("shop.Order#v1") // the wire name; field names match the wire too
class Order {
  constructor(public orderId = "", public item = "") {}
}

@entry("shop.Shipment#v1")
class Shipment {
  constructor(public orderId = "", public item = "", public by = "") {}
}

@agent("fulfiller", { description: "Ships orders" })
class Fulfiller {
  @spaceTake(Order, "orders", { lease: "30s", produces: Shipment })
  ship(order: Order): Shipment {
    return new Shipment(order.orderId, order.item, "fulfiller");
  }
}

const identity = Identity.generate();
const peer = new Peer(identity, groupIdFromFounding("shop-v1"));
await peer.connect("127.0.0.1", 7700); // the seed
await new Promise((resolve) => setTimeout(resolve, 1000));
new Binder(peer, { agent: identity.renewingSubordinate("fulfiller", "PT24H") }).bind(new Fulfiller());

if (process.argv[2]) {                  // node build/fulfiller.js kite
  const orders = new Space(peer, "orders");
  orders.write(new Order("o-1", process.argv[2]), "10m");
  console.log(await orders.read(new Template(Shipment), "30s"));
  peer.close();
}
```

**4. Run two instances.** The first only ships. The second also writes an order, prints the shipment, and exits.

```
npx tsc
node build/fulfiller.js
node build/fulfiller.js kite
```

Either instance can take the order, because both run the same agent.

**5. Kill one.** Make `ship` `async` with a `Promise<Shipment>` result, and add `console.log("shipping", order.orderId);` and `await new Promise((resolve) => setTimeout(resolve, 10_000));` at the top. Start both instances, write an order from the second, and run `kill -9` on whichever instance prints `shipping`. If you killed the first instance, the second prints the shipment. If you killed the second, the first prints `shipping o-1` again when the 30 second lease lapses.

The sections below add the rest: the three tested walk-throughs under "How to use AI with AgentSpaces", the cross-language guarantee, joining by GroupID, bootstrap and invite keys, and layers 3 and 4 in TypeScript.

## About @agentspaces/client

The TypeScript wire-compatible client: the same protocol the Java and Python
peers speak. From 0.4.0 the client is a **portable core**
(`srad/agentspaces-js.md` §3.1): the main entry imports no Node module, so it
loads in browsers, Web Workers, Cloudflare Workers and workerd, Deno, and Bun
as it does on Node 22 or later. Crypto runs on the audited noble libraries
(`@noble/curves`, `@noble/hashes`) everywhere; the CBOR codec is in
`src/cbor.ts`. A `Peer` joins a Java fleet in the dial-only posture over a
frame channel its dialers open, answers SWIM pings, introduces its
self-advertisement once, writes signed entries, takes under the LEASE_RACE
claim lattice, and reads spaces back through anti-entropy. (A production client
would re-lease its self-advertisement on the advertisement TTL; the demo client
leans on ping liveness and does not.)

```ts
import { Peer, Identity } from "@agentspaces/client";   // every runtime
import "@agentspaces/client/node";                      // Node: registers the tcp dialer
const peer = new Peer(Identity.generate(), groupId);
await peer.connect("seed.example.com", 7500);
```

### Changes from 0.2.0

0.2.0 is deprecated, and the client makes no API compatibility promise before
1.0. What changed in 0.4.0:

| 0.2.0 | 0.4.0 |
|---|---|
| TCP dialing built into `Peer` | `import "@agentspaces/client/node"` registers the `tcp` dialer; `peer.registerDialer(d)` adds others; seeds carry a `scheme` (`tcp` when absent) |
| `Identity.loadOrCreate(dir)`, `Identity.agentKeys(...)`, `identity.savePkcs8(path)` | `loadOrCreateIdentity(dir)`, `agentKeys(...)`, `savePkcs8(identity, path)` from `@agentspaces/client/node` |
| `Buffer` in and out (`dumps`, frames, bodies, views) | plain `Uint8Array`; `bytes` helpers (`toHex`, `fromHex`, `toBase64`, `fromBase64`, `concat`, `equals`) |
| `node:crypto` Ed25519, SHA-256, HKDF | the installed `CryptoPort`: noble by default, `installCrypto(nodeCrypto)` on Node for OpenSSL |
| `Subscription` an `EventEmitter` | the same `on`, `once`, `off`, `emit` on the core's `Emitter` |
| `TakeContext` over `AsyncLocalStorage` | the same API; `AsyncLocalStorage` on Node (installed by the node entry), a synchronous scope elsewhere |
| `beacon.seedsOf(group, "tcp")` | also `beacon.seedsFor(group, schemes)`; joins take seeds of every scheme the peer dials |
| `engines.node >=20` | `>=22` |

The suites prove the core in Node, Deno, Bun, workerd, and headless Chromium,
Firefox, and WebKit (`test/runtimes.test.ts`, `test/browser.test.ts`, which
skip a runtime that is not installed unless `AGENTSPACES_RUNTIMES_REQUIRED=1`
or `AGENTSPACES_BROWSERS_REQUIRED=1`), and `npm run size` reports the
browser bundle against its budget.

## How to use AI with AgentSpaces

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

### 1. Build an agent and hand it work from another peer

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

### 2. A crashed worker's take reappears

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

### 3. Exactly once, through an ordered log of Node voters

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

## The cross-language guarantee

The tests prove this client byte-identical against the SAME
`agentspaces-spec/golden.json` (vendored here as `test/golden.json`) the Python client uses, generated from the
Java codec by `tools/golden/GoldenVectors.java`: every encoding, and every
signature (RFC 8032 signing is deterministic), matches exactly, including the
v0.1.10 vectors (the self-certifying founding document, the `GROUP_AD_WANT`
and `GROUP_AD` frames, the AgentCard and SpaceAdvertisement, the aggregate
and gossip-learn capability payloads), and every `*_cbor` vector is a fixed
point of `dumps(loads(x))`.

### Numbers on the wire

JavaScript has one number type and Java has several, and signatures cover the
bytes, so `src/cbor.ts` keeps the distinction explicit in both directions:

- **Doubles.** A plain `number` encodes as a CBOR integer; wrap it in
  `CborDouble` to emit a float64 (an auction bid, an aggregate share). Every
  float the decoder meets comes back as a `CborDouble`, never a bare number,
  so a decoded claim or a histogram's `double[]` re-encodes to exactly the
  bytes that were signed. That is what keeps signature verification of decoded
  claims working.
- **64-bit integers.** A Java `long` outside `Number.MAX_SAFE_INTEGER` (an
  aggregate roster token, a claim expiry an adversary set to `Long.MAX_VALUE`)
  decodes as a `bigint`, and a `bigint` encodes as a minimal-width CBOR
  integer, so int64 values round-trip byte-exactly instead of losing precision
  or throwing. A `bigint` inside the safe range encodes identically to the
  equivalent `number` and decodes back as a `number`. `wire.rosterToken(peerId)`
  returns the participant token of SPEC section 8 as a `bigint`.

## Agents of their own (v0.1.13)

A TypeScript peer can give each agent a key of its own, certified by the peer and
renewed at half-life, so the fleet stores its work `AGENT_ATTESTED` (SPEC §4.2).
Certificates are judged at the signing time of what they certify.

```ts
const identity = Identity.loadOrCreate("./keys");          // peer.key + peer.pub, Java's layout
const agent = identity.renewingSubordinate("ts-worker", "PT24H");
const peer = new Peer(identity, group);
const entryId = await peer.takeEntry("tasks", TASK_TYPE, "ts-worker", 60_000, 600, 8_000, agent);
peer.completeEntry("tasks", entryId!, agent);              // an attested take completes as its agent
peer.writeEntry("tasks", FINDING_TYPE, finding, "ts-worker", 3_600_000, agent);
```

- **Attested transitions.** An agent-attested entry's transitions must be agent-signed
  (A6).
- **Persistent agent keys.** `Identity.agentKeys(dir, peerId, name)` mirrors Java's
  `AgentKeystore`. `identity.savePkcs8(path)` writes a key as PKCS#8 DER, atomically
  and owner-only (0600).
- **Revocations.** The peer reads the `revocations` and `credential-revocations` streams
  and applies the freeze rule at merge:
  - founder-rooted peer revocations are accepted;
  - agent and agent-key revocations are accepted from the founder or the agent's own
    peer;
  - CA-rooted records are ignored;
  - a late joiner learns the revocations issued before it arrived: the peer pulls
    both streams once on joining, and every `pullSpace` names them too;
  - a founder-rooted peer revocation needs the founder known: `joinByGroupId` sets it
    from the verified founding document, and a peer on a literal group passes it as
    `new Peer(identity, group, now, founderPeerId)` (without it, peer revocations are
    ignored);
  - the freeze rule covers every incoming state, held entries included, so a retired
    agent's later renewals and a revoked holder's completions are refused.
- **What the client does not do yet.** Content-key epochs and per-agent key wrap are
  pinned by the golden vectors, but the client does not decrypt sealed spaces.

## Joining by GroupID

A group founded with `foundGroup(...)` (SPEC sections 4.4 and 5.1) has a
self-certifying id: the hash of its signed founding document. A peer that
knows only that id and a seed endpoint joins with

```ts
const peer = new Peer(Identity.generate(), groupId);
const founding = await peer.joinByGroupId("hq.example", 7500, groupId);
```

which dials the seed, sends an unaddressed `GROUP_AD_WANT` naming the group,
and waits for a `GROUP_AD` whose body passes the four checks of
`verifySignedGroupAd`: the founder key hashes to the advertisement's issuer,
the founder's signature verifies over the founding fields, the founding
document re-derives to exactly the wanted GroupID, and the `id` URI names it.
Answers that fail (a different policy under the same id, a forged signature)
are ignored, so a hostile seed can delay the join but never substitute a
group; the promise rejects with a timeout error (default 10 s) when no
verified document arrives, and only after success does the peer introduce
itself. Frames whose envelope `ver` is not 3 are dropped before any signature
work (SPEC section 9). `connect(host, port)` remains the path for
literal-founding groups whose id every member derives from shared
configuration.

## Bootstrap and invite keys

Discovery SRAD §3.5 and §3.8 (DB-X-02, DB-X-03, DB-X-07). A beacon serves a
signed JSON document (`/.well-known/agentspaces/beacon.json`) listing, per
group, its self-certifying founding advertisement and its seeds; `bootstrap`
fetches it, verifies the issuer's Ed25519 signature over the canonical bytes
(the pinned `beaconPeer` when given), verifies the founding with the same
four checks `joinByGroupId` applies, and dials the document's `tcp` seeds in
priority order. `https://` only unless `allowPlain`; at most 64 KiB.

```ts
const peer = new Peer(Identity.generate(), "aspace://z7f3a...");
await peer.bootstrap("https://agentspaces.corp.example/.well-known/agentspaces/beacon.json",
  { groupId: "aspace://z7f3a...", beaconPeer: "z6Mk...beaconPeerId" });
```

`connectAny(seeds)` is what `bootstrap` ends in and `connect(host, port)` is
now built on: the seeds are dialed in order (a hostname becomes one seed per
address it resolves to), and a lost socket fails over to the next seed
inside the reconnect window, one dial at a time with a pause after every
full round.

```ts
await peer.connectAny([{ host: "seed-a.corp.example", port: 7500 },
                       { host: "seed-b.corp.example", port: 7500 }]);
```

An invite key is the whole invitation for a group for friends: the compact
`aspace-inv1-<code>-<secret>[-<delegation>][@host]` for a text message, or
`https://<host>/j/<code>#<secret>[.<delegation>]` for a phone (the server
sees `/j/<code>` only). From the 128-bit secret, HKDF-SHA256 derives the
lookup code, the invite signing key, and the group's content key, bit for
bit as Java and Python do (`test/social-golden.json`). `joinInvite` fetches
the beacon document under the code, takes the founder's delegation from the
key or the document's `invite` field, signs this peer's `(candidate, group)`
with the invite key into a `d1:` credential under the `aspace:join` resource
hint of its self-advertisement, verifies the founding against the
delegation's group, and dials the seeds.

```ts
const { groupId, contentKey, pinnedKey } = await peer.joinInvite(
  "aspace-inv1-N9BAGDAC8ZW79GD8-000G40R40M30E209185GR38E1W");
// contentKey: Uint8Array(32), the group's content key (epoch 0); the beacon never sees it.
// pinnedKey: the key pinned to the delegation joined under; store it and join with it next time.
```

Store `pinnedKey` and pass it to `joinInvite` on the next start: the members
that admitted this peer re-admit it after the key's window only under the
same credential (SPEC §5.1, v0.1.20), and the beacon document may carry a
newer delegation by then.

`social.GroupSecret`, `social.InviteKey.parse`, `social.issueDelegated`,
`social.delegationHash` and `social.credentialHash` (what a `JOIN_CREDENTIAL`
revocation names) are exported for a founder written in TypeScript;
`beacon.signBeaconDocument` and `beacon.documentJson` serve a document.

## Layers 3 and 4, TypeScript-shaped

The same AgentSpace and the same capability services the Java annotations
bind, as stage-3 decorators on plain classes (`L3L4-COVERAGE.md` §6.5).
TypeScript keeps no parameter types at runtime, so the cue type is the
decorator's first argument. An `@entry` class names its wire schema; a
`Space` holds the layer-3 verbs; a `Template` carries the Java matchers
(`eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `oneOf`, `contains`, `isNull`,
`notNull`, or any function) over fields and tags; `watch` is an
`EventEmitter` and `events` an async iterator, each delivering `WRITTEN`,
`TAKEN`, and `COMPLETED` once per entry; `TakeContext.current()` (an
`AsyncLocalStorage`) is the take a worker runs under.

```ts
@entry("ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1")
class ResearchTask { constructor(public topic = "", public priority = 0) {} }

@agent("researcher", { description: "Researches topics", goals: ["research"] })
class Researcher {
  @spaceTake(ResearchTask, "tasks", { lease: "30s", where: { priority: gte(1) }, produces: Finding })
  research(task: ResearchTask): Finding { ... }

  @spaceNotify(Finding, "tasks")
  audit(finding: Finding): null { ... }

  @bidFunction(ResearchTask, "tasks")
  price(task: ResearchTask): number { ... }

  @ballot("votes", { prefix: "council:" })
  judge(proposal: Proposal): string | null { ... }

  @onDecision("votes", { prefix: "council:" })
  record(decision: Decision): null { ... }
}

const bound = new Binder(peer, { agent: identity.renewingSubordinate("ts-worker", "PT24H") }).bind(new Researcher());
```

`Binder.bind` runs the loops the Java `AgentBinder` runs, on Promises: the
take loop, reactions off the delivery path, the ballot once per proposal, the
decision once at quorum, and the AgentCard (with the declared actions and the
agent certificate) published on the `ads` stream on bind. `vote.propose`,
`vote.cast`, and `vote.decision` are the procedural forms; the tally rule is
Java's. Numbers: a fractional field is encoded as a float64, an integral one
as an integer, and decoded doubles are unwrapped before matching.

The return conventions are the Java binder's (ISSUE-WorkflowVerbs,
ISSUE-Motion): `null` writes nothing; `new Tagged(value, { region: "eu" })`
is written with its tags; an array is the fork, each element written on its
own after the take completes; a `new Motion(proposalId, question, options,
quorum, space?)` opens a vote once per proposal id in its space or the
binder's `voteSpace`. Two more cues: `@propose(Claim, "claims", "votes",
["approve", "deny"], 2, { prefix: "claim:", key: "claimId" })` opens a vote
from a cue once per key (the method returns the question, `null` to ask
nothing, or a `Motion`), and `@spaceJoin("intake", "claimId", [part(Fraud),
part(Coverage), part(Claim, { optional: true })], { resultSpace: ... })` is
the LOCAL join: once per key, when every required part is readable, the
method receives a `Joined` (`key`, `get`, `find`, `all`, `has`); `mode:
"LEASED"` fires once fleet-wide through a `JoinTicket` the ticket discipline
decides, and `mode: "ORDERED"` through a ticket the ordered log commits
(`new Binder(peer, { ordered })`), with the part-lag wait of the Java binder.
`@spaceReduce(Payment, Total, "ledger", { key: "account" })` keeps one
accumulator record per key as the Java binder does, and `@orderedTake` is a
take whose claim the ordered log commits, from any residency. `Space.entries(template)`
is the metadata view (`Entry<T>`: `entryId`, `value`, `tags`, `issuer`,
`expiresAtMillis`, `taken`), and every event carries its entry's tags. A
watch, and `@spaceNotify(..., { on: [...] })`, deliver five kinds: `WRITTEN`,
`TAKEN`, `COMPLETED`, `EXPIRED` (the write lease lapsed while the entry was
open: a leased entry as a timer), and `REAPPEARED` (a take claim lapsed),
the last two judged by a sweep on the clock, once per entry and lapse. A
`new Contribution(epoch, value)` return starts the epoch on the binder's
aggregate, and `produces` on a take or notify takes a list. The
wire is version 3: maps a signature covers (`tags`, `costHints`,
`spaceBindings`) are sorted by `canonicalMap`, shorter UTF-8 keys first and
bytewise between equal lengths.

`capabilities/` speaks the layer-4 pipes (`PIPE_DATA` frames addressed to a
member): `Aggregate` (push-sum `avg`, roster `sum` and `count`, `min`, `max`,
`estimate`, `Settle`, `awaitSettled`, `onEstimate`, and the `@onEstimate`
decorator), `Semantic` (the hashing embedder with Java's `String.hashCode`
so the vectors agree, `query`, `remoteQuery` over the query pipe, and
answers to other members' queries), and `actions` and `invoke` (the actions
the cards on the `ads` stream declare, invoked through the task space with
the shared-fields correlation), `OrderedLog` (the Raft client: a signed
`ClaimCommand` submitted to the advertised leader, the committed claim seen
as the space folds it), and `vote.castPreference`/`leader` (MAJORITY_GOSSIP
over push-sum shares, agreeing with Java's `VoteCapability`). A dial-only
peer sends frames to the members it can reach (the seed it dialed), never
to a member it only heard of; a peer that accepts connections
(`peer.acceptChannel`, the `@agentspaces/node` service host) serves
anti-entropy in Java's digest formats, relays rumors between its links, and
keeps one session per link. Not here: the gossip-learning exchange (its
payload is encoded and golden-pinned); the Raft voter is `@agentspaces/ordered`.

`demo/council.ts` is the whole of it against the Java `CouncilFleet`
coordinator; `test/layer34.test.ts`, `test/layer4.test.ts`, and
`test/verbs.test.ts` prove each piece without a socket.

## Run it

```
npm install
npm test                # tsc + golden vectors via node --test

# the trilingual demo (from the repo root):
clients/run-trilingual-demo.sh
```

The demo runs a Java coordinator publishing six tasks while a Python worker,
this TypeScript worker, and a LangChain4j worker race for them under the
claim lattice; the coordinator prints each finding with the language-tagged
worker that produced it. Its second act is the council: the Java
`CouncilFleet` coordinator with the Python and TypeScript council workers
voting, contributing to the push-sum epoch, answering the semantic query, and
serving a remote action. Four runtimes, one space, no broker.

## On a network

The client is generous in what it accepts and cautious in what it sends
(ROBUSTNESS.md). Every verified frame passes a `FrameFilter` first: a stamp
older than five minutes is stale, one further ahead than the HLC drift bound is
refused, and a sender-and-stamp pair seen before is a replay; all three are
dropped without a reply and counted (`peer.frames.stale`, `.ahead`,
`.replayed`). A kind this client does not speak is counted in
`peer.ignoredKinds`, a body that does not decode in `peer.malformedFrames`, and
the reader goes on. A lost socket is a hiccup, not the end: the peer re-dials
the seed every `reconnectIntervalMs` (5 s) for `reconnectWindowMs` (10 min),
one dial at a time, then introduces itself again and pulls again what it had
pulled (revocations, advertisements, spaces), counting in `peer.reconnects`;
`peer.connected()` says whether the link is up. `close()` by the owner is
final. `test/robustness.test.ts` pins each case against a fake seed over TCP.

## Exact work selection and local snapshots

`takeEntry` accepts an optional `exactEntryId` argument (before the template
matcher and the bid function). Selection always
filters by the group's space ID, uses the effective renewed write lease, and
rechecks the winning claim before returning. `requireHeld` validates an exact,
current claim before an application records a result; `completeEntry` applies
the same guard. The lease-race protocol remains advisory under partitions;
applications must fence external effects separately.

Writes are folded into the issuer's verified local replica before transport.
`exportSnapshot` contains signed states, claims, and revocations, without keys.
`restoreSnapshot` re-verifies revocations before claims and states. Applications
own atomic file storage, size limits and single-writer exclusion. A snapshot is
not a remote acknowledgment or a distributed durability guarantee. Configure the
same trusted founding identity before restoring founder-rooted revocations.
