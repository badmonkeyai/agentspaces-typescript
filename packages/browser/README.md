# @agentspaces/browser

## Introducing AgentSpaces by Bad Monkey AI

**A peer-to-peer coordination fabric for agents, services, and the people who work with them.**

AgentSpaces is a P2P framework to quickly discover and join P2P networks, where agents, software services, and people share assets, queries, results, and coordinate. The framework helps you build fleets of agents, tie in other software, and coordinate across them with a replicated tuple space, quorum building, and more. Agents post work, claim tasks, publish results, vote on decisions, and recover from each other's failures. There is no broker, no registry, no scheduler, and no server to keep alive. Coordination is peer-to-peer, secured end to end, and replicated across the fleet.

## Quick start: build your first agent in the browser

An agent is a method. Its parameter is the work it takes, and its return value is the next entry in the space. In a browser tab the agent lives in the worker, because a page cannot send a class across a message port. The worker is a SharedWorker that holds one peer for the whole origin, the page writes work and reads results through it, and the fleet sees one member however many tabs are open.

**1. Start a seed that admits the page.** A browser reaches the fleet over WebSocket, and a `ws` listener admits a page only when the page's origin is on its list. The `dev-local` profile signs every frame over plain loopback TCP and WebSocket. Use it on a laptop and never on a shared network.

`seed.yaml`:

```yaml
agentspaces:
  security:
    profile: dev-local
  bind: 127.0.0.1:7701
  tick-millis: 250
  transport:
    ws:
      bind: 127.0.0.1:7702
      allowed-origins: [ "http://127.0.0.1:8080" ]
  groups:
    - name: shop
      founding: shop-v1
      spaces: [ orders ]
```

```
npx agentspaces-node run seed.yaml
```

The first run creates a `keys/` directory beside `seed.yaml` to hold the seed's identity.

**2. Create the project.**

```
mkdir shop && cd shop
npm init -y && npm pkg set type=module
npm install @agentspaces/browser @agentspaces/client @agentspaces/node
npm install -D esbuild typescript
```

Until the packages are on npm, install them from a clone: `npm install /path/to/agentspaces-typescript /path/to/agentspaces-typescript/packages/browser /path/to/agentspaces-typescript/packages/node`.

**3. Write the entries, the agent, the worker, and the page.** The page and the worker share the entries. The agent binds in the worker from `onResume`, which fires after the host dials the seed and again after any pause, because the host closes worker-side agents when it pauses.

`entries.ts`:

```typescript
import { entry } from "@agentspaces/client";

@entry("shop.Order#v1") // the wire name; field names match the wire too
export class Order {
  constructor(public orderId = "", public item = "") {}
}

@entry("shop.Shipment#v1")
export class Shipment {
  constructor(public orderId = "", public item = "", public by = "") {}
}
```

`fulfiller.ts`:

```typescript
import { agent, spaceTake } from "@agentspaces/client";
import { Order, Shipment } from "./entries.js";

@agent("fulfiller", { description: "Ships orders" })
export class Fulfiller {
  @spaceTake(Order, "orders", { lease: "30s", produces: Shipment })
  ship(order: Order): Shipment {
    return new Shipment(order.orderId, order.item, "fulfiller");
  }
}
```

`worker.ts`:

```typescript
import { host } from "@agentspaces/browser/worker";
import { Fulfiller } from "./fulfiller.js";

host.onResume(() => host.bind(new Fulfiller())); // the agent runs in the worker, so every tab shares it
```

`page.ts`:

```typescript
import { connect } from "@agentspaces/browser";
import { Template } from "@agentspaces/client";
import { Order, Shipment } from "./entries.js";

const host = await connect({
  founding: "shop-v1",
  seeds: ["ws://127.0.0.1:7702/aspace"],
  worker: new URL("./worker.js", import.meta.url),
});
const orders = host.space("orders");
await orders.write(new Order("o-1", "kite"), "10m");
const shipment = await orders.read(new Template(Shipment), 30_000);
document.body.textContent = `${shipment?.item} shipped by ${shipment?.by}`;
```

`public/index.html`:

```html
<!doctype html>
<meta charset="utf-8">
<title>shop</title>
<script type="module" src="page.js"></script>
```

**4. Build and serve.** Set the esbuild target to `es2022`. Its default target leaves the decorators as written, and the browser rejects the bundle with a syntax error. Any static server works.

```
npx esbuild page.ts worker.ts --bundle --format=esm --target=es2022 --outdir=public
cd public && python3 -m http.server 8080 --bind 127.0.0.1
```

Open `http://127.0.0.1:8080/index.html`. The page writes an order, the agent in the worker ships it, and the page shows `kite shipped by fulfiller`. Open a second tab and both tabs share the one worker.

The sections below add the rest: the worker and page files in detail, the residency table, the drift and pause rules, and the options `connect` takes.

## About @agentspaces/browser

The resident host of the AgentSpaces JavaScript client (`srad/agentspaces-js.md`
§3.6, JS-R-02): one `Peer` of `@agentspaces/client` running in a SharedWorker
(a dedicated Worker where the browser has none, or when asked), holding the
Web Lock `agentspaces:<group>:<peerId>` so one peer per identity per origin
runs, its keys and state in IndexedDB, and every page of the origin attached
over a MessagePort with the core's space verbs. A page sees the fleet through
the worker; the fleet sees one member whatever the number of tabs.

## Key files

| File | What it is |
| --- | --- |
| `src/page.ts` | The page side: `connect(options)` starts or joins the worker, says hello, asks `navigator.storage.persist()`, and returns a `BrowserHost` (`peerId`, `shared`, `instance`, `state`, `"state"` events) whose `space(name)` carries `write`, `entries`, `readAll`, `read`, `take`, `watch`, `events`, `notify`, and `renew` over the port; `RemoteTaken` (`complete`, `renew`) and `RemoteSubscription` (`"event"`, `"close"`, the async iterator, `renew`, `close`). Templates stay the core's `Template`, function matchers included: the host filters by schema, the page judges fields and tags, and a take claims the exact entry the page chose. |
| `demo/swarm.ts`, `demo/swarm-page.ts` | The swarm demo (LB-C-06): a hub and two server peers hold one artifact; the page fetches it through its worker from all three, the hub directly and the servers through the hub as a relay, and draws the bytes from each. `npm run demo:swarm` prints the URL; `node build/demo/swarm.js --check` runs the page in headless Chromium and prints the outcome. |
| `src/opfs.ts` | `OpfsStore`, the content swarm's piece store over the origin private file system (SPEC v0.1.23 §8): one directory per root with the pieces at their offsets, the verified bitfield, and the manifest, so a fetch resumes after a reload and a browser that holds an artifact serves it; reads answer later (the API is asynchronous on a page) and writes queue behind a memory copy that serves meanwhile; `OpfsStore.open(name)` reads every root back and throws where the API is absent, so a caller falls back to the core's `MemoryStore`. Build the swarm as `new Content(new Pipes(peer), new Space(peer, "content"), await OpfsStore.open())`. |
| `src/worker.ts` | The worker entry (`@agentspaces/browser/worker`): detects its scope, builds one `ResidentHost`, serves each `onconnect` port of a SharedWorker or the own scope of a dedicated Worker, and closes a dedicated Worker once its page detaches. A custom worker script imports `ResidentHost` instead and calls `startResidentHost`, then `host.bind(agent)` for agents whose code lives in the worker. |
| `src/host.ts` | `ResidentHost`: identity and agent key bootstrap under the identity lock, the Web Lock election, the peer with `js.residency=resident` in its hints, the snapshot restore, the port protocol, the pause rule, the drift rule (`observeCadence`, JS-R-06), and the tick (the cadence, lapsed members, anti-entropy, the advertisement, the EXPIRED and REAPPEARED sweep, keep-alive renewal of held claims at half-lease, the silent-page sweep, the periodic snapshot). |
| `src/lock.ts` | `LockElection`: `acquire(name, waitMillis)` holds a lock for the host's life and refuses after the wait naming the lock; `withLock` is the bootstrap's critical section. The browser releases a lock when its holder's global dies, so the next tab's host takes over without a message. |
| `src/idb.ts` | `IndexedDbKeyStore`, the core's `KeyStore` port over one object store of the group's database (`keys` for `peer.key`, `peer.pub`, and `agents/<name>/agent.key`; `state` for the CBOR snapshot); `openDatabase`, `closeDatabase`, `deleteDatabase`. Typed structurally, so the package compiles without the DOM library. |
| `src/protocol.ts` | The port protocol: requests by tag with an id, answers with a value or an error, pushes (`event`, `closed`, `state`); `WireEntry` carries the record's own payload and tag bytes so a float stays a float across the port; the lock, database, and key names. |
| `test/resident.test.ts`, `test/browser/harness.ts` | The host in Chromium, Firefox, and WebKit through Playwright against a `ServiceHost` hub of `@agentspaces/node` over `ws`, the worker entry served as one esbuild bundle. |
| `test/host.test.ts` | The host in Node over in-memory stand-ins for IndexedDB, Web Locks, and a port pair, against the same hub. |
| `test/portable.test.ts` | Both entries import no Node module and name no Node global; the protocol names and the CBOR crossing. |

## Residency

| Residency | Realised by | Lifetime | May host |
|---|---|---|---|
| `visitor` | a page's main thread; any host whose timers drift | while the tab is visible; freezes, discards | the space verbs, watches, LEASE_RACE takes, LOCAL joins, push-sum and votes, the Raft client, dialers, store adapters |
| **`resident`** (this package) | a SharedWorker (else a dedicated Worker) holding a Web Lock, with IndexedDB storage | while any tab of the origin holds it | everything a visitor hosts, plus LEASED joins, `@SpaceReduce` accumulators, the ORDERED join as a participant through the Raft client |
| `service` | `@agentspaces/node` | a process under an operator | everything, plus listeners, Raft voter, ORDERED join coordinator, relay role, connector runtime |
| `cell` | `@agentspaces/workers` | activated by requests and alarms; durable storage | everything a resident hosts, plus the connector runtime and agent cells |

The host declares `resident`; the core judges it (`requireResidency`, JS-R-01). What pages reach over the port is the space verbs and `notify`; the binder verbs run only for code loaded in the worker (`host.bind`), because a page cannot send a class across a port.

## The drift rule (JS-R-06)

`observeCadence(now)` is a pure function of the observed tick times, the service host's rule (`DRIFT_TICKS` 3, `DRIFT_FACTOR` 2, `RECOVERY_MILLIS` 60 s): a tick later than twice the period, three times running, drops the host to visitor duties. It logs the drift, sets `js.residency=visitor` in its hints and introduces itself at once when connected, closes every worker-side binding (the `Binder` judges LEASED and ORDERED joins and reduces by residency, so a visitor may not carry them) keeping the instances, and renews no held claim, so each lapses on its own lease. Sixty seconds of cadence restore `resident`: the hint, the bindings bound again from the kept instances, and renewals. The first observation after a start or resume only sets the cadence, so a pause is never a drift. Pages see the change as a `state` event (`residency`, `drifts`).

## The pause rule (JS-R-03)

The host runs while at least one attached page is active. A page reports `pagehide` and `freeze` as inactive and `pageshow` and `resume` as active, beats every 5 s while attached, and detaches on a `pagehide` that is not a back-forward cache entry. When the last active page goes, the host snapshots its state to IndexedDB, stops its tick (the only renewer of held claims), closes every worker-side binding, and closes its channel with a clean WebSocket close, so the hub sees the member leave. While paused, `write`, `take`, `complete`, and both renewals are refused naming the pause; reads of the local replica still answer. A page returning resumes the same identity: the host dials again, introduces itself, pulls its spaces, and forgets every hold whose lease lapsed while it was away. Nothing is renewed by anything but the tick, so no claim outlives its lease across a pause; a `notify` lease runs on the timer port and lapses on time, paused or not. Worker termination (the last tab closing, the browser discarding the worker) drops the socket and releases the lock; the next page's `connect` restarts the host from IndexedDB with the same PeerID. A hidden-but-alive tab does not pause the host: only `pagehide` and `freeze` do.

## Use

```ts
import { connect } from "@agentspaces/browser";
import { Template, entry } from "@agentspaces/client";

@entry("com.acme.Task#v1")
class Task { constructor(public topic = "", public priority = 0) {} }

const host = await connect({
  group: "zGroupId",                           // or founding: "research-fleet-demo-v1"
  seeds: ["wss://fleet.example.com:443/aspace"],
  worker: new URL("./agentspaces-worker.js", import.meta.url),
});
const tasks = host.space("tasks");
await tasks.write(new Task("index the corpus", 3), "10m");
const taken = await tasks.take(new Template(Task, { priority: (p) => Number(p) >= 2 }), "1m", "15s", { keepAlive: true });
await taken?.complete(new Task("done", 0));
tasks.watch(new Template(Task), (e) => console.log(e.kind, e.entry.value.topic));
host.on("state", (s) => console.log(s.paused ? "paused" : "running", s.connected));
```

`agentspaces-worker.js` is `export * from "@agentspaces/browser/worker";` built as a browser module (esbuild, Vite, or any bundler that bundles the core and the noble packages into one file; the bundle must register the dialers, which the host does by name, since a bundler may prune the core's side-effect import of `transport/defaults.js`). The `wss` listener the browser dials needs the page's origin on its allowlist (`allowed-origins` of the Java bindings, `origins` of `ServiceHost`); `navigator.storage.persist()` is asked on the page, never waited on (Firefox puts the question to the user, and `connect` must not hang on a prompt), and its answer lands in `host.persisted` and a `"persisted"` event; `null` means unanswered or absent, `false` only that the browser may evict the origin's storage under pressure (headless Chromium and WebKit answer `false`; headless Firefox leaves the prompt open).

Options: `shared: false` forces a dedicated Worker (one page, its own host); `lockWaitMillis` (3 s; `null` waits for good) bounds the wait for the Web Lock; `database`, `agentName` (`resident`), `tickMillis` (1 s), `snapshotMillis` (30 s), `pageTimeoutMillis` (15 s), `beatMillis` (5 s), `helloTimeoutMillis` (30 s). No option caps the number of pages, spaces, subscriptions, or holds.

## Requirements to tests

| Row | Requirement | Test |
| --- | --- | --- |
| JS-R-02 | A SharedWorker when available, else a dedicated Worker | `resident.test.ts` "two tabs share one PeerID and one ws connection" (`shared` equals the browser's `SharedWorker` presence) and "a dedicated Worker is the fallback, forced here" in each engine |
| JS-R-02 | The Web Lock `agentspaces:<group>:<peerId>`, one peer per identity per origin | `resident.test.ts` "the Web Lock refuses a second host for the same identity in the origin"; `host.test.ts` "mints its identity once … refuses a second host"; `portable.test.ts` lock names |
| JS-R-02 | Pages talk to the host over MessagePorts with the space verbs | `resident.test.ts` "a write from one tab is read in the other", "a watch in one tab sees a write from the other"; `host.test.ts` "subscriptions" |
| JS-R-02 | Keys and state in IndexedDB; `navigator.storage.persist()` called | `resident.test.ts` "keys persist across a reload, and the worker's death closes the channel" (the PeerID read back from IndexedDB; the restarted host restores its snapshot); the persist answer is reported per engine; `host.test.ts` "the snapshot round trip" |
| JS-R-03 | Stops renewing leases and closes its channels on `pagehide`/`freeze` of the last page, worker termination, port close; resumes with the same identity; nothing outlives its lease across a pause | `resident.test.ts` "the pause rule" (a 1 s claim renewed while running, refused and lapsed while paused, taken by the hub, the same PeerID on resume, completion refused) and "keys persist … the worker's death closes the channel"; `host.test.ts` "the pause rule" and the silent-page sweep in "subscriptions" |
| JS-R-06 | A tick later than twice the period three times running drops the host to visitor duties (bindings closed, held claims left to lapse, the drift logged, the hint updated); 60 s of cadence restores them | `host.test.ts` "a host whose tick drifts three times drops to visitor duties … and recovers after 60 s of cadence" (a fake cadence drives `observeCadence`; the hub takes the un-renewed job; the hub hears `visitor` then `resident`; the re-bound agent reacts again); `resident.test.ts` reports `residency` and `drifts` in every status |
| JS-R-07 | `js.residency=resident` in the self-advertisement hints, `visitor` while drifting | `resident.test.ts` (the hub's member record for the host), `host.test.ts` "mints its identity once" and the drift test |
| JS-P-08 | Identity persistence through the `KeyStore` port, IndexedDB here | `host.test.ts` "mints its identity once" (`peer.key`, `peer.pub`, the agent key); `resident.test.ts` "keys persist across a reload" |
| JS-P-01 | Neither entry imports a Node module | `portable.test.ts` |
| JS-K-03 | This README | — |

## The content swarm in the worker

Connect with a `content` block and the resident host runs the content swarm
(SPEC v0.1.23 §8) in its worker: pieces go to the origin private file system
where the thread can write it and to memory otherwise, a fetch runs in the
worker however many tabs watch it, and progress reaches each page as pushes.
The bytes cross the port only when a page reads them.

```ts
const host = await connect({ group, seeds, worker: "/worker.js", content: { pieceSize: 256 * 1024 } });
const final = await host.content.fetch(root, (p) => drawProgress(p.bytesReceived, p.bySource));
const bytes = await host.content.read(root);
const mine = await host.content.publish(bytes, { name: "notes.bin" });   // served from this worker
```

`host.content.list()` and `describe(root)` read the group's manifests;
`(await host.status()).contentStore` says where the pieces live. The
resident test runs a fetch from the hub and a publish back to it in every
engine; Chromium and Firefox store on OPFS, Playwright's WebKit worker on
memory.

## Run it

```
cd agentspaces-typescript && npm run build          # the core
cd packages/node && npm run build                   # the hub the tests dial
cd ../browser && npm run build && npm test
```

The browser test needs Playwright's Chromium, Firefox, and WebKit (`npx playwright install`); a missing one is skipped with a note unless `AGENTSPACES_BROWSERS_REQUIRED=1`. Observed on 2026-10-18: Playwright's WebKit build exposes `SharedWorker` with module scripts, so the forced-fallback scenario is what proves the dedicated-Worker path in every engine; `navigator.storage.persist` is a page API (absent in workers) and answers `false` headless; no engine fires a `close` event on a `MessagePort`, which is why pages beat and the host sweeps the silent.

## Not here

The Raft voter, the ORDERED join coordinator, listeners, and the relay role (`service`, in `@agentspaces/node`); the connector runtime (`service` and `cell`); binder verbs over the port (bind in the worker instead); WebRTC (`@agentspaces/webrtc`); a browser-driven drift case (the drift rule is proven in Node, where a fake cadence can be fed; a page cannot slow a worker's tick on purpose).
