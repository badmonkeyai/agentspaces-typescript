# @agentspaces/node

## Introducing AgentSpaces by Bad Monkey AI

**A peer-to-peer coordination fabric for agents, services, and the people who work with them.**

AgentSpaces is a P2P framework to quickly discover and join P2P networks, where agents, software services, and people share assets, queries, results, and coordinate. The framework helps you build fleets of agents, tie in other software, and coordinate across them with a replicated tuple space, quorum building, and more. Agents post work, claim tasks, publish results, vote on decisions, and recover from each other's failures. There is no broker, no registry, no scheduler, and no server to keep alive. Coordination is peer-to-peer, secured end to end, and replicated across the fleet.

## Quick start: build your first agent on a Node service host

An agent is a method. Its parameter is the work it takes, and its return value is the next entry in the space. A service host is a Node process that listens, so one process can be the seed and the home of an agent: the host joins the group, serves anti-entropy to the peers behind it, and drains on `SIGTERM`, while a `Binder` runs the agent on the host's own peer.

**1. Create the project.**

```
mkdir shop && cd shop
npm init -y && npm pkg set type=module
npm install @agentspaces/client @agentspaces/node
npm install -D typescript @types/node
```

Until the packages are on npm, install them from a clone: `npm install /path/to/agentspaces-typescript /path/to/agentspaces-typescript/packages/node`. Compile with a `tsconfig.json` that targets ES2022 with `NodeNext` modules (standard decorators need no `experimentalDecorators`).

**2. Write the agent and the host.** `@entry` names each entry's wire schema, and the field names match the wire. The host listens on the port you pass, dials a seed when you name one, and writes an order when you give it an item.

`fulfiller.ts`:

```typescript
import { Binder, Identity, Space, Template, agent, entry, groupIdFromFounding, parseSeed, spaceTake } from "@agentspaces/client";
import { ServiceHost } from "@agentspaces/node";

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

const [port = "7701", seed, item] = process.argv.slice(2);   // node build/fulfiller.js 7702 127.0.0.1:7701 kite
const identity = Identity.generate();
const host = new ServiceHost(identity, groupIdFromFounding("shop-v1"), {
  listeners: [{ scheme: "tcp", bind: `127.0.0.1:${port}` }],
  seeds: seed ? [parseSeed(seed)] : [],
  spaces: ["orders"],
  tickMillis: 250,
  signals: true,                                              // SIGTERM or Ctrl-C drains and stops the host
});
await host.start();
new Binder(host.peer, { agent: identity.renewingSubordinate("fulfiller", "PT24H") }).bind(new Fulfiller());

if (item) {
  const orders = new Space(host.peer, "orders");
  orders.write(new Order("o-1", item), "10m");
  console.log(await orders.read(new Template(Shipment), "30s"));
  await host.stop();
}
```

**3. Run two instances.** The first founds the group on port 7701. The second takes its own port, the first instance as its seed, and an item to order.

```
npx tsc
node build/fulfiller.js
node build/fulfiller.js 7702 127.0.0.1:7701 kite
```

The second instance prints the shipment and stops. Either instance can take the order, because both run the same agent.

**4. Kill one.** Make `ship` `async` with a `Promise<Shipment>` result, and add `console.log("shipping", order.orderId);` and `await new Promise((resolve) => setTimeout(resolve, 10_000));` at the top. Start both instances, write an order from the second, and run `kill -9` on whichever instance prints `shipping`. If you killed the first instance, the second prints the shipment. If you killed the second, the first prints `shipping o-1` again when the 30 second lease lapses. A plain `kill` or Ctrl-C takes the other path: with `signals: true` the host drains and stops cleanly.

A host with no agent code is one command, `npx agentspaces-node run fleet.yaml`, described under [Using it](#using-it).

## About @agentspaces/node

The service host of the AgentSpaces JavaScript client: a Node 22 process that accepts
connections on `tcp` and `ws`, dials its seeds, serves anti-entropy and relays rumors for the
members behind it, hosts Raft voters and keepers, ticks at a fixed cadence and reports its true
cadence to its duties, and drains on `SIGTERM`. It is the residency `service` of
`srad/agentspaces-js.md` §3.6: everything a Java member does except the Java-only transports.

**Architecture position.** A host over the portable core (`@agentspaces/client`) and the voter
(`@agentspaces/ordered`). SPEC §5.3 (anti-entropy), §5.5 (`tcp`, `ws`), §5.6 (session attestation
on unattested links). TECH-SPEC §10.1, §10.3. Design of record: `srad/agentspaces-js.md` §4.5
(JS-R-04, JS-R-06, JS-R-07), §4.2 (JS-H-11).

## Using it

From a fleet file — the `agentspaces:` subtree of a Java fleet YAML, so one file describes both:

```yaml
agentspaces:
  keystore: keys                  # the identity, created on first run (agentspaces-node id prints it)
  bind: 0.0.0.0:7500              # the tcp listener
  tick-millis: 1000
  transport:
    ws:
      bind: 0.0.0.0:7501
      allowed-origins: [ "https://app.example" ]   # browsers; empty refuses every browser
  groups:
    - name: council
      founding: council-v1        # or group-id: <self-certifying id>
      seeds: 10.0.0.5:7460
      spaces: [ tasks, votes ]
      ordered-logs:
        - { space: tasks, members: [ zJavaVoterA, zJavaVoterB ], log-dir: log/tasks }
```

```
npx agentspaces-node run fleet.yaml
npx agentspaces-node id keys
```

In code: `new ServiceHost(identity, group, { listeners, seeds, spaces, tickMillis })`, then
`host.addDuty(ordered)` and `await host.start()`; `await host.stop()` drains within `drainMillis`.
Electron and Tauri applications run the host in their Node or sidecar process the same way.

## Key files

| File | What it is |
| --- | --- |
| `src/host.ts` | `ServiceHost`: listeners, the self-advertisement with endpoints and `js.residency=service`, the tick (members lapsed, an anti-entropy round every ten ticks, the advertisement every five minutes, each duty's tick), the drift rule (three ticks later than twice the period drop the host to `visitor` and suspend its duties; sixty seconds of cadence restore them), `stop()` within the drain bound, optional `SIGTERM`/`SIGINT` handlers. |
| `src/ws-listener.ts` | `WsListener`: the `ws` binding with the `aspace.1` subprotocol required and `OriginPolicy` (no `Origin` passes; a listed one, or any under `*`). |
| `src/file-log-store.ts` | `FileLogStore`: the layout of the Java `FileLogStore` (`term-vote` rewritten through a temporary file and a rename; `entries` append-only records of term, length, command, CRC32, fsynced; a torn tail dropped on load). |
| `src/fleet.ts`, `src/cli.ts` | The fleet file (`parseFleet`, `startFleet`) and the CLI (`run`, `id`). |
| re-exports of `@agentspaces/client/node` | `TcpListener`, `TcpDialer`, `FileKeyStore`, `loadOrCreateIdentity`, `nodeCrypto`. |

The serving half itself — Java-format digests and deltas, `PULL_RESP`, `PING_REQ` relay, rumor
forwarding across links, one session per link — is in the core `Peer` (`src/serving.ts` and the
`acceptChannel` path of `src/peer.ts`), so any host that accepts connections gets it.

## Requirements to tests

| Row | Test |
| --- | --- |
| JS-R-04 service host: tick, true cadence, drain, CLI over the fleet YAML | `test/host.test.ts` ("a tcp hub relays...", "a hub with no seeds... stop drains within its bound"), `test/fleet.test.ts` (YAML parse, `startFleet`, the CLI) |
| JS-R-06 drift to visitor duties and recovery | `test/host.test.ts` "a host whose tick drifts three times drops to visitor duties and recovers after 60 s" |
| JS-R-07 `js.residency` hint | `test/host.test.ts` (the hub's advertisement carries `js.residency=service`) |
| JS-H-11 `ws` listener, endpoints advertised | `test/ws-listener.test.ts` |
| JS-V-06 file log store, vote intact across a restart | `test/file-log-store.test.ts` |
| Serving half (core): digests, deltas, relay, sessions per link, lapsed members, anti-entropy rounds | root `test/host-links.test.ts`, `test/serving.test.ts` (golden `space_state_hash`, `space_claim_hash`, `java_double_strings`) |
| Cross-language: a Node voter beside Java voters, leader killed | `agentspaces-capabilities` `NodeVoterDeskTest` (worker `test/workers/voter-worker.ts`) |

No fleet-size caps: the rumor memory is a cache size and a property; the only bounds are per-source rates and per-message sizes.
