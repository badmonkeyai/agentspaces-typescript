# @agentspaces/workers

The cell host of the AgentSpaces JavaScript client (srad/agentspaces-js.md §3.6, §3.8, §4.5, §4.7,
§4.8, appendix F): Durable Object cells on celld, workerd, and Cloudflare Workers. A cell is one
Durable Object carrying one core `Peer`: its identity and state snapshot in the object's own SQLite
storage, its durable tick on the alarm, one outbound `wss` connection to the fleet's seeds (`ws`
under the `dev-local` profile), and `js.residency=cell` in its advertisement. The **connector cell**
(`AgentSpacesConnectorCell`) runs `@agentspaces/connect`'s `ConnectorRuntime` over the deployment's
own bindings, publishing Durable Object classes and instances, KV, D1, R2, Queues, Workflows, and
Worker routes as AssetCards under a manifest that is the whole allowlist. The **agent cell**
(`AgentSpacesCell`) binds decorated agents as a member in its own name. `once()` gives a target
operation exactly-once semantics under the invocation id the fleet carries, and `fleet(env)` gives a
Worker space handles over the cell's stub. No `node:` module is imported under `src/`; only the
public Workers APIs are used, so one bundle runs on all three runtimes.

**Architecture position.** Hosts and gateways. SPEC §5.2 (hints), §6.1a (AssetCards), §6.3;
TECH-SPEC §6; srad/celld-assetcard-analysis.md §1, §6, §7.

## Use

```ts
import { AgentSpacesConnectorCell, once } from "@agentspaces/workers";
import type { AssetManifest } from "@agentspaces/workers";

export class Fleet extends AgentSpacesConnectorCell<Env> {
  protected manifest(): AssetManifest {
    return { application: "inventory", runtime: "celld", freshness: "PT30S",
      durableObjects: [{ binding: "INVENTORY", className: "Inventory", shape: "aspace:InventoryState",
        description: "Persistent stock per warehouse",
        read: [{ name: "getInventory", params: [], description: "current stock" }],
        invoke: [{ name: "reserveStock", params: ["sku", "qty"], description: "reserve units" }],
        objects: ["warehouse-7", "warehouse-9"] }] };
  }
}

export class Inventory extends DurableObject<Env> {
  async reserveStock(params: { sku: string; qty: string }, invocationId: string) {
    return once(this.ctx.storage, invocationId, () => this.reserve(params.sku, Number(params.qty)));
  }
}

export default { scheduled: (_e, env: Env) => env.FLEET.getByName("connector").fetch("https://cell/wake") };
```

`example/wrangler.json` is the one file that deploys this unchanged: the two Durable Object
bindings, one `new_sqlite_classes` migration, a cron that wakes the connector each minute, and the
`vars` block `AGENTSPACES_GROUP`, `AGENTSPACES_SEEDS`, `AGENTSPACES_INVITE`, `AGENTSPACES_PROFILE`.
The cell answers `/wake` (connect and arm the alarm), `/status`, and `/pause`. A fleet member then
reads through `aspace:cap/data-query` (`DataQuery` with `op` and the operation's parameters; a class
card also takes `object`) and operates through `aspace:cap/asset-invoke` (`AssetInvocations.invoke`
in Java, `invoke` in `@agentspaces/connect`).

## Key files

| File | What it is |
| --- | --- |
| `src/cell.ts` | `CellHost`: the Durable Object base. Identity from `SqliteKeyStore` (minted once), the `Peer` with `js.residency=cell` and the invite's join credential, the snapshot restored on construction and persisted on a cadence (chunked rows of `aspace_state`), `/wake`, `/status`, `/pause`, the alarm (reconnect while down, the subclass's duties, the snapshot, the next alarm at the busy, idle, or reconnect cadence), the in-memory housekeeping tick while live, one immediate redial on socket close, the RPC verbs `fleet()` drives. `AgentSpacesConnectorCell`: the runtime over `WorkersAssetProvider`, cards refreshed on the alarm. `AgentSpacesCell`: a `Binder` at residency `cell`, AgentCards re-published at half TTL. |
| `src/manifest.ts` | `AssetManifest` and the per-kind specs, `validateManifest` (refuses naming the rule), `assetsOf`, `cardOf` (SPEC §6.1a fields alone, appendix F `access` keys, id `<application>:<asset>`), `cardTtl`. |
| `src/providers.ts` | `WorkersAssetProvider`: the appendix F mapping per binding; the request judged against the allowlist before anything runs (`read-ops`, `invoke-ops`, `params`, `object-param`, `object`, `prefixes`); the invocation id as the last RPC argument and as `Aspace-Invocation-Id` on routes. |
| `src/once.ts` | `once(storage, invocationId, fn)`: the `aspace_once` table, the stored result on a repeat, the retention (default 24 h), one run for concurrent calls under one id. |
| `src/keystore.ts` | `SqliteKeyStore` (the core `KeyStore` port over `ctx.storage.sql`), `loadOrCreateIdentity`. |
| `src/config.ts` | `cellConfig(env)`: the `vars`, the profile rule for seeds, every cadence as an option. |
| `src/fleet.ts` | `fleet(env, binding, name)`: `Fleet`, `FleetSpace` (`write`, `entries`, `readAll`, `take`), `FleetTaken` (`complete`, `renew`) over the stub's RPC. |
| `src/workers-types.ts` | The slice of the Workers platform the package touches, as structural types, so Node tests fake it and the build needs no global Workers typings. |
| `example/` | The JS-C-12 demonstration Worker: `Inventory` (stock per warehouse, `once` on both operations, a durable run counter), `Fleet` (the connector), `Adjuster` (an agent cell with `DamageEstimator`), `wrangler.json`. |
| `test/workers/workerd-run.ts` | The harness: esbuild bundle of the example, a workerd config with SQLite-backed namespaces on local disk and the `vars` as text bindings, `workerd serve`. |
| `test/workers/workerd-runner.ts` | The runner the Java `WorkerdCellConnectorTest` spawns: the example under workerd dialing a Java `ws` seed, JSON events (`up`, `runs`, `done`) on stdout. |

## Key dependencies

`@agentspaces/client` (the portable core), `@agentspaces/connect` (the runtime, the entries, the
clients). Dev: `@agentspaces/node` (the hub of the workerd test), `@cloudflare/workers-types` (the
example's type check), the root's `workerd` and `esbuild`.

## Requirements and the tests that prove them

| Row | What it asks | Proof |
| --- | --- | --- |
| JS-R-05 | The cell host: identity and state in SQLite, the tick on the alarm, outbound `wss` or `ws` by profile, reconnection on socket close and on each alarm while down, one bundle on the three runtimes | `test/workerd.test.ts` (the cell dials the hub, resumes under the same PeerID after `/pause` and after a workerd restart, refreshes its card under the same id); `test/once.test.ts` "the SQLite key store ..." (the identity resumes on every load); `test/config.test.ts` (seeds by profile) |
| JS-R-03 | Nothing outlives its lease across a pause; the same identity resumes | `test/workerd.test.ts` (`/pause`: the hub sees the link close; `/wake`: the same PeerID; the restart: the same PeerID, the connector's memory gone, the target's `once` table not) |
| JS-R-07 | `js.residency=cell` in the hints | `test/workerd.test.ts` (the hub's copy of both cells' advertisements) |
| JS-P-08 | The SQLite key store | `test/once.test.ts` "the SQLite key store round-trips bytes ..." |
| JS-C-04 | `once(invocationId, fn)` in SQLite, the stored result on a repeat, a configurable retention (24 h) | `test/once.test.ts` (one run per id; concurrent calls share one run; a failed run records nothing; the retention and its default); `test/workerd.test.ts` (`reserveStock` once under a retry and across the restart: `/runs` stays at one) |
| JS-C-05 | The connector cell: the runtime on the host, the manifest, a non-agent member, `connector` by default | `test/workerd.test.ts` (cards from the cell, no AgentCard from it, `servedBy: connector`) |
| JS-C-06 | The providers: DO classes and instances, KV `get`/`list` under prefixes, D1 named queries, R2 `head`/`list`/`get`, Queues `send`, Workflows `create`/`status`, routes GET-as-read and POST-as-invoke | `test/providers.test.ts` (one test per kind over fake bindings); `test/workerd.test.ts` (a real Durable Object) |
| JS-C-07 | Nothing unlisted runs; parameters validated against declared names; refusals name the rule | `test/providers.test.ts` "requests outside the allowlist are refused ..." (thirteen refusals, no binding touched), "D1 runs only the named query"; `test/manifest.test.ts` "a manifest that could not be served honestly ..."; `test/workerd.test.ts` (`dropTable`: `invoke-ops`; an undeclared `sql` parameter: `params`; a class card without `object`: `object-param`) |
| JS-C-08 | SPEC §6.1a fields alone, `workers://<application>/<kind>/<name>`, appendix F access keys, ids stable across restarts and moves | `test/manifest.test.ts` (every kind's card; the id across renderings); `test/workerd.test.ts` (`inventory:do/Inventory` before and after the restart, one card per id) |
| JS-C-12 | The §7 demonstration on workerd: a stateful Durable Object discovered through its card, queried by a Java agent, updated exactly once under a forced retry | Java `agentspaces-connect-core` `WorkerdCellConnectorTest` (a Java peer with a `ws` listener as the seed; `DataQueryClient.fetch`, `AssetInvocations.invoke` and `retry` under one id; the runner's `done` line reports one run); `test/workerd.test.ts` (the same with the TypeScript client, plus the restart) |
| JS-C-13 | The trust boundaries in this README | below |
| JS-S-05 | `AgentSpacesCell`: decorated agents as a member with its own identity | `test/workerd.test.ts` (the `Adjuster` cell's own PeerID, its AgentCard, a `DamageReport` taken and a `DamageEstimate` written) |
| JS-S-06 | `fleet(env, binding)`: space handles over the stub | `test/config.test.ts` "fleet() drives the cell's RPC verbs ..."; `test/workerd.test.ts` (`/entries` reads the data space through `fleet(env)` in the Worker) |
| JS-S-07 | One `wrangler.json` with the binding, one migration, the `vars` block, deployed unchanged | `example/wrangler.json`; the workerd run uses its `vars` as text bindings and its classes as SQLite namespaces; celld and Cloudflare: see the limits below |
| JS-S-08 | Each runtime's limits in this README | below |
| JS-K-03 | This README and its map | this file |

## Trust boundaries (JS-C-13)

- **The bucket or account administers every cell.** On celld the bucket (and whoever can write to
  it) owns the cells' SQLite files, the identity keys inside them, and the code they run; on
  Cloudflare the account does. A cell's identity is only as private as that storage; the fleet
  admits the identity, not the storage.
- **The connector's identity holds the authority over the operations it lists.** Every card and
  every result is signed by the connector cell's key; a fleet trusting the asset trusts that peer.
  The manifest is the allowlist: nothing a request names outside it runs, and the connector holds no
  credential beyond the deployment's own bindings.
- **The fleet's authorizer grants the JS-C-02 scopes.** With an `authorizer` in `connectorOptions`,
  a card is published only under `aspace:connector-serve:<asset>` and an operation runs only for a
  requester holding `aspace:connector-invoke:<asset>:<operation>`; without one, every admitted
  member may query and invoke what the manifest lists.
- **celld's own peer traffic is plaintext on the operator's network** (appendix D: HTTP between
  nodes with HMAC on tunnel setup). The cell's link to the fleet is `wss` under `attested`; the
  traffic between celld nodes that moves a cell is the operator's to protect.
- `dev-local` is the only profile that dials plaintext `ws`; an `attested` cell refuses a plaintext
  seed at configuration time, naming the rule.

## Runtime limits (JS-S-08)

- **celld.** An outbound Durable Object WebSocket closes when a cell moves between nodes; the cell
  then resumes on its next alarm (the one immediate redial, then every `reconnectMillis`), and every
  claim it held lapses with its lease (the pause rule). celld ships Linux and macOS binaries; one
  cell runs on one node at a time under a bucket lease with a fencing epoch. Not run here: no celld
  binary is installed in this workspace; the bundle uses only the APIs appendix D lists celld as
  supporting (Durable Objects, SQLite, alarms, outbound WebSocket).
- **workerd.** Durable Objects are single-instance and local to the process; storage is in-memory
  or local disk (the test uses local disk so a restart keeps identities). Objects are evicted after
  10 s idle unless a connection keeps them live; `preventEviction` is a workerd-only knob. This is
  the runtime the package's test proves.
- **Cloudflare.** An object with an open (non-hibernated) WebSocket stays resident and is billed for
  its duration; this cell keeps its outbound socket live so its session survives, so a connected
  connector is a resident object. The hibernation API is not used for the outbound socket. SQLite
  rows are bounded by the platform's per-value size, which is why the snapshot is chunked. Not run
  here: no account; `wrangler deploy` of `example/wrangler.json` is the documented path.

## Artifacts from R2

A cell can hold large objects in R2 and serve them to the fleet as artifacts of the content swarm
(`aspace:cap/content-swarm`). The object stays in the bucket; the cell hashes it piece by piece
through ranged gets, publishes a manifest, and answers each piece request with one ranged `get`.
Members fetch the pieces through the hub like any other artifact, and verify every piece against
the manifest's root.

Bind the bucket in `wrangler.json`:

```json
"r2_buckets": [{ "binding": "MODELS", "bucket_name": "models" }]
```

Give the provider the swarm and a store over the same binding:

```ts
import { R2PieceStore } from "@agentspaces/workers";
import { Space, capabilities } from "@agentspaces/client";

export class Fleet extends AgentSpacesConnectorCell<Env> {
  protected override providerOptions(env: Env) {
    const store = new R2PieceStore(env.MODELS);
    const content = new capabilities.Content(new capabilities.Pipes(this.peer),
      new Space(this.peer, "content"), store, { pieceSize: 4 * 1024 * 1024 });
    content.run(); // ticks the swarm on the peer's timer, as the Node test below does
    return { artifacts: { content, store, pieceSize: 4 * 1024 * 1024 } };
  }
}
```

An R2 `get` whose body exceeds `maxInlineResultBytes` is then answered with the artifact's `root`
and `pieces` instead of an error (the provider is built after the cell's peer, so `this.peer` is
set), and `publishR2Object(content, store, key)` publishes an object
directly. Choose the piece size so the object fits in 64 pieces: the table travels inline, so a
4 MiB piece bounds an object at 256 MiB.

To check it against a real `workerd`, deploy with `npx wrangler dev` (it runs `workerd` with a
local R2), upload an object with `npx wrangler r2 object put models/checkpoint.bin --file ./ckpt.bin
--local`, and point a Java or Node member at the hub the cell joins. The Java test
`WorkersR2HolderTest` in `examples/example-29-content-swarm` runs the same store under Node over a
bucket that answers ranged gets as R2 does (`build/test/workers/r2-holder.js`): the cell joins a
Java hub on `ws`, publishes 3 MiB, and a Java member on `tcp` fetches every byte through the hub.
It skips without `npm run build` here unless `-Dtsclient.required=true`.

## Notes

- Build order: `npm run build` at the client root, then `packages/connect`, `packages/node`, then
  `npm run build && npm test` here. `npm run check:example` type-checks the example against
  `@cloudflare/workers-types`. The workerd test skips when `workerd` or `esbuild` is missing unless
  `AGENTSPACES_RUNTIMES_REQUIRED=1`.
- The Java test (`agentspaces-connect-core` `WorkerdCellConnectorTest`) spawns
  `build/test/workers/workerd-runner.js` and skips when the build or `workerd` is absent unless
  `-Dtsclient.required=true`; it adds `agentspaces-transport-http` as a test dependency of
  connect-core for the `ws` listener.
- `DataQueryClient` is pull-once: a result still inside its freshness window answers the identical
  query from the space; query another instance card, or wait the window, to force execution.
- A result over `maxInlineResultBytes` (R2 `get`, a large read) is answered with an error naming
  the limit, unless the provider is given `artifacts: { content, store }` with an `R2PieceStore`
  over the same bucket: the object is then hashed piece by piece through ranged gets, published as
  an artifact of the content swarm (`publishR2Object`), and the row carries its `root` and `pieces`;
  members fetch the pieces from the cell, which serves each by a ranged `get` (LB-C-05, SPEC
  v0.1.23 §8). The cell's own peer needs a `Content` over its `Pipes` and a `content` space.
- Every bound is an option: `tickMillis`, `idleMillis`, `reconnectMillis`, `snapshotMillis`,
  `introduceMillis`, `busyWindowMillis`, `listLimit`, `maxInlineResultBytes`, the `once` retention,
  the runtime's leases and `invocationRetention`. No fleet-size cap exists.
- `webSocketClose` is implemented for a socket a subclass hands to the hibernation API; the base
  class itself keeps its outbound socket as a live client socket.
