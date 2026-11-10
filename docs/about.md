# About @agentspaces/client

Written for: TypeScript and JavaScript developers who build with @agentspaces/client.

**A peer-to-peer coordination fabric for agents, services, and the people who work with them.**

AgentSpaces is a P2P framework to quickly discover and join P2P networks, where agents, software services, and people share assets, queries, results, and coordinate. The framework helps you build fleets of agents, tie in other software, and coordinate across them with a replicated tuple space, quorum building, and more. Agents post work, claim tasks, publish results, vote on decisions, and recover from each other's failures. There is no broker, no registry, no scheduler, and no server to keep alive. Coordination is peer-to-peer, secured end to end, and replicated across the fleet.

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
import "@agentspaces/client/node";                      // Node: registers the tcp and tls dialers
const peer = new Peer(Identity.generate(), groupId);
await peer.connect("seed.example.com", 7500);
```

## Changes from 0.2.0

0.2.0 is deprecated, and the client makes no API compatibility promise before
1.0. What changed in 0.4.0:

| 0.2.0 | 0.4.0 |
|---|---|
| TCP dialing built into `Peer` | `import "@agentspaces/client/node"` registers the `tcp` and `tls` dialers; `peer.registerDialer(d)` adds others; seeds carry a `scheme` (`tcp` when absent) |
| `Identity.loadOrCreate(dir)`, `Identity.agentKeys(...)`, `identity.savePkcs8(path)` | `loadOrCreateIdentity(dir)`, `agentKeys(...)`, `savePkcs8(identity, path)` from `@agentspaces/client/node` |
| `Buffer` in and out (`dumps`, frames, bodies, views) | plain `Uint8Array`; `bytes` helpers (`toHex`, `fromHex`, `toBase64`, `fromBase64`, `concat`, `equals`) |
| `node:crypto` Ed25519, SHA-256, HKDF | the installed `CryptoPort`: noble by default, `installCrypto(nodeCrypto)` on Node for OpenSSL |
| `Subscription` an `EventEmitter` | the same `on`, `once`, `off`, `emit` on the core's `Emitter` |
| `TakeContext` over `AsyncLocalStorage` | the same API; `AsyncLocalStorage` on Node (installed by the node entry), a synchronous scope elsewhere |
| `beacon.seedsOf(group, "tcp")` | also `beacon.seedsFor(group, schemes)`; joins take seeds of every scheme the peer dials |
| `engines.node >=20` | `>=22` |

What 0.5.0 adds for a read-only visitor peer, such as a console's:
`new Template(ANY_TYPE)` (`"*"`) reads and watches every type in a space, each `Entry` naming its wire `type`
(a take still names one type); and `cbor.loads` decodes the big-number tags Java's Jackson codec writes
(see "On a network").

The suites prove the core in Node, Deno, Bun, workerd, and headless Chromium,
Firefox, and WebKit (`test/runtimes.test.ts`, `test/browser.test.ts`, which
skip a runtime that is not installed unless `AGENTSPACES_RUNTIMES_REQUIRED=1`
or `AGENTSPACES_BROWSERS_REQUIRED=1`), and `npm run size` reports the
browser bundle against its budget.
