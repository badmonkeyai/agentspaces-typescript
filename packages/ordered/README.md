# @agentspaces/ordered

The Raft voter of the AgentSpaces JavaScript client and the coordinator that installs what the
log commits: a portable port of the Java `RaftLog` and `OrderedTakes` that runs on any `Peer`
whose host carries the `voter` duty (a Node service host today; cells and resident browsers
later, see JS-F-19 and JS-F-22). Byte for byte the Java voter's frames, so a mixed fleet of Java
and Node voters elects, replicates, and commits as one log.

**Architecture position.** Layer 4, capabilities, in TypeScript. SPEC §8 (`aspace:cap/ordered-log`),
§7.4 (ORDERED takes). TECH-SPEC §10.2. Design of record: `srad/agentspaces-js.md` §4.6 (JS-V-06,
JS-V-07, JS-V-10, JS-V-11) and §4.5 (JS-R-06). The Raft *client* — submitting a claim through the
log from any residency — lives in the core (`capabilities.OrderedLog`); this package is the voter.

## Using it

```ts
import { Peer } from "@agentspaces/client";
import { OrderedLogHost } from "@agentspaces/ordered";
import { FileLogStore, ServiceHost } from "@agentspaces/node";

const host = new ServiceHost(identity, groupId, { listeners: [{ scheme: "tcp", bind: "0.0.0.0:7500" }], spaces: ["jobs"] });
const log = new OrderedLogHost(host.peer, "jobs", [javaVoterA, javaVoterB, identity.peerId],
  { store: new FileLogStore("./log/jobs"), residency: "service" });
await log.ready();
host.addDuty(log);   // ticked at the host's cadence, suspended while the tick drifts
await host.start();
```

The member list is fixed at construction and identical on every member, as in Java; `members`
must include this peer. A peer hosts at most one log per group (JS-V-10). Clients take through it
with `new capabilities.OrderedLog(new capabilities.Pipes(peer)).take(...)` or the binder's
`@orderedTake`; a binder on the voter host passes `committed: log.onCommitted.bind(log)` so its
ORDERED joins and reduces judge tickets in log order.

## Key files

| File | What it is |
| --- | --- |
| `src/raft.ts` | `RaftLog`: elections with randomized timeouts, replication, commit on majority, leader hints, the `RAFT_CLIENT` gate (a non-member's `clientSubmit` admitted within `CLIENT_SUBMITS_PER_SECOND` per sender), `suspend()`/`resume()` (JS-R-06), `parameters()` for the advertisement; `frame(kind, body)` encodes the `RaftMessages.Frame` union. |
| `src/store.ts` | `LogStore` (`load`, `saveTermVote`, `append(fromIndex, entries)`, `truncateFrom`) and `MemoryLogStore`; the voter writes term and vote before a `VoteReply` and entries before an `AppendReply`. |
| `src/host.ts` | `OrderedLogHost`: wires the voter to the peer's `aspace:cap/ordered-log` pipe, applies committed `ClaimCommand`s as `OrderedTakes.onCommand` does (holder key must be the claim holder's peer, claim bound to its entry, install only at `epoch == committed + 1`, then gossip the claim), publishes the `CapabilityAdvertisement` (`members`, `role`, `term`, `leaseUntil`), keeps the one-log-per-peer-per-group rule, and exposes `onCommitted`. |

## Requirements to tests

| Row | Test |
| --- | --- |
| JS-V-06 frames byte-identical to Java, membership fixed, durable before reply | `test/raft.test.ts` (golden `raft_*`; "a voter restarted from its store keeps its term and vote"; "a store write that fails sends no reply") |
| JS-V-07 claims through the log, completion at `epoch == committed + 1` | `test/host.test.ts` "three voters over real peers elect, advertise, and commit a dial-only client's take at epoch 1"; the binder's `@orderedTake` in the root `test/verbs-ordered.test.ts` |
| JS-V-10 one log per group | `test/host.test.ts` "a peer hosts at most one ordered log per group and a visitor may host none" |
| JS-V-11 cross-language desk, leader killed mid-take | `test/host.test.ts` "the leader's loss mid-fleet" (TypeScript only) and the Java `NodeVoterDeskTest` in `agentspaces-capabilities` (two Java voters, one Node voter, a TypeScript clerk) |
| JS-R-01 residency judged at construction | `test/host.test.ts` (a visitor is refused naming `@agentspaces/node`) |
| JS-R-06 a suspended voter counts as absent and rejoins | `test/host.test.ts` "a suspended voter counts as absent..." |
| JS-N-01 golden vectors | `test/raft.test.ts` "the Raft frames encode as the Java records do" |

No fleet-size caps: the client-submit rate is per sender and a property; nothing bounds members, logs, or clients.
