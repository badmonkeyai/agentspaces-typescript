# @agentspaces/client (TypeScript)

The TypeScript wire-compatible client: the same protocol the Java and Python
peers speak, from Node's standard library alone (net for TCP, crypto for
Ed25519 and SHA-256; the CBOR codec is in `src/cbor.ts`). A `Peer` joins a
Java fleet over TCP in the dial-only posture, answers SWIM pings, introduces
its self-advertisement once, writes signed entries, takes under the LEASE_RACE
claim lattice, and reads spaces back through anti-entropy. (A production client
would re-lease its self-advertisement on the advertisement TTL; the demo client
leans on ping liveness and does not.)

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
method receives a `Joined` (`key`, `get`, `find`, `all`, `has`). The
fleet-wide LEASED and ORDERED join modes, `@SpaceReduce`, and `@OrderedTake`
need the ticket and the ordered log and are not here. `Space.entries(template)`
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
the shared-fields correlation). A dial-only peer sends frames to the members
it can reach (the seed it dialed), never to a member it only heard of.
Not here: the ordered log (the Raft client), so ordered takes, reduces, and
the fleet-wide LEASED and ORDERED join modes; the gossip-learning exchange
(its payload is encoded and golden-pinned); and MAJORITY_GOSSIP.

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
