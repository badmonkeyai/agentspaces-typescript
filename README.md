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
itself. Frames whose envelope `ver` is not 2 are dropped before any signature
work (SPEC section 9). `connect(host, port)` remains the path for
literal-founding groups whose id every member derives from shared
configuration.

## Run it

```
npm install
npm test                # tsc + golden vectors via node --test

# the trilingual demo (from the repo root):
clients/run-trilingual-demo.sh
```

The demo runs a Java coordinator publishing six tasks while a Python worker
and this TypeScript worker race for them under the claim lattice; the
coordinator prints each finding with the language-tagged worker that produced
it. Three runtimes, one space, no broker.

## Exact work selection and local snapshots

`takeEntry` accepts an optional final `exactEntryId` argument. Selection always
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
