# Agents of their own (v0.1.13)

Written for: TypeScript and JavaScript developers who build with @agentspaces/client.

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
