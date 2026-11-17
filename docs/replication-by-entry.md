# Replication by entry (v0.1.35)

Written for: TypeScript and JavaScript developers who build with @agentspaces/client.

From 0.7.0 a member repairs a space by entry instead of by its whole text digest. The client implements SPEC annex
I.6 (`wire.ae=2`), the per-entry horizon of SPEC §7.3 (`wire.horizon=1`), and the renewal rule of SPEC §7.2. Nothing
changes in how you write, read, take or watch.

## What a round does now

- Every member advertises `wire.hashes=1`, `wire.ae=2` and `wire.horizon=1` in its card.
- A round toward a member opens in the form that member's current card names:
  - `wire.ae=2`: the audit. The space's fingerprinted trie is compared by its stream hash, the nodes that differ are
    walked down, and only the entries that differ are fetched by id.
  - `wire.hashes=1` alone: the hashed round of v0.1.17. A hash per stream goes first, and the full text follows only
    for the streams that differ.
  - Neither hint: the full text digest, as before.
- Every answer stays within a budget (1 MiB by default). A late joiner therefore pulls a large space in bounded
  answers, and the audit carries on from where the first answer stopped.
- `peer.replicationStatus()` reports the forms in view, the audit's counters, the pacing figures and each space's
  horizon mode.

## The settings

A host reads four options, and so does `peer.configureReplication(...)`. They match Java's keys
(`agentspaces.gossip.audit`, `audit-budget`, `audit-sessions` and `agentspaces.space.horizon`):

| Option | Default | What it does |
|---|---|---|
| `audit` | `true` | Advertise `wire.hashes=1` and `wire.ae=2`, and audit toward members that carry them. `false` makes the member a 0.6.0 member. |
| `auditBudget` | 1 MiB | The bytes this member asks an answer to stay within, from 4 KiB to 4 MiB. |
| `auditSessions` | 4 | The audit sessions this member keeps open per asker, from 1 to 4. |
| `horizon` | `"per-entry"` | Advertise `wire.horizon=1`. `"legacy"` keeps two maximum leases for every withdrawal. Anything else is refused. |

Where each host reads them:

- `@agentspaces/node`: the `ServiceHost` options, or the fleet file's `gossip.audit`, `gossip.audit-budget`,
  `gossip.audit-sessions` and `space.horizon` keys, as Java's fleet file names them.
- `@agentspaces/browser`: the `connect(...)` options, passed to the host with the page's hello.
- `@agentspaces/workers`: the `CellConfig` overrides, or the `vars` `AGENTSPACES_AUDIT`, `AGENTSPACES_AUDIT_BUDGET`,
  `AGENTSPACES_AUDIT_SESSIONS` and `AGENTSPACES_HORIZON`.
- The other packages (`yjs`, `automerge`, `connect`, `webrtc`, `ordered`) run over a `Peer` you build, so they take
  the settings of the host or `Peer` they are given.

A misspelt value is refused, so it never passes for the default. Advertise a changed setting with `peer.introduce()`.

## Renewal never shortens

- `renewEntry`, `Taken.renew` and `Subscription.renew` extend a lease to at least the extension from now, and never
  shorten it: `expiry = max(current, now + extension)`.
- Only the issuer renews a write, and only while the entry is present and its lease has not lapsed. Any other renewal
  throws and sends nothing.
- `Taken.renew` renews the take lease, as Java's `TakenEntry.renew` does.
- To give a taken entry back, call `Taken.release()` and let its take lease lapse.
- To end a write sooner, cancel it. To shorten a write's lease, cancel it and write it again.

## The horizon

- A withdrawn entry is collected ten minutes after its own lease expiry once every member in view has advertised
  `wire.horizon=1` for three rounds, and one maximum lease plus five minutes have passed since then.
- A member without the hint in view returns every withdrawal to two maximum leases at once.
- A withdrawal is never collected before ten minutes past its expiry, under either rule.
- A completed entry keeps two maximum leases. A lapsed entry keeps at most five minutes.

## Bounds against a hostile member

An adversarial review (2026-11-15) fixed five places where one member could make another do unbounded or needless
work. `test/adversary-replication.test.ts` shows each one.

- An audit descent asks at most 64 bodies per opening. A body whose every answer is refused asks nothing, and each
  opening admits one root answer per stream, owed to the last two openings at most.
- An asker compares a partner's lines one slot at a time, so the cost follows the answer, not its own set.
- A partner knows the bytes of the lines under every node, so it never walks lines it could not send.
- A `PULL_RESP` remainder continues only a budgeted pull this member sent to that partner. Any other is counted under
  `pacing.remainderUnsolicited` and draws nothing.
- A space's text digest is kept until the space changes, so a probe whose hash differs costs no rebuild.

None of these changes a byte on the wire: the answers, the fetched ids and the audit transcripts are the ones before.
