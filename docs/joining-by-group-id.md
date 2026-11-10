# Joining by GroupID

Written for: TypeScript and JavaScript developers who build with @agentspaces/client.

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
