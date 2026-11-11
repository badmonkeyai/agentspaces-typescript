# Bootstrap and invite keys

Written for: TypeScript and JavaScript developers who build with @agentspaces/client.

A beacon serves a
signed JSON document (`/.well-known/agentspaces/beacon.json`) listing, per
group, its self-certifying founding advertisement and its seeds; `bootstrap`
fetches it, verifies the issuer's Ed25519 signature over the canonical bytes
(the pinned `beaconPeer` when given), refuses a signed document unless it
arrives as exactly its canonical JSON with its signature and key in padded
standard base64, verifies the founding with the same
four checks `joinByGroupId` applies, and dials the document's `tcp` seeds in
priority order. `https://` only unless `allowPlain`; at most 64 KiB.

```ts
const peer = new Peer(Identity.generate(), "aspace://z7f3a...");
await peer.bootstrap("https://agentspaces.corp.example/.well-known/agentspaces/beacon.json",
  { groupId: "aspace://z7f3a...", beaconPeer: "z6Mk...beaconPeerId" });
```

`bootstrap` keeps asking inside a budget, as the Java join by id does.
`timeoutMs` (3 000) bounds one fetch of the document and `joinTimeoutMs`
(10 000) bounds the whole call. A first attempt that succeeds fetches once and
dials once. Otherwise the call works in slices of 1 s, 2 s, 4 s, then 5 s
each: at the start of each slice it fetches the document again when the
beacon was unreachable or answered an error (`beacon.BeaconUnavailableError`)
or the document named no seed this peer dials, and it dials again, once per
slice, every seed that refused, so a beacon or a seed that starts a few
seconds after the peer (the usual case in Compose and Kubernetes) is reached
on a later slice. A refusal (a document or a founding that does not verify, a
founding for another id) rejects at once. When the budget runs out the call
rejects with `BootstrapTimeoutError` (`fetches`, `dialed`, `connected`, and
the last error as `cause`), and its message carries the same counts.

`connectAny(seeds)` is what `bootstrap` ends in and `connect(host, port)` is
now built on: the seeds are dialed in order (a hostname becomes one seed per
address it resolves to), and a lost socket fails over to the next seed
inside the reconnect window, one dial at a time with a pause after every
full round.

```ts
await peer.connectAny([{ host: "seed-a.corp.example", port: 7500 },
                       { host: "seed-b.corp.example", port: 7500 }]);
```

An invite key is the whole invitation for a group for friends: the compact
`aspace-inv1-<code>-<secret>[-<delegation>][@host]` for a text message, or
`https://<host>/j/<code>#<secret>[.<delegation>]` for a phone (the server
sees `/j/<code>` only). From the 128-bit secret, HKDF-SHA256 derives the
lookup code, the invite signing key, and the group's content key, bit for
bit as Java and Python do (`test/social-golden.json`). `joinInvite` fetches
the beacon document under the code, takes the founder's delegation from the
key or the document's `invite` field, signs this peer's `(candidate, group)`
with the invite key into a `d1:` credential under the `aspace:join` resource
hint of its self-advertisement, verifies the founding against the
delegation's group, and dials the seeds.

```ts
const { groupId, contentKey, pinnedKey } = await peer.joinInvite(
  "aspace-inv1-N9BAGDAC8ZW79GD8-000G40R40M30E209185GR38E1W");
// contentKey: Uint8Array(32), the group's content key (epoch 0); the beacon never sees it.
// pinnedKey: the key pinned to the delegation joined under; store it and join with it next time.
```

Store `pinnedKey` and pass it to `joinInvite` on the next start: the members
that admitted this peer re-admit it after the key's window only under the
same credential (SPEC §5.1, v0.1.20), and the beacon document may carry a
newer delegation by then.

`social.GroupSecret`, `social.InviteKey.parse`, `social.issueDelegated`,
`social.delegationHash` and `social.credentialHash` (what a `JOIN_CREDENTIAL`
revocation names) are exported for a founder written in TypeScript;
`beacon.signBeaconDocument` and `beacon.documentJson` serve a document.
