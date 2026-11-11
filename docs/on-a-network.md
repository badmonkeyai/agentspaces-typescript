# On a network

Written for: TypeScript and JavaScript developers who build with @agentspaces/client.

The client refuses every carrier that is not in the wire encoding, and stays
cautious in what it sends (ROBUSTNESS.md). SPEC section 9.1 defines the wire encoding, its annex I
tabulates the vectors, and `test/wire-encoding-vectors.json` holds their bytes.

- **Items.** `cbor.loads` accepts a document only in the one form its value
  encodes to: one item, at most 64 levels deep, shortest heads, definite byte
  strings and arrays, indefinite maps with unique text keys, a long text in
  Jackson's exact chunks, false, true and null as the only simple values, no
  half floats, and no tag except a bignum past a Java `long` of at most 1000 bytes or a
  normalized decimal. A decoded map remembers the order its keys arrived in and
  re-encodes in that order, and `cbor.canonicalMap` marks a map the encoder
  writes in the RFC 8949 key order, integer-like keys included. `cbor.dumps`
  writes a plain object or a JavaScript `Map` with text keys: a plain object
  lists its integer-like keys first, and a `Map` keeps its insertion order.
- **Records.** `src/records.ts` holds every protocol record this client reads,
  with Java's fields in declared order. `records.decodeRecord` conforms a
  carrier to its record and refuses it unless the conformed value re-encodes
  to exactly the bytes received. A field of the wrong kind is refused and
  never coerced: an epoch as a float, a decimal or text, a bid as an integer or
  text, a byte string where text belongs, an `Instant` or `Duration` that Java
  would print differently, or a kind outside its enum. The client also
  refuses each record Java's constructor refuses: an inline payload past
  64 KiB, a non-positive epoch, dot counter or lease expiry, and a
  certificate with a zero TTL or an encryption key of other than 32 bytes.
  A frame passes this check, and its body after it, before any signature
  counts. A frame that fails counts in `peer.malformedFrames`, a space delta
  in `peer.deltasUndecodable`, and an advertisement or revocation goes
  unheld.
  Every advertisement this client signs is conformed to its record first.
  The aggregate and semantic capabilities, `@agentspaces/ordered`, and
  `@agentspaces/webrtc`'s `signal.decode` read their pipe payloads the same
  way, so an unknown key or a wrong type refuses a payload.
- **Stamps.** A stamp holds at most 3996 UTF-16 units, so it always travels
  as one definite text, and `hlcNow` refuses a node past 3965 units.
- **Values.** A record's payload is an application document signed as bytes.
  The entry replicates whatever the payload holds, and every read skips a
  value that is no document in the wire encoding (`cbor.readDocument`).
- **Agent ids.** `Identity.agent` refuses a local name that is empty or holds
  a `/` or a `:`, and a record, claim, lease or certificate naming such an
  agent is undecodable.

Every verified frame then passes a `FrameFilter`, which judges the stamp in
SPEC section 9's order against this client's wall time. A stamp older than
five minutes is stale (`.stale`) and a repeated sender-and-stamp pair is a
replay (`.replayed`). A stamp past the HLC drift bound by at most
`wire.FAR_FUTURE_MARGIN_MILLIS` (5 s) counts in `.framesFarFutureSkewed`, one
further ahead in `.framesFarFuture`, and a counter above `wire.LOGICAL_LIMIT`
(65536) in `.framesLogicalRefused`, the names of Java's counters.

The replica checks a state or claim in Java's order: its signatures and
certificate, its actor's revocation, then its stamps.

- A revoked actor's state or claim counts in no stamp counter. The replica
  acknowledges it in its digest as an `a:e:` or `a:c:` line, keeping Java's
  8192 most recent acknowledgements.
- A counter above the limit in a record's `issued`, a state's `leaseStamp` or
  `signedAt`, or a claim's stamp counts in `peer.stampsLogicalRefused`, once
  per distinct offer.
- A record, lease stamp, agent-signed `signedAt` or gossiped claim stamped past
  the drift bound plus the margin waits, unmerged and unacknowledged, and
  counts in `peer.stampsFarFutureDeferred`. One more than
  `wire.FAR_FUTURE_HOSTILE_MILLIS` (one hour) further ahead counts in
  `peer.stampsFarFutureRefused`, and the replica acknowledges it when it is a
  state.
- Claims order by Java's rules: longs as longs, and bids by `Double.compare`,
  so a bid of -0.0 ranks ahead of a bid of 0.0.
- Collection drops a tombstone with its claim, its block, and its bulk payload
  (through the content seam's `unpin`), and a claim on an entry the replica
  collected or never held goes once it expires, so the claim map stays bounded.
- A PRef head orders by its `pdt.issued` and `pdt.issuer` attributes as Java's
  Refs does, and falls back to the entry's own stamp and issuer together
  otherwise, a `pdt.issued` past the drift bound plus the margin included.
  Every other attribute holds text, and a head with a null or non-text value
  there does not decode and counts once in `headsIgnored`, as a head that
  breaks a bound or names another kind or ref does (see the persistent data
  structures section).

The peer counts a kind of `Envelope.Kind` this client does not speak in
`peer.ignoredKinds`, and the reader goes on. A lost socket is a hiccup: the
peer re-dials the seeds one dial at a time, pausing after each round of refusals
for `reconnectIntervalMs` (5 s), then 10, 20 and 30 s with a random spread, until
`close()` (swarm retries, ROBUSTNESS.md §10.3 E5). A link that ends within
`reconnectIntervalMs` of its dial counts as a refused round, so a seed that accepts
each dial and drops it at once gets the same pauses (§10.6). The peer then introduces
itself again and pulls again what it had pulled (revocations, advertisements, spaces),
counting in `peer.reconnects`; `peer.connected()` says whether the link is up.
A host whose own durable timer owns every dial, as the workers cell's alarm does,
sets `peer.redial = false` and dials again with `connectAny`.
`close()` by the owner is final. `test/robustness.test.ts`,
`test/wire-encoding.test.ts` and `test/hlc-round-six.test.ts` pin these cases.
