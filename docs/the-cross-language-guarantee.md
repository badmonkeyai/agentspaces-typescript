# The cross-language guarantee

Written for: TypeScript and JavaScript developers who build with @agentspaces/client.

The tests prove this client byte-identical against the SAME
`agentspaces-spec/golden.json` (vendored here as `test/golden.json`) the Python client uses, generated from the
Java codec by `tools/golden/GoldenVectors.java`: every encoding, and every
signature (RFC 8032 signing is deterministic), matches exactly, including the
v0.1.10 vectors (the self-certifying founding document, the `GROUP_AD_WANT`
and `GROUP_AD` frames, the AgentCard and SpaceAdvertisement, the aggregate
and gossip-learn capability payloads), and every `*_cbor` vector is a fixed
point of `dumps(loads(x))`.

## Numbers on the wire

JavaScript has one number type and Java has several, and signatures cover the
bytes, so `src/cbor.ts` keeps the distinction explicit in both directions. Each
value has exactly one encoding (HLC round six, 2026-11-08), so every decoded
value re-encodes to the bytes it arrived in:

- **Doubles.** A plain `number` encodes as a CBOR integer; wrap it in
  `CborDouble` to emit a float64 (an auction bid, an aggregate share). A float32
  that Java wrote for a `float` decodes as a `CborFloat32` and goes back out as
  a float32. The only NaN on the wire is the one Java's constants hold.
- **Integers.** A Java `long` outside `Number.MAX_SAFE_INTEGER` decodes as a
  `bigint`. A `bigint` inside a Java `long` encodes as a plain integer, and one
  outside it as a bignum (tag 2 or 3), the form Java writes for a `BigInteger`.
  `wire.rosterToken(peerId)` returns the participant token of SPEC section 8 as
  a `bigint`.
- **Decimals.** A Java `BigDecimal` decodes as a `CborDecimal`, which holds
  its `exponent` and `mantissa` exactly. The class normalizes itself, so 1.50
  and 1.5 hold the same fields and encode to the same bytes, and its `value`
  gives the nearest double.
