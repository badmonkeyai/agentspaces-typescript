# @agentspaces/webrtc

The `webrtc` binding of the AgentSpaces JavaScript client: a direct, encrypted, authenticated link
between two members no one can dial — two browsers, or a browser and a JVM peer — over one WebRTC
data channel, with signalling carried over the fleet itself and attestation by the DTLS fingerprint
each side signs. It runs over the global `RTCPeerConnection` in a browser and over
[`node-datachannel`](https://www.npmjs.com/package/node-datachannel)'s polyfill on Node; when
neither exists, installation fails naming the package.

**Architecture position.** A binding over the portable core (`@agentspaces/client`), the TypeScript
twin of the Java `agentspaces-transport-webrtc`. SPEC §5.5, §5.6. Design of record:
`srad/agentspaces-js.md` §3.4, §3.5, §4.3, appendix B.

## Using it

```ts
import { Peer } from "@agentspaces/client";
import { WebRtcBinding } from "@agentspaces/webrtc";

const peer = new Peer(identity, groupId);
await peer.connectAny(seeds);                 // join a fleet with a RELAY-role seed
const webrtc = await WebRtcBinding.install(peer);   // throws naming the package if no RTCPeerConnection

const channel = await webrtc.connect(targetPeerId); // dial another member by signalling
channel.onFrame((frame) => { /* ... */ });
channel.send(bytes);
```

`install` registers the `aspace:cap/rtc-signal` pipe handler and a `webrtc` dialer, and returns the
binding; an inbound offer opens a channel handed to `peer.acceptChannel` (or your `onAccept`).
Signalling travels as signed `PIPE_DATA` of `aspace:cap/rtc-signal`, sent directly when the target
is reachable and inside a `RELAY_FRAME` through a RELAY-role member otherwise (`peer.sendPipeOrRelay`,
added to the core for this binding). ICE servers come from `WebRtcBinding.install(peer, { iceServers:
[...] })`; the default is empty, so only host and mDNS candidates gather.

On Node, add the optional peer dependency `node-datachannel`; in a browser nothing extra is needed.

## How it works

The same model as the Java binding, byte-compatible on the wire:

- **One connection, one channel** `aspace/1`, negotiated id 0, ordered, reliable. Frames travel as
  appendix-B one-byte-header chunks of at most `min(16 KiB, maxMessageSize) - 1` payload bytes; the
  receiver reassembles up to 8 MiB and closes on a larger frame or a malformed chunk (`chunk.ts`).
- **Signalling** `OFFER`, `ANSWER`, `CAND`, `END` bodies in canonical CBOR (`signal.ts`), encoded
  through the core codec so the bytes equal the Java `RtcSignal` record exactly; receivers ignore
  unknown keys.
- **Attestation** the SDP fingerprints go in the signed `fp` list; a remote SDP whose
  `a=fingerprint` lines differ is refused, and DTLS refuses a mismatching certificate, so an open
  channel's `attestedPeer()` is the PeerID that signed the offer or answer (`fingerprints.ts`).
- **Bounds** 6 offers per peer per minute, 64 candidates per session, 64 KiB per body, a 15 s dial
  (`END(2)` on timeout); backpressure pauses above 4 MiB buffered and resumes at the 1 MiB low
  event, failing a send after 30 s paused. None caps members, sessions, or connections.
- **Privacy** candidates and SDP travel only inside signals to their target and are never logged
  above DEBUG.
- **The relay offload (JS-W-11)** the core counts, per member, the frames a relay carried between
  the peer and it in a sliding minute (`peer.onRelayed`, `peer.relayedWithInLastMinute`; it only
  counts and tells, with no WebRTC code in the core). The binding subscribes on `install`: past
  `offloadFramesPerMinute` (30) for a member that advertises a `webrtc` endpoint, is not reachable,
  has no signalling in progress, and no failed dial inside `offloadRetryMillis` (5 minutes), it
  dials the member and hands the open channel to `peer.acceptChannel` as a link, so the next
  frames go direct and the relay carries none (JS-Q-PRF-03). A dial that cannot complete fails
  at the dial bound, leaves the relay path as it was, and starts the backoff (JS-Q-REL-08). Both
  are options of `install`, settings rather than caps; `counters.offloadAttempts`, `offloadOpened`,
  and `offloadFailed` count what it did.

## Key files

| File | What it is |
| --- | --- |
| `src/binding.ts` | `WebRtcBinding`: `install`, `connect`, the inbound-offer path, the `RTCPeerConnection`/`node-datachannel` resolution, the `FrameChannel` over the data channel with chunking and backpressure. |
| `src/chunk.ts` | The appendix-B chunk codec: `payloadCapacity`, `split` (validated before copying), `Reassembler` (bounded, resets on a violation). |
| `src/fingerprints.ts` | RFC 8122 fingerprint parsing and the SDP-against-`fp` match. |
| `src/signal.ts` | The signalling bodies, their canonical encoding, the bounds, and unknown-key tolerance. |
| `src/counters.ts` | `WebRtcCounters`: sessions, failures by reason, signals dropped, chunks and bytes, selected candidate type. |

## Requirement to test map (SRAD `srad/agentspaces-js.md`)

| Requirements | Tests |
| --- | --- |
| JS-W-05, JS-F-01 | `test/chunk.test.ts` (capacity; the `ceil(n/C)` split and its input validation; reassembly, its bounds, the FINAL-then-MORE reset, the overflow refusal; a randomized round trip) |
| JS-W-03, JS-F-02 | `test/signal.test.ts` (the canonical bodies, pinned byte-for-byte against the Java `RtcSignalTest`; unknown-key tolerance; the bounds) |
| JS-W-04 | `test/signal.test.ts` (fingerprints match exactly the signed list) |
| JS-W-02, JS-W-04, JS-W-05, JS-W-14 | `test/node-to-node.test.ts` (two bindings over `node-datachannel` open a channel, attest, and exchange a small and a 200 KB chunked frame; counters) |
| JS-W-11, JS-Q-PRF-03, JS-Q-REL-08 | `test/offload.test.ts` (past the threshold the binding dials over `node-datachannel`, adopts the channel, and counts; a member without a `webrtc` endpoint is left alone; a dial that cannot complete fails at the bound and is not retried before the backoff), `../../test/host-links.test.ts` (the core's count per pair, both directions, the sliding minute, the bounded memory) |
| JS-W-12 | `agentspaces-transport-webrtc/src/test/.../TwoBrowserWebRtcTest.java` (opt-in: two headless Chromium pages over a Java RELAY seed open a `webrtc` connection and exchange frames) |

## Not here

The Java engine's natives, DTLS policy, and the enterprise-CA path live in
`agentspaces-transport-webrtc`; WebRTC Direct (no signalling) and WebTransport are FUTURE rows
(JS-F-10, JS-F-11).
