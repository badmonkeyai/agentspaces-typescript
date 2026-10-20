# @agentspaces/automerge

The automerge-repo `NetworkAdapter` over an AgentSpaces fleet
(`srad/agentspaces-js.md` JS-S-01, JS-S-03). A `Repo` that syncs over a
WebSocket server today syncs over the fleet by changing one constructor
argument: the members a peer's capability pipes reach become the Repo's
peers, under their AgentSpaces PeerID, and the Repo's messages travel as
signed `PIPE_DATA` frames of capability `aspace:cap/automerge`. The adapter
runs at the `visitor` residency, needs no ordered log, and carries the
library's bytes untouched: AgentSpaces adds signing, membership, and the
link, and changes nothing in Automerge's document or sync format.

```ts
import { Repo } from "@automerge/automerge-repo";
import { Peer, Identity, capabilities } from "@agentspaces/client";
import { AgentSpacesNetworkAdapter } from "@agentspaces/automerge";

const peer = new Peer(Identity.generate(), groupId);
await peer.connect("seed.example.com", 7500);
const pipes = new capabilities.Pipes(peer);

const repo = new Repo({ network: [new AgentSpacesNetworkAdapter(pipes)] });   // the one changed argument
```

Pass `peerId: adapter.fleetPeerId` as well when the Repo's own id should
read as the PeerID its peers know it under; without it the Repo picks a
random id for itself, and its peers still see the PeerID, since a message's
`senderId` is set from the frame's signer on receipt.

## What travels

- **Peers.** The adapter sweeps `pipes.members()` (the members a frame can
  reach: those that signed a frame on this peer's connection) on a period of
  its own (`sweepMillis`, 250 ms) and on every frame it receives. A member
  it has not greeted gets an `arrive`; one that answers with `welcome`, or
  arrives itself, is a `peer-candidate` with its PeerID as `peerId` and the
  metadata it announced (`storageId`, `isEphemeral`). A member that leaves
  the reachable set (its link ended, its advertisement lapsed and a host
  called `peer.expireMembers()`), or that sends `leave` on `disconnect()`,
  is `peer-disconnected`. The greeting is the shape of the library's own
  BroadcastChannel adapter; a member running no adapter never answers and
  never becomes a peer.
- **Messages.** `send(message)` encodes the Repo's `Message` with the
  library's `cbor.encode` (cbor-x, `tagUint8Array: false, useRecords:
  false`): the same bytes `@automerge/automerge-repo-network-websocket` puts
  on a socket, and the whole payload of one frame addressed to
  `message.targetId`. On receipt the bytes decode back and `senderId` is set
  to the PeerID that signed the frame, whatever the bytes claim: the
  signature is the identity. Nothing else is added, read, or rewritten.
- **Topology.** A frame reaches only a member the peer has a link to; a seed
  does not relay a frame to a dial-only member behind it. Two dial-only
  members behind one hub are therefore not each other's peers; the hub's own
  Repo is what relays, by syncing with both, as a sync server does. A mesh
  of listening peers is a mesh of Repo peers.

## Bounds

The fleet's frame cap is `wire.MAX_FRAME_BYTES` (8 MiB); a transport drops a
larger frame silently. The adapter refuses rather than chunks: a message
whose encoding exceeds `maxPayloadBytes` (default the cap less 64 KiB of
envelope headroom; the option never exceeds the cap) is refused with an error
naming the message type, the document, the size, and the bound, thrown from
`send` or passed to `onRefused` when given. Automerge's sync messages are
already incremental; one above the cap is a bulk catch-up of a document that
has outgrown a frame, which the application should know about rather than
have hidden. There is no cap on peers, documents, or rate.

## Requirements and the tests that prove them

All in `test/adapter.test.ts`.

| Row | Requirement | Test |
|---|---|---|
| JS-S-01 | members become `peer-candidate` under their PeerID; sync messages travel as `aspace:cap/automerge` frames; one constructor argument changes | "two Repos over two peers are each other's peer-candidate under their PeerIDs and converge" |
| JS-S-01 | a late joiner catches up | "a third peer joining late catches up on the document" |
| JS-S-01 | departures are `peer-disconnected` | "a departure fires peer-disconnected: by the goodbye, and by a lost link alone" |
| JS-S-03 | the payload is the library's own encoding, byte for byte; the signer is the sender | "the payload is the library's own encoding of its message, byte for byte, and the signer is the sender" |
| JS-S-03 | the only bound is a per-message size, an option under the frame cap, refused by name | "an oversize message is refused by name, not chunked, and the bound is an option under the frame cap" |
| JS-S-03 | `visitor` residency, no ordered log, pipes alone | "the adapter runs at the visitor residency over pipes alone: no ordered log, no host duty" |
| JS-S-03, JS-P-01 | the entry imports no Node module and names no Node global | "the package entry imports no Node module and names no Node global" |

Versions proven: `@automerge/automerge-repo` 2.6.0-alpha.3, `@automerge/automerge` 3.5.0.

## Building

```sh
cd agentspaces-typescript && npm run build        # the core first
cd packages/automerge && npm run build && npm test
```
