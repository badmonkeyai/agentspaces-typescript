# @agentspaces/yjs

The Yjs provider over an AgentSpaces fleet (`srad/agentspaces-js.md`
JS-S-02, JS-S-03). A document that syncs through y-websocket today syncs
over the fleet by changing one constructor argument: per document, the
y-protocols sync messages (step 1, step 2, update) and awareness updates
travel as signed `PIPE_DATA` frames of capability `aspace:cap/yjs`, with the
document's name as the room beside them, to the members a peer's capability
pipes reach. The provider runs at the `visitor` residency, needs no ordered
log, and carries the library's bytes untouched: AgentSpaces adds signing,
membership, and the link, and changes nothing in Yjs's document or sync
format.

```ts
import * as Y from "yjs";
import { Peer, Identity, capabilities } from "@agentspaces/client";
import { AgentSpacesProvider } from "@agentspaces/yjs";

const peer = new Peer(Identity.generate(), groupId);
await peer.connect("seed.example.com", 7500);
const pipes = new capabilities.Pipes(peer);

const doc = new Y.Doc();
const provider = new AgentSpacesProvider(pipes, "notes", doc);   // the pipes where a WebSocket URL went
provider.awareness.setLocalStateField("user", { name: "ada" });
provider.on("sync", (synced) => { /* a member's full state has arrived */ });
```

`provider.awareness` is a y-protocols `Awareness` the provider makes on the
document (pass `awareness` to share one); `destroy()` disconnects and
destroys the one it made. One peer serves any number of rooms; the first
provider on a `Pipes` takes the capability's handler and routes by room.

## What travels

- **The payload.** A two-field CBOR map `{room, message}` in the core's
  codec. `message` is what y-websocket writes on its socket: one varUint
  for the outer kind (`MESSAGE_SYNC` 0, `MESSAGE_AWARENESS` 1,
  `MESSAGE_QUERY_AWARENESS` 3, numbered as y-websocket numbers them) and then
  the y-protocols bytes, as `y-protocols/sync` and `y-protocols/awareness`
  wrote them. Nothing is added inside them; a plain `Y.Doc` applies the
  bytes with y-protocols alone (the suite does).
- **Members.** The provider sweeps `pipes.members()` on a period
  (`sweepMillis`, 250 ms; the first provider on a `Pipes` sets it) and on
  every frame it receives. A member it has not greeted gets step 1 and every
  awareness state this peer holds. A received step 1 is answered with step 2,
  with this peer's own step 1 when no step 2 of theirs has been heard
  (once per meeting: a greeting that found no provider on their side yet is
  made good this way, and two greetings that cross cost one empty step 2),
  and with the awareness states, as a y-websocket server answers a
  connection. `synced` turns true at the first step 2 received.
- **Relay.** Every member is a peer of every other. A received update is
  applied under an origin naming its sender and sent on to everyone else
  only if it changed the document, so a hub relays for the dial-only
  members behind it (a frame reaches only a member the peer has a link to)
  and a mesh's echoes die out. Awareness goes the same way, deduplicated by
  its clocks.
- **Departures.** A client's awareness state is attributed to the member
  whose news of it was the latest accepted (an echo of news already held is
  rejected by the clocks and attributes nothing). When a member leaves the
  reachable set, the clients attributed to it are retired and the retirement
  travels on, as a y-websocket server retires a connection's; `disconnect()`
  retires this client's own state first. A state a relay retired wrongly
  returns with its owner's next renewal (y-protocols renews every 15 s).

## Bounds

The fleet's frame cap is `wire.MAX_FRAME_BYTES` (8 MiB); a transport drops a
larger frame silently. The provider refuses rather than chunks: a payload
above `maxPayloadBytes` (default the cap less 64 KiB of envelope headroom;
the option never exceeds the cap) is refused with an error naming the room,
the kind, the size, and the bound. For this peer's own change the error is
thrown from the transaction; for an answer to a member's frame (a step 2
larger than a frame) it goes to `onRefused` when given and otherwise to the
`refused` event, never into the peer's frame handling. A step 2 above the
cap means the document has outgrown a frame; the application should know
rather than have it hidden. There is no cap on members, rooms, or rate.

## Requirements and the tests that prove them

All in `test/provider.test.ts`.

| Row | Requirement | Test |
|---|---|---|
| JS-S-02 | sync and awareness per document travel as `aspace:cap/yjs` frames; two docs converge; awareness propagates; one constructor argument changes | "two Y.Docs over two peers converge in both directions and awareness states propagate" |
| JS-S-02 | a late joiner syncs; a departure retires its awareness | "a late joiner syncs the document through the hub and sees the others' awareness" |
| JS-S-02 | the document name is the room; rooms stay apart | "two rooms on one peer stay apart, and a frame for a room nobody serves is dropped" |
| JS-S-03 | the y-protocols bytes are passed through byte for byte; a plain `Y.Doc` applies them | "the y-protocols bytes travel as y-websocket writes them, byte for byte, and a plain Y.Doc applies them" |
| JS-S-03 | the only bound is a per-message size, an option under the frame cap, refused by name | "an oversize message is refused by name, not chunked, and the bound is an option under the frame cap" |
| JS-S-03 | `visitor` residency, no ordered log, pipes alone | "the provider runs at the visitor residency over pipes alone: no ordered log, no host duty" |
| JS-S-03, JS-P-01 | the entry imports no Node module and names no Node global | "the package entry imports no Node module and names no Node global" |

Versions proven: `yjs` 13.6.33, `y-protocols` 1.0.7, `lib0` 0.2.119. The
provider uses only the y-protocols entry points, which serve Yjs 14 too;
the suite here runs against the installed major (13).

## Building

```sh
cd agentspaces-typescript && npm run build        # the core first
cd packages/yjs && npm run build && npm test
```
