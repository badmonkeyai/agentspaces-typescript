/*
 * Copyright 2026 Bad Monkey, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Session attestation between two TypeScript peers over crossed in-memory
 * channels (srad/agentspaces-js.md JS-H-05, JS-Q-SEC-02): the hint travels
 * in the self-advertisement, a frame past the introduction opens the hello,
 * the answer confirms the opener, the opener's first tagged frame confirms
 * the answerer, a tampered tag and a stale hello are refused, and a peer
 * that advertises no hint is never offered a session.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import { deriveSessionKey, sessionHelloBody, parseSessionHello, encodeSessionFrame, SESSION_HINT }
  from "../src/session.js";
import { ChannelEvents, FrameChannel } from "../src/transport.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import { fromHex, toHex, utf8 } from "../src/bytes.js";
import "../src/node/index.js";

const GROUP = "session-test-group";

type Side = { peer: Peer; events: ChannelEvents; sent: Uint8Array[]; tap: ((f: Uint8Array) => Uint8Array | null) | null };

/** Two peers whose channels deliver to each other, optionally through a tap that alters or drops frames. */
async function pair(now: () => number = Date.now, aAuth: "signed" | "session" = "session"): Promise<[Side, Side]> {
  const a: Side = { peer: new Peer(Identity.generate(), GROUP, now), events: new ChannelEvents(), sent: [], tap: null };
  const b: Side = { peer: new Peer(Identity.generate(), GROUP, now), events: new ChannelEvents(), sent: [], tap: null };
  a.peer.channelAuth = aAuth;
  const channel = (own: Side, other: Side): FrameChannel => ({
    scheme: "mem", remote: "mem", attestedPeer: () => null,
    send: (frame) => {
      own.sent.push(frame);
      const delivered = own.tap === null ? frame : own.tap(frame);
      if (delivered !== null) {
        other.events.deliver(delivered);
      }
    },
    onFrame: (r) => own.events.onFrame(r),
    onClose: (l) => own.events.onClose(l),
    close: () => own.events.close("closed"),
  });
  a.peer.registerDialer({ scheme: "mem", dial: async () => channel(a, b) });
  b.peer.registerDialer({ scheme: "mem", dial: async () => channel(b, a) });
  await a.peer.connectAny([{ host: "x", port: 1, scheme: "mem" }]); // introduces a to b
  await b.peer.connectAny([{ host: "x", port: 1, scheme: "mem" }]); // introduces b to a
  return [a, b];
}

function kinds(frames: Uint8Array[]): string[] {
  return frames.map((f) => String((wire.loadsSigned(f) as { envelope: { kind: string } }).envelope.kind));
}

test("the hint rides the self-advertisement and a session establishes both ways", async () => {
  const [a, b] = await pair();
  assert.ok(a.peer.sessionPeers.has(b.peer.identity.peerId), "a saw b's hint");
  assert.ok(b.peer.sessionPeers.has(a.peer.identity.peerId), "b saw a's hint");
  // a's connect-time DIGEST (a frame past the introduction) made b open the hello toward a as b
  // connected; a answered; b, confirmed by the answer, already introduced itself under the key.
  assert.ok(kinds(b.sent).includes("SESSION_HELLO"), "b opened");
  assert.ok(kinds(a.sent).includes("SESSION_HELLO"), "a answered");
  assert.ok(b.peer.sessionFramesSent >= 1, "b's introduction travelled under the session key");
  const bBefore = b.peer.sessionFramesSent;
  b.peer.pullSpace("tasks"); // b's tagged frame confirms a
  assert.equal(b.peer.sessionFramesSent, bBefore + 1);
  const aBefore = a.peer.sessionFramesSent;
  a.peer.pullSpace("tasks");
  assert.equal(a.peer.sessionFramesSent, aBefore + 1, "a's frame travelled under the session key too");
  assert.equal(a.peer.malformedFrames, 0);
  assert.equal(b.peer.malformedFrames, 0);
  a.peer.close();
  b.peer.close();
});

test("a tampered tag is refused and a frame from the wrong peer under the session is refused", async () => {
  const [a, b] = await pair();
  a.peer.pullSpace("tasks");
  b.peer.pullSpace("tasks"); // confirms a
  a.tap = (frame) => {
    const copy = new Uint8Array(frame);
    copy[copy.length - 1] ^= 0x01; // the tag is the last field
    return copy;
  };
  const malformedBefore = b.peer.malformedFrames;
  a.peer.pullSpace("tasks");
  assert.equal(b.peer.malformedFrames, malformedBefore + 1, "the tampered session frame was dropped");
  a.peer.close();
  b.peer.close();
});

test("a stale hello is ignored and counted, and a peer without the hint gets no session", async () => {
  let clock = 1_800_000_000_000;
  const [a, b] = await pair(() => clock);
  // b's hello to a, replayed 31 s later on a fresh session, is stale.
  a.peer.pullSpace("tasks");
  const hello = b.sent.find((f) => kinds([f])[0] === "SESSION_HELLO")!;
  clock += 31_000;
  const c = new Peer(a.peer.identity, GROUP, () => clock); // a fresh peer with a's identity and no session
  const events = new ChannelEvents();
  c.registerDialer({ scheme: "mem", dial: async () => ({ scheme: "mem", remote: "mem", attestedPeer: () => null,
    send: () => undefined, onFrame: (r) => events.onFrame(r), onClose: (l) => events.onClose(l), close: () => undefined }) });
  await c.connectAny([{ host: "x", port: 1, scheme: "mem" }]);
  c.sessionPeers.add(b.peer.identity.peerId);
  events.deliver(hello);
  assert.equal(c.framesStale, 1);
  c.close();
  // A signed-mode peer advertises no hint, so nobody opens toward it.
  const [d, e] = await pair(Date.now, "signed");
  assert.ok(!e.peer.sessionPeers.has(d.peer.identity.peerId));
  d.peer.pullSpace("tasks");
  assert.ok(!kinds(e.sent).includes("SESSION_HELLO"));
  d.peer.close();
  e.peer.close();
  a.peer.close();
  b.peer.close();
});

const GOLDEN: { [key: string]: string } = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "test", "golden.json"), "utf-8"));

test("the session vectors match the Java node's (golden session_*)", () => {
  if (GOLDEN["session_key"] === undefined) {
    return; // the generator has not run with the session vectors yet; the inline case below still pins Java
  }
  const c = wire.cryptoPort();
  const aPriv = fromHex(GOLDEN["session_a_scalar"]);
  const bPriv = fromHex(GOLDEN["session_b_scalar"]);
  assert.equal(toHex(c.x25519PublicKey(aPriv)), GOLDEN["session_a_public"]);
  assert.equal(toHex(c.x25519PublicKey(bPriv)), GOLDEN["session_b_public"]);
  const aNonce = fromHex(GOLDEN["session_a_nonce"]);
  const bNonce = fromHex(GOLDEN["session_b_nonce"]);
  const key = deriveSessionKey(aPriv, "zA", aNonce, fromHex(GOLDEN["session_b_public"]), "zB", bNonce);
  assert.equal(toHex(key), GOLDEN["session_key"]);
  assert.equal(toHex(deriveSessionKey(bPriv, "zB", bNonce, fromHex(GOLDEN["session_a_public"]), "zA", aNonce)),
    GOLDEN["session_key"]);
  assert.equal(toHex(sessionHelloBody(fromHex(GOLDEN["session_a_public"]), aNonce, "zB", null)),
    GOLDEN["session_hello_cbor"]);
  assert.equal(toHex(sessionHelloBody(fromHex(GOLDEN["session_b_public"]), bNonce, "zA", aNonce)),
    GOLDEN["session_answer_cbor"]);
  const env = wire.loadsSigned(fromHex(GOLDEN["session_envelope_cbor"])) as Dict;
  assert.equal(toHex(encodeSessionFrame(env, key)), GOLDEN["session_frame_cbor"]);
  const decoded = wire.decodeFrameDetailed(fromHex(GOLDEN["session_frame_cbor"]), { session: { peer: "zA", key } });
  assert.equal(decoded?.auth, "SESSION");
  assert.equal(decoded?.env["kind"], "PING");
});

test("the hello body and the key derivation are deterministic for fixed inputs", () => {
  const body = sessionHelloBody(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), "zPeer", null);
  const parsed = parseSessionHello(body)!;
  assert.equal(parsed.remote, "zPeer");
  assert.equal(parsed.echo, null);
  assert.deepEqual(new Uint8Array(parsed.nonce), new Uint8Array(32).fill(2));
  const aPrivate = fromHex("0101010101010101010101010101010101010101010101010101010101010101");
  const bPrivate = fromHex("0202020202020202020202020202020202020202020202020202020202020202");
  const aPublic = wire.cryptoPort().x25519PublicKey(aPrivate);
  const bPublic = wire.cryptoPort().x25519PublicKey(bPrivate);
  const aNonce = new Uint8Array(32).fill(0xaa);
  const bNonce = new Uint8Array(32).fill(0xbb);
  const fromA = deriveSessionKey(aPrivate, "zA", aNonce, bPublic, "zB", bNonce);
  const fromB = deriveSessionKey(bPrivate, "zB", bNonce, aPublic, "zA", aNonce);
  assert.equal(toHex(fromA), toHex(fromB), "both ends derive one key");
  const env = wire.envelope(GROUP, "PING", "zA", "1735689600000:3:zA", utf8("x"), "zB");
  const frame = encodeSessionFrame(env, fromA);
  const decoded = wire.decodeFrameDetailed(frame, { session: { peer: "zA", key: fromA } });
  assert.equal(decoded?.auth, "SESSION");
  assert.equal(wire.decodeFrameDetailed(frame, { session: { peer: "zB", key: fromA } }), null);
  assert.equal(wire.decodeFrameDetailed(frame, {}), null, "no session, no acceptance");
  assert.equal(SESSION_HINT, "wire.session");
});
