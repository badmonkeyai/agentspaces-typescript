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
 * The portable core's guarantees (srad/agentspaces-js.md JS-P-01, JS-P-02,
 * JS-P-05, JS-Q-AVL-03): the main entry's module graph imports no Node module
 * and names no Node global; the noble and node:crypto ports agree byte for
 * byte; a peer refuses seeds it has no dialer for, naming the package.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { fromHex, toHex, utf8 } from "../src/bytes.js";
import { CryptoPort, installCrypto, nobleCrypto } from "../src/crypto.js";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import { MemoryKeyStore, mayHost, platform, requireResidency, residencyOf } from "../src/platform.js";
import { parseSeed, seedUrl } from "../src/seed.js";
import { ChannelEvents, FrameChannel, defaultDialers } from "../src/transport.js";
import * as wire from "../src/wire.js";
import { nodeCrypto } from "../src/node/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(here, "..", "src");

/** Every module the entry reaches through relative imports, with its source. */
function moduleGraph(entry: string): Map<string, string> {
  const seen = new Map<string, string>();
  const pending = [entry];
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (seen.has(file)) {
      continue;
    }
    const source = readFileSync(file, "utf-8");
    seen.set(file, source);
    for (const match of source.matchAll(/(?:import|export)[^'"]*?from\s+["']([^"']+)["']|import\s+["']([^"']+)["']/g)) {
      const spec = match[1] ?? match[2];
      if (spec.startsWith(".")) {
        pending.push(join(dirname(file), spec));
      }
    }
  }
  return seen;
}

test("the main entry imports no Node module and names no Node global (JS-P-01)", () => {
  const graph = moduleGraph(join(here, "..", "src", "index.js"));
  assert.ok(graph.size > 15, `the graph reaches the core (${graph.size} modules)`);
  for (const [file, source] of graph) {
    const name = file.substring(file.indexOf("build"));
    assert.ok(!file.includes(`${"/"}node${"/"}`), `${name}: the node adapters stay out of the main entry`);
    assert.doesNotMatch(source, /from\s+["']node:/, `${name} imports a node: module`);
    assert.doesNotMatch(source, /import\s+["']node:/, `${name} imports a node: module`);
    const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    assert.doesNotMatch(code, /\bBuffer\b/, `${name} names Buffer`);
    assert.doesNotMatch(code, /\bprocess\./, `${name} names process`);
    assert.doesNotMatch(code, /\brequire\(/, `${name} calls require`);
  }
  assert.ok(SRC.length > 0);
});

/** What both ports must produce for fixed inputs. */
function vectors(port: CryptoPort): string[] {
  const seed = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"); // RFC 8032 test 1
  const message = utf8("agentspaces");
  const pub = port.ed25519PublicKey(seed);
  const signature = port.ed25519Sign(seed, message);
  const x = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"); // RFC 7748 Alice
  const y = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"); // RFC 7748 Bob
  return [
    toHex(pub), toHex(signature), String(port.ed25519Verify(pub, message, signature)),
    String(port.ed25519Verify(pub, utf8("tampered"), signature)),
    toHex(port.sha256(message)), toHex(port.sha512(message)),
    toHex(port.hmacSha256(utf8("key"), message)),
    toHex(port.hkdfSha256(utf8("ikm"), utf8("salt"), utf8("info"), 42)),
    toHex(port.x25519PublicKey(x)), toHex(port.x25519(x, port.x25519PublicKey(y))),
  ];
}

test("the noble and node:crypto ports agree byte for byte (JS-P-02)", () => {
  const noble = vectors(nobleCrypto);
  assert.deepEqual(vectors(nodeCrypto), noble);
  // RFC 8032 test 1 and RFC 7748 §6.1 pin the ports to the standards, not only to each other.
  assert.equal(noble[0], "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  assert.equal(noble[9], "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
  assert.equal(noble[2], "true");
  assert.equal(noble[3], "false");
});

test("a frame signed under one port verifies under the other", () => {
  const previous = installCrypto(nodeCrypto);
  try {
    const signer = Identity.generate();
    const frame = wire.encodeFrame(wire.envelope("g", "PING", signer.peerId, "1:0:x", wire.pingBody(1), null), signer);
    installCrypto(nobleCrypto);
    assert.ok(wire.decodeFrame(frame) !== null);
  } finally {
    installCrypto(previous);
  }
});

test("seeds parse with a scheme and a path (FR-2)", () => {
  assert.deepEqual(parseSeed("wss://fleet.example.com:443/aspace"),
    { host: "fleet.example.com", port: 443, scheme: "wss", path: "/aspace" });
  assert.deepEqual(parseSeed("[::1]:7503/aspace", 7500, "ws"), { host: "::1", port: 7503, scheme: "ws", path: "/aspace" });
  assert.deepEqual(parseSeed("10.0.0.5"), { host: "10.0.0.5", port: 7500 });
  assert.equal(seedUrl({ host: "::1", port: 9, scheme: "ws", path: "/x" }), "ws://[::1]:9/x");
  assert.throws(() => parseSeed("host:99999"));
});

test("a peer with no dialer for a seed's scheme refuses, naming the package (JS-Q-AVL-03)", async () => {
  const peer = new Peer(Identity.generate(), "g");
  assert.ok(peer.dialableSchemes().includes("tcp"), "the node entry registered tcp");
  await assert.rejects(peer.connectAny([{ host: "h", port: 1, scheme: "webrtc" }]),
    /no dialer for the seeds' schemes \(webrtc\).*@agentspaces\/webrtc/);
});

test("a peer dials the seed's scheme through its dialer and frames flow both ways (JS-P-05)", async () => {
  const sent: Uint8Array[] = [];
  let channel: (FrameChannel & { events: ChannelEvents }) | null = null;
  const peer = new Peer(Identity.generate(), "g");
  peer.registerDialer({
    scheme: "mem",
    async dial(seed) {
      const events = new ChannelEvents();
      channel = {
        scheme: "mem", remote: seedUrl(seed), events,
        attestedPeer: () => null,
        send: (frame) => { sent.push(frame); },
        onFrame: (r) => events.onFrame(r),
        onClose: (l) => events.onClose(l),
        close: () => events.close("closed"),
      };
      return channel;
    },
  });
  await peer.connectAny([{ host: "x", port: 1, scheme: "mem" }]);
  assert.ok(peer.connected());
  assert.ok(sent.length >= 1, "the introduction went out on the channel");
  assert.ok(wire.decodeFrame(sent[0]) !== null, "whole frames, no length prefix");
  const other = Identity.generate();
  const ping = wire.encodeFrame(wire.envelope("g", "PING", other.peerId,
    wire.hlcNow(other.peerId), wire.pingBody(3), peer.identity.peerId), other);
  const before = sent.length;
  channel!.events.deliver(ping);
  assert.equal(wire.decodeFrame(sent[before])?.["kind"], "ACK", "the ping is answered on the same channel");
  channel!.events.close("gone");
  assert.equal(peer.connected(), false);
  peer.close();
});

test("residency gates duties and an unknown class ranks as a visitor (JS-R-01, JS-F-03)", () => {
  assert.equal(residencyOf("cell"), "cell");
  assert.equal(residencyOf("service-worker"), "visitor");
  assert.ok(mayHost("service", "voter"));
  assert.ok(!mayHost("cell", "voter"));
  assert.ok(mayHost("cell", "connector"));
  assert.ok(mayHost("resident", "keeper"));
  assert.throws(() => requireResidency("visitor", "voter", "voter for ordered log 'payments'"),
    /voter for ordered log 'payments' needs residency service; this host is visitor; run it in @agentspaces\/node/);
  const p = platform();
  assert.equal(p.residency, "visitor");
  assert.equal(p.crypto.name, "noble");
  assert.ok(defaultDialers().some((d) => d.scheme === "tcp"));
});

test("the memory key store round-trips copies", async () => {
  const store = new MemoryKeyStore();
  const value = new Uint8Array([1, 2, 3]);
  await store.save("peer.key", value);
  value[0] = 9;
  assert.deepEqual(await store.load("peer.key"), new Uint8Array([1, 2, 3]));
  await store.remove("peer.key");
  assert.equal(await store.load("peer.key"), null);
});
