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
 * The automerge-repo adapter over real peers (srad/agentspaces-js.md
 * JS-S-01, JS-S-03): two Repos on two peers linked through the in-memory
 * transport become each other's peer-candidate under their PeerIDs and
 * converge on a document; a third peer joining late catches up through the
 * hub's Repo; a departure fires peer-disconnected, by the goodbye and by the
 * lost link alike; the payload on the wire is the library's own encoding of
 * its message, byte for byte, and a message's sender is the frame's signer;
 * an oversize message is refused by name; the adapter runs at the visitor
 * residency with no ordered log and imports no Node module.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { Repo, cbor } from "@automerge/automerge-repo";
import type { DocHandle, Message, PeerId } from "@automerge/automerge-repo";
import { Identity, MemoryNetwork, Peer, capabilities, platform, settle, wire } from "@agentspaces/client";
import { AgentSpacesNetworkAdapter, DEFAULT_MAX_PAYLOAD_BYTES, TYPE } from "../src/index.js";

const { Pipes, ORDERED_LOG_TYPE } = capabilities;
const GROUP = "zAutomergeGroup";
type Doc = { text: string; count: number };

type Member = { peer: Peer; pipes: capabilities.Pipes; adapter: AgentSpacesNetworkAdapter; repo: Repo; close: () => Promise<void> };

/** A hub listening on `hub:1` with `n` dial-only members; every peer runs a Repo over the adapter. */
async function fleet(n: number): Promise<{ hub: Member; members: Member[]; net: MemoryNetwork; join: () => Promise<Member>; stop: () => Promise<void> }> {
  const net = new MemoryNetwork();
  const hubPeer = new Peer(Identity.generate(), GROUP);
  hubPeer.endpoints.push({ transport: "mem", address: "hub:1", priority: 0 });
  const closeListener = await net.listen("hub:1", (channel) => hubPeer.acceptChannel(channel));
  const hub = withRepo(hubPeer);
  const members: Member[] = [];
  const join = async (): Promise<Member> => {
    const peer = new Peer(Identity.generate(), GROUP);
    peer.registerDialer(net.dialer());
    await peer.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    const member = withRepo(peer);
    members.push(member);
    await settle();
    return member;
  };
  for (let i = 0; i < n; i++) {
    await join();
  }
  return { hub, members, net, join, stop: async () => {
    for (const m of [...members, hub]) {
      await m.close();
    }
    closeListener();
  } };
}

function withRepo(peer: Peer): Member {
  const pipes = new Pipes(peer);
  const adapter = new AgentSpacesNetworkAdapter(pipes, { sweepMillis: 20 });
  // The one constructor argument an application changes: the network. The peerId is the
  // fleet's so the Repo's own id and the id its peers know it under agree.
  const repo = new Repo({ network: [adapter], peerId: adapter.fleetPeerId });
  return { peer, pipes, adapter, repo, close: async () => { await repo.shutdown(); adapter.disconnect(); peer.close(); } };
}

async function until(condition: () => boolean, what: string, timeoutMillis = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMillis;
  while (!condition()) {
    if (Date.now() > deadline) {
      assert.fail(`timed out waiting for ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function peerIds(adapter: AgentSpacesNetworkAdapter): string[] {
  return adapter.peers().map(String).sort();
}

test("two Repos over two peers are each other's peer-candidate under their PeerIDs and converge (JS-S-01)", async () => {
  const { hub, members: [b], stop } = await fleet(1);
  try {
    await until(() => peerIds(hub.adapter).length === 1 && peerIds(b.adapter).length === 1, "the greetings");
    assert.deepEqual(peerIds(hub.adapter), [b.peer.identity.peerId]);
    assert.deepEqual(peerIds(b.adapter), [hub.peer.identity.peerId]);
    assert.ok(hub.adapter.isReady() && b.adapter.isReady());
    // B writes; A finds the document through the fleet and reads B's change.
    const handleB = b.repo.create<Doc>({ text: "hello", count: 1 });
    const handleA = await hub.repo.find<Doc>(handleB.url);
    await handleA.whenReady();
    assert.equal(handleA.doc()?.text, "hello");
    // A changes; B sees it: both directions, so both Repos hold the same heads.
    handleA.change((d) => { d.text = "hello from A"; d.count += 1; });
    await until(() => handleB.doc()?.text === "hello from A", "A's change at B");
    assert.equal(handleB.doc()?.count, 2);
    assert.deepEqual(handleA.heads(), handleB.heads());
    assert.ok(hub.adapter.received >= 1 && b.adapter.received >= 1, "sync messages travelled as frames");
    assert.equal(hub.adapter.dropped + b.adapter.dropped, 0);
  } finally {
    await stop();
  }
});

test("a third peer joining late catches up on the document (JS-S-01)", async () => {
  const { hub, members: [b], join, stop } = await fleet(1);
  try {
    await until(() => peerIds(b.adapter).length === 1, "B's greeting");
    const handleB = b.repo.create<Doc>({ text: "before C", count: 0 });
    for (let i = 0; i < 5; i++) {
      handleB.change((d) => { d.count += 1; });
    }
    const handleA = await hub.repo.find<Doc>(handleB.url);
    await until(() => handleA.doc()?.count === 5, "the hub caught up");
    // C arrives after the writes: dial-only behind the hub, it cannot reach B, so the hub's Repo relays.
    const c = await join();
    await until(() => peerIds(c.adapter).length === 1, "C's greeting");
    assert.deepEqual(peerIds(c.adapter), [hub.peer.identity.peerId]);
    assert.deepEqual(peerIds(hub.adapter), [b.peer.identity.peerId, c.peer.identity.peerId].sort());
    const handleC = await c.repo.find<Doc>(handleB.url);
    await handleC.whenReady();
    assert.equal(handleC.doc()?.text, "before C");
    assert.equal(handleC.doc()?.count, 5);
    // And C's later change reaches B through the hub.
    handleC.change((d) => { d.text = "from C"; });
    await until(() => handleB.doc()?.text === "from C", "C's change at B");
  } finally {
    await stop();
  }
});

test("a departure fires peer-disconnected: by the goodbye, and by a lost link alone (JS-S-01)", async () => {
  const { hub, members: [b, c], stop } = await fleet(2);
  try {
    await until(() => peerIds(hub.adapter).length === 2, "both greetings");
    const gone: string[] = [];
    hub.adapter.on("peer-disconnected", ({ peerId }) => gone.push(peerId));
    // B disconnects its adapter: the leave greeting is immediate.
    b.adapter.disconnect();
    await settle();
    assert.deepEqual(gone, [b.peer.identity.peerId]);
    assert.deepEqual(peerIds(hub.adapter), [c.peer.identity.peerId]);
    // C's peer closes without a word: the link ends, the member leaves the reachable set, the sweep notices.
    c.peer.close();
    await until(() => gone.length === 2, "the sweep after the lost link");
    assert.deepEqual(gone, [b.peer.identity.peerId, c.peer.identity.peerId]);
    assert.deepEqual(peerIds(hub.adapter), []);
  } finally {
    await stop();
  }
});

test("the payload is the library's own encoding of its message, byte for byte, and the signer is the sender (JS-S-03)", async () => {
  // Two adapters driven by the test in a Repo's place, so the message is the test's and nothing
  // else listens: a hub and one dial-only member.
  const net = new MemoryNetwork();
  const hubPeer = new Peer(Identity.generate(), GROUP);
  const closeListener = await net.listen("hub:1", (channel) => hubPeer.acceptChannel(channel));
  const member = new Peer(Identity.generate(), GROUP);
  member.registerDialer(net.dialer());
  await member.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
  const hub = new AgentSpacesNetworkAdapter(new Pipes(hubPeer), { sweepMillis: 20 });
  const b = new AgentSpacesNetworkAdapter(new Pipes(member), { sweepMillis: 20 });
  hub.connect(hub.fleetPeerId, { isEphemeral: true });
  b.connect(b.fleetPeerId);
  try {
    await until(() => peerIds(hub).length === 1 && peerIds(b).length === 1, "the greetings");
    // Tap what the hub's peer receives on the capability by wrapping the handler the adapter installed.
    const installed = hubPeer.pipeHandlers.get(TYPE)!;
    const seen: Uint8Array[] = [];
    hubPeer.pipeHandlers.set(TYPE, (from, payload) => { seen.push(payload.slice()); installed(from, payload); });
    const heard: Message[] = [];
    hub.on("message", (m) => heard.push(m));
    const data = new Uint8Array(4096);
    for (let i = 0; i < data.length; i++) {
      data[i] = (i * 7 + 3) & 0xff;
    }
    const message: Message = { type: "sync", senderId: b.fleetPeerId, targetId: hub.fleetPeerId,
      documentId: "3xampleDocumentId" as Message["documentId"], data };
    b.send(message);
    await until(() => heard.length === 1, "the message at the hub");
    assert.deepEqual(seen.at(-1), new Uint8Array(cbor.encode(message)), "the frame payload is cbor.encode(message), untouched");
    assert.deepEqual(cbor.decode<Message>(seen.at(-1)!).data, data, "the document bytes round-trip unchanged");
    assert.deepEqual(heard[0].data, data);
    assert.equal(heard[0].senderId, member.identity.peerId);
    assert.equal(heard[0].documentId, "3xampleDocumentId");
    // A message claiming another sender arrives under the PeerID that signed the frame.
    b.send({ ...message, senderId: "someone-else" as PeerId });
    await until(() => heard.length === 2, "the second message");
    assert.equal(heard[1].senderId, member.identity.peerId);
    assert.equal(cbor.decode<Message>(seen.at(-1)!).senderId, "someone-else", "the bytes themselves were not rewritten");
    assert.equal(hub.dropped, 0);
  } finally {
    b.disconnect();
    hub.disconnect();
    member.close();
    hubPeer.close();
    closeListener();
  }
});

test("an oversize message is refused by name, not chunked, and the bound is an option under the frame cap (JS-S-03)", async () => {
  const peer = new Peer(Identity.generate(), GROUP);
  const pipes = new Pipes(peer);
  const adapter = new AgentSpacesNetworkAdapter(pipes, { maxPayloadBytes: 1024 });
  adapter.connect(adapter.fleetPeerId);
  try {
    const big: Message = { type: "sync", senderId: adapter.fleetPeerId, targetId: "zOther" as PeerId,
      documentId: "3bigDoc" as Message["documentId"], data: new Uint8Array(2048) };
    assert.throws(() => adapter.send(big), /sync message for document 3bigDoc of \d+ bytes exceeds maxPayloadBytes 1024 .*8388608.*refused, not chunked/);
    assert.equal(adapter.maxPayloadBytes, 1024);
    const unbounded = new AgentSpacesNetworkAdapter(new Pipes(new Peer(Identity.generate(), GROUP)), { maxPayloadBytes: 2 ** 40 });
    assert.equal(unbounded.maxPayloadBytes, wire.MAX_FRAME_BYTES, "the option never exceeds the frame cap");
    assert.equal(DEFAULT_MAX_PAYLOAD_BYTES, wire.MAX_FRAME_BYTES - 64 * 1024);
    const refused: number[] = [];
    const observing = new AgentSpacesNetworkAdapter(new Pipes(new Peer(Identity.generate(), GROUP)),
      { maxPayloadBytes: 1024, onRefused: (_m, bytes) => refused.push(bytes) });
    observing.connect(observing.fleetPeerId);
    observing.send(big);
    assert.equal(refused.length, 1);
    observing.disconnect();
  } finally {
    adapter.disconnect();
    peer.close();
  }
});

test("the adapter runs at the visitor residency over pipes alone: no ordered log, no host duty (JS-S-03)", async () => {
  const { hub, members: [b], stop } = await fleet(1);
  try {
    assert.equal(platform().residency, "visitor", "the suite runs as the core's default visitor");
    await until(() => peerIds(b.adapter).length === 1, "the greeting");
    for (const m of [hub, b]) {
      assert.ok(!m.peer.pipeHandlers.has(ORDERED_LOG_TYPE), "no ordered log joined");
      assert.deepEqual([...m.peer.pipeHandlers.keys()], [TYPE], "the adapter's handler is the only capability");
    }
    const handle: DocHandle<Doc> = b.repo.create<Doc>({ text: "visitor", count: 0 });
    const atHub = await hub.repo.find<Doc>(handle.url);
    await atHub.whenReady();
    assert.equal(atHub.doc()?.text, "visitor");
  } finally {
    await stop();
  }
});

/** Every module the entry reaches through relative imports, with its source (as test/portable.test.ts of the core). */
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

test("the package entry imports no Node module and names no Node global (JS-S-03, JS-P-01)", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const graph = moduleGraph(join(here, "..", "src", "index.js"));
  assert.ok(graph.size >= 2, `the graph reaches the adapter (${graph.size} modules)`);
  for (const [file, source] of graph) {
    const name = file.substring(file.indexOf("build"));
    assert.doesNotMatch(source, /from\s+["']node:/, `${name} imports a node: module`);
    assert.doesNotMatch(source, /import\s+["']node:/, `${name} imports a node: module`);
    assert.doesNotMatch(source, /from\s+["']@agentspaces\/client\/node["']/, `${name} imports the node entry`);
    const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    assert.doesNotMatch(code, /\bBuffer\b/, `${name} names Buffer`);
    assert.doesNotMatch(code, /\bprocess\./, `${name} names process`);
    assert.doesNotMatch(code, /\brequire\(/, `${name} calls require`);
  }
});
