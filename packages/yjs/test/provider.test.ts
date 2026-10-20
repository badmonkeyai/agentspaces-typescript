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
 * The Yjs provider over real peers (srad/agentspaces-js.md JS-S-02,
 * JS-S-03): two Y.Docs on two peers linked through the in-memory transport
 * converge in both directions and their awareness states propagate; a third
 * peer joining late syncs through the hub and sees the others' awareness; a
 * departed member's awareness is retired; two rooms on one peer stay apart;
 * the y-protocols bytes on the wire are what y-websocket would write, byte
 * for byte, and a plain Y.Doc applies them with no provider; an oversize
 * message is refused by name; the provider runs at the visitor residency
 * with no ordered log and imports no Node module.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import * as Y from "yjs";
import * as syncProtocol from "y-protocols/sync";
import * as encoding from "lib0/encoding";
import * as decoding from "lib0/decoding";
import { Identity, MemoryNetwork, Peer, capabilities, cbor, platform, settle, wire } from "@agentspaces/client";
import { AgentSpacesProvider, DEFAULT_MAX_PAYLOAD_BYTES, MESSAGE_SYNC, TYPE } from "../src/index.js";

const { Pipes, ORDERED_LOG_TYPE } = capabilities;
const GROUP = "zYjsGroup";
const ROOM = "notes";

type Member = { peer: Peer; pipes: capabilities.Pipes; doc: Y.Doc; provider: AgentSpacesProvider; close: () => void };

/** A hub listening on `hub:1` with `n` dial-only members; every peer runs a provider for ROOM. */
async function fleet(n: number): Promise<{ hub: Member; members: Member[]; join: () => Promise<Member>; stop: () => void }> {
  const net = new MemoryNetwork();
  const hubPeer = new Peer(Identity.generate(), GROUP);
  hubPeer.endpoints.push({ transport: "mem", address: "hub:1", priority: 0 });
  const closeListener = await net.listen("hub:1", (channel) => hubPeer.acceptChannel(channel));
  const hub = withProvider(hubPeer);
  const members: Member[] = [];
  const join = async (): Promise<Member> => {
    const peer = new Peer(Identity.generate(), GROUP);
    peer.registerDialer(net.dialer());
    await peer.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    const member = withProvider(peer);
    members.push(member);
    await settle();
    return member;
  };
  for (let i = 0; i < n; i++) {
    await join();
  }
  return { hub, members, join, stop: () => { [...members, hub].forEach((m) => m.close()); closeListener(); } };
}

function withProvider(peer: Peer, room = ROOM): Member {
  const pipes = new Pipes(peer);
  const doc = new Y.Doc();
  // The one constructor argument an application changes: the pipes in a WebSocket URL's place.
  const provider = new AgentSpacesProvider(pipes, room, doc, { sweepMillis: 20 });
  return { peer, pipes, doc, provider, close: () => { provider.destroy(); doc.destroy(); peer.close(); } };
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

const text = (m: Member): string => m.doc.getText("t").toString();
/** The names the awareness holds, this client's own included once it has one (a fresh client's local state is `{}`). */
const names = (m: Member): string[] => [...m.provider.awareness.getStates().values()]
  .filter((s) => typeof s["name"] === "string").map((s) => String(s["name"])).sort();

test("two Y.Docs over two peers converge in both directions and awareness states propagate (JS-S-02)", async () => {
  const { hub, members: [b], stop } = await fleet(1);
  try {
    await until(() => hub.provider.members().length === 1 && b.provider.members().length === 1, "the greetings");
    assert.deepEqual(hub.provider.members(), [b.peer.identity.peerId]);
    await until(() => hub.provider.synced && b.provider.synced, "step 2 both ways");
    b.doc.getText("t").insert(0, "hello");
    await until(() => text(hub) === "hello", "B's insert at the hub");
    hub.doc.getText("t").insert(5, " world");
    await until(() => text(b) === "hello world", "the hub's insert at B");
    assert.deepEqual(Y.encodeStateVector(hub.doc), Y.encodeStateVector(b.doc));
    hub.provider.awareness.setLocalStateField("name", "hub");
    b.provider.awareness.setLocalStateField("name", "b");
    await until(() => names(hub).length === 2 && names(b).length === 2, "awareness both ways");
    assert.deepEqual(names(hub), ["b", "hub"]);
    assert.deepEqual(names(b), ["b", "hub"]);
    assert.ok(hub.provider.received >= 2 && b.provider.received >= 2, "messages travelled as frames");
    assert.equal(hub.provider.dropped + b.provider.dropped, 0);
  } finally {
    stop();
  }
});

test("a late joiner syncs the document through the hub and sees the others' awareness (JS-S-02)", async () => {
  const { hub, members: [b], join, stop } = await fleet(1);
  try {
    await until(() => b.provider.synced, "B synced");
    b.doc.getText("t").insert(0, "before C");
    b.provider.awareness.setLocalStateField("name", "b");
    hub.provider.awareness.setLocalStateField("name", "hub");
    await until(() => text(hub) === "before C" && names(hub).length === 2, "the hub caught up");
    // C arrives after the writes: dial-only behind the hub, it cannot reach B, so the hub relays.
    const c = await join();
    await until(() => c.provider.synced, "C's step 2");
    assert.equal(text(c), "before C");
    await until(() => names(c).length === 2, "the others' awareness at C");
    assert.deepEqual(names(c), ["b", "hub"]);
    c.doc.getText("t").insert(0, "C: ");
    c.provider.awareness.setLocalStateField("name", "c");
    await until(() => text(b) === "C: before C" && names(b).length === 3, "C's change and state at B, through the hub");
    assert.deepEqual(names(b), ["b", "c", "hub"]);
    // A departure retires the member's awareness for the others, and the retirement travels on.
    c.close();
    await until(() => names(hub).length === 2 && names(b).length === 2, "C's state retired");
    assert.deepEqual(names(b), ["b", "hub"]);
    assert.deepEqual(hub.provider.members().sort(), [b.peer.identity.peerId]);
  } finally {
    stop();
  }
});

test("two rooms on one peer stay apart, and a frame for a room nobody serves is dropped (JS-S-02)", async () => {
  const { hub, members: [b], stop } = await fleet(1);
  const hubOther = new Y.Doc();
  const bOther = new Y.Doc();
  const hubProvider2 = new AgentSpacesProvider(hub.pipes, "other", hubOther);
  const bProvider2 = new AgentSpacesProvider(b.pipes, "other", bOther);
  try {
    await until(() => b.provider.synced && bProvider2.synced, "both rooms synced");
    b.doc.getText("t").insert(0, "notes");
    bOther.getText("t").insert(0, "other");
    await until(() => text(hub) === "notes" && hubOther.getText("t").toString() === "other", "both rooms at the hub");
    assert.equal(hub.doc.getText("t").toString(), "notes");
    assert.throws(() => new AgentSpacesProvider(hub.pipes, "other", new Y.Doc()), /room 'other' already has a provider/);
    const before = hub.provider.dropped;
    hub.pipes.send(b.peer.identity.peerId, TYPE, cbor.dumps({ room: "nobody", message: new Uint8Array([0]) }));
    await until(() => b.provider.dropped === before + 1, "the stray frame dropped");
  } finally {
    hubProvider2.destroy();
    bProvider2.destroy();
    hubOther.destroy();
    bOther.destroy();
    stop();
  }
});

test("the y-protocols bytes travel as y-websocket writes them, byte for byte, and a plain Y.Doc applies them (JS-S-03)", async () => {
  const net = new MemoryNetwork();
  const hubPeer = new Peer(Identity.generate(), GROUP);
  const closeListener = await net.listen("hub:1", (channel) => hubPeer.acceptChannel(channel));
  const member = new Peer(Identity.generate(), GROUP);
  member.registerDialer(net.dialer());
  await member.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
  // The hub runs no provider: a bare pipes handler records what lands, and a plain Y.Doc applies it with y-protocols alone.
  const seen: Array<{ from: string; room: string; message: Uint8Array }> = [];
  new Pipes(hubPeer).onCapability(TYPE, (from, payload) => {
    const frame = cbor.loads(payload) as { room: string; message: Uint8Array };
    seen.push({ from, room: frame.room, message: frame.message.slice() });
  });
  const doc = new Y.Doc();
  const emitted: Uint8Array[] = [];
  doc.on("update", (update: Uint8Array) => emitted.push(update.slice()));
  const provider = new AgentSpacesProvider(new Pipes(member), ROOM, doc, { sweepMillis: 20 });
  try {
    await until(() => seen.length >= 1, "step 1 at the hub");
    doc.getText("t").insert(0, "opaque");
    await until(() => seen.length >= 2, "the update at the hub");
    const update = seen.find((s) => s.message[1] === syncProtocol.messageYjsUpdate)!;
    assert.equal(update.from, member.identity.peerId);
    assert.equal(update.room, ROOM);
    const expected = encoding.createEncoder();
    encoding.writeVarUint(expected, MESSAGE_SYNC);
    syncProtocol.writeUpdate(expected, emitted[0]);
    assert.deepEqual(update.message, encoding.toUint8Array(expected), "the frame carries y-websocket's framing of Yjs's own update bytes");
    const step1 = seen.find((s) => s.message[1] === syncProtocol.messageYjsSyncStep1)!;
    assert.deepEqual(step1.message.subarray(0, 2), new Uint8Array([MESSAGE_SYNC, syncProtocol.messageYjsSyncStep1]));
    // A plain document, no provider: y-protocols reads the message as it would from a socket.
    const plain = new Y.Doc();
    const decoder = decoding.createDecoder(update.message);
    assert.equal(decoding.readVarUint(decoder), MESSAGE_SYNC);
    syncProtocol.readSyncMessage(decoder, encoding.createEncoder(), plain, "test");
    assert.equal(plain.getText("t").toString(), "opaque");
    plain.destroy();
  } finally {
    provider.destroy();
    doc.destroy();
    member.close();
    hubPeer.close();
    closeListener();
  }
});

test("an oversize message is refused by name, not chunked, and the bound is an option under the frame cap (JS-S-03)", async () => {
  const net = new MemoryNetwork();
  const hubPeer = new Peer(Identity.generate(), GROUP);
  const closeListener = await net.listen("hub:1", (channel) => hubPeer.acceptChannel(channel));
  const member = new Peer(Identity.generate(), GROUP);
  member.registerDialer(net.dialer());
  await member.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
  new Pipes(hubPeer); // the hub only needs to be reachable
  const doc = new Y.Doc();
  const provider = new AgentSpacesProvider(new Pipes(member), ROOM, doc, { sweepMillis: 20, maxPayloadBytes: 512 });
  try {
    await until(() => provider.members().length === 1, "the hub greeted");
    assert.throws(() => doc.getText("t").insert(0, "x".repeat(2048)),
      /sync message for room 'notes' of \d+ bytes exceeds maxPayloadBytes 512 .*8388608.*refused, not chunked/);
    assert.equal(provider.maxPayloadBytes, 512);
    const refused: Array<[string, string, number]> = [];
    const observing = new AgentSpacesProvider(new Pipes(member), "observed", new Y.Doc(),
      { maxPayloadBytes: 512, onRefused: (room, kind, bytes) => refused.push([room, kind, bytes]) });
    await until(() => observing.members().length === 1, "the hub greeted again");
    observing.doc.getText("t").insert(0, "y".repeat(2048));
    assert.equal(refused.length, 1);
    assert.deepEqual(refused[0].slice(0, 2), ["observed", "sync"]);
    observing.destroy();
    const unbounded = new AgentSpacesProvider(new Pipes(new Peer(Identity.generate(), GROUP)), ROOM, new Y.Doc(),
      { connect: false, maxPayloadBytes: 2 ** 40 });
    assert.equal(unbounded.maxPayloadBytes, wire.MAX_FRAME_BYTES, "the option never exceeds the frame cap");
    unbounded.destroy();
    assert.equal(DEFAULT_MAX_PAYLOAD_BYTES, wire.MAX_FRAME_BYTES - 64 * 1024);
  } finally {
    provider.destroy();
    doc.destroy();
    member.close();
    hubPeer.close();
    closeListener();
  }
});

test("the provider runs at the visitor residency over pipes alone: no ordered log, no host duty (JS-S-03)", async () => {
  const { hub, members: [b], stop } = await fleet(1);
  try {
    assert.equal(platform().residency, "visitor", "the suite runs as the core's default visitor");
    await until(() => b.provider.synced, "synced");
    for (const m of [hub, b]) {
      assert.ok(!m.peer.pipeHandlers.has(ORDERED_LOG_TYPE), "no ordered log joined");
      assert.deepEqual([...m.peer.pipeHandlers.keys()], [TYPE], "the provider's handler is the only capability");
    }
    b.doc.getText("t").insert(0, "visitor");
    await until(() => text(hub) === "visitor", "the write at the hub");
  } finally {
    stop();
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
  assert.ok(graph.size >= 2, `the graph reaches the provider (${graph.size} modules)`);
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
