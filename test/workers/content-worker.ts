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
 * The TypeScript worker of the Java cross-language content-swarm test (agentspaces-content
 * TypeScriptContentClientTest; srad/large-networks-bulk-data.md §10): dials a Java relay over
 * tcp, joins by the founding, fetches the root the Java side published from every holder it can
 * see (the seed directly, the other Java member through the seed as a relay), publishes an
 * artifact of its own, waits until the Java members hold it in full, and prints one JSON line.
 *
 *     node build/test/workers/content-worker.js <host> <port> <founding> <root> [maxSeconds] [scheme]
 *
 * `scheme` is `tcp` (the default) or `ws`, the binding the worker dials its seed over.
 */

import { createHash } from "node:crypto";

import { Content, MemoryStore, Pipes } from "../../src/capabilities/index.js";
import { Identity, groupIdFromFounding } from "../../src/identity.js";
import { Peer } from "../../src/peer.js";
import { Space } from "../../src/space.js";
import "../../src/node/index.js";

const PIECE = 64 * 1024;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function replyArtifact(): Uint8Array {
  const out = new Uint8Array(3 * PIECE + 77);
  for (let i = 0; i < out.length; i++) {
    out[i] = (i * 13 + 5) & 0xff;
  }
  return out;
}

async function main(): Promise<number> {
  const [host, port, founding, root, maxSeconds, scheme] = process.argv.slice(2);
  const deadline = Date.now() + Number(maxSeconds ?? 90) * 1000;
  const peer = new Peer(Identity.generate(), groupIdFromFounding(founding!));
  await peer.connectAny([{ host: host!, port: Number(port), scheme: scheme ?? "tcp", ...(scheme === "ws" ? { path: "/aspace" } : {}) }]);
  const space = new Space(peer, "content");
  const content = new Content(new Pipes(peer), space, new MemoryStore(), { pieceSize: PIECE });
  content.run(100);
  await sleep(1000);
  peer.pullSpace("content");
  const fetch = content.fetch(root!);
  while (!fetch.done && Date.now() < deadline) {
    if (fetch.manifest === null) {
      peer.pullSpace("content");
    }
    await sleep(500);
  }
  if (!fetch.complete) {
    console.log(JSON.stringify({ ok: false, reason: "fetch did not complete", trace: fetch.trace.slice(-8),
      manifestKnown: fetch.manifest !== null, holdings: content.holdings(root!).length, seedPeer: peer.seedPeer,
      progress: fetch.progress() }));
    peer.close();
    return 2;
  }
  const data = fetch.readBytes();
  const progress = fetch.progress();
  const mine = content.publish(replyArtifact(), { name: "from-typescript.bin" });
  let javaHolders: string[] = [];
  while (Date.now() < deadline) {
    javaHolders = content.holdings(String(mine["root"]))
      .filter((h) => h["holder"] !== peer.identity.peerId && Boolean(h["complete"]))
      .map((h) => String(h["holder"])).sort();
    if (javaHolders.length >= 2) {
      break;
    }
    peer.pullSpace("content");
    await sleep(500);
  }
  await sleep(500);
  const report = { ok: javaHolders.length >= 2, peerId: peer.identity.peerId, seedPeer: peer.seedPeer, root, scheme: scheme ?? "tcp",
    bytes: data.length, sha256: createHash("sha256").update(data).digest("hex"), bySource: progress.bytesBySource,
    publishedRoot: mine["root"], javaHolders, relayedFrames: peer.relayedFrames, bytesServed: content.bytesServed,
    relaySignals: peer.relaySignals.length };
  console.log(JSON.stringify(report));
  content.stop();
  peer.close();
  return report.ok ? 0 : 4;
}

main().then((code) => process.exit(code), (e) => {
  console.log(JSON.stringify({ ok: false, reason: String(e instanceof Error ? e.stack ?? e.message : e) }));
  process.exit(1);
});
