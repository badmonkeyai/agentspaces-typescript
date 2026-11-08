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
 * The TypeScript worker of the Java cross-language PDT test (srad/agentspaces-pdt.md PD-Q-INT-01,
 * PD-Q-INT-03, PD-C-05; the Python `tests/workers/pdt_worker.py` has the same shape): dials a Java
 * relay over tcp, joins by the founding, follows the map ref the Java side named, derefs it once it
 * holds the head's tree, swaps one key of its own (`ts.<peerId>` = "hello"), waits until a later Java
 * head carries the key `java.ack` (or the time runs out), and prints one JSON line.
 *
 *     node build/test/workers/pdt-worker.js <host> <port> <founding> <space> <name> [maxSeconds] [scheme] [contentKeyBase64]
 *
 * `scheme` is `tcp` (the default) or `ws`; `contentKeyBase64` gives the group's epoch-0 content key
 * for a group that seals (the worker then advertises `sealing = group-key` and opens sealed NODES).
 */

import { fromBase64 } from "../../src/bytes.js";
import { Content, MemoryStore, Pipes } from "../../src/capabilities/index.js";
import { Identity, groupIdFromFounding } from "../../src/identity.js";
import { Peer } from "../../src/peer.js";
import * as pdt from "../../src/pdt/index.js";
import { Space } from "../../src/space.js";
import "../../src/node/index.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function main(): Promise<number> {
  const [host, port, founding, spaceName, name, maxSeconds, scheme, keyBase64] = process.argv.slice(2);
  const deadline = Date.now() + Number(maxSeconds ?? 90) * 1000;
  const peer = new Peer(Identity.generate(), groupIdFromFounding(founding!));
  await peer.connectAny([{ host: host!, port: Number(port), scheme: scheme ?? "tcp", ...(scheme === "ws" ? { path: "/aspace" } : {}) }]);
  const content = new Content(new Pipes(peer), new Space(peer, "content"), new MemoryStore(), { pieceSize: 64 * 1024 });
  content.run(100);
  const keys = keyBase64 ? pdt.ContentKeys.of(fromBase64(keyBase64)) : null;
  const engine = new pdt.Pdt(peer, { content, keys });
  engine.run(100);
  await sleep(1000);
  peer.pullSpace("content");
  peer.pullSpace(spaceName!);
  peer.pullAds();
  const ref = engine.ref<pdt.PMap<string, pdt.CborValue>>(spaceName!, name!, "map");
  let value: pdt.PMap<string, pdt.CborValue> | null = null;
  while (Date.now() < deadline) {
    if (ref.heads().length > 0) {
      value = await ref.deref();
      break;
    }
    peer.pullSpace(spaceName!);
    peer.pullAds();
    await sleep(500);
  }
  if (value === null) {
    console.log(JSON.stringify({ ok: false, reason: "no loadable head", peerId: peer.identity.peerId, seedPeer: peer.seedPeer,
      stats: engine.stats(), ads: [...peer.ads.values()].map((a) => a.type) }));
    peer.close();
    return 2;
  }
  const readRoot = value.root();
  const readCount = value.count();
  const sample = Object.fromEntries(value.keys().slice(0, 5).map((k) => [k, value!.get(k)]));
  const mine = `ts.${peer.identity.peerId}`;
  const written = await ref.swap((m) => m.assoc(mine, "hello"));
  let acked = false;
  while (Date.now() < deadline) {
    const current = await ref.deref();
    if (current.has("java.ack") && current.get(mine) === "hello") {
      acked = true;
      break;
    }
    peer.pullSpace(spaceName!);
    await sleep(500);
  }
  const final = await ref.deref();
  const report = { ok: acked, peerId: peer.identity.peerId, seedPeer: peer.seedPeer, scheme: scheme ?? "tcp", readRoot, readCount,
    sample, writtenRoot: written.root(), finalRoot: final.root(), finalCount: final.count(), heads: ref.heads().length,
    history: ref.history(8).map((h) => h.root), stats: engine.stats() };
  console.log(JSON.stringify(report));
  engine.close();
  content.stop();
  peer.close();
  return report.ok ? 0 : 4;
}

main().then((code) => process.exit(code), (e) => {
  console.log(JSON.stringify({ ok: false, reason: String(e instanceof Error ? e.stack ?? e.message : e) }));
  process.exit(1);
});
