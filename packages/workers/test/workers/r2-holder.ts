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
 * A Workers cell's content holder under Node (srad/large-networks-bulk-data.md LB-Q-INT-04): the
 * cell's `R2PieceStore` over an in-memory bucket that answers ranged gets as R2 does, publishing
 * one object as an artifact into a group it joins through a hub, and serving its pieces by
 * ranged get to whoever fetches. The Java `WorkersR2HolderTest` spawns it; a real `workerd` with an
 * R2 binding runs the same store (packages/workers README, "Artifacts from R2").
 *
 *     node build/test/workers/r2-holder.js <scheme> <host> <port> <founding> <mebibytes>
 *
 * Prints `{"root": ..., "size": ..., "pieces": ...}` once published, then `{"ranged": n}` on `stop`.
 */

import { createInterface } from "node:readline";

import { Identity, Peer, Space, capabilities, groupIdFromFounding } from "@agentspaces/client";
import "@agentspaces/client/node";
import { R2PieceStore, publishR2Object } from "../../src/content.js";
import type { R2BucketLike, R2ObjectLike } from "../../src/workers-types.js";

const [scheme, host, port, founding, mebibytes] = process.argv.slice(2);
const size = Math.round(Number(mebibytes ?? "3") * 1024 * 1024);
/** The object both sides compute: byte i is (i * 31 + 7) mod 256. */
const OBJECT = new Uint8Array(size).map((_, i) => (i * 31 + 7) & 0xff);
let ranged = 0;

const object = (body: Uint8Array): R2ObjectLike & { arrayBuffer(): Promise<ArrayBuffer> } => ({
  key: "models/checkpoint.bin", size: OBJECT.length, etag: "etag-1", uploaded: new Date(0),
  httpMetadata: { contentType: "application/octet-stream" }, arrayBuffer: async () => body.slice().buffer,
});

const bucket: R2BucketLike = {
  head: async (key) => (key === "models/checkpoint.bin" ? object(new Uint8Array()) : null),
  list: async () => ({ objects: [object(new Uint8Array())], truncated: false }),
  get: async (key, options) => {
    if (key !== "models/checkpoint.bin") {
      return null;
    }
    const range = options?.range;
    if (range !== undefined) {
      ranged += 1;
      return object(OBJECT.subarray(range.offset, range.offset + range.length));
    }
    return object(OBJECT);
  },
};

async function main(): Promise<void> {
  const peer = new Peer(Identity.generate(), groupIdFromFounding(founding!));
  await peer.connectAny([{ host: host!, port: Number(port), scheme: scheme ?? "ws" }]);
  const store = new R2PieceStore(bucket);
  const content = new capabilities.Content(new capabilities.Pipes(peer), new Space(peer, "content"), store,
    { pieceSize: 256 * 1024 });
  content.run(100);
  await new Promise((r) => setTimeout(r, 1000));
  const manifest = await publishR2Object(content, store, "models/checkpoint.bin", { pieceSize: 256 * 1024 });
  console.log(JSON.stringify({ root: manifest["root"], size: manifest["size"], pieces: manifest["pieces"] }));
  const lines = createInterface({ input: process.stdin });
  lines.on("line", (line) => {
    if (line.trim() === "stop") {
      console.log(JSON.stringify({ ranged, bytesServed: content.bytesServed }));
      content.stop();
      peer.close();
      process.exit(0);
    }
  });
}

main().catch((e: unknown) => {
  console.log(JSON.stringify({ error: e instanceof Error ? e.stack ?? e.message : String(e) }));
  process.exit(1);
});
