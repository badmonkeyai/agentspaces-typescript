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
 * The file-backed node store for Node (srad/agentspaces-pdt.md PD-S-01, PD-S-07, PD-C-05): one file per
 * CID under `path`, sharded by the first two characters after the multibase prefix, with the index of
 * held CIDs read from the directory at open. A restart reads every node back, so a ref's versions and
 * a holder's roots survive. Writes land through a temporary file and a rename; a crash leaves no half
 * node behind, and every node is verified against its CID before `NodeStore` hands it to the backend.
 *
 *     const store = new NodeStore(new FileNodeBackend("/var/lib/agentspaces/pdt"));
 */

import * as fs from "node:fs";
import * as nodePath from "node:path";

import type { NodeBackend } from "../pdt/store.js";

export class FileNodeBackend implements NodeBackend {
  readonly kind = "file";
  private readonly index = new Map<string, number>();

  constructor(readonly path: string) {
    fs.mkdirSync(path, { recursive: true });
    for (const shard of fs.readdirSync(path)) {
      const dir = nodePath.join(path, shard);
      if (shard.length !== 2 || !fs.statSync(dir).isDirectory()) {
        continue;
      }
      for (const name of fs.readdirSync(dir)) {
        if (name.endsWith(".node")) {
          const cid = name.slice(0, -".node".length);
          this.index.set(cid, fs.statSync(nodePath.join(dir, name)).size);
        }
      }
    }
  }

  private fileOf(cid: string): string {
    return nodePath.join(this.path, cid.slice(1, 3), `${cid}.node`);
  }

  get(cid: string): Uint8Array | undefined {
    if (!this.index.has(cid)) {
      return undefined;
    }
    try {
      return new Uint8Array(fs.readFileSync(this.fileOf(cid)));
    } catch {
      this.index.delete(cid);
      return undefined;
    }
  }

  has(cid: string): boolean {
    return this.index.has(cid);
  }

  put(cid: string, bytes: Uint8Array): boolean {
    if (this.index.has(cid)) {
      return false;
    }
    const file = this.fileOf(cid);
    fs.mkdirSync(nodePath.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, bytes);
    fs.renameSync(tmp, file);
    this.index.set(cid, bytes.length);
    return true;
  }

  remove(cid: string): boolean {
    if (!this.index.delete(cid)) {
      return false;
    }
    fs.rmSync(this.fileOf(cid), { force: true });
    return true;
  }

  cids(): Iterable<string> {
    return this.index.keys();
  }

  size(): number {
    return this.index.size;
  }

  /** Bytes held, from the index. */
  bytes(): number {
    let total = 0;
    for (const n of this.index.values()) {
      total += n;
    }
    return total;
  }

  flush(): void {}
}
