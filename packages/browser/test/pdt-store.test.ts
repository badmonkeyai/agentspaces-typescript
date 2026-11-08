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
 * The OPFS pack node backend in Node (srad/agentspaces-pdt.md PD-C-05): an in-memory stand-in for a
 * directory with synchronous access handles carries the pack, so the index rebuild, a torn tail,
 * removal, compaction, and a `PMap` over it are proven here without a browser.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { pdt } from "@agentspaces/client";

import { OpfsNodeBackend } from "../src/pdt-store.js";

class FakeFile {
  bytes = new Uint8Array();
  async createSyncAccessHandle() {
    const file = this;
    return {
      read(buffer: Uint8Array, options?: { at?: number }): number {
        const at = options?.at ?? 0;
        const n = Math.max(0, Math.min(buffer.length, file.bytes.length - at));
        buffer.set(file.bytes.subarray(at, at + n), 0);
        return n;
      },
      write(buffer: Uint8Array, options?: { at?: number }): number {
        const at = options?.at ?? 0;
        if (at + buffer.length > file.bytes.length) {
          const grown = new Uint8Array(at + buffer.length);
          grown.set(file.bytes, 0);
          file.bytes = grown;
        }
        file.bytes.set(buffer, at);
        return buffer.length;
      },
      truncate(size: number): void { file.bytes = file.bytes.subarray(0, size); },
      flush(): void {},
      close(): void {},
      getSize(): number { return file.bytes.length; },
    };
  }
}

class FakeDirectory {
  readonly dirs = new Map<string, FakeDirectory>();
  readonly files = new Map<string, FakeFile>();
  async getDirectoryHandle(name: string, options?: { create?: boolean }): Promise<FakeDirectory> {
    let dir = this.dirs.get(name);
    if (dir === undefined) {
      if (!options?.create) throw new Error("not found");
      dir = new FakeDirectory();
      this.dirs.set(name, dir);
    }
    return dir;
  }
  async getFileHandle(name: string, options?: { create?: boolean }): Promise<FakeFile> {
    let file = this.files.get(name);
    if (file === undefined) {
      if (!options?.create) throw new Error("not found");
      file = new FakeFile();
      this.files.set(name, file);
    }
    return file;
  }
  async removeEntry(name: string): Promise<void> { this.dirs.delete(name); this.files.delete(name); }
}

test("the pack backend stores, reopens from the pack, survives a torn tail, and compacts", async () => {
  const root = new FakeDirectory();
  const backend = await OpfsNodeBackend.open("pdt", root);
  const store = new pdt.NodeStore(backend);
  let map = pdt.PMap.empty<string, pdt.CborValue>(store);
  for (let i = 0; i < 500; i++) {
    map = map.assoc(`k${i}`, i);
  }
  const mapRoot = map.root();
  assert.ok(store.complete(mapRoot));
  assert.equal(store.put(new Uint8Array([1, 2, 3]), pdt.cids.RAW), store.put(new Uint8Array([1, 2, 3]), pdt.cids.RAW));
  backend.close();
  // reopened: the index comes from the pack alone
  const reopened = await OpfsNodeBackend.open("pdt", root);
  assert.equal(reopened.size(), backend.size());
  const again = new pdt.NodeStore(reopened);
  assert.ok(again.complete(mapRoot));
  assert.equal(pdt.PMap.load<string, pdt.CborValue>(again, mapRoot).get("k42"), 42);
  // a torn tail (a crash mid-write) is cut off and everything before it stands
  const file = (await (await root.getDirectoryHandle("pdt")).getFileHandle("nodes.pack"));
  const whole = file.bytes.length;
  file.bytes = new Uint8Array([...file.bytes, 0, 0, 1, 0, 0, 3, 0x62]);
  const torn = await OpfsNodeBackend.open("pdt", root);
  assert.equal(torn.size(), reopened.size());
  assert.equal(file.bytes.length, whole);
  // removal and compaction
  const removedCid = again.links(mapRoot)[0]!;
  assert.ok(torn.remove(removedCid));
  assert.ok(torn.deadBytes() > 0);
  assert.ok(!torn.has(removedCid));
  assert.equal(await torn.compact(false), false, "below half dead, no compaction");
  assert.equal(await torn.compact(true), true);
  assert.equal(torn.deadBytes(), 0);
  assert.ok(!new pdt.NodeStore(torn).complete(mapRoot));
  assert.ok(torn.get(mapRoot) !== undefined);
  const final = await OpfsNodeBackend.open("pdt", root);
  assert.equal(final.size(), torn.size());
  await OpfsNodeBackend.erase("pdt", root);
  assert.equal((await OpfsNodeBackend.open("pdt", root)).size(), 0);
});
