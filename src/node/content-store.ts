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
 * The file-backed piece store for Node (srad/large-networks-bulk-data.md LB-T-01, LB-C-02): one
 * directory per root under `path` holding `data` (pieces at their offsets), `have` (the verified
 * bitfield, persisted every eight pieces and on `flush`), and `manifest.cbor`. A restart reads
 * every root back, so a fetch resumes and a holder republishes.
 */

import * as fs from "node:fs";
import * as nodePath from "node:path";

import { dumps, loads } from "../cbor.js";
import { decodeHave, encodeHave, pieceLength } from "../capabilities/content.js";
import type { PieceStore } from "../capabilities/content.js";
import type { Dict } from "../wire.js";

interface Held { manifest: Dict; dir: string; have: Set<number>; persisted: number }

export class FileStore implements PieceStore {
  static readonly PERSIST_EVERY = 8;
  readonly kind = "file";
  private readonly held = new Map<string, Held>();

  constructor(readonly path: string) {
    fs.mkdirSync(path, { recursive: true });
    for (const name of fs.readdirSync(path)) {
      const dir = nodePath.join(path, name);
      const manifestFile = nodePath.join(dir, "manifest.cbor");
      if (!fs.existsSync(manifestFile) || !fs.statSync(manifestFile).isFile()) {
        continue;
      }
      const manifest = loads(new Uint8Array(fs.readFileSync(manifestFile))) as Dict;
      const haveFile = nodePath.join(dir, "have");
      const have = fs.existsSync(haveFile)
        ? decodeHave(new Uint8Array(fs.readFileSync(haveFile)), Number(manifest["pieces"])) : new Set<number>();
      this.held.set(String(manifest["root"]), { manifest, dir, have, persisted: have.size });
    }
  }

  roots(): Set<string> {
    return new Set(this.held.keys());
  }

  manifest(root: string): Dict | null {
    return this.held.get(root)?.manifest ?? null;
  }

  open(m: Dict): void {
    const root = String(m["root"]);
    if (this.held.has(root)) {
      return;
    }
    const dir = nodePath.join(this.path, root.replace(/[^A-Za-z0-9]/g, "_"));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(nodePath.join(dir, "manifest.cbor"), dumps(m));
    const data = nodePath.join(dir, "data");
    if (!fs.existsSync(data)) {
      const fd = fs.openSync(data, "w");
      try {
        if (Number(m["size"]) > 0) {
          fs.writeSync(fd, new Uint8Array([0]), 0, 1, Number(m["size"]) - 1);
        }
      } finally {
        fs.closeSync(fd);
      }
    }
    this.held.set(root, { manifest: m, dir, have: new Set(), persisted: 0 });
  }

  have(root: string): Set<number> {
    return new Set(this.held.get(root)?.have ?? []);
  }

  read(root: string, index: number, offset: number, length: number): Uint8Array | null {
    const h = this.held.get(root);
    if (h === undefined || !h.have.has(index)) {
      return null;
    }
    const m = h.manifest;
    const plen = pieceLength(Number(m["size"]), Number(m["pieceSize"]), index);
    if (offset < 0 || offset > plen) {
      return null;
    }
    const n = Math.min(length, plen - offset);
    const out = new Uint8Array(n);
    const fd = fs.openSync(nodePath.join(h.dir, "data"), "r");
    try {
      let got = 0;
      while (got < n) {
        const read = fs.readSync(fd, out, got, n - got, index * Number(m["pieceSize"]) + offset + got);
        if (read <= 0) {
          break;
        }
        got += read;
      }
      return out.subarray(0, got);
    } finally {
      fs.closeSync(fd);
    }
  }

  write(root: string, index: number, data: Uint8Array): void {
    const h = this.held.get(root);
    if (h === undefined) {
      throw new Error(`root ${root} is not open in this store`);
    }
    if (h.have.has(index)) {
      return;
    }
    const fd = fs.openSync(nodePath.join(h.dir, "data"), "r+");
    try {
      let put = 0;
      while (put < data.length) {
        put += fs.writeSync(fd, data, put, data.length - put, index * Number(h.manifest["pieceSize"]) + put);
      }
      h.have.add(index);
      const complete = h.have.size >= Number(h.manifest["pieces"]);
      if (complete || h.have.size - h.persisted >= FileStore.PERSIST_EVERY) {
        fs.fsyncSync(fd);
        this.persist(h);
      }
    } finally {
      fs.closeSync(fd);
    }
  }

  private persist(h: Held): void {
    const tmp = nodePath.join(h.dir, "have.tmp");
    fs.writeFileSync(tmp, encodeHave(h.have, Number(h.manifest["pieces"])));
    fs.renameSync(tmp, nodePath.join(h.dir, "have"));
    h.persisted = h.have.size;
  }

  flush(): void {
    for (const h of this.held.values()) {
      if (h.have.size > h.persisted) {
        const fd = fs.openSync(nodePath.join(h.dir, "data"), "r+");
        try {
          fs.fsyncSync(fd);
        } finally {
          fs.closeSync(fd);
        }
        this.persist(h);
      }
    }
  }

  readAll(root: string): Uint8Array {
    const h = this.held.get(root);
    if (h === undefined || h.have.size < Number(h.manifest["pieces"])) {
      throw new Error(`root ${root} is incomplete here`);
    }
    return new Uint8Array(fs.readFileSync(nodePath.join(h.dir, "data"))).subarray(0, Number(h.manifest["size"]));
  }

  pin(root: string): void {
    const h = this.held.get(root);
    if (h !== undefined) {
      fs.writeFileSync(nodePath.join(h.dir, "pin"), new Uint8Array());
    }
  }

  unpin(root: string): void {
    const h = this.held.get(root);
    if (h !== undefined) {
      fs.rmSync(nodePath.join(h.dir, "pin"), { force: true });
    }
  }

  forget(root: string): void {
    const h = this.held.get(root);
    if (h !== undefined) {
      this.held.delete(root);
      fs.rmSync(h.dir, { recursive: true, force: true });
    }
  }
}
