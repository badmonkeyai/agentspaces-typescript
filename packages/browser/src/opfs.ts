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
 * The browser's piece store over the origin private file system (srad/large-networks-bulk-data.md
 * LB-C-01): one directory per root under a named directory, holding `data` (pieces at their
 * offsets), `have` (the verified bitfield) and `manifest.cbor`, so a fetch resumes after a reload
 * and a browser that holds an artifact serves it. The file system's API is asynchronous on a page,
 * so reads answer later (the core's holder side waits for them) and writes queue in order behind
 * a memory copy that serves until the file has them; `OpfsStore.open` reads every root back.
 * In a worker (where the resident host runs) the store uses synchronous access handles, which
 * every engine offers there, and reads answer at once; on a page it uses writable streams, which
 * Safari's page thread refuses. `OpfsStore.open` probes both, and where neither works, or the
 * API is absent, it fails and the caller falls back to a `MemoryStore` (the core's rule for
 * browsers without OPFS).
 */

import { capabilities, cbor, wire } from "@agentspaces/client";

type Dict = wire.Dict;

interface SyncHandleLike {
  read(buffer: Uint8Array, options?: { at?: number }): number;
  write(buffer: Uint8Array, options?: { at?: number }): number;
  truncate(size: number): void;
  flush(): void;
  close(): void;
  getSize(): number;
}

interface FileHandleLike {
  getFile(): Promise<{ size: number; arrayBuffer(): Promise<ArrayBuffer>; slice(a: number, b: number): { arrayBuffer(): Promise<ArrayBuffer> } }>;
  createWritable?(options?: { keepExistingData?: boolean }): Promise<{
    write(data: Uint8Array | { type: "write"; position: number; data: Uint8Array } | { type: "truncate"; size: number }): Promise<void>;
    close(): Promise<void>;
  }>;
  createSyncAccessHandle?(): Promise<SyncHandleLike>;
}

/** How files are written: synchronous access handles (a worker) or writable streams (a page). */
export type OpfsMode = "sync" | "stream";

interface DirectoryHandleLike {
  getDirectoryHandle(name: string, options?: { create?: boolean }): Promise<DirectoryHandleLike>;
  getFileHandle(name: string, options?: { create?: boolean }): Promise<FileHandleLike>;
  removeEntry(name: string, options?: { recursive?: boolean }): Promise<void>;
  keys(): AsyncIterable<string>;
}

interface Held {
  manifest: Dict;
  dir: DirectoryHandleLike;
  data: FileHandleLike;
  have: Set<number>;
  /** Pieces written to memory and not yet to the file; served from here meanwhile. */
  staged: Map<number, Uint8Array>;
  persisted: number;
  queue: Promise<void>;
  /** The open synchronous handle on `data`, in sync mode, once the queue opened it. */
  sync: SyncHandleLike | null;
}

/** Whether this runtime offers the origin private file system. */
export function opfsAvailable(): boolean {
  const storage = (globalThis as { navigator?: { storage?: { getDirectory?: unknown } } }).navigator?.storage;
  return typeof storage?.getDirectory === "function";
}

export class OpfsStore implements capabilities.PieceStore {
  static readonly PERSIST_EVERY = 8;
  readonly kind = "opfs";
  readonly writable = true;
  private readonly held = new Map<string, Held>();
  private readonly pinned = new Set<string>();

  private constructor(readonly root: DirectoryHandleLike, readonly name: string, readonly mode: OpfsMode) {}

  /** Opens (or creates) the store under `name`, probes how this thread may write, and reads every root it holds. */
  static async open(name = "agentspaces-content"): Promise<OpfsStore> {
    if (!opfsAvailable()) {
      throw new Error("the origin private file system is not available here");
    }
    const top = await (globalThis as unknown as { navigator: { storage: { getDirectory(): Promise<DirectoryHandleLike> } } })
      .navigator.storage.getDirectory();
    const dir = await top.getDirectoryHandle(name, { create: true });
    const mode = await probe(dir);
    const store = new OpfsStore(dir, name, mode);
    for await (const entry of dir.keys()) {
      try {
        const sub = await dir.getDirectoryHandle(entry);
        const manifest = cbor.loads(new Uint8Array(await (await (await sub.getFileHandle("manifest.cbor")).getFile()).arrayBuffer())) as Dict;
        const data = await sub.getFileHandle("data");
        let have = new Set<number>();
        try {
          const bits = new Uint8Array(await (await (await sub.getFileHandle("have")).getFile()).arrayBuffer());
          have = capabilities.decodeHave(bits, Number(manifest["pieces"]));
        } catch {
          // no bitfield yet: nothing verified
        }
        const held: Held = { manifest, dir: sub, data, have, staged: new Map(), persisted: have.size,
          queue: Promise.resolve(), sync: null };
        if (mode === "sync") {
          held.queue = data.createSyncAccessHandle!().then((h) => { held.sync = h; });
        }
        store.held.set(String(manifest["root"]), held);
      } catch {
        // not one of ours, or half written: skipped
      }
    }
    return store;
  }

  roots(): Set<string> {
    return new Set(this.held.keys());
  }

  manifest(root: string): Dict | null {
    return this.held.get(root)?.manifest ?? null;
  }

  /** Registers a root; the directory and files are created on the queue before the first write lands. */
  open(m: Dict): void {
    const root = String(m["root"]);
    if (this.held.has(root)) {
      return;
    }
    const held: Held = { manifest: m, dir: null as unknown as DirectoryHandleLike, data: null as unknown as FileHandleLike,
      have: new Set(), staged: new Map(), persisted: 0, queue: Promise.resolve(), sync: null };
    held.queue = (async () => {
      held.dir = await this.root.getDirectoryHandle(root.replace(/[^A-Za-z0-9]/g, "_"), { create: true });
      await this.writeWhole(await held.dir.getFileHandle("manifest.cbor", { create: true }), cbor.dumps(m));
      held.data = await held.dir.getFileHandle("data", { create: true });
      if (this.mode === "sync") {
        held.sync = await held.data.createSyncAccessHandle!();
      }
    })();
    this.held.set(root, held);
  }

  /** Resolves once every queued write of a root reached the file system. */
  async settled(root: string): Promise<void> {
    await this.held.get(root)?.queue;
  }

  have(root: string): Set<number> {
    const h = this.held.get(root);
    return h === undefined ? new Set() : new Set([...h.have, ...h.staged.keys()]);
  }

  read(root: string, index: number, offset: number, length: number): Uint8Array | null | Promise<Uint8Array | null> {
    const h = this.held.get(root);
    if (h === undefined) {
      return null;
    }
    const staged = h.staged.get(index);
    if (staged !== undefined) {
      return offset < 0 || offset > staged.length ? null : staged.subarray(offset, Math.min(staged.length, offset + length));
    }
    if (!h.have.has(index)) {
      return null;
    }
    const m = h.manifest;
    const plen = capabilities.pieceLength(Number(m["size"]), Number(m["pieceSize"]), index);
    if (offset < 0 || offset > plen) {
      return null;
    }
    const n = Math.min(length, plen - offset);
    const at = index * Number(m["pieceSize"]) + offset;
    if (h.sync !== null) {
      const out = new Uint8Array(n);
      const got = h.sync.read(out, { at });
      return got === n ? out : out.subarray(0, got);
    }
    return h.queue.then(async () => {
      if (h.sync !== null) {
        const out = new Uint8Array(n);
        return out.subarray(0, h.sync.read(out, { at }));
      }
      const file = await h.data.getFile();
      return new Uint8Array(await file.slice(at, at + n).arrayBuffer());
    });
  }

  write(root: string, index: number, data: Uint8Array): void {
    const h = this.held.get(root);
    if (h === undefined) {
      throw new Error(`root ${root} is not open in this store`);
    }
    if (h.have.has(index) || h.staged.has(index)) {
      return;
    }
    h.staged.set(index, new Uint8Array(data));
    const m = h.manifest;
    h.queue = h.queue.then(async () => {
      if (h.sync !== null) {
        h.sync.write(data, { at: index * Number(m["pieceSize"]) });
        h.sync.flush();
      } else {
        const w = await h.data.createWritable!({ keepExistingData: true });
        await w.write({ type: "write", position: index * Number(m["pieceSize"]), data });
        await w.close();
      }
      h.have.add(index);
      h.staged.delete(index);
      const complete = h.have.size >= Number(m["pieces"]);
      if (complete || h.have.size - h.persisted >= OpfsStore.PERSIST_EVERY) {
        await this.persist(h);
      }
    }).catch(() => {
      // the piece stays staged in memory: served from here, written again on the next flush
      h.staged.set(index, new Uint8Array(data));
    });
  }

  private async persist(h: Held): Promise<void> {
    await this.writeWhole(await h.dir.getFileHandle("have", { create: true }),
      capabilities.encodeHave(h.have, Number(h.manifest["pieces"])));
    h.persisted = h.have.size;
  }

  /** Replaces a small file's contents, by the mode this thread may use. */
  private async writeWhole(file: FileHandleLike, bytes: Uint8Array): Promise<void> {
    if (this.mode === "sync") {
      const handle = await file.createSyncAccessHandle!();
      try {
        handle.truncate(0);
        handle.write(bytes, { at: 0 });
        handle.flush();
      } finally {
        handle.close();
      }
      return;
    }
    const w = await file.createWritable!();
    await w.write(bytes);
    await w.close();
  }

  flush(): void {
    for (const h of this.held.values()) {
      h.queue = h.queue.then(async () => {
        if (h.have.size > h.persisted) {
          await this.persist(h);
        }
      });
    }
  }

  readAll(): Uint8Array {
    throw new Error("an OPFS store reads whole artifacts asynchronously: use readArtifact(root)");
  }

  /** The whole artifact, once every piece is on the file system. */
  async readArtifact(root: string): Promise<Uint8Array> {
    const h = this.held.get(root);
    if (h === undefined) {
      throw new Error(`root ${root} is not held here`);
    }
    await h.queue;
    if (h.have.size < Number(h.manifest["pieces"])) {
      throw new Error(`root ${root} is incomplete here`);
    }
    const size = Number(h.manifest["size"]);
    if (h.sync !== null) {
      const out = new Uint8Array(size);
      return out.subarray(0, h.sync.read(out, { at: 0 }));
    }
    const file = await h.data.getFile();
    return new Uint8Array(await file.slice(0, size).arrayBuffer());
  }

  /** Closes the open handles; a worker closing, or a test reopening the same directory. */
  async close(): Promise<void> {
    for (const h of this.held.values()) {
      await h.queue;
      h.sync?.close();
      h.sync = null;
    }
  }

  pin(root: string): void {
    this.pinned.add(root);
  }

  unpin(root: string): void {
    this.pinned.delete(root);
  }

  forget(root: string): void {
    const h = this.held.get(root);
    if (h !== undefined) {
      this.held.delete(root);
      void h.queue.then(() => { h.sync?.close(); h.sync = null; })
        .then(() => this.root.removeEntry(root.replace(/[^A-Za-z0-9]/g, "_"), { recursive: true })).catch(() => undefined);
    }
  }

  /** Removes the whole store directory; for tests and a user's "clear data". */
  static async erase(name = "agentspaces-content"): Promise<void> {
    if (!opfsAvailable()) {
      return;
    }
    const top = await (globalThis as unknown as { navigator: { storage: { getDirectory(): Promise<DirectoryHandleLike> } } })
      .navigator.storage.getDirectory();
    try {
      await top.removeEntry(name, { recursive: true });
    } catch {
      // nothing there
    }
  }
}

/** Which write path this thread may use: a sync handle (a worker), a writable stream (a page), or neither. */
async function probe(dir: DirectoryHandleLike): Promise<OpfsMode> {
  const file = await dir.getFileHandle(".probe", { create: true });
  if (typeof file.createSyncAccessHandle === "function") {
    try {
      const handle = await file.createSyncAccessHandle();
      handle.close();
      return "sync";
    } catch {
      // not a worker: fall through to the stream
    }
  }
  if (typeof file.createWritable === "function") {
    try {
      const w = await file.createWritable();
      await w.write(new Uint8Array());
      await w.close();
      return "stream";
    } catch {
      // Safari's page thread: neither path
    }
  }
  throw new Error("this thread can read the origin private file system but not write it; run the store in a worker");
}
