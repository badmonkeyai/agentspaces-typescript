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
 * The browser's node store over the origin private file system (srad/agentspaces-pdt.md PD-C-05,
 * PD-S-02 in miniature): one append-only pack file per store with an in-memory index from CID to
 * offset and length, read and written through a synchronous access handle, which every engine offers
 * in a worker (where the resident host runs). The values layer reads nodes inside ordinary calls, so
 * the backend must answer synchronously; a page thread, which gets writable streams only, cannot
 * host it and `OpfsNodeBackend.open` refuses there, so the caller keeps a `MemoryBackend` (the rule
 * `OpfsStore` follows for pieces).
 *
 * Pack record: [u32 len][u16 cidLen][cid][payload]; `open` rebuilds the index by scanning the pack,
 * so no separate index file can go stale. A removal rewrites the index only; the bytes stay until
 * `compact`, which copies the live records into a fresh pack.
 */

import { pdt } from "@agentspaces/client";

interface SyncHandleLike {
  read(buffer: Uint8Array, options?: { at?: number }): number;
  write(buffer: Uint8Array, options?: { at?: number }): number;
  truncate(size: number): void;
  flush(): void;
  close(): void;
  getSize(): number;
}

interface FileHandleLike {
  createSyncAccessHandle?(): Promise<SyncHandleLike>;
}

interface DirectoryHandleLike {
  getDirectoryHandle(name: string, options?: { create?: boolean }): Promise<DirectoryHandleLike>;
  getFileHandle(name: string, options?: { create?: boolean }): Promise<FileHandleLike>;
  removeEntry(name: string, options?: { recursive?: boolean }): Promise<void>;
}

interface Slot { offset: number; length: number }

const HEADER = 4 + 2;

export class OpfsNodeBackend implements pdt.NodeBackend {
  readonly kind = "opfs-pack";
  private readonly index = new Map<string, Slot>();
  private end = 0;
  private dead = 0;

  private constructor(readonly dir: DirectoryHandleLike, private handle: SyncHandleLike, readonly name: string) {}

  /**
   * Opens (or creates) the pack under `name` in the origin private file system and rebuilds its index.
   * Fails on a thread without synchronous access handles (a page): fall back to memory there.
   */
  static async open(name = "agentspaces-pdt", root?: DirectoryHandleLike): Promise<OpfsNodeBackend> {
    const top = root ?? await (globalThis as unknown as { navigator?: { storage?: { getDirectory?(): Promise<DirectoryHandleLike> } } })
      .navigator?.storage?.getDirectory?.();
    if (top === undefined) {
      throw new Error("the origin private file system is not available here");
    }
    const dir = await top.getDirectoryHandle(name, { create: true });
    const file = await dir.getFileHandle("nodes.pack", { create: true });
    if (typeof file.createSyncAccessHandle !== "function") {
      throw new Error("this thread has no synchronous access handles; run the node store in a worker");
    }
    const handle = await file.createSyncAccessHandle();
    const backend = new OpfsNodeBackend(dir, handle, name);
    backend.rebuild();
    return backend;
  }

  private rebuild(): void {
    const size = this.handle.getSize();
    const header = new Uint8Array(HEADER);
    let at = 0;
    this.index.clear();
    while (at + HEADER <= size) {
      if (this.handle.read(header, { at }) !== HEADER) {
        break;
      }
      const view = new DataView(header.buffer);
      const length = view.getUint32(0, false);
      const cidLength = view.getUint16(4, false);
      if (length < cidLength || at + HEADER + length > size) {
        break; // a torn tail: everything before it stands
      }
      const cidBytes = new Uint8Array(cidLength);
      this.handle.read(cidBytes, { at: at + HEADER });
      const cid = new TextDecoder().decode(cidBytes);
      this.index.set(cid, { offset: at + HEADER + cidLength, length: length - cidLength });
      at += HEADER + length;
    }
    this.end = at;
    this.dead = 0;
    if (at < size) {
      this.handle.truncate(at);
    }
  }

  get(cid: string): Uint8Array | undefined {
    const slot = this.index.get(cid);
    if (slot === undefined) {
      return undefined;
    }
    const out = new Uint8Array(slot.length);
    const got = this.handle.read(out, { at: slot.offset });
    return got === slot.length ? out : undefined;
  }

  has(cid: string): boolean {
    return this.index.has(cid);
  }

  put(cid: string, bytes: Uint8Array): boolean {
    if (this.index.has(cid)) {
      return false;
    }
    const cidBytes = new TextEncoder().encode(cid);
    const record = new Uint8Array(HEADER + cidBytes.length + bytes.length);
    const view = new DataView(record.buffer);
    view.setUint32(0, cidBytes.length + bytes.length, false);
    view.setUint16(4, cidBytes.length, false);
    record.set(cidBytes, HEADER);
    record.set(bytes, HEADER + cidBytes.length);
    this.handle.write(record, { at: this.end });
    this.index.set(cid, { offset: this.end + HEADER + cidBytes.length, length: bytes.length });
    this.end += record.length;
    return true;
  }

  remove(cid: string): boolean {
    const slot = this.index.get(cid);
    if (slot === undefined) {
      return false;
    }
    this.index.delete(cid);
    this.dead += slot.length;
    return true;
  }

  cids(): Iterable<string> {
    return this.index.keys();
  }

  size(): number {
    return this.index.size;
  }

  /** Bytes of removed records still in the pack. */
  deadBytes(): number {
    return this.dead;
  }

  flush(): void {
    this.handle.flush();
  }

  /** Copies the live records into a fresh pack when more than half the bytes are dead (or always when forced). */
  async compact(force = false): Promise<boolean> {
    if (!force && this.dead * 2 <= this.end) {
      return false;
    }
    const live: [string, Uint8Array][] = [];
    for (const cid of this.index.keys()) {
      const bytes = this.get(cid);
      if (bytes !== undefined) {
        live.push([cid, bytes]);
      }
    }
    this.handle.truncate(0);
    this.index.clear();
    this.end = 0;
    this.dead = 0;
    for (const [cid, bytes] of live) {
      this.put(cid, bytes);
    }
    this.handle.flush();
    return true;
  }

  close(): void {
    this.handle.flush();
    this.handle.close();
  }

  /** Removes the whole store directory. */
  static async erase(name = "agentspaces-pdt", root?: DirectoryHandleLike): Promise<void> {
    const top = root ?? await (globalThis as unknown as { navigator?: { storage?: { getDirectory?(): Promise<DirectoryHandleLike> } } })
      .navigator?.storage?.getDirectory?.();
    try {
      await top?.removeEntry(name, { recursive: true });
    } catch {
      // nothing there
    }
  }
}
