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
 * The node store (srad/agentspaces-pdt.md §3.4, PD-S-01, PD-S-06, PD-S-07): nodes by CID over a
 * backend of bytes, with `has` without a read, batch `put`, root pins with a reference count, and
 * completeness per root. Every node is verified against its CID before it is stored (PD-N-06), on
 * every path: `put` hashes, `putVerified` checks. The memory backend serves tests and the browser's
 * fallback; `@agentspaces/client/node` adds a file backend and `@agentspaces/browser` an OPFS pack.
 *
 * The backend is synchronous because the values layer reads nodes on demand inside ordinary calls
 * (`get`, `nth`, iteration); a backend that must read asynchronously loads its index at open time.
 */

import * as cids from "./cids.js";
import { MAX_DEPTH, NodeFormatError, links as nodeLinks } from "./nodes.js";

/** Where the bytes live: a map, a directory, an OPFS pack. */
export interface NodeBackend {
  readonly kind: string;
  get(cid: string): Uint8Array | undefined;
  has(cid: string): boolean;
  /** Stores bytes under a CID the caller verified; returns false when already held. */
  put(cid: string, bytes: Uint8Array): boolean;
  remove(cid: string): boolean;
  cids(): Iterable<string>;
  size(): number;
  /** Flushes anything buffered; a memory backend does nothing. */
  flush(): void;
}

/** Nodes on the heap. */
export class MemoryBackend implements NodeBackend {
  readonly kind = "memory";
  private readonly nodes = new Map<string, Uint8Array>();

  get(cid: string): Uint8Array | undefined {
    return this.nodes.get(cid);
  }

  has(cid: string): boolean {
    return this.nodes.has(cid);
  }

  put(cid: string, bytes: Uint8Array): boolean {
    if (this.nodes.has(cid)) {
      return false;
    }
    this.nodes.set(cid, new Uint8Array(bytes));
    return true;
  }

  remove(cid: string): boolean {
    return this.nodes.delete(cid);
  }

  cids(): Iterable<string> {
    return this.nodes.keys();
  }

  size(): number {
    return this.nodes.size;
  }

  flush(): void {}
}

/** A node the store or the swarm cannot produce (PD-V-06). */
export class NodeUnavailableError extends Error {
  constructor(readonly cid: string, detail = "") {
    super(`node ${cid} is not available here${detail ? `: ${detail}` : ""}`);
    this.name = "NodeUnavailableError";
  }
}

/** The link rule the walks use: a node the codec refuses is a leaf. */
function linksOrLeaf(cid: string, bytes: Uint8Array): string[] {
  try {
    return nodeLinks(bytes, cid);
  } catch (e) {
    if (e instanceof NodeFormatError) {
      return [];
    }
    throw e;
  }
}

export class NodeStore {
  private readonly pins = new Map<string, number>();
  /** Nodes stored since the last `drain`; a swap records its delta through it. */
  private recorder: Map<string, Uint8Array> | null = null;
  bytesHeld = 0;

  constructor(readonly backend: NodeBackend = new MemoryBackend()) {
    for (const cid of backend.cids()) {
      this.bytesHeld += backend.get(cid)?.length ?? 0;
    }
  }

  static inMemory(): NodeStore {
    return new NodeStore(new MemoryBackend());
  }

  has(cid: string): boolean {
    return this.backend.has(cid);
  }

  /** The node's bytes, or undefined. A held node is trusted: it was verified on the way in. */
  get(cid: string): Uint8Array | undefined {
    return this.backend.get(cid);
  }

  /** The node's bytes; throws `NodeUnavailableError` when absent. */
  load(cid: string): Uint8Array {
    const bytes = this.backend.get(cid);
    if (bytes === undefined) {
      throw new NodeUnavailableError(cid);
    }
    return bytes;
  }

  /** Hashes and stores bytes under a codec; returns the CID. */
  put(bytes: Uint8Array, codec: number): string {
    const cid = cids.of(bytes, codec);
    this.store(cid, bytes);
    return cid;
  }

  /** Stores bytes whose CID the caller names; refuses bytes that do not hash to it (PD-N-06). */
  putVerified(cid: string, bytes: Uint8Array): boolean {
    if (!cids.verifies(cid, bytes)) {
      throw new NodeFormatError("bytes do not hash to the CID", cid);
    }
    return this.store(cid, bytes);
  }

  putAll(nodes: Iterable<[string, Uint8Array]>): number {
    let stored = 0;
    for (const [cid, bytes] of nodes) {
      if (this.putVerified(cid, bytes)) {
        stored += 1;
      }
    }
    return stored;
  }

  private store(cid: string, bytes: Uint8Array): boolean {
    if (this.recorder !== null && !this.recorder.has(cid)) {
      this.recorder.set(cid, new Uint8Array(bytes));
    }
    if (!this.backend.put(cid, bytes)) {
      return false;
    }
    this.bytesHeld += bytes.length;
    return true;
  }

  /** Starts recording every node stored from now; `drain` returns and clears the record. */
  record(): void {
    this.recorder = new Map();
  }

  drain(): Map<string, Uint8Array> {
    const out = this.recorder ?? new Map();
    this.recorder = null;
    return out;
  }

  remove(cid: string): boolean {
    const bytes = this.backend.get(cid);
    if (bytes === undefined || !this.backend.remove(cid)) {
      return false;
    }
    this.bytesHeld -= bytes.length;
    return true;
  }

  cids(): Iterable<string> {
    return this.backend.cids();
  }

  get nodesHeld(): number {
    return this.backend.size();
  }

  flush(): void {
    this.backend.flush();
  }

  // ---- pins

  pin(root: string): void {
    this.pins.set(root, (this.pins.get(root) ?? 0) + 1);
  }

  unpin(root: string): void {
    const n = this.pins.get(root) ?? 0;
    if (n <= 1) {
      this.pins.delete(root);
    } else {
      this.pins.set(root, n - 1);
    }
  }

  pinned(): Set<string> {
    return new Set(this.pins.keys());
  }

  isPinned(root: string): boolean {
    return this.pins.has(root);
  }

  // ---- walks

  /** The links of a held node (a refused node and a raw chunk are leaves). */
  links(cid: string): string[] {
    const bytes = this.backend.get(cid);
    return bytes === undefined ? [] : linksOrLeaf(cid, bytes);
  }

  /** Every CID reachable from `root` through held nodes, the root included; bounded by the tree depth. */
  reachable(root: string, limit = Number.POSITIVE_INFINITY): Set<string> {
    const seen = new Set<string>();
    const queue: [string, number][] = [[root, 0]];
    while (queue.length > 0 && seen.size < limit) {
      const [cid, depth] = queue.shift()!;
      if (seen.has(cid)) {
        continue;
      }
      seen.add(cid);
      const bytes = this.backend.get(cid);
      if (bytes === undefined) {
        continue;
      }
      if (depth >= MAX_DEPTH) {
        throw new NodeFormatError(`tree deeper than ${MAX_DEPTH} levels`, cid);
      }
      for (const link of linksOrLeaf(cid, bytes)) {
        if (!seen.has(link)) {
          queue.push([link, depth + 1]);
        }
      }
    }
    return seen;
  }

  /** The CIDs reachable from `root` that the store lacks (the root itself when absent). */
  missing(root: string): Set<string> {
    const missing = new Set<string>();
    for (const cid of this.reachable(root)) {
      if (!this.backend.has(cid)) {
        missing.add(cid);
      }
    }
    return missing;
  }

  /** Whether every node reachable from `root` is held. */
  complete(root: string): boolean {
    const seen = new Set<string>();
    const queue: [string, number][] = [[root, 0]];
    while (queue.length > 0) {
      const [cid, depth] = queue.shift()!;
      if (seen.has(cid)) {
        continue;
      }
      seen.add(cid);
      const bytes = this.backend.get(cid);
      if (bytes === undefined) {
        return false;
      }
      if (depth >= MAX_DEPTH) {
        return false;
      }
      for (const link of linksOrLeaf(cid, bytes)) {
        if (!seen.has(link)) {
          queue.push([link, depth + 1]);
        }
      }
    }
    return true;
  }

  /**
   * Mark-and-sweep collection (PD-S-04): keeps every node reachable from the pinned roots and
   * `extraRoots`, removes the rest, visiting at most `visits` nodes; returns how many it removed.
   */
  collect(extraRoots: Iterable<string> = [], visits = 10_000): number {
    const marked = new Set<string>();
    const roots = new Set<string>([...this.pins.keys(), ...extraRoots]);
    for (const root of roots) {
      for (const cid of this.reachable(root)) {
        marked.add(cid);
      }
    }
    let removed = 0, visited = 0;
    for (const cid of [...this.backend.cids()]) {
      if (visited++ >= visits) {
        break;
      }
      if (!marked.has(cid) && this.remove(cid)) {
        removed += 1;
      }
    }
    return removed;
  }
}
