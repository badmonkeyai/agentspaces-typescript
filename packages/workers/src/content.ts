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
 * The R2 backend of the content swarm (srad/large-networks-bulk-data.md LB-C-05): a Workers
 * cell holds artifacts as R2 objects and serves pieces by ranged `get`, so an object above
 * the inline bound becomes an artifact other members fetch instead of an error. The store is
 * read-only: `publishR2Object` hashes an object piece by piece through ranged gets, registers
 * the root against its key, and publishes the manifest and the cell's complete holding.
 */

import { capabilities, wire } from "@agentspaces/client";
import type { R2BucketLike } from "./workers-types.js";

type Dict = wire.Dict;
type PieceStore = capabilities.PieceStore;

interface HeldObject { key: string; manifest: Dict; etag: string }

export class R2PieceStore implements PieceStore {
  readonly kind = "r2";
  readonly writable = false;
  private readonly held = new Map<string, HeldObject>();
  private readonly byKey = new Map<string, string>();
  private readonly pinned = new Set<string>();

  constructor(readonly bucket: R2BucketLike) {}

  /** The root registered for an object key, when one is. */
  rootOf(key: string): string | null {
    return this.byKey.get(key) ?? null;
  }

  /** The object key behind a root. */
  keyOf(root: string): string | null {
    return this.held.get(root)?.key ?? null;
  }

  /** Registers an object the manifest describes; `publishR2Object` does the hashing first. */
  register(root: string, key: string, etag: string, manifest: Dict): void {
    this.held.set(root, { key, manifest, etag });
    this.byKey.set(key, root);
  }

  roots(): Set<string> {
    return new Set(this.held.keys());
  }

  manifest(root: string): Dict | null {
    return this.held.get(root)?.manifest ?? null;
  }

  open(m: Dict): void {
    if (!this.held.has(String(m["root"]))) {
      throw new Error("an R2 store holds what its bucket holds; register an object through publishR2Object");
    }
  }

  have(root: string): Set<number> {
    const h = this.held.get(root);
    if (h === undefined) {
      return new Set();
    }
    const pieces = Number(h.manifest["pieces"]);
    return new Set(Array.from({ length: pieces }, (_, i) => i));
  }

  async read(root: string, index: number, offset: number, length: number): Promise<Uint8Array | null> {
    const h = this.held.get(root);
    if (h === undefined) {
      return null;
    }
    const size = Number(h.manifest["size"]);
    const pieceSize = Number(h.manifest["pieceSize"]);
    const pieceLength = capabilities.pieceLength(size, pieceSize, index);
    if (index < 0 || index >= Number(h.manifest["pieces"]) || offset < 0 || offset > pieceLength) {
      return null;
    }
    const n = Math.min(length, pieceLength - offset);
    if (n === 0) {
      return new Uint8Array();
    }
    const object = await this.bucket.get(h.key, { range: { offset: index * pieceSize + offset, length: n } });
    if (object === null) {
      return null;
    }
    const bytes = new Uint8Array(await object.arrayBuffer());
    return bytes.length === n ? bytes : bytes.subarray(0, n);
  }

  write(): void {
    throw new Error("an R2 store is read-only: a cell serves its objects and fetches nothing into the bucket");
  }

  readAll(): Uint8Array {
    throw new Error("an R2 store does not read whole objects; fetch the artifact or get the object");
  }

  pin(root: string): void {
    this.pinned.add(root);
  }

  unpin(root: string): void {
    this.pinned.delete(root);
  }

  flush(): void {}

  forget(root: string): void {
    const h = this.held.get(root);
    if (h !== undefined) {
      this.held.delete(root);
      this.byKey.delete(h.key);
    }
  }
}

export type R2PublishOptions = {
  /** The piece size; default 1 MiB. Hashing reads the object once, one ranged get per piece. */
  pieceSize?: number;
  /** A display name; default the key. */
  name?: string | null;
  /** The manifest's lease; default seven days. */
  lease?: number | string;
};

/**
 * Publishes an R2 object as an artifact: hashes it piece by piece with ranged gets (so
 * no more than one piece is in memory), registers the root in the store, and writes the
 * manifest and the cell's complete holding through `content`. An object already published
 * under the same etag returns its root without re-reading.
 */
export async function publishR2Object(content: capabilities.Content, store: R2PieceStore, key: string,
                                      options: R2PublishOptions = {}): Promise<Dict> {
  const head = await store.bucket.head(key);
  if (head === null) {
    throw new Error(`no object ${key}`);
  }
  const existing = store.rootOf(key);
  if (existing !== null) {
    const m = store.manifest(existing)!;
    const held = (store as unknown as { held: Map<string, HeldObject> }).held.get(existing);
    if (held !== undefined && held.etag === head.etag) {
      return m;
    }
    store.forget(existing);
  }
  const pieceSize = options.pieceSize ?? capabilities.DEFAULT_PIECE_SIZE;
  const pieces = capabilities.piecesOf(head.size, pieceSize);
  if (pieces > capabilities.INLINE_TABLE_PIECES) {
    throw new Error(`object ${key} of ${head.size} bytes needs ${pieces} pieces; this client keeps the table inline`
      + ` (at most ${capabilities.INLINE_TABLE_PIECES}): use a larger pieceSize`);
  }
  const table = new Uint8Array(pieces * capabilities.HASH_BYTES);
  for (let i = 0; i < pieces; i++) {
    const length = capabilities.pieceLength(head.size, pieceSize, i);
    const object = await store.bucket.get(key, { range: { offset: i * pieceSize, length } });
    if (object === null) {
      throw new Error(`object ${key} vanished while hashing`);
    }
    const piece = new Uint8Array(await object.arrayBuffer());
    table.set(capabilities.hashPieces(piece, Math.max(piece.length, 1)).subarray(0, capabilities.HASH_BYTES), i * capabilities.HASH_BYTES);
  }
  const root = capabilities.contentRoot(table);
  const manifest = capabilities.manifest(root, head.size, pieceSize, table, content.selfId, content.peer.now(),
    { name: options.name === undefined ? key : options.name, mediaType: head.httpMetadata?.contentType ?? null });
  store.register(root, key, head.etag, manifest);
  content.publishManifest(manifest, { lease: options.lease ?? capabilities.Content.MANIFEST_LEASE });
  return manifest;
}
