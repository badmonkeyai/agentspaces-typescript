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
 * Persistent data structures with structural sharing (srad/agentspaces-pdt.md, PD-C-05): maps, sets,
 * vectors, and blobs as content-addressed trees whose unchanged parts every version shares, refs that
 * name a value in a space, and the tree exchange that moves only a version's delta. The facade:
 *
 *     const pdt = new Pdt(peer, { content });     // attaches as peer.pdt
 *     const facts = pdt.ref<PMap<string, CborValue>>("research", "facts", "map");
 *     await facts.swap((m) => m.assoc("k", "v"));
 *     (await facts.deref()).get("k");
 *
 * Every value is immutable; an operation returns a new value that shares every untouched node. The
 * node store keeps nodes by CID (memory here; a file backend from `@agentspaces/client/node`, an OPFS
 * pack from `@agentspaces/browser`).
 */

import type { CborValue } from "../cbor.js";
import type { Content } from "../capabilities/content.js";
import type { Peer } from "../peer.js";
import { Space } from "../space.js";
import type { Dict } from "../wire.js";
import * as cids from "./cids.js";
import * as fastcdc from "./fastcdc.js";
import * as nodes from "./nodes.js";
import { DEFAULT_CONFIG, MergeFunction, Ref, Refs, RefsConfig } from "./refs.js";
import { NodeStore } from "./store.js";
import { Ctx, readPayload } from "./values.js";
import * as tree from "./tree.js";
import { ContentKeys, TreeExchange } from "./tree.js";

export { cids, fastcdc, nodes, tree };
export { NodeStore, MemoryBackend, NodeUnavailableError } from "./store.js";
export type { NodeBackend } from "./store.js";
export { Link, Embedded, NodeFormatError, MAX_NODE_BYTES, MAX_LINKS, MAX_DEPTH } from "./nodes.js";
export type { Node } from "./nodes.js";
export { PMap, PSet, Editor, RawMap } from "./champ.js";
export type { Diff, Resolver } from "./champ.js";
export { PVector, VectorEditor } from "./vector.js";
export { PBlob, BlobTree } from "./blob.js";
export type { Entry as BlobEntry } from "./blob.js";
export { cborCodec, XNode, BlobNode, Flusher, VALUE_LIMIT, TREE_LIMIT } from "./values.js";
export type { Codec } from "./values.js";
export { ContentKeys, TreeExchange, TreeFetch, TreeServer } from "./tree.js";
export type { TreeExchangeOptions, TreeProgress } from "./tree.js";
export { Ref, Refs, PREF_TYPE, INLINE_DELTA_BYTES, MAX_SEQ, pref, prefTags, prefViolation, headsAmong, mergeOrder, collectDelta,
  acceptInline, kindNamed } from "./refs.js";
export type { Head, PConflict, MergeFunction, RefKind, RefKindName, RefsConfig, PRefFields } from "./refs.js";
export type { CborValue };

export interface PdtOptions {
  /** The node store; memory by default. */
  store?: NodeStore;
  /** The content swarm the deltas travel over; without one, heads travel inline only. */
  content?: Content | null;
  /** The group's content keys for `group-key` sealing of the tree exchange. */
  keys?: ContentKeys | null;
  /** Nodes a swap created travel inline on the head up to this many bytes (32 KiB). */
  inlineDelta?: number;
  /** A head's lease; renewed at half-life (10 minutes). */
  headLeaseMillis?: number;
  /** How long a superseded own head stays before it is cancelled (2 s, never less). */
  cancelGraceMillis?: number;
  /** How long `deref` waits for a head's nodes (10 s). */
  loadTimeoutMillis?: number;
  /** `full` fetches a head's delta when the head arrives; `lazy` only on access. */
  follow?: "full" | "lazy";
  /** What heads say about their nodes: `none` or `group-key`. */
  sealing?: string;
  retainVersions?: number;
  retainAgeMillis?: number;
  /** The lease, timeout, and retries of a linear ref's take. */
  take?: { leaseMillis?: number; timeoutMillis?: number; retries?: number };
  /** Per-ref modes: `multi` (the default) or `linear`. */
  modes?: { [name: string]: "multi" | "linear" };
  mayServe?: ((peer: string, cid: string) => boolean) | null;
  advertises?: ((peer: string) => boolean) | null;
}

/** The facade: one per peer, attached as `peer.pdt`. */
export class Pdt {
  readonly store: NodeStore;
  readonly exchange: TreeExchange | null;
  readonly refs: Refs;
  readonly config: RefsConfig;
  private readonly spaces = new Map<string, Space>();
  private ticking: { stop(): void } | null = null;

  constructor(readonly peer: Peer, options: PdtOptions = {}) {
    this.store = options.store ?? NodeStore.inMemory();
    const content = options.content ?? null;
    this.exchange = content === null ? null : new TreeExchange(content, this.store,
      { keys: options.keys ?? null, mayServe: options.mayServe ?? null, advertises: options.advertises ?? null });
    this.config = { ...DEFAULT_CONFIG,
      inlineDelta: options.inlineDelta ?? DEFAULT_CONFIG.inlineDelta,
      headLeaseMillis: options.headLeaseMillis ?? DEFAULT_CONFIG.headLeaseMillis,
      cancelGraceMillis: Math.max(DEFAULT_CONFIG.cancelGraceMillis, options.cancelGraceMillis ?? DEFAULT_CONFIG.cancelGraceMillis),
      loadTimeoutMillis: options.loadTimeoutMillis ?? DEFAULT_CONFIG.loadTimeoutMillis,
      follow: options.follow ?? "full",
      sealing: options.sealing ?? (options.keys ? "group-key" : "none"),
      retainVersions: options.retainVersions ?? DEFAULT_CONFIG.retainVersions,
      retainAgeMillis: options.retainAgeMillis ?? DEFAULT_CONFIG.retainAgeMillis,
      takeLeaseMillis: options.take?.leaseMillis ?? DEFAULT_CONFIG.takeLeaseMillis,
      takeTimeoutMillis: options.take?.timeoutMillis ?? DEFAULT_CONFIG.takeTimeoutMillis,
      takeRetries: options.take?.retries ?? DEFAULT_CONFIG.takeRetries,
      modes: { ...(options.modes ?? {}) } };
    this.refs = new Refs(peer, this.store, this.exchange, this.config);
    peer.pdt = this;
  }

  /** The space the heads of `space` live in (one `Space` per name). */
  space(name: string | Space): Space {
    if (name instanceof Space) {
      return name;
    }
    let space = this.spaces.get(name);
    if (space === undefined) {
      space = new Space(this.peer, name);
      this.spaces.set(name, space);
    }
    return space;
  }

  /** A ref by space, name, and kind (`map`, `set`, `vector`, `blob`, `tree`). */
  ref<T = unknown>(space: string | Space, name: string, kind: "map" | "set" | "vector" | "blob" | "tree"): Ref<T> {
    return this.refs.ref<T>(this.space(space), name, kind);
  }

  /** Registers the merge for a name's vector or blob (or any kind) on this reader. */
  mergeFor<T>(name: string, fn: MergeFunction<T>): this {
    this.refs.mergeFor(name, fn);
    return this;
  }

  /** Re-publishes this peer's content-swarm advertisement (`trees = "1"`). */
  advertise(): void {
    this.exchange?.advertise();
  }

  run(intervalMillis = 250): void {
    if (this.ticking === null) {
      this.ticking = this.peer.every(intervalMillis, () => this.tick());
    }
  }

  tick(): void {
    this.exchange?.tick();
    this.refs.tick();
  }

  /** Escalated space payloads reassembled here (PD-E-03). */
  payloadsRead = 0;

  /**
   * The bytes of an escalated space payload (srad/agentspaces-pdt.md §3.7, PD-E-01, PD-E-03):
   * reassembled when the store holds the tree whole, else null after starting one tree fetch for
   * the root, as `Content.local` and `Content.ensure` do for a flat artifact; reads never block on
   * the network. Without a tree exchange a root the store lacks stays null.
   */
  payload(root: string): Uint8Array | null {
    cids.parse(root);
    if (this.store.complete(root)) {
      const bytes = readPayload(root, new Ctx(this.store));
      this.payloadsRead += 1;
      return bytes;
    }
    this.exchange?.fetchTree(root);
    return null;
  }

  /** Mark-and-sweep over the pinned roots and every live ref root (PD-S-04). */
  collect(visits = 10_000): number {
    const removed = this.store.collect(this.refs.liveRoots(), visits);
    if (removed > 0) {
      this.refs.forgetHeld();
    }
    return removed;
  }

  stop(): void {
    this.ticking?.stop();
    this.ticking = null;
    this.store.flush();
  }

  close(): void {
    this.stop();
    this.refs.close();
  }

  stats(): Dict {
    return { refs: this.refs.refCount(), heads: this.refs.headCount(), deltasInline: this.refs.deltasInline,
      deltasFetched: this.refs.deltasFetched, conflicts: this.refs.conflicts, bytesReceived: this.refs.bytesReceived,
      headsIgnored: this.refs.headsIgnored, nodesDropped: this.refs.nodesDropped, headsRewritten: this.refs.headsRewritten,
      basesFetched: this.refs.basesFetched, nodesHeld: this.store.nodesHeld, bytesHeld: this.store.bytesHeld,
      ...(this.exchange === null ? {} : { tree: this.exchange.stats() }) };
  }
}
