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
 * The follower's side of eager push (PDT 2 phase 7, P2-C-01, P2-P-02, P2-P-03, P2-Q-SEC-03; srad/agentspaces-pdt2.md
 * §3.4), a port of Java's `PushBundle` and `PushReceiver`. A writer that pushes announces the bundles of a delta on its
 * head ({@link ATTR}) and publishes the nodes as {@link PushBundle} rumours on the ref's stream `pdt:<space>:<name>`.
 *
 * A follower reads each bundle strictly, spends its bytes from the stream's token bucket, and holds its nodes aside, at
 * most `maxBytes` bytes and `maxBytes / 160` nodes per root and {@link PENDING_ROOTS} roots per stream; a root no head
 * announced never displaces an announced one. Once a live head announces the push of its root, the follower stores
 * each held node that hashes to a CID the root reaches through nodes the push stored, and drops the rest. The walk runs
 * once from the root and then resumes only at the links the push still lacks. A root the bundles complete needs no
 * request. The grace of an announced root is sized for lateness (swarm retries, ROBUSTNESS.md §10.3 P4): the repair
 * window by which a member has asked a second announcer, plus the bundles at the stream's budget, between `grace` and
 * `maxGrace`; past it the follower fetches what is missing and still stores late bundles for two graces. A bundle
 * outside its grammar, a bound, or a budget is dropped, counted, and never forwarded; nobody is struck (rule 16).
 */

import type { CborValue } from "../cbor.js";
import { cryptoPort } from "../crypto.js";
import { readRecord, type Schema } from "../records.js";
import type { Dict } from "../wire.js";
import * as cids from "./cids.js";
import { links as nodeLinks } from "./nodes.js";
import { NodeStore } from "./store.js";

/** The head attribute that announces a push: the canonical decimal count of its bundles (§3.4). */
export const ATTR = "pdt.push";
/** The version of the bundle record. */
export const VERSION = 1;
/** The most bytes of nodes one bundle carries: 1 MiB. */
export const MAX_BYTES = 1 << 20;
/** The most parts of one delta. */
export const MAX_PARTS = 64;
/** Roots whose bundles one stream holds at once. */
export const PENDING_ROOTS = 4;
/** Graces a root's bundles are held before they go, announced or not. */
export const ORPHAN_GRACES = 2;
/** What keeping one node aside costs beyond its bytes, so a root holds at most `maxBytes / 160` nodes. */
export const HELD_NODE_OVERHEAD = 160;
/**
 * The time by which a member that missed a bundle's eager copy has asked a second member that announced it: Java's
 * repair window at its widest, 500 ms plus a spread of up to 4 s (swarm retries, ROBUSTNESS.md §10.5, A1).
 */
export const REPAIR_WINDOW_MILLIS = 4500;

/** `PushBundle` in Java field order (§6.10.4), read strictly. */
const BUNDLE: Schema = { record: "PushBundle", fields: [["v", "int"], ["root", "String", "nonNull"], ["seq", "long"],
  ["part", "int"], ["parts", "int"], ["nodes", { listOf: "bytes" }, "nonNull"]] };

/** The stream of a ref (P2-P-01). */
export const stream = (space: string, name: string): string => `pdt:${space}:${name}`;

/** The first rule a bundle breaks, or null. */
export function bundleViolation(b: Dict): string | null {
  if (b["v"] !== VERSION) {
    return `unsupported PushBundle version ${String(b["v"])}`;
  }
  if (!cids.isCid(b["root"])) {
    return `root is not a CID: ${String(b["root"])}`;
  }
  const seq = b["seq"];
  if ((typeof seq !== "number" && typeof seq !== "bigint") || seq < 0 || seq > 2 ** 53) {
    return `seq ${String(seq)} is outside 0 to 2^53`;
  }
  const part = Number(b["part"]), parts = Number(b["parts"]);
  if (parts < 1 || parts > MAX_PARTS || part < 0 || part >= parts) {
    return `part ${part} of ${parts} is outside 1 to ${MAX_PARTS} parts`;
  }
  const nodes = b["nodes"] as Uint8Array[];
  if (nodes.length === 0) {
    return "a bundle carries at least one node";
  }
  let bytes = 0;
  for (const node of nodes) {
    if (node.length === 0) {
      return "a bundle carries an empty node";
    }
    bytes += node.length;
  }
  return bytes > MAX_BYTES ? `a bundle carries at most ${MAX_BYTES} bytes of nodes, got ${bytes}` : null;
}

/** A bundle read strictly and within its bounds, or null. */
export function readBundle(payload: Uint8Array): Dict | null {
  const bundle = readRecord(payload, BUNDLE);
  return bundle === null || bundleViolation(bundle) !== null ? null : bundle;
}

/** The bundles a head announces under {@link ATTR}, or 0 when it announces none (Java's PushPublisher.announced). */
export function announced(attrs: { [key: string]: CborValue } | undefined): number {
  const text = attrs?.[ATTR];
  if (typeof text !== "string" || !/^[1-9][0-9]?$/.test(text)) {
    return 0;
  }
  const parts = Number(text);
  return parts <= MAX_PARTS ? parts : 0;
}

/** The follower's settings (Java's PushPublisher.Config). */
export interface PushConfig {
  /** The stream's token bucket refills this many bytes a second (2 MiB). */
  bytesPerSecond: number;
  /** The bucket's size and the most a root holds aside (8 MiB). */
  maxBytes: number;
  /** The floor of an announced root's grace (2 s), and its ceiling (15 s). */
  graceMillis: number;
  maxGraceMillis: number;
}

export const DEFAULT_PUSH: PushConfig = { bytesPerSecond: 2 << 20, maxBytes: 8 << 20, graceMillis: 2000, maxGraceMillis: 15_000 };

/** What a follower does with an announced root it does not hold: fetch at once, wait for the bundles, or fetch the rest. */
export type Wait = "none" | "wait" | "late";

class Assembly {
  anchored = -1;
  graceMillis = 0;
  late = false;
  readonly held = new Map<string, Uint8Array>();
  heldBytes = 0;
  readonly stored = new Set<string>();
  /** The links the walk could not follow yet, by digest, where it resumes when a bundle brings one. */
  readonly missing = new Map<string, string>();
  complete = false;

  constructor(readonly root: string, readonly created: number) {}
}

class Stream {
  readonly assemblies = new Map<string, Assembly>();
  constructor(public tokens: number, public refilled: number) {}
}

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export class PushReceiver {
  private readonly streams = new Map<string, Stream>();
  bundlesReceived = 0;
  bundlesDropped = 0;
  nodesStored = 0;
  bytesStored = 0;
  nodesDropped = 0;
  fallbacks = 0;

  constructor(private readonly store: NodeStore, private readonly clock: () => number, readonly config: PushConfig = DEFAULT_PUSH) {}

  /** The most nodes one root holds aside. */
  maxNodes(): number {
    return Math.floor(this.config.maxBytes / HELD_NODE_OVERHEAD);
  }

  /** Starts taking a stream's bundles. */
  follow(name: string): void {
    if (!this.streams.has(name)) {
      this.streams.set(name, new Stream(this.config.maxBytes, this.clock()));
    }
  }

  /** Stops taking a stream's bundles. */
  unfollow(name: string): void {
    this.streams.delete(name);
  }

  /**
   * Takes one bundle of a followed stream; returns whether this follower took it, which is what it forwards (PDT 2
   * phase 5 adversary, A4): a bundle under a root already complete goes on, since another follower may lack its nodes.
   */
  onBundle(name: string, payload: Uint8Array): boolean {
    const s = this.streams.get(name);
    if (s === undefined) {
      return true; // a stream this follower does not take is relayed unread (rule 16)
    }
    const bundle = readBundle(payload);
    if (bundle === null) {
      this.bundlesDropped += 1;
      return false;
    }
    const now = this.clock();
    s.tokens = Math.min(this.config.maxBytes, s.tokens + (now - s.refilled) * (this.config.bytesPerSecond / 1000));
    s.refilled = now;
    if (s.tokens < payload.length) {
      this.bundlesDropped += 1;
      return false;
    }
    s.tokens -= payload.length;
    const root = String(bundle["root"]);
    let a = s.assemblies.get(root);
    if (a === undefined) {
      if (!this.room(s, false)) {
        this.bundlesDropped += 1; // every root this stream holds was announced
        return false;
      }
      a = new Assembly(root, now);
      s.assemblies.set(root, a);
    }
    const nodes = bundle["nodes"] as Uint8Array[];
    if (a.complete) {
      this.bundlesReceived += 1;
      this.nodesDropped += nodes.length;
      return true;
    }
    const bytes = nodes.reduce((n, node) => n + node.length, 0);
    if (a.heldBytes + bytes > this.config.maxBytes || a.held.size + nodes.length > this.maxNodes()) {
      this.bundlesDropped += 1;
      return false;
    }
    this.bundlesReceived += 1;
    const found: string[] = [];
    for (const node of nodes) {
      const digest = hex(cryptoPort().sha256(node));
      if (!a.held.has(digest)) {
        a.held.set(digest, node);
        a.heldBytes += node.length;
        const link = a.missing.get(digest);
        if (link !== undefined) {
          a.missing.delete(digest);
          found.push(link);
        }
      }
    }
    if (found.length > 0) {
      this.walk(a, found);
    }
    return true;
  }

  /**
   * Makes room for one more root: a complete root goes first, then the oldest no head announced, and an announced
   * root displaces the oldest announced one only for another announced root. False when there is no room.
   */
  private room(s: Stream, announcedRoot: boolean): boolean {
    if (s.assemblies.size < PENDING_ROOTS) {
      return true;
    }
    const values = [...s.assemblies.values()];
    const gone = values.find((a) => a.complete) ?? values.find((a) => a.anchored < 0) ?? (announcedRoot ? values[0] : undefined);
    if (gone === undefined) {
      return false;
    }
    this.nodesDropped += gone.held.size;
    s.assemblies.delete(gone.root);
    return true;
  }

  /** A live head announced the push of its root: the held nodes the root reaches are stored now, the rest as they come. */
  expect(name: string, root: string, parts: number): void {
    const s = this.streams.get(name);
    if (s === undefined) {
      return;
    }
    const now = this.clock();
    let a = s.assemblies.get(root);
    if (a === undefined) {
      this.room(s, true);
      a = new Assembly(root, now);
      s.assemblies.set(root, a);
    }
    if (a.anchored < 0) {
      a.anchored = now;
      a.graceMillis = this.grace(parts);
      this.walk(a, [root]);
    }
  }

  /** The wait for an announced push of `parts` bundles: the repair window plus the bundles at the stream's budget. */
  grace(parts: number): number {
    const sized = REPAIR_WINDOW_MILLIS + parts * MAX_BYTES * 1000 / this.config.bytesPerSecond;
    return Math.max(this.config.graceMillis, Math.min(this.config.maxGraceMillis, sized));
  }

  private walk(a: Assembly, from: string[]): void {
    const frontier = [...from];
    while (frontier.length > 0) {
      const cid = frontier.shift()!;
      if (a.stored.has(cid) || this.store.has(cid) || !cids.isCid(cid)) {
        continue;
      }
      const digest = hex(cids.parse(cid).digest);
      const bytes = a.held.get(digest);
      if (bytes === undefined) {
        a.missing.set(digest, cid);
        continue;
      }
      a.held.delete(digest);
      a.heldBytes -= bytes.length;
      try {
        this.store.putVerified(cid, bytes);
      } catch {
        this.nodesDropped += 1;
        a.missing.set(digest, cid);
        continue;
      }
      a.stored.add(cid);
      this.nodesStored += 1;
      this.bytesStored += bytes.length;
      if (cids.parse(cid).codec === cids.DAG_CBOR) {
        try {
          frontier.push(...nodeLinks(bytes, cid));
        } catch {
          // a node that does not decode links nothing
        }
      }
    }
    if (a.missing.size === 0) {
      a.complete = true;
      this.nodesDropped += a.held.size; // what the root does not reach was never part of its delta
      a.held.clear();
      a.heldBytes = 0;
    }
  }

  /** Whether a follower waits for the push of a root it does not hold. */
  check(name: string, root: string, now: number): Wait {
    const a = this.streams.get(name)?.assemblies.get(root);
    if (a === undefined || a.anchored < 0 || a.complete) {
      return "none";
    }
    if (now - a.anchored < a.graceMillis) {
      return "wait";
    }
    if (!a.late) {
      a.late = true;
      this.fallbacks += 1;
    }
    return "late";
  }

  /** Drops the bundles of roots held too long: two of its graces after an announcement, two floor graces otherwise. */
  expire(now: number): void {
    const floor = this.config.graceMillis * ORPHAN_GRACES;
    for (const s of this.streams.values()) {
      for (const a of [...s.assemblies.values()]) {
        const anchored = a.anchored >= 0;
        if (now - (anchored ? a.anchored : a.created) > (anchored ? a.graceMillis * ORPHAN_GRACES : floor)) {
          if (anchored && !a.complete && !a.late) {
            this.fallbacks += 1; // a tick that came after two graces: the follower fetches the root without a "late" check
          }
          this.nodesDropped += a.held.size;
          s.assemblies.delete(a.root);
        }
      }
    }
  }

  stats(): Dict {
    return { bundlesReceived: this.bundlesReceived, bundlesDropped: this.bundlesDropped, nodesStored: this.nodesStored,
      bytesStored: this.bytesStored, nodesDropped: this.nodesDropped, fallbacks: this.fallbacks };
  }
}
