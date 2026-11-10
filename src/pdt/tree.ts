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
 * The tree exchange over the content swarm (srad/agentspaces-pdt.md §3.5, group X, PD-P-03, §10.2):
 * four messages beside the swarm's seven, as tagged CBOR inside `PIPE_DATA` under
 * `aspace:cap/content-swarm`.
 *
 * | Tag | Message     | Fields                                  |
 * |-----|-------------|-----------------------------------------|
 * | 8   | `NODE_WANT` | req, cids (at most 256)                 |
 * | 9   | `NODES`     | req, nodes or sealed + epoch, missing   |
 * | 10  | `TREE_WANT` | req, root, haves (at most 64), budget   |
 * | 11  | `TREE_END`  | req, frontier (at most 1,024), reason   |
 *
 * The holder (`TreeServer`) walks a `TREE_WANT` breadth first, prunes every subtree under a `haves` root
 * it holds, stops at the budget or the walk cap, and closes with `TREE_END`; with `haves` it holds none
 * of, it sends two levels and closes with reason 3. The fetcher (`TreeFetch`) asks for the root, then one
 * `TREE_WANT` per child subtree spread over the top sources, then `NODE_WANT` batches for the frontier;
 * every node verifies against a CID the fetch asked for or reached through a verified parent, and a node
 * that fails strikes its sender. `REJECT` (tag 5) is reused with `index` -1. A peer sends tags 8 to 11
 * only to a member whose content-swarm advertisement carries `trees = "1"` (PD-X-01).
 *
 * Sealing (`group-key`): a holder with the group's content key seals the canonical CBOR of the nodes list
 * under the write epoch with AES-256-GCM and AAD `aspace:pdt|<recipient>|<req>`; a keyless holder refuses
 * a requester in a group that seals.
 */

import { concat, utf8 } from "../bytes.js";
import { canonicalMap, dumps, loads } from "../cbor.js";
import { cryptoPort } from "../crypto.js";
import type { Content } from "../capabilities/content.js";
import { HOLDING_TYPE, REASON_NOT_HELD, REASON_OVER_BUDGET, REASON_POLICY, REASON_UNKNOWN_ROOT, REJECT,
  SEALING_GROUP_KEY, SEALING_NONE, TYPE as CONTENT_TYPE, holdingTags } from "../capabilities/content.js";
import { instantIso } from "../identity.js";
import type { Peer } from "../peer.js";
import { readRecord, type Schema } from "../records.js";
import { durationMillis } from "../space.js";
import type { Dict } from "../wire.js";
import * as cids from "./cids.js";
import * as dcz from "./dcz.js";
import { NodeStore } from "./store.js";
import { SketchServer, SketchSession, SketchSet, MAX_SKETCH_BYTES } from "./sync.js";
import type { Outcome } from "./sync.js";

export const NODE_WANT = 8, NODES = 9, TREE_WANT = 10, TREE_END = 11;
/**
 * A possession challenge (PDT 2 phase 7, P2-C-01; srad/agentspaces-pdt2.md §3.2.4, §6.10.3 row 15): a level-2 form,
 * answered with `NODES` for the picks held and `REJECT` reason 1 for a root held not at all.
 */
export const CHALLENGE = 12;
export const END_DONE = 1, END_BUDGET = 2, END_HAVES_NOT_HELD = 3, END_WALK_CAP = 4;
/** A reconciliation round answering a sketch `TREE_WANT`: an empty frontier and the reply in `sketch` (rule 13). */
export const END_SKETCH = 5;
/** The most picks one `CHALLENGE` names (§3.2.4). */
export const MAX_PICKS = 16;
export const MAX_WANT_CIDS = 256;
export const MAX_NODES_BYTES = 4 * 1024 * 1024;
export const MAX_HAVES = 64;
export const MAX_BUDGET = 64 * 1024 * 1024;
export const MAX_FRONTIER = 1024;
export const MAX_WALK_NODES = 100_000;
/** The `index` of a REJECT that answers a tree request. */
export const TREE_INDEX = -1;
export const TREES_PARAMETER = "trees";
export const TREES_VERSION = "1";
/**
 * The PDT feature level on the content-swarm advertisement (PDT 2 phase 0, P2-F-05; srad/agentspaces-pdt2.md
 * §6.10.2): a member sends a level-2 form (`TREE_WANT.sketch`, `TREE_END.sketch`, `NODES.deltas`, tag 12)
 * only to a member whose newest unexpired advertisement states 2 or above. `trees` stays "1", which 0.5.0
 * peers compare exactly. This client advertises no level, so it stands at level 1 until its decoders carry
 * every level-2 schema of §6.10.4 (P2-C-01).
 */
export const PDT_PARAMETER = "pdt";
/** The PDT feature level this client stands at by default (PDT 2 phase 7, P2-C-01). */
export const PDT_LEVEL = 2;
/** "0", or a non-zero ASCII digit followed by ASCII digits: the one spelling of each level. */
const CANONICAL_DECIMAL = /^(?:0|[1-9][0-9]*)$/;

/**
 * The PDT feature level a content-swarm advertisement states (P2-F-05): its `pdt` parameter as canonical
 * decimal text, and level 1 for an absent advertisement, an absent parameter, or any other value, since
 * every 0.5.0 peer that advertises `trees = "1"` stands there. A level past 2^53 - 1 reads as 2^53 - 1.
 */
export function featureLevel(ad: Dict | null): number {
  const parameters = ad?.["parameters"];
  const text = typeof parameters === "object" && parameters !== null ? (parameters as Dict)[PDT_PARAMETER] : undefined;
  if (typeof text !== "string" || !CANONICAL_DECIMAL.test(text)) {
    return 1;
  }
  return Math.max(1, Math.min(Number(text), Number.MAX_SAFE_INTEGER));
}
export const SEALING_AAD_PREFIX = "aspace:pdt|";
export const CAPABILITY_AD_TYPE = "CapabilityAdvertisement";
export const ADVERTISEMENT_TTL_MILLIS = 15 * 60 * 1000;
const LEVELS_WITHOUT_HAVES = 2;
const NODE_FRAMING_BYTES = 5;
const MESSAGE_FRAMING_BYTES = 5 + 12 + 16;

// ------------------------------------------------------------------ messages

export const nodeWant = (req: number, cidList: string[]): Dict => ({ t: NODE_WANT, req, cids: cidList });
export const nodesMessage = (req: number, nodes: Uint8Array[], missing: string[] | null = null): Dict =>
  ({ t: NODES, req, nodes, sealed: null, epoch: null, missing });
export const sealedNodes = (req: number, sealed: Uint8Array, epoch: number, missing: string[] | null = null): Dict =>
  ({ t: NODES, req, nodes: null, sealed, epoch, missing });
export const treeWant = (req: number, root: string, haves: string[], budget = MAX_BUDGET): Dict =>
  ({ t: TREE_WANT, req, root, haves, budget, sketch: null });
export const treeEnd = (req: number, frontier: string[], reason: number): Dict => ({ t: TREE_END, req, frontier, reason });
/** A sketch `TREE_WANT` (rule 12, P2-K-02): root `""`, no haves, and the sketch; sent only to a level-2 member. */
export const sketchWant = (req: number, sketch: Uint8Array, budget = 64 * 1024): Dict =>
  ({ t: TREE_WANT, req, root: "", haves: [], budget, sketch });
/** A reconciliation round's answer (rule 13): reason 5, an empty frontier, and the reply appended last. */
export const sketchEnd = (req: number, sketch: Uint8Array): Dict => ({ t: TREE_END, req, frontier: [], reason: END_SKETCH, sketch });
/** A possession challenge (P2-S-07): picks of nodes by CID, or of chunk groups by `{cid, offset, length}`. */
export const challengeMessage = (req: number, root: string, picks: Dict[]): Dict => ({ t: CHALLENGE, req, root, picks });
export const treeReject = (root: string, reason: number): Dict => ({ t: REJECT, root, index: TREE_INDEX, reason });

/**
 * The tree messages and the tree `REJECT` as Java's `Messages` records declare them (PDT 2 phase 1,
 * P2-X-09): every field present in this order, a null written as null, and no other field, so a receiver
 * reads a frame as Java's `fromWire` does and a relabelled one is undecodable.
 */
const NODE_DELTA: Schema = { record: "Messages.NodeDelta", fields: [["cid", "String", "nonNull"], ["base", "String", "nonNull"],
  ["dcz", "bytes", "nonNull"]] };
const PICK: Schema = { record: "Messages.Pick", fields: [["cid", "String", "nonNull"], ["offset", "Long", "omitNull"],
  ["length", "Integer", "omitNull"]] };
/**
 * The level-2 schemas of §6.10.4 (PDT 2 phase 7, P2-C-01, P2-F-07) join the level-1 fields: `NODES.deltas` and
 * `TREE_END.sketch` appended last and absent when null, so a message without them keeps its level-1 bytes, and the
 * `CHALLENGE` of tag 12.
 */
const TREE_SCHEMAS: ReadonlyMap<number, Schema> = new Map<number, Schema>([
  [NODE_WANT, { record: "Messages.NodeWant", fields: [["t", "int"], ["req", "int"], ["cids", { listOf: "String" }]] }],
  [NODES, { record: "Messages.Nodes", fields: [["t", "int"], ["req", "int"], ["nodes", { listOf: "bytes" }],
    ["sealed", "bytes"], ["epoch", "Long"], ["missing", { listOf: "String" }], ["deltas", { listOf: NODE_DELTA }, "omitNull"]] }],
  [TREE_WANT, { record: "Messages.TreeWant", fields: [["t", "int"], ["req", "int"], ["root", "String"],
    ["haves", { listOf: "String" }], ["budget", "long"], ["sketch", "bytes"]] }],
  [TREE_END, { record: "Messages.TreeEnd", fields: [["t", "int"], ["req", "int"], ["frontier", { listOf: "String" }],
    ["reason", "int"], ["sketch", "bytes", "omitNull"]] }],
  [CHALLENGE, { record: "Messages.Challenge", fields: [["t", "int"], ["req", "int"], ["root", "String"],
    ["picks", { listOf: PICK }]] }],
  [REJECT, { record: "Messages.Reject", fields: [["t", "int"], ["root", "String"], ["index", "int"], ["reason", "int"]] }],
]);

/**
 * A tree message or tree `REJECT` read strictly (PDT 2 phase 1, P2-X-09): the frame's tag names its
 * schema, the bytes are exactly that record's wire encoding, and a tree message keeps every bound of
 * {@link treeViolation}; null for anything else, which the receiver counts and strikes nobody for.
 */
export function readTreeMessage(payload: Uint8Array): Dict | null {
  const tag = peekTag(payload);
  const schema = TREE_SCHEMAS.get(tag);
  const msg = schema === undefined ? null : readRecord(payload, schema);
  if (msg === null || msg["t"] !== tag) {
    return null;
  }
  return tag === REJECT || treeViolation(msg) === null ? msg : null;
}

/** The tag of a content-swarm frame from its first bytes (the map's first key is `t`), or 0. */
export function peekTag(payload: Uint8Array): number {
  if (payload.length < 4 || payload[0] !== 0xbf || payload[1] !== 0x61 || payload[2] !== 0x74) {
    return 0;
  }
  const head = payload[3]!;
  if (head < 24) {
    return head;
  }
  if (head === 24 && payload.length > 4) {
    return payload[4]!;
  }
  return 0;
}

function cidList(value: unknown, max: number): string[] | null {
  if (value === null || value === undefined) {
    return [];
  }
  if (!Array.isArray(value) || value.length > max) {
    return null;
  }
  for (const item of value) {
    if (!cids.isCid(item)) {
      return null;
    }
  }
  return value as string[];
}

/** Whether a `TREE_WANT` is a reconciliation round (rule 12): root `""` with a sketch. */
export function isSketchWant(msg: Dict): boolean {
  return msg["t"] === TREE_WANT && msg["root"] === "" && msg["sketch"] instanceof Uint8Array;
}

/** Whether text is a BLAKE3 identity in its canonical form: CIDv1 `raw` over multihash 0x1e, 32 bytes (P2-B-01). */
function isIdentity(text: unknown): boolean {
  if (typeof text !== "string" || !text.startsWith("b")) {
    return false;
  }
  try {
    const binary = cids.base32Decode(text.slice(1));
    return binary.length === 36 && binary[0] === 0x01 && binary[1] === cids.RAW && binary[2] === 0x1e && binary[3] === 0x20
      && "b" + cids.base32Lower(binary) === text;
  } catch {
    return false;
  }
}

/** The first bound a tree message breaks (PD-X-02), or null. */
export function treeViolation(msg: Dict): string | null {
  const req = msg["req"];
  if (typeof req !== "number") {
    return "req is not a number";
  }
  switch (msg["t"]) {
    case NODE_WANT: {
      const list = cidList(msg["cids"], MAX_WANT_CIDS);
      return list === null || list.length === 0 ? `a NODE_WANT carries 1 to ${MAX_WANT_CIDS} CIDs` : null;
    }
    case NODES: {
      const nodes = msg["nodes"], sealed = msg["sealed"];
      if ((nodes == null) === (sealed == null)) {
        return "a NODES carries exactly one of nodes and sealed";
      }
      if ((sealed != null) !== (msg["epoch"] != null)) {
        return "epoch is present iff sealed is";
      }
      if (sealed != null && msg["deltas"] != null) {
        // PDT 2 phase 4 measures (srad/agentspaces-pdt2.md §10.14): frames travel in plaintext answers only
        return "a sealed NODES carries no deltas";
      }
      let bytes = 0;
      if (nodes != null) {
        if (!Array.isArray(nodes)) {
          return "nodes is not a list";
        }
        for (const n of nodes) {
          if (!(n instanceof Uint8Array)) {
            return "a node is not a byte string";
          }
          bytes += n.length;
        }
      } else if (sealed instanceof Uint8Array) {
        bytes = sealed.length;
      } else {
        return "sealed is not a byte string";
      }
      if (bytes > MAX_NODES_BYTES) {
        return `a NODES carries at most ${MAX_NODES_BYTES} bytes of nodes, got ${bytes}`;
      }
      const deltas = msg["deltas"];
      if (deltas != null) {
        if (!Array.isArray(deltas) || deltas.length > MAX_WANT_CIDS) {
          return `a NODES carries at most ${MAX_WANT_CIDS} deltas`;
        }
        for (const delta of deltas as Dict[]) {
          if (!cids.isCid(delta["cid"]) || !cids.isCid(delta["base"]) || !(delta["dcz"] instanceof Uint8Array)) {
            return "deltas holds an entry without a CID, a base CID, and a frame";
          }
          bytes += delta["dcz"].length;
        }
        if (bytes > MAX_NODES_BYTES) {
          return `a NODES carries at most ${MAX_NODES_BYTES} bytes of nodes and deltas, got ${bytes}`;
        }
      }
      const missing = cidList(msg["missing"], MAX_WANT_CIDS);
      return missing === null ? `a NODES names at most ${MAX_WANT_CIDS} missing CIDs` : null;
    }
    case TREE_WANT: {
      if (isSketchWant(msg)) {
        const listed = msg["haves"];
        if (Array.isArray(listed) && listed.length > 0) {
          return "a sketch TREE_WANT names no haves";
        }
        const sketchBudget = Number(msg["budget"]);
        return sketchBudget > 0 && sketchBudget <= MAX_BUDGET ? null : `budget is outside (0, ${MAX_BUDGET}]`;
      }
      if (!cids.isCid(msg["root"])) {
        return "root is not a CID";
      }
      const haves = cidList(msg["haves"], MAX_HAVES);
      if (haves === null) {
        return `a TREE_WANT names at most ${MAX_HAVES} haves`;
      }
      const budget = Number(msg["budget"]);
      return budget > 0 && budget <= MAX_BUDGET ? null : `budget is outside (0, ${MAX_BUDGET}]`;
    }
    case TREE_END: {
      const frontier = cidList(msg["frontier"], MAX_FRONTIER);
      if (frontier === null || msg["frontier"] == null) {
        return `a TREE_END names at most ${MAX_FRONTIER} frontier cids`;
      }
      const reason = Number(msg["reason"]);
      if (reason < END_DONE || reason > END_SKETCH) {
        return "unknown reason";
      }
      if ((reason === END_SKETCH) !== (msg["sketch"] != null)) {
        return `a TREE_END carries a sketch exactly when its reason is ${END_SKETCH}`;
      }
      return reason === END_SKETCH && frontier.length > 0 ? "a sketch TREE_END carries an empty frontier" : null;
    }
    case CHALLENGE: {
      if (!cids.isCid(msg["root"])) {
        return "root is not a CID";
      }
      const picks = msg["picks"];
      if (!Array.isArray(picks) || picks.length === 0 || picks.length > MAX_PICKS) {
        return `a CHALLENGE names 1 to ${MAX_PICKS} picks`;
      }
      for (const pick of picks as Dict[]) {
        const offset = pick["offset"], length = pick["length"];
        if ((offset == null) !== (length == null)) {
          return "a pick carries both or neither of offset and length";
        }
        if (offset == null ? !cids.isCid(pick["cid"]) : !isIdentity(pick["cid"])) {
          return "a node pick names a sha2-256 CID and a chunk-group pick a BLAKE3 identity";
        }
        if (offset != null && (Number(offset) < 0 || Number(length) <= 0 || Number(length) > MAX_NODES_BYTES)) {
          return `a chunk-group pick holds an offset of at least 0 and a length in (0, ${MAX_NODES_BYTES}]`;
        }
      }
      return null;
    }
    default:
      return "unknown tag";
  }
}

// ------------------------------------------------------------------ keys and sealing

/** The group's content keys by epoch: the TypeScript client holds the keys an invite or a host gives it. */
export class ContentKeys {
  private readonly keys = new Map<number, Uint8Array>();

  constructor(keys: Iterable<[number, Uint8Array]> = []) {
    for (const [epoch, key] of keys) {
      this.install(epoch, key);
    }
  }

  /** A ring of one key as epoch 0 (an invite's content key). */
  static of(epochZero: Uint8Array): ContentKeys {
    return new ContentKeys([[0, epochZero]]);
  }

  install(epoch: number, key: Uint8Array): void {
    if (key.length !== 32) {
      throw new Error(`a content key has 32 bytes, got ${key.length}`);
    }
    this.keys.set(epoch, new Uint8Array(key));
  }

  /** The newest epoch held: what a holder seals under. */
  writeEpoch(): number {
    return Math.max(...this.keys.keys());
  }

  key(epoch: number): Uint8Array | undefined {
    return this.keys.get(epoch);
  }

  epochs(): number[] {
    return [...this.keys.keys()].sort((a, b) => a - b);
  }
}

const subtle = (): SubtleCrypto => {
  const s = (globalThis.crypto as Crypto | undefined)?.subtle;
  if (s === undefined) {
    throw new Error("WebCrypto is not available here; group-key sealing needs crypto.subtle");
  }
  return s;
};

/** A copy over a plain ArrayBuffer, the type WebCrypto's declarations accept. */
const plain = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(bytes);

/** AES-256-GCM with a 12-byte random nonce in front and the 16-byte tag behind, as the Java `GroupKey` seals. */
export async function seal(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  const nonce = cryptoPort().randomBytes(12);
  const k = await subtle().importKey("raw", plain(key), { name: "AES-GCM" }, false, ["encrypt"]);
  const sealed = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: plain(nonce), additionalData: plain(aad), tagLength: 128 },
    k, plain(plaintext)));
  return concat(nonce, sealed);
}

/** Opens what `seal` produced, or returns null. */
export async function open(key: Uint8Array, sealed: Uint8Array, aad: Uint8Array): Promise<Uint8Array | null> {
  if (sealed.length <= 12) {
    return null;
  }
  try {
    const k = await subtle().importKey("raw", plain(key), { name: "AES-GCM" }, false, ["decrypt"]);
    return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: plain(sealed.subarray(0, 12)), additionalData: plain(aad),
      tagLength: 128 }, k, plain(sealed.subarray(12))));
  } catch {
    return null;
  }
}

export function sealingAad(recipient: string, req: number): Uint8Array {
  return utf8(`${SEALING_AAD_PREFIX}${recipient}|${req}`);
}

// ------------------------------------------------------------------ the holder

export interface ServerHost {
  mayServe(from: string, cid: string): boolean;
  withinUploadBudget(bytes: number): boolean;
  /** A NODES for `to`, sealed when the group seals; null when this host cannot seal (REJECT 3 follows). */
  seal(to: string, req: number, nodes: Uint8Array[], missing: string[] | null): Promise<Dict | null>;
  send(to: string, message: Dict): void;
  served?(nodes: number, bytes: number): void;
  nowMillis?(): number;
}

/** The holder side of the exchange (PD-X-03): the breadth-first walk with pruning, budgets, and the walk cap. */
export class TreeServer {
  rejected = 0;
  dropped = 0;
  nodesServed = 0;
  nodesWalked = 0;
  private readonly pruneCache = new Map<string, { at: number; cids: Set<string> }>();

  constructor(readonly store: NodeStore, readonly host: ServerHost, readonly walkCap = MAX_WALK_NODES) {}

  private now(): number {
    return this.host.nowMillis?.() ?? Date.now();
  }

  async serveNodeWant(from: string, want: Dict): Promise<void> {
    if (treeViolation(want) !== null) {
      this.dropped += 1;
      return;
    }
    const list = want["cids"] as string[];
    const req = Number(want["req"]);
    const first = list[0]!;
    for (const cid of list) {
      if (!this.host.mayServe(from, cid)) {
        this.reject(from, first, REASON_POLICY);
        return;
      }
    }
    if (!(await this.canSeal(from, req))) {
      this.reject(from, first, REASON_POLICY);
      return;
    }
    let batch: Uint8Array[] = [];
    const missing: string[] = [];
    let packed = MESSAGE_FRAMING_BYTES;
    let overBudget = false;
    for (const cid of list) {
      const bytes = this.store.get(cid);
      if (bytes === undefined) {
        missing.push(cid);
        continue;
      }
      if (!this.host.withinUploadBudget(bytes.length)) {
        overBudget = true;
        break;
      }
      if (packed + bytes.length + NODE_FRAMING_BYTES > MAX_NODES_BYTES && batch.length > 0) {
        if (!(await this.flush(from, req, first, batch, null))) {
          return;
        }
        batch = [];
        packed = MESSAGE_FRAMING_BYTES;
      }
      batch.push(bytes);
      packed += bytes.length + NODE_FRAMING_BYTES;
    }
    if (overBudget) {
      if (batch.length > 0 || missing.length > 0) {
        if (!(await this.flush(from, req, first, batch, missing))) {
          return;
        }
      }
      this.reject(from, first, REASON_OVER_BUDGET);
      return;
    }
    await this.flush(from, req, first, batch, missing);
  }

  async serveTreeWant(from: string, want: Dict): Promise<void> {
    if (treeViolation(want) !== null) {
      this.dropped += 1;
      return;
    }
    const root = String(want["root"]);
    const req = Number(want["req"]);
    const budget = Number(want["budget"]);
    if (!this.host.mayServe(from, root)) {
      this.reject(from, root, REASON_POLICY);
      return;
    }
    if (!this.store.has(root)) {
      this.reject(from, root, REASON_NOT_HELD);
      return;
    }
    if (!(await this.canSeal(from, req))) {
      this.reject(from, root, REASON_POLICY);
      return;
    }
    const haves = (want["haves"] as string[] | null) ?? [];
    const prune = new Set<string>();
    let anyHaveHeld = false;
    let pruneBudget = this.walkCap;
    for (const have of new Set(haves)) {
      if (!this.store.has(have)) {
        continue;
      }
      anyHaveHeld = true;
      if (pruneBudget <= 0) {
        continue;
      }
      const reachable = this.reachableFor(have, pruneBudget);
      pruneBudget -= reachable.size;
      for (const cid of reachable) {
        prune.add(cid);
      }
    }
    const topLevelsOnly = haves.length > 0 && !anyHaveHeld;
    const maxDepth = topLevelsOnly ? LEVELS_WITHOUT_HAVES - 1 : Number.POSITIVE_INFINITY;
    const queue: [string, number][] = [[root, 0]];
    const visited = new Set<string>([root]);
    let batch: Uint8Array[] = [];
    let missing: string[] = [];
    let packed = MESSAGE_FRAMING_BYTES;
    let sent = 0, walked = 0;
    let reason = END_DONE;
    let sentAnything = false;
    while (queue.length > 0) {
      const [cid, depth] = queue[0]!;
      if (walked >= this.walkCap) {
        reason = END_WALK_CAP;
        break;
      }
      if (depth > maxDepth) {
        reason = END_HAVES_NOT_HELD;
        break;
      }
      const bytes = this.store.get(cid);
      if (bytes === undefined) {
        queue.shift();
        if (missing.length < MAX_WANT_CIDS) {
          missing.push(cid);
        }
        continue;
      }
      if (sent + bytes.length > budget) {
        reason = END_BUDGET;
        break;
      }
      if (!this.host.withinUploadBudget(bytes.length)) {
        if (!sentAnything && batch.length === 0) {
          this.reject(from, root, REASON_OVER_BUDGET);
          return;
        }
        reason = END_BUDGET;
        break;
      }
      queue.shift();
      walked += 1;
      this.nodesWalked += 1;
      if (packed + bytes.length + NODE_FRAMING_BYTES > MAX_NODES_BYTES && batch.length > 0) {
        if (!(await this.flush(from, req, root, batch, missing))) {
          return;
        }
        sentAnything = true;
        batch = [];
        missing = [];
        packed = MESSAGE_FRAMING_BYTES;
      }
      batch.push(bytes);
      packed += bytes.length + NODE_FRAMING_BYTES;
      sent += bytes.length;
      for (const child of this.store.links(cid)) {
        if (!prune.has(child) && !visited.has(child)) {
          visited.add(child);
          queue.push([child, depth + 1]);
        }
      }
    }
    if (batch.length > 0 || missing.length > 0) {
      if (!(await this.flush(from, req, root, batch, missing))) {
        return;
      }
    }
    const frontier = queue.slice(0, MAX_FRONTIER).map(([cid]) => cid);
    if (reason === END_DONE && queue.length > 0) {
      reason = END_BUDGET;
    }
    this.host.send(from, treeEnd(req, frontier, reason));
  }

  /**
   * Answers a `CHALLENGE` (PDT 2 phase 7, P2-C-01, P2-S-07; Java's TreeServer.serve(Challenge)): each pick is granted
   * as a `NODE_WANT`'s CID is, the held picks go back in `NODES` under the challenge's `req` with the rest in
   * `missing`, and a holder of no pick refuses the root with `REJECT` reason 1. A chunk-group pick is answered missing.
   */
  async serveChallenge(from: string, challenge: Dict): Promise<void> {
    if (treeViolation(challenge) !== null) {
      this.dropped += 1;
      return;
    }
    const root = String(challenge["root"]);
    const req = Number(challenge["req"]);
    const picks = challenge["picks"] as Dict[];
    if (!this.host.mayServe(from, root) || picks.some((p) => !this.host.mayServe(from, String(p["cid"])))) {
      this.reject(from, root, REASON_POLICY);
      return;
    }
    if (!(await this.canSeal(from, req))) {
      this.reject(from, root, REASON_POLICY);
      return;
    }
    const held: Uint8Array[] = [];
    const missing: string[] = [];
    let total = 0;
    for (const pick of picks) {
      const bytes = pick["offset"] == null ? this.store.get(String(pick["cid"])) : undefined;
      if (bytes === undefined) {
        missing.push(String(pick["cid"]));
      } else {
        held.push(bytes);
        total += bytes.length;
      }
    }
    if (held.length === 0) {
      this.reject(from, root, REASON_NOT_HELD);
      return;
    }
    if (!this.host.withinUploadBudget(total)) {
      this.reject(from, root, REASON_OVER_BUDGET);
      return;
    }
    let batch: Uint8Array[] = [];
    let packed = MESSAGE_FRAMING_BYTES;
    for (const bytes of held) {
      if (packed + bytes.length + NODE_FRAMING_BYTES > MAX_NODES_BYTES && batch.length > 0) {
        if (!(await this.flush(from, req, root, batch, null))) {
          return;
        }
        batch = [];
        packed = MESSAGE_FRAMING_BYTES;
      }
      batch.push(bytes);
      packed += bytes.length + NODE_FRAMING_BYTES;
    }
    await this.flush(from, req, root, batch, missing);
  }

  private reachableFor(have: string, limit: number): Set<string> {
    const now = this.now();
    const cached = this.pruneCache.get(have);
    if (cached !== undefined && now - cached.at <= 10_000) {
      return cached.cids;
    }
    const reachable = this.walkReachable(have, limit);
    this.pruneCache.set(have, { at: now, cids: reachable });
    if (this.pruneCache.size > 32) {
      this.pruneCache.delete(this.pruneCache.keys().next().value!);
    }
    return reachable;
  }

  private walkReachable(root: string, limit: number): Set<string> {
    const seen = new Set<string>([root]);
    const queue = [root];
    let walked = 0;
    while (queue.length > 0 && walked < limit) {
      const cid = queue.shift()!;
      if (!this.store.has(cid)) {
        continue;
      }
      walked += 1;
      this.nodesWalked += 1;
      for (const child of this.store.links(cid)) {
        if (!seen.has(child)) {
          seen.add(child);
          queue.push(child);
        }
      }
    }
    for (const left of queue) {
      seen.delete(left);
    }
    return seen;
  }

  private async canSeal(to: string, req: number): Promise<boolean> {
    return (await this.host.seal(to, req, [], null)) !== null;
  }

  private async flush(to: string, req: number, root: string, batch: Uint8Array[], missing: string[] | null): Promise<boolean> {
    const message = await this.host.seal(to, req, batch, missing !== null && missing.length > 0 ? [...missing] : null);
    if (message === null) {
      this.reject(to, root, REASON_POLICY);
      return false;
    }
    let bytes = 0;
    for (const node of batch) {
      bytes += node.length;
    }
    this.nodesServed += batch.length;
    this.host.served?.(batch.length, bytes);
    this.host.send(to, message);
    return true;
  }

  private reject(to: string, root: string, reason: number): void {
    this.rejected += 1;
    this.host.send(to, treeReject(root, reason));
  }
}

// ------------------------------------------------------------------ the fetch

/**
 * The first bench of a source that answered `missing` for a CID, in milliseconds; each later such answer doubles it up
 * to {@link MISSING_BENCH_MAX_MILLIS} (swarm retries, ROBUSTNESS.md §10.3 B6 and E4).
 */
export const MISSING_BENCH_MILLIS = 1000;
export const MISSING_BENCH_MAX_MILLIS = 16_000;

class Source {
  window = 2;
  inFlight = 0;
  srttMillis = -1;
  timeouts = 0;
  droppedUntil = 0;
  bytesVerified = 0;
  /** Whether a frame of this source did not open, so the fetch opens none of its later frames (P2-Q-SEC-05). */
  framesRefused = false;
  /**
   * CIDs this source answered `missing` for, each with the clock time its bench ends and the answers so far: a holder
   * that lacked a node may hold it later, so the fetch asks it again once the bench ends, with a random spread.
   */
  private readonly benched = new Map<string, { until: number; answers: number }>();

  constructor(readonly peer: string, public via: string[] | null) {}

  usable(now: number): boolean {
    return this.droppedUntil <= now;
  }

  lacks(cid: string, now: number): boolean {
    const bench = this.benched.get(cid);
    return bench !== undefined && now < bench.until;
  }

  lack(cid: string, now: number): void {
    const bench = this.benched.get(cid) ?? { until: 0, answers: 0 };
    this.benched.set(cid, bench);
    if (now < bench.until) {
      return;
    }
    bench.answers += 1;
    const wait = Math.min(MISSING_BENCH_MAX_MILLIS, MISSING_BENCH_MILLIS * 2 ** (bench.answers - 1));
    bench.until = now + wait + Math.random() * wait / 2;
  }
}

interface Request {
  req: number;
  source: Source;
  kind: number;
  /** The CIDs asked for (`NODE_WANT`), matched in order. */
  cids: string[];
  matched: Set<number>;
  /** The subtree root of a `TREE_WANT`. */
  subtree: string | null;
  sent: number;
  delivered: number;
  duplicated: boolean;
}

export interface TreeProgress {
  nodesReceived: number;
  bytesReceived: number;
  bytesBySource: { [peer: string]: number };
  sourcesActive: number;
  roundTrips: number;
}

export interface FetchHost {
  readonly store: NodeStore;
  readonly selfId: string;
  nextReq(): number;
  send(to: string, message: Dict, via: string[] | null): void;
  /** Holders of a root, as `[peer, via]`. */
  holdersOf(root: string): [string, string[] | null][];
  advertisesTrees(peer: string): boolean;
  hopsTo(peer: string): number;
  /** Opens a NODES message (plaintext or sealed); null when it cannot be opened. */
  open(from: string, req: number, msg: Dict): Promise<Uint8Array[] | null>;
  strike(peer: string, reason: string): void;
  nowMillis(): number;
  /** Whether this peer reads the level-2 forms (P2-F-05), so a fetch applies `NODES.deltas` (P2-Z-01). */
  readsDeltas(): boolean;
}

/**
 * One tree fetch (PD-X-04 to PD-X-08): top down, parents before children, `TREE_WANT` walks per child
 * subtree across the top sources, then `NODE_WANT` batches for the frontier, every node verified against a
 * CID the fetch asked for or reached through a verified parent. A bare batch (`cids` given, no root) asks
 * for exactly those nodes.
 */
export class TreeFetch {
  static readonly MIN_TIMEOUT_MILLIS = 10_000;
  static readonly MAX_WINDOW = 16;
  static readonly TIMEOUTS_BEFORE_DROP = 3;
  static readonly DROP_MILLIS = 60_000;
  static readonly STALL_MILLIS = 10_000;

  readonly sources = new Map<string, Source>();
  private readonly requests = new Map<number, Request>();
  /** CIDs wanted and not yet asked for. */
  private readonly frontier = new Set<string>();
  /** CIDs a verified parent linked to or the fetch asked for: what a `NODES` may carry. */
  private readonly expected = new Set<string>();
  /** Child subtrees still to walk with a `TREE_WANT`. */
  private readonly subtreesPending: string[] = [];
  /** Subtrees whose walk delivered something and ended early: never walked again, finished by `NODE_WANT`. */
  private readonly walkedPartly = new Set<string>();
  readonly trace: string[] = [];
  done = false;
  failure: string | null = null;
  bytesReceived = 0;
  nodesReceived = 0;
  roundTrips = 0;
  /** Chunks rebuilt from an intra-chunk delta and verified, and deltas refused (PDT 2 phase 7, P2-Z-01). */
  deltasApplied = 0;
  deltasRefused = 0;
  private readonly started: number;
  private sourcesReadAt = 0;
  private stalledSince = 0;
  private rootAsked = false;
  private readonly waiters: (() => void)[] = [];
  private scheduling = false;

  constructor(private readonly host: FetchHost, readonly root: string | null, readonly haves: string[],
              readonly prefer: string[], readonly bare: string[] = []) {
    this.started = host.nowMillis();
    for (const cid of bare) {
      this.frontier.add(cid);
      this.expected.add(cid);
    }
  }

  get complete(): boolean {
    return this.done && this.failure === null;
  }

  await(timeoutMillis: number): Promise<boolean> {
    if (this.done) {
      return Promise.resolve(this.complete);
    }
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(this.complete), timeoutMillis);
      this.waiters.push(() => { clearTimeout(timer); resolve(this.complete); });
    });
  }

  progress(): TreeProgress {
    const bytesBySource: { [peer: string]: number } = {};
    let active = 0;
    for (const s of this.sources.values()) {
      bytesBySource[s.peer] = s.bytesVerified;
      if (s.inFlight > 0) {
        active += 1;
      }
    }
    return { nodesReceived: this.nodesReceived, bytesReceived: this.bytesReceived, bytesBySource, sourcesActive: active,
      roundTrips: this.roundTrips };
  }

  note(line: string): void {
    this.trace.push(line);
    if (this.trace.length > 256) {
      this.trace.splice(0, this.trace.length - 256);
    }
  }

  cancel(): void {
    if (!this.done) {
      this.failure = "cancelled";
      this.finish();
    }
  }

  private fail(reason: string): void {
    this.failure = reason;
    this.note(reason);
    this.finish();
  }

  private finish(): void {
    if (this.done) {
      return;
    }
    this.done = true;
    this.requests.clear();
    if (this.failure === null) {
      this.note(`complete: ${this.nodesReceived} nodes, ${this.bytesReceived} bytes in ${this.host.nowMillis() - this.started} ms`);
    }
    for (const w of this.waiters.splice(0)) {
      w();
    }
  }

  start(): void {
    this.refreshSources();
    if (this.root !== null) {
      if (this.host.store.has(this.root)) {
        this.planSubtrees();
      } else {
        this.expected.add(this.root);
      }
    }
    this.checkComplete();
    this.schedule();
  }

  /** Re-reads the holders (a holding appeared) and schedules. */
  holdingsChanged(): void {
    if (!this.done) {
      this.refreshSources();
      this.schedule();
    }
  }

  tick(): void {
    if (this.done) {
      return;
    }
    const now = this.host.nowMillis();
    this.timeOut(now);
    if (now - this.sourcesReadAt >= 5000) {
      this.refreshSources();
    }
    this.schedule();
    this.checkStalled(now);
  }

  private refreshSources(): void {
    this.sourcesReadAt = this.host.nowMillis();
    const candidates = new Map<string, string[] | null>();
    const roots = this.root === null ? [] : [this.root, ...this.haves];
    for (const root of roots) {
      for (const [peer, via] of this.host.holdersOf(root)) {
        if (!candidates.has(peer)) {
          candidates.set(peer, via);
        }
      }
    }
    for (const cid of this.bare) {
      for (const [peer, via] of this.host.holdersOf(cid)) {
        if (!candidates.has(peer)) {
          candidates.set(peer, via);
        }
      }
    }
    for (const peer of this.prefer) {
      if (!candidates.has(peer)) {
        candidates.set(peer, null);
      }
    }
    for (const [peer, via] of candidates) {
      if (peer === this.host.selfId || this.sources.has(peer) || !this.host.advertisesTrees(peer)) {
        continue;
      }
      this.sources.set(peer, new Source(peer, via));
      this.note(`source ${peer.slice(0, 10)}`);
    }
  }

  private planSubtrees(): void {
    if (this.root === null) {
      return;
    }
    const links = this.host.store.links(this.root);
    for (const child of links) {
      this.expected.add(child);
    }
    const missing = links.filter((child) => !this.host.store.complete(child));
    if (missing.length === 0) {
      return;
    }
    if (links.length <= 1 || this.sources.size === 0) {
      // one walk from the root covers everything (the root is held, so the holder sends it again at no real cost)
      this.subtreesPending.push(this.root);
      return;
    }
    this.subtreesPending.push(...new Set(missing));
  }

  private ordered(now: number): Source[] {
    const preferred = new Set(this.prefer);
    return [...this.sources.values()].filter((s) => s.usable(now)).sort((a, b) =>
      (Number(preferred.has(b.peer)) - Number(preferred.has(a.peer)))
      || (this.host.hopsTo(a.peer) - this.host.hopsTo(b.peer)) || (b.bytesVerified - a.bytesVerified));
  }

  schedule(): void {
    if (this.scheduling || this.done) {
      return;
    }
    this.scheduling = true;
    try {
      this.scheduleOnce();
    } finally {
      this.scheduling = false;
    }
  }

  private scheduleOnce(): void {
    const now = this.host.nowMillis();
    const usable = this.ordered(now);
    if (usable.length === 0) {
      return;
    }
    // the root first, once, while its answer is outstanding
    if (this.root !== null && !this.host.store.has(this.root)) {
      if (!this.rootAsked) {
        const source = usable.find((s) => !s.lacks(this.root!, now));
        if (source !== undefined) {
          this.rootAsked = true;
          this.frontier.delete(this.root);
          this.send(source, NODE_WANT, [this.root], null, now);
        }
      }
      return;
    }
    // subtree walks across the top two sources
    let walkers = 0;
    for (const source of usable) {
      if (walkers >= 2) {
        break;
      }
      while (this.subtreesPending.length > 0 && source.inFlight < source.window) {
        const subtree = this.subtreesPending.shift()!;
        if (this.host.store.complete(subtree)) {
          continue;
        }
        const haves = this.haves.filter((h) => this.host.store.complete(h)).slice(0, MAX_HAVES);
        this.send(source, TREE_WANT, [subtree], subtree, now, haves);
      }
      walkers += 1;
    }
    // the frontier as NODE_WANT batches
    for (const source of usable) {
      while (source.inFlight < source.window) {
        const batch: string[] = [];
        for (const cid of this.frontier) {
          if (!source.lacks(cid, now) && !this.host.store.has(cid)) {
            batch.push(cid);
            if (batch.length >= MAX_WANT_CIDS) {
              break;
            }
          }
        }
        if (batch.length === 0) {
          break;
        }
        for (const cid of batch) {
          this.frontier.delete(cid);
        }
        this.send(source, NODE_WANT, batch, null, now);
      }
    }
    for (const cid of [...this.frontier]) {
      if (this.host.store.has(cid)) {
        this.frontier.delete(cid);
      }
    }
    this.endgame(usable, now);
  }

  private endgame(usable: Source[], now: number): void {
    if (this.frontier.size > 0 || this.subtreesPending.length > 0 || this.requests.size === 0) {
      return;
    }
    for (const request of [...this.requests.values()]) {
      if (request.duplicated || request.kind !== NODE_WANT) {
        continue;
      }
      const late = now - request.sent > Math.max(1000, 2 * Math.max(0, request.source.srttMillis));
      if (!late) {
        continue;
      }
      const other = usable.find((s) => s !== request.source && s.inFlight < s.window
        && request.cids.some((cid) => !s.lacks(cid, now)));
      if (other === undefined) {
        continue;
      }
      request.duplicated = true;
      const left = request.cids.filter((cid, i) => !request.matched.has(i) && !this.host.store.has(cid));
      if (left.length > 0) {
        this.send(other, NODE_WANT, left, null, now);
      }
    }
  }

  private send(source: Source, kind: number, list: string[], subtree: string | null, now: number, haves: string[] = []): void {
    const req = this.host.nextReq();
    this.requests.set(req, { req, source, kind, cids: list, matched: new Set(), subtree, sent: now, delivered: 0, duplicated: false });
    source.inFlight += 1;
    for (const cid of list) {
      this.expected.add(cid);
    }
    const message = kind === TREE_WANT ? treeWant(req, list[0]!, haves) : nodeWant(req, list);
    this.host.send(source.peer, message, source.via);
  }

  private timeOut(now: number): void {
    for (const request of [...this.requests.values()]) {
      const s = request.source;
      const limit = Math.max(TreeFetch.MIN_TIMEOUT_MILLIS, s.srttMillis > 0 ? 8 * s.srttMillis : 0);
      if (now - request.sent <= limit) {
        continue;
      }
      this.release(request, true);
      s.window = Math.max(1, Math.floor(s.window / 2));
      s.timeouts += 1;
      if (s.timeouts >= TreeFetch.TIMEOUTS_BEFORE_DROP) {
        s.droppedUntil = now + TreeFetch.DROP_MILLIS;
        s.timeouts = 0;
        this.note(`source ${s.peer.slice(0, 10)} timed out ${TreeFetch.TIMEOUTS_BEFORE_DROP} times; dropped for 60 s`);
      }
    }
  }

  /** Forgets a request; what it did not deliver returns to the frontier (or the subtree queue). */
  private release(request: Request, requeue: boolean): void {
    if (!this.requests.delete(request.req)) {
      return;
    }
    request.source.inFlight = Math.max(0, request.source.inFlight - 1);
    if (!requeue) {
      return;
    }
    if (request.kind === TREE_WANT) {
      const subtree = request.subtree!;
      if (request.delivered > 0 || this.walkedPartly.has(subtree)) {
        this.walkedPartly.add(subtree);
        for (const cid of this.host.store.missing(subtree)) {
          this.frontier.add(cid);
        }
      } else {
        this.subtreesPending.push(subtree);
      }
      return;
    }
    request.cids.forEach((cid, i) => {
      if (!request.matched.has(i) && !this.host.store.has(cid)) {
        this.frontier.add(cid);
      }
    });
    if (this.root !== null && request.cids.includes(this.root) && !this.host.store.has(this.root)) {
      this.rootAsked = false;
    }
  }

  async onNodes(from: string, msg: Dict): Promise<boolean> {
    if (this.done) {
      return false;
    }
    const request = this.requests.get(Number(msg["req"] ?? -1));
    if (request === undefined || request.source.peer !== from) {
      return false;
    }
    const nodes = await this.host.open(from, request.req, msg);
    if (this.done || !this.requests.has(request.req)) {
      return true;
    }
    if (nodes === null) {
      // sealed under a key this peer lacks (or malformed): the request is released and the source rests, so an
      // answer this fetch cannot read never turns into a tight ask-and-answer loop
      this.note(`a NODES from ${from.slice(0, 10)} could not be opened; released`);
      this.release(request, true);
      request.source.droppedUntil = this.host.nowMillis() + TreeFetch.DROP_MILLIS;
      this.schedule();
      return true;
    }
    const s = request.source;
    const rtt = this.host.nowMillis() - request.sent;
    s.srttMillis = s.srttMillis < 0 ? rtt : (s.srttMillis * 7 + rtt) / 8;
    s.timeouts = 0;
    const missing = (msg["missing"] as string[] | null) ?? [];
    if (request.kind === NODE_WANT) {
      let cursor = 0;
      for (const node of nodes) {
        const digest = cryptoPort().sha256(node);
        let found = -1;
        for (let i = cursor; i < request.cids.length; i++) {
          if (!request.matched.has(i) && digestMatches(request.cids[i]!, digest)) {
            found = i;
            break;
          }
        }
        if (found < 0) {
          this.strike(s, `a node that matches no CID of request ${request.req}`);
          this.release(request, true);
          this.schedule();
          return true;
        }
        request.matched.add(found);
        cursor = found + 1;
        this.accept(request.cids[found]!, node, s, null);
      }
      for (const cid of missing) {
        if (request.cids.includes(cid)) {
          s.lack(cid, this.host.nowMillis());
          if (!this.host.store.has(cid)) {
            this.frontier.add(cid);
          }
        }
      }
      const closed = msg["missing"] != null || request.cids.every((cid, i) => request.matched.has(i) || this.host.store.has(cid));
      if (closed) {
        this.roundTrips += 1;
        this.release(request, false);
        if (this.root !== null && missing.includes(this.root)) {
          this.rootAsked = false; // asked again of another source, or of this one once its bench ends (swarm retries)
        }
        request.cids.forEach((cid, i) => {
          if (!request.matched.has(i) && !this.host.store.has(cid) && !missing.includes(cid)) {
            this.frontier.add(cid);
          }
        });
      }
    } else {
      for (const node of nodes) {
        const digest = cryptoPort().sha256(node);
        const cid = cids.ofDigest(digest, cids.DAG_CBOR);
        const rawCid = cids.ofDigest(digest, cids.RAW);
        const match = this.expected.has(cid) ? cid : this.expected.has(rawCid) ? rawCid : null;
        if (match === null) {
          this.strike(s, `a node that no verified parent of subtree ${request.subtree} links to`);
          this.release(request, true);
          this.schedule();
          return true;
        }
        request.delivered += 1;
        this.accept(match, node, s, request.subtree);
      }
      const deltas = msg["deltas"] as Dict[] | undefined;
      if (deltas !== undefined && this.host.readsDeltas()) {
        for (const delta of deltas) {
          if (!this.acceptDelta(request, delta)) {
            this.schedule();
            return true;
          }
        }
      }
      for (const cid of missing) {
        if (this.expected.has(cid)) {
          s.lack(cid, this.host.nowMillis());
          if (!this.host.store.has(cid)) {
            this.frontier.add(cid);
          }
        }
      }
    }
    this.checkComplete();
    this.schedule();
    return true;
  }

  onTreeEnd(from: string, msg: Dict): boolean {
    if (this.done) {
      return false;
    }
    const request = this.requests.get(Number(msg["req"] ?? -1));
    if (request === undefined || request.source.peer !== from || request.kind !== TREE_WANT) {
      return false;
    }
    this.roundTrips += 1;
    const frontier = (msg["frontier"] as string[] | null) ?? [];
    let foreign = 0;
    for (const cid of frontier) {
      if (this.expected.has(cid) || cid === request.subtree) {
        if (!this.host.store.has(cid)) {
          this.frontier.add(cid);
        }
      } else {
        foreign += 1;
      }
    }
    if (foreign > 0) {
      this.strike(request.source, `${foreign} frontier cids outside the tree`);
    }
    this.release(request, false);
    for (const cid of this.host.store.missing(request.subtree!)) {
      if (this.expected.has(cid)) {
        this.frontier.add(cid);
      }
    }
    this.checkComplete();
    this.schedule();
    return true;
  }

  onReject(from: string, msg: Dict): boolean {
    const s = this.sources.get(from);
    if (s === undefined || this.done) {
      return false;
    }
    const root = String(msg["root"]);
    const request = [...this.requests.values()].find((r) => r.source === s && (r.subtree === root || r.cids[0] === root));
    if (request !== undefined) {
      this.release(request, true);
    }
    const reason = Number(msg["reason"]);
    if (reason === REASON_OVER_BUDGET || reason === REASON_POLICY) {
      s.droppedUntil = this.host.nowMillis() + TreeFetch.DROP_MILLIS;
      this.note(`source ${s.peer.slice(0, 10)} rejected (${reason}); dropped for a while`);
    } else {
      s.lack(root, this.host.nowMillis());
    }
    this.schedule();
    return true;
  }

  /**
   * Applies one delta of a `TREE_WANT` answer (PDT 2 phase 7, P2-Z-01, Java's TreeFetchSession.acceptDelta): the chunk
   * it names must be one a verified node links, or its sender is struck; a delta over a base this store lacks, or
   * that names no two chunks, is ignored and the chunk asked for by `NODE_WANT`; a frame that does not open costs no
   * strike, and the fetch opens no later frame of that source (P2-Q-SEC-05); a frame that opens to bytes the chunk's
   * CID does not name strikes its sender. Only the verified chunk is stored. Returns false when the source was struck.
   */
  private acceptDelta(request: Request, delta: Dict): boolean {
    const s = request.source;
    const cid = String(delta["cid"]), base = String(delta["base"]);
    const frame = delta["dcz"] as Uint8Array;
    if (!this.expected.has(cid)) {
      this.strike(s, `a delta of TREE_WANT ${request.req} under ${request.subtree} names ${cid}, which no verified node links to`);
      this.release(request, true);
      return false;
    }
    if (this.host.store.has(cid)) {
      this.bytesReceived += frame.length; // a duplicate delivery still costs its bytes
      return true;
    }
    if (cids.parse(cid).codec !== cids.RAW || cids.parse(base).codec !== cids.RAW) {
      this.deltasRefused += 1;
      this.frontier.add(cid);
      return true;
    }
    const held = this.host.store.get(base);
    if (s.framesRefused || held === undefined) {
      this.frontier.add(cid); // asked for whole by NODE_WANT
      return true;
    }
    let chunk: Uint8Array;
    try {
      chunk = dcz.decode(held, frame);
    } catch (e) {
      this.deltasRefused += 1;
      s.framesRefused = true;
      this.note(`a delta for ${cid.slice(0, 16)} refused (${e instanceof Error ? e.message : String(e)}); asking for the chunk whole`);
      this.frontier.add(cid);
      return true;
    }
    if (cids.of(chunk, cids.RAW) !== cid) {
      this.deltasRefused += 1;
      this.strike(s, `a delta of TREE_WANT ${request.req} rebuilds bytes that do not hash to ${cid}`);
      this.release(request, true);
      return false;
    }
    this.deltasApplied += 1;
    this.accept(cid, chunk, s, request.subtree, frame.length);
    return true;
  }

  /** Stores a verified node and follows its links; `wireBytes` is what it cost to receive (a delta's frame). */
  private accept(cid: string, node: Uint8Array, s: Source, subtree: string | null, wireBytes = node.length): void {
    this.bytesReceived += wireBytes;
    s.bytesVerified += wireBytes;
    if (this.host.store.has(cid)) {
      return;
    }
    try {
      this.host.store.putVerified(cid, node);
    } catch (e) {
      this.note(`node ${cid.slice(0, 16)} refused: ${e instanceof Error ? e.message : String(e)}`);
      return;
    }
    this.nodesReceived += 1;
    this.frontier.delete(cid);
    for (const link of this.host.store.links(cid)) {
      this.expected.add(link);
      if (!this.host.store.has(link) && subtree === null) {
        this.frontier.add(link);
      }
    }
    if (this.root !== null && cid === this.root) {
      this.planSubtrees();
    }
  }

  private strike(s: Source, why: string): void {
    this.note(`source ${s.peer.slice(0, 10)} struck: ${why}`);
    s.droppedUntil = Number.POSITIVE_INFINITY;
    this.host.strike(s.peer, why);
  }

  private checkComplete(): void {
    if (this.done) {
      return;
    }
    const complete = this.root !== null ? this.host.store.complete(this.root) : this.bare.every((cid) => this.host.store.has(cid));
    if (complete) {
      this.finish();
    }
  }

  private checkStalled(now: number): void {
    const usable = this.ordered(now);
    const anything = this.frontier.size > 0 || this.subtreesPending.length > 0 || (this.root !== null && !this.host.store.has(this.root));
    const stalled = this.requests.size === 0 && anything && (usable.length === 0
      || [...this.frontier].every((cid) => usable.every((s) => s.lacks(cid, now))));
    if (!stalled) {
      this.stalledSince = 0;
      return;
    }
    if (this.stalledSince === 0) {
      this.stalledSince = now;
    } else if (now - this.stalledSince >= TreeFetch.STALL_MILLIS) {
      this.fail(`no reachable holder for ${this.root ?? this.bare.join(",")}`);
    }
  }
}

function digestMatches(cid: string, digest: Uint8Array): boolean {
  const parsed = cids.parse(cid);
  for (let i = 0; i < 32; i++) {
    if (parsed.digest[i] !== digest[i]) {
      return false;
    }
  }
  return true;
}

// ------------------------------------------------------------------ the capability

export interface TreeExchangeOptions {
  /** The group's content keys; null for a group without a key ring. */
  keys?: ContentKeys | null;
  /** Refuses a request when it returns false. */
  mayServe?: ((peer: string, cid: string) => boolean) | null;
  /** Whether a member advertises the tree exchange; by default read from the ads cache. */
  advertises?: ((peer: string) => boolean) | null;
  /** Whether the group seals, when no advertisement says so (a keyless holder refuses in a sealing group). */
  groupSeals?: boolean;
  /**
   * The PDT feature level this member stands at (P2-F-05): {@link PDT_LEVEL} by default, or 1 for a member that reads
   * and sends no level-2 form, as a 0.5.0 peer does.
   */
  level?: number;
}

interface HolderState { entryId: string | null; writtenAt: number; count: number; complete: boolean }

/** The outcome of a possession challenge (P2-S-07): whether every pick verified within the deadline, and why not. */
export interface ChallengeResult { passed: boolean; proven: number; picks: number; failure: string | null; millis: number }

interface Challenge { root: string; store: string; req: number; picks: Set<string>; proven: Set<string>; sent: number;
  deadline: number; resolve: (result: ChallengeResult) => void }

/** The fixed part of a challenge's deadline (§3.2.4), and the round trip one hop of the path is taken to cost. */
export const CHALLENGE_DEADLINE_MILLIS = 2000;
const CHALLENGE_HOP_MILLIS = 250;

/**
 * The tree exchange attached to a `Content`: routes tags 8 to 11 (and tree `REJECT`s) from the content
 * pipe to the holder and the fetches, publishes this peer's content-swarm advertisement with `trees = "1"`,
 * holds tree roots with `Holding` records, and drives fetches from `tick`.
 */
export class TreeExchange {
  readonly peer: Peer;
  readonly selfId: string;
  readonly server: TreeServer;
  readonly fetches = new Map<string, TreeFetch>();
  readonly keys: ContentKeys | null;
  private readonly mayServe: ((peer: string, cid: string) => boolean) | null;
  private readonly advertises: ((peer: string) => boolean) | null;
  private readonly groupSealsOption: boolean;
  private readonly levelOption: number;
  private readonly holderState = new Map<string, HolderState>();
  private req = 0;
  private advertisedAt = 0;
  treeMessagesDropped = 0;
  nodesStruck = 0;
  bytesServed = 0;
  /** The holder's side of a reconciliation, over the roots this member holds complete (PDT 2 phase 7, P2-K-02). */
  readonly sketches: SketchServer;
  private readonly sessions = new Set<SketchSession>();
  private readonly challenges = new Map<string, Challenge>();
  /** Reconciliation rounds started again after a late answer (swarm retries, ROBUSTNESS.md §10.2). */
  sketchRetries = 0;

  constructor(readonly content: Content, readonly store: NodeStore, options: TreeExchangeOptions = {}) {
    this.peer = content.peer;
    this.selfId = content.selfId;
    this.keys = options.keys ?? null;
    this.mayServe = options.mayServe ?? null;
    this.advertises = options.advertises ?? null;
    this.groupSealsOption = options.groupSeals ?? false;
    this.levelOption = options.level ?? PDT_LEVEL;
    this.sketches = new SketchServer(() => this.heldRoots(), () => this.peer.now());
    this.server = new TreeServer(store, {
      mayServe: (from, cid) => this.mayServe === null || this.mayServe(from, cid),
      withinUploadBudget: () => true,
      seal: (to, req, nodes, missing) => this.seal(to, req, nodes, missing),
      send: (to, message) => this.send(to, message),
      served: (_nodes, bytes) => { this.bytesServed += bytes; },
      nowMillis: () => this.peer.now(),
    });
    const previous = this.peer.pipeHandlers.get(CONTENT_TYPE);
    this.peer.pipeHandlers.set(CONTENT_TYPE, (from, payload) => {
      const tag = peekTag(payload);
      if (tag >= NODE_WANT && tag <= CHALLENGE) {
        this.onFrame(from, payload);
        return;
      }
      if (tag === REJECT) {
        const msg = readTreeMessage(payload);
        if (msg !== null && msg["index"] === TREE_INDEX && msg["root"] === "") {
          for (const session of this.sessions) {
            if (session.onReject(from, Number(msg["reason"]))) {
              break;
            }
          }
          return;
        }
        if (msg !== null && msg["index"] === TREE_INDEX) {
          const root = String(msg["root"]);
          const challenge = [...this.challenges.values()].find((c) => c.store === from && c.root === root);
          if (challenge !== undefined) {
            this.settleChallenge(challenge, `refused with REJECT reason ${String(msg["reason"])}`);
            return;
          }
          for (const f of this.fetches.values()) {
            if (f.onReject(from, msg) && (f.root === root || f.bare.includes(root))) {
              break;
            }
          }
          return;
        }
      }
      previous?.(from, payload);
    });
    this.advertise();
  }

  nextReq(): number {
    this.req += 1;
    return this.req;
  }

  send(to: string, message: Dict, via: string[] | null = null): void {
    this.content.pipes.send(to, CONTENT_TYPE, dumps(message), via);
  }

  // ---- the advertisement (PD-X-01)

  /**
   * This peer's content-swarm capability advertisement: piece sizes, sealing, seed mode, `trees = "1"`, and at level 2
   * `pdt = "2"` (PDT 2 phase 7, P2-C-01, P2-F-05), since this client's decoders carry every level-2 schema of §6.10.4.
   */
  advertisement(): Dict {
    const now = this.peer.now();
    const parameters: Dict = { pieceSizes: "65536-4194304", sealing: this.keys === null ? SEALING_NONE : SEALING_GROUP_KEY,
      seedMode: "always", [TREES_PARAMETER]: TREES_VERSION };
    if (this.level() >= 2) {
      parameters[PDT_PARAMETER] = String(this.level());
    }
    return { id: `aspace://${this.peer.group}/cap/content-swarm/${this.selfId}`, issuer: this.selfId, group: this.peer.group,
      issued: instantIso(now - (now % 1000)), ttl: "PT15M", capabilityType: CONTENT_TYPE, version: "0.1", binding: "pipe",
      parameters: canonicalMap(parameters), costHints: {} };
  }

  /** Publishes the advertisement on the `ads` stream; `tick` renews it at half its lease. */
  advertise(): void {
    this.advertisedAt = this.peer.now();
    this.peer.publishAd(CAPABILITY_AD_TYPE, this.advertisement());
  }

  /** The newest unexpired content-swarm advertisement of a member, or null. */
  advertisementOf(peer: string): Dict | null {
    const now = this.peer.now();
    let best: { issued: number; ad: Dict } | null = null;
    for (const cached of this.peer.ads.values()) {
      if (cached.type !== CAPABILITY_AD_TYPE || cached.issuer !== peer || cached.expires <= now
          || cached.ad["capabilityType"] !== CONTENT_TYPE) {
        continue;
      }
      const issued = Date.parse(String(cached.ad["issued"]));
      if (best === null || issued > best.issued) {
        best = { issued, ad: cached.ad };
      }
    }
    return best?.ad ?? null;
  }

  /** Whether a member's current content-swarm advertisement carries `trees = "1"`. */
  advertisesTrees(peer: string): boolean {
    if (this.advertises !== null) {
      return this.advertises(peer);
    }
    const ad = this.advertisementOf(peer);
    return ad !== null && ((ad["parameters"] as Dict | null) ?? {})[TREES_PARAMETER] === TREES_VERSION;
  }

  /** The PDT feature level this member stands at (P2-F-05). */
  level(): number {
    return this.levelOption;
  }

  /** A member's PDT feature level, from its newest unexpired content-swarm advertisement (P2-F-05). */
  pdtLevel(peer: string): number {
    return featureLevel(this.advertisementOf(peer));
  }

  /** Whether any member's current advertisement says the group's content travels sealed. */
  groupSeals(): boolean {
    if (this.groupSealsOption) {
      return true;
    }
    const now = this.peer.now();
    for (const cached of this.peer.ads.values()) {
      if (cached.type === CAPABILITY_AD_TYPE && cached.expires > now && cached.ad["capabilityType"] === CONTENT_TYPE
          && ((cached.ad["parameters"] as Dict | null) ?? {})["sealing"] === SEALING_GROUP_KEY) {
        return true;
      }
    }
    return false;
  }

  // ---- sealing

  private async seal(to: string, req: number, nodes: Uint8Array[], missing: string[] | null): Promise<Dict | null> {
    if (this.keys === null) {
      if (this.groupSeals()) {
        return null;
      }
      return nodesMessage(req, nodes, missing);
    }
    const epoch = this.keys.writeEpoch();
    const key = this.keys.key(epoch)!;
    return sealedNodes(req, await seal(key, dumps(nodes), sealingAad(to, req)), epoch, missing);
  }

  private async open(_from: string, req: number, msg: Dict): Promise<Uint8Array[] | null> {
    if (msg["sealed"] == null) {
      return (msg["nodes"] as Uint8Array[] | null) ?? [];
    }
    if (this.keys === null) {
      return null;
    }
    const key = this.keys.key(Number(msg["epoch"]));
    if (key === undefined) {
      return null;
    }
    const plain = await open(key, msg["sealed"] as Uint8Array, sealingAad(this.selfId, req));
    if (plain === null) {
      return null;
    }
    try {
      const list = loads(plain);
      return Array.isArray(list) && list.every((n) => n instanceof Uint8Array) ? (list as Uint8Array[]) : null;
    } catch {
      return null;
    }
  }

  // ---- fetching

  private host(): FetchHost {
    return {
      store: this.store,
      selfId: this.selfId,
      nextReq: () => this.nextReq(),
      send: (to, message, via) => this.send(to, message, via),
      holdersOf: (root) => this.content.holdings(root).map((h) => [String(h["holder"]),
        Array.isArray(h["via"]) ? (h["via"] as unknown[]).filter((v): v is string => typeof v === "string") : null]),
      advertisesTrees: (peer) => this.advertisesTrees(peer),
      hopsTo: (peer) => this.content.hopsTo(peer),
      open: (from, req, msg) => this.open(from, req, msg),
      strike: (_peer, _reason) => { this.nodesStruck += 1; },
      nowMillis: () => this.peer.now(),
      readsDeltas: () => this.level() >= 2,
    };
  }

  /** The members that hold a root, by their holdings (a retry asks these before the issuer; swarm retries). */
  holders(root: string): string[] {
    return [...new Set(this.content.holdings(root).map((h) => String(h["holder"])))];
  }

  /** Starts (or continues) fetching every node under `root` absent under the `haves` roots held here. */
  fetchTree(root: string, haves: string[] = [], prefer: string[] = []): TreeFetch {
    const existing = this.fetches.get(root);
    if (existing !== undefined && !existing.done) {
      return existing;
    }
    const held = haves.filter((h) => h !== root && this.store.complete(h)).slice(0, MAX_HAVES);
    const f = new TreeFetch(this.host(), root, held, prefer);
    this.fetches.set(root, f);
    f.start();
    if (f.done) {
      this.fetches.delete(root);
    }
    return f;
  }

  /** Fetches exactly these nodes from their holders and the preferred peers. */
  fetchNodes(list: string[], prefer: string[] = []): TreeFetch {
    const key = `nodes:${list.join(",")}`;
    const existing = this.fetches.get(key);
    if (existing !== undefined && !existing.done) {
      return existing;
    }
    const f = new TreeFetch(this.host(), null, [], prefer, list);
    this.fetches.set(key, f);
    f.start();
    if (f.done) {
      this.fetches.delete(key);
    }
    return f;
  }

  tick(): void {
    for (const [key, f] of [...this.fetches]) {
      f.tick();
      if (f.done) {
        this.fetches.delete(key);
      }
    }
    const now = this.peer.now();
    for (const session of [...this.sessions]) {
      session.tick(now);
      if (session.finished) {
        this.sessions.delete(session);
      }
    }
    for (const challenge of [...this.challenges.values()]) {
      if (now >= challenge.deadline) {
        this.settleChallenge(challenge, `no answer within ${challenge.deadline - challenge.sent} ms`);
      }
    }
    for (const root of [...this.holderState.keys()]) {
      this.refreshHolding(root, false);
    }
    if (this.peer.now() - this.advertisedAt >= ADVERTISEMENT_TTL_MILLIS / 2) {
      this.advertise();
    }
  }

  /** Tells every live fetch that holdings changed. */
  holdingsChanged(): void {
    for (const f of this.fetches.values()) {
      f.holdingsChanged();
    }
  }

  // ---- holdings for tree roots (PD-S-06)

  /** Pins a root and writes a `Holding` for it (`have` null, `complete` from the store). */
  holdTree(root: string): void {
    this.store.pin(root);
    this.refreshHolding(root, true);
  }

  /** Unpins a root; its holding lapses at the end of its lease. */
  release(root: string): void {
    this.store.unpin(root);
    this.holderState.delete(root);
  }

  private refreshHolding(root: string, force: boolean): void {
    if (!this.store.has(root)) {
      return;
    }
    let state = this.holderState.get(root);
    if (state === undefined) {
      state = { entryId: null, writtenAt: 0, count: -1, complete: false };
      this.holderState.set(root, state);
    }
    const now = this.peer.now();
    const due = force || state.entryId === null || (now - state.writtenAt >= 10_000 && !state.complete);
    if (due) {
      const reachable = this.store.reachable(root);
      let count = 0;
      for (const cid of reachable) {
        if (this.store.has(cid)) {
          count += 1;
        }
      }
      const complete = this.store.complete(root);
      if (!force && state.count === count && state.complete === complete && state.entryId !== null) {
        return;
      }
      const via = this.peer.relayFor(this.selfId) !== null && this.peer.seedPeer !== null ? [this.peer.seedPeer] : null;
      const h: Dict = { v: 1, root, holder: this.selfId, complete, have: null, count, via, cost: null };
      const space = this.content.space;
      state.entryId = this.peer.writeEntry(space.name, HOLDING_TYPE, h, space.agentName, durationMillis("2m"), space.agent,
        holdingTags(h));
      state.count = count;
      state.complete = complete;
      state.writtenAt = now;
      this.holdingsChanged();
    } else if (now - state.writtenAt >= 50_000 && state.entryId !== null) {
      try {
        this.peer.renewEntry(this.content.space.name, state.entryId, 120_000, null);
        state.writtenAt = now;
      } catch {
        state.entryId = null;
      }
    }
  }

  // ---- reconciliation (PDT 2 phase 7, P2-K-02, P2-K-03)

  /**
   * The roots this member holds complete: the tree roots it holds and the flat artifacts whose every piece it holds,
   * the set a reconciliation compares (Java's Content.heldRoots).
   */
  heldRoots(): string[] {
    const out: string[] = [];
    for (const root of this.holderState.keys()) {
      if (this.store.complete(root)) {
        out.push(root);
      }
    }
    for (const root of this.content.store.roots()) {
      const m = this.content.store.manifest(root);
      if (m !== null && this.content.store.have(root).size >= Number(m["pieces"])) {
        out.push(root);
      }
    }
    return out;
  }

  /**
   * Reconciles this member's held roots with another member's (P2-K-03): negentropy when `expected` is 0, else RIBLT
   * for about that many differences, falling back to negentropy. A sketch goes only to a member at level 2 (P2-F-05),
   * so a peer at level 1 rejects the promise at once. The outcome lists the roots this member holds and the other
   * lacks, and the roots the other holds and this member lacks; the caller fetches what it needs.
   */
  reconcileHeld(peer: string, expected = 0): Promise<Outcome> {
    if (this.level() < 2 || this.pdtLevel(peer) < 2) {
      return Promise.reject(new Error(`${peer.slice(0, 10)} stands at level ${this.pdtLevel(peer)}; a sketch goes only to a`
        + " member at level 2"));
    }
    const session = new SketchSession(peer, SketchSet.of(this.heldRoots()), expected, {
      nowMillis: () => this.peer.now(),
      nextReq: () => this.nextReq(),
      send: (to, req, sketch) => {
        const message = sketchWant(req, sketch, MAX_SKETCH_BYTES);
        this.send(to, message);
        return dumps(message).length;
      },
    });
    this.sessions.add(session);
    session.start();
    const counted = (o: Outcome): Outcome => {
      this.sketchRetries += o.retries;
      return o;
    };
    return session.outcome.then(counted);
  }

  /**
   * Answers a sketch `TREE_WANT` (rule 12): a member at level 1 drops it, as a 0.5.0 holder does; an asker this member
   * reads at level 1 gets the level-1 `REJECT` reason 3 (PDT 2 phase 5 adversary, A6); otherwise the holder's answer
   * goes back as a `TREE_END` of reason 5, a refusal as a `REJECT` for the root `""`, and a drop is counted.
   */
  private answerSketch(from: string, want: Dict): void {
    if (this.level() < 2) {
      this.treeMessagesDropped += 1;
      return;
    }
    if (this.pdtLevel(from) < 2) {
      this.send(from, treeReject("", REASON_POLICY));
      return;
    }
    const answer = this.sketches.answer(from, Number(want["req"]), want["sketch"] as Uint8Array, Number(want["budget"]));
    if (answer.kind === "reply") {
      this.send(from, sketchEnd(Number(want["req"]), answer.sketch));
    } else if (answer.kind === "refusal") {
      this.send(from, treeReject("", answer.reason));
    } else {
      this.treeMessagesDropped += 1;
    }
  }

  // ---- possession challenges (PDT 2 phase 7, P2-C-01, P2-S-07)

  /**
   * Challenges a member's possession of a tree root this member holds (P2-S-07): up to {@link MAX_PICKS} random nodes
   * of the root, answered within the deadline of §3.2.4, 2 s plus eight round trips of the path, else the challenge
   * fails. The member must stand at level 2 (P2-F-05). Each node that comes back verifies against its CID.
   */
  challenge(root: string, store: string): Promise<ChallengeResult> {
    if (this.level() < 2 || this.pdtLevel(store) < 2) {
      return Promise.reject(new Error(`${store.slice(0, 10)} stands at level ${this.pdtLevel(store)}; a challenge goes only to a`
        + " member at level 2"));
    }
    const candidates = [...this.store.reachable(root)].filter((cid) => this.store.has(cid));
    if (candidates.length === 0) {
      return Promise.reject(new Error(`this member holds nothing of ${root} to pick from`));
    }
    for (let i = candidates.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [candidates[i], candidates[j]] = [candidates[j]!, candidates[i]!];
    }
    const picks = candidates.slice(0, MAX_PICKS);
    const req = this.nextReq();
    const sent = this.peer.now();
    const roundTrip = this.content.hopsTo(store) * CHALLENGE_HOP_MILLIS;
    return new Promise((resolve) => {
      const challenge: Challenge = { root, store, req, picks: new Set(picks), proven: new Set(), sent,
        deadline: sent + CHALLENGE_DEADLINE_MILLIS + 8 * roundTrip, resolve };
      this.challenges.set(`${store}|${req}`, challenge);
      this.send(store, challengeMessage(req, root, picks.map((cid) => ({ cid }))));
    });
  }

  private async onChallengeNodes(challenge: Challenge, msg: Dict): Promise<void> {
    const nodes = await this.open(challenge.store, challenge.req, msg);
    if (nodes === null) {
      this.settleChallenge(challenge, "an answer this member could not open");
      return;
    }
    for (const node of nodes) {
      const cid = [...challenge.picks].find((pick) => cids.verifies(pick, node));
      if (cid === undefined) {
        this.settleChallenge(challenge, "a node that matches no pick");
        return;
      }
      challenge.proven.add(cid);
    }
    const missing = (msg["missing"] as string[] | null) ?? [];
    if (missing.length > 0) {
      this.settleChallenge(challenge, `${missing.length} picks not held`);
    } else if (challenge.proven.size === challenge.picks.size) {
      this.settleChallenge(challenge, null);
    }
  }

  private settleChallenge(challenge: Challenge, failure: string | null): void {
    if (this.challenges.delete(`${challenge.store}|${challenge.req}`)) {
      challenge.resolve({ passed: failure === null, proven: challenge.proven.size, picks: challenge.picks.size, failure,
        millis: this.peer.now() - challenge.sent });
    }
  }

  // ---- frames

  private onFrame(from: string, payload: Uint8Array): void {
    if (payload.length > MAX_NODES_BYTES + 64 * 1024) {
      this.treeMessagesDropped += 1;
      return;
    }
    const msg = readTreeMessage(payload);
    if (msg === null) {
      this.treeMessagesDropped += 1;
      return;
    }
    switch (msg["t"]) {
      case NODE_WANT:
        this.queue(from, () => this.server.serveNodeWant(from, msg));
        break;
      case TREE_WANT:
        this.queue(from, isSketchWant(msg) ? async () => this.answerSketch(from, msg) : () => this.server.serveTreeWant(from, msg));
        break;
      case CHALLENGE:
        if (this.level() < 2) {
          this.treeMessagesDropped += 1; // a level-1 member reads no tag 12
          return;
        }
        this.queue(from, () => this.server.serveChallenge(from, msg));
        break;
      case NODES:
        this.queue(from, async () => {
          const challenge = this.challenges.get(`${from}|${String(msg["req"])}`);
          if (challenge !== undefined) {
            await this.onChallengeNodes(challenge, msg);
            return;
          }
          for (const f of this.fetches.values()) {
            if (await f.onNodes(from, msg)) {
              break;
            }
          }
        });
        break;
      case TREE_END:
        if (msg["reason"] === END_SKETCH) {
          this.queue(from, async () => {
            const taken = [...this.sessions].some((session) => session.onEnd(from, Number(msg["req"]), msg["sketch"] as Uint8Array,
              payload.length));
            if (!taken) {
              this.treeMessagesDropped += 1;
            }
          });
          return;
        }
        this.queue(from, async () => {
          for (const f of this.fetches.values()) {
            if (f.onTreeEnd(from, msg)) {
              break;
            }
          }
        });
        break;
    }
  }

  private readonly queues = new Map<string, Promise<void>>();

  /** One serial queue per sending peer, so a breadth-first stream arrives parents first. */
  private queue(from: string, work: () => Promise<void>): void {
    const previous = this.queues.get(from) ?? Promise.resolve();
    const next = previous.then(work).catch((e) => {
      this.treeMessagesDropped += 1;
      this.server.dropped += 1;
      void e;
    });
    this.queues.set(from, next);
  }

  /** Resolves when every queued frame of every peer has been handled (tests). */
  async settled(): Promise<void> {
    await Promise.all([...this.queues.values()]);
  }

  stats(): Dict {
    return { fetchesActive: this.fetches.size, nodesServed: this.server.nodesServed, bytesServed: this.bytesServed,
      treeRequestsRejected: this.server.rejected, treeMessagesDropped: this.treeMessagesDropped + this.server.dropped,
      nodesStruck: this.nodesStruck, nodesHeld: this.store.nodesHeld, bytesHeld: this.store.bytesHeld,
      sketchSessions: this.sessions.size, sketchRetries: this.sketchRetries, challengesPending: this.challenges.size };
  }
}

export { REASON_NOT_HELD, REASON_OVER_BUDGET, REASON_POLICY, REASON_UNKNOWN_ROOT };
