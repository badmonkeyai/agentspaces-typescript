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
 * The content swarm, `aspace:cap/content-swarm` (SPEC v0.1.23 §7.1, §8, annex G;
 * srad/large-networks-bulk-data.md): a large artifact is a signed `Manifest` entry naming the
 * CIDv1 root of its fixed-size pieces, each member that holds pieces writes a leased `Holding`,
 * and the pieces move as tagged `PIPE_DATA` payloads from every reachable holder at once,
 * verified against the manifest's table before they are stored or served.
 *
 *     const content = new Content(new Pipes(peer), new Space(peer, "content"), new MemoryStore());
 *     content.run();
 *     const manifest = content.publish(bytes, { name: "weights.bin" });
 *     const fetch = content.fetch(manifest.root);
 *     if (await fetch.await(60_000)) { const data = fetch.readBytes(); }
 *
 * A dial-only client reaches its seed directly and every other holder through it when the seed
 * holds the RELAY role (`Peer.sendPipe`); a space over a peer with the capability attached
 * escalates a payload above `escalateAbove` to an artifact (SPEC §7.1, group E).
 */

import { dumps, loads, canonicalMap } from "../cbor.js";
import { cryptoPort } from "../crypto.js";
import { multibase, spaceIdLocal } from "../identity.js";
import type { BulkPayloads, Peer } from "../peer.js";
import type { Space } from "../space.js";
import { durationMillis } from "../space.js";
import type { Dict } from "../wire.js";
import type { Pipes } from "./pipes.js";

export const TYPE = "aspace:cap/content-swarm";
export const MANIFEST_TYPE = "ai.badmonkey.agentspaces.agent.content.Manifest#v1";
export const HOLDING_TYPE = "ai.badmonkey.agentspaces.agent.content.Holding#v1";

export const VERSION = 1;
export const INLINE_TABLE_PIECES = 64;
export const HASH_BYTES = 32;
export const MIN_PIECE_SIZE = 64 * 1024;
export const MAX_PIECE_SIZE = 4 * 1024 * 1024;
export const DEFAULT_PIECE_SIZE = 1024 * 1024;
export const MAX_HAVE_BYTES = 8 * 1024;
export const RANGE_UNIT = 64 * 1024;

export const PIECE_WANT = 1, PIECE = 2, HAVE = 3, CANCEL = 4, REJECT = 5, MANIFEST_WANT = 6, MANIFEST = 7;
export const REASON_NOT_HELD = 1, REASON_OVER_BUDGET = 2, REASON_POLICY = 3, REASON_UNKNOWN_ROOT = 4;
export const SEALING_NONE = "none", SEALING_GROUP_KEY = "group-key";
export const HASHING_PLAIN = "plain", HASHING_SEALED = "sealed";

const B32 = "abcdefghijklmnopqrstuvwxyz234567";

const sha256 = (data: Uint8Array): Uint8Array => cryptoPort().sha256(data);

// ------------------------------------------------------------------ roots

/** RFC 4648 base32, lower case, unpadded: the multibase `b` form. */
export function base32Lower(data: Uint8Array): string {
  let out = "", buffer = 0, bits = 0;
  for (const b of data) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(buffer >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
    buffer &= 0xffff; // keep the shifts within 32 bits
  }
  if (bits > 0) {
    out += B32[(buffer << (5 - bits)) & 0x1f];
  }
  return out;
}

/** The CIDv1 of a piece table: 0x01, raw 0x55, sha2-256 0x12, 32 bytes, base32 `b`. */
export function contentRoot(table: Uint8Array): string {
  if (table.length % HASH_BYTES !== 0) {
    throw new Error("table is not a multiple of 32 bytes");
  }
  const digest = sha256(table);
  const cid = new Uint8Array(4 + digest.length);
  cid.set([0x01, 0x55, 0x12, 0x20], 0);
  cid.set(digest, 4);
  return "b" + base32Lower(cid);
}

/** Whether a `payloadRef` names a content root (`b`) rather than one block (`z`). */
export function isRoot(ref: unknown): ref is string {
  return typeof ref === "string" && ref.length > 1 && ref.startsWith("b");
}

/** The piece table of bytes in memory. */
export function hashPieces(data: Uint8Array, pieceSize = DEFAULT_PIECE_SIZE): Uint8Array {
  const n = piecesOf(data.length, pieceSize);
  const table = new Uint8Array(n * HASH_BYTES);
  for (let i = 0; i < n; i++) {
    table.set(sha256(data.subarray(i * pieceSize, Math.min(data.length, (i + 1) * pieceSize))), i * HASH_BYTES);
  }
  return table;
}

export function piecesOf(size: number, pieceSize: number): number {
  return size === 0 ? 0 : Math.ceil(size / pieceSize);
}

export function pieceLength(size: number, pieceSize: number, index: number): number {
  return Math.min(pieceSize, size - index * pieceSize);
}

export function verifies(table: Uint8Array, index: number, piece: Uint8Array): boolean {
  const start = index * HASH_BYTES;
  if (index < 0 || start + HASH_BYTES > table.length) {
    return false;
  }
  const digest = sha256(piece);
  for (let i = 0; i < HASH_BYTES; i++) {
    if (digest[i] !== table[start + i]) {
      return false;
    }
  }
  return true;
}

// ------------------------------------------------------------------ records

export interface ManifestOptions {
  tableRef?: string | null;
  name?: string | null;
  mediaType?: string | null;
  attrs?: { [key: string]: string } | null;
  sealing?: string;
  keyEpoch?: number | null;
  hashing?: string;
}

/** A `Manifest` value in Java field order (annex G). */
export function manifest(root: string, size: number, pieceSize: number, table: Uint8Array | null,
                         origin: string, createdMillis: number, options: ManifestOptions = {}): Dict {
  const attrs = options.attrs ?? null;
  return { v: VERSION, root, size, pieceSize, pieces: piecesOf(size, pieceSize), table,
    tableRef: options.tableRef ?? null, tableRefs: null, name: options.name ?? null,
    mediaType: options.mediaType ?? null, sealing: options.sealing ?? SEALING_NONE,
    keyEpoch: options.keyEpoch ?? null, hashing: options.hashing ?? HASHING_PLAIN, origin,
    created: createdMillis, attrs: attrs === null || Object.keys(attrs).length === 0 ? null : canonicalMap(attrs) };
}

/** The first broken invariant of a manifest, or null (SPEC annex G). */
export function manifestViolation(m: Dict): string | null {
  if (m["v"] !== VERSION) {
    return `unsupported manifest version ${String(m["v"])}`;
  }
  const ps = Number(m["pieceSize"]);
  if (!(ps >= MIN_PIECE_SIZE && ps <= MAX_PIECE_SIZE) || (ps & (ps - 1)) !== 0) {
    return "pieceSize is not a power of two in [64 KiB, 4 MiB]";
  }
  const size = Number(m["size"]);
  if (!(size >= 0) || Number(m["pieces"]) !== piecesOf(size, ps)) {
    return "pieces does not match ceil(size / pieceSize)";
  }
  const table = m["table"], ref = m["tableRef"];
  if ((table == null) === (ref == null)) {
    return "exactly one of table and tableRef must be present";
  }
  if (table != null) {
    if (!(table instanceof Uint8Array)) {
      return "table is not bytes";
    }
    if (Number(m["pieces"]) > INLINE_TABLE_PIECES) {
      return "inline table above the inline bound";
    }
    if (table.length !== Number(m["pieces"]) * HASH_BYTES) {
      return "table length does not match pieces";
    }
    if (contentRoot(table) !== m["root"]) {
      return "table does not hash to the root";
    }
  }
  if (m["sealing"] !== SEALING_NONE && m["sealing"] !== SEALING_GROUP_KEY) {
    return "unknown sealing";
  }
  if (m["hashing"] !== HASHING_PLAIN && m["hashing"] !== HASHING_SEALED) {
    return "unknown hashing";
  }
  if (!isRoot(m["root"])) {
    return "root is not a content root";
  }
  return null;
}

/** The manifest's tags as Java writes them (LB-M-09): the user's attrs, then root and name, which keep their meaning. */
export function manifestTags(m: Dict): Dict {
  const tags: Dict = { ...((m["attrs"] as Dict | null) ?? {}) };
  tags["root"] = m["root"];
  if (typeof m["name"] === "string" && m["name"].length > 0) {
    tags["name"] = m["name"];
  } else {
    delete tags["name"];
  }
  return tags;
}

/** Alternating runs of zeros and ones as unsigned varints, zeros first. */
export function encodeHave(have: Set<number>, pieces: number): Uint8Array {
  const out: number[] = [];
  let i = 0, value = false;
  while (i < pieces) {
    let run = 0;
    while (i < pieces && have.has(i) === value) {
      run += 1;
      i += 1;
    }
    while (run > 0x7f) {
      out.push((run & 0x7f) | 0x80);
      run = Math.floor(run / 128);
    }
    out.push(run);
    value = !value;
  }
  return new Uint8Array(out);
}

/** The pieces a holding states; every piece when the field is null. */
export function decodeHave(data: Uint8Array | null | undefined, pieces: number): Set<number> {
  const have = new Set<number>();
  if (data == null) {
    for (let i = 0; i < pieces; i++) {
      have.add(i);
    }
    return have;
  }
  let pos = 0, i = 0, value = false;
  while (pos < data.length && i < pieces) {
    let run = 0, shift = 0;
    while (pos < data.length) {
      const b = data[pos++];
      run += (b & 0x7f) * 2 ** shift;
      shift += 7;
      if ((b & 0x80) === 0) {
        break;
      }
    }
    const end = Math.min(pieces, i + run);
    if (value) {
      for (let k = i; k < end; k++) {
        have.add(k);
      }
    }
    i = end;
    value = !value;
  }
  return have;
}

/** A `Holding` value in Java field order. */
export function holding(root: string, holder: string, have: Set<number>, pieces: number,
                        via: string[] | null = null): Dict {
  const complete = pieces > 0 && have.size >= pieces;
  let encoded: Uint8Array | null = complete ? null : encodeHave(have, pieces);
  if (encoded !== null && encoded.length > MAX_HAVE_BYTES) {
    encoded = null;
  }
  return { v: VERSION, root, holder, complete, have: encoded, count: have.size,
    via: via !== null && via.length > 0 ? [...via] : null, cost: null };
}

export function holdingTags(h: Dict): Dict {
  return { root: h["root"], holder: h["holder"] };
}

// ------------------------------------------------------------------ messages

export const pieceWant = (root: string, index: number, offset: number, length: number, req: number): Dict =>
  ({ t: PIECE_WANT, root, index, offset, length, req });
export const piece = (root: string, index: number, offset: number, bytes: Uint8Array, req: number): Dict =>
  ({ t: PIECE, root, index, offset, bytes, req });
export const haveMessage = (root: string, have: Uint8Array | null, complete: boolean): Dict =>
  ({ t: HAVE, root, have, complete });
export const cancel = (root: string, index: number, req: number): Dict => ({ t: CANCEL, root, index, req });
export const reject = (root: string, index: number, reason: number): Dict => ({ t: REJECT, root, index, reason });
export const manifestWant = (root: string): Dict => ({ t: MANIFEST_WANT, root });
export const manifestReply = (root: string, record: Uint8Array): Dict => ({ t: MANIFEST, root, record });

// ------------------------------------------------------------------ stores

/**
 * One backend of pieces (the PieceStore SPI in miniature). Callers verify; a store never
 * hashes. `read` may answer later (a remote backend such as a Workers cell's R2 bucket
 * serves a range by a ranged get), and a holder serves it when it lands; a backend that
 * only serves what it already holds leaves `writable` false and refuses `write`.
 */
export interface PieceStore {
  readonly kind: string;
  /** Whether `write` is allowed; absent means yes. */
  readonly writable?: boolean;
  roots(): Set<string>;
  manifest(root: string): Dict | null;
  open(m: Dict): void;
  have(root: string): Set<number>;
  read(root: string, index: number, offset: number, length: number): Uint8Array | null | Promise<Uint8Array | null>;
  write(root: string, index: number, data: Uint8Array): void;
  readAll(root: string): Uint8Array;
  pin(root: string): void;
  unpin(root: string): void;
  flush(): void;
  forget(root: string): void;
}

/** Pieces on the heap; for tests, browsers without OPFS, and small artifacts. */
export class MemoryStore implements PieceStore {
  readonly kind = "memory";
  private readonly held = new Map<string, { manifest: Dict; pieces: Map<number, Uint8Array> }>();
  private readonly pinned = new Set<string>();

  roots(): Set<string> {
    return new Set(this.held.keys());
  }

  manifest(root: string): Dict | null {
    return this.held.get(root)?.manifest ?? null;
  }

  open(m: Dict): void {
    const root = String(m["root"]);
    if (!this.held.has(root)) {
      this.held.set(root, { manifest: m, pieces: new Map() });
    }
  }

  have(root: string): Set<number> {
    return new Set(this.held.get(root)?.pieces.keys() ?? []);
  }

  read(root: string, index: number, offset: number, length: number): Uint8Array | null {
    const data = this.held.get(root)?.pieces.get(index);
    if (data === undefined || offset < 0 || offset > data.length) {
      return null;
    }
    return data.subarray(offset, Math.min(data.length, offset + length));
  }

  write(root: string, index: number, data: Uint8Array): void {
    const h = this.held.get(root);
    if (h === undefined) {
      throw new Error(`root ${root} is not open in this store`);
    }
    if (!h.pieces.has(index)) {
      h.pieces.set(index, new Uint8Array(data));
    }
  }

  readAll(root: string): Uint8Array {
    const h = this.held.get(root);
    const n = h === undefined ? 0 : Number(h.manifest["pieces"]);
    if (h === undefined || h.pieces.size < n) {
      throw new Error(`root ${root} is incomplete here`);
    }
    const out = new Uint8Array(Number(h.manifest["size"]));
    let at = 0;
    for (let i = 0; i < n; i++) {
      const p = h.pieces.get(i)!;
      out.set(p, at);
      at += p.length;
    }
    return out;
  }

  pin(root: string): void { this.pinned.add(root); }
  unpin(root: string): void { this.pinned.delete(root); }
  flush(): void {}
  forget(root: string): void { this.held.delete(root); }
}

// ------------------------------------------------------------------ the fetch

interface Assignment { index: number; length: number; buffer: Uint8Array; units: Set<number>; unitCount: number; next: number }

class Source {
  window = 2;
  inFlight = 0;
  rangeLength = RANGE_UNIT;
  srttMillis = -1;
  successes = 0;
  timeouts = 0;
  droppedUntil = 0;
  bytesVerified = 0;
  assignment: Assignment | null = null;
  retry: [number, number, number][] = [];

  constructor(readonly peer: string, public have: Set<number>, public via: string[] | null) {}
}

interface Outstanding { source: Source; index: number; offset: number; length: number; sent: number }

export interface Progress {
  piecesVerified: number;
  pieces: number;
  bytesReceived: number;
  bytesBySource: { [peer: string]: number };
  sourcesActive: number;
  fraction: number;
}

/**
 * One fetch: the scheduler of SRAD §3.4 in miniature (rarest first, a window of ranges per
 * source, timeouts that halve it, endgame duplicates, per-piece verification, strikes), driven
 * from `Content.tick`.
 */
export class Fetch {
  static readonly MIN_TIMEOUT_MILLIS = 10_000;
  static readonly MAX_WINDOW = 32;
  static readonly TIMEOUTS_BEFORE_DROP = 3;
  static readonly DROP_MILLIS = 60_000;

  manifest: Dict | null = null;
  table: Uint8Array | null = null;
  readonly verified = new Set<number>();
  readonly sources = new Map<string, Source>();
  private readonly outstanding = new Map<number, Outstanding>();
  private readonly assigned = new Map<number, Source[]>();
  readonly trace: string[] = [];
  done = false;
  failure: string | null = null;
  bytesReceived = 0;
  readonly started = Date.now();
  holdingsReadAt = 0;
  manifestAskedAt = 0;
  private scheduling = false;
  private reschedule = false;
  private readonly waiters: (() => void)[] = [];

  constructor(private readonly content: Content, readonly root: string) {}

  get complete(): boolean {
    return this.done && this.failure === null;
  }

  /** Resolves with whether the fetch completed, within `timeoutMillis`. */
  await(timeoutMillis: number): Promise<boolean> {
    if (this.done) {
      return Promise.resolve(this.complete);
    }
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(this.complete), timeoutMillis);
      this.waiters.push(() => { clearTimeout(timer); resolve(this.complete); });
    });
  }

  progress(): Progress {
    const pieces = this.manifest === null ? 0 : Number(this.manifest["pieces"]);
    const bytesBySource: { [peer: string]: number } = {};
    let active = 0;
    for (const s of this.sources.values()) {
      bytesBySource[s.peer] = s.bytesVerified;
      if (s.inFlight > 0) {
        active += 1;
      }
    }
    return { piecesVerified: this.verified.size, pieces, bytesReceived: this.bytesReceived, bytesBySource,
      sourcesActive: active, fraction: pieces === 0 ? 0 : this.verified.size / pieces };
  }

  readBytes(): Uint8Array {
    if (!this.complete) {
      throw new Error(`fetch of ${this.root} is not complete`);
    }
    return this.content.store.readAll(this.root);
  }

  cancel(): void {
    if (!this.done) {
      this.failure = "cancelled";
      this.finish();
    }
  }

  note(line: string): void {
    this.trace.push(line);
    if (this.trace.length > 256) {
      this.trace.splice(0, this.trace.length - 256);
    }
  }

  fail(reason: string): void {
    this.failure = reason;
    this.note(reason);
    this.finish();
  }

  start(m: Dict, table: Uint8Array): void {
    if (this.manifest !== null) {
      return;
    }
    this.manifest = m;
    this.table = table;
    this.content.store.open(m);
    const pieces = Number(m["pieces"]);
    for (const i of this.content.store.have(this.root)) {
      if (i < pieces) {
        this.verified.add(i);
      }
    }
    for (const i of this.verified) {
      this.bytesReceived += pieceLength(Number(m["size"]), Number(m["pieceSize"]), i);
    }
    this.note(`start: ${pieces} pieces of ${String(m["pieceSize"])} bytes, ${this.verified.size} already verified`);
    if (this.verified.size >= pieces) {
      this.finish();
      return;
    }
    this.refreshSources();
    this.schedule();
  }

  tick(): void {
    if (this.done || this.manifest === null) {
      return;
    }
    const now = Date.now();
    this.timeOut(now);
    if (now - this.holdingsReadAt >= 5000) {
      this.refreshSources();
    }
    this.schedule();
  }

  private refreshSources(): void {
    this.holdingsReadAt = Date.now();
    const pieces = Number(this.manifest!["pieces"]);
    const seen = new Set<string>();
    for (const h of this.content.holdings(this.root)) {
      const peer = String(h["holder"]);
      if (peer === this.content.selfId || seen.has(peer)) {
        continue;
      }
      seen.add(peer);
      const have = h["complete"] ? decodeHave(null, pieces) : decodeHave(h["have"] as Uint8Array | null, pieces);
      const via = Array.isArray(h["via"]) ? (h["via"] as unknown[]).filter((v) => typeof v === "string") as string[] : [];
      const existing = this.sources.get(peer);
      if (existing !== undefined) {
        existing.have = have;
        existing.via = via.length > 0 ? via : null;
      } else if (this.sources.size < this.content.maxSessions) {
        this.sources.set(peer, new Source(peer, have, via.length > 0 ? via : null));
        this.note(`source ${peer.slice(0, 10)} (${h["complete"] ? "complete" : `${String(h["count"])} pieces`})`);
      }
    }
  }

  private timeOut(now: number): void {
    for (const [req, o] of [...this.outstanding]) {
      const limit = Math.max(Fetch.MIN_TIMEOUT_MILLIS, o.source.srttMillis > 0 ? 8 * o.source.srttMillis : 0);
      if (now - o.sent <= limit) {
        continue;
      }
      const s = o.source;
      this.outstanding.delete(req);
      s.inFlight = Math.max(0, s.inFlight - 1);
      s.window = Math.max(1, Math.floor(s.window / 2));
      s.rangeLength = Math.max(RANGE_UNIT, Math.floor(s.rangeLength / 2));
      s.timeouts += 1;
      s.retry.unshift([o.index, o.offset, o.length]);
      if (s.timeouts >= Fetch.TIMEOUTS_BEFORE_DROP) {
        s.droppedUntil = now + Fetch.DROP_MILLIS;
        s.timeouts = 0;
        this.release(s);
        this.note(`source ${s.peer.slice(0, 10)} timed out ${Fetch.TIMEOUTS_BEFORE_DROP} times; dropped for 60 s`);
      }
    }
  }

  private release(s: Source): void {
    const a = s.assignment;
    if (a === null) {
      return;
    }
    s.assignment = null;
    s.retry = [];
    const holders = this.assigned.get(a.index);
    if (holders !== undefined) {
      const rest = holders.filter((x) => x !== s);
      if (rest.length === 0) {
        this.assigned.delete(a.index);
      } else {
        this.assigned.set(a.index, rest);
      }
    }
  }

  schedule(): void {
    if (this.scheduling) {
      this.reschedule = true;
      return;
    }
    this.scheduling = true;
    try {
      do {
        this.reschedule = false;
        this.scheduleOnce();
      } while (this.reschedule && !this.done);
    } finally {
      this.scheduling = false;
    }
  }

  private scheduleOnce(): void {
    if (this.done || this.manifest === null) {
      return;
    }
    const now = Date.now();
    const pieces = Number(this.manifest["pieces"]);
    const availability = new Array<number>(pieces).fill(0);
    for (const s of this.sources.values()) {
      for (const i of s.have) {
        if (i < pieces) {
          availability[i] += 1;
        }
      }
    }
    let endgame = true;
    for (let i = 0; i < pieces; i++) {
      if (!this.verified.has(i) && !this.assigned.has(i)) {
        endgame = false;
        break;
      }
    }
    const order = [...this.sources.values()].sort((a, b) =>
      (this.content.hopsTo(a.peer) - this.content.hopsTo(b.peer)) || (b.bytesVerified - a.bytesVerified));
    for (const s of order) {
      if (s.droppedUntil > now) {
        continue;
      }
      let granted = 0;
      while (s.inFlight < s.window && granted < s.window) {
        const range = this.nextRange(s, availability, endgame);
        if (range === null) {
          break;
        }
        const [index, offset, length] = range;
        const req = this.content.nextReq();
        this.outstanding.set(req, { source: s, index, offset, length, sent: now });
        s.inFlight += 1;
        granted += 1;
        this.content.send(s.peer, pieceWant(this.root, index, offset, length, req), s.via);
        if (this.reschedule) {
          break;
        }
      }
    }
  }

  private nextRange(s: Source, availability: number[], endgame: boolean): [number, number, number] | null {
    if (s.retry.length > 0) {
      const [index, offset, length] = s.retry.shift()!;
      if (!this.verified.has(index) && s.assignment !== null && s.assignment.index === index) {
        return [index, offset, length];
      }
    }
    let a = s.assignment;
    if (a !== null && (this.verified.has(a.index) || a.units.size >= a.unitCount)) {
      this.release(s);
      a = null;
    }
    if (a === null) {
      const index = this.pick(s, availability, endgame);
      if (index < 0) {
        return null;
      }
      const m = this.manifest!;
      const length = pieceLength(Number(m["size"]), Number(m["pieceSize"]), index);
      a = { index, length, buffer: new Uint8Array(length), units: new Set(),
        unitCount: Math.ceil(length / RANGE_UNIT), next: 0 };
      s.assignment = a;
      this.assigned.set(index, [...(this.assigned.get(index) ?? []), s]);
    }
    if (a.next >= a.length) {
      return null;
    }
    const offset = a.next;
    const length = Math.min(s.rangeLength, a.length - offset);
    a.next += length;
    return [a.index, offset, length];
  }

  private pick(s: Source, availability: number[], endgame: boolean): number {
    const pieces = Number(this.manifest!["pieces"]);
    let best = -1, bestCount = 1 << 30, ties = 0;
    const cold = this.verified.size === 0 && this.assigned.size === 0;
    for (let i = 0; i < pieces; i++) {
      if (this.verified.has(i) || !s.have.has(i)) {
        continue;
      }
      const holders = this.assigned.get(i);
      if (holders !== undefined && (!endgame || holders.includes(s))) {
        continue;
      }
      const count = cold ? 0 : availability[i];
      if (count < bestCount) {
        best = i;
        bestCount = count;
        ties = 1;
      } else if (count === bestCount) {
        ties += 1;
        if (Math.floor(this.content.random() * ties) === 0) {
          best = i;
        }
      }
    }
    return best;
  }

  onPiece(sender: string, msg: Dict): void {
    if (this.done || this.manifest === null) {
      return;
    }
    const o = this.outstanding.get(Number(msg["req"] ?? -1));
    if (o === undefined) {
      return;
    }
    this.outstanding.delete(Number(msg["req"]));
    const s = o.source;
    if (s.peer !== sender || o.index !== msg["index"] || o.offset !== msg["offset"]) {
      return;
    }
    s.inFlight = Math.max(0, s.inFlight - 1);
    const rtt = Date.now() - o.sent;
    s.srttMillis = s.srttMillis < 0 ? rtt : (s.srttMillis * 7 + rtt) / 8;
    s.timeouts = 0;
    const data = msg["bytes"] instanceof Uint8Array ? msg["bytes"] : new Uint8Array();
    const a = s.assignment;
    if (a === null || a.index !== o.index || this.verified.has(o.index)) {
      this.schedule();
      return;
    }
    if (data.length !== o.length || o.offset + o.length > a.length) {
      s.retry.unshift([o.index, o.offset, o.length]);
      this.schedule();
      return;
    }
    a.buffer.set(data, o.offset);
    for (let u = Math.floor(o.offset / RANGE_UNIT); u <= Math.floor((o.offset + o.length - 1) / RANGE_UNIT); u++) {
      a.units.add(u);
    }
    s.successes += 1;
    if (s.window < Fetch.MAX_WINDOW) {
      s.window += 1;
    }
    const pieceSize = Number(this.manifest["pieceSize"]);
    if (s.successes % 8 === 0 && s.rangeLength < pieceSize) {
      s.rangeLength = Math.min(pieceSize, s.rangeLength * 2);
    }
    if (a.units.size >= a.unitCount) {
      this.completePiece(s, a);
    }
    this.schedule();
  }

  onReject(sender: string, msg: Dict): void {
    const s = this.sources.get(sender);
    if (s === undefined) {
      return;
    }
    for (const [req, o] of this.outstanding) {
      if (o.source === s && o.index === msg["index"]) {
        this.outstanding.delete(req);
        s.inFlight = Math.max(0, s.inFlight - 1);
        s.retry.unshift([o.index, o.offset, o.length]);
        break;
      }
    }
    if (msg["reason"] === REASON_OVER_BUDGET || msg["reason"] === REASON_POLICY) {
      s.droppedUntil = Date.now() + Fetch.DROP_MILLIS;
      this.note(`source ${s.peer.slice(0, 10)} rejected (${String(msg["reason"])}); dropped for a while`);
    } else {
      s.have.delete(Number(msg["index"] ?? -1));
    }
    this.release(s);
    this.schedule();
  }

  private completePiece(s: Source, a: Assignment): void {
    const data = a.buffer;
    if (verifies(this.table!, a.index, data)) {
      this.content.store.write(this.root, a.index, data);
      this.verified.add(a.index);
      this.bytesReceived += data.length;
      s.bytesVerified += data.length;
      for (const other of this.assigned.get(a.index) ?? []) {
        if (other === s) {
          continue;
        }
        for (const [req, o] of [...this.outstanding]) {
          if (o.source === other && o.index === a.index) {
            this.outstanding.delete(req);
            other.inFlight = Math.max(0, other.inFlight - 1);
            this.content.send(other.peer, cancel(this.root, a.index, req), other.via);
          }
        }
        other.assignment = null;
        other.retry = [];
      }
      this.assigned.delete(a.index);
      s.assignment = null;
      this.content.onPieceVerified(this);
      if (this.verified.size >= Number(this.manifest!["pieces"])) {
        this.finish();
      }
    } else {
      this.note(`piece ${a.index} from ${s.peer.slice(0, 10)} failed its hash; struck`);
      this.content.piecesStruck += 1;
      this.release(s);
      s.droppedUntil = Number.POSITIVE_INFINITY;
    }
  }

  private finish(): void {
    if (this.done) {
      return;
    }
    if (this.failure === null) {
      this.note(`complete: ${this.verified.size} pieces, ${this.bytesReceived} bytes in ${Date.now() - this.started} ms`);
    }
    this.outstanding.clear();
    this.done = true;
    if (this.failure === null) {
      this.content.onComplete(this);
    }
    for (const w of this.waiters.splice(0)) {
      w();
    }
  }
}

// ------------------------------------------------------------------ the capability

export interface ContentOptions {
  /** The publisher's default piece size. */
  pieceSize?: number;
  /** Sources a fetch draws from at once. */
  maxSessions?: number;
  /** Payload bytes above which a space over this peer escalates to an artifact; 0 disables. */
  escalateAbove?: number;
  /** Refuses a want when it returns false (the policy seam). */
  mayServe?: ((peer: string, manifest: Dict) => boolean) | null;
  /** A deterministic random source for tests. */
  random?: () => number;
}

export interface PublishOptions {
  name?: string | null;
  mediaType?: string | null;
  attrs?: { [key: string]: string } | null;
  lease?: number | string;
  pieceSize?: number;
  replicate?: boolean;
}

interface HolderState { count: number; writtenAt: number; entryId: string | null }

/**
 * The content swarm over a `Pipes` and the group's content `Space`. `run(intervalMillis)`
 * drives the ticks on the peer's timers, or the host calls `tick`. Constructing it attaches it
 * to the peer (`peer.content`), so every `Space` over the peer escalates payloads above
 * `escalateAbove` to artifacts.
 */
export class Content implements BulkPayloads {
  static readonly HOLDING_LEASE = "2m";
  static readonly MANIFEST_LEASE = "7d";

  readonly peer: Peer;
  readonly selfId: string;
  readonly pieceSize: number;
  readonly maxSessions: number;
  readonly escalateAbove: number;
  readonly random: () => number;
  private readonly mayServe: ((peer: string, manifest: Dict) => boolean) | null;
  private readonly spaceId: string;
  readonly fetches = new Map<string, Fetch>();
  private readonly holderState = new Map<string, HolderState>();
  private req = 0;
  private ticking: { stop(): void } | null = null;
  bytesServed = 0;
  wantsRefused = 0;
  piecesStruck = 0;

  constructor(readonly pipes: Pipes, readonly space: Space, readonly store: PieceStore = new MemoryStore(),
              options: ContentOptions = {}) {
    this.peer = pipes.peer;
    this.selfId = this.peer.identity.peerId;
    this.pieceSize = options.pieceSize ?? DEFAULT_PIECE_SIZE;
    this.maxSessions = options.maxSessions ?? 16;
    this.escalateAbove = options.escalateAbove ?? 4 * 1024 * 1024;
    this.mayServe = options.mayServe ?? null;
    this.random = options.random ?? Math.random;
    this.spaceId = spaceIdLocal(`${this.peer.group}/${space.name}`);
    pipes.onCapability(TYPE, (from, payload) => this.onFrame(from, payload));
    this.peer.content = this;
    this.start();
  }

  // ---- wiring

  /** Publishes holdings for everything the store already holds. */
  start(): void {
    for (const root of this.store.roots()) {
      if (this.store.have(root).size > 0) {
        this.refreshHolding(root, true);
      }
    }
  }

  run(intervalMillis = 250): void {
    if (this.ticking === null) {
      this.ticking = this.peer.every(intervalMillis, () => this.tick());
    }
  }

  stop(): void {
    this.ticking?.stop();
    this.ticking = null;
    this.store.flush();
  }

  nextReq(): number {
    this.req += 1;
    return this.req;
  }

  send(to: string, msg: Dict, via: string[] | null = null): void {
    this.pipes.send(to, TYPE, dumps(msg), via);
  }

  hopsTo(peerId: string): number {
    return this.peer.relayFor(peerId) === null ? 0 : 1;
  }

  // ---- the replica

  private records(typeName: string, root: string | null = null): Dict[] {
    const now = this.peer.now();
    const found: Dict[] = [];
    for (const dto of this.peer.states.values()) {
      const record = (dto["record"] as Dict | undefined) ?? {};
      if (record["type"] !== typeName || dto["completed"] || record["spaceId"] !== this.spaceId) {
        continue;
      }
      const lease = (record["lease"] as Dict | undefined) ?? {};
      if (Number(lease["expiresAtMillis"] ?? 0) <= now) {
        continue;
      }
      if (root !== null && ((record["tags"] as Dict | undefined) ?? {})["root"] !== root) {
        continue;
      }
      const payload = record["payload"];
      if (!(payload instanceof Uint8Array)) {
        continue;
      }
      try {
        const value = loads(payload);
        if (typeof value === "object" && value !== null && !(value instanceof Uint8Array) && !Array.isArray(value)) {
          found.push(value as Dict);
        }
      } catch {
        // a malformed record is not a manifest or a holding
      }
    }
    return found;
  }

  manifestOf(root: string): Dict | null {
    const held = this.store.manifest(root);
    if (held !== null) {
      return held;
    }
    for (const candidate of this.records(MANIFEST_TYPE, root)) {
      if (manifestViolation(candidate) === null) {
        return candidate;
      }
    }
    return null;
  }

  /** One holding per holder: the fullest one, since a holder that cannot withdraw leaves earlier ones to lapse. */
  holdings(root: string): Dict[] {
    const best = new Map<string, Dict>();
    for (const h of this.records(HOLDING_TYPE, root)) {
      if (h["v"] !== VERSION || typeof h["holder"] !== "string") {
        continue;
      }
      const seen = best.get(h["holder"]);
      const better = seen === undefined || (Boolean(h["complete"]) && !seen["complete"])
        || (Boolean(h["complete"]) === Boolean(seen["complete"]) && Number(h["count"] ?? 0) > Number(seen["count"] ?? 0));
      if (better) {
        best.set(h["holder"], h);
      }
    }
    return [...best.values()];
  }

  describe(root: string): Dict | null {
    const m = this.manifestOf(root);
    if (m === null) {
      return null;
    }
    const hs = this.holdings(root);
    return { manifest: m, completeHolders: hs.filter((h) => Boolean(h["complete"])).length,
      partialHolders: hs.filter((h) => !h["complete"]).length, held: this.store.have(root).size };
  }

  listManifests(limit = 1000): Dict[] {
    return this.records(MANIFEST_TYPE).filter((m) => manifestViolation(m) === null).slice(0, limit);
  }

  // ---- publish

  /** Publishes bytes; returns the manifest. */
  publish(data: Uint8Array, options: PublishOptions = {}): Dict {
    const pieceSize = options.pieceSize ?? this.pieceSize;
    const n = piecesOf(data.length, pieceSize);
    if (n > INLINE_TABLE_PIECES) {
      throw new Error("artifacts above 64 pieces need the block exchange for their table; "
        + "use a larger piece size (this client keeps the table inline)");
    }
    const table = hashPieces(data, pieceSize);
    const m = manifest(contentRoot(table), data.length, pieceSize, table, this.selfId, this.peer.now(),
      { name: options.name ?? null, mediaType: options.mediaType ?? null, attrs: options.attrs ?? null });
    this.store.open(m);
    for (let i = 0; i < n; i++) {
      this.store.write(String(m["root"]), i, data.subarray(i * pieceSize, Math.min(data.length, (i + 1) * pieceSize)));
    }
    return this.published(m, options.lease ?? Content.MANIFEST_LEASE, options.replicate ?? true);
  }

  /**
   * Publishes a root the store already holds in full (a backend that maps a root to an
   * object it serves in place, such as a Workers cell's R2 bucket): writes the manifest and
   * this peer's complete holding without copying a byte.
   */
  publishManifest(m: Dict, options: Pick<PublishOptions, "lease" | "replicate"> = {}): Dict {
    if (manifestViolation(m) !== null) {
      throw new Error(`manifest refused: ${manifestViolation(m)}`);
    }
    const root = String(m["root"]);
    this.store.open(m);
    if (this.store.have(root).size < Number(m["pieces"])) {
      throw new Error(`root ${root} is not complete in this store`);
    }
    return this.published(m, options.lease ?? Content.MANIFEST_LEASE, options.replicate ?? true);
  }

  /** A space's escalation seam: the payload as the space produced it; returns the root. */
  publishOpaque(payload: Uint8Array, leaseMillis: number): string {
    let ps = this.pieceSize;
    while (piecesOf(payload.length, ps) > INLINE_TABLE_PIECES && ps < MAX_PIECE_SIZE) {
      ps *= 2;
    }
    return String(this.publish(payload, { mediaType: "application/cbor", lease: leaseMillis, pieceSize: ps })["root"]);
  }

  private published(m: Dict, lease: number | string, replicate: boolean): Dict {
    const root = String(m["root"]);
    this.store.pin(root);
    if (replicate && this.records(MANIFEST_TYPE, root).length === 0) {
      this.write(MANIFEST_TYPE, m, lease, manifestTags(m));
    }
    this.refreshHolding(root, true);
    return m;
  }

  /** The bridge: writes a manifest here for a root the store holds in full. */
  share(root: string, lease: number | string = Content.MANIFEST_LEASE): Dict {
    const m = this.store.manifest(root);
    if (m === null || this.store.have(root).size < Number(m["pieces"])) {
      throw new Error(`root ${root} is not complete in this store`);
    }
    return this.published({ ...m, origin: this.selfId, created: this.peer.now() }, lease, true);
  }

  pin(root: string): void { this.store.pin(root); }
  unpin(root: string): void { this.store.unpin(root); }

  // ---- fetch

  fetch(root: string): Fetch {
    if (!isRoot(root)) {
      throw new Error(`not a content root: ${root}`);
    }
    const existing = this.fetches.get(root);
    if (existing !== undefined) {
      return existing;
    }
    const f = new Fetch(this, root);
    this.fetches.set(root, f);
    this.drive(f);
    return f;
  }

  /** The complete artifact when the store holds it (the space's read seam). */
  local(root: string): Uint8Array | null {
    const m = this.store.manifest(root);
    if (m === null || this.store.have(root).size < Number(m["pieces"])) {
      return null;
    }
    return this.store.readAll(root);
  }

  /** Starts or continues acquiring a root (the space's read seam). */
  ensure(root: string): void {
    this.fetch(root);
  }

  private drive(f: Fetch): void {
    if (f.done) {
      this.fetches.delete(f.root);
      return;
    }
    if (f.manifest === null) {
      const m = this.manifestOf(f.root);
      if (m === null) {
        const now = Date.now();
        if (now - f.manifestAskedAt >= 2000) {
          f.manifestAskedAt = now;
          for (const h of this.holdings(f.root)) {
            if (h["holder"] !== this.selfId) {
              this.send(String(h["holder"]), manifestWant(f.root));
            }
          }
        }
        return;
      }
      if (!(m["table"] instanceof Uint8Array)) {
        f.fail("the manifest's table is a block; this client keeps tables inline");
      } else if (m["sealing"] !== SEALING_NONE) {
        f.fail("sealed root; this client holds no content key");
      } else {
        f.start(m, m["table"]);
      }
      if (f.done) {
        this.fetches.delete(f.root);
      }
      return;
    }
    f.tick();
    if (f.done) {
      this.fetches.delete(f.root);
    }
  }

  tick(): void {
    for (const f of [...this.fetches.values()]) {
      this.drive(f);
    }
    for (const root of [...this.holderState.keys()]) {
      this.refreshHolding(root, false);
    }
  }

  // ---- holdings

  private refreshHolding(root: string, force: boolean): void {
    const m = this.store.manifest(root);
    if (m === null) {
      return;
    }
    const have = this.store.have(root);
    if (have.size === 0) {
      return;
    }
    let state = this.holderState.get(root);
    if (state === undefined) {
      state = { count: -1, writtenAt: 0, entryId: null };
      this.holderState.set(root, state);
    }
    const now = Date.now();
    const pieces = Number(m["pieces"]);
    const complete = have.size >= pieces;
    const changed = state.count !== have.size;
    const due = force || state.entryId === null
      || (changed && (complete || now - state.writtenAt >= 10_000 || have.size - state.count >= 32));
    if (due) {
      const via = this.peer.relayFor(this.selfId) !== null && this.peer.seedPeer !== null ? [this.peer.seedPeer] : null;
      const h = holding(root, this.selfId, have, pieces, via);
      state.entryId = this.write(HOLDING_TYPE, h, Content.HOLDING_LEASE, holdingTags(h));
      state.count = have.size;
      state.writtenAt = now;
    } else if (now - state.writtenAt >= 50_000 && state.entryId !== null) {
      try {
        this.peer.renewEntry(this.space.name, state.entryId, 120_000, null);
        state.writtenAt = now;
      } catch {
        state.entryId = null;
      }
    }
  }

  onPieceVerified(f: Fetch): void {
    this.refreshHolding(f.root, false);
  }

  onComplete(f: Fetch): void {
    this.store.pin(f.root);
    this.refreshHolding(f.root, true);
    this.store.flush();
  }

  // ---- the holder side

  private onFrame(sender: string, payload: Uint8Array): void {
    let msg: Dict;
    try {
      msg = loads(payload) as Dict;
    } catch {
      return;
    }
    if (typeof msg !== "object" || msg === null) {
      return;
    }
    const t = msg["t"];
    const root = String(msg["root"]);
    if (t === PIECE_WANT) {
      this.serve(sender, msg);
    } else if (t === PIECE) {
      const f = this.fetches.get(root);
      if (f !== undefined) {
        f.onPiece(sender, msg);
        if (f.done) {
          this.fetches.delete(root);
        }
      }
    } else if (t === REJECT) {
      this.fetches.get(root)?.onReject(sender, msg);
    } else if (t === MANIFEST_WANT) {
      const m = this.store.manifest(root);
      if (m !== null) {
        this.send(sender, manifestReply(root, dumps(m)));
      }
    } else if (t === MANIFEST) {
      const f = this.fetches.get(root);
      if (f === undefined || f.manifest !== null) {
        return;
      }
      let m: Dict;
      try {
        m = loads(msg["record"] instanceof Uint8Array ? msg["record"] : new Uint8Array()) as Dict;
      } catch {
        return;
      }
      if (typeof m === "object" && m !== null && m["root"] === f.root && manifestViolation(m) === null) {
        this.store.open(m);
        this.drive(f);
      }
    }
  }

  private serve(sender: string, want: Dict): void {
    const root = String(want["root"]);
    const m = this.store.manifest(root);
    if (m === null) {
      this.refuse(sender, want, REASON_UNKNOWN_ROOT);
      return;
    }
    if ((this.mayServe !== null && !this.mayServe(sender, m)) || m["sealing"] !== SEALING_NONE) {
      this.refuse(sender, want, REASON_POLICY);
      return;
    }
    const length = Number(want["length"] ?? 0);
    if (!(length > 0 && length <= MAX_PIECE_SIZE)) {
      this.refuse(sender, want, REASON_UNKNOWN_ROOT);
      return;
    }
    const got = this.store.read(root, Number(want["index"] ?? -1), Number(want["offset"] ?? 0), length);
    const reply = (data: Uint8Array | null): void => {
      if (data === null) {
        this.refuse(sender, want, REASON_NOT_HELD);
        return;
      }
      this.bytesServed += data.length;
      this.send(sender, piece(root, Number(want["index"]), Number(want["offset"]), data, Number(want["req"])));
    };
    if (got instanceof Promise) {
      got.then(reply, () => reply(null));
    } else {
      reply(got);
    }
  }

  private refuse(sender: string, want: Dict, reason: number): void {
    this.wantsRefused += 1;
    this.send(sender, reject(String(want["root"]), Number(want["index"] ?? -1), reason));
  }

  /** A reserved record (`<fqcn>#v1`) written in Java field order, never escalated. */
  private write(typeName: string, value: Dict, lease: number | string, tags: Dict): string {
    return this.peer.writeEntry(this.space.name, typeName, value, this.space.agentName,
      durationMillis(lease), this.space.agent, tags);
  }

  stats(): Dict {
    return { fetchesActive: this.fetches.size, rootsHeld: this.store.roots().size, bytesServed: this.bytesServed,
      wantsRefused: this.wantsRefused, piecesStruck: this.piecesStruck };
  }
}

/** The block id helper the legacy exchange uses (`z` + base58 of sha-256), for callers that mix both. */
export function blockId(data: Uint8Array): string {
  return multibase(sha256(data));
}
