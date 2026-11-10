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
 * The node codec of the persistent data structures (srad/agentspaces-pdt.md §3.1, PD-N-01, PD-N-03,
 * PD-N-04, §10.2), a port of the Java `NodeCodec`: a node is a definite-length CBOR map with text keys
 * in DAG-CBOR order (shorter key first, then bytewise), shortest integer heads, a link as tag 42 over a
 * byte string of `0x00` plus the binary CID, and application items (keys, values, elements) spliced in as
 * the raw CBOR bytes the client's codec gives them. The node's own layer is strict DAG-CBOR; an embedded
 * item keeps the client codec's form (an indefinite map, a float64), which is why `@ipld/dag-cbor` accepts
 * `pdt_node_dagcbor` and refuses `pdt_node_embedded` (the PD-N-03 test records both).
 *
 * Kinds and schemas: `m` {d, n, e, c, cnt}, `mc` {e}, `v` {c | e}, `vr` {n, s, r, t}, `b` {h, c, z},
 * `x` {v}. A decoder refuses a node over 1 MiB, more than 1,024 links, a key outside the kind's schema,
 * an unknown kind, an unknown link codec, keys out of order, and trailing bytes, naming the rule.
 *
 * Both directions also refuse an embedded item that is no document in the wire encoding (rules S1 to
 * S12, the big-number tags 2, 3 and 4 included, no other tag), as Java's NodeCodec does (HLC round six,
 * 2026-11-08, definition 2.4 and change JD-4). A bare link item in a value slot, a spilled value
 * (PD-N-05), is the one exception; a key never spills.
 *
 * PDT 2 phase 0 (srad/agentspaces-pdt2.md §3, annex H as Java's NodeCodec carries it) adds the seven
 * level-2 kinds, strict DAG-CBOR down to every item except a `db` root's schema and an `rr` tail, which
 * keep the embedded rules above: `db` {v, s, me, mt, bf, i: {aevt, avet, eavt} of links, t: tail link or
 * null} and `dn` {l, x, e: [datom...], c} (P2-D-01), `rr` {n, s, r, t} and `rv` {c, z} (P2-R-01), `t`
 * {r: [run...], v} (P2-T-01), `vg` {r: CID text, b: [CID text...], i, t, p: [link...]} (P2-V-01), and `bo`
 * {g, n, p: bytes, c} (P2-B-02). Their text is well-formed UTF-8 with no lone surrogate, every header is
 * in its shortest form, and a datom float is a finite float64. Kinds `s`, `tm` and `ec` are reserved
 * (PD-F-01, P2-F-04); the typed readers of `kinds.ts` check the rules that span fields.
 */

import { compare, concat, fromUtf8, utf8 } from "../bytes.js";
import { CborDouble, loads } from "../cbor.js";
import * as cids from "./cids.js";

export const MAX_NODE_BYTES = 1024 * 1024;
export const MAX_LINKS = 1024;
export const MAX_DEPTH = 64;
export const LINK_TAG = 42;
export const KIND_KEY = "k";

export const KIND_M = "m", KIND_MC = "mc", KIND_V = "v", KIND_VR = "vr", KIND_B = "b", KIND_X = "x";
/**
 * The sealed envelope of the `sealed-nodes` mode (PD-P-05, srad/agentspaces-pdt.md §10.2):
 * `{k:"sn", ct: ciphertext and tag, ep: epoch, ln: [links of the plaintext], nc: nonce}`. This
 * port walks it (its links are in the clear) and does not open it.
 */
export const KIND_SN = "sn";
/** PDT 2 phase 0 (P2-D-01): a DataScript database root and a sorted-set node (srad/agentspaces-pdt2.md §3.1.1). */
export const KIND_DB = "db", KIND_DN = "dn";
/** PDT 2 phase 0 (P2-R-01): an RRB vector root and interior node (§3.7). */
export const KIND_RR = "rr", KIND_RV = "rv";
/** PDT 2 phase 0 (P2-T-01): a text leaf of Fugue runs (§3.9). */
export const KIND_T = "t";
/** PDT 2 phase 0 (P2-V-01): a version graph node, named by the attribute `pdt.ancestry` (§3.10). */
export const KIND_VG = "vg";
/** PDT 2 phase 0 (P2-B-02): a node of a blob's Bao outboard, named by the attribute `pdt.bao` (§3.5). */
export const KIND_BO = "bo";
/**
 * Kinds reserved for later layouts, which a decoder refuses by name: `s` sorted map (PD-F-01), `tm` text
 * marks and `ec` erasure-coded stripe (PDT 2 phase 0, P2-F-04). PDT 2 gave `rr` its schema.
 */
export const RESERVED_KINDS = new Set(["s", "tm", "ec"]);
/** An `sn` node may reach 1 MiB plus 48 KiB; every other kind keeps the 1 MiB bound. */
export const MAX_SEALED_NODE_BYTES = 1024 * 1024 + 48 * 1024;

/** The 41-byte link item: d8 2a 58 25 00 + binary CID. */
export const LINK_ITEM_LENGTH = 5 + cids.BINARY_LENGTH;

/** A link to another node by CID. */
export class Link {
  constructor(readonly cid: string) {}
}

/** An application item embedded as its raw CBOR bytes. */
export class Embedded {
  constructor(readonly bytes: Uint8Array) {}
}

/**
 * A signed 64-bit integer of a datom (PDT 2 phase 0, P2-D-01): a number within the safe range, a bigint
 * outside it, so one value has one form and two equal datoms compare equal.
 */
export type Int64 = number | bigint;

const INT64_MIN = -(1n << 63n);
const INT64_MAX = (1n << 63n) - 1n;

/** `value` in its one form, or a RangeError naming `what` when it is no signed 64-bit integer. */
function int64(value: Int64, what: string): Int64 {
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    if (Number.isInteger(value)) {
      throw new RangeError(`${what} ${value} is not a signed 64-bit integer held exactly`);
    }
    throw new RangeError(`${what} must be an integer, found ${value}`);
  }
  const big = BigInt(value);
  if (big < INT64_MIN || big > INT64_MAX) {
    throw new RangeError(`${what} ${big} is not a signed 64-bit integer`);
  }
  return Number.isSafeInteger(Number(big)) && BigInt(Number(big)) === big ? Number(big) : big;
}

/**
 * A tagged datom value, `[tag, inner]` on the wire (PDT 2 phase 0, P2-D-01; §3.1.1): `u` over the 16 bytes
 * of a UUID, `i` over epoch milliseconds, `n` over the minimal big-endian two's complement bytes of a big
 * integer (Java's `BigInteger.toByteArray`).
 */
export class DatomTag {
  readonly inner: Uint8Array | Int64;

  constructor(readonly tag: "u" | "i" | "n", inner: Uint8Array | Int64) {
    switch (tag) {
      case "u":
        if (!(inner instanceof Uint8Array) || inner.length !== 16) {
          throw new RangeError("a uuid value holds 16 bytes");
        }
        this.inner = inner;
        break;
      case "i":
        if (inner instanceof Uint8Array) {
          throw new RangeError("an instant value holds an integer of epoch milliseconds");
        }
        this.inner = int64(inner, "an instant");
        break;
      case "n":
        if (!(inner instanceof Uint8Array) || !minimalTwosComplement(inner)) {
          throw new RangeError("a bigint value holds its minimal two's complement bytes");
        }
        this.inner = inner;
        break;
      default:
        throw new RangeError(`unknown value tag '${String(tag)}'`);
    }
  }

  /** The tagged form of a UUID's 16 bytes, most significant first. */
  static uuid(bytes: Uint8Array): DatomTag {
    return new DatomTag("u", bytes);
  }

  /** The tagged form of an instant in epoch milliseconds. */
  static instant(epochMillis: Int64): DatomTag {
    return new DatomTag("i", epochMillis);
  }

  /** The tagged form of a big integer: the fewest two's complement bytes that hold it. */
  static bigint(value: bigint): DatomTag {
    const out: number[] = [];
    let rest = value;
    do {
      out.unshift(Number(rest & 0xffn));
      rest >>= 8n;
    } while (!((rest === 0n && (out[0]! & 0x80) === 0) || (rest === -1n && (out[0]! & 0x80) !== 0)));
    return new DatomTag("n", Uint8Array.from(out));
  }
}

/** Whether bytes are what `BigInteger.toByteArray` writes: non-empty, with no redundant sign byte. */
function minimalTwosComplement(b: Uint8Array): boolean {
  if (b.length === 0) {
    return false;
  }
  return b.length === 1 || !((b[0] === 0 && b[1]! < 0x80) || (b[0] === 0xff && b[1]! >= 0x80));
}

/**
 * A datom value (PDT 2 phase 0, P2-D-01; §3.1.1): an integer (or a ref), text (or a keyword's print form),
 * a boolean, bytes, a finite float64 held as a {@link CborDouble}, a {@link Link} (a value spilled out of
 * line, PD-N-05), or a {@link DatomTag}.
 */
export type DatomValue = Int64 | string | boolean | Uint8Array | CborDouble | Link | DatomTag;

/**
 * One datom of a `dn` node (PDT 2 phase 0, P2-D-01; srad/agentspaces-pdt2.md §3.1.1): on the wire the
 * definite array `[e, a, v, tx]`, the entity and the transaction as CBOR integers (a negative transaction
 * marks a retraction), the attribute as the keyword's print form. The constructor refuses tx 0 and a value
 * outside the grammar, as Java's Datom does.
 */
export class Datom {
  readonly e: Int64;
  readonly v: DatomValue;
  readonly tx: Int64;

  constructor(e: Int64, readonly a: string, v: DatomValue, tx: Int64) {
    this.e = int64(e, "a datom's entity");
    this.tx = int64(tx, "a datom's tx");
    if (this.tx === 0) {
      throw new RangeError("a datom's tx is non-zero: its sign marks a retraction");
    }
    if (typeof a !== "string") {
      throw new RangeError("a datom's attribute is text");
    }
    if (typeof v === "number" || typeof v === "bigint") {
      if (typeof v === "number" && !Number.isInteger(v)) {
        throw new RangeError(`a datom float travels as a CborDouble, found the number ${v}`);
      }
      this.v = int64(v, "a datom's value");
    } else if (v instanceof CborDouble) {
      if (v.constructor !== CborDouble || !Number.isFinite(v.value)) {
        throw new RangeError(`a datom float is a finite float64, found ${String(v.value)}`);
      }
      this.v = v;
    } else if (typeof v === "string" || typeof v === "boolean" || v instanceof Uint8Array || v instanceof Link
        || v instanceof DatomTag) {
      this.v = v;
    } else {
      throw new RangeError(`a datom value is an integer, text, a boolean, bytes, a float64, a link, or a tagged pair; `
        + `the grammar holds no ${describe(v)}`);
    }
  }
}

/** A character id of a text leaf: the replica and the counter (PDT 2 phase 0, P2-T-01). */
export class CharId {
  constructor(readonly replica: string, readonly counter: number) {
    if (typeof replica !== "string" || replica.length === 0) {
      throw new RangeError("a character id names a non-empty replica");
    }
    if (!Number.isSafeInteger(counter) || counter < 0) {
      throw new RangeError(`a character counter is a non-negative integer, found ${counter}`);
    }
  }
}

/**
 * One run of a text leaf, kind `t` (PDT 2 phase 0, P2-T-01; srad/agentspaces-pdt2.md §3.9): characters from
 * one replica with consecutive counters, each after the first the right child of the one before it. On the
 * wire the definite array `[replica, counter, parent, side, length, deleted, text]`, with the points Java's
 * build pinned: the parent is the Fugue parent of the first character as `[replica, counter]` or null for
 * the document root, `length` counts code points, and a deleted run keeps its ids and drops its text.
 */
export class TextRun {
  constructor(readonly replica: string, readonly counter: number, readonly parent: CharId | null,
      readonly side: "L" | "R", readonly length: number, readonly deleted: boolean, readonly text: string) {
    if (typeof replica !== "string" || replica.length === 0) {
      throw new RangeError("a run names a non-empty replica");
    }
    if (!Number.isSafeInteger(counter) || counter < 0) {
      throw new RangeError(`a run counter is a non-negative integer, found ${counter}`);
    }
    if (side !== "L" && side !== "R") {
      throw new RangeError(`a run side is L or R, found '${String(side)}'`);
    }
    if (parent === null && side === "L") {
      // the document root is the leftmost neighbour of every insert, so Fugue gives it right children only
      throw new RangeError("a child of the document root hangs on its right, found side L");
    }
    if (!Number.isSafeInteger(length) || length < 1) {
      throw new RangeError(`a run length is at least 1, found ${length}`);
    }
    if (counter + length > Number.MAX_SAFE_INTEGER) {
      throw new RangeError("a run's counters pass 2^53 - 1");
    }
    if (LONE_SURROGATE.test(text)) {
      throw new RangeError("a run's text holds a lone surrogate");
    }
    if (deleted && text.length > 0) {
      throw new RangeError("a deleted run carries no text");
    }
    const codePoints = [...text].length;
    if (!deleted && codePoints !== length) {
      throw new RangeError(`a live run of length ${length} holds ${codePoints} code points`);
    }
  }
}

/** A `db` root's index map (PDT 2 phase 0, P2-D-01): exactly `aevt`, `avet` and `eavt`, each a link. */
export interface IndexLinks {
  readonly aevt: Link;
  readonly avet: Link;
  readonly eavt: Link;
}

/** The keys of a `db` root's index map, in DAG-CBOR order. */
const INDEX_KEYS = ["aevt", "avet", "eavt"] as const;

/** A string holding a UTF-16 surrogate outside a pair, which UTF-8 cannot carry. */
const LONE_SURROGATE = /\p{Cs}/u;

/** UTF-8 that refuses a malformed sequence instead of replacing it (PDT 2 phase 0). */
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export type Field = "uint" | "link" | "linkOrNull" | "links" | "embedded" | "embeddeds" | "uints" | "bytes"
  // PDT 2 phase 0 (P2-D-01, P2-T-01, P2-V-01): the strict field types of the level-2 kinds
  | "text" | "cid" | "cids" | "index" | "datoms" | "runs";

const SCHEMAS: { [kind: string]: { [key: string]: Field } } = {
  m: { d: "uint", n: "uint", e: "embeddeds", c: "links", cnt: "uint" },
  mc: { e: "embeddeds" },
  v: { c: "links", e: "embeddeds" },
  vr: { n: "uint", s: "uint", r: "linkOrNull", t: "embeddeds" },
  b: { h: "uint", c: "links", z: "uints" },
  x: { v: "embedded" },
  sn: { ct: "bytes", ep: "uint", ln: "links", nc: "bytes" },
  // PDT 2 phase 0 (srad/agentspaces-pdt2.md §3.1.1, §3.5, §3.7, §3.9, §3.10)
  db: { v: "uint", s: "embedded", me: "uint", mt: "uint", bf: "uint", i: "index", t: "linkOrNull" },
  dn: { l: "uint", x: "text", e: "datoms", c: "links" },
  rr: { n: "uint", s: "uint", r: "linkOrNull", t: "embeddeds" },
  rv: { c: "links", z: "uints" },
  t: { r: "runs", v: "uint" },
  vg: { r: "cid", b: "cids", i: "text", t: "text", p: "links" },
  bo: { g: "uint", n: "uint", p: "bytes", c: "links" },
};

export type NodeValue = number | Link | null | Link[] | Embedded | Embedded[] | number[] | string | Uint8Array
  | string[] | IndexLinks | Datom[] | TextRun[];
export type Node = { [key: string]: NodeValue };

/** A node the codec refuses, with the rule and (when known) the CID. */
export class NodeFormatError extends Error {
  constructor(message: string, readonly cid: string | null = null) {
    super(cid === null ? message : `${cid}: ${message}`);
    this.name = "NodeFormatError";
  }
}

export function schemaOf(kind: string, cid: string | null = null): { [key: string]: Field } {
  if (RESERVED_KINDS.has(kind)) {
    throw new NodeFormatError(`kind '${kind}' is reserved and has no schema in this release`, cid);
  }
  const schema = SCHEMAS[kind];
  if (schema === undefined) {
    throw new NodeFormatError(`unknown kind '${kind}'`, cid);
  }
  return schema;
}

/** DAG-CBOR key order: shorter UTF-8 first, then bytewise. */
export function compareKeys(a: string, b: string): number {
  const ab = utf8(a), bb = utf8(b);
  return ab.length - bb.length || compare(ab, bb);
}

// ------------------------------------------------------------------ writing

export function header(major: number, value: number): Uint8Array {
  if (value < 24) {
    return Uint8Array.of((major << 5) | value);
  }
  if (value < 0x100) {
    return Uint8Array.of((major << 5) | 24, value);
  }
  if (value < 0x10000) {
    return Uint8Array.of((major << 5) | 25, value >>> 8, value & 0xff);
  }
  if (value < 0x100000000) {
    return Uint8Array.of((major << 5) | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
  }
  if (!Number.isSafeInteger(value)) {
    throw new NodeFormatError(`integer ${value} is not a safe integer`);
  }
  const out = new Uint8Array(9);
  out[0] = (major << 5) | 27;
  new DataView(out.buffer).setBigUint64(1, BigInt(value), false);
  return out;
}

/** The 41-byte tag-42 link item of a CID. */
export function linkItem(cid: string): Uint8Array {
  const out = new Uint8Array(LINK_ITEM_LENGTH);
  out.set([0xd8, LINK_TAG, 0x58, LINK_ITEM_LENGTH - 4, 0x00], 0);
  out.set(cids.binary(cid), 5);
  return out;
}

/** Whether an item is exactly a tag-42 link item. */
export function isLinkShaped(bytes: Uint8Array): boolean {
  return bytes.length === LINK_ITEM_LENGTH && bytes[0] === 0xd8 && bytes[1] === LINK_TAG
    && bytes[2] === 0x58 && bytes[3] === LINK_ITEM_LENGTH - 4 && bytes[4] === 0x00;
}

/** The CID a link-shaped item names, or null. */
export function spilledLink(bytes: Uint8Array): string | null {
  if (!isLinkShaped(bytes)) {
    return null;
  }
  try {
    return cids.fromBinary(bytes.subarray(5));
  } catch (e) {
    throw new NodeFormatError(`spilled value link refused: ${e instanceof Error ? e.message : String(e)}`);
  }
}

function text(value: string): Uint8Array {
  const bytes = utf8(value);
  return concat(header(3, bytes.length), bytes);
}

/** A header whose argument is a bigint up to 2^64 - 1, in its shortest form (PDT 2 phase 0, P2-D-01). */
function bigHeader(major: number, value: bigint): Uint8Array {
  if (value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return header(major, Number(value));
  }
  const out = new Uint8Array(9);
  out[0] = (major << 5) | 27;
  new DataView(out.buffer).setBigUint64(1, value, false);
  return out;
}

/** A signed integer: major type 0, or major type 1 over -1 - value (PDT 2 phase 0, P2-D-01). */
function sint(value: Int64): Uint8Array {
  const big = BigInt(value);
  return big >= 0n ? bigHeader(0, big) : bigHeader(1, -1n - big);
}

/** Text that UTF-8 can carry: a lone surrogate is refused, never replaced (PDT 2 phase 0). */
function strictText(key: string, value: unknown): Uint8Array {
  if (typeof value !== "string") {
    throw new NodeFormatError(`'${key}' must hold text, found ${describe(value)}`);
  }
  if (LONE_SURROGATE.test(value)) {
    throw new NodeFormatError(`'${key}' text holds a lone surrogate`);
  }
  return text(value);
}

/** A CID held as text (PDT 2 phase 0, P2-V-01): a `vg` node names roots without linking them. */
function cidText(key: string, value: unknown): Uint8Array {
  if (!cids.isCid(value)) {
    throw new NodeFormatError(`'${key}' must hold a CID as text, found ${typeof value === "string" ? `'${value}'` : describe(value)}`);
  }
  return text(value);
}

/** Whether a value is an index map's shape before its keys are checked. */
function isIndexShaped(value: unknown): value is { [key: string]: unknown } {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array)
    && !(value instanceof Link) && !(value instanceof Embedded);
}

function uintOf(key: string, value: NodeValue): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new NodeFormatError(`'${key}' must be an unsigned integer, found ${describe(value)}`);
  }
  return value;
}

function describe(value: unknown): string {
  return value === null ? "null" : Array.isArray(value) ? "list" : typeof value === "object" ? value.constructor.name : typeof value;
}

function listOf(key: string, value: NodeValue): unknown[] {
  if (!Array.isArray(value)) {
    throw new NodeFormatError(`'${key}' must be a list, found ${describe(value)}`);
  }
  return value;
}

/** Encodes a node; throws `NodeFormatError` for a key outside the schema or a bound breached. */
export function encode(node: Node): Uint8Array {
  const kind = node[KIND_KEY];
  if (typeof kind !== "string") {
    throw new NodeFormatError(`node has no '${KIND_KEY}' field`);
  }
  const schema = schemaOf(kind);
  const keys = Object.keys(node);
  for (const key of keys) {
    if (key !== KIND_KEY && schema[key] === undefined) {
      throw new NodeFormatError(`key '${key}' outside the schema of kind '${kind}'`);
    }
  }
  keys.sort(compareKeys);
  const parts: Uint8Array[] = [header(5, keys.length)];
  let links = 0;
  const link = (key: string, value: unknown): void => {
    if (!(value instanceof Link)) {
      throw new NodeFormatError(`'${key}' must hold a link, found ${describe(value)}`);
    }
    if (++links > MAX_LINKS) {
      throw new NodeFormatError(`node has more than ${MAX_LINKS} links`);
    }
    parts.push(linkItem(value.cid));
  };
  const embedded = (key: string, value: unknown, keySlot: boolean): void => {
    if (!(value instanceof Embedded)) {
      throw new NodeFormatError(`'${key}' must hold an embedded CBOR item, found ${describe(value)}`);
    }
    const bytes = value.bytes;
    if (skip(bytes, 0) !== bytes.length) {
      throw new NodeFormatError(`'${key}' embedded item has trailing bytes`);
    }
    checkEmbedded(key, bytes, keySlot, null);
    if (isLinkShaped(bytes) && ++links > MAX_LINKS) {
      throw new NodeFormatError(`node has more than ${MAX_LINKS} links`);
    }
    parts.push(bytes);
  };
  for (const key of keys) {
    parts.push(text(key));
    const value = node[key]!;
    if (key === KIND_KEY) {
      parts.push(text(kind));
      continue;
    }
    switch (schema[key]) {
      case "uint":
        parts.push(header(0, uintOf(key, value)));
        break;
      case "link":
        link(key, value);
        break;
      case "linkOrNull":
        if (value === null) {
          parts.push(Uint8Array.of(0xf6));
        } else {
          link(key, value);
        }
        break;
      case "links": {
        const list = listOf(key, value);
        parts.push(header(4, list.length));
        for (const item of list) {
          link(key, item);
        }
        break;
      }
      case "embedded":
        embedded(key, value, false);
        break;
      case "embeddeds": {
        const list = listOf(key, value);
        const keyed = isKeyed(kind, key);
        parts.push(header(4, list.length));
        list.forEach((item, i) => embedded(key, item, keyed && i % 2 === 0));
        break;
      }
      case "uints": {
        const list = listOf(key, value);
        parts.push(header(4, list.length));
        for (const item of list) {
          parts.push(header(0, uintOf(key, item as NodeValue)));
        }
        break;
      }
      case "bytes": {
        if (!(value instanceof Uint8Array)) {
          throw new NodeFormatError(`'${key}' must be a byte string`);
        }
        parts.push(header(2, value.length), value);
        break;
      }
      case "text":
        parts.push(strictText(key, value));
        break;
      case "cid":
        parts.push(cidText(key, value));
        break;
      case "cids": {
        const list = listOf(key, value);
        parts.push(header(4, list.length));
        for (const item of list) {
          parts.push(cidText(key, item));
        }
        break;
      }
      case "index": {
        const keysOf = isIndexShaped(value) ? Object.keys(value).sort() : null;
        if (keysOf === null || keysOf.join(",") !== INDEX_KEYS.join(",")) {
          throw new NodeFormatError(`'${key}' must map exactly aevt, avet and eavt to links, found ${
            keysOf === null ? describe(value) : `[${keysOf.join(", ")}]`}`);
        }
        parts.push(header(5, INDEX_KEYS.length));
        for (const index of INDEX_KEYS) {
          parts.push(text(index));
          link(key, (value as unknown as { [key: string]: unknown })[index]);
        }
        break;
      }
      case "datoms": {
        const list = listOf(key, value);
        parts.push(header(4, list.length));
        for (const item of list) {
          if (!(item instanceof Datom)) {
            throw new NodeFormatError(`'${key}' must hold datoms, found ${describe(item)}`);
          }
          parts.push(header(4, 4), sint(item.e), strictText(key, item.a));
          const v = item.v;
          if (v instanceof Link) {
            link(key, v);
          } else if (v instanceof DatomTag) {
            parts.push(header(4, 2), text(v.tag),
              v.inner instanceof Uint8Array ? concat(header(2, v.inner.length), v.inner) : sint(v.inner));
          } else if (v instanceof CborDouble) {
            const float = new Uint8Array(9);
            float[0] = 0xfb;
            new DataView(float.buffer).setFloat64(1, v.value, false);
            parts.push(float);
          } else if (v instanceof Uint8Array) {
            parts.push(header(2, v.length), v);
          } else if (typeof v === "boolean") {
            parts.push(Uint8Array.of(v ? 0xf5 : 0xf4));
          } else if (typeof v === "string") {
            parts.push(strictText(key, v));
          } else {
            parts.push(sint(v));
          }
          parts.push(sint(item.tx));
        }
        break;
      }
      case "runs": {
        const list = listOf(key, value);
        parts.push(header(4, list.length));
        for (const item of list) {
          if (!(item instanceof TextRun)) {
            throw new NodeFormatError(`'${key}' must hold text runs, found ${describe(item)}`);
          }
          parts.push(header(4, 7), strictText(key, item.replica), header(0, item.counter));
          parts.push(item.parent === null ? Uint8Array.of(0xf6)
            : concat(header(4, 2), strictText(key, item.parent.replica), header(0, item.parent.counter)));
          parts.push(text(item.side), header(0, item.length), Uint8Array.of(item.deleted ? 0xf5 : 0xf4),
            strictText(key, item.text));
        }
        break;
      }
      default:
        throw new NodeFormatError(`unhandled field ${key}`);
    }
  }
  const out = concat(...parts);
  if (out.length > boundOf(kind)) {
    throw new NodeFormatError(`node of ${out.length} bytes exceeds ${boundOf(kind)} bytes`);
  }
  return out;
}

/** Whether a field of a kind is an entry list whose even slots hold keys: `e` of a map node. */
function isKeyed(kind: string, key: string): boolean {
  return (kind === KIND_M || kind === KIND_MC) && key === "e";
}

/**
 * Refuses an embedded item that is no document in the wire encoding (HLC round six, 2026-11-08,
 * definition 2.4 and change JD-4, as Java's NodeCodec.checkEmbedded): every application key and value
 * obeys rules S1 to S12, so tags 2, 3 and 4 stand in it and no other tag does. A link-shaped item in a
 * value slot is a spilled value (PD-N-05) and passes; in a key slot it is tag 42 in an application
 * document, and the codec refuses it.
 */
function checkEmbedded(key: string, bytes: Uint8Array, keySlot: boolean, cid: string | null): void {
  if (!keySlot && isLinkShaped(bytes)) {
    return;
  }
  try {
    loads(bytes);
  } catch (e) {
    throw new NodeFormatError(`'${key}' ${keySlot ? "key item" : "embedded item"} breaks the wire encoding: `
      + (e instanceof Error ? e.message : String(e)), cid);
  }
}

// ------------------------------------------------------------------ reading

class In {
  p = 0;
  constructor(readonly bytes: Uint8Array, readonly cid: string | null) {}

  u8(): number {
    if (this.p >= this.bytes.length) {
      throw new NodeFormatError("truncated node", this.cid);
    }
    return this.bytes[this.p++]!;
  }

  peek(): number {
    if (this.p >= this.bytes.length) {
      throw new NodeFormatError("truncated node", this.cid);
    }
    return this.bytes[this.p]!;
  }

  advance(n: number): void {
    if (this.p + n > this.bytes.length) {
      throw new NodeFormatError("truncated node", this.cid);
    }
    this.p += n;
  }

  /** The argument of a head whose additional information is `info`, as a safe integer. */
  argument(info: number): number {
    if (info < 24) {
      return info;
    }
    if (info === 24) {
      return this.u8();
    }
    if (info === 25) {
      return (this.u8() << 8) | this.u8();
    }
    if (info === 26) {
      return ((this.u8() << 24) >>> 0) + (this.u8() << 16) + (this.u8() << 8) + this.u8();
    }
    if (info === 27) {
      let big = 0n;
      for (let i = 0; i < 8; i++) {
        big = (big << 8n) | BigInt(this.u8());
      }
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new NodeFormatError("integer above 2^53", this.cid);
      }
      return Number(big);
    }
    if (info === 31) {
      throw new NodeFormatError("indefinite length inside a node", this.cid);
    }
    throw new NodeFormatError(`reserved additional information ${info}`, this.cid);
  }

  /**
   * A definite header of the expected major type in its shortest form, as Java's NodeCodec reads every
   * structural header (PDT 2 phase 0: the level-2 kinds are strict DAG-CBOR down to every item).
   */
  headerOf(major: number, what: string): number {
    const initial = this.u8();
    if (initial >> 5 !== major) {
      throw new NodeFormatError(`'${what}' has major type ${initial >> 5} where ${major} was expected`, this.cid);
    }
    const info = initial & 0x1f;
    const value = this.argument(info);
    if (!shortest(info, value)) {
      throw new NodeFormatError(`'${what}' integer not in shortest form`, this.cid);
    }
    return value;
  }

  /** A signed integer under its shortest head, within the 64-bit range (PDT 2 phase 0, P2-D-01). */
  sint(what: string): Int64 {
    const initial = this.u8();
    const major = initial >> 5;
    if (major !== 0 && major !== 1) {
      throw new NodeFormatError(`'${what}' must be an integer, found major type ${major}`, this.cid);
    }
    const info = initial & 0x1f;
    let argument: bigint;
    if (info === 27) {
      argument = 0n;
      for (let i = 0; i < 8; i++) {
        argument = (argument << 8n) | BigInt(this.u8());
      }
      if (argument < 0x100000000n) {
        throw new NodeFormatError(`'${what}' integer not in shortest form`, this.cid);
      }
      if (argument > INT64_MAX) {
        throw new NodeFormatError(`'${what}' integer beyond the signed 64-bit range`, this.cid);
      }
    } else {
      const value = this.argument(info);
      if (!shortest(info, value)) {
        throw new NodeFormatError(`'${what}' integer not in shortest form`, this.cid);
      }
      argument = BigInt(value);
    }
    return int64(major === 0 ? argument : -1n - argument, what);
  }

  /** Text that is well-formed UTF-8 (PDT 2 phase 0): a malformed sequence is refused, never replaced. */
  strictText(what: string): string {
    const n = this.headerOf(3, what);
    this.advance(n);
    try {
      return STRICT_UTF8.decode(this.bytes.subarray(this.p - n, this.p));
    } catch {
      throw new NodeFormatError(`'${what}' text is not well-formed UTF-8`, this.cid);
    }
  }

  cidText(what: string): string {
    const value = this.strictText(what);
    if (!cids.isCid(value)) {
      throw new NodeFormatError(`'${what}' must hold a CID as text, found '${value}'`, this.cid);
    }
    return value;
  }

  bool(what: string): boolean {
    const initial = this.u8();
    if (initial !== 0xf5 && initial !== 0xf4) {
      throw new NodeFormatError(`'${what}' must be a boolean, found initial byte 0x${initial.toString(16)}`, this.cid);
    }
    return initial === 0xf5;
  }

  byteString(what: string): Uint8Array {
    const n = this.headerOf(2, what);
    this.advance(n);
    return this.bytes.slice(this.p - n, this.p);
  }

  /** The `db` root's index map: exactly aevt, avet, eavt, in that order, each a link (P2-D-01). */
  index(what: string): IndexLinks {
    if (this.headerOf(5, what) !== INDEX_KEYS.length) {
      throw new NodeFormatError(`'${what}' must map exactly aevt, avet and eavt to links, in that order`, this.cid);
    }
    const out: { [key: string]: Link } = {};
    for (const expected of INDEX_KEYS) {
      if (this.strictText(what) !== expected) {
        throw new NodeFormatError(`'${what}' must map exactly aevt, avet and eavt to links, in that order`, this.cid);
      }
      out[expected] = this.link(what);
    }
    return out as unknown as IndexLinks;
  }

  /** One datom `[e, a, v, tx]` under the value grammar of §3.1.1 (PDT 2 phase 0, P2-D-01). */
  datom(what: string): Datom {
    if (this.headerOf(4, what) !== 4) {
      throw new NodeFormatError(`'${what}' datom must hold four items`, this.cid);
    }
    const e = this.sint(what);
    const a = this.strictText(what);
    const v = this.datomValue(what);
    const tx = this.sint(what);
    return this.built(what, "datom", () => new Datom(e, a, v, tx));
  }

  private datomValue(what: string): DatomValue {
    const initial = this.peek();
    switch (initial >> 5) {
      case 0: case 1:
        return this.sint(what);
      case 2:
        return this.byteString(what);
      case 3:
        return this.strictText(what);
      case 6:
        return this.link(what);
      case 4: {
        if (this.headerOf(4, what) !== 2) {
          throw new NodeFormatError(`'${what}' tagged datom value must hold two items`, this.cid);
        }
        const tag = this.strictText(what);
        let inner: Uint8Array | Int64;
        if (tag === "i") {
          if (this.peek() >> 5 > 1) {
            throw new NodeFormatError(`'${what}' instant value must hold an integer`, this.cid);
          }
          inner = this.sint(what);
        } else if (tag === "u" || tag === "n") {
          inner = this.byteString(what);
        } else {
          throw new NodeFormatError(`'${what}' unknown value tag '${tag}'`, this.cid);
        }
        return this.built(what, "tagged value", () => new DatomTag(tag as "u" | "i" | "n", inner));
      }
      case 7:
        switch (initial) {
          case 0xf5: case 0xf4:
            return this.bool(what);
          case 0xfb: {
            this.advance(9);
            const value = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.p - 8, 8).getFloat64(0, false);
            if (!Number.isFinite(value)) {
              throw new NodeFormatError(`'${what}' float value is not finite`, this.cid);
            }
            return new CborDouble(value);
          }
          case 0xfa:
            throw new NodeFormatError(`'${what}' float value is float32; a datom float is float64`, this.cid);
          case 0xf9:
            throw new NodeFormatError(`'${what}' float value is a half float; a datom float is float64`, this.cid);
          case 0xf6:
            throw new NodeFormatError(`'${what}' datom value is null`, this.cid);
          default:
            throw new NodeFormatError(`'${what}' datom value is simple value 0x${initial.toString(16)}`, this.cid);
        }
      default:
        throw new NodeFormatError(`'${what}' datom value of major type ${initial >> 5}; the grammar holds integers, `
          + "bytes, text, links, tagged pairs, booleans and float64", this.cid);
    }
  }

  /** One run `[replica, counter, parent, side, length, deleted, text]` (PDT 2 phase 0, P2-T-01). */
  run(what: string): TextRun {
    if (this.headerOf(4, what) !== 7) {
      throw new NodeFormatError(`'${what}' run must hold seven items`, this.cid);
    }
    const replica = this.strictText(what);
    const counter = this.uint(what);
    let parent: CharId | null = null;
    if (this.peek() === 0xf6) {
      this.advance(1);
    } else {
      if (this.headerOf(4, what) !== 2) {
        throw new NodeFormatError(`'${what}' run parent must be null or [replica, counter]`, this.cid);
      }
      const parentReplica = this.strictText(what);
      const parentCounter = this.uint(what);
      parent = this.built(what, "run parent", () => new CharId(parentReplica, parentCounter));
    }
    const side = this.strictText(what);
    const length = this.uint(what);
    const deleted = this.bool(what);
    const runText = this.strictText(what);
    return this.built(what, "run", () => new TextRun(replica, counter, parent, side as "L" | "R", length, deleted, runText));
  }

  /** A value the constructor builds, its refusal turned into a refusal of the node. */
  private built<T>(what: string, name: string, constructor: () => T): T {
    try {
      return constructor();
    } catch (e) {
      throw new NodeFormatError(`'${what}' ${name} refused: ${e instanceof Error ? e.message : String(e)}`, this.cid);
    }
  }

  uint(what: string): number {
    return this.headerOf(0, what);
  }

  text(what: string): string {
    const n = this.headerOf(3, what);
    this.advance(n);
    return fromUtf8(this.bytes, this.p - n, this.p);
  }

  link(what: string): Link {
    const initial = this.u8();
    if (initial !== 0xd8 || this.u8() !== LINK_TAG) {
      throw new NodeFormatError(`'${what}' is not a tag-42 link`, this.cid);
    }
    const n = this.headerOf(2, what);
    if (n !== cids.BINARY_LENGTH + 1 || this.peek() !== 0x00) {
      throw new NodeFormatError(`'${what}' link is not a 0x00-prefixed binary CID of ${cids.BINARY_LENGTH} bytes`, this.cid);
    }
    this.advance(n);
    try {
      return new Link(cids.fromBinary(this.bytes.subarray(this.p - n + 1, this.p)));
    } catch (e) {
      throw new NodeFormatError(`'${what}' link refused: ${e instanceof Error ? e.message : String(e)}`, this.cid);
    }
  }

  /** One embedded item, which must be in the wire encoding (see {@link checkEmbedded}). */
  embedded(what: string, keySlot: boolean): Embedded {
    const start = this.p;
    skipItem(this, 0);
    const bytes = this.bytes.subarray(start, this.p);
    checkEmbedded(what, bytes, keySlot, this.cid);
    return new Embedded(bytes);
  }
}

/** Whether an argument sits in the shortest head that holds it. */
function shortest(info: number, value: number): boolean {
  switch (info) {
    case 24: return value >= 24;
    case 25: return value >= 0x100;
    case 26: return value >= 0x10000;
    case 27: return value >= 0x100000000;
    default: return true;
  }
}

function skipItem(input: In, depth: number): void {
  if (depth > MAX_DEPTH) {
    throw new NodeFormatError(`CBOR nesting deeper than ${MAX_DEPTH} levels`, input.cid);
  }
  const initial = input.u8();
  const major = initial >> 5;
  const info = initial & 0x1f;
  if (major === 7) {
    switch (info) {
      case 24: input.advance(1); return;
      case 25: input.advance(2); return;
      case 26: input.advance(4); return;
      case 27: input.advance(8); return;
      case 28: case 29: case 30:
        throw new NodeFormatError(`reserved additional information ${info}`, input.cid);
      case 31:
        throw new NodeFormatError("unexpected break code", input.cid);
      default:
        return;
    }
  }
  if (info === 31) {
    switch (major) {
      case 2: case 3:
        while (input.peek() !== 0xff) {
          const chunk = input.u8();
          if (chunk >> 5 !== major || (chunk & 0x1f) === 31) {
            throw new NodeFormatError("malformed indefinite string chunk", input.cid);
          }
          input.advance(input.argument(chunk & 0x1f));
        }
        input.advance(1);
        return;
      case 4:
        while (input.peek() !== 0xff) {
          skipItem(input, depth + 1);
        }
        input.advance(1);
        return;
      case 5:
        while (input.peek() !== 0xff) {
          skipItem(input, depth + 1);
          skipItem(input, depth + 1);
        }
        input.advance(1);
        return;
      default:
        throw new NodeFormatError(`indefinite length on major type ${major}`, input.cid);
    }
  }
  if ((major === 0 || major === 1) && info === 27) {
    // an integer's argument is no length, so a skip passes any 64-bit one: a datom holds the whole signed
    // range (PDT 2 phase 0, P2-D-01), and Java's skip reads every argument as a long
    input.advance(8);
    return;
  }
  const n = input.argument(info);
  switch (major) {
    case 0: case 1:
      return;
    case 2: case 3:
      input.advance(n);
      return;
    case 4:
      for (let i = 0; i < n; i++) {
        skipItem(input, depth + 1);
      }
      return;
    case 5:
      for (let i = 0; i < n; i++) {
        skipItem(input, depth + 1);
        skipItem(input, depth + 1);
      }
      return;
    case 6:
      skipItem(input, depth + 1);
      return;
    default:
      throw new NodeFormatError(`unsupported major ${major}`, input.cid);
  }
}

/** The offset after one CBOR item that starts at `offset`. */
export function skip(bytes: Uint8Array, offset: number): number {
  const input = new In(bytes, null);
  input.p = offset;
  skipItem(input, 0);
  return input.p;
}

interface Scan { kind: string; offsets: [string, number][] }

/** The byte bound of a kind: the sealed bound for an `sn` envelope, 1 MiB otherwise. */
export function boundOf(kind: string): number {
  return kind === KIND_SN ? MAX_SEALED_NODE_BYTES : MAX_NODE_BYTES;
}

/** Whether bytes open as the `sn` envelope map: `a5 61 6b 62 73 6e` (`{k: "sn", ...}`, five keys). */
function startsAsSealed(bytes: Uint8Array): boolean {
  return bytes.length > 6 && bytes[0] === 0xa5 && bytes[1] === 0x61 && bytes[2] === 0x6b
    && bytes[3] === 0x62 && bytes[4] === 0x73 && bytes[5] === 0x6e;
}

function scan(bytes: Uint8Array, cid: string | null): Scan {
  if (bytes.length > MAX_NODE_BYTES && !startsAsSealed(bytes)) {
    throw new NodeFormatError(`node of ${bytes.length} bytes exceeds ${MAX_NODE_BYTES} bytes (1 MiB)`, cid);
  }
  if (bytes.length > MAX_SEALED_NODE_BYTES) {
    throw new NodeFormatError(`node of ${bytes.length} bytes exceeds ${MAX_SEALED_NODE_BYTES} bytes (1 MiB + 48 KiB)`, cid);
  }
  const input = new In(bytes, cid);
  const entries = input.headerOf(5, "node");
  const offsets: [string, number][] = [];
  let kind: string | null = null;
  let previous: string | null = null;
  for (let i = 0; i < entries; i++) {
    const key = input.text("key");
    if (previous !== null) {
      const order = compareKeys(previous, key);
      if (order === 0) {
        throw new NodeFormatError(`duplicate key '${key}'`, cid);
      }
      if (order > 0) {
        throw new NodeFormatError(`keys out of canonical order: '${key}' after '${previous}'`, cid);
      }
    }
    previous = key;
    offsets.push([key, input.p]);
    if (key === KIND_KEY) {
      kind = input.text(KIND_KEY);
    } else {
      skipItem(input, 0);
    }
  }
  if (input.p !== bytes.length) {
    throw new NodeFormatError("trailing bytes after the node map", cid);
  }
  if (kind === null) {
    throw new NodeFormatError(`node has no '${KIND_KEY}' field`, cid);
  }
  if (bytes.length > boundOf(kind)) {
    throw new NodeFormatError(`node of ${bytes.length} bytes exceeds ${MAX_NODE_BYTES} bytes (1 MiB)`, cid);
  }
  return { kind, offsets };
}

function readField(input: In, kind: string, key: string, field: Field): NodeValue {
  switch (field) {
    case "uint":
      return input.uint(key);
    case "link":
      return input.link(key);
    case "linkOrNull":
      if (input.peek() === 0xf6) {
        input.advance(1);
        return null;
      }
      return input.link(key);
    case "links": {
      const n = input.headerOf(4, key);
      if (n > MAX_LINKS) {
        throw new NodeFormatError(`node has more than ${MAX_LINKS} links`, input.cid);
      }
      const list: Link[] = [];
      for (let i = 0; i < n; i++) {
        list.push(input.link(key));
      }
      return list;
    }
    case "embedded":
      return input.embedded(key, false);
    case "embeddeds": {
      const n = input.headerOf(4, key);
      const keyed = isKeyed(kind, key);
      const list: Embedded[] = [];
      for (let i = 0; i < n; i++) {
        list.push(input.embedded(key, keyed && i % 2 === 0));
      }
      return list;
    }
    case "uints": {
      const n = input.headerOf(4, key);
      const list: number[] = [];
      for (let i = 0; i < n; i++) {
        list.push(input.uint(key));
      }
      return list;
    }
    case "bytes":
      return input.byteString(key);
    case "text":
      return input.strictText(key);
    case "cid":
      return input.cidText(key);
    case "cids": {
      const n = input.headerOf(4, key);
      const list: string[] = [];
      for (let i = 0; i < n; i++) {
        list.push(input.cidText(key));
      }
      return list;
    }
    case "index":
      return input.index(key);
    case "datoms": {
      const n = input.headerOf(4, key);
      const list: Datom[] = [];
      for (let i = 0; i < n; i++) {
        list.push(input.datom(key));
      }
      return list;
    }
    case "runs": {
      const n = input.headerOf(4, key);
      const list: TextRun[] = [];
      for (let i = 0; i < n; i++) {
        list.push(input.run(key));
      }
      return list;
    }
    default:
      throw new NodeFormatError(`unhandled field ${key}`, input.cid);
  }
}

/** Decodes a node by its schema; the CID (when given) names the node in any error. */
export function decode(bytes: Uint8Array, cid: string | null = null): Node {
  const scanned = scan(bytes, cid);
  const schema = schemaOf(scanned.kind, cid);
  const input = new In(bytes, cid);
  const node: Node = {};
  let links = 0;
  for (const [key, offset] of scanned.offsets) {
    if (key === KIND_KEY) {
      node[key] = scanned.kind;
      continue;
    }
    const field = schema[key];
    if (field === undefined) {
      throw new NodeFormatError(`key '${key}' outside the schema of kind '${scanned.kind}'`, cid);
    }
    input.p = offset;
    const value = readField(input, scanned.kind, key, field);
    links += fieldLinks(scanned.kind, key, value).length;
    node[key] = value;
  }
  if (links > MAX_LINKS) {
    throw new NodeFormatError(`node has more than ${MAX_LINKS} links`, cid);
  }
  return node;
}

/** The kind of a node without decoding its fields. */
export function kindOf(bytes: Uint8Array, cid: string | null = null): string {
  return scan(bytes, cid).kind;
}

/**
 * The links one field of a node carries, in order: a link, each link of a list, every embedded value item
 * that is exactly a tag-42 link item (a spilled value, PD-N-05; a map node's key positions skipped), a
 * `db` root's index links in aevt, avet, eavt order, and every datom value spilled to a link (PDT 2
 * phase 0, P2-D-01).
 */
function fieldLinks(kind: string, key: string, value: NodeValue): string[] {
  const out: string[] = [];
  const keyed = isKeyed(kind, key);
  const one = (item: unknown, keySlot: boolean): void => {
    if (item instanceof Link) {
      out.push(item.cid);
    } else if (item instanceof Embedded && !keySlot) {
      const spilled = spilledLink(item.bytes);
      if (spilled !== null) {
        out.push(spilled);
      }
    } else if (item instanceof Datom && item.v instanceof Link) {
      out.push(item.v.cid);
    }
  };
  if (Array.isArray(value)) {
    value.forEach((item, i) => one(item, keyed && i % 2 === 0));
  } else if (isIndexShaped(value)) {
    for (const index of INDEX_KEYS) {
      one(value[index], false);
    }
  } else {
    one(value, false);
  }
  return out;
}

/**
 * The links of a node in field order: the link fields plus every embedded value item that is exactly a
 * tag-42 link item (a spilled value, PD-N-05; a map node's key positions are skipped), and for the level-2
 * kinds the index links of a `db` root and the spilled values of datoms (PDT 2 phase 0). A raw chunk has
 * none.
 */
export function links(bytes: Uint8Array, cid: string | null = null): string[] {
  if (cid !== null && cids.parse(cid).codec === cids.RAW) {
    return [];
  }
  const node = decode(bytes, cid);
  const kind = node[KIND_KEY] as string;
  const out: string[] = [];
  for (const [key, value] of Object.entries(node)) {
    if (key !== KIND_KEY) {
      out.push(...fieldLinks(kind, key, value));
    }
  }
  return out;
}
