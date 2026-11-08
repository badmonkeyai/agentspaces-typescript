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
 */

import { compare, concat, fromUtf8, utf8 } from "../bytes.js";
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
/** Kinds reserved by PD-F-01 for later layouts (`s` sorted map, `rr` RRB vector); a decoder refuses them by name. */
export const RESERVED_KINDS = new Set(["s", "rr"]);
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

export type Field = "uint" | "link" | "linkOrNull" | "links" | "embedded" | "embeddeds" | "uints" | "bytes";

const SCHEMAS: { [kind: string]: { [key: string]: Field } } = {
  m: { d: "uint", n: "uint", e: "embeddeds", c: "links", cnt: "uint" },
  mc: { e: "embeddeds" },
  v: { c: "links", e: "embeddeds" },
  vr: { n: "uint", s: "uint", r: "linkOrNull", t: "embeddeds" },
  b: { h: "uint", c: "links", z: "uints" },
  x: { v: "embedded" },
  sn: { ct: "bytes", ep: "uint", ln: "links", nc: "bytes" },
};

export type NodeValue = number | Link | null | Link[] | Embedded | Embedded[] | number[] | string | Uint8Array;
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
  const embedded = (key: string, value: unknown): void => {
    if (!(value instanceof Embedded)) {
      throw new NodeFormatError(`'${key}' must hold an embedded CBOR item, found ${describe(value)}`);
    }
    const bytes = value.bytes;
    if (skip(bytes, 0) !== bytes.length) {
      throw new NodeFormatError(`'${key}' embedded item has trailing bytes`);
    }
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
        embedded(key, value);
        break;
      case "embeddeds": {
        const list = listOf(key, value);
        parts.push(header(4, list.length));
        for (const item of list) {
          embedded(key, item);
        }
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

  headerOf(major: number, what: string): number {
    const initial = this.u8();
    if (initial >> 5 !== major) {
      throw new NodeFormatError(`'${what}' has major type ${initial >> 5} where ${major} was expected`, this.cid);
    }
    return this.argument(initial & 0x1f);
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

  embedded(): Embedded {
    const start = this.p;
    skipItem(this, 0);
    return new Embedded(this.bytes.subarray(start, this.p));
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

function readField(input: In, key: string, field: Field): NodeValue {
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
      return input.embedded();
    case "embeddeds": {
      const n = input.headerOf(4, key);
      const list: Embedded[] = [];
      for (let i = 0; i < n; i++) {
        list.push(input.embedded());
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
    case "bytes": {
      const n = input.headerOf(2, key);
      const start = input.p;
      input.advance(n);
      return input.bytes.slice(start, input.p);
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
    const value = readField(input, key, field);
    if (value instanceof Link) {
      links += 1;
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (item instanceof Link || (item instanceof Embedded && isLinkShaped(item.bytes))) {
          links += 1;
        }
      }
    } else if (value instanceof Embedded && isLinkShaped(value.bytes)) {
      links += 1;
    }
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
 * The links of a node in field order: the link fields plus every embedded value item that is exactly a
 * tag-42 link item (a spilled value, PD-N-05); a map node's key positions are skipped. A raw chunk has
 * none.
 */
export function links(bytes: Uint8Array, cid: string | null = null): string[] {
  if (cid !== null && cids.parse(cid).codec === cids.RAW) {
    return [];
  }
  const node = decode(bytes, cid);
  const kind = node[KIND_KEY] as string;
  const out: string[] = [];
  const keyed = (kind === KIND_M || kind === KIND_MC);
  for (const [key, value] of Object.entries(node)) {
    if (key === KIND_KEY) {
      continue;
    }
    if (value instanceof Link) {
      out.push(value.cid);
    } else if (value instanceof Embedded) {
      const spilled = spilledLink(value.bytes);
      if (spilled !== null) {
        out.push(spilled);
      }
    } else if (Array.isArray(value)) {
      value.forEach((item, i) => {
        if (item instanceof Link) {
          out.push(item.cid);
        } else if (item instanceof Embedded && !(keyed && key === "e" && i % 2 === 0)) {
          const spilled = spilledLink(item.bytes);
          if (spilled !== null) {
            out.push(spilled);
          }
        }
      });
    }
  }
  return out;
}
