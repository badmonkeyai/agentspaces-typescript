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
 * The DataScript database reader (srad/agentspaces-pdt2.md §3.1.5; PDT 2 phase 2, P2-D-09): a lazy reader
 * over the `db` root and `dn` nodes of §3.1.1 that answers `datoms`, `entity`, and `lookup` as DataScript
 * answers them, without Datalog.
 *
 * `new DbReader(root, store)` reads the root node and nothing else. A read walks one index from its root,
 * loading only the nodes whose key range meets the components, and applies the tail (the datoms of the
 * transactions not yet folded) over the index: a retraction removes the datom it names, and an assertion adds
 * one. The store's `load` throws `NodeUnavailableError` for a node it lacks.
 *
 * The comparators are DataScript's: `eavt`, `aevt`, and `avet` order datoms by their components in the
 * index's order, the attribute as a Clojure keyword (namespace first, a keyword without one before every
 * keyword with one), and the value by `value-compare`: numbers by value across long, double, and big integer,
 * other values of two classes by the class name, text by UTF-16 code unit, a UUID by its two signed halves,
 * and an instant by its milliseconds. A text value of a colon and a name is a keyword's print form (P2-D-01); a
 * text value that starts with a backslash is the string after it, the escape the Clojure face writes for a string
 * that starts with `:` or a backslash. Values come back in the datom grammar, escape included.
 * DataScript orders two byte arrays by identity hash, so the reader reads a byte array component by equality
 * and never seeks on it.
 *
 * `value-compare` is no total order: it compares numbers by value but a number and a value of another class by
 * class name, so an attribute that holds a big integer, a keyword or a boolean, and a double or a long can sort
 * in a cycle, and DataScript's sort then leaves two values out of order when other values sit between them.
 * The reader therefore checks neighbours only: each leaf holds its datoms in its index's order, and each node
 * lies between the branch key before its own and its own branch key, which are its neighbours in the index.
 * It refuses anything else by name.
 */

import { equals, toHex } from "../bytes.js";
import { CborDouble, loads } from "../cbor.js";
import type { CborValue } from "../cbor.js";
import { DbRoot, DnNode, AEVT, AVET, EAVT, TAIL } from "./kinds.js";
import { Datom, DatomTag, Link, NodeFormatError, isLinkShaped, spilledLink } from "./nodes.js";
import type { DatomValue, Int64 } from "./nodes.js";
import type { NodeStore } from "./store.js";
import { Ctx, resolve } from "./values.js";

type Field = "e" | "a" | "v";

/** The components of each index, in the index's order. */
export const COMPONENTS: { readonly [index: string]: readonly Field[] } = {
  [EAVT]: ["e", "a", "v"], [AEVT]: ["a", "e", "v"], [AVET]: ["a", "v", "e"] };

/** DataScript's implicit schema, merged under every database's own. */
export const IMPLICIT_SCHEMA = { ":db/ident": { ":db/unique": ":db.unique/identity" } };

/** The decoded nodes a reader keeps, least recently used first out. */
export const CACHE_NODES = 1024;

/** An attribute's properties as the schema holds them, keyword keys as their print form. */
export type Properties = { [property: string]: CborValue };

/** An entity's attributes: one value, or the values of a cardinality-many attribute in index order. */
export type Entity = { [attribute: string]: DatomValue | DatomValue[] };

const KEYWORD = "clojure.lang.Keyword", STRING = "java.lang.String", BYTES = "[B";
const TAGGED_CLASS = { u: "java.util.UUID", i: "java.util.Date", n: "clojure.lang.BigInt" } as const;

function sign(x: number | bigint | string | boolean, y: number | bigint | string | boolean): number {
  return x > y ? 1 : x < y ? -1 : 0;
}

/**
 * A keyword's print form as Clojure's `Symbol.compareTo` orders it: no namespace first, then the namespace,
 * then the name. `Symbol.intern` splits at the first `/` unless the name is `/`.
 */
function keywordParts(text: string): [boolean, string, string] {
  const body = text.slice(1);
  const cut = body.indexOf("/");
  return cut === -1 || body === "/" ? [false, "", body] : [true, body.slice(0, cut), body.slice(cut + 1)];
}

function compareKeywords(x: string, y: string): number {
  const [hx, nx, mx] = keywordParts(x);
  const [hy, ny, my] = keywordParts(y);
  return sign(hx, hy) || sign(nx, ny) || sign(mx, my);
}

/** A big integer's minimal two's complement bytes as a bigint. */
function twosComplement(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const b of bytes) {
    out = (out << 8n) | BigInt(b);
  }
  return (bytes[0]! & 0x80) !== 0 ? out - (1n << BigInt(bytes.length * 8)) : out;
}

function numberOf(v: DatomValue): number | bigint | CborDouble | null {
  if (typeof v === "number" || typeof v === "bigint" || v instanceof CborDouble) {
    return v;
  }
  return v instanceof DatomTag && v.tag === "n" ? twosComplement(v.inner as Uint8Array) : null;
}

/** A keyword's print form: a colon and a name. A lone `:` is a string. */
const isKeyword = (text: string): boolean => text.length > 1 && text.startsWith(":");

/**
 * The string a text value stands for: the Clojure face writes a string that starts with `:` or a backslash with
 * one more backslash in front (`agentspaces.pdt`), and a reader drops it, as Java's `DatomOrder` does.
 */
const stringOf = (text: string): string => (text.startsWith("\\") ? text.slice(1) : text);

function classOf(v: DatomValue): string {
  if (typeof v === "string") {
    return isKeyword(v) ? KEYWORD : STRING;
  }
  if (typeof v === "boolean") {
    return "java.lang.Boolean";
  }
  if (v instanceof Uint8Array) {
    return BYTES;
  }
  if (v instanceof DatomTag) {
    return TAGGED_CLASS[v.tag];
  }
  if (v instanceof Link) {
    throw new RangeError("a spilled value compares only once the reader resolves it");
  }
  return v instanceof CborDouble ? "java.lang.Double" : "java.lang.Long";
}

function uuidHalves(bytes: Uint8Array): [bigint, bigint] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return [view.getBigInt64(0), view.getBigInt64(8)];
}

/**
 * DataScript's `value-compare` over two datom values as -1, 0, or 1, or null for two byte arrays of different
 * content, which DataScript orders by identity hash. Neither value is a spilled link.
 */
export function compareValues(x: DatomValue, y: DatomValue): number | null {
  const nx = numberOf(x), ny = numberOf(y);
  if (nx !== null && ny !== null) {
    if (nx instanceof CborDouble || ny instanceof CborDouble) {
      // Clojure's Numbers.compare widens a long or a big integer to a double beside a double
      const fx = nx instanceof CborDouble ? nx.value : Number(nx), fy = ny instanceof CborDouble ? ny.value : Number(ny);
      return sign(fx, fy);
    }
    return sign(nx, ny);
  }
  const cx = classOf(x), cy = classOf(y);
  if (cx !== cy) {
    return sign(cx, cy);
  }
  if (cx === BYTES) {
    return equals(x as Uint8Array, y as Uint8Array) ? 0 : null;
  }
  if (cx === KEYWORD) {
    return compareKeywords(x as string, y as string);
  }
  if (x instanceof DatomTag && y instanceof DatomTag) {
    if (x.tag === "u") {
      const [mx, lx] = uuidHalves(x.inner as Uint8Array), [my, ly] = uuidHalves(y.inner as Uint8Array);
      return sign(mx, my) || sign(lx, ly);
    }
    return sign(x.inner as Int64, y.inner as Int64);
  }
  if (cx === STRING) {
    return sign(stringOf(x as string), stringOf(y as string));
  }
  return sign(x as boolean, y as boolean);
}

/** An order, or `unknown` in its place when byte arrays leave it unknown. */
function known(order: number | null, unknown: number): number {
  return order ?? unknown;
}

function compareComponent(field: Field, d: Datom, value: DatomValue): number | null {
  if (field === "a") {
    return compareKeywords(d.a, value as string);
  }
  return field === "v" ? compareValues(d.v, value) : sign(d.e, value as Int64);
}

/**
 * Where a datom lies against the components: before them (-1), among them (0), after them (1), or null when a
 * byte array leaves the order unknown.
 */
function comparePrefix(d: Datom, fields: readonly Field[], components: readonly DatomValue[]): number | null {
  for (let i = 0; i < components.length; i++) {
    const c = compareComponent(fields[i]!, d, components[i]!);
    if (c !== 0) {
      return c;
    }
  }
  return 0;
}

const abs = (tx: Int64): Int64 => (tx < 0 ? -tx : tx) as Int64;

function compareDatoms(index: string, x: Datom, y: Datom): number | null {
  const fields = COMPONENTS[index]!;
  const c = comparePrefix(x, fields, fields.map((f) => y[f]));
  return c !== 0 ? c : sign(abs(x.tx), abs(y.tx));
}

/** The key of a value under DataScript's datom equality: numbers by value, the rest by class and value. */
function valueKey(v: DatomValue): string {
  const n = numberOf(v);
  if (n !== null) {
    const value = n instanceof CborDouble ? n.value : n;
    return `number:${typeof value === "number" && Number.isInteger(value) ? BigInt(value) : value}`;
  }
  if (v instanceof Uint8Array) {
    return `${BYTES}:${toHex(v)}`;
  }
  if (v instanceof DatomTag) {
    return `${classOf(v)}:${v.inner instanceof Uint8Array ? toHex(v.inner) : String(v.inner)}`;
  }
  return `${classOf(v)}:${String(v)}`;
}

const datomKey = (d: Datom): string => JSON.stringify([String(d.e), d.a, valueKey(d.v)]);

/** A lazy reader over one `db` root (PDT 2 phase 2, P2-D-09). */
export class DbReader {
  private readonly db: DbRoot;
  private readonly ctx: Ctx;
  private readonly nodes = new Map<string, DnNode>();
  private readonly indexRoots: { readonly [index: string]: Link };
  private schemaRead: { [attribute: string]: Properties } | null = null;
  private tailRead: Map<string, Datom | null> | null = null;
  private attrSets: { unique: Set<string>; many: Set<string>; indexed: Set<string> } | null = null;

  constructor(readonly root: string, private readonly store: NodeStore) {
    this.ctx = new Ctx(store);
    this.db = DbRoot.decode(store.load(root), root);
    this.indexRoots = { [EAVT]: this.db.eavt, [AEVT]: this.db.aevt, [AVET]: this.db.avet };
  }

  get maxEid(): number {
    return this.db.maxEid;
  }

  get maxTx(): number {
    return this.db.maxTx;
  }

  /** The database's schema under DataScript's implicit one, attribute to properties. */
  get schema(): { readonly [attribute: string]: Properties } {
    if (this.schemaRead === null) {
      let item = this.db.schema.bytes;
      if (isLinkShaped(item)) {
        item = resolve(spilledLink(item)!, this.ctx);
      }
      const schema = loads(item) as { [attribute: string]: CborValue };
      for (const properties of Object.values(schema)) {
        if (typeof properties !== "object" || properties === null || Array.isArray(properties)
            || properties instanceof Uint8Array || properties instanceof CborDouble) {
          throw new NodeFormatError("a db schema maps each attribute to a map of its properties", this.root);
        }
      }
      this.schemaRead = { ...IMPLICIT_SCHEMA, ...(schema as { [attribute: string]: Properties }) };
    }
    return this.schemaRead;
  }

  private get attrs(): { unique: Set<string>; many: Set<string>; indexed: Set<string> } {
    if (this.attrSets === null) {
      const pick = (test: (p: Properties) => boolean): Set<string> =>
        new Set(Object.entries(this.schema).filter(([, p]) => test(p)).map(([a]) => a));
      this.attrSets = {
        unique: pick((p) => ":db/unique" in p),
        many: pick((p) => p[":db/cardinality"] === ":db.cardinality/many"),
        // DataScript's rschema puts unique, ref, :db/index true, and tuple attributes in avet
        indexed: pick((p) => ":db/unique" in p || p[":db/valueType"] === ":db.type/ref" || p[":db/index"] === true
          || ":db/tupleAttrs" in p) };
    }
    return this.attrSets;
  }

  /** The tail applied in transaction order: each datom's key to its last assertion, or null after a retraction. */
  private get tail(): Map<string, Datom | null> {
    if (this.tailRead === null) {
      const applied = new Map<string, Datom | null>();
      if (this.db.tail !== null) {
        const tail = this.load(this.db.tail.cid);
        if (tail.index !== TAIL) {
          throw new NodeFormatError(`the db root's 't' links index ${tail.index}, expected the tail`, this.db.tail.cid);
        }
        for (const d of tail.datoms) {
          applied.set(datomKey(d), d.tx > 0 ? d : null);
        }
      }
      this.tailRead = applied;
    }
    return this.tailRead;
  }

  // ---- reads

  /**
   * The datoms of `index` whose leading components equal `components`, in index order, as
   * `(d/datoms db index c1 c2 c3)` returns them; the components follow the index's order.
   */
  datoms(index: string, ...components: DatomValue[]): IterableIterator<Datom> {
    const fields = COMPONENTS[index];
    if (fields === undefined) {
      throw new RangeError(`unknown index ${index}; the indexes are eavt, aevt and avet`);
    }
    if (components.length > 3) {
      throw new RangeError("a read names at most three components");
    }
    if (index === AVET && components.length > 0 && !this.attrs.indexed.has(components[0] as string)) {
      throw new RangeError(`attribute ${String(components[0])} should be marked as :db/index true to read avet`);
    }
    const leading = fields.slice(0, components.length);
    const added = [...this.tail.values()]
      .filter((d): d is Datom => d !== null && this.inIndex(index, d) && comparePrefix(d, leading, components) === 0)
      .sort((x, y) => known(compareDatoms(index, x, y), 0));
    return this.merge(index, this.range(index, leading, components), added);
  }

  /**
   * The attributes of an entity as `(d/touch (d/entity db e))` holds them: one value for a cardinality-one
   * attribute, an array in index order for a cardinality-many one, a ref as its id.
   */
  entity(e: Int64): Entity {
    const out: Entity = {};
    for (const d of this.datoms(EAVT, e)) {
      if (this.attrs.many.has(d.a)) {
        ((out[d.a] ??= []) as DatomValue[]).push(d.v);
      } else {
        out[d.a] = d.v;
      }
    }
    return out;
  }

  /** The entity of the lookup ref `[a v]`, as `(d/entid db [a v])` resolves it, or null. */
  lookup(a: string, v: DatomValue): Int64 | null {
    if (!this.attrs.unique.has(a)) {
      throw new RangeError(`lookup attribute ${a} is not :db/unique`);
    }
    for (const d of this.datoms(AVET, a, v)) {
      return d.e;
    }
    return null;
  }

  // ---- the walk

  private inIndex(index: string, d: Datom): boolean {
    return index !== AVET || this.attrs.indexed.has(d.a);
  }

  private *merge(index: string, stored: Iterable<Datom>, added: Datom[]): IterableIterator<Datom> {
    let i = 0;
    for (const d of stored) {
      while (i < added.length && known(compareDatoms(index, added[i]!, d), 0) < 0) {
        yield added[i++]!;
      }
      yield d;
    }
    yield* added.slice(i);
  }

  private *range(index: string, fields: readonly Field[], components: readonly DatomValue[]): IterableIterator<Datom> {
    const tail = this.tail;
    for (const d of this.scan(index, this.indexRoots[index]!.cid, null, null, null, fields, components)) {
      const c = comparePrefix(d, fields, components);
      if (c !== null && c > 0) {
        return;
      }
      if (c !== 0 && !(c === null && matches(d, fields, components))) {
        continue;
      }
      if (!tail.has(datomKey(d))) {
        yield d;
      }
    }
  }

  private *scan(index: string, cid: string, level: number | null, low: Datom | null, high: Datom | null,
      fields: readonly Field[], components: readonly DatomValue[]): IterableIterator<Datom> {
    const node = this.load(cid);
    check(index, cid, node, level, low, high);
    if (node.level === 0) {
      yield* node.datoms;
      return;
    }
    let start = 0;
    while (start < node.datoms.length && comparePrefix(node.datoms[start]!, fields, components) === -1) {
      start += 1;
    }
    for (let j = start; j < node.datoms.length; j++) {
      yield* this.scan(index, node.children[j]!.cid, node.level - 1, j > 0 ? node.datoms[j - 1]! : low,
        node.datoms[j]!, fields, components);
    }
  }

  private load(cid: string): DnNode {
    const held = this.nodes.get(cid);
    if (held !== undefined) {
      this.nodes.delete(cid);
      this.nodes.set(cid, held);
      return held;
    }
    const read = DnNode.decode(this.store.load(cid), cid);
    const node = new DnNode(read.level, read.index, read.datoms.map((d) => this.resolved(cid, d)), read.children);
    if (node.index !== TAIL) {
      checkLeaf(cid, node);
    }
    this.nodes.set(cid, node);
    if (this.nodes.size > CACHE_NODES) {
      this.nodes.delete(this.nodes.keys().next().value!);
    }
    return node;
  }

  /** A datom whose spilled value (PD-N-05) reads as the value it names. */
  private resolved(cid: string, d: Datom): Datom {
    if (!(d.v instanceof Link)) {
      return d;
    }
    try {
      return new Datom(d.e, d.a, loads(resolve(d.v.cid, this.ctx)) as DatomValue, d.tx);
    } catch (e) {
      if (e instanceof RangeError) {
        throw new NodeFormatError(`a spilled datom value is no datom value: ${e.message}`, cid);
      }
      throw e;
    }
  }
}

function matches(d: Datom, fields: readonly Field[], components: readonly DatomValue[]): boolean {
  return fields.every((f, i) => (f === "v" ? compareValues(d.v, components[i]!) === 0 : d[f] === components[i]));
}

/**
 * The node's place in its index: its index, its level one below its parent's, and its datoms above the key
 * before its branch key and at most that key.
 */
function check(index: string, cid: string, node: DnNode, level: number | null, low: Datom | null, high: Datom | null): void {
  if (node.index !== index) {
    throw new NodeFormatError(`expected a node of index ${index}, found index ${node.index}`, cid);
  }
  if (level !== null && node.level !== level) {
    throw new NodeFormatError(`a child of a level ${level + 1} branch sits at level ${node.level}`, cid);
  }
  if (node.datoms.length === 0) {
    return;
  }
  if ((low !== null && known(compareDatoms(index, node.datoms[0]!, low), 1) <= 0)
      || (high !== null && known(compareDatoms(index, node.datoms[node.datoms.length - 1]!, high), 0) > 0)) {
    throw new NodeFormatError(`a datom sits outside its branch key's range in ${index}`, cid);
  }
}

function checkLeaf(cid: string, node: DnNode): void {
  if (node.datoms.some((d) => d.tx < 0)) {
    throw new NodeFormatError(`an index holds assertions only, found a retraction in ${node.index}`, cid);
  }
  if (node.level > 0) {
    return;
  }
  for (let i = 1; i < node.datoms.length; i++) {
    if (known(compareDatoms(node.index, node.datoms[i - 1]!, node.datoms[i]!), -1) >= 0) {
      throw new NodeFormatError(`datoms out of ${node.index} order`, cid);
    }
  }
}
