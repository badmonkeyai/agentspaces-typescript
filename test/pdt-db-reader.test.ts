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
 * The DataScript database reader (srad/agentspaces-pdt2.md §3.1.5; PDT 2 phase 2, P2-D-09): the golden database
 * of phase 0 read through its root, a 1,000-datom database read lazily over a counting store, the tail applied
 * over the indexes, the comparators against DataScript's `value-compare` (the expected signs come from
 * DataScript 1.7.8 run on the same pairs), and the refusals of a tree out of order. The Python suite
 * `test_pdt2_db_reader.py` holds the same cases.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { CborDouble, dumps } from "../src/cbor.js";
import * as pdt from "../src/pdt/index.js";
import type { DatomValue } from "../src/pdt/nodes.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8"));
const { Datom, DatomTag, Embedded, Link, NodeFormatError } = pdt.nodes;
const { DbRoot, DnNode } = pdt.kinds;
const { DbReader, compareValues } = pdt;
type Datom = pdt.nodes.Datom;
const TX0 = 0x20000000, TX1 = TX0 + 1, TX2 = TX0 + 2;
const fromHex = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, "hex"));

/** A node store that counts the nodes a read asks for. */
class CountingStore extends pdt.NodeStore {
  loads: string[] = [];

  override load(cid: string): Uint8Array {
    this.loads.push(cid);
    return super.load(cid);
  }
}

const put = (store: pdt.NodeStore, node: { encode(): Uint8Array }): pdt.nodes.Link =>
  new Link(store.put(node.encode(), pdt.cids.DAG_CBOR));
const schemaOf = (schema: object): pdt.nodes.Embedded => new Embedded(dumps(schema as never));
const rootOf = (store: pdt.NodeStore, schema: object, maxEid: number, links: { [i: string]: pdt.nodes.Link },
  tail: pdt.nodes.Link | null = null, branching = 128): string =>
  store.put(new DbRoot({ schema: schemaOf(schema), maxEid, maxTx: TX1, branching, eavt: links["eavt"]!,
    aevt: links["aevt"]!, avet: links["avet"]!, tail }).encode(), pdt.cids.DAG_CBOR);
const plain = (ds: Iterable<Datom>): unknown[] => [...ds].map((d) => [d.e, d.a, d.v, d.tx]);

function goldenStore(): { store: CountingStore; root: string } {
  const store = new CountingStore();
  for (const name of ["pdt_db_root", "pdt_dn_leaf", "pdt_dn_tail", "pdt_dn_branch"]) {
    for (const part of GOLDEN[name]!.split(",")) {
      store.put(fromHex(part), pdt.cids.DAG_CBOR);
    }
  }
  return { store, root: pdt.cids.of(fromHex(GOLDEN["pdt_db_root"]!.split(",")[0]!), pdt.cids.DAG_CBOR) };
}

// ------------------------------------------------------------------ the golden database of phase 0

test("PDT 2 phase 2: the golden database reads through its root with the tail applied (P2-D-09)", () => {
  const { store, root } = goldenStore();
  const db = new DbReader(root, store);
  assert.deepEqual(store.loads, [root], "restore reads the db root and nothing else (P2-D-04)");
  assert.deepEqual([db.maxEid, db.maxTx], [2, TX2]);
  assert.deepEqual({ ...db.schema[":person/name"] }, { ":db/index": true });
  // the tail retracts [2 :person/age 45] and asserts 46 in transaction TX2
  assert.deepEqual(plain(db.datoms("eavt")), [[1, ":person/age", 36, TX1], [1, ":person/name", "Ada", TX1],
    [2, ":person/age", 46, TX2], [2, ":person/name", "Grace", TX1]]);
  assert.deepEqual([...db.datoms("aevt", ":person/age")].map((d) => d.v), [36, 46]);
  assert.deepEqual([...db.datoms("avet", ":person/name", "Grace")].map((d) => d.e), [2]);
  assert.deepEqual(db.entity(2), { ":person/age": 46, ":person/name": "Grace" });
  assert.deepEqual(db.entity(3), {});
});

test("PDT 2 phase 2: a lookup and an avet read follow the schema as DataScript does (P2-D-09)", () => {
  const { store, root } = goldenStore();
  const db = new DbReader(root, store);
  assert.throws(() => db.lookup(":person/name", "Ada"), /not :db\/unique/);
  assert.throws(() => [...db.datoms("avet", ":person/age")], /:db\/index/);
  assert.throws(() => db.datoms("vaet"), /index/);
  assert.equal(db.lookup(":db/ident", ":nobody"), null, "the implicit schema makes :db/ident unique");
});

test("PDT 2 phase 2: the branch vector reads one child for one entity (P2-D-09)", () => {
  const { store } = goldenStore();
  const [branchHex, , secondHex] = GOLDEN["pdt_dn_branch"]!.split(",");
  const branch = pdt.cids.of(fromHex(branchHex!), pdt.cids.DAG_CBOR);
  const root = rootOf(store, {}, 2, { eavt: new Link(branch), aevt: put(store, DnNode.leaf("aevt", [])),
    avet: put(store, DnNode.leaf("avet", [])) });
  store.loads = [];
  const db = new DbReader(root, store);
  assert.deepEqual([...db.datoms("eavt", 2)].map((d) => d.v), [45, "Grace"]);
  assert.deepEqual(store.loads, [root, branch, pdt.cids.of(fromHex(secondHex!), pdt.cids.DAG_CBOR)],
    "the first child is never read");
});

// ------------------------------------------------------------------ a 1,000-datom database

const PEOPLE = 250;
const SCHEMA = { ":person/email": { ":db/unique": ":db.unique/identity" },
  ":person/friend": { ":db/valueType": ":db.type/ref", ":db/cardinality": ":db.cardinality/many" },
  ":person/name": { ":db/index": true } };
const pad = (e: number): string => String(e).padStart(4, "0");

/** Four datoms per person, 1,000 in all; ASCII text in one width sorts the same in every order. */
function people(): Datom[] {
  const out: Datom[] = [];
  for (let e = 1; e <= PEOPLE; e++) {
    out.push(new Datom(e, ":person/age", 20 + (e % 50), TX1), new Datom(e, ":person/email", `p${pad(e)}@example.org`, TX1),
      new Datom(e, ":person/friend", (e % PEOPLE) + 1, TX1), new Datom(e, ":person/name", `name-${pad(e)}`, TX1));
  }
  return out;
}

const KEYS: { [index: string]: (d: Datom) => unknown[] } = { eavt: (d) => [d.e, d.a, d.v], aevt: (d) => [d.a, d.e, d.v],
  avet: (d) => [d.a, d.v, d.e] };
const byIndex = (index: string, ds: Datom[]): Datom[] => [...ds].sort((x, y) => {
  const kx = KEYS[index]!(x), ky = KEYS[index]!(y);
  for (let i = 0; i < kx.length; i++) {
    if (kx[i] !== ky[i]) {
      return (kx[i] as number) < (ky[i] as number) ? -1 : 1;
    }
  }
  return 0;
});

/** A persistent-sorted-set tree over sorted datoms: leaves of `bf` datoms, each branch keying a child by its largest datom. */
function tree(store: pdt.NodeStore, index: string, datoms: Datom[], bf = 128): { link: pdt.nodes.Link; depth: number } {
  let level: [pdt.nodes.Link, Datom | null][] = [];
  for (let i = 0; i < datoms.length; i += bf) {
    level.push([put(store, DnNode.leaf(index, datoms.slice(i, i + bf))), datoms[Math.min(i + bf, datoms.length) - 1]!]);
  }
  if (level.length === 0) {
    level = [[put(store, DnNode.leaf(index, [])), null]];
  }
  let depth = 1;
  while (level.length > 1) {
    const next: [pdt.nodes.Link, Datom | null][] = [];
    for (let i = 0; i < level.length; i += bf) {
      const group = level.slice(i, i + bf);
      next.push([put(store, DnNode.branch(depth, index, group.map(([, k]) => k!), group.map(([c]) => c))),
        group[group.length - 1]![1]]);
    }
    level = next;
    depth += 1;
  }
  return { link: level[0]![0], depth };
}

function database(datoms: Datom[], tail: Datom[] = [], bf = 128):
    { store: CountingStore; root: string; depth: { [i: string]: number } } {
  const store = new CountingStore();
  const indexed = new Set([":person/email", ":person/friend", ":person/name"]);
  const links: { [i: string]: pdt.nodes.Link } = {}, depth: { [i: string]: number } = {};
  for (const index of ["eavt", "aevt", "avet"]) {
    const built = tree(store, index, byIndex(index, datoms.filter((d) => index !== "avet" || indexed.has(d.a))), bf);
    links[index] = built.link;
    depth[index] = built.depth;
  }
  const root = rootOf(store, SCHEMA, PEOPLE, links, tail.length > 0 ? put(store, DnNode.tail(tail)) : null, bf);
  store.loads = [];
  return { store, root, depth };
}

test("PDT 2 phase 2: the first datom of a thousand reads at most depth plus one nodes (P2-D-09)", () => {
  const datoms = people();
  assert.equal(datoms.length, 1000);
  const { store, root, depth } = database(datoms);
  assert.equal(depth["eavt"], 2);
  const first = new DbReader(root, store).datoms("eavt").next().value as Datom;
  assert.deepEqual([first.e, first.a], [1, ":person/age"]);
  assert.ok(store.loads.length <= depth["eavt"]! + 1, String(store.loads));
});

test("PDT 2 phase 2: every read of a thousand datoms equals the sorted set (P2-D-09)", () => {
  const datoms = people();
  const { store, root } = database(datoms, [], 8);
  const db = new DbReader(root, store);
  const eavt = byIndex("eavt", datoms);
  assert.deepEqual(plain(db.datoms("eavt")), plain(eavt));
  assert.deepEqual(plain(db.datoms("aevt")), plain(byIndex("aevt", datoms)));
  assert.deepEqual(plain(db.datoms("avet")), plain(byIndex("avet", datoms.filter((d) => d.a !== ":person/age"))));
  assert.deepEqual(plain(db.datoms("eavt", 17)), plain(eavt.filter((d) => d.e === 17)));
  assert.deepEqual(plain(db.datoms("eavt", 17, ":person/name")), [[17, ":person/name", "name-0017", TX1]]);
  assert.deepEqual(plain(db.datoms("eavt", 17, ":person/name", "nobody")), []);
  assert.deepEqual(plain(db.datoms("aevt", ":person/friend", 9)), [[9, ":person/friend", 10, TX1]]);
  assert.deepEqual([...db.datoms("avet", ":person/friend", 10)].map((d) => d.e), [9]);
  assert.deepEqual(plain(db.datoms("eavt", PEOPLE + 1)), []);
  assert.deepEqual(plain(db.datoms("aevt", ":person/zzz")), []);
});

test("PDT 2 phase 2: an entity and a lookup read only their own paths (P2-D-09)", () => {
  const { store, root, depth } = database(people());
  const db = new DbReader(root, store);
  assert.equal(db.lookup(":person/email", "p0200@example.org"), 200);
  assert.ok(store.loads.length <= 1 + depth["avet"]!, String(store.loads));
  assert.equal(db.lookup(":person/email", "nobody@example.org"), null);
  assert.deepEqual(db.entity(200), { ":person/age": 20, ":person/email": "p0200@example.org", ":person/friend": [201],
    ":person/name": "name-0200" });
});

test("PDT 2 phase 2: a read stops at the first datom past its components (P2-D-09)", () => {
  const { store, root, depth } = database(people(), [], 8);
  const db = new DbReader(root, store);
  assert.equal(depth["eavt"], 4);
  assert.equal(Object.keys(db.entity(17)).length, 4);
  // the path to entity 17's leaf, and at most the next leaf, where the datom past entity 17 sits
  assert.ok(store.loads.length <= 1 + depth["eavt"]! + 1, String(store.loads));
});

test("PDT 2 phase 2: the tail retracts, asserts, and reasserts over the indexes (P2-D-09)", () => {
  const tail = [new Datom(5, ":person/name", "name-0005", -(TX1 + 1)), new Datom(5, ":person/name", "Eve", TX1 + 1),
    new Datom(5, ":person/friend", 1, TX1 + 1), new Datom(5, ":person/friend", 6, -(TX1 + 2)),
    new Datom(251, ":person/email", "new@example.org", TX1 + 2), new Datom(251, ":person/email", "new@example.org", -(TX1 + 3)),
    new Datom(251, ":person/email", "new@example.org", TX1 + 3), new Datom(1, ":person/age", 21, -(TX1 + 3))];
  const { store, root } = database(people(), tail, 16);
  const db = new DbReader(root, store);
  assert.deepEqual(db.entity(5), { ":person/age": 25, ":person/email": "p0005@example.org", ":person/friend": [1],
    ":person/name": "Eve" });
  assert.equal(db.lookup(":person/email", "new@example.org"), 251);
  assert.deepEqual(db.entity(1), { ":person/email": "p0001@example.org", ":person/friend": [2], ":person/name": "name-0001" });
  assert.deepEqual([...db.datoms("avet", ":person/name")].slice(0, 5).map((d) => d.v),
    ["Eve", "name-0001", "name-0002", "name-0003", "name-0004"]);
  assert.deepEqual([...db.datoms("aevt", ":person/friend", 5)].map((d) => [d.e, d.v, d.tx]), [[5, 1, TX1 + 1]]);
  const all = [...db.datoms("eavt")];
  assert.equal(all[all.length - 1]!.e, 251);
  // name 5 and friend 6 of entity 5 and the age of entity 1 leave; Eve, friend 1, and entity 251's email arrive
  assert.equal(all.length, 1000);
});

test("PDT 2 phase 2: a spilled value and a spilled schema read through their links (P2-D-09)", () => {
  const store = new CountingStore();
  const longText = "a long biography ".repeat(100);
  const spill = store.put(pdt.nodes.encode({ k: "x", v: new Embedded(dumps(longText)) }), pdt.cids.DAG_CBOR);
  const schema = store.put(pdt.nodes.encode({ k: "x", v: new Embedded(dumps({ ":person/name": { ":db/unique":
    ":db.unique/identity" } })) }), pdt.cids.DAG_CBOR);
  const datoms = [new Datom(1, ":person/bio", new Link(spill), TX1), new Datom(1, ":person/name", "Ada", TX1)];
  const root = store.put(new DbRoot({ schema: new Embedded(pdt.nodes.linkItem(schema)), maxEid: 1, maxTx: TX1,
    branching: 128, eavt: tree(store, "eavt", datoms).link, aevt: tree(store, "aevt", datoms).link,
    avet: tree(store, "avet", [datoms[1]!]).link, tail: null }).encode(), pdt.cids.DAG_CBOR);
  const db = new DbReader(root, store);
  assert.deepEqual(db.entity(1), { ":person/bio": longText, ":person/name": "Ada" });
  assert.deepEqual([...db.datoms("aevt", ":person/bio", 1, longText)].map((d) => d.v), [longText]);
  assert.equal(db.lookup(":person/name", "Ada"), 1);
  assert.ok(store.loads.includes(schema));
});

// ------------------------------------------------------------------ the comparators

const uuid = (high: number): pdt.nodes.DatomTag => DatomTag.uuid(Uint8Array.from({ length: 16 }, (_, i) => (i === 0 ? high : 0)));
const double = (v: number): CborDouble => new CborDouble(v);
const PAIRS: [DatomValue, DatomValue, number][] = [
  // value-compare of DataScript 1.7.8 on the same pairs, run 2026-11-09
  [":a/c", ":a.b/c", -1], [":a", ":a/b", -1], [":b", ":a/b", -1], ["￿", "\u{1f600}", 1],
  [1, double(1), 0], [1, double(1.5), -1], [2, DatomTag.bigint(2n), 0], [DatomTag.bigint(5n), 6, -1],
  [1, true, 1], [true, "x", -1], [":x", "x", -1], [Uint8Array.of(1), "x", -1], [DatomTag.bigint(5n), "s", -1],
  [double(1.5), true, 1], [false, true, -1], [uuid(0x80), uuid(0), -1], [DatomTag.instant(5), DatomTag.instant(6), -1],
  [DatomTag.instant(5), uuid(0), -1],
  // PDT 2 phase 2 gate, P2-D-09: a text that starts with a backslash is the string after it, the escape the Clojure
  // face writes for a string that starts with ':' or '\\', and ':' alone is a string
  ["\\:x", "B", -1], ["\\b", "a", 1], ["\\:x", ":x", 1], ["\\:x", "\\:x", 0], [":", "a", -1], [":", ":a", 1]];

test("PDT 2 phase 2: values compare as DataScript's value-compare does (P2-D-09)", () => {
  for (const [x, y, s] of PAIRS) {
    assert.equal(compareValues(x, y), s, `${String(x)} against ${String(y)}`);
    assert.equal(compareValues(y, x), -s || 0, `${String(y)} against ${String(x)}`);
  }
  assert.equal(compareValues(Uint8Array.of(1), Uint8Array.of(1)), 0);
  assert.equal(compareValues(Uint8Array.of(1), Uint8Array.of(2)), null, "DataScript orders two arrays by identity hash");
});

test("PDT 2 phase 2: the golden sample answers as DataScript does (P2-D-09)", () => {
  // pdt_db_sample is 1,000 folded datoms and a three-datom tail; each answer of pdt_db_sample_answers is a dn
  // leaf of the datoms DataScript returns, in the index's order
  const [root, ...parts] = GOLDEN["pdt_db_sample"]!.split(",");
  const store = new CountingStore();
  for (const part of parts) {
    store.put(fromHex(part), pdt.cids.DAG_CBOR);
  }
  const answers = new Map(GOLDEN["pdt_db_sample_answers"]!.split(",").map((pair) => {
    const [name, leaf] = pair.split("=", 2);
    return [name!, DnNode.decode(fromHex(leaf!)).datoms.map((d) => [d.e, d.a, d.v])];
  }));
  const db = new DbReader(root!, store);
  assert.deepEqual(store.loads, [root]);
  const read = (index: string, ...components: DatomValue[]): unknown[] =>
    [...db.datoms(index, ...components)].map((d) => [d.e, d.a, d.v]);
  assert.equal(read("eavt").length, 1001);
  assert.deepEqual(read("eavt", 7), answers.get("eavt_7"));
  assert.deepEqual(read("eavt", 126), answers.get("eavt_126"));
  assert.deepEqual(read("aevt", ":p/name"), answers.get("aevt_name"));
  assert.deepEqual(read("avet", ":p/name", "Ada"), answers.get("avet_name_ada"));
  assert.deepEqual(read("avet", ":p/friend", 9), answers.get("avet_friend_9"));
  assert.deepEqual(read("eavt", 42), answers.get("entity_42"));
  assert.deepEqual(read("avet", ":p/email", "p42@example.org"), answers.get("lookup_email_p42"));
  assert.deepEqual(read("avet", ":p/name", "Person 7"), []);
  assert.deepEqual(answers.get("avet_name_person7"), []);
  assert.equal(db.lookup(":p/email", "p42@example.org"), 42);
  assert.deepEqual(db.entity(7)[":p/tag"], [":tag/odd"]);
  assert.equal(db.entity(7)[":p/name"], "Ada");
});

test("PDT 2 phase 2: a byte array component reads by equality (P2-D-09)", () => {
  const datoms = [new Datom(1, ":file/hash", Uint8Array.of(9), TX1), new Datom(2, ":file/hash", Uint8Array.of(1), TX1),
    new Datom(3, ":file/hash", Uint8Array.of(5), TX1)];
  const store = new CountingStore();
  const links = { eavt: tree(store, "eavt", datoms).link, aevt: tree(store, "aevt", datoms).link,
    avet: tree(store, "avet", datoms).link };
  const db = new DbReader(rootOf(store, { ":file/hash": { ":db/unique": ":db.unique/identity" } }, 3, links), store);
  assert.equal(db.lookup(":file/hash", Uint8Array.of(1)), 2);
});

test("PDT 2 phase 2: a branch over values DataScript orders in a cycle reads (P2-D-09)", () => {
  // value-compare puts a big integer before a keyword by class, the keyword before a double by class, and the
  // numbers by value, so DataScript's sort may leave 2.0 before 1.0 two leaves apart; its leaves still hold each
  // neighbour in order, and the reader refuses only a neighbour out of order
  const datoms = [double(2), DatomTag.bigint(3n), ":k", double(1)].map((v, i) => new Datom(i + 1, ":x/v", v, TX1));
  const store = new CountingStore();
  const links = { eavt: put(store, DnNode.leaf("eavt", [])), aevt: put(store, DnNode.leaf("aevt", [])),
    avet: tree(store, "avet", datoms, 2).link };
  const db = new DbReader(rootOf(store, { ":x/v": { ":db/index": true } }, 4, links, null, 2), store);
  assert.deepEqual(plain(db.datoms("avet")), plain(datoms));
});

// ------------------------------------------------------------------ refusals

function hostile(eavt: pdt.nodes.Link, store: pdt.NodeStore, tail: pdt.nodes.Link | null = null): pdt.DbReader {
  const links = { eavt, aevt: put(store, DnNode.leaf("aevt", [])), avet: put(store, DnNode.leaf("avet", [])) };
  return new DbReader(rootOf(store, {}, 9, links, tail), store);
}

test("PDT 2 phase 2: a leaf out of comparator order is refused by name (P2-D-09)", () => {
  const store = new CountingStore();
  for (const leaf of [[new Datom(2, ":a/b", 1, TX1), new Datom(1, ":a/b", 1, TX1)],
    [new Datom(1, ":a/b", 1, TX1), new Datom(1, ":a/b", 1, TX1)]]) {
    const db = hostile(put(store, DnNode.leaf("eavt", leaf)), store);
    assert.throws(() => [...db.datoms("eavt")], (e: unknown) => e instanceof NodeFormatError && /eavt order/.test(e.message));
  }
});

test("PDT 2 phase 2: a child outside its branch key is refused (P2-D-09)", () => {
  const [a, b, c] = [1, 2, 3].map((e) => new Datom(e, ":a/b", 1, TX1));
  const store = new CountingStore();
  const first = put(store, DnNode.leaf("eavt", [a!, c!])), second = put(store, DnNode.leaf("eavt", [b!]));
  for (const eavt of [put(store, DnNode.branch(1, "eavt", [b!, c!], [first, second])),
    put(store, DnNode.branch(1, "eavt", [b!], [first]))]) {
    assert.throws(() => [...hostile(eavt, store).datoms("eavt")], /outside/);
  }
});

test("PDT 2 phase 2: a node of another index or level and a retraction in an index are refused (P2-D-09)", () => {
  const store = new CountingStore();
  const d = new Datom(1, ":a/b", 1, TX1);
  const eavt = put(store, DnNode.leaf("eavt", [d]));
  assert.throws(() => [...hostile(put(store, DnNode.leaf("aevt", [d])), store).datoms("eavt")], /index aevt/);
  assert.throws(() => [...hostile(put(store, DnNode.branch(2, "eavt", [d], [eavt])), store).datoms("eavt")], /level/);
  assert.throws(() => [...hostile(put(store, DnNode.leaf("eavt", [new Datom(1, ":a/b", 1, -TX1)])), store).datoms("eavt")],
    /retraction/);
  assert.throws(() => [...hostile(eavt, store, eavt).datoms("eavt")], /tail/);
});

// ------------------------------------------------------------------ a database DataScript wrote

/**
 * PDT 2 phase 2 gate, P2-D-09: agentspaces-datascript's cross_language_test writes the database through the adapter
 * (every value form, the escaped strings, branches, and a tail) with DataScript's answers; the Python suite reads the
 * same fixture.
 */
type Fixture = { root: string; nodes: string[]; queries: { index: string; n: number; probe: string; answer: string }[];
  lookups: { a: string; v: string; e: number }[] };
const DATASCRIPT_DB: Fixture = JSON.parse(readFileSync(join(here, "..", "..", "test", "pdt2-datascript-db.json"), "utf8"));

function datascriptReader(): pdt.DbReader {
  const store = new pdt.NodeStore();
  for (const part of DATASCRIPT_DB.nodes) {
    store.put(fromHex(part), pdt.cids.DAG_CBOR);
  }
  return new DbReader(DATASCRIPT_DB.root, store);
}

test("PDT 2 phase 2: a database DataScript wrote answers as DataScript does (P2-D-09)", () => {
  const db = datascriptReader();
  const triple = (d: Datom): unknown[] => [d.e, d.a, d.v];
  for (const query of DATASCRIPT_DB.queries) {
    const probe = DnNode.decode(fromHex(query.probe)).datoms[0]!;
    const byIndex: { [index: string]: DatomValue[] } = { eavt: [probe.e, probe.a, probe.v], aevt: [probe.a, probe.e, probe.v],
      avet: [probe.a, probe.v, probe.e] };
    const components = byIndex[query.index]!.slice(0, query.n);
    assert.deepEqual([...db.datoms(query.index, ...components)].map(triple),
      DnNode.decode(fromHex(query.answer)).datoms.map(triple), `${query.index} ${components.map(String).join(" ")}`);
  }
  assert.deepEqual(DATASCRIPT_DB.lookups.map((q) => db.lookup(q.a, q.v)), DATASCRIPT_DB.lookups.map((q) => q.e));
});
