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
 * PDT 2 phase 7, group T in TypeScript (srad/agentspaces-pdt2.md §3.9; P2-C-01, P2-T-01 to P2-T-03, P2-T-05): the
 * insert rule of Fugue replayed byte for byte (`pdt_text_edits`), the value form read strictly (`pdt_text_value`), a
 * text map value spilled to a `t` node (`pdt_text_spill`), the replica id of an agent (`pdt_text_replica`), and the
 * union of two texts, alone and in the key-wise merge of a map.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { fromHex } from "../src/bytes.js";
import { dumps } from "../src/cbor.js";
import * as pdt from "../src/pdt/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8"));
const parts = (name: string): string[] => GOLDEN[name]!.split(",");
const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const { PText } = pdt;
const { TextLeaf } = pdt.kinds;
const { TextRun, CharId } = pdt.nodes;

/** The leaf of `pdt_text_runs`, as Java's PdtVectors.textRuns builds it. */
const textRuns = (): pdt.kinds.TextLeaf => new TextLeaf([
  new TextRun("alice", 0, null, "R", 4, false, "Ab\u{1F600}c"),
  new TextRun("alice", 4, new CharId("alice", 1), "L", 2, true, ""),
  new TextRun("bob", 0, new CharId("alice", 3), "R", 2, false, "é!")]);

const base = (): pdt.PText => PText.empty("alice").insert(0, "Hello world").insert(5, ";");

test("PDT 2 phase 7: the insert rule replays pdt_text_edits byte for byte (P2-T-01, P2-T-02, P2-C-01)", () => {
  assert.equal(base().toString(), "Hello; world");
  const alice = base().delete(0, 1).insert(0, "J");
  const bob = base().withReplica("bob").insert(12, "!").insert(7, "big ");
  assert.equal(alice.toString(), "Jello; world");
  assert.equal(bob.toString(), "Hello; big world!");
  const merged = alice.merge(bob);
  const [aliceHex, bobHex, mergedHex, text] = parts("pdt_text_edits");
  assert.equal(toHex(alice.leaf().encode()), aliceHex);
  assert.equal(toHex(bob.leaf().encode()), bobHex);
  assert.equal(toHex(merged.leaf().encode()), mergedHex);
  assert.equal(merged.toString(), text);
  assert.equal(bob.merge(alice).toString(), "Jello; big world!", "the union commutes");
  assert.equal(merged.length(), [..."Jello; big world!"].length);
});

test("PDT 2 phase 7: typing at the cursor extends one run, and a delete keeps ids and drops text (P2-T-02)", () => {
  const typed = PText.empty("w").insert(0, "a").insert(1, "b").insert(2, "c");
  assert.equal(typed.leaf().runs.length, 1, "one run");
  const cut = typed.delete(1, 1);
  assert.equal(cut.toString(), "ac");
  assert.equal(cut.order().length, 3, "the deleted character keeps its id");
  assert.equal(cut.leaf().runs.filter((r) => r.deleted).length, 1);
  assert.equal(PText.empty("w").insert(0, "").leaf().runs.length, 0, "an empty insert changes nothing");
  assert.throws(() => typed.insert(4, "x"), RangeError);
  assert.throws(() => typed.delete(2, 2), RangeError);
  assert.equal(PText.empty("w").insert(0, "\u{1F600}x").length(), 2, "positions count code points");
});

test("PDT 2 phase 7: the value form of pdt_text_runs matches pdt_text_value and reads strictly (P2-T-02)", () => {
  const codec = PText.codec("alice");
  const value = codec.encode(PText.of(textRuns(), "alice"));
  assert.equal(toHex(value), GOLDEN["pdt_text_value"]);
  const read = codec.decode(fromHex(GOLDEN["pdt_text_value"]!));
  assert.equal(read.toString(), "Ab\u{1F600}cé!");
  assert.deepEqual(read.leaf().encode(), textRuns().encode());
  assert.ok(PText.isText(value));
  const wire = { k: "t", r: textRuns().runs.map((run) => [run.replica, run.counter,
    run.parent === null ? null : [run.parent.replica, run.parent.counter], run.side, run.length, run.deleted, run.text]), v: 1 };
  assert.deepEqual(dumps(wire), value, "the value form is the wire encoding of the leaf's map");
  const refused: [string, Uint8Array][] = [
    ["another key", dumps({ ...wire, x: 1 })],
    ["another version", dumps({ ...wire, v: 2 })],
    ["the node form", textRuns().encode()],
    ["a run of six fields", dumps({ ...wire, r: [wire.r[0]!.slice(0, 6)] })],
    ["runs out of canonical order", dumps({ ...wire, r: [...wire.r].reverse() })],
  ];
  for (const [why, bytes] of refused) {
    assert.throws(() => codec.decode(bytes), RangeError, why);
    assert.equal(PText.isText(bytes), false, why);
  }
});

test("PDT 2 phase 7: a text map value above 1 KiB spills to a t node as pdt_text_spill (P2-T-02)", () => {
  const store = pdt.NodeStore.inMemory();
  const map = pdt.PMap.empty<string, pdt.PText>(store, undefined, PText.codec("alice"))
    .assoc("doc", PText.empty("alice").insert(0, "x".repeat(1100)))
    .assoc("note", PText.of(textRuns(), "alice"));
  const root = map.root();
  const [rootHex, textHex] = parts("pdt_text_spill");
  assert.equal(toHex(store.get(root)!), rootHex);
  assert.equal(pdt.nodes.links(store.get(root)!).length, 1, "the note stays inline, the doc spills");
  const spilled = pdt.nodes.links(store.get(root)!)[0]!;
  assert.equal(toHex(store.get(spilled)!), textHex);
  assert.equal(TextLeaf.decode(store.get(spilled)!).text(), "x".repeat(1100));
  const reader = pdt.NodeStore.inMemory();
  for (const hexNode of parts("pdt_text_spill")) {
    reader.put(fromHex(hexNode), pdt.cids.DAG_CBOR);
  }
  const read = pdt.PMap.load<string, pdt.PText>(reader, root, undefined, PText.codec("bob"));
  assert.equal(read.get("doc")!.toString(), "x".repeat(1100));
  assert.equal(read.get("note")!.toString(), "Ab\u{1F600}cé!");
  assert.equal(read.get("doc")!.replica, "bob", "a codec reads every text for its own replica");
});

test("PDT 2 phase 7: an escalated payload keeps level-1 kinds, so a text there spills as a map (rule 7)", () => {
  const store = pdt.NodeStore.inMemory();
  const value = PText.codec("alice").encode(PText.empty("alice").insert(0, "y".repeat(1100)));
  const { root, nodes } = pdt.writePayload(value, store);
  for (const node of nodes.values()) {
    assert.notEqual(pdt.nodes.kindOf(node), "t", "no t node in a payload tree");
  }
  assert.deepEqual(pdt.readPayload(root, new pdt.Ctx(store)), value);
});

test("PDT 2 phase 7: the replica id of the golden writer matches pdt_text_replica (P2-T-02)", () => {
  const [agent, replica] = parts("pdt_text_replica");
  assert.equal(PText.replicaOf(agent!), replica);
  assert.equal(replica!.length, PText.REPLICA_LENGTH);
});

test("PDT 2 phase 7: two replicas' concurrent edits converge with each insert kept together (P2-T-03, P2-T-05)", () => {
  let seed = 7;
  const next = (n: number): number => {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    return seed % n;
  };
  for (let trial = 0; trial < 20; trial++) {
    let a = PText.empty("a").insert(0, "base text");
    let b = a.withReplica("b");
    const insertsOfA: string[] = [];
    for (let i = 0; i < 50; i++) {
      for (const side of ["a", "b"] as const) {
        const t = side === "a" ? a : b;
        let edited: pdt.PText;
        if (t.length() > 0 && next(3) === 0) {
          const at = next(t.length());
          edited = t.delete(at, Math.min(1 + next(3), t.length() - at));
        } else {
          const word = `${side}${i}`;
          if (side === "a") {
            insertsOfA.push(word);
          }
          edited = t.insert(next(t.length() + 1), word);
        }
        if (side === "a") {
          a = edited;
        } else {
          b = edited;
        }
      }
    }
    const ab = a.merge(b), ba = b.merge(a);
    assert.deepEqual(ab.leaf().encode(), ba.leaf().encode(), `trial ${trial} converges`);
    assert.equal(ab.toString(), ba.toString());
  }
});

test("PDT 2 phase 7: a map merge takes the union of two texts under one key and raises no conflict (P2-T-03)", () => {
  const store = pdt.NodeStore.inMemory();
  const codec = PText.codec("alice");
  const start = pdt.PMap.empty<string, pdt.PText>(store, undefined, codec).assoc("doc", PText.empty("alice").insert(0, "Hello"));
  const mine = start.assoc("doc", start.get("doc")!.insert(5, " world"));
  const theirs = start.assoc("doc", start.get("doc")!.withReplica("bob").insert(0, ">> "));
  const conflicts: string[] = [];
  const merged = mine.merge3(start, theirs, (key, _b, _m, t) => {
    conflicts.push(String(key));
    return t;
  });
  assert.equal(conflicts.length, 0);
  assert.equal(merged.get("doc")!.toString(), ">> Hello world");
  const other = theirs.merge3(start, mine, (_k, _b, _m, t) => t);
  assert.equal(other.get("doc")!.toString(), ">> Hello world", "every replica merges alike");
  const clash = start.assoc("doc", PText.empty("alice").insert(0, "different"));
  const resolved = mine.merge3(start, clash, (key, _b, _m, t) => {
    conflicts.push(String(key));
    return t;
  });
  assert.deepEqual(conflicts, ["doc"], "two texts that disagree on a character go to the resolver");
  assert.equal(resolved.get("doc")!.toString(), "different");
});
