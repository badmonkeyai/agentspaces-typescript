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
 * HLC round seven, 2026-11-08: the gaps SPEC §9.3 and TECH-SPEC §11 left after round six, as they bind
 * this client, settled by the reference rule (Java's behaviour unless it breaks F1 or F3).
 *
 * 1. A bignum holds at most 1000 bytes, alone or as a decimal's mantissa (S9): no decoder reads a longer
 *    one and no encoder writes one, as Jackson reads none.
 * 2. `dumps` writes a JavaScript Map as the map it holds, in its insertion order; it once wrote `BF FF`.
 * 5. A stamp is one definite text of at most 3996 UTF-16 units: a longer text travels only in Jackson's
 *    chunks and is no stamp, a `pdt.issued` included, and a clock's node leaves room for the longest
 *    physical and logical parts.
 * 6. The aggregate and semantic-discovery pipe payloads decode under their SPEC annex I schemas and the
 *    canonical-bytes rule, as Java's fromWire reads them; a `double` field takes any float64.
 * 8. A beacon document that carries a signature arrives as exactly its canonical JSON (the
 *    `beacon-document` vectors).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { documentSigner, parseBeaconDocument } from "../src/beacon.js";
import { CborDecimal, CborDouble, CborFloat32, dumps, loads } from "../src/cbor.js";
import { Aggregate } from "../src/capabilities/aggregate.js";
import type { Pipes } from "../src/capabilities/pipes.js";
import { Semantic } from "../src/capabilities/semantic.js";
import * as records from "../src/records.js";
import { decodeHlc, hlcNow } from "../src/wire.js";

const here = dirname(fileURLToPath(import.meta.url));
type Vector = { id: string; carrier: string; hex: string; verdict: string; why: string; signer?: string | null };
const VECTORS = (JSON.parse(readFileSync(join(here, "..", "..", "test", "wire-encoding-vectors.json"), "utf-8")) as
  { vectors: Vector[] }).vectors;

// 1. A bignum holds at most 1000 bytes ----------------------------------------------------------------

test("the encoder writes no bignum past 1000 bytes", () => {
  const widest = (1n << 7991n) + 1n;
  assert.equal(dumps(widest).length, 1004);
  assert.equal(loads(dumps(widest)), widest);
  for (const value of [1n << 7999n, -(1n << 7999n), new CborDecimal(-1, (1n << 7999n) + 1n)]) {
    assert.throws(() => dumps(value), RangeError);
  }
});

// 2. A Map writes as the map it holds -------------------------------------------------------------------

test("dumps writes a Map as an indefinite map in its insertion order, integer-like keys included", () => {
  const map = new Map<string, number>([["b", 1], ["10", 2]]);
  assert.equal(Buffer.from(dumps(map)).toString("hex"), "bf616201623130" + "02ff");
  assert.equal(Buffer.from(dumps({ outer: new Map([["k", [new Map()]]]) })).toString("hex"),
    "bf656f75746572bf616b81bfffffff");
  assert.throws(() => dumps(new Map<unknown, number>([[1, 1]]) as unknown as Map<string, number>), RangeError);
});

// 5. A stamp is at most 3996 UTF-16 units ---------------------------------------------------------------

const PREFIX = "1800000000000:0:";

test("a stamp past 3996 UTF-16 units is no stamp", () => {
  const edge = PREFIX + "n".repeat(3996 - PREFIX.length);
  assert.notEqual(decodeHlc(edge), null);
  assert.equal(decodeHlc(edge + "n"), null);
  const pairs = PREFIX + "\u{1F600}".repeat((3996 - PREFIX.length) / 2);
  assert.notEqual(decodeHlc(pairs), null);
  assert.equal(decodeHlc(pairs + "n"), null);
  assert.equal(decodeHlc(loads(dumps(edge + "n"))), null);
});

test("a clock refuses a node that could carry a stamp past 3996 units", () => {
  const longest = "n".repeat(3965);
  assert.equal(`${(1n << 63n) - 1n}:${2 ** 31 - 1}:${longest}`.length, 3996);
  assert.ok(hlcNow(longest, 1_800_000_000_000).endsWith(longest));
  assert.throws(() => hlcNow(longest + "n", 1_800_000_000_000));
});

// 6. Pipe payloads decode under their schemas -----------------------------------------------------------

/** Capability pipes that hand a test the handler and keep what the capability sends. */
function stubPipes() {
  const handlers = new Map<string, (from: string, payload: Uint8Array) => void>();
  const sent: Uint8Array[] = [];
  const pipes = {
    peer: { identity: { peerId: "zSelf" }, ads: new Map(), now: () => 1_800_000_000_000 },
    onCapability: (type: string, handler: (from: string, payload: Uint8Array) => void) => handlers.set(type, handler),
    send: (_to: string, _type: string, payload: Uint8Array) => sent.push(payload),
    members: () => [],
  };
  return { pipes: pipes as unknown as Pipes, handlers, sent };
}

function frame(variant: { [key: string]: unknown }): Uint8Array {
  return dumps({ share: null, extremum: null, histogram: null, roster: null, ...variant } as never);
}

function aggregateHears(payload: Uint8Array): boolean {
  const { pipes, handlers } = stubPipes();
  const aggregate = new Aggregate(pipes, false);
  handlers.get("aspace:cap/aggregate")!("zPeer", payload);
  return aggregate.exchanged;
}

test("an aggregate frame decodes under its schema, a NaN extremum included", () => {
  assert.ok(aggregateHears(frame({ extremum: { epochId: "e", max: true, value: new CborDouble(Number.NaN) } })));
  assert.ok(aggregateHears(frame({ share: { epochId: "e", value: new CborDouble(1), weight: new CborDouble(0.5) } })));
  assert.ok(aggregateHears(frame({ roster: { epochId: "e", members: [-5, 7] } })));
  assert.ok(!aggregateHears(frame({ share: { epochId: "e", value: 1, weight: new CborDouble(0.5) } })));
  assert.ok(!aggregateHears(frame({ share: { epochId: "e", value: new CborFloat32(1), weight: new CborDouble(0.5) } })));
  assert.ok(!aggregateHears(frame({ share: { epochId: "e", value: new CborDouble(1), weight: new CborDouble(0.5), x: 1 } })));
  assert.ok(!aggregateHears(frame({ roster: { epochId: "e", members: [new CborDouble(1)] } })));
  assert.ok(!aggregateHears(dumps({ share: { epochId: "e", value: new CborDouble(1), weight: new CborDouble(0.5) } })));
});

test("a semantic query decodes under its schema", () => {
  const { pipes, handlers, sent } = stubPipes();
  new Semantic(pipes);
  const hear = handlers.get("aspace:cap/semantic-discovery")!;
  hear("zPeer", dumps({ nonce: 3, text: "tasks", limit: 4 }));
  assert.equal(sent.length, 1);
  const relabels: Array<{ [key: string]: string | number | CborDouble }> = [
    { nonce: 3, text: "tasks", limit: new CborDouble(4) }, { nonce: "3", text: "tasks", limit: 4 },
    { nonce: 3, text: "tasks", limit: 4, x: 1 }, { text: "tasks", nonce: 3, limit: 4 }];
  for (const relabel of relabels) {
    hear("zPeer", dumps(relabel));
  }
  assert.equal(sent.length, 1);
});

test("a take claim keeps its finite bid while a double field takes any float64", () => {
  assert.notEqual(records.conformed({ epochId: "e", max: false, value: new CborDouble(Infinity) },
    records.AGGREGATE_EXTREMUM), null);
  const claim = { entryId: "e", spaceId: "s", epoch: 1, stamp: "1:0:n", holder: "zPeer/w",
    bid: new CborDouble(Number.NaN), expiresAtMillis: 5 };
  assert.equal(records.conformed(claim, records.TAKE_CLAIM), null);
  assert.notEqual(records.conformed({ ...claim, bid: new CborDouble(-0) }, records.TAKE_CLAIM), null);
});

// 8. A signed beacon document arrives canonical ---------------------------------------------------------

const BEACONS = VECTORS.filter((v) => v.carrier === "beacon-document");

test("every beacon vector reads exactly as its verdict says", () => {
  assert.equal(BEACONS.length, 40);
  for (const v of BEACONS) {
    const body = Uint8Array.from(Buffer.from(v.hex, "hex"));
    if (v.verdict === "accept") {
      assert.equal(documentSigner(parseBeaconDocument(body)), v.signer, v.id);
      assert.equal(documentSigner(parseBeaconDocument(Buffer.from(body).toString("utf-8"))), v.signer, v.id);
    } else {
      assert.throws(() => parseBeaconDocument(body), Error, `${v.id}: ${v.why}`);
    }
  }
});
