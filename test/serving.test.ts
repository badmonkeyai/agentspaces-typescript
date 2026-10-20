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
 * The Java encodings the serving half reproduces (srad/agentspaces-js.md
 * JS-R-04): `String.hashCode`, `Long.hashCode`, the record and `Objects.hash`
 * chains behind `ReplicatedSpace.stateHash`, `Double.toString` behind
 * `claimHash`, and the digest line formats, against values computed by the
 * JDK and, once the generator has run, the golden vectors `space_state_hash`,
 * `space_claim_hash`, and `java_double_strings`.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { fromHex } from "../src/bytes.js";
import { loads } from "../src/cbor.js";
import * as serving from "../src/serving.js";
import type { Dict } from "../src/wire.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf-8")) as
  { [key: string]: unknown };

test("String.hashCode and Long.hashCode as the JDK computes them", () => {
  assert.equal(serving.javaStringHash(""), 0);
  assert.equal(serving.javaStringHash("a"), 97);
  assert.equal(serving.javaStringHash("hello"), 99162322);
  assert.equal(serving.javaStringHash("polygenelubricants"), Math.pow(2, 31) * -1); // the famous Integer.MIN_VALUE string
  assert.equal(serving.javaLongHash(0), 0);
  assert.equal(serving.javaLongHash(1), 1);
  assert.equal(serving.javaLongHash(-1), 0);
  assert.equal(serving.javaLongHash(4294967296), 1); // 2^32: the high word folds in
  assert.equal(serving.javaLongHash(1735689600000), 1735689600000 % 4294967296 ^ Math.floor(1735689600000 / 4294967296));
});

test("Double.toString as Java prints it", () => {
  const cases: [number, string][] = [
    [1, "1.0"], [0.5, "0.5"], [100, "100.0"], [-2.5, "-2.5"], [0.001, "0.001"], [1e7, "1.0E7"],
    [1.5e-5, "1.5E-5"], [123456789, "1.23456789E8"], [0.0001, "1.0E-4"], [0, "0.0"], [3.25, "3.25"],
    [9999999, "9999999.0"], [1e21, "1.0E21"], [Number.NaN, "NaN"], [Number.POSITIVE_INFINITY, "Infinity"],
  ];
  for (const [value, expected] of cases) {
    assert.equal(serving.javaDoubleString(value), expected, String(value));
  }
  const golden = GOLDEN["java_double_strings"] as { [text: string]: string } | undefined;
  for (const [text, expected] of Object.entries(golden ?? {})) {
    assert.equal(serving.javaDoubleString(Number(text)), expected, `golden ${text}`);
  }
});

test("the state and claim hashes match ReplicatedSpace on the golden delta (space_state_hash, space_claim_hash)", () => {
  const delta = loads(fromHex(String(GOLDEN["delta_cbor"]))) as Dict;
  const dto = delta["state"] as Dict;
  const hash = serving.stateHash(dto);
  assert.match(hash, /^[0-9a-f]{1,8}$/);
  // A changed component changes the hash: the completion flag and the lease stamp both count.
  assert.notEqual(serving.stateHash({ ...dto, completed: true }), hash);
  assert.notEqual(serving.stateHash({ ...dto, leaseStamp: "1:0:x" }), hash);
  // Dot sets hash by membership, not order or repetition, as Java's Set does.
  const adds = dto["adds"] as Dict[];
  assert.equal(serving.stateHash({ ...dto, adds: [...adds, ...adds] }), hash);
  if (GOLDEN["space_state_hash"] !== undefined) {
    assert.equal(hash, GOLDEN["space_state_hash"]);
  }
  const claimDelta = loads(fromHex(String(GOLDEN["claim_delta_cbor"]))) as Dict;
  const claim = ((claimDelta["claim"] as Dict)["claim"]) as Dict;
  const claimHash = serving.claimHash(claim);
  assert.match(claimHash, /^\d+:\d+:\d+:[^:]+:-?[\d.E-]+:\d+$/);
  if (GOLDEN["space_claim_hash"] !== undefined) {
    assert.equal(claimHash, GOLDEN["space_claim_hash"]);
  }
});

test("digest lines sort as a TreeMap and the ad digest carries its hash first", () => {
  const lines = serving.digestLines(new Map([["e:b", "1"], ["c:a", "2"], ["e:a", "3"]]));
  assert.equal(lines, "c:a=2\ne:a=3\ne:b=1\n");
  assert.deepEqual([...serving.parseDigestLines(new TextEncoder().encode(lines))].filter((l) => l.length > 0),
    ["c:a=2", "e:a=3", "e:b=1"]);
  const ads = serving.adDigest(new Map([["aspace://g/agent/x", "1735689600000"]]));
  assert.equal(ads.length, 32 + "aspace://g/agent/x=1735689600000\n".length);
  assert.deepEqual([...serving.parseAdDigestKeys(ads)], ["aspace://g/agent/x=1735689600000"]);
  assert.equal(serving.parseAdDigestKeys(new Uint8Array()).size, 0);
  assert.match(serving.revocationLine("r:zPeer", new Uint8Array([1, 2, 3])), /^r:zPeer=[0-9a-f]{64}$/);
});
