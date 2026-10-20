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

import assert from "node:assert/strict";
import test from "node:test";
import { cbor } from "@agentspaces/client";
import * as sig from "../src/signal.js";
import * as fp from "../src/fingerprints.js";

const SID = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
const FP = "sha-256 AB:CD";
const SDP = "v=0\r\na=fingerprint:sha-256 AB:CD\r\n";

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// The Java-to-TypeScript byte pins (JS-W-03): the same hex is asserted in the Java
// RtcSignalTest. Golden vectors for these bodies are owned by another agent this round; until the
// generator emits them, these pins keep the two codecs byte-identical (indefinite map, component
// order v, fp, mid, sdp, sid, cand, code, kind, absent keys omitted).
test("END(2) matches the Java canonical bytes", () => {
  assert.equal(hex(sig.encode(sig.end(SID, sig.END_TIMEOUT))),
    "bf6176016373696450000102030405060708090a0b0c0d0e0f64636f646502646b696e6463454e44ff");
});

test("the end of the trickle matches the Java canonical bytes", () => {
  assert.equal(hex(sig.encode(sig.candidate(SID, "", "0"))),
    "bf617601636d696461306373696450000102030405060708090a0b0c0d0e0f6463616e6460646b696e646443414e44ff");
});

test("ANSWER matches the Java canonical bytes", () => {
  assert.equal(hex(sig.encode(sig.answer(SID, SDP, [FP]))), "bf617601626670816d7368612d3235362041"
    + "423a4344637364707822763d300d0a613d66696e6765727072696e743a7368612d3235362041423a43440d0a637369645000"
    + "0102030405060708090a0b0c0d0e0f646b696e6466414e53574552ff");
});

test("OFFER matches the Java canonical bytes", () => {
  assert.equal(hex(sig.encode(sig.offer(SID, SDP, [FP]))), "bf617601626670816d7368612d32353620414"
    + "23a4344637364707822763d300d0a613d66696e6765727072696e743a7368612d3235362041423a43440d0a637369645000"
    + "0102030405060708090a0b0c0d0e0f646b696e64654f46464552ff");
});

test("CAND matches the Java canonical bytes", () => {
  assert.equal(hex(sig.encode(sig.candidate(SID, "candidate:1 1 UDP 1 192.0.2.1 5000 typ host", "0"))),
    "bf617601636d696461306373696450000102030405060708090a0b0c0d0e0f6463616e64782b63616e646964"
    + "6174653a312031205544502031203139322e302e322e3120353030302074797020686f7374646b696e646443414e44ff");
});

test("a receiver ignores unknown keys and judges the known ones (JS-F-02)", () => {
  // A body with later fields (a WebRTC Direct cert hash, a renegotiation kind) the reader ignores.
  const body = cbor.dumps({ v: 1, sid: SID, kind: "END", code: 0, certhash: "later", renegotiate: "ice-restart" });
  const signal = sig.decode(body);
  assert.ok(signal !== null);
  assert.equal(sig.malformed(signal!), null);
  assert.equal(signal!.kind, "END");
  assert.equal(signal!.code, 0);
});

test("the bounds of appendix B", () => {
  assert.equal(sig.malformed(sig.offer(SID, "x".repeat(sig.MAX_SDP + 1), [FP])), "sdp");
  assert.equal(sig.malformed(sig.offer(SID, SDP, [])), "fp");
  assert.equal(sig.malformed(sig.offer(SID, SDP, [FP, FP, FP, FP, FP])), "fp");
  assert.equal(sig.malformed(sig.offer(SID, SDP, ["md5 AB:CD"])), null);
  assert.equal(sig.malformed(sig.offer(SID, SDP, ["garbage"])), "fp");
  assert.equal(sig.malformed(sig.candidate(SID, "c".repeat(sig.MAX_CAND + 1), "0")), "cand");
  assert.equal(sig.malformed({ v: 1, sid: SID, kind: "RENEG" as sig.SignalKind }), "kind RENEG");
  assert.equal(sig.malformed({ v: 2, sid: SID, kind: "END", code: 0 }), "v 2");
  assert.equal(sig.malformed({ v: 1, sid: new Uint8Array(15), kind: "END", code: 0 }), "sid");
});

test("fingerprints match exactly the signed list (JS-W-04)", () => {
  assert.deepEqual(fp.fingerprintsOf("v=0\r\na=fingerprint:SHA-256 ab:cd\r\n"), ["sha-256 AB:CD"]);
  assert.equal(fp.matches(SDP, [FP]), true);
  assert.equal(fp.matches(SDP, ["sha-256 AB:CE"]), false);
  assert.equal(fp.matches(SDP, [FP, "sha-256 AB:CE"]), false);
  assert.equal(fp.matches(SDP, []), false);
  assert.equal(fp.matches("v=0\r\n", [FP]), false);
});
