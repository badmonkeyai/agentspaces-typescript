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
 * The serving half of anti-entropy (SPEC §5.3; srad/agentspaces-js.md
 * JS-R-04): the digest and delta encodings a Java member produces and
 * expects, so a peer that accepts connections answers a DIGEST exactly as
 * `ReplicatedSpace`, `AdCache`, and `RevocationRegistry` do. A space digest
 * is one line per entry and per claim, `e:<entryId>=<stateHash>` and
 * `c:<entryId>=<claimHash>`, in key order; the state hash is Java's
 * `Objects.hash(adds, removes, lease.stamp, completed)` over the record
 * components, reproduced here bit for bit and pinned by the golden vectors
 * `space_state_hash`, `space_claim_hash`, and `java_double_strings`.
 */

import { cryptoPort } from "./crypto.js";
import { utf8 } from "./bytes.js";
import { CborDouble, CborValue } from "./cbor.js";
import type { Dict } from "./wire.js";

/** `String.hashCode()`: UTF-16 code units, 31-chained, wrapped to int32. */
export function javaStringHash(text: string): number {
  let h = 0;
  for (let i = 0; i < text.length; i++) {
    h = (Math.imul(h, 31) + text.charCodeAt(i)) | 0;
  }
  return h;
}

/** `Long.hashCode(v)`: `(int) (v ^ (v >>> 32))`, for any safe integer. */
export function javaLongHash(value: number | bigint): number {
  const v = BigInt.asUintN(64, BigInt(value));
  return Number(BigInt.asIntN(32, v ^ (v >> 32n)));
}

/** `Boolean.hashCode`. */
function javaBooleanHash(value: boolean): number {
  return value ? 1231 : 1237;
}

/** A record's hash as `java.lang.runtime.ObjectMethods` derives it: 31-chained over the components from 0. */
function javaRecordHash(components: number[]): number {
  let h = 0;
  for (const c of components) {
    h = (Math.imul(h, 31) + c) | 0;
  }
  return h;
}

/** `Objects.hash(...)` (`Arrays.hashCode`): 31-chained over the elements from 1. */
function javaObjectsHash(components: number[]): number {
  let h = 1;
  for (const c of components) {
    h = (Math.imul(h, 31) + c) | 0;
  }
  return h;
}

/** A `Dot(String replica, long counter)` record's hash. */
export function dotHash(dot: Dict): number {
  return javaRecordHash([javaStringHash(String(dot["replica"] ?? "")), javaLongHash(Number(dot["counter"] ?? 0))]);
}

/** A `Set<Dot>`'s hash: the sum of its members' hashes (duplicates by replica and counter count once). */
export function dotSetHash(dots: unknown): number {
  const seen = new Set<string>();
  let h = 0;
  for (const dot of Array.isArray(dots) ? dots : []) {
    if (dot === null || typeof dot !== "object") {
      continue;
    }
    const d = dot as Dict;
    const key = `${String(d["replica"] ?? "")}\u0000${Number(d["counter"] ?? 0)}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    h = (h + dotHash(d)) | 0;
  }
  return h;
}

/** An `HlcTimestamp(long physical, int logical, String node)` record's hash, from its encoded form. */
export function hlcHash(encoded: string): number {
  const first = encoded.indexOf(":");
  const second = encoded.indexOf(":", first + 1);
  const physical = Number(encoded.slice(0, first));
  const logical = Number(encoded.slice(first + 1, second)) | 0;
  const node = encoded.slice(second + 1);
  return javaRecordHash([javaLongHash(physical), logical, javaStringHash(node)]);
}

/** `Integer.toHexString`: two's complement, lower case, no padding. */
export function javaHex(value: number): string {
  return (value >>> 0).toString(16);
}

/**
 * `ReplicatedSpace.stateHash`: `Integer.toHexString(Objects.hash(adds, removes, lease.stamp, completed))`
 * over the wire form of an entry's state (the DTO a peer holds).
 */
export function stateHash(dto: Dict): string {
  return javaHex(javaObjectsHash([
    dotSetHash(dto["adds"]), dotSetHash(dto["removes"]),
    hlcHash(String(dto["leaseStamp"] ?? "0:0:")), javaBooleanHash(Boolean(dto["completed"])),
  ]));
}

/**
 * `Double.toString(d)`: the shortest digits that round-trip, always with a
 * fraction, and in computerized scientific notation (`1.0E7`, `1.5E-5`)
 * outside [1e-3, 1e7).
 */
export function javaDoubleString(value: number): string {
  if (Number.isNaN(value)) {
    return "NaN";
  }
  if (!Number.isFinite(value)) {
    return value > 0 ? "Infinity" : "-Infinity";
  }
  if (value === 0) {
    return Object.is(value, -0) ? "-0.0" : "0.0";
  }
  if (Math.abs(value) === Number.MIN_VALUE) {
    return value > 0 ? "4.9E-324" : "-4.9E-324"; // Java prints the smallest subnormal with two digits
  }
  const magnitude = Math.abs(value);
  if (magnitude >= 1e-3 && magnitude < 1e7) {
    const plain = value.toFixed(20).replace(/0+$/, "");
    const shortest = String(value); // the shortest round-trip digits, which Java also prints
    const text = shortest.includes("e") ? plain : shortest;
    return text.includes(".") ? text : `${text}.0`;
  }
  const [mantissa, exponent] = value.toExponential().split("e");
  return `${mantissa.includes(".") ? mantissa : `${mantissa}.0`}E${Number(exponent)}`;
}

function numeric(value: CborValue | undefined): number {
  return value instanceof CborDouble ? value.value : Number(value ?? 0);
}

/** `ReplicatedSpace.claimHash`: `epoch:stamp:bid:expiresAtMillis`, the bid as Java prints a double. */
export function claimHash(claim: Dict): string {
  return `${Math.trunc(numeric(claim["epoch"]))}:${String(claim["stamp"] ?? "")}:`
    + `${javaDoubleString(numeric(claim["bid"]))}:${Math.trunc(numeric(claim["expiresAtMillis"]))}`;
}

/** The lines of a digest, `key=value` each, in Java `TreeMap` (UTF-16 code unit) order. */
export function digestLines(summary: Map<string, string>): string {
  const keys = [...summary.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  let out = "";
  for (const key of keys) {
    out += `${key}=${summary.get(key)!}\n`;
  }
  return out;
}

/** The lines of a remote digest as a set, the way `deltaFor` reads them. */
export function parseDigestLines(digest: Uint8Array): Set<string> {
  return new Set(new TextDecoder().decode(digest).split("\n"));
}

/**
 * `AdCache.digest`: SHA-256 of the key lines, then the lines (`<id>=<issuedMillis>`), so a
 * partner compares the hash first; `parseAdDigestKeys` reads the lines back.
 */
export function adDigest(keys: Map<string, string>): Uint8Array {
  const lines = utf8(digestLines(keys));
  const hash = cryptoPort().sha256(lines);
  const out = new Uint8Array(hash.length + lines.length);
  out.set(hash, 0);
  out.set(lines, hash.length);
  return out;
}

export function parseAdDigestKeys(digest: Uint8Array): Set<string> {
  if (digest.length <= 32) {
    return new Set();
  }
  return new Set(new TextDecoder().decode(digest.subarray(32)).split("\n").filter((line) => line.length > 0));
}

/** A revocation digest line: `<key>=<sha256 hex of the signed bytes>` (`r:<peer>` or `c:<kind>:<target>`). */
export function revocationLine(key: string, adBytes: Uint8Array): string {
  return `${key}=${[...cryptoPort().sha256(adBytes)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}
