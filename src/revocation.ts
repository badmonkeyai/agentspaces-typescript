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
 * Revocations in TypeScript (SPEC §5.6, v0.1.13): the `revocations` stream's
 * peer revocations and the `credential-revocations` stream's revocations of
 * agents, agent keys, X.509 leaves, and join credentials, verified as a Java
 * member verifies them except for the CA-rooted path, which this client does
 * not carry (a CA-rooted record is ignored, never trusted). One record per
 * target, by Java's total order: authority (founder, then the agent's own
 * peer), then the newer `issued`, then the larger SHA-256 of the signed bytes.
 */

import { createHash } from "node:crypto";
import { CborValue, loads } from "./cbor.js";
import { Identity, deriveId, parseInstantMillis } from "./identity.js";

type Dict = { [key: string]: CborValue };

export const PEER_STREAM = "revocations";
export const CREDENTIAL_STREAM = "credential-revocations";
export const STREAMS = [PEER_STREAM, CREDENTIAL_STREAM];
export const KEY_COMPROMISE = "key-compromise";
export const REASONS = [KEY_COMPROMISE, "retired", "superseded", "privilege-withdrawn", "unspecified"];
const KINDS = ["AGENT", "AGENT_KEY", "X509_LEAF", "JOIN_CREDENTIAL"];
const FOUNDER = 3;
const OWN_PEER = 1;
const MAX_ISSUED_SKEW_MILLIS = 10 * 60 * 1000;
const MAX_RETAINED = 4096;

type Held = { rank: number; issued: number; hash: string; ad: Dict };

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

/** CredentialRevocation.Target.canonical: the target's text within its kind. */
export function canonicalTarget(target: Dict): string {
  switch (target["kind"]) {
    case "AGENT": return String(target["agent"]);
    case "AGENT_KEY": return `${String(target["agent"])}#${hex(target["keyFingerprint"] as Uint8Array)}`;
    case "X509_LEAF": return hex(target["certificateFingerprint"] as Uint8Array);
    default: return hex(target["credentialHash"] as Uint8Array);
  }
}

/** CredentialRevocation.idFor: aspace://<group>/revocation/<kind>/<canonical>. */
export function revocationId(group: string, target: Dict): string {
  return `aspace://${group}/revocation/${String(target["kind"]).toLowerCase()}/${canonicalTarget(target)}`;
}

function validTarget(target: unknown): target is Dict {
  if (typeof target !== "object" || target === null || Array.isArray(target)) {
    return false;
  }
  const t = target as Dict;
  const sized = (key: string) => t[key] instanceof Uint8Array && (t[key] as Uint8Array).length === 32;
  switch (t["kind"]) {
    case "AGENT": return typeof t["agent"] === "string";
    case "AGENT_KEY": return typeof t["agent"] === "string" && sized("keyFingerprint");
    case "X509_LEAF": return sized("certificateFingerprint");
    case "JOIN_CREDENTIAL": return sized("credentialHash");
    default: return false;
  }
}

function refusesAt(ad: Dict, signingMillis: number | null): boolean {
  if (ad["reason"] === KEY_COMPROMISE || signingMillis === null) {
    return true;
  }
  return signingMillis >= parseInstantMillis(ad["effectiveFrom"] ?? ad["issued"]);
}

/** One group's accepted revocations as a client holds and applies them. */
export class Registry {
  readonly peers = new Map<string, Held>();
  readonly credentials = new Map<string, Held>();

  constructor(private readonly founder: () => string | null,
              private readonly group: () => string | null = () => null) {}

  /** Verifies and accepts one rumor payload (a CBOR SignedRevocation). */
  accept(stream: string, payload: unknown, nowMillis: number): boolean {
    if (!(payload instanceof Uint8Array)) {
      return false;
    }
    let signed: CborValue;
    try {
      signed = loads(Buffer.from(payload));
    } catch {
      return false;
    }
    return this.acceptSigned(stream, signed, nowMillis);
  }

  /** Verifies and accepts one decoded SignedRevocation {adBytes, publicKey, signature}. */
  acceptSigned(stream: string, signed: unknown, nowMillis: number): boolean {
    if (typeof signed !== "object" || signed === null || Array.isArray(signed)) {
      return false;
    }
    const s = signed as Dict;
    const adBytes = s["adBytes"];
    const key = s["publicKey"];
    const signature = s["signature"];
    if (!(adBytes instanceof Uint8Array) || !(key instanceof Uint8Array) || key.length !== 32
        || !(signature instanceof Uint8Array)) {
      return false;
    }
    let ad: Dict;
    let issued: number;
    try {
      ad = loads(Buffer.from(adBytes)) as Dict;
      issued = parseInstantMillis(ad["issued"]);
    } catch {
      return false;
    }
    const group = this.group();
    if (typeof ad !== "object" || ad === null || deriveId(key) !== ad["issuer"]
        || !Identity.verify(key, adBytes, signature)
        || issued > nowMillis + MAX_ISSUED_SKEW_MILLIS
        || (group !== null && ad["group"] !== group)) {
      return false;
    }
    const hash = createHash("sha256").update(adBytes).digest("hex");
    if (stream === PEER_STREAM) {
      const founder = this.founder();
      // Founder-rooted only: a CA-rooted record is not trusted here.
      if (founder === null || ad["issuer"] !== founder || typeof ad["revoked"] !== "string") {
        return false;
      }
      return keep(this.peers, ad["revoked"] as string, { rank: FOUNDER, issued, hash, ad });
    }
    if (stream !== CREDENTIAL_STREAM) {
      return false;
    }
    const target = ad["target"];
    if (!validTarget(target) || !REASONS.includes(String(ad["reason"]))
        || ad["id"] !== revocationId(String(ad["group"]), target)) {
      return false;
    }
    try {
      if (ad["effectiveFrom"] != null && parseInstantMillis(ad["effectiveFrom"]) > issued) {
        return false;
      }
    } catch {
      return false;
    }
    let rank: number;
    if (ad["issuer"] === this.founder()) {
      rank = FOUNDER;
    } else if ((target["kind"] === "AGENT" || target["kind"] === "AGENT_KEY")
        && String(target["agent"]).startsWith(`${String(ad["issuer"])}/`)) {
      rank = OWN_PEER;
    } else {
      return false;
    }
    return keep(this.credentials, `${String(target["kind"])}:${canonicalTarget(target)}`,
      { rank, issued, hash, ad });
  }

  peerRevoked(peerId: string): boolean {
    return this.peers.has(peerId);
  }

  /**
   * RevocationView.refuses: a newly arriving signature by `agentId` is refused
   * when its peer is revoked, or an agent-wide or (given the key) key
   * revocation refuses `signingMillis` under the freeze rule.
   */
  refuses(agentId: unknown, agentKey: unknown, signingMillis: number | null): boolean {
    if (typeof agentId !== "string" || !agentId.includes("/")) {
      return false;
    }
    if (this.peerRevoked(agentId.slice(0, agentId.indexOf("/")))) {
      return true;
    }
    const whole = this.credentials.get(`AGENT:${agentId}`);
    if (whole !== undefined && refusesAt(whole.ad, signingMillis)) {
      return true;
    }
    if (agentKey instanceof Uint8Array) {
      const fingerprint = createHash("sha256").update(agentKey).digest("hex");
      const one = this.credentials.get(`AGENT_KEY:${agentId}#${fingerprint}`);
      if (one !== undefined && refusesAt(one.ad, signingMillis)) {
        return true;
      }
    }
    return false;
  }
}

function outranks(a: Held, b: Held): boolean {
  if (a.rank !== b.rank) return a.rank > b.rank;
  if (a.issued !== b.issued) return a.issued > b.issued;
  return a.hash > b.hash;
}

function keep(table: Map<string, Held>, key: string, candidate: Held): boolean {
  const held = table.get(key);
  if (held === undefined) {
    if (table.size >= MAX_RETAINED) {
      return false;
    }
    table.set(key, candidate);
    return true;
  }
  if (outranks(candidate, held)) {
    table.set(key, candidate);
  }
  return false;
}

export { KINDS };
