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
 * Layer 0 in TypeScript (spec §4): Ed25519 identity over the installed
 * crypto port (noble by default, srad/agentspaces-js.md JS-P-02), and the
 * self-certifying derivations. A PeerID is multibase
 * base58btc of sha-256 over the raw 32-byte public key; GroupIDs and SpaceIDs
 * derive the same way from their founding bytes (§4.4). The group founding
 * of §5.1 lives here too: the founding fields, the founder's signature, the
 * founding document whose hash is the GroupID, and the four-check verifier a
 * joiner applies to every GROUP_AD it is served.
 */

import { concat, equals, fromHex, toHex, utf8 } from "./bytes.js";
import { CborDouble, CborValue, dumps, loads } from "./cbor.js";
import { cryptoPort } from "./crypto.js";

type Dict = { [key: string]: CborValue };

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** The 12-byte X.509 SubjectPublicKeyInfo prefix for an Ed25519 public key. */
export const SPKI_PREFIX = fromHex("302a300506032b6570032100");
/** The 16-byte PKCS#8 PrivateKeyInfo prefix wrapping a raw Ed25519 seed (RFC 8410). */
export const PKCS8_PREFIX = fromHex("302e020100300506032b657004220420");
/** The Ed25519 algorithm identifier inside a PKCS#8 PrivateKeyInfo (RFC 8410). */
const ED25519_ALGORITHM = fromHex("300506032b6570");

/** Base58 (Bitcoin alphabet) with leading-zero preservation. */
export function base58btc(data: Uint8Array): string {
  let zeros = 0;
  while (zeros < data.length && data[zeros] === 0) {
    zeros++;
  }
  let n = BigInt("0x" + (toHex(data) || "0"));
  let encoded = "";
  while (n > 0n) {
    encoded = ALPHABET[Number(n % 58n)] + encoded;
    n /= 58n;
  }
  return "1".repeat(zeros) + encoded;
}

/** The multibase form the Java side uses: 'z' + base58btc. */
export function multibase(data: Uint8Array): string {
  return "z" + base58btc(data);
}

/** multibase(sha-256(material)): PeerIDs, GroupIDs, and SpaceIDs alike. */
export function deriveId(material: Uint8Array): string {
  return multibase(cryptoPort().sha256(material));
}

/**
 * GroupId.fromFounding, in TypeScript: the literal-founding form, for groups
 * whose members share a founding string as configuration (§10.1 `founding`).
 */
export function groupIdFromFounding(founding: Uint8Array | string): string {
  return deriveId(typeof founding === "string" ? utf8(founding) : founding);
}

// ------------------------------------------------------- group founding (§5.1)

/** The URI scheme prefix a founding advertisement's id carries (§4.4). */
export const ASPACE_URI_PREFIX = "aspace://";

/**
 * GroupFounding.FoundingFields in canonical order: the immutable fields of a
 * group that no later party may change. `ttl` and `periodIso` are java.time
 * Duration strings ("PT24H", "PT1S"); `issuedIso` is an ISO instant.
 */
export function foundingFields(name: string, founder: string, issuedIso: string,
                               ttlIso: string, membershipPolicy: string,
                               defaultStrategy: string, fanout: number,
                               periodIso: string): Dict {
  return { name, founder, issued: issuedIso, ttl: ttlIso, membershipPolicy,
    defaultStrategy, gossip: { fanout, period: periodIso } };
}

/** The founding fields of a GroupAdvertisement, rebuilt in canonical order. */
export function foundingFieldsOf(ad: Dict): Dict {
  const gossip = (ad["gossip"] ?? {}) as Dict;
  return foundingFields(String(ad["name"]), String(ad["issuer"]),
    String(ad["issued"]), String(ad["ttl"]), String(ad["membershipPolicy"]),
    String(ad["defaultStrategy"]), Number(gossip["fanout"]),
    String(gossip["period"]));
}

/**
 * GroupFounding.FoundingDocument: the founding fields and the founder's
 * signature over their canonical CBOR. Its canonical CBOR hashes to the GroupID.
 */
export function foundingDocument(fields: Dict, signature: Uint8Array): Dict {
  return { fields, signature };
}

/** GroupId.fromFounding over a founding document's canonical CBOR (§4.4). */
export function groupIdFromFoundingDocument(documentBytes: Uint8Array): string {
  return deriveId(documentBytes);
}

/**
 * A GroupAdvertisement in Java field order: id, issuer, group, issued, ttl,
 * name, membershipPolicy, defaultStrategy, gossip {fanout, period}.
 */
export function groupAdvertisement(group: string, fields: Dict): Dict {
  return { id: ASPACE_URI_PREFIX + group, issuer: fields["founder"], group,
    issued: fields["issued"], ttl: fields["ttl"], name: fields["name"],
    membershipPolicy: fields["membershipPolicy"],
    defaultStrategy: fields["defaultStrategy"], gossip: fields["gossip"] };
}

/**
 * GroupFounding.found: signs the founding fields, derives the self-certifying
 * GroupID from the founding document, and returns the
 * SignedGroupAdvertisement {advertisement, founderPublicKey, signature} to
 * join with and to serve to newcomers as a GROUP_AD body (§5.1, §9).
 */
export function foundGroup(identity: Identity, name: string, membershipPolicy: string,
                           defaultStrategy: string, fanout: number, periodIso: string,
                           issuedIso: string, ttlIso: string): Dict {
  const fields = foundingFields(name, identity.peerId, issuedIso, ttlIso,
    membershipPolicy, defaultStrategy, fanout, periodIso);
  const signature = identity.sign(dumps(fields));
  const group = groupIdFromFoundingDocument(dumps(foundingDocument(fields, signature)));
  return { advertisement: groupAdvertisement(group, fields),
    founderPublicKey: identity.publicRaw, signature };
}

/**
 * GroupFounding.verify, the four checks of §5.1 a joiner applies to every
 * GROUP_AD before acting on it: the founder key hashes to the advertisement's
 * issuer; the signature verifies over the founding fields rebuilt from the
 * advertisement; the founding document derives to `advertisement.group`; and
 * the `id` URI names that group. Returns the verified GroupID, or null.
 * Accepts the decoded SignedGroupAdvertisement or its raw CBOR bytes.
 */
export function verifySignedGroupAd(signed: CborValue | Uint8Array): string | null {
  let value: CborValue = signed;
  if (signed instanceof Uint8Array) {
    try {
      value = loads(signed);
    } catch {
      return null;
    }
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)
      || value instanceof CborDouble) {
    return null;
  }
  const wrapper = value as Dict;
  const ad = wrapper["advertisement"];
  const key = wrapper["founderPublicKey"];
  const signature = wrapper["signature"];
  if (typeof ad !== "object" || ad === null || Array.isArray(ad)
      || !(key instanceof Uint8Array) || key.length !== 32
      || !(signature instanceof Uint8Array)) {
    return null;
  }
  const advertisement = ad as Dict;
  const group = advertisement["group"];
  if (typeof group !== "string" || deriveId(key) !== advertisement["issuer"]) {
    return null;
  }
  const fields = foundingFieldsOf(advertisement);
  if (!Identity.verify(key, dumps(fields), signature)) {
    return null;
  }
  const derived = groupIdFromFoundingDocument(dumps(foundingDocument(fields, signature)));
  if (derived !== group || advertisement["id"] !== ASPACE_URI_PREFIX + group) {
    return null;
  }
  return group;
}

/** SpaceId.local, in TypeScript: the hash of 'local:' + name. */
export function spaceIdLocal(name: string): string {
  return deriveId(utf8("local:" + name));
}

/** An Ed25519 peer identity with the Java-compatible PeerID. */
// ------------------------------------------------------ agent certificates
// Subordinate agent keys (SPEC §4.2, §11a.3; TECH-SPEC §7.2; QA4 A4-7). A peer
// may give an agent its own Ed25519 key and certify it: the certificate binds
// the agent's name and key to the peer for a validity window, and records the
// agent writes are then signed by the agent key. A receiver still sees the
// peer key in EntryStateDto.issuerPublicKey; the certificate rides beside it.

const INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;
const DURATION = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)(?:\.(\d{1,9}))?S)?$/;

/**
 * java.time.Instant text ("2026-01-01T00:00:00Z", optional fraction) to epoch
 * milliseconds. Java prints UTC with a 'Z' and up to nine fraction digits;
 * anything else is not an Instant this wire carries.
 */
export function parseInstantMillis(iso: unknown): number {
  const match = typeof iso === "string" ? INSTANT.exec(iso) : null;
  if (!match) {
    throw new Error(`not an ISO-8601 instant: ${String(iso)}`);
  }
  const [, year, month, day, hour, minute, second, fraction] = match;
  let millis = Date.UTC(Number(year), Number(month) - 1, Number(day),
    Number(hour), Number(minute), Number(second));
  if (fraction) {
    millis += Number(fraction.padEnd(9, "0").slice(0, 3));
  }
  return millis;
}

/** java.time.Duration text as Java prints it ("PT24H", "PT1H30M", "PT0.5S"; never days) to milliseconds. */
export function parseDurationMillis(iso: unknown): number {
  const match = typeof iso === "string" && iso !== "PT" ? DURATION.exec(iso) : null;
  if (!match) {
    throw new Error(`not an ISO-8601 duration: ${String(iso)}`);
  }
  const [, hours, minutes, seconds, fraction] = match;
  let millis = (Number(hours ?? 0) * 3600 + Number(minutes ?? 0) * 60
    + Number(seconds ?? 0)) * 1000;
  if (fraction) {
    millis += Number(fraction.padEnd(9, "0").slice(0, 3));
  }
  return millis;
}

/** How far a signing time may lead the receiver's clock (HybridLogicalClock.MAX_DRIFT_MILLIS). */
export const MAX_DRIFT_MILLIS = 10 * 60 * 1000;

/**
 * An AgentCertificate in Java record order: agent, agentPublicKey, issued,
 * ttl, peerSignature, and (v0.1.13, SPEC §11a.2a) the agent's X25519
 * `encryptionPublicKey`, appended and omitted when absent, so a certificate
 * without it keeps its exact bytes. With no signature this is the body the
 * peer signs (AgentCertificate.unsigned).
 */
export function agentCertificate(agent: string, agentPublicKey: Uint8Array,
                                 issued: string, ttl: string,
                                 peerSignature: Uint8Array | null = null,
                                 encryptionPublicKey: Uint8Array | null = null): Dict {
  const certificate: Dict = { agent, agentPublicKey, issued, ttl, peerSignature };
  if (encryptionPublicKey !== null) {
    certificate["encryptionPublicKey"] = encryptionPublicKey;
  }
  return certificate;
}

/** The signed body of a (possibly decoded) certificate: canonical order, signature cleared. */
export function certificateBody(certificate: Dict): Dict {
  const encryption = certificate["encryptionPublicKey"];
  return agentCertificate(String(certificate["agent"]),
    certificate["agentPublicKey"] as Uint8Array, String(certificate["issued"]),
    String(certificate["ttl"]), null,
    encryption instanceof Uint8Array ? encryption : null);
}

/**
 * AgentCertificate.covers (SPEC §4.2, v0.1.13): `signingMillis` lies in
 * `[issued, issued + ttl)`, the issue instant at millisecond precision.
 */
export function certificateCovers(certificate: Dict, signingMillis: number): boolean {
  const issued = parseInstantMillis(certificate["issued"]);
  return issued <= signingMillis
    && signingMillis < issued + parseDurationMillis(certificate["ttl"]);
}

/**
 * AgentCertificates.verifyAt (SPEC §4.2, v0.1.13): judged at the signing time
 * of what it certifies (a record's issue stamp, a claim's stamp, a state's
 * signedAt), not at receipt. The window covers the signing time, which may
 * lead the receiver's clock by at most the HLC drift ceiling, and every check
 * of `verifyAgentCertificate` holds at that time.
 */
export function verifyAgentCertificateAt(certificate: unknown, peerPublicRaw: Uint8Array,
                                         expectedAgent: string, signingMillis: number,
                                         receiverNowMillis: number): boolean {
  try {
    if (typeof certificate !== "object" || certificate === null || Array.isArray(certificate)
        || !certificateCovers(certificate as Dict, signingMillis)
        || signingMillis > receiverNowMillis + MAX_DRIFT_MILLIS) {
      return false;
    }
  } catch {
    return false;
  }
  return verifyAgentCertificate(certificate, peerPublicRaw, expectedAgent, signingMillis);
}

/** Epoch milliseconds as java.time.Instant prints them (whole seconds bare, else 3 fraction digits). */
export function instantIso(millis: number): string {
  const text = new Date(millis).toISOString(); // always .sssZ
  return millis % 1000 === 0 ? text.replace(/\.000Z$/, "Z") : text;
}

/** AgentCertificates.sign: the peer signs the body. Only the agent's own peer may certify it. */
export function signAgentCertificate(body: Dict, peer: Identity): Dict {
  if (!String(body["agent"]).startsWith(peer.peerId + "/")) {
    throw new Error(`certificate for ${String(body["agent"])} cannot be issued by ${peer.peerId}`);
  }
  const unsigned = certificateBody(body);
  return { ...unsigned, peerSignature: peer.sign(dumps(unsigned)) };
}

/**
 * AgentCertificates.verify: the certificate carries a signature and a 32-byte
 * agent key, names exactly `expectedAgent`, that agent's peer is the peer
 * `peerPublicRaw` hashes to, it is unexpired at `nowMillis` (expiry is
 * issued + ttl, inclusive), and the peer's signature verifies over the
 * canonical body.
 */
export function verifyAgentCertificate(certificate: unknown, peerPublicRaw: Uint8Array,
                                       expectedAgent: string, nowMillis: number): boolean {
  try {
    if (typeof certificate !== "object" || certificate === null
        || Array.isArray(certificate)) {
      return false;
    }
    const cert = certificate as Dict;
    const signature = cert["peerSignature"];
    const agentKey = cert["agentPublicKey"];
    const agent = cert["agent"];
    const encryption = cert["encryptionPublicKey"];
    if (!(signature instanceof Uint8Array) || !(agentKey instanceof Uint8Array)
        || agentKey.length !== 32
        || (encryption !== undefined && encryption !== null
          && (!(encryption instanceof Uint8Array) || encryption.length !== 32))
        || !(peerPublicRaw instanceof Uint8Array)
        || peerPublicRaw.length !== 32 || typeof agent !== "string"
        || agent !== expectedAgent
        || !agent.startsWith(deriveId(peerPublicRaw) + "/")) {
      return false;
    }
    const expires = parseInstantMillis(cert["issued"]) + parseDurationMillis(cert["ttl"]);
    if (nowMillis >= expires) {
      return false;
    }
    return Identity.verify(peerPublicRaw, dumps(certificateBody(cert)), signature);
  } catch {
    return false;
  }
}

/**
 * A subordinate agent identity: the agent's own Ed25519 key plus the
 * peer-signed certificate that vouches for it. Records the agent writes are
 * signed with `sign`; the certificate travels in the state DTO.
 */
export class AgentIdentity {
  static readonly RETAINED = 256;
  readonly publicRaw: Uint8Array;
  private current: Dict;
  private readonly issued: Dict[];

  /**
   * With `peer`, `ttl`, and `clock` this is a renewing identity
   * (`Identity.renewingSubordinate`, SPEC §4.2, v0.1.13): it re-issues its
   * certificate for the same key at half-life, lazily on every sign and
   * lookup, and keeps up to RETAINED earlier certificates.
   */
  constructor(readonly agentId: string, private readonly key: Identity,
              certificate: Dict, private readonly peer: Identity | null = null,
              private readonly ttl: string | null = null,
              private readonly clock: () => number = Date.now,
              private readonly encryptionPublicKey: Uint8Array | null = null) {
    this.publicRaw = key.publicRaw;
    this.current = certificate;
    this.issued = [certificate];
  }

  /** The newest certificate. */
  get certificate(): Dict {
    return this.current;
  }

  /** Re-issues the certificate when half its lifetime has passed; returns whether it did. */
  renewIfDue(nowMillis: number = this.clock()): boolean {
    if (this.peer === null || this.ttl === null) {
      return false;
    }
    const issued = parseInstantMillis(this.current["issued"]);
    const ttl = parseDurationMillis(this.current["ttl"]);
    if (nowMillis < issued + Math.floor(ttl / 2)) {
      return false;
    }
    const body = agentCertificate(this.agentId, this.publicRaw, instantIso(nowMillis),
      this.ttl, null, this.encryptionPublicKey);
    this.current = signAgentCertificate(body, this.peer);
    this.issued.push(this.current);
    if (this.issued.length > AgentIdentity.RETAINED) {
      this.issued.splice(0, this.issued.length - AgentIdentity.RETAINED);
    }
    return true;
  }

  /** The newest held certificate covering `signingMillis`, or null. */
  certificateCovering(signingMillis: number): Dict | null {
    this.renewIfDue();
    for (let i = this.issued.length - 1; i >= 0; i--) {
      try {
        if (certificateCovers(this.issued[i], signingMillis)) {
          return this.issued[i];
        }
      } catch {
        // an unparseable certificate covers nothing
      }
    }
    return null;
  }

  sign(message: Uint8Array): Uint8Array {
    this.renewIfDue();
    return this.key.sign(message);
  }
}

/**
 * The 32-byte RFC 8032 seed inside an Ed25519 PKCS#8 PrivateKeyInfo, version 1
 * (the 48-byte form Java's keystore and Node write) or version 2 with the
 * public key appended (RFC 5958 OneAsymmetricKey). Anything else is refused.
 */
export function seedFromPkcs8(pkcs8: Uint8Array): Uint8Array {
  if (pkcs8.length >= 48 && equals(pkcs8.subarray(0, 16), PKCS8_PREFIX)) {
    return pkcs8.slice(16, 48);
  }
  // v2: 30 len 02 01 01 30 05 06 03 2b 65 70 04 22 04 20 <seed> [a1 ... public key]
  const algorithmAt = 5;
  if (pkcs8.length >= 48 && pkcs8[0] === 0x30 && pkcs8[2] === 0x02 && pkcs8[3] === 0x01
      && (pkcs8[4] === 0x00 || pkcs8[4] === 0x01)
      && equals(pkcs8.subarray(algorithmAt, algorithmAt + 7), ED25519_ALGORITHM)
      && pkcs8[12] === 0x04 && pkcs8[13] === 0x22 && pkcs8[14] === 0x04 && pkcs8[15] === 0x20) {
    return pkcs8.slice(16, 48);
  }
  throw new Error("not an Ed25519 PKCS#8 private key");
}

export class Identity {
  readonly publicRaw: Uint8Array;
  readonly peerId: string;

  private constructor(private readonly seed: Uint8Array) {
    this.publicRaw = cryptoPort().ed25519PublicKey(seed);
    this.peerId = deriveId(this.publicRaw);
  }

  static generate(): Identity {
    return new Identity(cryptoPort().randomBytes(32));
  }

  static fromPkcs8(pkcs8: Uint8Array): Identity {
    return new Identity(seedFromPkcs8(pkcs8));
  }

  /**
   * Ed25519.fromSeed: the identity whose private key is the RFC 8032 32-byte
   * seed (an HKDF output, for instance); the public key follows from it.
   */
  static fromSeed(seed: Uint8Array): Identity {
    if (seed.length !== 32) {
      throw new Error(`an Ed25519 seed is 32 bytes, not ${seed.length}`);
    }
    return new Identity(new Uint8Array(seed));
  }

  sign(message: Uint8Array): Uint8Array {
    return cryptoPort().ed25519Sign(this.seed, message);
  }

  /** The AgentID string form: '<peerId>/<localName>'. */
  agent(localName: string): string {
    return `${this.peerId}/${localName}`;
  }

  /**
   * PeerIdentity.subordinate: certifies a fresh (or given) agent key for
   * '<peerId>/<localName>' from `issued` for `ttl` (java.time text forms).
   */
  subordinate(localName: string, issued: string, ttl = "PT1H",
              key: Identity = Identity.generate()): AgentIdentity {
    const body = agentCertificate(this.agent(localName), key.publicRaw, issued, ttl);
    return new AgentIdentity(this.agent(localName), key, signAgentCertificate(body, this));
  }

  /**
   * PeerIdentity.renewingSubordinate (SPEC §4.2, v0.1.13): an agent key whose
   * certificate this peer re-issues at half-life; `encryptionPublicKey`
   * certifies an X25519 key too (SPEC §11a.2a).
   */
  renewingSubordinate(localName: string, ttl = "PT24H", key: Identity = Identity.generate(),
                      clock: () => number = Date.now,
                      encryptionPublicKey: Uint8Array | null = null): AgentIdentity {
    const body = agentCertificate(this.agent(localName), key.publicRaw, instantIso(clock()),
      ttl, null, encryptionPublicKey);
    return new AgentIdentity(this.agent(localName), key, signAgentCertificate(body, this),
      this, ttl, clock, encryptionPublicKey);
  }

  /** The private key as PKCS#8 DER (version 1, 48 bytes), the form Java's keystore writes. */
  pkcs8(): Uint8Array {
    return concat(PKCS8_PREFIX, this.seed);
  }

  /** The public key as X.509 SubjectPublicKeyInfo DER. */
  spki(): Uint8Array {
    return concat(SPKI_PREFIX, this.publicRaw);
  }

  static verify(publicRaw: Uint8Array, message: Uint8Array,
                signature: Uint8Array): boolean {
    if (!(publicRaw instanceof Uint8Array) || !(message instanceof Uint8Array)
        || !(signature instanceof Uint8Array)) {
      return false;
    }
    return cryptoPort().ed25519Verify(publicRaw, message, signature);
  }
}
