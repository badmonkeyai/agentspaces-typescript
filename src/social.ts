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
 * The invite key and the delegated credential (discovery SRAD §3.8,
 * appendix F), in TypeScript: the group secret and its three HKDF-SHA256
 * derivations (invite signing key, content key, lookup code), Crockford
 * base32, the two renderings of the key, and the CBOR records of
 * `JoinCredentials` (Delegation, DelegatedCredential, CredentialView,
 * DelegationView) encoded by the same encoder the advertisements use, so a
 * credential this client issues is byte for byte the one Java issues.
 * Proved against `agentspaces-bootstrap-social/golden/social-golden.json`.
 */

import { equals, fromBase64, toBase64, utf8 } from "./bytes.js";
import { cryptoPort } from "./crypto.js";
import { CborDouble, CborValue, dumps, loads } from "./cbor.js";
import { Identity, deriveId } from "./identity.js";

type Dict = { [key: string]: CborValue };

// ------------------------------------------------------- Crockford base32

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CROCKFORD_DECODE = new Map<string, number>();
for (let i = 0; i < CROCKFORD.length; i++) {
  CROCKFORD_DECODE.set(CROCKFORD[i], i);
}
CROCKFORD_DECODE.set("O", 0);
CROCKFORD_DECODE.set("I", 1);
CROCKFORD_DECODE.set("L", 1);

/** Crockford base32 (no I, L, O, U), no padding, as Base32Crockford.encode writes it. */
export function base32CrockfordEncode(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const b of bytes) {
    buffer = ((buffer << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(buffer >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += CROCKFORD[(buffer << (5 - bits)) & 31];
  }
  return out;
}

/**
 * Decodes Crockford base32: case-insensitive, dashes and spaces ignored,
 * O read as 0 and I/L as 1 (a key read aloud survives). Throws on any other
 * character outside the alphabet.
 */
export function base32CrockfordDecode(text: string): Uint8Array {
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const c of text.toUpperCase()) {
    if (c === "-" || c === " ") {
      continue;
    }
    const value = CROCKFORD_DECODE.get(c);
    if (value === undefined) {
      throw new Error(`not a Crockford base32 character: '${c}'`);
    }
    buffer = ((buffer << 5) | value) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

// ------------------------------------------------------------ group secret

/** The HKDF salt, also the key format's version tag. */
export const SALT = "aspace-inv1";
/** The secret's length in bytes. */
export const SECRET_LENGTH = 16;
/** The lookup code's length in bytes (80 bits, 16 base32 characters). */
export const CODE_LENGTH = 10;

/**
 * GroupSecret: 128 bits the creator draws, from which every holder derives
 * by HKDF-SHA256 (salt {@link SALT}, distinct info strings) the invite
 * signing key, the content key (epoch 0), and the lookup code. The
 * derivation is the protocol: bit-identical in Java, Python, and here.
 */
export class GroupSecret {
  private constructor(private readonly secret: Uint8Array) {}

  /** A fresh secret. */
  static random(): GroupSecret {
    return new GroupSecret(cryptoPort().randomBytes(SECRET_LENGTH));
  }

  /** A secret from its 16 bytes. */
  static of(bytes: Uint8Array): GroupSecret {
    if (bytes.length !== SECRET_LENGTH) {
      throw new Error(`a group secret is ${SECRET_LENGTH} bytes, not ${bytes.length}`);
    }
    return new GroupSecret(Uint8Array.from(bytes));
  }

  /** The bytes, a copy. */
  bytes(): Uint8Array {
    return Uint8Array.from(this.secret);
  }

  /** The invite signing key's 32-byte Ed25519 seed (RFC 8032 private key). */
  inviteSeed(): Uint8Array {
    return this.derive("invite-sign", 32);
  }

  /** The invite signing key pair, as an identity that signs. */
  inviteIdentity(): Identity {
    return Identity.fromSeed(this.inviteSeed());
  }

  /** The raw public half of the invite signing key. */
  invitePublicKey(): Uint8Array {
    return this.inviteIdentity().publicRaw;
  }

  /** The group's content key, epoch 0, 32 bytes. */
  contentKey(): Uint8Array {
    return this.derive("content-key", 32);
  }

  /** The content key as the starter's `content-key` property takes it. */
  contentKeyBase64(): string {
    return toBase64(this.contentKey());
  }

  /** The lookup code: 80 bits of a one-way derivation, 16 Crockford base32 characters. */
  code(): string {
    return base32CrockfordEncode(this.derive("lookup", CODE_LENGTH));
  }

  equals(other: GroupSecret): boolean {
    return equals(this.secret, other.secret);
  }

  toString(): string {
    return `GroupSecret[${this.code()}]`;
  }

  private derive(info: string, length: number): Uint8Array {
    return cryptoPort().hkdfSha256(this.secret, utf8(SALT), utf8(info), length);
  }
}

// --------------------------------------------------------------- invite key

/** The compact prefix. */
export const INVITE_PREFIX = "aspace-inv1-";
/** The built-in default social beacon, omitted from compact keys. */
export const DEFAULT_HOST = "s.agentspaces.dev";

/**
 * The invite key (SRAD appendix F), one string in two renderings. Compact,
 * for a text message: `aspace-inv1-<code>-<secret>[-<delegation>][@host[:port]]`,
 * Crockford base32 segments, the host present only when the beacon is not
 * the default. URL, for a phone: `https://<host>/j/<code>#<secret>[.<delegation>]`;
 * the server receives the path only. The delegation (public data, base64 of
 * its CBOR as `delegation` here) may travel in the key or be fetched from
 * the beacon document's `invite` field.
 */
export class InviteKey {
  readonly host: string;
  readonly code: string;

  constructor(host: string, code: string, readonly secret: GroupSecret,
              readonly delegation: string | null = null) {
    this.host = host.trim().toLowerCase();
    this.code = code.trim().toUpperCase();
  }

  /** A key for a secret at a host (the default beacon when none is given). */
  static of(secret: GroupSecret, delegation: string | null = null, host = DEFAULT_HOST): InviteKey {
    return new InviteKey(host, secret.code(), secret, delegation);
  }

  /** The compact rendering. */
  compact(): string {
    let out = INVITE_PREFIX + this.code + "-" + base32CrockfordEncode(this.secret.bytes());
    if (this.delegation !== null) {
      out += "-" + base32CrockfordEncode(fromBase64(this.delegation));
    }
    if (this.host !== DEFAULT_HOST) {
      out += "@" + this.host;
    }
    return out;
  }

  /** The URL rendering. */
  url(): string {
    let out = `https://${this.host}/j/${this.code}#${base32CrockfordEncode(this.secret.bytes())}`;
    if (this.delegation !== null) {
      out += "." + base32CrockfordEncode(fromBase64(this.delegation));
    }
    return out;
  }

  /** The beacon's base URL. */
  beaconUrl(scheme: "https" | "http" = "https"): string {
    return `${scheme}://${this.host}`;
  }

  /** The document URL at the beacon (`/j/<code>`), what the server receives. */
  documentUrl(scheme: "https" | "http" = "https"): string {
    return `${scheme}://${this.host}/j/${this.code}`;
  }

  /** The same key with a delegation. */
  withDelegation(delegation: string | null): InviteKey {
    return new InviteKey(this.host, this.code, this.secret, delegation);
  }

  /** The same key at another host (a self-hosted beacon). */
  withHost(host: string): InviteKey {
    return new InviteKey(host, this.code, this.secret, this.delegation);
  }

  /**
   * Parses either rendering; spaces, line wraps, and case are forgiven. The
   * code must be the one the secret derives, else the text is not a key.
   */
  static parse(text: string): InviteKey {
    let t = text.trim();
    const lower = t.toLowerCase();
    if (lower.startsWith("https://") || lower.startsWith("http://")) {
      return InviteKey.parseUrl(t);
    }
    t = t.replace(/[ \n\r\t]/g, ""); // a key pasted with spaces or a wrap
    if (!t.toLowerCase().startsWith(INVITE_PREFIX)) {
      throw new Error(`not an invite key: it does not start with ${INVITE_PREFIX}`);
    }
    let rest = t.substring(INVITE_PREFIX.length);
    let host = DEFAULT_HOST;
    const at = rest.lastIndexOf("@");
    if (at >= 0) {
      host = rest.substring(at + 1).trim();
      rest = rest.substring(0, at);
    }
    const segments = rest.split("-");
    if (segments.length < 2 || segments.length > 3) {
      throw new Error("not an invite key: expected code-secret[-delegation]");
    }
    const secret = secretOf(segments[1]);
    const code = segments[0].toUpperCase();
    if (code !== secret.code()) {
      throw new Error("not an invite key: the code does not belong to the secret");
    }
    const delegation = segments.length === 3
      ? toBase64(base32CrockfordDecode(segments[2])) : null;
    return new InviteKey(host, code, secret, delegation);
  }

  private static parseUrl(text: string): InviteKey {
    const url = new URL(text.replace(/ /g, ""));
    const path = url.pathname;
    const j = path.indexOf("/j/");
    const fragment = url.hash.startsWith("#") ? url.hash.substring(1) : url.hash;
    if (j < 0 || fragment.trim() === "") {
      throw new Error("not an invite link: expected https://host/j/<code>#<secret>");
    }
    let code = path.substring(j + 3);
    const slash = code.indexOf("/");
    if (slash >= 0) {
      code = code.substring(0, slash);
    }
    const dot = fragment.indexOf(".");
    const secret = secretOf(dot < 0 ? fragment : fragment.substring(0, dot));
    if (code.toUpperCase() !== secret.code()) {
      throw new Error("not an invite link: the code does not belong to the secret");
    }
    const delegation = dot < 0 ? null
      : toBase64(base32CrockfordDecode(fragment.substring(dot + 1)));
    const host = url.hostname + (url.port !== "" && url.port !== "443" ? ":" + url.port : "");
    return new InviteKey(host, code, secret, delegation);
  }

  toString(): string {
    return `${INVITE_PREFIX}${this.code}-…${this.host === DEFAULT_HOST ? "" : "@" + this.host}`;
  }
}

function secretOf(segment: string): GroupSecret {
  const bytes = base32CrockfordDecode(segment);
  if (bytes.length !== SECRET_LENGTH) {
    throw new Error(`not an invite key: the secret is ${bytes.length} bytes`);
  }
  return GroupSecret.of(bytes);
}

// -------------------------------------------- delegations and credentials

/** The resource-hint key a candidate carries its join credential under (JoinCredentials.HINT_KEY). */
export const JOIN_HINT = "aspace:join";
/** The prefix of a delegated credential string. */
export const DELEGATED_PREFIX = "d1:";
/** The clock skew a delegation's expiry is judged with (JoinCredentials.EXPIRY_SKEW). */
export const EXPIRY_SKEW_MILLIS = 10 * 60 * 1000;

/** JoinCredentials.Delegation, decoded: the founder's key, the delegated key, and the founder's signature. */
export interface Delegation {
  founderKey: Uint8Array;
  inviteKey: Uint8Array;
  group: string;
  notAfterMillis: number;
  label: string;
  signature: Uint8Array;
}

/** JoinCredentials.DelegationInfo: what a delegation says, for a reader. */
export interface DelegationInfo {
  founder: string;
  inviteKey: Uint8Array;
  group: string;
  notAfterMillis: number;
  label: string;
}

/** The Delegation record in Java field order: what `delegationHash` hashes. */
function delegationRecord(d: Delegation): Dict {
  return { founderKey: d.founderKey, inviteKey: d.inviteKey, group: d.group,
    notAfterMillis: d.notAfterMillis, label: d.label, signature: d.signature };
}

/** JoinCredentials.DelegationView: the bytes a founder signs when delegating. */
export function delegationView(inviteKey: Uint8Array, group: string, notAfterMillis: number,
                               label: string): Uint8Array {
  return dumps({ inviteKey, group, notAfterMillis, label });
}

/** JoinCredentials.CredentialView: the bytes an issuer signs, the candidate bound to the group. */
export function credentialView(candidate: string, group: string): Uint8Array {
  return dumps({ candidate, group });
}

function isDict(value: CborValue): value is Dict {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && !(value instanceof Uint8Array) && !(value instanceof CborDouble);
}

function delegationOf(value: CborValue): Delegation | null {
  if (!isDict(value)) {
    return null;
  }
  const founderKey = value["founderKey"];
  const inviteKey = value["inviteKey"];
  const group = value["group"];
  const notAfter = value["notAfterMillis"];
  const label = value["label"];
  const signature = value["signature"];
  if (!(founderKey instanceof Uint8Array) || !(inviteKey instanceof Uint8Array)
      || typeof group !== "string" || !(signature instanceof Uint8Array)
      || (typeof notAfter !== "number" && typeof notAfter !== "bigint")) {
    return null;
  }
  return { founderKey, inviteKey, group, notAfterMillis: Number(notAfter),
    label: typeof label === "string" ? label : "", signature };
}

/** Decodes a delegation string (base64 CBOR), or returns null when it does not parse. */
export function parseDelegation(delegation: string): Delegation | null {
  try {
    return delegationOf(loads(fromBase64(delegation.trim())));
  } catch {
    return null;
  }
}

/** Decodes a delegated credential string into its delegation and the invite key's signature. */
export function parseDelegatedCredential(credential: string): { delegation: Delegation; signature: Uint8Array } | null {
  try {
    const value = loads(fromBase64(stripPrefix(credential.trim())));
    if (!isDict(value)) {
      return null;
    }
    const delegation = delegationOf(value["delegation"]);
    const signature = value["signature"];
    if (delegation === null || !(signature instanceof Uint8Array)) {
      return null;
    }
    return { delegation, signature };
  } catch {
    return null;
  }
}

/** JoinCredentials.describe: what a delegation says. */
export function describeDelegation(delegation: string): DelegationInfo | null {
  const d = parseDelegation(delegation);
  if (d === null) {
    return null;
  }
  return { founder: deriveId(d.founderKey), inviteKey: d.inviteKey, group: d.group,
    notAfterMillis: d.notAfterMillis, label: d.label };
}

/** SocialGroups.groupOf: the GroupId a delegation names. */
export function delegationGroup(delegation: string): string {
  const d = parseDelegation(delegation);
  if (d === null) {
    throw new Error("not a delegation");
  }
  return d.group;
}

/**
 * JoinCredentials.delegate: the founder signs, once, the invite key bound to
 * the group with an expiry and a label. Public data; what `issueDelegated`
 * takes. Here so a TypeScript founder can create a group for friends.
 */
export function delegate(founder: Identity, group: string, inviteKey: Uint8Array,
                         notAfterMillis: number, label: string): string {
  if (inviteKey.length !== 32) {
    throw new Error("an invite key is a raw 32-byte Ed25519 public key");
  }
  const signature = founder.sign(delegationView(inviteKey, group, notAfterMillis, label));
  return toBase64(dumps(delegationRecord({ founderKey: founder.publicRaw, inviteKey, group,
    notAfterMillis, label, signature })));
}

/**
 * JoinCredentials.issueDelegated: the invite signing key's signature over
 * `(candidate, group)` under the delegation, as the `d1:`-prefixed string a
 * candidate presents under {@link JOIN_HINT}. Ed25519 is deterministic, so
 * the same inputs give Java's exact bytes.
 */
export function issueDelegated(delegation: string, inviteSeed: Uint8Array | Identity,
                               candidate: string): string {
  const parsed = parseDelegation(delegation);
  if (parsed === null) {
    throw new Error("not a delegation string");
  }
  const signer = inviteSeed instanceof Identity ? inviteSeed : Identity.fromSeed(inviteSeed);
  const signature = signer.sign(credentialView(candidate, parsed.group));
  return DELEGATED_PREFIX + toBase64(dumps({ delegation: delegationRecord(parsed), signature }));
}

/** JoinCredentials.hash: the SHA-256 of a credential's decoded bytes (what a JOIN_CREDENTIAL revocation names). */
export function credentialHash(credential: string): Uint8Array {
  return sha256(fromBase64(stripPrefix(credential.trim())));
}

/**
 * JoinCredentials.delegationHash: the SHA-256 of a delegation's bytes, from
 * a delegation string or a delegated credential string; revoking it refuses
 * every credential issued under it. Null when the string does not parse.
 */
export function delegationHash(delegationOrCredential: string): Uint8Array | null {
  const trimmed = delegationOrCredential.trim();
  const delegation = trimmed.startsWith(DELEGATED_PREFIX)
    ? parseDelegatedCredential(trimmed)?.delegation ?? null : parseDelegation(trimmed);
  return delegation === null ? null : sha256(dumps(delegationRecord(delegation)));
}

/**
 * JoinCredentials.verify for the delegated shape, judged at `nowMillis`:
 * the founder key hashes to the group's issuer, the delegation names the
 * group, is unexpired (ten minutes of skew), and its signature verifies;
 * then the candidate signature verifies under the delegated key. Revocation
 * is the registry's business, not this function's.
 */
export function delegatedCredentialAdmits(credential: string, candidate: string,
                                          groupAdIssuer: string, groupId: string,
                                          nowMillis: number = Date.now()): boolean {
  const parsed = parseDelegatedCredential(credential);
  if (parsed === null || !credential.trim().startsWith(DELEGATED_PREFIX)) {
    return false;
  }
  if (!delegationVerifies(parsed.delegation, groupAdIssuer, groupId, nowMillis)) {
    return false;
  }
  return Identity.verify(parsed.delegation.inviteKey, credentialView(candidate, groupId),
    parsed.signature);
}

/** Whether a delegation admits anyone at all in a group, judged at `nowMillis`. */
export function delegationVerifies(delegation: Delegation, groupAdIssuer: string,
                                   groupId: string, nowMillis: number = Date.now()): boolean {
  if (delegation.founderKey.length !== 32 || delegation.inviteKey.length !== 32) {
    return false;
  }
  if (deriveId(delegation.founderKey) !== groupAdIssuer || delegation.group !== groupId) {
    return false;
  }
  if (nowMillis - EXPIRY_SKEW_MILLIS > delegation.notAfterMillis) {
    return false;
  }
  return Identity.verify(delegation.founderKey,
    delegationView(delegation.inviteKey, delegation.group, delegation.notAfterMillis,
      delegation.label), delegation.signature);
}

/** SocialGroups.hintsFor: the `aspace:join` hint a holder of a key presents for its own peer. */
export function hintsFor(key: InviteKey, delegation: string, self: string): { [key: string]: string } {
  return { [JOIN_HINT]: issueDelegated(delegation, key.secret.inviteSeed(), self) };
}

function stripPrefix(encoded: string): string {
  return encoded.startsWith(DELEGATED_PREFIX) ? encoded.substring(DELEGATED_PREFIX.length) : encoded;
}

function sha256(bytes: Uint8Array): Uint8Array {
  return cryptoPort().sha256(bytes);
}
