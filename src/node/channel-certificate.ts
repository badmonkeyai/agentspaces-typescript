/*
 * Copyright 2026 Bad Monkey, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Channel certificates (SPEC §5.6): a fresh EC P-256 key for TLS in a
 * self-signed X.509 certificate whose signature is the peer's Ed25519 identity
 * signature over the TBSCertificate (id-Ed25519, RFC 8410), with the raw
 * identity key in the subject CN as multibase base58btc. The TLS handshake
 * proves possession of the P-256 key; the endorsement binds the channel to
 * PeerID = multibase(sha-256(identity key)). No CA participates. Mirrors Java
 * `ChannelCertificate`; Node has no X.509 builder, so the certificate is
 * assembled here in DER and signed by the identity.
 */

import { X509Certificate, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { concat } from "../bytes.js";
import { Identity, deriveId, multibase } from "../identity.js";

/** id-Ed25519 (RFC 8410). */
export const ED25519_SIG_OID = "1.3.101.112";
const CN_OID = "2.5.4.3";
/** The SubjectPublicKeyInfo prefix of a raw Ed25519 key (RFC 8410 §4). */
const ED25519_SPKI_PREFIX = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** The inverse of `base58btc` in identity.ts; throws on a foreign character. */
export function base58Decode(text: string): Uint8Array {
  let number = 0n;
  for (const char of text) {
    const digit = ALPHABET.indexOf(char);
    if (digit < 0) {
      throw new Error(`not base58: ${JSON.stringify(char)}`);
    }
    number = number * 58n + BigInt(digit);
  }
  let zeros = 0;
  while (zeros < text.length && text[zeros] === "1") {
    zeros++;
  }
  const body: number[] = [];
  while (number > 0n) {
    body.unshift(Number(number & 0xffn));
    number >>= 8n;
  }
  return new Uint8Array([...new Array<number>(zeros).fill(0), ...body]);
}

// ------------------------------------------------------------------ DER

function derLength(length: number): Uint8Array {
  if (length < 0x80) {
    return new Uint8Array([length]);
  }
  const bytes: number[] = [];
  for (let n = length; n > 0; n >>= 8) {
    bytes.unshift(n & 0xff);
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function der(tag: number, content: Uint8Array): Uint8Array {
  return concat(new Uint8Array([tag]), derLength(content.length), content);
}

const sequence = (...parts: Uint8Array[]): Uint8Array => der(0x30, concat(...parts));
const set = (...parts: Uint8Array[]): Uint8Array => der(0x31, concat(...parts));

/** A positive INTEGER from big-endian magnitude bytes. */
function integer(magnitude: Uint8Array): Uint8Array {
  let start = 0;
  while (start < magnitude.length - 1 && magnitude[start] === 0) {
    start++;
  }
  const trimmed = magnitude.subarray(start);
  return der(0x02, trimmed[0] >= 0x80 ? concat(new Uint8Array([0]), trimmed) : trimmed);
}

function oid(dotted: string): Uint8Array {
  const arcs = dotted.split(".").map(Number);
  const bytes: number[] = [arcs[0] * 40 + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const chunk: number[] = [arc & 0x7f];
    for (let n = arc >> 7; n > 0; n >>= 7) {
      chunk.unshift((n & 0x7f) | 0x80);
    }
    bytes.push(...chunk);
  }
  return der(0x06, new Uint8Array(bytes));
}

const utf8 = (text: string): Uint8Array => der(0x0c, new TextEncoder().encode(text));

/** UTCTime through 2049, GeneralizedTime after (RFC 5280 §4.1.2.5). */
function time(date: Date): Uint8Array {
  const pad = (n: number): string => String(n).padStart(2, "0");
  const body = `${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}`
    + `${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  const year = date.getUTCFullYear();
  return year < 2050
    ? der(0x17, new TextEncoder().encode(`${pad(year % 100)}${body}`))
    : der(0x18, new TextEncoder().encode(`${year}${body}`));
}

const bitString = (bytes: Uint8Array): Uint8Array => der(0x03, concat(new Uint8Array([0]), bytes));

/** One DER element at `offset`: its tag, where its content starts, and where it ends. */
function element(bytes: Uint8Array, offset: number): { tag: number; start: number; end: number } {
  if (offset + 2 > bytes.length) {
    throw new Error("truncated DER");
  }
  const tag = bytes[offset];
  let length = bytes[offset + 1];
  let start = offset + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || start + count > bytes.length) {
      throw new Error("bad DER length");
    }
    length = 0;
    for (let i = 0; i < count; i++) {
      length = (length << 8) | bytes[start + i];
    }
    start += count;
  }
  if (start + length > bytes.length) {
    throw new Error("truncated DER");
  }
  return { tag, start, end: start + length };
}

/** The dotted OID of a certificate's outer signatureAlgorithm, or null when the shape is wrong. */
export function signatureAlgorithmOf(certificate: Uint8Array): string | null {
  try {
    const outer = element(certificate, 0);
    const tbs = element(certificate, outer.start);
    const algorithm = element(certificate, tbs.end);
    const identifier = element(certificate, algorithm.start);
    if (outer.tag !== 0x30 || algorithm.tag !== 0x30 || identifier.tag !== 0x06) {
      return null;
    }
    const content = certificate.subarray(identifier.start, identifier.end);
    const arcs = [Math.floor(content[0] / 40), content[0] % 40];
    let value = 0;
    for (const byte of content.subarray(1)) {
      value = (value << 7) | (byte & 0x7f);
      if ((byte & 0x80) === 0) {
        arcs.push(value);
        value = 0;
      }
    }
    return arcs.join(".");
  } catch {
    return null;
  }
}

// ------------------------------------------------------ the certificate

/** A channel certificate: the P-256 key in PEM (PKCS#8), the certificate in PEM and DER. */
export type ChannelCertificate = { keyPem: string; certificatePem: string; certificateDer: Uint8Array };

function pem(label: string, der: Uint8Array): string {
  const base64 = Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n").trimEnd();
  return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----\n`;
}

/**
 * `ChannelCertificate.generate`: a fresh P-256 key, a self-signed certificate
 * naming `identityKey` (raw Ed25519) in the CN, valid from an hour ago for a
 * year, signed by `signer` with id-Ed25519 over the TBSCertificate. Tests sign
 * with a stranger to prove the attestation refuses the result.
 */
export function buildChannelCertificate(identityKey: Uint8Array, signer: Identity): ChannelCertificate {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = new Uint8Array(pair.publicKey.export({ type: "spki", format: "der" }));
  const name = sequence(set(sequence(oid(CN_OID), utf8(multibase(identityKey)))));
  const notBefore = new Date(Date.now() - 3_600_000);
  const notAfter = new Date(notBefore.getTime() + 365 * 86_400_000);
  const algorithm = sequence(oid(ED25519_SIG_OID));
  const tbs = sequence(
    der(0xa0, integer(new Uint8Array([2]))), // version v3
    integer(new Uint8Array(randomBytes(9))),
    algorithm,
    name,
    sequence(time(notBefore), time(notAfter)),
    name,
    spki,
  );
  const certificateDer = sequence(tbs, algorithm, bitString(signer.sign(tbs)));
  return {
    keyPem: pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    certificatePem: pem("CERTIFICATE", certificateDer),
    certificateDer,
  };
}

/** The channel certificate of `identity`, endorsed by itself. */
export function generateChannelCertificate(identity: Identity): ChannelCertificate {
  return buildChannelCertificate(identity.publicRaw, identity);
}

/**
 * `ChannelCertificate.attest`: the PeerID a presented certificate (DER)
 * attests, or null: the signature algorithm is id-Ed25519, the subject is one
 * CN that decodes to a 32-byte key, and that key's signature over the
 * TBSCertificate verifies.
 */
export function attestChannelCertificate(certificate: Uint8Array): string | null {
  try {
    if (signatureAlgorithmOf(certificate) !== ED25519_SIG_OID) {
      return null;
    }
    const parsed = new X509Certificate(certificate);
    const subject = parsed.subject;
    if (!subject.startsWith("CN=") || subject.includes("\n") || subject.length > 3 + 64 || subject[3] !== "z") {
      return null;
    }
    const raw = base58Decode(subject.substring(4));
    if (raw.length !== 32) {
      return null;
    }
    const key = createPublicKey({ key: Buffer.from(concat(ED25519_SPKI_PREFIX, raw)), format: "der", type: "spki" });
    return parsed.verify(key) ? deriveId(raw) : null;
  } catch {
    return null;
  }
}
