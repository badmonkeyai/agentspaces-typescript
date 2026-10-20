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
 * The crypto port of the portable core (srad/agentspaces-js.md §3.1,
 * JS-P-02). Every signature, hash, derivation, and key agreement in the
 * client goes through the installed {@link CryptoPort}. The default port is
 * the audited noble libraries, synchronous and identical on every runtime;
 * a Node service may install a `node:crypto` port from
 * `@agentspaces/client/node` for speed, and both produce the golden vectors
 * byte for byte.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { randomBytes } from "./bytes.js";

export interface CryptoPort {
  /** The name shown in diagnostics ("noble", "node"). */
  readonly name: string;
  /** The Ed25519 public key (32 bytes) of a 32-byte RFC 8032 seed. */
  ed25519PublicKey(seed: Uint8Array): Uint8Array;
  /** An Ed25519 signature (64 bytes) by the seed's key. */
  ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array;
  /** Strict RFC 8032 verification; false on any malformed input. */
  ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
  sha256(data: Uint8Array): Uint8Array;
  sha512(data: Uint8Array): Uint8Array;
  hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array;
  /** HKDF-SHA-256 (RFC 5869). */
  hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array;
  /** The X25519 public key of a 32-byte private scalar. */
  x25519PublicKey(privateKey: Uint8Array): Uint8Array;
  /** The X25519 shared secret (RFC 7748). */
  x25519(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  randomBytes(length: number): Uint8Array;
}

/** The noble implementation: pure JavaScript, synchronous, every runtime. */
export const nobleCrypto: CryptoPort = {
  name: "noble",
  ed25519PublicKey: (seed) => ed25519.getPublicKey(seed),
  ed25519Sign: (seed, message) => ed25519.sign(message, seed),
  ed25519Verify(publicKey, message, signature) {
    try {
      return publicKey.length === 32 && signature.length === 64
        && ed25519.verify(signature, message, publicKey, { zip215: false });
    } catch {
      return false;
    }
  },
  sha256: (data) => sha256(data),
  sha512: (data) => sha512(data),
  hmacSha256: (key, data) => hmac(sha256, key, data),
  hkdfSha256: (ikm, salt, info, length) => hkdf(sha256, ikm, salt, info, length),
  x25519PublicKey: (privateKey) => x25519.getPublicKey(privateKey),
  x25519: (privateKey, publicKey) => x25519.getSharedSecret(privateKey, publicKey),
  randomBytes,
};

let installed: CryptoPort = nobleCrypto;

/** The crypto port in use. */
export function cryptoPort(): CryptoPort {
  return installed;
}

/** Installs a crypto port process-wide (for instance the `node:crypto` port); returns the previous one. */
export function installCrypto(port: CryptoPort): CryptoPort {
  const previous = installed;
  installed = port;
  return previous;
}
