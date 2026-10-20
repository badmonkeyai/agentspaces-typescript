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
 * The `node:crypto` crypto port (JS-P-02): OpenSSL's Ed25519, SHA-2, HMAC,
 * HKDF, and X25519, for Node services that want native speed. Opt in with
 * `installCrypto(nodeCrypto)`; the golden vectors pin both ports to the same
 * bytes.
 */

import {
  createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, hkdfSync,
  randomBytes as nodeRandomBytes, sign, verify,
} from "node:crypto";
import { concat, fromHex } from "../bytes.js";
import { CryptoPort } from "../crypto.js";

const ED25519_PKCS8 = fromHex("302e020100300506032b657004220420");
const ED25519_SPKI = fromHex("302a300506032b6570032100");
const X25519_PKCS8 = fromHex("302e020100300506032b656e04220420");
const X25519_SPKI = fromHex("302a300506032b656e032100");

function privateKey(prefix: Uint8Array, raw: Uint8Array) {
  return createPrivateKey({ key: Buffer.from(concat(prefix, raw)), format: "der", type: "pkcs8" });
}

function publicKey(prefix: Uint8Array, raw: Uint8Array) {
  return createPublicKey({ key: Buffer.from(concat(prefix, raw)), format: "der", type: "spki" });
}

function rawPublic(key: ReturnType<typeof createPublicKey>): Uint8Array {
  const der = key.export({ type: "spki", format: "der" });
  return new Uint8Array(der.subarray(der.length - 32));
}

export const nodeCrypto: CryptoPort = {
  name: "node",
  ed25519PublicKey: (seed) => rawPublic(createPublicKey(privateKey(ED25519_PKCS8, seed))),
  ed25519Sign: (seed, message) => new Uint8Array(sign(null, message, privateKey(ED25519_PKCS8, seed))),
  ed25519Verify(key, message, signature) {
    try {
      return key.length === 32 && signature.length === 64
        && verify(null, message, publicKey(ED25519_SPKI, key), signature);
    } catch {
      return false;
    }
  },
  sha256: (data) => new Uint8Array(createHash("sha256").update(data).digest()),
  sha512: (data) => new Uint8Array(createHash("sha512").update(data).digest()),
  hmacSha256: (key, data) => new Uint8Array(createHmac("sha256", key).update(data).digest()),
  hkdfSha256: (ikm, salt, info, length) => new Uint8Array(hkdfSync("sha256", ikm, salt, info, length)),
  x25519PublicKey: (raw) => rawPublic(createPublicKey(privateKey(X25519_PKCS8, raw))),
  x25519: (raw, peer) => new Uint8Array(diffieHellman({
    privateKey: privateKey(X25519_PKCS8, raw), publicKey: publicKey(X25519_SPKI, peer),
  })),
  randomBytes: (length) => new Uint8Array(nodeRandomBytes(length)),
};
