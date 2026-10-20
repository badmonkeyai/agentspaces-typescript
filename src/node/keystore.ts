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
 * The file keystore for Node hosts (srad/agentspaces-js.md JS-P-08): the
 * FileKeystore layout of the Java side, `peer.key` (PKCS#8 DER, 0600) and
 * `peer.pub` (raw 32 bytes), and the agent keystore beneath it. Node only;
 * the portable core never imports this module.
 */

import {
  closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { randomBytes, toHex } from "../bytes.js";
import { Identity } from "../identity.js";
import { KeyStore } from "../platform.js";

/** Writes the identity's private key as PKCS#8 DER to `path`: an atomic replace, owner-only (0600). */
export function savePkcs8(identity: Identity, path: string): void {
  writeKeyFile(path, identity.pkcs8(), true);
}

/**
 * FileKeystore.loadOrCreate (SPEC §4.1, v0.1.13): `peer.key` and `peer.pub`
 * in `directory`, minted when absent. A half-written pair, a wrong-size
 * public file, or a private key that does not sign for the public one is
 * refused, naming the files.
 */
export function loadOrCreateIdentity(directory: string, privateName = "peer.key",
                                     publicName = "peer.pub"): Identity {
  const privatePath = join(directory, privateName);
  const publicPath = join(directory, publicName);
  const hasPrivate = existsSync(privatePath);
  const hasPublic = existsSync(publicPath);
  if (hasPrivate !== hasPublic) {
    const [present, missing] = hasPrivate ? [privatePath, publicPath] : [publicPath, privatePath];
    throw new Error(`corrupt keystore: ${present} exists but ${missing} does not`);
  }
  if (!hasPrivate) {
    const identity = Identity.generate();
    writeKeyFile(privatePath, identity.pkcs8(), true);
    writeKeyFile(publicPath, identity.publicRaw, false);
    return identity;
  }
  const identity = Identity.fromPkcs8(new Uint8Array(readFileSync(privatePath)));
  const pub = new Uint8Array(readFileSync(publicPath));
  if (pub.length !== 32) {
    throw new Error(`corrupt keystore: ${publicPath} is not a raw Ed25519 public key`);
  }
  const probe = randomBytes(32);
  if (!Identity.verify(pub, probe, identity.sign(probe))) {
    throw new Error(`corrupt keystore: ${privatePath} does not belong to the public key in ${publicPath}`);
  }
  return identity;
}

const SAFE_NAME = /^[A-Za-z0-9._-]{1,64}$/;

/** AgentKeystore.signingKeys: `<dir>/<peer-id>/<local-name>/agent.key` and `agent.pub`. */
export function agentKeys(directory: string, peerId: string, localName: string): Identity {
  for (const [name, what] of [[peerId, "peer id"], [localName, "agent name"]]) {
    if (!SAFE_NAME.test(name) || name === "." || name === "..") {
      throw new Error(`${what} '${name}' is not a safe file name`);
    }
  }
  return loadOrCreateIdentity(join(directory, peerId, localName), "agent.key", "agent.pub");
}

/** KeyFiles.write: atomic replace through a temp file in the same directory, 0600 for a secret. */
export function writeKeyFile(path: string, data: Uint8Array, secret: boolean): void {
  const directory = dirname(resolve(path));
  mkdirSync(directory, { recursive: true });
  const temp = join(directory, `.${secret ? "key" : "pub"}-${process.pid}-${toHex(randomBytes(4))}.tmp`);
  const descriptor = openSync(temp, "wx", secret ? 0o600 : 0o644);
  try {
    writeSync(descriptor, data);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  try {
    renameSync(temp, path);
  } finally {
    if (existsSync(temp)) {
      rmSync(temp);
    }
  }
}

/** A {@link KeyStore} over a directory: one file per name, secrets written 0600. */
export class FileKeyStore implements KeyStore {
  constructor(private readonly directory: string) {}

  async load(name: string): Promise<Uint8Array | null> {
    const path = this.path(name);
    return existsSync(path) ? new Uint8Array(readFileSync(path)) : null;
  }

  async save(name: string, value: Uint8Array): Promise<void> {
    writeKeyFile(this.path(name), value, true);
  }

  async remove(name: string): Promise<void> {
    const path = this.path(name);
    if (existsSync(path)) {
      rmSync(path);
    }
  }

  private path(name: string): string {
    if (!SAFE_NAME.test(name) || name === "." || name === "..") {
      throw new Error(`key name '${name}' is not a safe file name`);
    }
    return join(this.directory, name);
  }
}
