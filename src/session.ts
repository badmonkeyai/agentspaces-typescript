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
 * Session attestation (SPEC §5.6, v0.1.17; srad/agentspaces-js.md JS-H-05):
 * on a connection the transport cannot attest, one fully signed
 * `SESSION_HELLO` each way establishes a key, after which frames carry an
 * HMAC-SHA-256 tag under it in place of the Ed25519 signature. This module
 * is the TypeScript twin of the Java node's session logic, byte for byte:
 * the hello body, the key derivation, the session frame, the age rule, the
 * tie rule when both ends open at once, and key confirmation.
 */

import { concat, equals, utf8 } from "./bytes.js";
import { CborValue, dumps, loads } from "./cbor.js";
import { cryptoPort } from "./crypto.js";
import * as wire from "./wire.js";
import type { Dict } from "./wire.js";

/** How old a hello may be, by its stamp, and still be answered (PeerNode.SESSION_HELLO_MAX_AGE_MILLIS). */
export const SESSION_HELLO_MAX_AGE_MILLIS = 30_000;
/** How long an unanswered opening hello stands before it may be repeated. */
export const SESSION_HELLO_RETRY_MILLIS = 5_000;
/** The resource hint a node advertises when it runs the SESSION mode. */
export const SESSION_HINT = "wire.session";
/** The length of a session tag; a session frame carries exactly this in the signature field. */
export const SESSION_MAC_LENGTH = 32;
const SESSION_INFO = utf8("agentspaces session v1");

/** The SESSION_HELLO body (Bodies.SessionHello) in Java record order. */
export function sessionHelloBody(ephemeralKey: Uint8Array, nonce: Uint8Array, remote: string,
                                 echo: Uint8Array | null): Uint8Array {
  return dumps({ ephemeralKey, nonce, remote, echo });
}

/** The hello a body decodes to, or null when it is not one. */
export function parseSessionHello(body: Uint8Array): { ephemeralKey: Uint8Array; nonce: Uint8Array;
    remote: string; echo: Uint8Array | null } | null {
  let value: CborValue;
  try {
    value = loads(body);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value) || value instanceof Uint8Array) {
    return null;
  }
  const hello = value as Dict;
  const key = hello["ephemeralKey"];
  const nonce = hello["nonce"];
  const echo = hello["echo"];
  if (!(key instanceof Uint8Array) || key.length !== 32 || !(nonce instanceof Uint8Array)
      || nonce.length < 16 || nonce.length > 64 || typeof hello["remote"] !== "string"
      || (echo !== null && echo !== undefined && !(echo instanceof Uint8Array))) {
    return null;
  }
  return { ephemeralKey: key, nonce, remote: hello["remote"], echo: echo instanceof Uint8Array ? echo : null };
}

/**
 * PeerNode.deriveSessionKey: HKDF-SHA-256 over the X25519 agreement, with an
 * empty salt and the info `"agentspaces session v1" || lower PeerID || 0 ||
 * higher PeerID || 0 || lower's nonce || higher's nonce`, 32 bytes.
 */
export function deriveSessionKey(ownPrivate: Uint8Array, ownPeerId: string, ownNonce: Uint8Array,
                                 remoteKey: Uint8Array, remotePeerId: string, remoteNonce: Uint8Array): Uint8Array {
  const crypto = cryptoPort();
  const shared = crypto.x25519(ownPrivate, remoteKey);
  const selfFirst = ownPeerId < remotePeerId;
  const first = selfFirst ? ownPeerId : remotePeerId;
  const second = selfFirst ? remotePeerId : ownPeerId;
  const firstNonce = selfFirst ? ownNonce : remoteNonce;
  const secondNonce = selfFirst ? remoteNonce : ownNonce;
  const info = concat(SESSION_INFO, utf8(first), new Uint8Array([0]), utf8(second), new Uint8Array([0]),
    firstNonce, secondNonce);
  return crypto.hkdfSha256(shared, new Uint8Array(0), info, SESSION_MAC_LENGTH);
}

/** WireCodec.encodeSession: no key, and the HMAC of the canonical envelope in the signature field. */
export function encodeSessionFrame(env: Dict, key: Uint8Array): Uint8Array {
  return dumps({ envelope: env, senderPublicKey: null, signature: cryptoPort().hmacSha256(key, dumps(env)) });
}

/** Whether a session tag verifies under the key for the envelope. */
export function sessionTagVerifies(env: Dict, tag: Uint8Array, key: Uint8Array): boolean {
  return tag.length === SESSION_MAC_LENGTH && equals(cryptoPort().hmacSha256(key, dumps(env)), tag);
}

/**
 * One connection's session, the state machine of PeerNode.Session: this
 * end's ephemeral key and nonce, the hello sent and answered flags, the
 * remote's half once it arrives, the derived key, and whether the other end
 * provably holds it (outbound frames carry a tag only then).
 */
export class Session {
  readonly ephemeralPrivate: Uint8Array;
  readonly ephemeralPublic: Uint8Array;
  readonly nonce: Uint8Array;
  helloSent = false;
  helloSentAtMillis = 0;
  /** Whether this end's hello was the answering one. */
  answered = false;
  remote: string | null = null;
  remoteKey: Uint8Array | null = null;
  remoteNonce: Uint8Array | null = null;
  key: Uint8Array | null = null;
  confirmed = false;

  constructor(private readonly ownPeerId: string) {
    const crypto = cryptoPort();
    this.ephemeralPrivate = crypto.randomBytes(32);
    this.ephemeralPublic = crypto.x25519PublicKey(this.ephemeralPrivate);
    this.nonce = crypto.randomBytes(32);
  }

  /** The hello body for the remote peer (opening when `echo` is null, answering otherwise). */
  hello(remote: string, echo: Uint8Array | null): Uint8Array {
    return sessionHelloBody(this.ephemeralPublic, this.nonce, remote, echo);
  }

  /** Whether an opening hello may go out now (PeerNode.maybeSessionHello's guard). */
  mayOpen(nowMillis: number): boolean {
    return this.key === null && !this.answered
      && !(this.helloSent && nowMillis - this.helloSentAtMillis < SESSION_HELLO_RETRY_MILLIS);
  }

  /** Marks a hello as sent. */
  sent(nowMillis: number, answering: boolean): void {
    this.helloSent = true;
    this.helloSentAtMillis = nowMillis;
    this.answered = answering;
  }

  /**
   * Takes the remote's half (PeerNode.onSessionHello's core): refuses a second
   * peer or a repeat; applies the tie rule when both ends opened at once; an
   * answer must echo this end's nonce. Returns what to do: "answer" (send the
   * answering hello), "confirmed" (an answer arrived; the key is confirmed),
   * or null (ignore).
   */
  accept(from: string, hello: { ephemeralKey: Uint8Array; nonce: Uint8Array; echo: Uint8Array | null }):
      "answer" | "confirmed" | null {
    if (this.key !== null || (this.remote !== null && this.remote !== from)) {
      return null;
    }
    const opening = hello.echo === null;
    if (opening) {
      if (this.helloSent && !this.answered && this.ownPeerId < from) {
        return null; // both opened at once: this end is the opener and waits for the answer
      }
    } else if (!this.helloSent || this.answered || !equals(hello.echo!, this.nonce)) {
      return null; // an answer to a hello this end never opened
    }
    this.remote = from;
    this.remoteKey = hello.ephemeralKey;
    this.remoteNonce = hello.nonce;
    this.key = deriveSessionKey(this.ephemeralPrivate, this.ownPeerId, this.nonce, hello.ephemeralKey, from,
      hello.nonce);
    this.confirmed = !opening;
    return opening ? "answer" : "confirmed";
  }

  /** Undoes `accept` when the answer could not be sent, so the opener opens again. */
  retract(): void {
    this.key = null;
    this.remote = null;
    this.remoteKey = null;
    this.remoteNonce = null;
    this.confirmed = false;
  }

  /** The key to tag a frame for `to` with, or null while unconfirmed or for another peer. */
  keyFor(to: string | null, kind: string): Uint8Array | null {
    return this.confirmed && this.key !== null && to !== null && to === this.remote
      && kind !== "SESSION_HELLO" && kind !== "CHANNEL_HELLO" ? this.key : null;
  }

  /** A frame tagged for `to`, or the fully signed frame. */
  encode(env: Dict, sign: (env: Dict) => Uint8Array): Uint8Array {
    const key = this.keyFor(env["to"] as string | null, String(env["kind"]));
    return key === null ? sign(env) : encodeSessionFrame(env, key);
  }

  /** The established session for the decoder, or null. */
  established(): wire.EstablishedSession | null {
    return this.key === null || this.remote === null ? null : { peer: this.remote, key: this.key };
  }
}
