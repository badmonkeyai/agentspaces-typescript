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
 * The content store's two entry records (PDT 2 phase 0, P2-S-02; srad/agentspaces-pdt2.md §3.2.2 and the
 * annex I schemas of §6.10.4), ports of Java's `StorePin` and `StoreReceipt`: a member's request that a
 * store hold a root, and the store's statement that it holds one. Both are protocol records read strictly
 * from their own bytes (SPEC §9.1, F3), so a payload with a field the schema does not name is undecodable.
 * Both travel ungated, since a level-1 replica stores and replicates an entry of an unknown type without
 * decoding it, and each changes shape only under a new type name (P2-F-08).
 *
 * Since the PDT 2 follow-ups of 2026-11-09 (F1) the pin entry a store takes is `SignedPin#v1`, the requester's
 * `StorePin` terms under the requester's Ed25519 signature, so a store charges only the member who signed them.
 * The signature covers {@link consentBytes}, the canonical CBOR of `{purpose, group, pin, notAfter}`, under `key`,
 * whose peer id is the pin's requester; `left` counts the copies still to place, which a store that forwards a
 * copy lowers by one, and no store takes the pin after `notAfter`, epoch milliseconds.
 */

import { utf8 } from "../bytes.js";
import { canonicalMap, dumps } from "../cbor.js";
import { Identity, deriveId } from "../identity.js";
import { conform, decodeRecord } from "../records.js";
import type { Schema } from "../records.js";
import type { Dict } from "../wire.js";
import * as cids from "./cids.js";

export const STORE_PIN_TYPE = "ai.badmonkey.agentspaces.agent.content.StorePin#v1";
export const STORE_RECEIPT_TYPE = "ai.badmonkey.agentspaces.agent.content.StoreReceipt#v1";
export const VERSION = 1;
export const KIND_TREE = "tree", KIND_ARTIFACT = "artifact";
export const ROOT_TAG = "root", REQUESTER_TAG = "requester", HOLDER_TAG = "holder";
export const MAX_HAVES = 8;
export const MAX_ATTRS = 32;
export const MAX_ATTRS_BYTES = 4 * 1024;
export const SIGNED_PIN_TYPE = "ai.badmonkey.agentspaces.agent.content.SignedPin#v1";
/** The text a pin's consent opens with, so the signature serves no other record of the requester's key. */
export const PURPOSE = "agentspaces.store-pin";
const KEY_BYTES = 32, SIG_BYTES = 64;

/** `StorePin { v, root, kind, lease, copies, requester, haves, attrs ?null }` in Java field order (§6.10.4). */
const STORE_PIN: Schema = { record: "StorePin", fields: [["v", "int"], ["root", "String", "nonNull"],
  ["kind", "String", "nonNull"], ["lease", "long"], ["copies", "int"], ["requester", "id", "nonNull"],
  ["haves", { listOf: "String" }, "nonNull"], ["attrs", { mapOf: "String" }, "omitNull"]] };

/** `SignedPin { v, pin, left, notAfter, key, sig }` in Java field order (F1). */
const SIGNED_PIN: Schema = { record: "SignedPin", fields: [["v", "int"], ["pin", STORE_PIN, "nonNull"], ["left", "int"],
  ["notAfter", "long"], ["key", "bytes", "nonNull"], ["sig", "bytes", "nonNull"]] };

/** `StoreReceipt { v, root, holder, bytes, until, blind }` in Java field order (§6.10.4). */
const STORE_RECEIPT: Schema = { record: "StoreReceipt", fields: [["v", "int"], ["root", "String", "nonNull"],
  ["holder", "id", "nonNull"], ["bytes", "long"], ["until", "long"], ["blind", "boolean"]] };

export interface StorePinFields {
  /** The root to hold: a tree root, or an artifact's manifest root. */
  root: string;
  /** {@link KIND_TREE} or {@link KIND_ARTIFACT}. */
  kind: string;
  /** The seconds the requester asks the store to hold the root, renewed by a rewrite. */
  lease: number;
  /** The stores the requester wants holding it, at least 1. */
  copies: number;
  requester: string;
  /** Bases the store may already hold, at most {@link MAX_HAVES}. */
  haves?: string[];
  attrs?: { [key: string]: string } | null;
}

/**
 * A `StorePin` in Java field order; `attrs` is absent when null. Throws `UndecodableError` for a value the
 * schema refuses (a fractional or unsafe lease, copies outside a Java int, an empty requester, an attrs value
 * that is not text), which Java's record types make unwritable, so no reader drops a pin this writes (PDT 2
 * phase 0, P2-S-02).
 */
export function storePin(fields: StorePinFields): Dict {
  const out: Dict = { v: VERSION, root: fields.root, kind: fields.kind, lease: fields.lease, copies: fields.copies,
    requester: fields.requester, haves: fields.haves ?? [] };
  if (fields.attrs != null) {
    out["attrs"] = canonicalMap({ ...fields.attrs });
  }
  return conform(out, STORE_PIN) as Dict;
}

/** A `StorePin` read strictly from its bytes; throws a RangeError when the payload is undecodable. */
export function decodeStorePin(bytes: Uint8Array): Dict {
  return decodeRecord(bytes, STORE_PIN) as Dict;
}

/** The tags a pin entry is written with. */
export function storePinTags(pin: Dict): Dict {
  return { [ROOT_TAG]: pin["root"]!, [REQUESTER_TAG]: pin["requester"]! };
}

/** The first bound of §3.2.2 a pin breaks, which a store judges before it takes the pin, or null. */
export function storePinViolation(pin: Dict): string | null {
  if (pin["v"] !== VERSION) {
    return `unsupported StorePin version ${String(pin["v"])}`;
  }
  if (!cids.isCid(pin["root"])) {
    return "root is not a CID";
  }
  if (pin["kind"] !== KIND_TREE && pin["kind"] !== KIND_ARTIFACT) {
    return `unknown kind ${String(pin["kind"])}`;
  }
  if (Number(pin["lease"]) < 1) {
    return `lease of ${String(pin["lease"])} seconds`;
  }
  if (Number(pin["copies"]) < 1) {
    return "copies below 1";
  }
  const haves = pin["haves"] as unknown[];
  if (haves.length > MAX_HAVES) {
    return `more than ${MAX_HAVES} haves`;
  }
  if (!haves.every((have) => cids.isCid(have))) {
    return "have is not a CID";
  }
  const attrs = pin["attrs"] as { [key: string]: string } | undefined;
  if (attrs !== undefined) {
    const entries = Object.entries(attrs);
    if (entries.length > MAX_ATTRS) {
      return `more than ${MAX_ATTRS} attrs`;
    }
    if (entries.reduce((sum, [key, value]) => sum + utf8(key).length + utf8(value).length, 0) > MAX_ATTRS_BYTES) {
      return `attrs larger than ${MAX_ATTRS_BYTES} bytes`;
    }
  }
  return null;
}

/** What a requester signs: the canonical CBOR of `{purpose, group, pin, notAfter}` in that order. */
export function consentBytes(pin: Dict, group: string, notAfter: number): Uint8Array {
  return dumps({ purpose: PURPOSE, group, pin, notAfter });
}

/**
 * The `SignedPin` of a requester's terms for every copy they ask, in Java field order. Throws when the terms
 * name another requester, since only that member signs them (F1).
 */
export function signPin(pin: Dict, group: string, notAfter: number, requester: Identity): Dict {
  if (pin["requester"] !== requester.peerId) {
    throw new Error(`the pin names requester ${String(pin["requester"])}, and only that member signs it`);
  }
  return conform({ v: VERSION, pin, left: pin["copies"]!, notAfter, key: requester.publicRaw,
    sig: requester.sign(consentBytes(pin, group, notAfter)) }, SIGNED_PIN) as Dict;
}

/** A `SignedPin` read strictly from its bytes, its pin under the `StorePin` schema; throws a RangeError when undecodable. */
export function decodeSignedPin(bytes: Uint8Array): Dict {
  return decodeRecord(bytes, SIGNED_PIN) as Dict;
}

/** The tags a signed pin is written with: its pin's. */
export function signedPinTags(signed: Dict): Dict {
  return storePinTags(signed["pin"] as Dict);
}

/**
 * The first rule a signed pin breaks (the version, the pin's bounds, the copies left, the deadline's sign, the
 * key and signature lengths), or null; {@link signedPinConsented} checks the signature.
 */
export function signedPinViolation(signed: Dict): string | null {
  if (signed["v"] !== VERSION) {
    return `unsupported SignedPin version ${String(signed["v"])}`;
  }
  const pin = signed["pin"] as Dict;
  const terms = storePinViolation(pin);
  if (terms !== null) {
    return terms;
  }
  const left = Number(signed["left"]), copies = Number(pin["copies"]);
  if (left < 1 || left > copies) {
    return `left ${left} is outside 1 to ${copies} copies`;
  }
  if (Number(signed["notAfter"]) < 0) {
    return "negative notAfter";
  }
  if ((signed["key"] as Uint8Array).length !== KEY_BYTES) {
    return "key is not 32 bytes";
  }
  if ((signed["sig"] as Uint8Array).length !== SIG_BYTES) {
    return "sig is not 64 bytes";
  }
  return null;
}

/**
 * Whether the requester the terms name signed them for this group and deadline: the key's peer id is the
 * requester's and the signature verifies over {@link consentBytes}.
 */
export function signedPinConsented(signed: Dict, group: string): boolean {
  const pin = signed["pin"] as Dict, key = signed["key"] as Uint8Array;
  return key.length === KEY_BYTES && deriveId(key) === pin["requester"]
    && Identity.verify(key, consentBytes(pin, group, Number(signed["notAfter"])), signed["sig"] as Uint8Array);
}

export interface StoreReceiptFields {
  root: string;
  holder: string;
  /** The bytes the store holds for the root. */
  bytes: number;
  /** Epoch milliseconds until which the store holds the root, as `Manifest.created` counts. */
  until: number;
  /** Whether the store holds without the content key (§3.2.5). */
  blind: boolean;
}

/**
 * A `StoreReceipt` in Java field order. Throws `UndecodableError` for a value the schema refuses, as
 * {@link storePin} does (PDT 2 phase 0, P2-S-02).
 */
export function storeReceipt(fields: StoreReceiptFields): Dict {
  return conform({ v: VERSION, root: fields.root, holder: fields.holder, bytes: fields.bytes, until: fields.until,
    blind: fields.blind }, STORE_RECEIPT) as Dict;
}

/** A `StoreReceipt` read strictly from its bytes; throws a RangeError when the payload is undecodable. */
export function decodeStoreReceipt(bytes: Uint8Array): Dict {
  return decodeRecord(bytes, STORE_RECEIPT) as Dict;
}

/** The tags a receipt entry is written with, as a `Holding` is tagged. */
export function storeReceiptTags(receipt: Dict): Dict {
  return { [ROOT_TAG]: receipt["root"]!, [HOLDER_TAG]: receipt["holder"]! };
}

/** The first rule a receipt breaks (version, root, the signs of the counts), or null. */
export function storeReceiptViolation(receipt: Dict): string | null {
  if (receipt["v"] !== VERSION) {
    return `unsupported StoreReceipt version ${String(receipt["v"])}`;
  }
  if (!cids.isCid(receipt["root"])) {
    return "root is not a CID";
  }
  if (Number(receipt["bytes"]) < 0) {
    return "negative bytes";
  }
  if (Number(receipt["until"]) < 0) {
    return "negative until";
  }
  return null;
}
