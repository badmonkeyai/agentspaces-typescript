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
 * The protocol records of the wire encoding (HLC round six, 2026-11-08, owner rulings F1 and F3;
 * rules P1 to P4), each with its fields in Java's declared order, and the strict read every network
 * carrier passes: {@link decodeRecord} decodes the document under the item rules of the codec,
 * conforms it to its schema, re-encodes the result, and refuses the carrier unless the bytes are
 * exactly the bytes received. The read refuses a field of the wrong kind and coerces nothing: no epoch
 * as a float, a decimal or text, no bid as an integer or text, no byte string where text belongs.
 */

import { compare, equals } from "./bytes.js";
import { CborDecimal, CborDouble, CborFloat32, CborValue, canonicalMap, dumps, loads, setEntry } from "./cbor.js";
import { CARD_SPILL_MAX_SIZE, INLINE_PAYLOAD_LIMIT, decodeHlc } from "./wire.js";

type Dict = { [key: string]: CborValue };

/** A field kind, as appendix A of the wire encoding names it. */
export type Kind =
  | "int" | "long" | "double" | "boolean" | "Integer" | "Long"
  | "String" | "bytes" | "id" | "AgentId" | "stamp" | "Instant" | "Duration"
  | { readonly enumOf: readonly string[] }
  | { readonly listOf: Kind }
  | { readonly setOf: Kind }
  | { readonly mapOf: Kind }
  | Schema;

/**
 * How a field appears: `always` present, a null written as null (a primitive kind is never null);
 * `nonNull` present and never null (a component Java's record requires); `omitNull` absent when null
 * and never written as null (Jackson NON_NULL); `omitEmpty` absent when null or empty (NON_EMPTY).
 */
export type Presence = "always" | "nonNull" | "omitNull" | "omitEmpty";

export type Field = readonly [name: string, kind: Kind, presence?: Presence];

/**
 * A protocol record: its name, its fields in declared order, and any check Java's constructor makes. A check
 * returns false to refuse the record, or refuses a field by name itself (AppCard origin and formats, 2026-11-09),
 * so the refusal says which rule failed; `path` is where the record sits in the carrier.
 */
export interface Schema {
  readonly record: string;
  readonly fields: readonly Field[];
  readonly check?: (value: Dict, path: string) => boolean;
}

/** A carrier refused under the wire encoding: undecodable, so its receiver strikes nobody. */
export class UndecodableError extends RangeError {}

const INT_MIN = -(2 ** 31);
const INT_MAX = 2 ** 31 - 1;
const LONG_MIN = -(1n << 63n);
const LONG_MAX = (1n << 63n) - 1n;

const PRIMITIVES = new Set<Kind>(["int", "long", "double", "boolean"]);

const listOf = (kind: Kind): Kind => ({ listOf: kind });
const setOf = (kind: Kind): Kind => ({ setOf: kind });
const mapOf = (kind: Kind): Kind => ({ mapOf: kind });
const enumOf = (...names: string[]): Kind => ({ enumOf: names });
const schema = (record: string, fields: readonly Field[], check?: (value: Dict, path: string) => boolean): Schema =>
  ({ record, fields, check });

/**
 * `fields` with every field that names no presence made `nonNull`: an advertisement record, whose Java
 * constructor refuses a null in every field it always writes, with requireNonNull or by writing a default
 * the received bytes do not hold (HLC round six, 2026-11-08, F1 and F3, adversary pass).
 */
const required = (fields: readonly Field[]): readonly Field[] =>
  fields.map(([name, kind, presence]) => [name, kind, presence ?? "nonNull"] as const);

/**
 * Java's AgentId grammar, as the wire encoding states it (HLC round six, 2026-11-08, R5):
 * `<peerId>/<localName>` with both parts non-empty and a local name holding no "/" and no ":".
 */
export function isAgentId(text: unknown): text is string {
  if (typeof text !== "string") {
    return false;
  }
  const slash = text.indexOf("/");
  if (slash <= 0 || slash === text.length - 1) {
    return false;
  }
  const local = text.substring(slash + 1);
  return !local.includes("/") && !local.includes(":");
}

const INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}|\d{6}|\d{9}))?Z$/;

/**
 * Whether `text` is an Instant exactly as Java's DateTimeFormatter.ISO_INSTANT prints it (HLC round
 * six, 2026-11-08, P2): a real UTC date and time in the years 0000 to 9999, and a fraction only when
 * the nanoseconds are not zero, in the fewest of 3, 6 or 9 digits that hold them.
 */
export function isJavaInstant(text: unknown): boolean {
  const match = typeof text === "string" ? INSTANT.exec(text) : null;
  if (match === null) {
    return false;
  }
  const [, year, month, day, hour, minute, second] = match.map(Number) as number[];
  const date = new Date(0);
  date.setUTCFullYear(year!, month! - 1, day!);
  date.setUTCHours(hour!, minute!, second!, 0);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month! - 1 || date.getUTCDate() !== day
      || date.getUTCHours() !== hour || date.getUTCMinutes() !== minute || date.getUTCSeconds() !== second) {
    return false;
  }
  const digits = match[7];
  return digits === undefined || (!/^0+$/.test(digits) && !(digits.length > 3 && digits.endsWith("000")));
}

const DURATION = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)(?:\.(\d{1,9}))?S)?$/;

/**
 * Whether `text` is a non-negative Duration exactly as Java's Duration.toString prints it (HLC round
 * six, 2026-11-08, P2): `PT0S` for zero, else hours when not zero, minutes from 1 to 59 when not
 * zero, then seconds from 0 to 59 with a fraction of 1 to 9 digits and no trailing zero, written
 * only when the seconds or the fraction are not zero; no leading zeros, and never days.
 */
export function isJavaDuration(text: unknown): boolean {
  if (text === "PT0S") {
    return true;
  }
  const match = typeof text === "string" ? DURATION.exec(text) : null;
  if (match === null || text === "PT") {
    return false;
  }
  const [, hours, minutes, seconds, fraction] = match;
  const canonical = (digits: string | undefined): boolean => digits === undefined || /^(?:0|[1-9]\d*)$/.test(digits);
  if (!canonical(hours) || !canonical(minutes) || !canonical(seconds)) {
    return false;
  }
  if (hours !== undefined && hours === "0") {
    return false;
  }
  if (minutes !== undefined && (minutes === "0" || Number(minutes) > 59)) {
    return false;
  }
  if (seconds !== undefined) {
    if (Number(seconds) > 59 || (fraction !== undefined && fraction.endsWith("0"))) {
      return false;
    }
    if (seconds === "0" && fraction === undefined) {
      return false; // zero seconds print only as PT0S, handled above
    }
  }
  return true;
}

function isMap(value: CborValue | undefined): value is Dict {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && !(value instanceof Uint8Array) && !(value instanceof CborDouble);
}

function refuse(path: string, why: string): never {
  throw new UndecodableError(`${path}: ${why}`);
}

/** The order the encoding gives a set's elements: by encoded bytes, shorter first, then bytewise. */
function bySetOrder(a: Uint8Array, b: Uint8Array): number {
  return a.length - b.length || compare(a, b);
}

/**
 * `value` conformed to `kind`: the value itself for a scalar, a fresh record in declared order, a
 * map its encoder sorts, a set in element order. Throws {@link UndecodableError} when the value is
 * not of the kind, so a caller re-encodes the result and compares it with the bytes it received.
 */
export function conform(value: CborValue | undefined, kind: Kind, path = "$"): CborValue {
  if (typeof kind === "string") {
    switch (kind) {
      case "int":
      case "Integer":
        if (typeof value !== "number" || !Number.isInteger(value) || value < INT_MIN || value > INT_MAX) {
          refuse(path, "not an int");
        }
        return value;
      case "long":
      case "Long":
        if (!((typeof value === "number" && Number.isSafeInteger(value))
            || (typeof value === "bigint" && value >= LONG_MIN && value <= LONG_MAX))) {
          refuse(path, "not a long");
        }
        return value;
      case "double":
        // any float64, as Java reads a double field; TakeClaim's own check keeps its bid finite
        // (HLC round seven, 2026-11-08)
        if (!(value instanceof CborDouble) || value instanceof CborFloat32 || value instanceof CborDecimal) {
          refuse(path, "not a float64");
        }
        return value;
      case "boolean":
        if (typeof value !== "boolean") {
          refuse(path, "not a boolean");
        }
        return value;
      case "String":
        if (typeof value !== "string") {
          refuse(path, "not text");
        }
        return value;
      case "id":
        if (typeof value !== "string" || value.length === 0) {
          refuse(path, "not a non-empty id");
        }
        return value;
      case "AgentId":
        if (!isAgentId(value)) {
          refuse(path, "not an agent id");
        }
        return value;
      case "stamp":
        if (decodeHlc(value) === null) {
          refuse(path, "not a canonical stamp");
        }
        return value as string;
      case "Instant":
        if (!isJavaInstant(value)) {
          refuse(path, "not an Instant as Java prints it");
        }
        return value as string;
      case "Duration":
        if (!isJavaDuration(value)) {
          refuse(path, "not a Duration as Java prints it");
        }
        return value as string;
      case "bytes":
        if (!(value instanceof Uint8Array)) {
          refuse(path, "not a byte string");
        }
        return value;
    }
  }
  if ("enumOf" in kind) {
    if (typeof value !== "string" || !kind.enumOf.includes(value)) {
      refuse(path, "not a constant of the enum");
    }
    return value;
  }
  if ("listOf" in kind) {
    if (!Array.isArray(value)) {
      refuse(path, "not an array");
    }
    return value.map((item, i) => conform(item, kind.listOf, `${path}[${i}]`));
  }
  if ("setOf" in kind) {
    if (!Array.isArray(value)) {
      refuse(path, "not an array");
    }
    const items = value.map((item, i) => {
      const conformed = conform(item, kind.setOf, `${path}[${i}]`);
      return { conformed, bytes: dumps(conformed) };
    }).sort((a, b) => bySetOrder(a.bytes, b.bytes));
    if (items.some((item, i) => i > 0 && equals(item.bytes, items[i - 1]!.bytes))) {
      refuse(path, "an element twice in a set");
    }
    return items.map((item) => item.conformed);
  }
  if ("mapOf" in kind) {
    if (!isMap(value)) {
      refuse(path, "not a map");
    }
    const out: Dict = {};
    for (const key of Object.keys(value)) {
      setEntry(out, key, conform(value[key], kind.mapOf, `${path}.${key}`));
    }
    return canonicalMap(out);
  }
  return conformRecord(value, kind, path);
}

function conformRecord(value: CborValue | undefined, kind: Schema, path: string): Dict {
  if (!isMap(value)) {
    refuse(path, `not a ${kind.record}`);
  }
  const out: Dict = {};
  const named = new Set<string>();
  for (const [name, fieldKind, presence = "always"] of kind.fields) {
    named.add(name);
    const item = value[name];
    const where = `${path}.${name}`;
    if (item === undefined) {
      if (presence === "always" || presence === "nonNull" || PRIMITIVES.has(fieldKind)) {
        refuse(where, "absent");
      }
      continue;
    }
    if (item === null) {
      if (presence !== "always" || PRIMITIVES.has(fieldKind)) {
        refuse(where, "null");
      }
      out[name] = null;
      continue;
    }
    if (presence === "omitEmpty" && Array.isArray(item) && item.length === 0) {
      refuse(where, "written empty");
    }
    out[name] = conform(item, fieldKind, where);
  }
  for (const key of Object.keys(value)) {
    if (!named.has(key)) {
      refuse(`${path}.${key}`, `a field ${kind.record} does not name`);
    }
  }
  if (kind.check !== undefined && !kind.check(out, path)) {
    refuse(path, `a ${kind.record} Java's constructor refuses`);
  }
  return out;
}

/**
 * The strict read of a carrier (HLC round six, 2026-11-08, F3): the document under the item rules,
 * conformed to `kind`, re-encoded, and compared with `bytes`. Returns the conformed value, whose
 * encoding is exactly `bytes`; throws {@link UndecodableError} (or the codec's RangeError) otherwise.
 */
export function decodeRecord(bytes: Uint8Array, kind: Kind): CborValue {
  const conformed = conform(loads(bytes), kind);
  if (!equals(dumps(conformed), bytes)) {
    throw new UndecodableError(`${typeof kind === "object" && "record" in kind ? kind.record : "the carrier"} is not in the wire encoding's form`);
  }
  return conformed;
}

/** {@link decodeRecord} as a map, or null when the carrier is undecodable. */
export function readRecord(bytes: unknown, kind: Schema): Dict | null {
  if (!(bytes instanceof Uint8Array)) {
    return null;
  }
  try {
    return decodeRecord(bytes, kind) as Dict;
  } catch {
    return null;
  }
}

/** {@link decodeRecord} of a list of `kind` (a revocation or view delta), or null when undecodable. */
export function readList(bytes: unknown, kind: Kind): CborValue[] | null {
  if (!(bytes instanceof Uint8Array)) {
    return null;
  }
  try {
    return decodeRecord(bytes, listOf(kind)) as CborValue[];
  } catch {
    return null;
  }
}

/** {@link conform} as a map, or null when the value is not of the record's kind. */
export function conformed(value: unknown, kind: Schema): Dict | null {
  try {
    return conformRecord(value as CborValue, kind, "$");
  } catch {
    return null;
  }
}

// ------------------------------------------------------------ appendix A

export const KINDS = ["PING", "PING_REQ", "ACK", "RUMOR", "DIGEST", "PULL_RESP", "QUERY", "QUERY_HIT", "BLOCK_WANT",
  "BLOCK", "PIPE_DATA", "BATCH", "HAVE", "GRAFT", "PRUNE", "RELAY_FRAME", "CHANNEL_HELLO", "SESSION_HELLO",
  "GROUP_AD_WANT", "GROUP_AD"] as const;

export const ENVELOPE = schema("Envelope", [["ver", "int"], ["group", "id", "nonNull"],
  ["kind", enumOf(...KINDS), "nonNull"], ["from", "id", "nonNull"], ["to", "id"], ["stamp", "stamp", "nonNull"],
  ["body", "bytes", "nonNull"]]);
export const SIGNED_FRAME = schema("WireCodec.Signed", [["envelope", ENVELOPE, "nonNull"], ["senderPublicKey", "bytes"],
  ["signature", "bytes"]]);

export const HAVE_ITEM = schema("Bodies.HaveItem", [["streamId", "String"], ["hash", "bytes"]]);
export const PING = schema("Bodies.Ping", [["nonce", "long"], ["root", "bytes", "omitNull"],
  ["hashes", mapOf("bytes"), "omitNull"], ["have", listOf(HAVE_ITEM), "omitNull"]]);
export const PING_REQ = schema("Bodies.PingReq", [["target", "id"], ["nonce", "long"]]);
export const ACK = schema("Bodies.Ack", [["nonce", "long"], ["onBehalf", "id"], ["root", "bytes", "omitNull"],
  ["hashes", mapOf("bytes"), "omitNull"], ["have", listOf(HAVE_ITEM), "omitNull"]]);
export const RUMOR = schema("Bodies.Rumor", [["streamId", "String"], ["itemId", "String"], ["hopsRemaining", "int"],
  ["payload", "bytes"]]);
export const DIGEST = schema("Bodies.Digest", [["digests", mapOf("bytes")], ["hashes", mapOf("bytes"), "omitNull"],
  ["want", listOf("String"), "omitNull"]]);
export const PULL_RESP = schema("Bodies.PullResp", [["deltas", mapOf("bytes")]]);
export const RELAY_FRAME = schema("Bodies.RelayFrame", [["target", "id"], ["frame", "bytes"],
  ["path", listOf("id"), "omitNull"], ["hop", "Integer", "omitNull"]]);
export const SESSION_HELLO = schema("Bodies.SessionHello", [["ephemeralKey", "bytes"], ["nonce", "bytes"],
  ["remote", "id"], ["echo", "bytes"]]);
export const CHANNEL_HELLO = schema("Bodies.ChannelHello", [["acceptsBare", "boolean"], ["attestedRemote", "id"]]);
export const BLOCK_WANT = schema("BlockExchange.Want", [["cid", "String"]]);
export const BLOCK = schema("BlockExchange.Block", [["cid", "String"], ["bytes", "bytes"]]);
export const PIPE_FRAME = schema("CapabilityPipes.PipeFrame", [["capability", "String"], ["payload", "bytes"]]);
export const RELAY_SIGNAL = schema("PeerNode.RelaySignal", [["target", "id"], ["failedHop", "id"], ["reason", "String"]]);

export const AGENT_CERTIFICATE = schema("AgentCertificate", [["agent", "AgentId", "nonNull"],
  ["agentPublicKey", "bytes", "nonNull"], ["issued", "Instant", "nonNull"], ["ttl", "Duration", "nonNull"],
  ["peerSignature", "bytes"], ["encryptionPublicKey", "bytes", "omitNull"]],
(c) => c["ttl"] !== "PT0S" && (c["encryptionPublicKey"] === undefined || (c["encryptionPublicKey"] as Uint8Array).length === 32));

const MEMBERSHIP = enumOf("OPEN", "INVITE", "POLICY");
const STRATEGY = enumOf("LEASE_RACE", "AUCTION", "ORDERED");
const AD_HEAD: readonly Field[] = required([["id", "String"], ["issuer", "id"], ["group", "id"], ["issued", "Instant"],
  ["ttl", "Duration"]]);

export const ENDPOINT = schema("PeerAdvertisement.Endpoint", [["transport", "String", "nonNull"],
  ["address", "String", "nonNull"], ["priority", "int"]]);
export const PEER_ADVERTISEMENT = schema("PeerAdvertisement", [["id", "String", "nonNull"], ["issuer", "id", "nonNull"],
  ["group", "id", "nonNull"], ["issued", "Instant", "nonNull"], ["ttl", "Duration", "nonNull"],
  ["endpoints", listOf(ENDPOINT), "nonNull"], ["roles", setOf(enumOf("RENDEZVOUS", "RELAY")), "nonNull"],
  ["resourceHints", mapOf("String"), "nonNull"]]);
export const GOSSIP_PARAMETERS = schema("GroupAdvertisement.GossipParameters", required([["fanout", "int"], ["period", "Duration"]]));
export const GROUP_ADVERTISEMENT = schema("GroupAdvertisement", required([...AD_HEAD, ["name", "String"],
  ["membershipPolicy", MEMBERSHIP], ["defaultStrategy", STRATEGY], ["gossip", GOSSIP_PARAMETERS]]));
export const SIGNED_GROUP_ADVERTISEMENT = schema("SignedGroupAdvertisement", [["advertisement", GROUP_ADVERTISEMENT, "nonNull"],
  ["founderPublicKey", "bytes", "nonNull"], ["signature", "bytes", "nonNull"]]);
export const SPACE_ADVERTISEMENT = schema("SpaceAdvertisement", required([...AD_HEAD, ["spaceName", "String"],
  ["schemaHints", listOf("String")], ["strategy", STRATEGY], ["admission", enumOf("GROUP", "ALLOWLIST", "CREDENTIAL", "AUTHORIZER")],
  ["replication", enumOf("FULL", "TAG_SHARDED")]]));
export const CAPABILITY_ADVERTISEMENT = schema("CapabilityAdvertisement", required([...AD_HEAD, ["capabilityType", "String"],
  ["version", "String"], ["binding", "String"], ["parameters", mapOf("String")], ["costHints", mapOf("String")]]));
export const ASSET_CARD = schema("AssetCard", required([...AD_HEAD, ["asset", "String"], ["uri", "String"],
  ["description", "String"], ["shape", "String"], ["freshness", "String"], ["costHints", mapOf("String")],
  ["access", mapOf("String")]]));
export const MODEL_CARD = schema("ModelCard", required([...AD_HEAD, ["name", "String"], ["version", "String"],
  ["tasks", listOf("String")], ["modality", "String"], ["limits", mapOf("String")], ["licence", "String"],
  ["provenance", mapOf("String")], ["evals", mapOf("String")], ["costHints", mapOf("String")],
  ["residency", mapOf("String")], ["engine", "String"], ["servers", listOf("id")]]));
export const CONTRACT = schema("CardAction.Contract", required([["pre", listOf("String")], ["post", listOf("String")],
  ["cost", "String"], ["methods", listOf("String")]]));
export const CARD_ACTION = schema("CardAction", required([["name", "String"], ["description", "String"],
  ["consumes", listOf("String")], ["produces", listOf("String")], ["space", "String", "omitNull"], ["kind", "String"],
  ["contract", CONTRACT, "omitNull"]]));
// AppCard origin and formats, 2026-11-09 (SPEC §6.1a.2 to §6.1a.5, §6.1b, v0.1.32; ISSUE-AppCardOriginFormats FR-1 to
// FR-5, FR-14): the closed values every reader checks at decode, and the value rules of Java's constructors, which
// its decoder calls. A closed value this build does not know makes the card undecodable (§6.1b, Unknown values).

/** How an app connects: a member, fed by an agent, behind the A2A gateway, or a static app that reads nothing live. */
export const APP_CARD_KINDS = ["peer", "fed", "gateway", "assembled"] as const;
export const APP_CARD_SHAPES = ["web", "desktop", "static", "a2ui"] as const;
export const APP_CARD_TRANSPORTS = ["views", "a2a"] as const;
/** `idp`, the identity provider of whoever runs the host, enforced at its door; or `none`. */
export const APP_CARD_SIGN_ONS = ["idp", "none"] as const;
export const APP_CARD_STATUSES = ["serving", "stopped"] as const;
export const UI_ROLES = ["panel", "control", "row"] as const;
/** The fields a stub moves into its parts document, in each card's field order (SPEC §6.1a.5). */
export const APP_CARD_SPILL_SET = ["reads", "actions", "views", "ui"] as const;
export const AGENT_CARD_SPILL_SET = ["actions", "ui"] as const;
/** The length of a stub's `spill.root`: `b`, then the unpadded base32 of a 36-byte CIDv1. */
export const CARD_SPILL_ROOT_LENGTH = 59;
export const APP_CARD_MAX_TERMS = 64;
export const APP_CARD_MAX_FORMATS = 16;
export const APP_CARD_MAX_FORMAT_LENGTH = 256;
export const UI_MAX_COMPONENTS = 32;
export const UI_MAX_CONTROLS = 16;
export const ORIGIN_MAX_SYSTEM = 64;
export const ORIGIN_MAX_REF = 256;
export const ORIGIN_MAX_VERSION = 64;
export const ORIGIN_MAX_ATTRS = 8;
export const ORIGIN_MAX_ATTR_KEY = 128;
export const ORIGIN_MAX_ATTR_VALUE = 256;

/** Whether every code unit is whitespace as Java's `String.isBlank` reads it (`Character.isWhitespace`). */
function isJavaBlank(text: unknown): boolean {
  return typeof text === "string" && /^[\t\n\v\f\r\x1c-\x20\u1680\u2000-\u2006\u2008-\u200a\u2028\u2029\u205f\u3000]*$/.test(text);
}

/** A control character: U+0000 to U+001F, or U+007F. */
const CONTROL = /[\x00-\x1f\x7f]/;
/** A control character, or a code unit of the Unicode White_Space property, as Java's AppCard reads an IRI. */
const WHITESPACE_OR_CONTROL = /[\x00-\x20\x7f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/;
/** A media type under the restricted names of RFC 6838 §4.2, lower-case, with no parameter. */
const MEDIA_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;
/** The scheme of a vocabulary IRI (RFC 3987 §2.2). */
const SCHEME = /^[a-z][a-z0-9+.-]*$/;
const ORIGIN_SYSTEM = /^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/;
const ORIGIN_KEY_TAIL = /^[a-z0-9.-]+$/;
const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

/**
 * Whether `text` is a content root as a stub's `spill.root` holds it (SPEC §6.1a.5, FR-14): `b`, then the lower-case
 * base32 (RFC 4648, no padding, zero pad bits) of a CIDv1 with codec raw (0x55) and a sha2-256 multihash.
 */
export function isSpillRoot(text: unknown): boolean {
  if (typeof text !== "string" || text.length !== CARD_SPILL_ROOT_LENGTH || text[0] !== "b") {
    return false;
  }
  const cid: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of text.slice(1)) {
    const value = BASE32.indexOf(ch);
    if (value < 0) {
      return false;
    }
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      cid.push((buffer >> bits) & 0xff);
    }
  }
  // 58 characters carry 36 bytes and 2 pad bits, which must be zero
  return cid.length === 36 && (buffer & ((1 << bits) - 1)) === 0
    && cid[0] === 0x01 && cid[1] === 0x55 && cid[2] === 0x12 && cid[3] === 0x20;
}

/** FR-3: 1 to 16 distinct entries, each a lower-case media type without parameter or a vocabulary IRI. */
export function checkFormats(formats: readonly CborValue[], path: string): void {
  if (formats.length === 0 || formats.length > APP_CARD_MAX_FORMATS) {
    refuse(path, `holds 1 to ${APP_CARD_MAX_FORMATS} entries, or is absent`);
  }
  if (new Set(formats).size !== formats.length) {
    refuse(path, "repeats an entry");
  }
  formats.forEach((value, i) => {
    const f = value as string;
    const where = `${path}[${i}]`;
    if (f.length === 0 || f.length > APP_CARD_MAX_FORMAT_LENGTH) {
      refuse(where, `is 1 to ${APP_CARD_MAX_FORMAT_LENGTH} code units`);
    }
    const colon = f.indexOf(":");
    if (colon < 0) {
      if (!MEDIA_TYPE.test(f)) {
        refuse(where, "a media type is lower-case type/subtype with no parameter");
      }
    } else if (!SCHEME.test(f.slice(0, colon)) || WHITESPACE_OR_CONTROL.test(f)) {
      refuse(where, "a vocabulary IRI has a scheme and no whitespace or control character");
    }
  });
}

/**
 * Checks a stub (FR-14): `spill.parts` names fields of the kind's spill set in its order, and every spill-set field
 * holds its placeholder, `[]` for a list the card always writes and absence for an optional field.
 */
function checkStub(card: Dict, path: string, spillSet: readonly string[], lists: readonly string[]): void {
  let last = -1;
  for (const part of (card["spill"] as Dict)["parts"] as string[]) {
    const at = spillSet.indexOf(part);
    if (at < 0) {
      refuse(`${path}.spill.parts`, `names ${part}, outside the spill set ${spillSet.join(", ")}`);
    }
    if (at <= last) {
      refuse(`${path}.spill.parts`, `breaks the field order of ${spillSet.join(", ")}`);
    }
    last = at;
  }
  for (const field of spillSet) {
    const value = card[field];
    if (lists.includes(field) ? (value as CborValue[]).length > 0 : value !== undefined) {
      refuse(`${path}.${field}`, "a stub holds its placeholder here; the value is in the parts document");
    }
  }
}

export const UI_COMPONENT = schema("UiDeclaration.Component", required([["id", "String"], ["catalogId", "String"],
  ["component", "String"], ["entry", "String"], ["controls", listOf("String")], ["role", enumOf(...UI_ROLES)]]),
(c, path) => {
  for (const field of ["id", "catalogId", "component"]) {
    if (isJavaBlank(c[field])) {
      refuse(`${path}.${field}`, "a ui component names an id, a catalog, and a component");
    }
  }
  return (c["controls"] as CborValue[]).length <= UI_MAX_CONTROLS;
});
export const UI_ENTRIES = schema("UiDeclaration.Entries", required([["reads", listOf("String")], ["writes", listOf("String")]]));
export const UI_DECLARATION = schema("UiDeclaration", required([["protocol", "String"], ["version", "String"],
  ["components", listOf(UI_COMPONENT)], ["entries", UI_ENTRIES], ["catalogIds", listOf("String")]]));
export const CARD_SPILL = schema("CardSpill", required([["root", "String"], ["size", "long"], ["parts", listOf("String")]]),
(s, path) => {
  if (!isSpillRoot(s["root"])) {
    refuse(`${path}.root`, "not a content root of codec raw over sha2-256");
  }
  const size = Number(s["size"]);
  if (!(size >= 1 && size <= CARD_SPILL_MAX_SIZE)) {
    refuse(`${path}.size`, "lies outside 1 to 2^53 - 1");
  }
  const parts = s["parts"] as string[];
  if (parts.length === 0) {
    refuse(`${path}.parts`, "names at least one field");
  }
  if (new Set(parts).size !== parts.length) {
    refuse(`${path}.parts`, "repeats a name");
  }
  return true;
});
export const AGENT_CARD = schema("AgentCard", required([...AD_HEAD, ["agent", "AgentId"], ["description", "String"],
  ["goals", listOf("String")], ["consumes", listOf("String")], ["produces", listOf("String")],
  ["costHints", mapOf("String")], ["spaceBindings", mapOf("String")], ["agentPublicKey", "bytes", "omitNull"],
  ["actions", listOf(CARD_ACTION), "omitNull"], ["agentCertificate", AGENT_CERTIFICATE, "omitNull"],
  ["ui", UI_DECLARATION, "omitNull"], ["spill", CARD_SPILL, "omitNull"]]),
(card, path) => {
  if (card["spill"] !== undefined) {
    checkStub(card, path, AGENT_CARD_SPILL_SET, []);
  }
  return true;
});
export const AGENT_CARD_PARTS = schema("AgentCard.Parts", [["actions", listOf(CARD_ACTION), "omitNull"],
  ["ui", UI_DECLARATION, "omitNull"]]);
export const APP_CARD_UI = schema("AppCard.Ui", required([["protocol", "String"], ["version", "String"],
  ["catalogIds", listOf("String")], ["agent", "String"], ["transport", enumOf(...APP_CARD_TRANSPORTS)],
  ["surfaces", listOf("String")], ["components", listOf(UI_COMPONENT), "omitEmpty"]]),
(ui, path) => {
  for (const field of ["protocol", "version"]) {
    if (isJavaBlank(ui[field])) {
      refuse(`${path}.${field}`, "blank");
    }
  }
  return (ui["catalogIds"] as CborValue[]).length <= APP_CARD_MAX_TERMS
    && (ui["surfaces"] as CborValue[]).length <= APP_CARD_MAX_TERMS
    && ((ui["components"] as CborValue[] | undefined) ?? []).length <= UI_MAX_COMPONENTS;
});
export const APP_CARD_HOST = schema("AppCard.Host", required([["url", "String"], ["port", "int"], ["hostAgent", "String"],
  ["path", "String"], ["signOn", enumOf(...APP_CARD_SIGN_ONS)], ["publishedBy", "String"], ["publishedAt", "Instant"],
  ["status", enumOf(...APP_CARD_STATUSES)]]),
(h, path) => {
  for (const field of ["url", "path"]) {
    if (isJavaBlank(h[field])) {
      refuse(`${path}.${field}`, "blank");
    }
  }
  return (h["port"] as number) >= 0 && (h["port"] as number) <= 65535;
});
export const APP_CARD_ORIGIN = schema("AppCard.Origin", required([["system", "String"], ["ref", "String"],
  ["version", "String"], ["attrs", mapOf("String"), "omitNull"]]),
(o, path) => {
  const system = o["system"] as string;
  const ref = o["ref"] as string;
  const version = o["version"] as string;
  if (!ORIGIN_SYSTEM.test(system)) {
    refuse(`${path}.system`, `1 to ${ORIGIN_MAX_SYSTEM} of [a-z0-9.-], starting and ending with a letter or digit`);
  }
  if (ref.length === 0 || ref.length > ORIGIN_MAX_REF || CONTROL.test(ref)) {
    refuse(`${path}.ref`, `1 to ${ORIGIN_MAX_REF} code units with no control character`);
  }
  if (version.length > ORIGIN_MAX_VERSION || CONTROL.test(version)) {
    refuse(`${path}.version`, `0 to ${ORIGIN_MAX_VERSION} code units with no control character`);
  }
  const attrs = o["attrs"] as Dict | undefined;
  if (attrs !== undefined) {
    const keys = Object.keys(attrs);
    if (keys.length === 0 || keys.length > ORIGIN_MAX_ATTRS) {
      refuse(`${path}.attrs`, `holds 1 to ${ORIGIN_MAX_ATTRS} entries, or is absent`);
    }
    const prefix = `${system}.`;
    for (const key of keys) {
      if (key.length > ORIGIN_MAX_ATTR_KEY || !key.startsWith(prefix) || !ORIGIN_KEY_TAIL.test(key.slice(prefix.length))) {
        refuse(`${path}.attrs.${key}`, `a key is ${prefix} then [a-z0-9.-]+, at most ${ORIGIN_MAX_ATTR_KEY} code units`);
      }
      const value = attrs[key] as string;
      if (value.length > ORIGIN_MAX_ATTR_VALUE || CONTROL.test(value)) {
        refuse(`${path}.attrs.${key}`, `a value is 0 to ${ORIGIN_MAX_ATTR_VALUE} code units with no control character`);
      }
    }
  }
  return true;
});
const withinTerms = (card: Dict): boolean => ["reads", "actions", "views"]
  .every((field) => (card[field] as CborValue[]).length <= APP_CARD_MAX_TERMS);
export const APP_CARD = schema("AppCard", required([...AD_HEAD, ["name", "String"], ["kind", enumOf(...APP_CARD_KINDS)],
  ["shape", enumOf(...APP_CARD_SHAPES)], ["owner", "String"], ["reads", listOf("String")], ["actions", listOf("String")],
  ["idpClient", "String"], ["url", "String"], ["pkg", "String"], ["version", "String"], ["views", listOf("String")],
  ["ui", APP_CARD_UI, "omitNull"], ["host", APP_CARD_HOST, "omitNull"], ["origin", APP_CARD_ORIGIN, "omitNull"],
  ["formats", listOf("String"), "omitNull"], ["spill", CARD_SPILL, "omitNull"]]),
(card, path) => {
  for (const field of ["name", "version"]) {
    if (isJavaBlank(card[field])) {
      refuse(`${path}.${field}`, "blank");
    }
  }
  if (!withinTerms(card)) {
    refuse(path, `an AppCard carries at most ${APP_CARD_MAX_TERMS} reads, actions, and views`);
  }
  if (card["formats"] !== undefined) {
    checkFormats(card["formats"] as CborValue[], `${path}.formats`);
  }
  const spill = card["spill"] as Dict | undefined;
  if (spill !== undefined) {
    checkStub(card, path, APP_CARD_SPILL_SET, ["reads", "actions", "views"]);
  }
  if (card["shape"] === "a2ui" && card["ui"] === undefined && !((spill?.["parts"] as string[] | undefined) ?? []).includes("ui")) {
    refuse(`${path}.ui`, "an a2ui app names its surfaces in ui");
  }
  return true;
});
export const APP_CARD_PARTS = schema("AppCard.Parts", required([["reads", listOf("String")], ["actions", listOf("String")],
  ["views", listOf("String")], ["ui", APP_CARD_UI, "omitNull"]]), withinTerms);

/** The advertisement types a StoredAd may name, as Java's AdCache registers them; any other is refused. */
export const AD_TYPES: ReadonlyMap<string, Schema> = new Map([
  ["PeerAdvertisement", PEER_ADVERTISEMENT], ["GroupAdvertisement", GROUP_ADVERTISEMENT],
  ["SpaceAdvertisement", SPACE_ADVERTISEMENT], ["CapabilityAdvertisement", CAPABILITY_ADVERTISEMENT],
  ["AgentCard", AGENT_CARD], ["AssetCard", ASSET_CARD], ["ModelCard", MODEL_CARD], ["AppCard", APP_CARD]]);

export const STORED_AD = schema("AdCache.StoredAd", [["adType", "String", "nonNull"], ["adBytes", "bytes", "nonNull"],
  ["publicKey", "bytes", "nonNull"], ["signature", "bytes", "nonNull"]]);
export const AD_CACHE_DELTA = schema("AdCache.Delta", [["ads", listOf(STORED_AD)]]);
export const SIGNED_PEER_AD = schema("PeerNode.SignedPeerAd", [["adBytes", "bytes", "nonNull"],
  ["publicKey", "bytes", "nonNull"], ["signature", "bytes", "nonNull"]]);
export const AD_QUERY = schema("DiscoveryService.AdQuery", [["queryId", "String"], ["asker", "id"], ["adType", "String"],
  ["fieldEquals", mapOf("String")]]);
export const QUERY_HITS = schema("DiscoveryService.QueryHits", [["queryId", "String"], ["hits", listOf(STORED_AD)]]);

export const SIGNED_REVOCATION = schema("RevocationRegistry.SignedRevocation", [["adBytes", "bytes", "nonNull"],
  ["publicKey", "bytes", "nonNull"], ["signature", "bytes", "nonNull"]]);
export const REVOCATION_ADVERTISEMENT = schema("RevocationAdvertisement", required([...AD_HEAD, ["revoked", "id"],
  ["reason", "String"], ["successor", "id", "always"], ["evidence", "bytes", "omitNull"]]));
export const REVOCATION_TARGET = schema("CredentialRevocation.Target", required([["kind", "String"], ["agent", "AgentId", "omitNull"],
  ["keyFingerprint", "bytes", "omitNull"], ["x509Issuer", "String", "omitNull"], ["x509Serial", "String", "omitNull"],
  ["certificateFingerprint", "bytes", "omitNull"], ["credentialHash", "bytes", "omitNull"]]));
export const CREDENTIAL_REVOCATION = schema("CredentialRevocation", required([...AD_HEAD, ["target", REVOCATION_TARGET],
  ["reason", "String"], ["effectiveFrom", "Instant", "omitNull"], ["evidence", "bytes", "omitNull"]]));

export const DELEGATION = schema("JoinCredentials.Delegation", [["founderKey", "bytes"], ["inviteKey", "bytes"],
  ["group", "id"], ["notAfterMillis", "long"], ["label", "String"], ["signature", "bytes"]]);
export const DELEGATED_CREDENTIAL = schema("JoinCredentials.DelegatedCredential", [["delegation", DELEGATION],
  ["signature", "bytes"]]);

export const DOT = schema("Dot", [["replica", "String", "nonNull"], ["counter", "long"]],
  (d) => typeof d["counter"] === "bigint" ? d["counter"] > 0n : (d["counter"] as number) > 0);
export const LEASE_INFO = schema("LeaseInfo", [["holder", "AgentId", "nonNull"], ["expiresAtMillis", "long"],
  ["kind", enumOf("WRITE", "TAKE"), "nonNull"]],
(l) => typeof l["expiresAtMillis"] === "bigint" ? l["expiresAtMillis"] > 0n : (l["expiresAtMillis"] as number) > 0);
export const ENTRY_RECORD = schema("EntryRecord", [["entryId", "id", "nonNull"], ["spaceId", "id", "nonNull"],
  ["type", "String", "nonNull"], ["payload", "bytes"], ["payloadRef", "String"], ["issuer", "AgentId", "nonNull"],
  ["issued", "stamp", "nonNull"], ["lease", LEASE_INFO, "nonNull"], ["tags", mapOf("String"), "nonNull"],
  ["sig", "bytes"], ["keyEpoch", "Long", "omitNull"]],
(r) => (r["payload"] === null) !== (r["payloadRef"] === null)
  && (r["payload"] === null || (r["payload"] as Uint8Array).length <= INLINE_PAYLOAD_LIMIT)
  && (r["keyEpoch"] === undefined || Number(r["keyEpoch"]) >= 1));
export const TAKE_CLAIM = schema("TakeClaim", [["entryId", "id", "nonNull"], ["spaceId", "id", "nonNull"],
  ["epoch", "long"], ["stamp", "stamp", "nonNull"], ["holder", "AgentId", "nonNull"], ["bid", "double"],
  ["expiresAtMillis", "long"]], (c) => (typeof c["epoch"] === "bigint" ? c["epoch"] > 0n : (c["epoch"] as number) > 0)
    && Number.isFinite((c["bid"] as CborDouble).value));
// Java's SignedClaim takes a null claim, key or signature, and verifyClaim drops such a claim
// uncounted, so the state beside it in a delta still merges (HLC round six, 2026-11-08, adversary pass).
export const SIGNED_CLAIM = schema("SpaceWire.SignedClaim", [["claim", TAKE_CLAIM], ["holderKey", "bytes"],
  ["signature", "bytes"], ["holderCertificate", AGENT_CERTIFICATE, "omitNull"]]);
// `signer` is text, as Java's EntryStateDto holds it: a signer that names no agent fails verifyState and
// is dropped uncounted, as Java drops it (HLC round six, 2026-11-08, R5 adversary pass).
export const ENTRY_STATE = schema("SpaceWire.EntryStateDto", [["record", ENTRY_RECORD, "omitNull"],
  ["issuerPublicKey", "bytes"], ["adds", listOf(DOT)], ["removes", listOf(DOT)], ["leaseStamp", "stamp"],
  ["leaseValue", LEASE_INFO], ["completed", "boolean"], ["stateSig", "bytes"],
  ["agentCertificate", AGENT_CERTIFICATE, "omitNull"], ["stateCertificate", AGENT_CERTIFICATE, "omitNull"],
  ["signer", "String", "omitNull"], ["signedAt", "stamp", "omitNull"], ["entryId", "id", "omitNull"]]);
export const SPACE_DELTA = schema("SpaceWire.Delta", [["state", ENTRY_STATE], ["claimEntry", "id"], ["claim", SIGNED_CLAIM]]);
export const SYNC_DELTA = schema("SpaceWire.SyncDelta", [["states", listOf(ENTRY_STATE)], ["claims", mapOf(SIGNED_CLAIM)]]);
export const CLAIM_COMMAND = schema("OrderedTakes.ClaimCommand", [["entryId", "id"], ["claim", TAKE_CLAIM],
  ["holderKey", "bytes"], ["signature", "bytes"], ["holderCertificate", AGENT_CERTIFICATE, "omitNull"]]);

// HLC round seven, 2026-11-08: the records that travel inside PipeFrame.payload (SPEC annex I), read as
// Java's fromWire reads them. GossipLearner.Exchange is absent: this client reads no learner exchange.
// Opaque here: SemHit.adBytes (read on the advertisement path) and a Raft command (a ClaimCommand).
export const AGGREGATE_SHARE = schema("PushSumAggregate.Share", [["epochId", "String"], ["value", "double"],
  ["weight", "double"]]);
export const AGGREGATE_EXTREMUM = schema("PushSumAggregate.Extremum", [["epochId", "String"], ["max", "boolean"],
  ["value", "double"]]);
export const AGGREGATE_HISTOGRAM = schema("PushSumAggregate.Histogram", [["epochId", "String"], ["lo", "double"],
  ["hi", "double"], ["buckets", listOf("double")]]);
export const AGGREGATE_ROSTER = schema("PushSumAggregate.Roster", [["epochId", "String"], ["members", listOf("long")]]);
export const AGGREGATE_FRAME = schema("PushSumAggregate.Frame", [["share", AGGREGATE_SHARE],
  ["extremum", AGGREGATE_EXTREMUM], ["histogram", AGGREGATE_HISTOGRAM], ["roster", AGGREGATE_ROSTER]]);
export const SEM_QUERY = schema("SemanticDiscovery.SemQuery", [["nonce", "long"], ["text", "String"], ["limit", "int"]]);
export const SEM_HIT = schema("SemanticDiscovery.SemHit", [["adType", "String"], ["adBytes", "bytes"],
  ["publicKey", "bytes"], ["signature", "bytes"]]);
export const SEM_RESPONSE = schema("SemanticDiscovery.SemResponse", [["nonce", "long"], ["hits", listOf(SEM_HIT)]]);
export const RAFT_REQUEST_VOTE = schema("RaftMessages.RequestVote", [["term", "long"], ["candidate", "id"],
  ["lastLogIndex", "long"], ["lastLogTerm", "long"]]);
export const RAFT_VOTE_REPLY = schema("RaftMessages.VoteReply", [["term", "long"], ["granted", "boolean"]]);
export const RAFT_LOG_ENTRY = schema("RaftMessages.LogEntry", [["term", "long"], ["command", "bytes"]]);
export const RAFT_APPEND_ENTRIES = schema("RaftMessages.AppendEntries", [["term", "long"], ["leader", "id"],
  ["prevLogIndex", "long"], ["prevLogTerm", "long"], ["entries", listOf(RAFT_LOG_ENTRY)], ["leaderCommit", "long"]]);
export const RAFT_APPEND_REPLY = schema("RaftMessages.AppendReply", [["term", "long"], ["follower", "id"],
  ["success", "boolean"], ["matchIndex", "long"]]);
export const RAFT_CLIENT_SUBMIT = schema("RaftMessages.ClientSubmit", [["command", "bytes"]]);
export const RAFT_FRAME = schema("RaftMessages.Frame", [["requestVote", RAFT_REQUEST_VOTE],
  ["voteReply", RAFT_VOTE_REPLY], ["appendEntries", RAFT_APPEND_ENTRIES], ["appendReply", RAFT_APPEND_REPLY],
  ["clientSubmit", RAFT_CLIENT_SUBMIT]]);
export const RTC_SIGNAL = schema("RtcSignal", [["v", "int"], ["fp", listOf("String"), "omitNull"],
  ["mid", "String", "omitNull"], ["sdp", "String", "omitNull"], ["sid", "bytes"], ["cand", "String", "omitNull"],
  ["code", "Integer", "omitNull"], ["kind", "String"]]);

/** Each body kind's record; a kind absent here carries an empty body (GROUP_AD_WANT) or one this client never reads. */
export const BODIES: ReadonlyMap<string, Schema> = new Map([
  ["PING", PING], ["PING_REQ", PING_REQ], ["ACK", ACK], ["RUMOR", RUMOR], ["DIGEST", DIGEST], ["PULL_RESP", PULL_RESP],
  ["QUERY", AD_QUERY], ["QUERY_HIT", QUERY_HITS], ["BLOCK_WANT", BLOCK_WANT], ["BLOCK", BLOCK],
  ["PIPE_DATA", PIPE_FRAME], ["RELAY_FRAME", RELAY_FRAME], ["CHANNEL_HELLO", CHANNEL_HELLO],
  ["SESSION_HELLO", SESSION_HELLO], ["GROUP_AD", SIGNED_GROUP_ADVERTISEMENT]]);
