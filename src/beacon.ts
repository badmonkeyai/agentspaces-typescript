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
 * The beacon document (discovery SRAD §3.5, appendix C): what a beacon
 * serves at `/.well-known/agentspaces/beacon.json` and a social beacon under
 * a lookup code at `/j/<code>`. Per group: the name, the `aspace://` id, the
 * signed founding advertisement (base64 CBOR), the seeds, the wire hints,
 * the multicast group, free parameters, and at a social beacon the public
 * delegation. Document-wide: the issuer PeerId, its raw key, the issue time,
 * a TTL in seconds, and the issuer's Ed25519 signature over the canonical
 * bytes: every field but `signature`, in declared order, no whitespace, map
 * keys sorted, nulls omitted (Jackson's `ORDER_MAP_ENTRIES_BY_KEYS` and
 * `NON_NULL`, reproduced here). A reader ignores unknown fields and refuses
 * a document that carries a content key, a credential, or a membership hint.
 */

import { Identity, deriveId, instantIso } from "./identity.js";
import { concat, equals, fromBase64, fromUtf8, toBase64, utf8 } from "./bytes.js";
import { Seed, parseSeed } from "./seed.js";

/** One seed: a transport scheme, `host:port`, and its order. */
export interface BeaconSeed {
  transport: string | null;
  address: string | null;
  priority: number;
}

/** One group a beacon has joined. */
export interface BeaconGroup {
  name: string;
  id?: string | null;
  founding?: string | null;
  seeds: BeaconSeed[];
  wire?: { [key: string]: number | null } | null;
  multicast?: string | null;
  parameters?: { [key: string]: string } | null;
  invite?: string | null;
}

/** The document. */
export interface BeaconDocument {
  v: number;
  issuer?: string | null;
  issuerKey?: string | null;
  issued?: string | null;
  /** A Java long: a bigint when a float64 cannot hold it exactly. */
  ttl: number | bigint;
  groups: BeaconGroup[];
  signature?: string | null;
}

/** The document version this library writes. */
export const VERSION = 1;
/** The well-known path (RFC 8615 shape). */
export const WELL_KNOWN = "/.well-known/agentspaces/beacon.json";
/** The most bytes a document may be: a beacon serves a few groups, not a dump. */
export const MAX_DOCUMENT_BYTES = 64 * 1024;
/** Parameter names a document never carries. */
export const FORBIDDEN_PARAMETERS = ["content-key", "contentkey", "credential", "membership",
  "hints", "secret", "invite-secret", "join-credential"];

// ----------------------------------------------------------- canonical JSON

/**
 * A JSON string as Jackson writes it: `"`, `\` and controls escaped (short forms, else `\u00XX`),
 * nothing else, except that the signed bytes come from Jackson's byte writer, which writes each
 * UTF-16 surrogate as an upper-case `\uXXXX` escape (HLC round seven, 2026-11-08).
 */
function jsonString(text: string, signed: boolean): string {
  let out = "\"";
  for (const ch of text) {
    const code = ch.codePointAt(0) as number;
    if (ch === "\"") {
      out += "\\\"";
    } else if (ch === "\\") {
      out += "\\\\";
    } else if (code < 0x20) {
      switch (ch) {
        case "\b": out += "\\b"; break;
        case "\t": out += "\\t"; break;
        case "\n": out += "\\n"; break;
        case "\f": out += "\\f"; break;
        case "\r": out += "\\r"; break;
        default: out += "\\u" + code.toString(16).toUpperCase().padStart(4, "0");
      }
    } else if (signed && (code > 0xffff || (code >= 0xd800 && code <= 0xdfff))) {
      for (let i = 0; i < ch.length; i++) {
        out += "\\u" + ch.charCodeAt(i).toString(16).toUpperCase();
      }
    } else {
      out += ch;
    }
  }
  return out + "\"";
}

/** Java's int, the type of `v`, a seed's priority and a wire hint. */
const INT_RANGE = [-(2 ** 31), 2 ** 31 - 1];
/** Java's long, the type of `ttl`. */
const LONG_MIN = -(1n << 63n);
const LONG_MAX = (1n << 63n) - 1n;

/** Whether the value is an integer the Java field holds: an int, or a long when `long`. */
function holdsJavaInteger(value: unknown, long: boolean): value is number | bigint {
  return typeof value === "bigint"
    ? long && value >= LONG_MIN && value <= LONG_MAX
    : typeof value === "number" && (long ? Number.isSafeInteger(value)
      : Number.isInteger(value) && value >= INT_RANGE[0]! && value <= INT_RANGE[1]!);
}

/** An integer the Java field holds (an int, or a long when `long`), as Jackson writes it. */
function jsonInteger(value: unknown, what: string, long = false): string {
  if (!holdsJavaInteger(value, long)) {
    throw new Error(`${what} must be an integer a Java ${long ? "long" : "int"} holds, not ${String(value)}`);
  }
  return String(value);
}

/** An object's fields in the given order, nulls and undefineds omitted. */
function jsonObject(fields: [string, string | null][], signed: boolean): string {
  return "{" + fields.filter(([, v]) => v !== null).map(([k, v]) => jsonString(k, signed) + ":" + v).join(",") + "}";
}

/**
 * A Map<String, X> with its keys sorted, as ORDER_MAP_ENTRIES_BY_KEYS writes it: in String.compareTo
 * order, by UTF-16 code units, which JavaScript's string comparison also uses.
 */
function jsonSortedMap(map: { [key: string]: unknown } | null | undefined, signed: boolean,
                       value: (v: unknown, k: string) => string): string | null {
  if (map === null || map === undefined) {
    return null;
  }
  const keys = Object.keys(map).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return "{" + keys.map((k) => jsonString(k, signed) + ":" + value(map[k], k)).join(",") + "}";
}

function optionalString(value: unknown, what: string, signed: boolean): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== "string") {
    throw new Error(`${what} must be a string`);
  }
  return jsonString(value, signed);
}

/** A seed as Jackson writes the Seed record, which writes a null transport or address. */
function jsonSeed(seed: BeaconSeed, signed: boolean): string {
  return jsonObject([
    ["transport", optionalString(seed.transport, "seed.transport", signed) ?? "null"],
    ["address", optionalString(seed.address, "seed.address", signed) ?? "null"],
    ["priority", jsonInteger(seed.priority, "seed.priority")],
  ], signed);
}

function jsonGroup(group: BeaconGroup, signed: boolean): string {
  if (typeof group.name !== "string") {
    throw new Error("a group needs a name");
  }
  return jsonObject([
    ["name", jsonString(group.name, signed)],
    ["id", optionalString(group.id, "group.id", signed)],
    ["founding", optionalString(group.founding, "group.founding", signed)],
    ["seeds", "[" + (group.seeds ?? []).map((seed) => jsonSeed(seed, signed)).join(",") + "]"],
    ["wire", jsonSortedMap(group.wire, signed, (v, k) => (v === null ? "null" : jsonInteger(v, `wire.${k}`)))],
    ["multicast", optionalString(group.multicast, "group.multicast", signed)],
    ["parameters", jsonSortedMap(group.parameters, signed,
      (v, k) => optionalString(v, `parameters.${k}`, signed) ?? "null")],
    ["invite", optionalString(group.invite, "group.invite", signed)],
  ], signed);
}

/** The document's fields but the signature, in declared order. */
function documentFields(document: BeaconDocument, signed: boolean): [string, string | null][] {
  return [
    ["v", jsonInteger(document.v, "v")],
    ["issuer", optionalString(document.issuer, "issuer", signed)],
    ["issuerKey", optionalString(document.issuerKey, "issuerKey", signed)],
    ["issued", optionalString(document.issued, "issued", signed)],
    ["ttl", jsonInteger(document.ttl, "ttl", true)],
    ["groups", "[" + (document.groups ?? []).map((group) => jsonGroup(group, signed)).join(",") + "]"],
  ];
}

/**
 * BeaconDocument.canonicalBytes: the document without its signature as
 * Jackson's byte writer writes it (declared field order, no whitespace, sorted
 * maps, nulls omitted, each surrogate escaped). The bytes the issuer signs and
 * a reader verifies.
 */
export function canonicalDocumentBytes(document: BeaconDocument): Uint8Array {
  return utf8(jsonObject(documentFields(document, true), true));
}

/**
 * The document as one-line JSON, signature included: what a beacon serves, Java's
 * toBytes, which Jackson's text writer writes, so a code point past U+FFFF stays as it is.
 */
export function documentJson(document: BeaconDocument): string {
  return jsonObject([...documentFields(document, false),
    ["signature", optionalString(document.signature, "signature", false)]], false);
}

/**
 * BeaconDocument.signed: builds and signs a document with the beacon's
 * identity. Here so a TypeScript beacon (or a test) can serve one.
 */
export function signBeaconDocument(issuer: Identity, groups: BeaconGroup[], ttlSeconds: number | bigint = 300,
                                   issuedMillis: number = Date.now()): BeaconDocument {
  for (const group of groups) {
    refuseForbidden(group);
  }
  const unsigned: BeaconDocument = {
    v: VERSION,
    issuer: issuer.peerId,
    issuerKey: toBase64(issuer.publicRaw),
    issued: instantIso(issuedMillis),
    ttl: ttlSeconds,
    groups,
  };
  const signature = issuer.sign(canonicalDocumentBytes(unsigned));
  return { ...unsigned, signature: toBase64(signature) };
}

// ------------------------------------------------------- parse and verify

function refuseForbidden(group: BeaconGroup): void {
  for (const key of Object.keys(group.parameters ?? {})) {
    if (FORBIDDEN_PARAMETERS.includes(key.toLowerCase())) {
      throw new Error(`a beacon document never carries '${key}'`);
    }
  }
}

/*
 * The member readers (SPEC v0.1.32 §9.3, 2026-11-09, the owner's rule that a wrong-typed field is
 * refused in every port): a document, signed or not, refuses a member it names that holds another
 * type than Java's field, as Java's reader does. An absent or null member reads as Java reads it.
 */

/** A text member, or null when absent. */
function textMember(value: unknown, what: string): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== "string") {
    throw new Error(`not a beacon document: ${what} is not text`);
  }
  return value;
}

/** An integer member a Java int holds; absent or null reads as Java's default 0. */
function intMember(value: unknown, what: string): number {
  if (value === null || value === undefined) {
    return 0;
  }
  if (!holdsJavaInteger(value, false)) {
    throw new Error(`not a beacon document: ${what} is no integer a Java int holds`);
  }
  return value as number;
}

/** An integer member a Java long holds, exactly; absent or null reads as 0. */
function longMember(value: unknown, what: string): number | bigint {
  if (value === null || value === undefined) {
    return 0;
  }
  if (!holdsJavaInteger(value, true)) {
    throw new Error(`not a beacon document: ${what} is no integer a Java long holds`);
  }
  return value;
}

/** A list member, empty when absent. */
function listMember(value: unknown, what: string): unknown[] {
  if (value === null || value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(`not a beacon document: ${what} is not an array`);
  }
  return value;
}

/** An object member whose every value meets `check`, or null when absent. */
function mapMember<T>(value: unknown, what: string, check: (v: unknown, what: string) => void):
  { [key: string]: T } | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`not a beacon document: ${what} is not an object`);
  }
  const map = value as { [key: string]: unknown };
  for (const key of Object.keys(map)) {
    check(map[key], `${what}.${key}`);
  }
  return map as { [key: string]: T };
}

/**
 * BeaconDocument.parse: reads a document from its JSON, refusing a version
 * below 1 and a group with a forbidden parameter. An unsigned document reads
 * leniently in form, with whitespace, any member order, and unknown members,
 * while every member it names holds its Java type (SPEC v0.1.32 §9.3,
 * 2026-11-09): a ttl sent as text or a priority sent as 1.0 refuses it, as
 * Java's reader refuses it. A document that carries a signature must
 * be exactly its canonical JSON, {@link documentJson} of what it decodes to
 * (HLC round seven, 2026-11-08, owner ruling F3 applied to the beacon
 * document): the signature covers {@link canonicalDocumentBytes}, which are
 * then the text received less the signature member, so whitespace, another
 * member order, an unknown or repeated member, another escape, or a number in
 * another form refuses the document instead of relabelling it.
 */
export function parseBeaconDocument(json: string | Uint8Array): BeaconDocument {
  const document = readDocument(typeof json === "string" ? json : fromUtf8(json));
  if (document.signature === null) {
    return document;
  }
  // bytes compare as bytes, since decoding drops a byte order mark and repairs ill-formed UTF-8
  const canonical = documentJson(document);
  if (typeof json === "string" ? canonical !== json : !equals(utf8(canonical), json)) {
    throw new Error("a signed beacon document is not its canonical JSON");
  }
  // the signature lies outside the signed bytes, so another text of the same bytes is a relabel
  if (!canonicalBase64(document.signature) || !canonicalBase64(document.issuerKey)) {
    throw new Error("a signed beacon document's signature or key is not canonical base64");
  }
  return document;
}

/**
 * JSON.parse keeping an integer past the float64 safe range as a bigint from its source text (HLC
 * round seven, 2026-11-08), so a ttl a Java long holds and a float64 does not reads exactly. A
 * number written with a fraction or an exponent reads as NaN (2026-11-09), since `1.0` and `1`
 * parse alike and Java's reader holds no such number in an integer member.
 */
function exactIntegers(_key: string, value: unknown, context?: { source?: string }): unknown {
  if (typeof value !== "number") {
    return value;
  }
  const source = context?.source ?? "";
  if (!/^-?\d+$/.test(source)) {
    return Number.NaN;
  }
  return Number.isSafeInteger(value) ? value : BigInt(source);
}

function readDocument(text: string): BeaconDocument {
  const raw: unknown = JSON.parse(text, exactIntegers as (key: string, value: unknown) => unknown);
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("not a beacon document");
  }
  const r = raw as { [key: string]: unknown };
  const v = intMember(r["v"], "v");
  if (v < 1) {
    throw new Error(`not a beacon document: v=${String(r["v"])}`);
  }
  const groups: BeaconGroup[] = [];
  for (const g of listMember(r["groups"], "groups")) {
    if (typeof g !== "object" || g === null || Array.isArray(g)) {
      throw new Error("not a beacon document: a group is not an object");
    }
    const group = g as { [key: string]: unknown };
    if (typeof group["name"] !== "string") {
      throw new Error("not a beacon document: a group has no name");
    }
    const seeds: BeaconSeed[] = [];
    for (const s of listMember(group["seeds"], "seeds")) {
      if (typeof s !== "object" || s === null || Array.isArray(s)) {
        throw new Error("not a beacon document: a seed is not an object");
      }
      const seed = s as { [key: string]: unknown };
      seeds.push({ transport: textMember(seed["transport"], "seed.transport"),
        address: textMember(seed["address"], "seed.address"), priority: intMember(seed["priority"], "seed.priority") });
    }
    const parsed: BeaconGroup = {
      name: group["name"],
      id: textMember(group["id"], "group.id"),
      founding: textMember(group["founding"], "group.founding"),
      seeds,
      wire: mapMember<number | null>(group["wire"], "wire", (value, what) => {
        if (value !== null) {
          intMember(value, what);
        }
      }),
      multicast: textMember(group["multicast"], "group.multicast"),
      parameters: mapMember<string>(group["parameters"], "parameters", (value, what) => textMember(value, what)),
      invite: textMember(group["invite"], "group.invite"),
    };
    refuseForbidden(parsed);
    groups.push(parsed);
  }
  return {
    v,
    issuer: textMember(r["issuer"], "issuer"),
    issuerKey: textMember(r["issuerKey"], "issuerKey"),
    issued: textMember(r["issued"], "issued"),
    ttl: longMember(r["ttl"], "ttl"),
    groups,
    // Jackson reads a number or a boolean as its text, which is then no canonical JSON
    signature: textMember(r["signature"], "the signature"),
  };
}

/** Whether the text is absent or the padded standard base64 of the bytes it decodes to. */
function canonicalBase64(text: string | null | undefined): boolean {
  try {
    return text === null || text === undefined || toBase64(fromBase64(text)) === text;
  } catch {
    return false;
  }
}

/**
 * BeaconDocument.signer: the PeerId the carried key hashes to, when it
 * equals `issuer` and the signature verifies under it over the canonical
 * bytes; null otherwise. A document without a key or a signature has none.
 */
export function documentSigner(document: BeaconDocument): string | null {
  if (!document.issuerKey || !document.signature || !document.issuer) {
    return null;
  }
  try {
    const key = fromBase64(document.issuerKey);
    if (key.length !== 32) {
      return null;
    }
    const signer = deriveId(key);
    if (signer !== document.issuer) {
      return null;
    }
    const signature = fromBase64(document.signature);
    return Identity.verify(key, canonicalDocumentBytes(document), signature) ? signer : null;
  } catch {
    return null;
  }
}

/** Whether the document is its issuer's. */
export function documentVerifies(document: BeaconDocument): boolean {
  return documentSigner(document) !== null;
}

// ------------------------------------------------------------- selection

/** The URI scheme prefix a group id carries. */
const ASPACE = "aspace://";

/** DnsSdLocator.parseId: the bare GroupId of `aspace://<id>[/...]` or `<id>`, or null. */
export function bareGroupId(value: string | null | undefined): string | null {
  if (typeof value !== "string") {
    return null;
  }
  let id = value.trim();
  if (id.toLowerCase().startsWith(ASPACE)) {
    id = id.substring(ASPACE.length);
  }
  const slash = id.indexOf("/");
  if (slash >= 0) {
    id = id.substring(0, slash);
  }
  return id === "" ? null : id;
}

/**
 * The group a reader wants: by `groupId` (the `aspace://` form or the bare
 * id) when given, else by `name`, else the only group the document carries.
 * Throws when nothing matches or the choice is ambiguous.
 */
export function groupFromDocument(document: BeaconDocument,
                                  options: { groupId?: string | null; name?: string | null } = {}): BeaconGroup {
  const wanted = bareGroupId(options.groupId);
  if (wanted !== null) {
    const group = document.groups.find((g) => bareGroupId(g.id) === wanted);
    if (group === undefined) {
      throw new Error(`the beacon document carries no group ${wanted}`);
    }
    return group;
  }
  if (options.name) {
    const group = document.groups.find((g) => g.name === options.name);
    if (group === undefined) {
      throw new Error(`the beacon document carries no group named '${options.name}'`);
    }
    return group;
  }
  if (document.groups.length === 1) {
    return document.groups[0];
  }
  throw new Error(document.groups.length === 0 ? "the beacon document carries no group"
    : `the beacon document carries ${document.groups.length} groups; say which`);
}

/** A seed address parsed: `host:port[/path]`, `[v6]:port[/path]`, or `host` with a default port. */
export function parseSeedAddress(address: string, defaultPort = 7500): Seed {
  return parseSeed(address, defaultPort);
}

/**
 * The group's seeds of one transport (`tcp` by default), in priority order,
 * as `{host, port}` pairs for `Peer.connectAny`.
 */
export function seedsOf(group: BeaconGroup, transport = "tcp"): Seed[] {
  return seedsFor(group, [transport]).map((s) => {
    const { scheme: _scheme, ...rest } = s;
    return rest;
  });
}

/**
 * The group's seeds of every scheme in `schemes`, in ascending priority with
 * the document's order kept among equals (SPEC §5.5), each carrying its
 * scheme. A seed of another scheme is skipped; an unparseable one too.
 */
export function seedsFor(group: BeaconGroup, schemes: Iterable<string>): Seed[] {
  const wanted = new Set([...schemes].map((s) => s.toLowerCase()));
  const out: { seed: Seed; priority: number; index: number }[] = [];
  group.seeds.forEach((s, index) => {
    const scheme = (s.transport ?? "tcp").toLowerCase();
    if (!wanted.has(scheme) || s.address === null) {
      return;
    }
    try {
      out.push({ seed: { ...parseSeed(s.address), scheme }, priority: s.priority, index });
    } catch {
      // an unparseable seed is skipped like a scheme this peer cannot dial
    }
  });
  return out.sort((a, b) => a.priority - b.priority || a.index - b.index).map((o) => o.seed);
}

export interface FetchOptions {
  /** Permit an `http://` URL (tests, a loopback beacon); refused by default. */
  allowPlain?: boolean;
  /** The beacon's PeerId when pinned: the document's verified signer must be it. */
  beaconPeer?: string | null;
  /** How long to wait for the document, milliseconds. */
  timeoutMs?: number;
  /** The fetch to use (a test's stub); the global one by default. */
  fetch?: typeof fetch;
}

/**
 * The beacon did not give a document: the GET failed (the host is down, the name does not
 * resolve, the per-attempt timeout passed) or it answered a status other than 2xx. A caller
 * with time left may ask again; `Peer.bootstrap` does. Every other failure of
 * {@link fetchBeaconDocument} (the scheme policy, the size cap, the shape, the signature,
 * the pin) is a plain `Error` and is a refusal that asking again would not change.
 */
export class BeaconUnavailableError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "BeaconUnavailableError";
  }
}

/**
 * Fetches a beacon document and verifies it: `https://` unless `allowPlain`,
 * at most {@link MAX_DOCUMENT_BYTES}, parsed with unknown fields ignored,
 * and the signature verified under the carried key, which must hash to the
 * carried issuer and, when `beaconPeer` pins it, to that PeerId. Rejects on
 * any failure: a reader never acts on an unverified document. A GET that
 * fails or answers a status other than 2xx rejects with
 * {@link BeaconUnavailableError}.
 */
export async function fetchBeaconDocument(url: string, options: FetchOptions = {}): Promise<BeaconDocument> {
  const target = new URL(url);
  if (target.protocol !== "https:" && !(options.allowPlain && target.protocol === "http:")) {
    throw new Error(`refusing to fetch a beacon document over ${target.protocol.replace(":", "")}`
      + " (set allowPlain for http)");
  }
  const doFetch = options.fetch ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 10_000);
  let bytes: Uint8Array;
  try {
    let response: Response;
    try {
      response = await doFetch(target, {
        signal: controller.signal, redirect: "error", headers: { accept: "application/json" },
      });
    } catch (e) {
      throw new BeaconUnavailableError(`GET ${target} failed: ${e instanceof Error ? e.message : String(e)}`,
        { cause: e });
    }
    if (!response.ok) {
      throw new BeaconUnavailableError(`GET ${target} answered ${response.status}`);
    }
    const declared = Number(response.headers.get("content-length") ?? 0);
    if (declared > MAX_DOCUMENT_BYTES) {
      throw new Error(`the beacon document is ${declared} bytes; at most ${MAX_DOCUMENT_BYTES} is read`);
    }
    bytes = await readCapped(response, MAX_DOCUMENT_BYTES, controller);
  } finally {
    clearTimeout(timer);
  }
  const document = parseBeaconDocument(bytes);
  const signer = documentSigner(document);
  if (signer === null) {
    throw new Error(`the beacon document at ${target} does not verify`);
  }
  if (options.beaconPeer && signer !== options.beaconPeer) {
    throw new Error(`the beacon document at ${target} is signed by ${signer}, not the pinned ${options.beaconPeer}`);
  }
  return document;
}

async function readCapped(response: Response, cap: number, controller: AbortController): Promise<Uint8Array> {
  const body = response.body;
  if (body === null) {
    return new Uint8Array(0);
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > cap) {
      controller.abort();
      throw new Error(`the beacon document exceeds ${cap} bytes`);
    }
    chunks.push(new Uint8Array(value));
  }
  return concat(...chunks);
}
