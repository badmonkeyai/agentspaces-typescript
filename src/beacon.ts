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
import { concat, fromBase64, fromUtf8, toBase64, utf8 } from "./bytes.js";
import { Seed, parseSeed } from "./seed.js";

/** One seed: a transport scheme, `host:port`, and its order. */
export interface BeaconSeed {
  transport: string;
  address: string;
  priority: number;
}

/** One group a beacon has joined. */
export interface BeaconGroup {
  name: string;
  id?: string | null;
  founding?: string | null;
  seeds: BeaconSeed[];
  wire?: { [key: string]: number } | null;
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
  ttl: number;
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

/** A JSON string as Jackson writes it: `"`, `\` and controls escaped (short forms, else `\u00XX`), nothing else. */
function jsonString(text: string): string {
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
    } else {
      out += ch;
    }
  }
  return out + "\"";
}

function jsonInteger(value: unknown, what: string): string {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error(`${what} must be an integer, not ${String(value)}`);
  }
  return String(value);
}

/** An object's fields in the given order, nulls and undefineds omitted. */
function jsonObject(fields: [string, string | null][]): string {
  return "{" + fields.filter(([, v]) => v !== null).map(([k, v]) => jsonString(k) + ":" + v).join(",") + "}";
}

/** A Map<String, X> with its keys sorted, as ORDER_MAP_ENTRIES_BY_KEYS writes it. */
function jsonSortedMap(map: { [key: string]: unknown } | null | undefined,
                       value: (v: unknown, k: string) => string): string | null {
  if (map === null || map === undefined) {
    return null;
  }
  const keys = Object.keys(map).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return "{" + keys.map((k) => jsonString(k) + ":" + value(map[k], k)).join(",") + "}";
}

function optionalString(value: unknown, what: string): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== "string") {
    throw new Error(`${what} must be a string`);
  }
  return jsonString(value);
}

function jsonSeed(seed: BeaconSeed): string {
  return jsonObject([
    ["transport", optionalString(seed.transport, "seed.transport")],
    ["address", optionalString(seed.address, "seed.address")],
    ["priority", jsonInteger(seed.priority, "seed.priority")],
  ]);
}

function jsonGroup(group: BeaconGroup): string {
  if (typeof group.name !== "string") {
    throw new Error("a group needs a name");
  }
  return jsonObject([
    ["name", jsonString(group.name)],
    ["id", optionalString(group.id, "group.id")],
    ["founding", optionalString(group.founding, "group.founding")],
    ["seeds", "[" + (group.seeds ?? []).map(jsonSeed).join(",") + "]"],
    ["wire", jsonSortedMap(group.wire, (v, k) => jsonInteger(v, `wire.${k}`))],
    ["multicast", optionalString(group.multicast, "group.multicast")],
    ["parameters", jsonSortedMap(group.parameters, (v, k) => optionalString(v, `parameters.${k}`) ?? "null")],
    ["invite", optionalString(group.invite, "group.invite")],
  ]);
}

/**
 * BeaconDocument.canonicalBytes: the document without its signature as
 * Jackson writes it (declared field order, no whitespace, sorted maps,
 * nulls omitted). The bytes the issuer signs and a reader verifies.
 */
export function canonicalDocumentBytes(document: BeaconDocument): Uint8Array {
  return utf8(jsonObject([
    ["v", jsonInteger(document.v, "v")],
    ["issuer", optionalString(document.issuer, "issuer")],
    ["issuerKey", optionalString(document.issuerKey, "issuerKey")],
    ["issued", optionalString(document.issued, "issued")],
    ["ttl", jsonInteger(document.ttl, "ttl")],
    ["groups", "[" + (document.groups ?? []).map(jsonGroup).join(",") + "]"],
  ]));
}

/** The document as one-line JSON, signature included: what a beacon serves. */
export function documentJson(document: BeaconDocument): string {
  const canonical = fromUtf8(canonicalDocumentBytes(document));
  if (document.signature === null || document.signature === undefined) {
    return canonical;
  }
  return canonical.slice(0, -1) + ",\"signature\":" + jsonString(document.signature) + "}";
}

/**
 * BeaconDocument.signed: builds and signs a document with the beacon's
 * identity. Here so a TypeScript beacon (or a test) can serve one.
 */
export function signBeaconDocument(issuer: Identity, groups: BeaconGroup[], ttlSeconds = 300,
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

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/**
 * BeaconDocument.parse: reads a document from its JSON, ignoring unknown
 * fields, refusing a version below 1 and a group with a forbidden parameter.
 */
export function parseBeaconDocument(json: string | Uint8Array): BeaconDocument {
  const raw: unknown = JSON.parse(typeof json === "string" ? json : fromUtf8(json));
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("not a beacon document");
  }
  const r = raw as { [key: string]: unknown };
  const v = Number(r["v"] ?? 0);
  if (!Number.isInteger(v) || v < 1) {
    throw new Error(`not a beacon document: v=${String(r["v"])}`);
  }
  const groups: BeaconGroup[] = [];
  for (const g of Array.isArray(r["groups"]) ? r["groups"] : []) {
    if (typeof g !== "object" || g === null) {
      throw new Error("not a beacon document: a group is not an object");
    }
    const group = g as { [key: string]: unknown };
    if (typeof group["name"] !== "string") {
      throw new Error("not a beacon document: a group has no name");
    }
    const seeds: BeaconSeed[] = [];
    for (const s of Array.isArray(group["seeds"]) ? group["seeds"] : []) {
      const seed = (s ?? {}) as { [key: string]: unknown };
      seeds.push({ transport: String(seed["transport"] ?? ""), address: String(seed["address"] ?? ""),
        priority: Number(seed["priority"] ?? 0) });
    }
    const parsed: BeaconGroup = {
      name: group["name"],
      id: asString(group["id"]),
      founding: asString(group["founding"]),
      seeds,
      wire: typeof group["wire"] === "object" && group["wire"] !== null
        ? group["wire"] as { [key: string]: number } : null,
      multicast: asString(group["multicast"]),
      parameters: typeof group["parameters"] === "object" && group["parameters"] !== null
        ? group["parameters"] as { [key: string]: string } : null,
      invite: asString(group["invite"]),
    };
    refuseForbidden(parsed);
    groups.push(parsed);
  }
  return {
    v,
    issuer: asString(r["issuer"]),
    issuerKey: asString(r["issuerKey"]),
    issued: asString(r["issued"]),
    ttl: Number(r["ttl"] ?? 0),
    groups,
    signature: asString(r["signature"]),
  };
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
    const scheme = s.transport.toLowerCase();
    if (!wanted.has(scheme)) {
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
 * Fetches a beacon document and verifies it: `https://` unless `allowPlain`,
 * at most {@link MAX_DOCUMENT_BYTES}, parsed with unknown fields ignored,
 * and the signature verified under the carried key, which must hash to the
 * carried issuer and, when `beaconPeer` pins it, to that PeerId. Rejects on
 * any failure: a reader never acts on an unverified document.
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
    const response = await doFetch(target, {
      signal: controller.signal, redirect: "error", headers: { accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error(`GET ${target} answered ${response.status}`);
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
