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
 * The GeoFeature of agentspaces-a2ui-geo in the TypeScript client (srad/agentspaces-geo.md §3.1, GEO-F-01).
 * A `GeoFeature` is a GeoJSON Feature (RFC 7946) with the foreign members `schemaVersion`, `kind`, `label`, `style`,
 * `at`, `severity` and `links`, as an `@entry` class whose fields are in Java's declared order, so a feature encodes
 * to the bytes the Java vector pins. `geoFeature` refuses what the Java record refuses, naming the field; `point`,
 * `line` and `polygon` build the usual shapes:
 *
 * ```ts
 * const ship = geo.point("ship-217", "track.ship.cargo", -3.0123, 53.4087, { at: new Date(),
 *   label: "MV Northgate", style: { icon: "ship", heading: 74 } });
 * await space.write(ship, { lease: 300_000, tags: { kind: ship.kind } });
 * ```
 *
 * `at` is a `Date`, or the text Java's `Instant` prints (`"2026-11-12T09:14:03Z"`); the builder writes a `Date` in
 * that text.
 *
 * A position's numbers are JavaScript numbers, so an integral coordinate encodes as a CBOR integer, which a Java
 * reader takes as it takes a double.
 */

import { canonicalMap, type CborValue } from "./cbor.js";
import { isJavaInstant } from "./records.js";
import { entry } from "./space.js";

export const GEO_NAMESPACE = "https://badmonkey.ai/agentspaces/a2ui-geo/v1/";
export const SPACE = "features";
export const MAX_POSITIONS = 10_000;
export const MAX_PROPERTIES_BYTES = 64 * 1024;
export const MAX_LINKS = 64;
export const GEOMETRIES = ["Point", "MultiPoint", "LineString", "MultiLineString", "Polygon", "MultiPolygon"] as const;
export const SEVERITIES = ["info", "warning", "serious", "critical"] as const;
export const ICONS = ["dot", "pin", "truck", "van", "car", "plane", "ship", "person", "arrow"] as const;
const KIND = /^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$/;
const HEX = /^#[0-9a-fA-F]{6}$/;
const RANGES: Record<string, [number, number]> = { opacity: [0, 1], width: [1, 8], size: [1, 64], heading: [0, 360] };

export type Position = number[];
export interface Geometry { type: (typeof GEOMETRIES)[number]; coordinates: unknown }
export interface Link { rel: string; id: string }
export type Style = Partial<{ color: string; fill: string; stroke: string; opacity: number; width: number; icon: (typeof ICONS)[number]; size: number; heading: number }>;

/** An object for a map; build it with `geoFeature`, `point`, `line` or `polygon`. */
@entry(GEO_NAMESPACE + "GeoFeature")
export class GeoFeature {
  schemaVersion = 1;
  type = "Feature";
  id = "";
  geometry: Record<string, unknown> = {};
  properties: Record<string, unknown> = {};
  kind = "";
  label = "";
  style: Record<string, unknown> = {};
  at = "";
  severity?: string;
  links?: Link[];
}

/** A kind's look, named once for an app: the legend's label, a default style and the card's fields. */
@entry(GEO_NAMESPACE + "FeatureKind")
export class FeatureKind {
  schemaVersion = 1;
  kind = "";
  label = "";
  style: Record<string, unknown> = {};
  fields: string[] = [];
}

const isNumber = (v: unknown): v is number => typeof v === "number";

function position(p: unknown): void {
  if (!Array.isArray(p) || p.length < 2 || p.length > 3 || !p.every(isNumber)) {
    throw new RangeError(`a position is [longitude, latitude] or [longitude, latitude, altitude]: ${JSON.stringify(p)}`);
  }
  if (!p.every(Number.isFinite)) throw new RangeError(`a position's numbers are finite: ${p}`);
  if (p[0] < -180 || p[0] > 180) throw new RangeError(`a position's longitude is from -180 to 180: ${p[0]}`);
  if (p[1] < -90 || p[1] > 90) throw new RangeError(`a position's latitude is from -90 to 90: ${p[1]}`);
}

function list(c: unknown, what: string): unknown[] {
  if (!Array.isArray(c) || c.length < 1) throw new RangeError(`${what}'s coordinates are a list of at least 1`);
  return c;
}

function line(c: unknown): void {
  const l = list(c, "a LineString");
  if (l.length < 2) throw new RangeError("a LineString has at least two positions");
  l.forEach(position);
}

function polygon(c: unknown): void {
  for (const ring of list(c, "a Polygon")) {
    const r = list(ring, "a Polygon's ring") as number[][];
    if (r.length < 4) throw new RangeError("a Polygon's ring has at least four positions and is closed (its last is its first)");
    r.forEach(position);
    const first = r[0]!, last = r[r.length - 1]!;
    if (first.length !== last.length || first.some((x, i) => x !== last[i])) throw new RangeError("a Polygon's ring is closed: its last position is its first");
  }
}

function count(c: unknown): number {
  if (Array.isArray(c) && c.length > 0 && isNumber(c[0])) return 1;
  return Array.isArray(c) ? c.reduce((n: number, x) => n + count(x), 0) : 0;
}

/** Refuses a geometry outside RFC 7946 and §3.1, naming what breaks. */
export function checkGeometry(g: Record<string, unknown>): void {
  const t = g?.type;
  if (t === "GeometryCollection") throw new RangeError("a GeoFeature's geometry is not a GeometryCollection; publish one feature per geometry");
  if (typeof t !== "string" || !(GEOMETRIES as readonly string[]).includes(t)) throw new RangeError(`a GeoFeature's geometry.type is one of ${GEOMETRIES.join(", ")}: ${String(t)}`);
  // only the members RFC 7946 gives a geometry: any other would ride past the position and size bounds to every page
  for (const [key, v] of Object.entries(g)) {
    if (key === "bbox") {
      if (!Array.isArray(v) || (v.length !== 4 && v.length !== 6) || !v.every(x => isNumber(x) && Number.isFinite(x))) {
        throw new RangeError(`a GeoFeature's geometry.bbox is 4 or 6 finite numbers: ${JSON.stringify(v)}`);
      }
    } else if (key === "crs") {
      throw new RangeError("a GeoFeature's geometry.crs is reserved: version 1 has none, and its absence means WGS 84");
    } else if (key !== "type" && key !== "coordinates") {
      throw new RangeError(`geometry.${key} is not a geometry member; a geometry has type, coordinates and an optional bbox`);
    }
  }
  const c = g.coordinates;
  switch (t) {
    case "Point": position(c); break;
    case "MultiPoint": list(c, "a MultiPoint").forEach(position); break;
    case "LineString": line(c); break;
    case "MultiLineString": list(c, "a MultiLineString").forEach(line); break;
    case "Polygon": polygon(c); break;
    default: list(c, "a MultiPolygon").forEach(polygon);
  }
  const n = count(c);
  if (n > MAX_POSITIONS) throw new RangeError(`a GeoFeature's geometry has at most 10000 positions: ${n}`);
}

/** Refuses a style outside the closed grammar of §3.1, naming the key. */
export function checkStyle(style: Record<string, unknown>, prefix = "style"): void {
  for (const [k, v] of Object.entries(style)) {
    const where = `${prefix}.${k}`;
    if (k === "color" || k === "fill" || k === "stroke") {
      if (typeof v !== "string" || !HEX.test(v)) throw new RangeError(`${where} is a hex colour #rrggbb: ${String(v)}`);
    } else if (k in RANGES) {
      const [lo, hi] = RANGES[k]!;
      if (!isNumber(v) || !Number.isFinite(v) || v < lo || v > hi) throw new RangeError(`${where} is a number from ${lo} to ${hi}: ${String(v)}`);
    } else if (k === "icon") {
      if (!(ICONS as readonly unknown[]).includes(v)) throw new RangeError(`${where} is one of ${ICONS.join(", ")}: ${String(v)}`);
    } else {
      throw new RangeError(`${where} is not a style key; the keys are color, fill, stroke, opacity, width, icon, size and heading`);
    }
  }
}

function depth(where: string, v: unknown, level: number): void {
  if (Array.isArray(v)) {
    if (level >= 2 && v.some(x => typeof x === "object" && x !== null)) throw new RangeError(`${where} nests past a depth of 2; flatten it`);
    v.forEach(x => depth(where, x, level + 1));
  } else if (typeof v === "object" && v !== null) {
    if (level >= 2 && Object.keys(v).length > 0) throw new RangeError(`${where} nests past a depth of 2; flatten it`);
    for (const [k, x] of Object.entries(v)) depth(`${where}.${k}`, x, level + 1);
  } else if (v !== null && v !== undefined && !["string", "number", "boolean"].includes(typeof v)) {
    throw new RangeError(`${where} is a string, a number, a boolean, a list or an object: ${typeof v}`);
  }
}

function checkKind(kind: unknown, record: string): void {
  if (typeof kind !== "string" || kind.length > 64 || !KIND.test(kind)) throw new RangeError(`a ${record}'s kind is a dotted lower-case name such as track.ship: ${String(kind)}`);
}

/** A value with every map in it, at any depth, in canonical order, as Java's codec writes every map. */
function canonical(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonical);
  if (typeof v === "object" && v !== null) {
    const out: Record<string, CborValue> = {};
    for (const [k, x] of Object.entries(v)) out[k] = canonical(x) as CborValue;
    return canonicalMap(out);
  }
  return v;
}

/**
 * `at` as the text Java's `Instant` prints and reads back to the same bytes: a `Date` is written so, and a string must
 * already be so (`"2026-11-12T09:14:03Z"`, a fraction of 3, 6 or 9 digits only when not zero).
 */
export function instantText(at: string | Date): string {
  if (at instanceof Date) {
    const ms = at.getTime();
    if (!Number.isFinite(ms)) throw new RangeError("a GeoFeature's at is a valid Date");
    const iso = at.toISOString().replace(/\.000Z$/, "Z");
    if (!isJavaInstant(iso)) throw new RangeError(`a GeoFeature's at is in the years 0000 to 9999: ${iso}`);
    return iso;
  }
  if (!isJavaInstant(at)) throw new RangeError(`a GeoFeature's at is an instant as Java prints it, such as 2026-11-12T09:14:03Z: ${String(at)}`);
  return at;
}

/** Whether `v` is non-blank text of at most `most` UTF-16 code units, as Java counts a string's length. */
const text = (v: unknown, most: number): boolean => typeof v === "string" && v.trim().length > 0 && v.length <= most;

export interface FeatureFields {
  schemaVersion?: number; type?: string; id: string; kind: string; geometry: Record<string, unknown>; at: string | Date;
  properties?: Record<string, unknown>; label?: string; style?: Style | Record<string, unknown>; severity?: string; links?: Link[];
}

/** A feature, checked as the Java record checks it. */
export function geoFeature(v: FeatureFields): GeoFeature {
  if ((v.schemaVersion ?? 1) !== 1) throw new RangeError(`a GeoFeature has schemaVersion 1: ${v.schemaVersion}`);
  if ((v.type ?? "Feature") !== "Feature") throw new RangeError(`a GeoFeature's type is Feature, as GeoJSON's: ${v.type}`);
  // eslint-disable-next-line no-control-regex
  if (typeof v.id !== "string" || !v.id.trim() || v.id.length > 128 || /[\x00-\x1f\x7f]/.test(v.id)) {
    throw new RangeError("a GeoFeature's id is 1 to 128 characters with no control character");
  }
  checkKind(v.kind, "GeoFeature");
  checkGeometry(v.geometry);
  const properties = { ...(v.properties ?? {}) };
  // Java's reader refuses a null in a map field, so a feature that held one would never be read
  for (const [k, x] of Object.entries(properties)) {
    if (x === null || x === undefined) throw new RangeError(`properties.${k} is ${x}; leave the key out instead`);
  }
  for (const [k, x] of Object.entries(properties)) depth(`properties.${k}`, x, 1);
  const size = new TextEncoder().encode(JSON.stringify(properties)).length;
  if (size > MAX_PROPERTIES_BYTES) throw new RangeError(`a GeoFeature's properties are at most 64 KiB: ${size} bytes`);
  const label = v.label ?? "";
  // eslint-disable-next-line no-control-regex
  if (label.length > 120 || /[\x00-\x08\x0a-\x1f]/.test(label)) throw new RangeError("a GeoFeature's label is at most 120 characters with no control character");
  const style = { ...(v.style ?? {}) } as Record<string, unknown>;
  checkStyle(style);
  if (!v.at) throw new RangeError("a GeoFeature has an at, an ISO-8601 instant");
  const at = instantText(v.at);
  if (v.severity !== undefined && v.severity !== null && !(SEVERITIES as readonly string[]).includes(v.severity)) {
    throw new RangeError(`a GeoFeature's severity is one of ${SEVERITIES.join(", ")}: ${v.severity}`);
  }
  const links = (v.links ?? []).map(l => {
    if (!text(l.rel, 64)) throw new RangeError("a link's rel is 1 to 64 characters");
    if (!text(l.id, 128)) throw new RangeError("a link's id is 1 to 128 characters");
    return { rel: l.rel, id: l.id };
  });
  if (links.length > MAX_LINKS) throw new RangeError(`a GeoFeature has at most 64 links: ${links.length}`);
  const f = new GeoFeature();
  f.id = v.id;
  f.geometry = canonical(v.geometry) as Record<string, unknown>;
  f.properties = canonical(properties) as Record<string, unknown>;
  f.kind = v.kind;
  f.label = label;
  f.style = canonical(style) as Record<string, unknown>;
  f.at = at;
  if (v.severity === undefined || v.severity === null) delete f.severity; else f.severity = v.severity;
  if (links.length === 0) delete f.links; else f.links = links;
  return f;
}

type Rest = Omit<FeatureFields, "id" | "kind" | "geometry">;

/** A point at a longitude and a latitude, WGS 84. */
export const point = (id: string, kind: string, lon: number, lat: number, rest: Rest): GeoFeature =>
  geoFeature({ ...rest, id, kind, geometry: { type: "Point", coordinates: [lon, lat] } });

/** A line through at least two positions, each [lon, lat]. */
export const lineString = (id: string, kind: string, positions: Position[], rest: Rest): GeoFeature =>
  geoFeature({ ...rest, id, kind, geometry: { type: "LineString", coordinates: positions.map(p => [...p]) } });

/** A polygon: rings of positions, the first the outline, each closed. */
export const polygonOf = (id: string, kind: string, rings: Position[][], rest: Rest): GeoFeature =>
  geoFeature({ ...rest, id, kind, geometry: { type: "Polygon", coordinates: rings.map(r => r.map(p => [...p])) } });

/** The bounds of a feature as [west, south, east, north]. */
export function bounds(f: GeoFeature): [number, number, number, number] {
  const b: [number, number, number, number] = [Infinity, Infinity, -Infinity, -Infinity];
  const walk = (c: unknown): void => {
    if (Array.isArray(c) && c.length > 0 && isNumber(c[0])) {
      b[0] = Math.min(b[0], c[0]); b[1] = Math.min(b[1], c[1]); b[2] = Math.max(b[2], c[0]); b[3] = Math.max(b[3], c[1]);
    } else if (Array.isArray(c)) c.forEach(walk);
  };
  walk(f.geometry.coordinates);
  return b;
}

/** A kind's look, checked as the Java record checks it. */
export function featureKind(v: { kind: string; label?: string; style?: Style; fields?: string[]; schemaVersion?: number }): FeatureKind {
  if ((v.schemaVersion ?? 1) !== 1) throw new RangeError(`a FeatureKind has schemaVersion 1: ${v.schemaVersion}`);
  checkKind(v.kind, "FeatureKind");
  const style = { ...(v.style ?? {}) } as Record<string, unknown>;
  checkStyle(style);
  const k = new FeatureKind();
  k.kind = v.kind;
  k.label = v.label && v.label.trim() ? v.label : v.kind;
  k.style = canonical(style) as Record<string, unknown>;
  k.fields = [...(v.fields ?? [])];
  return k;
}

/** A binding's kind filter: a pattern ending in * takes every kind that starts with what comes before it. */
export const kindMatches = (pattern: string, kind: string): boolean =>
  pattern.endsWith("*") ? kind.startsWith(pattern.slice(0, -1)) : pattern === kind;

/** Whether a FeatureKind covers a feature's kind: the same, or it followed by a dot and more. */
export const covers = (k: FeatureKind, kind: string): boolean => kind === k.kind || kind.startsWith(k.kind + ".");
