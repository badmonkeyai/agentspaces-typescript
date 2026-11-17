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
 * srad/agentspaces-geo.md GEO-F-01: the GeoFeature in the TypeScript client encodes to the bytes of the Java vector of
 * agentspaces-a2ui-geo (copied into test/a2ui-vectors), and its factory refuses what the Java record refuses, naming
 * the field.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { CborDouble, dumps, loads } from "../src/cbor.js";
import { schemaOf, toPayload } from "../src/space.js";
import * as geo from "../src/geo.js";

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, "..", "..", "test", "a2ui-vectors");
const hexOf = (b: Uint8Array) => Buffer.from(b).toString("hex");
const at = "2026-11-12T09:14:03Z";

test("a feature encodes to the Java vector's bytes, and its bytes decode to its fields", () => {
  const json = JSON.parse(readFileSync(join(dir, "geo_feature.json"), "utf8"));
  const hex = readFileSync(join(dir, "geo_feature_cbor.hex"), "utf8").trim();
  assert.equal(hexOf(dumps(toPayload(geo.geoFeature(json)))), hex);
  const plainOf = (x: unknown) => JSON.parse(JSON.stringify(x, (_k, v) => (v instanceof CborDouble ? v.value : v)));
  assert.deepEqual(plainOf(loads(Buffer.from(hex, "hex"))), json, "the bytes decode to the fields (a float64 decodes as a CborDouble)");
  const ship = geo.point("ship-217", "track.ship.cargo", -3.0123, 53.4087, { at, label: "MV Northgate",
    properties: { mmsi: "235012345", speed_kn: 11.2, destination: "Berth 4" }, style: { icon: "ship", color: "#8888cc", heading: 74 },
    severity: "info", links: [{ rel: "bound-for", id: "berth-4" }] });
  assert.equal(hexOf(dumps(toPayload(ship))), hex, "the point builder gives the same bytes");
  assert.equal(schemaOf(geo.GeoFeature), "https://badmonkey.ai/agentspaces/a2ui-geo/v1/GeoFeature");
  assert.equal(schemaOf(geo.FeatureKind), "https://badmonkey.ai/agentspaces/a2ui-geo/v1/FeatureKind");
  const plain = geo.point("a", "k", 0.5, 0.5, { at });
  assert.ok(!("severity" in plain) && !("links" in plain), "absent severity and links are left out, as Java's");
});

test("shapes and bounds", () => {
  const berth = geo.polygonOf("berth-4", "area.berth", [[[-3.01, 53.40], [-3.00, 53.40], [-3.00, 53.41], [-3.01, 53.41], [-3.01, 53.40]]], { at });
  assert.deepEqual(geo.bounds(berth), [-3.01, 53.40, -3.00, 53.41]);
  assert.equal(geo.lineString("r", "route.ferry", [[-3.0, 53.4], [-3.1, 53.45]], { at }).geometry.type, "LineString");
});

test("a feature that breaks a rule is refused by name", () => {
  const cases: Array<[() => unknown, RegExp]> = [
    [() => geo.point("", "track.ship", 0, 0, { at }), /id/],
    [() => geo.point("x".repeat(129), "track.ship", 0, 0, { at }), /id/],
    [() => geo.point("a", "Track Ship", 0, 0, { at }), /kind/],
    [() => geo.point("a", "k", 181, 0, { at }), /longitude/],
    [() => geo.point("a", "k", 0, -91, { at }), /latitude/],
    [() => geo.point("a", "k", NaN, 0, { at }), /finite/],
    [() => geo.lineString("a", "route", [[0, 0]], { at }), /two positions/],
    [() => geo.polygonOf("a", "area", [[[0, 0], [1, 0], [1, 1], [0, 1]]], { at }), /closed/],
    [() => geo.geoFeature({ id: "a", kind: "k", geometry: { type: "GeometryCollection", geometries: [] }, at }), /GeometryCollection/],
    [() => geo.point("a", "k", 0, 0, { at, style: { font: "Comic Sans" } as never }), /style\.font/],
    [() => geo.point("a", "k", 0, 0, { at, style: { color: "url(javascript:x)" } }), /style\.color/],
    [() => geo.point("a", "k", 0, 0, { at, style: { opacity: 2 } }), /style\.opacity/],
    [() => geo.point("a", "k", 0, 0, { at, style: { icon: "skull" } as never }), /style\.icon/],
    [() => geo.point("a", "k", 0, 0, { at, label: "x".repeat(121) }), /label/],
    [() => geo.point("a", "k", 0, 0, { at, severity: "panic" }), /severity/],
    [() => geo.point("a", "k", 0, 0, { at, properties: { a: { b: { c: { d: 1 } } } } }), /depth/],
    [() => geo.point("a", "k", 0, 0, { at, properties: { blob: "x".repeat(70_000) } }), /64 KiB/],
    [() => geo.lineString("a", "route", Array.from({ length: 10_001 }, (_, i) => [i * 0.00001, 0]), { at }), /10000 positions/],
    [() => geo.point("a", "k", 0, 0, { at, links: Array.from({ length: 65 }, (_, i) => ({ rel: "near", id: "f-" + i })) }), /64 links/],
    [() => geo.geoFeature({ schemaVersion: 2, id: "a", kind: "k", geometry: { type: "Point", coordinates: [0, 0] }, at }), /schemaVersion/],
    [() => geo.geoFeature({ type: "FeatureCollection", id: "a", kind: "k", geometry: { type: "Point", coordinates: [0, 0] }, at }), /type/],
    // a geometry holds only type, coordinates and a bbox, so nothing rides past the bounds to a page (GEO-Q-12)
    [() => geo.geoFeature({ id: "a", kind: "k", geometry: { type: "Point", coordinates: [0, 0], blob: "x".repeat(500_000) }, at }), /geometry\.blob/],
    [() => geo.geoFeature({ id: "a", kind: "k", geometry: { type: "Point", coordinates: [0, 0], crs: { type: "name" } }, at }), /geometry\.crs/],
    [() => geo.geoFeature({ id: "a", kind: "k", geometry: { type: "Point", coordinates: [0, 0], bbox: [0, 0, 1] }, at }), /geometry\.bbox/],
    // Java refuses a null property value, so the builder does
    [() => geo.point("a", "k", 0, 0, { at, properties: { eta: null } }), /properties\.eta/],
    [() => geo.point("a", "k", 0, 0, { at, style: { color: null } as never }), /style\.color/],
    // at is an instant as Java prints it
    [() => geo.point("a", "k", 0, 0, { at: "yesterday" }), /at/],
    [() => geo.point("a", "k", 0, 0, { at: "2026-11-12" }), /at/],
    [() => geo.point("a", "k", 0, 0, { at: "2026-11-12T09:14:03.000Z" }), /at/],
    [() => geo.point("a", "k", 0, 0, { at: new Date(NaN) }), /valid Date/],
    // a link's rel and id are non-blank
    [() => geo.point("a", "k", 0, 0, { at, links: [{ rel: " ", id: "x" }] }), /rel/],
    [() => geo.point("a", "k", 0, 0, { at, links: [{ rel: "near", id: "  " }] }), /link's id/],
    [() => geo.point("a", "k", 0, 0, { at, links: [{ rel: "near", id: "\u{1F6A2}".repeat(100) }] }), /link's id/],
  ];
  for (const [make, match] of cases) assert.throws(make, match);
});

test("a feature kind names a look once", () => {
  const k = geo.featureKind({ kind: "track.ship", label: "Ships", style: { icon: "ship", color: "#8888cc" }, fields: ["mmsi"] });
  assert.ok(geo.covers(k, "track.ship.cargo") && !geo.covers(k, "track.shipyard"));
  assert.ok(geo.kindMatches("track.ship*", "track.ship.cargo") && geo.kindMatches("area.berth", "area.berth") && !geo.kindMatches("area.berth", "area.berths"));
  assert.throws(() => geo.featureKind({ kind: "track.ship", style: { color: "blue" } }), /style\.color/);
});

test("a feature kind encodes to the Java vector's bytes", () => {
  const json = JSON.parse(readFileSync(join(dir, "feature_kind.json"), "utf8"));
  const hex = readFileSync(join(dir, "feature_kind_cbor.hex"), "utf8").trim();
  assert.equal(hexOf(dumps(toPayload(geo.featureKind(json)))), hex);
});

test("at is written as Java prints an instant", () => {
  const atOf = (a: string | Date) => geo.point("a", "k", 0, 0, { at: a }).at;
  assert.equal(atOf(new Date(Date.UTC(2026, 10, 12, 9, 14, 3))), "2026-11-12T09:14:03Z");
  assert.equal(atOf(new Date(Date.UTC(2026, 10, 12, 9, 14, 3, 250))), "2026-11-12T09:14:03.250Z");
  assert.equal(atOf("2026-11-12T09:14:03.123456Z"), "2026-11-12T09:14:03.123456Z");
});

test("a geometry may carry a bbox", () => {
  const f = geo.geoFeature({ id: "a", kind: "k", geometry: { type: "Point", coordinates: [1, 2], bbox: [1, 2, 1, 2] }, at });
  assert.deepEqual(f.geometry.bbox, [1, 2, 1, 2]);
});
