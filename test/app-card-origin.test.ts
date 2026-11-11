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
 * The AppCard's closed `kind`, its open `origin` and `formats`, and `signOn` as `idp` or `none` in the TypeScript
 * client (SPEC §6.1a.2, §6.1a.4, §6.1b, v0.1.32; ISSUE-AppCardOriginFormats FR-1 to FR-5, FR-8, FR-9; AppCard origin
 * and formats, 2026-11-09). The golden vectors are the contract: the accept vectors read strictly and re-encode byte
 * for byte, and each refusal vector is refused at decode for its own rule. A missing vector fails the suite.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { textOf } from "../src/capabilities/semantic.js";
import { dumps } from "../src/cbor.js";
import * as records from "../src/records.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8")) as { [k: string]: string };
const hex = (name: string): Uint8Array => {
  assert.ok(name in GOLDEN, `golden.json holds ${name}`);
  return Uint8Array.from(Buffer.from(GOLDEN[name]!, "hex"));
};

test("the closed values are the four connection kinds and idp or none", () => {
  assert.deepEqual([...records.APP_CARD_KINDS], ["peer", "fed", "gateway", "assembled"]);
  assert.deepEqual([...records.APP_CARD_SIGN_ONS], ["idp", "none"]);
  assert.deepEqual([...records.APP_CARD_SHAPES], ["web", "desktop", "static", "a2ui"]);
  assert.deepEqual([...records.APP_CARD_TRANSPORTS], ["views", "a2a"]);
  assert.deepEqual([...records.APP_CARD_STATUSES], ["serving", "stopped"]);
  assert.deepEqual([...records.UI_ROLES], ["panel", "control", "row"]);
});

test("the accept vectors read strictly and re-encode byte for byte", () => {
  for (const name of ["app_card_host_cbor", "app_card_origin_formats_cbor", "app_card_spill_cbor"]) {
    const raw = hex(name);
    assert.deepEqual(dumps(records.decodeRecord(raw, records.APP_CARD)), raw, name);
  }
  for (const name of ["agent_card_ui_cbor", "agent_card_spill_cbor"]) {
    const raw = hex(name);
    assert.deepEqual(dumps(records.decodeRecord(raw, records.AGENT_CARD)), raw, name);
  }
});

/** Each refusal vector, the record it is read as, and the rule its refusal names (ISSUE-AppCardOriginFormats §9.6). */
const REFUSALS: Array<[string, records.Schema, RegExp]> = [
  ["adv_app_card_kind_realm_cbor", records.APP_CARD, /^\$\.kind: /],
  ["adv_app_card_sign_on_tenant_cbor", records.APP_CARD, /^\$\.host\.signOn: /],
  ["adv_app_card_formats_empty_cbor", records.APP_CARD, /^\$\.formats: holds 1 to 16/],
  ["adv_app_card_origin_attrs_empty_cbor", records.APP_CARD, /^\$\.origin\.attrs: holds 1 to 8/],
  ["adv_app_card_formats_bound_cbor", records.APP_CARD, /^\$\.formats: holds 1 to 16/],
  ["adv_app_card_formats_upper_cbor", records.APP_CARD, /^\$\.formats\[\d+\]: .*media type/],
  ["adv_app_card_formats_duplicate_cbor", records.APP_CARD, /^\$\.formats: repeats/],
  ["adv_app_card_formats_parameter_cbor", records.APP_CARD, /^\$\.formats\[\d+\]: .*media type/],
  ["adv_app_card_origin_system_cbor", records.APP_CARD, /^\$\.origin\.system: /],
  ["adv_app_card_origin_attrs_prefix_cbor", records.APP_CARD, /^\$\.origin\.attrs\.namespace: /],
  ["adv_app_card_origin_ref_bound_cbor", records.APP_CARD, /^\$\.origin\.ref: /],
  ["adv_app_card_spill_placeholder_cbor", records.APP_CARD, /^\$\.ui: .*stub/],
  ["adv_app_card_spill_parts_order_cbor", records.APP_CARD, /^\$\.spill\.parts: .*order/],
  ["adv_app_card_spill_parts_unknown_cbor", records.APP_CARD, /^\$\.spill\.parts: .*outside/],
  ["adv_app_card_spill_parts_empty_cbor", records.APP_CARD, /^\$\.spill\.parts: .*at least one/],
  ["adv_app_card_spill_root_codec_cbor", records.APP_CARD, /^\$\.spill\.root: /],
  ["adv_app_card_spill_size_zero_cbor", records.APP_CARD, /^\$\.spill\.size: /],
  ["adv_agent_card_spill_actions_cbor", records.AGENT_CARD, /^\$\.actions: .*stub/],
];

test("each refusal vector is refused at decode for its own rule", () => {
  assert.equal(REFUSALS.length, 18);
  for (const [name, schema, reason] of REFUSALS) {
    assert.throws(() => records.decodeRecord(hex(name), schema),
      (e: unknown) => e instanceof records.UndecodableError && reason.test(e.message), name);
  }
});

test("the origin builder rebuilds the vector's origin and stores no empty attrs", () => {
  const card = records.decodeRecord(hex("app_card_origin_formats_cbor"), records.APP_CARD) as Dict;
  // the realm values of SPEC v0.1.33 (REALM.md §5 revision 4): the realm's semver, the form and the specification
  // commit, the realm's commit, the import document's digest, and the app link as url
  const origin = wire.appCardOrigin("realm", "example-realm/example-app", "1.0.0", {
    "realm.namespace": "urn:realm:example-realm#", "realm.format": "yaml@89faba629f66e715421ba0f1b535142e4d2ef3aa",
    "realm.digest": "sha256:ae7219d1e1e24b382d3ffc38aeb92052628db2d0f55d5dc75b3a72fd19965637",
    "realm.commit": "0123456789abcdef0123456789abcdef01234567", "realm.reads": "Item,Order" });
  assert.deepEqual(dumps(origin), dumps(card["origin"]!));
  assert.deepEqual(Object.keys(origin["attrs"] as Dict),
    ["realm.reads", "realm.commit", "realm.digest", "realm.format", "realm.namespace"]);
  assert.equal(card["url"], "app://example-realm/example-app");
  assert.deepEqual(wire.appCardOrigin("console", "example-console/example-board", "", {}),
    { system: "console", ref: "example-console/example-board", version: "" });
  assert.deepEqual(wire.appCardOrigin("com.example.apps", "a/b"), { system: "com.example.apps", ref: "a/b", version: "" });
  assert.throws(() => wire.appCardOrigin("Realm Two", "a"), /origin\.system/);
  assert.throws(() => wire.appCardOrigin("realm", ""), /origin\.ref/);
  assert.throws(() => wire.appCardOrigin("realm", "a", "v".repeat(65)), /origin\.version/);
  assert.throws(() => wire.appCardOrigin("realm", "a", "", { namespace: "x" }), /origin\.attrs\.namespace/);
  assert.throws(() => wire.appCardOrigin("realm", "a", "", { "realm.k": "bad\u0001" }), /origin\.attrs\.realm\.k/);
});

test("the formats normaliser lower-cases media types, keeps the first of a repeat, and stores an empty list as absent", () => {
  assert.deepEqual(wire.appCardFormats(["Text/HTML", "application/geo+json", "text/html", "urn:Realm:X#"]),
    ["text/html", "application/geo+json", "urn:Realm:X#"]);
  assert.equal(wire.appCardFormats([]), null);
  assert.equal(wire.appCardFormats(null), null);
  assert.throws(() => wire.appCardFormats(["text/html;charset=utf-8"]), /media type/);
  assert.throws(() => wire.appCardFormats(Array.from({ length: 17 }, (_, i) => `text/x${i}`)), /holds 1 to 16/);
});

test("fromOrigin and handles read the inline fields, a stub's included", () => {
  const card = records.decodeRecord(hex("app_card_origin_formats_cbor"), records.APP_CARD) as Dict;
  assert.ok(wire.fromOrigin(card, "realm"));
  assert.ok(wire.fromOrigin(card, "realm", "example-realm/example-app"));
  assert.ok(wire.fromOrigin(card, "realm", "example-realm/*"));
  assert.ok(!wire.fromOrigin(card, "realm", "other-realm/*"));
  assert.ok(!wire.fromOrigin(card, "console"));
  assert.ok(wire.handles(card, "application/geo+json"));
  assert.ok(wire.handles(card, "Application/GEO+json"));
  assert.ok(wire.handles(card, "application/*"));
  assert.ok(!wire.handles(card, "image/*"));
  assert.ok(wire.handles(card, "urn:realm:example-realm#"));
  assert.ok(!wire.handles(card, "URN:realm:example-realm#"));
  const stub = records.decodeRecord(hex("app_card_spill_cbor"), records.APP_CARD) as Dict;
  assert.ok(wire.fromOrigin(stub, "console", "example-console/*"));
  assert.ok(!wire.handles(stub, "text/html"), "a card without formats handles nothing");
});

test("the gate strips origin, formats, and an idp host from a level-1 view, and keeps a none host", () => {
  const full = records.decodeRecord(hex("app_card_origin_formats_cbor"), records.APP_CARD) as Dict;
  assert.deepEqual(wire.appCardForView(full, true), full);
  const stripped = wire.appCardForView(full, false);
  assert.ok(!("origin" in stripped) && !("formats" in stripped));
  const hosted = records.decodeRecord(hex("app_card_host_cbor"), records.APP_CARD) as Dict;
  assert.ok(!("host" in wire.appCardForView(hosted, false)), "an idp host never reaches a level-1 reader");
  const open = { ...hosted, host: { ...(hosted["host"] as Dict), signOn: "none" } };
  assert.ok("host" in wire.appCardForView(open, false), "a none host reads at level 1 and stays");
  assert.throws(() => wire.appCardForView(records.decodeRecord(hex("app_card_spill_cbor"), records.APP_CARD) as Dict, false),
    /full card/);
});

test("a host is idp by default and refuses tenant", () => {
  assert.equal(wire.appCardHost("https://chat.example.org")["signOn"], "idp");
  assert.equal(wire.appCardHost("https://chat.example.org", 0, "", "/", "none")["signOn"], "none");
  assert.throws(() => wire.appCardHost("https://chat.example.org", 0, "", "/", "tenant" as never), /idp or none/);
});

test("the semantic text adds the origin's system and ref and every format after the url", () => {
  const card = records.decodeRecord(hex("app_card_origin_formats_cbor"), records.APP_CARD) as Dict;
  assert.equal(textOf("AppCard", card), "example-app fed static example-realm app://example-realm/example-app"
    + " realm example-realm/example-app text/html application/geo+json urn:realm:example-realm#");
  const hosted = records.decodeRecord(hex("app_card_host_cbor"), records.APP_CARD) as Dict;
  assert.equal(textOf("AppCard", hosted), "Support chat fed a2ui support ");
});
