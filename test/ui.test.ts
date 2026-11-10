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
 * SPEC §6.1a.3 (v0.1.26; ISSUE-UiComponents FR-6): the ui declaration on an AgentCard in the
 * TypeScript client. The builders emit the Java field order; the golden card with a declaration
 * round-trips byte for byte; a card without one carries no `ui` key.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { dumps, loads } from "../src/cbor.js";
import { appCardHost, uiComponent as uiComponentRecord, uiDeclaration } from "../src/wire.js";

type Dict = { [k: string]: unknown };
const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8")) as { [k: string]: string };   // from build/test, as the other tests
const hex = (name: string) => {
  assert.ok(name in GOLDEN, `golden.json holds ${name}`);   // a missing vector fails, it never skips
  return Uint8Array.from(Buffer.from(GOLDEN[name]!, "hex"));
};
const same = (a: Uint8Array, b: Uint8Array) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

// neutral vectors, 2026-11-09: the example catalog and entry types of golden.json
const SHARED_ITEM = "https://example.org/ns/demo/v1/SharedItem";
const MESSAGE = "https://example.org/ns/demo/v1/Message";

test("the builders emit a declaration in Java field order with the catalogs derived", () => {
  const ui = uiDeclaration([
    uiComponentRecord("share", "example-widgets", "ItemPanel", SHARED_ITEM, ["research"], "panel"),
    uiComponentRecord("ask", "example-widgets", "MessageInput", MESSAGE, [], "control"),
  ], [SHARED_ITEM], [MESSAGE]);
  assert.deepEqual(Object.keys(ui), ["protocol", "version", "components", "entries", "catalogIds"]);
  assert.equal(ui["protocol"], "a2ui");
  assert.deepEqual(Object.keys((ui["components"] as Dict[])[0]), ["id", "catalogId", "component", "entry", "controls", "role"]);
  assert.deepEqual(ui["catalogIds"], ["example-widgets"]);
});

test("the golden card with a declaration round-trips byte for byte", () => {
  const raw = hex("agent_card_ui_cbor");
  const card = loads(raw) as Dict;
  const keys = Object.keys(card);
  assert.equal(keys[keys.length - 1], "ui", "ui is the last key, appended after agentCertificate");
  assert.ok(same(dumps(card as never), raw));
  const ui = card["ui"] as Dict;
  const components = (ui["components"] as Dict[]).map(c => uiComponentRecord(String(c["id"]), String(c["catalogId"]), String(c["component"]),
    String(c["entry"]), c["controls"] as string[], c["role"] as "panel" | "control" | "row"));
  const entries = ui["entries"] as { reads: string[]; writes: string[] };
  const rebuilt = uiDeclaration(components, entries.reads, entries.writes);
  assert.ok(same(dumps(rebuilt as never), dumps(ui as never)), "the TypeScript builder encodes the Java declaration byte for byte");
  const without: Dict = { ...card };
  delete without["ui"];
  assert.ok(!("ui" in (loads(dumps(without as never)) as Dict)));
});

// SPEC §6.1a.4 (v0.1.28, ISSUE-AppHost; v0.1.32, AppCard origin and formats, 2026-11-09): a published AppCard carries
// its host after ui; the builder encodes it byte for byte, signOn idp.
test("the golden app card with a host round-trips byte for byte", () => {
  const raw = hex("app_card_host_cbor");
  const card = loads(raw) as Dict;
  const keys = Object.keys(card);
  assert.deepEqual(keys.slice(-2), ["ui", "host"], "host is appended after ui");
  assert.ok(same(dumps(card as never), raw));
  const host = card["host"] as Dict;
  const rebuilt = appCardHost(String(host["url"]), Number(host["port"]), String(host["hostAgent"]), String(host["path"]), host["signOn"] as "idp" | "none",
    String(host["publishedBy"]), String(host["publishedAt"]), host["status"] as "serving" | "stopped");
  assert.ok(same(dumps(rebuilt as never), dumps(host as never)), "the TypeScript builder encodes the Java host byte for byte");
  assert.equal(host["url"], "https://chat.example.org");
  assert.equal(host["port"], 7801);
  assert.equal(host["signOn"], "idp");
  const without: Dict = { ...card };
  delete without["host"];
  assert.ok(!("host" in (loads(dumps(without as never)) as Dict)));
  assert.throws(() => appCardHost(""), /url/);
  assert.throws(() => appCardHost("http://x", 70000), /port/);
  assert.throws(() => appCardHost("http://x", 0, "", "/", "password" as never), /signOn/);
});
