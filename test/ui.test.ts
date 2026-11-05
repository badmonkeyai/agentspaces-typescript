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
import { uiComponent as uiComponentRecord, uiDeclaration } from "../src/wire.js";

type Dict = { [k: string]: unknown };
const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8")) as { [k: string]: string };   // from build/test, as the other tests
const hex = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));
const same = (a: Uint8Array, b: Uint8Array) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

const SHARED_OBJECT = "https://badmonkey.ai/ns/apps/v1/SharedObject";
const CHAT_MESSAGE = "https://badmonkey.ai/ns/apps/v1/ChatMessage";

test("the builders emit a declaration in Java field order with the catalogs derived", () => {
  const ui = uiDeclaration([
    uiComponentRecord("ObjectShare", "bma-widgets", "ObjectShare", SHARED_OBJECT, ["research"], "panel"),
    uiComponentRecord("ask", "bma-widgets", "ChatInput", CHAT_MESSAGE, [], "control"),
  ], [SHARED_OBJECT], [CHAT_MESSAGE]);
  assert.deepEqual(Object.keys(ui), ["protocol", "version", "components", "entries", "catalogIds"]);
  assert.equal(ui["protocol"], "a2ui");
  assert.deepEqual(Object.keys((ui["components"] as Dict[])[0]), ["id", "catalogId", "component", "entry", "controls", "role"]);
  assert.deepEqual(ui["catalogIds"], ["bma-widgets"]);
});

test("the golden card with a declaration round-trips byte for byte", { skip: !("agent_card_ui_cbor" in GOLDEN) }, () => {
  const raw = hex(GOLDEN["agent_card_ui_cbor"]);
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
