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
 * ISSUE-A2uiAppComponents FR-11, FR-12, SR-3 (spiral 6 S6-U-26): the open A2UI records in the TypeScript client
 * encode to the bytes of the Java vectors of agentspaces-a2ui (copied into test/a2ui-vectors), each factory refuses
 * what the Java constructor refuses, the hint rule picks the version, and the builders shape the six components as
 * the Java Surfaces does.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { dumps, loads } from "../src/cbor.js";
import { schemaOf, toPayload } from "../src/space.js";
import * as a2ui from "../src/a2ui.js";

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, "..", "..", "test", "a2ui-vectors");
const vector = (name: string) => ({ json: JSON.parse(readFileSync(join(dir, name + ".json"), "utf8")), hex: readFileSync(join(dir, name + "_cbor.hex"), "utf8").trim() });
const hexOf = (b: Uint8Array) => Buffer.from(b).toString("hex");

test("each record encodes to the Java vector's bytes, and its bytes decode to its fields", () => {
  const cases: Array<[string, (j: any) => object]> = [
    ["chat_message_v1", j => a2ui.chatMessage(j)], ["chat_message_v2", j => a2ui.chatMessage(j)],
    ["shared_file_v1", j => a2ui.sharedFile(j)], ["shared_file_v2", j => a2ui.sharedFile(j)],
    ["working_on_v1", j => a2ui.workingOn(j)], ["chat_progress_v1", j => a2ui.chatProgress(j)],
  ];
  for (const [name, make] of cases) {
    const v = vector(name);
    const record = make(v.json);
    assert.equal(hexOf(dumps(toPayload(record))), v.hex, name + " pins the canonical bytes");
    assert.deepEqual(JSON.parse(JSON.stringify(loads(Buffer.from(v.hex, "hex")))), v.json, name + " decodes to its fields");
  }
  assert.equal(schemaOf(a2ui.ChatMessage), "https://badmonkey.ai/agentspaces/a2ui/v1/ChatMessage");
  assert.equal(schemaOf(a2ui.ChatProgress), "https://badmonkey.ai/agentspaces/a2ui/v1/ChatProgress");
  assert.ok(!("format" in a2ui.chatMessage({ id: "m", key: "k", at: "2026-11-10T09:00:00Z" })), "a version 1 line carries no version 2 field");
});

test("a record that breaks a bound is refused (SR-3)", () => {
  const at = "2026-11-10T09:00:00Z";
  assert.throws(() => a2ui.sharedFile({ schemaVersion: 2, id: "f", name: "x", at, path: "a/../b" }), /path must be relative/);
  assert.throws(() => a2ui.sharedFile({ schemaVersion: 2, id: "f", name: "x", at, path: "/etc/passwd" }), /path must be relative/);
  assert.throws(() => a2ui.sharedFile({ id: "f", name: "x", at, path: "a" }), /version 1 SharedFile/);
  assert.throws(() => a2ui.chatMessage({ schemaVersion: 2, id: "m", key: "k", at, cites: Array.from({ length: 17 }, (_, i) => ({ file: "f" + i })) }), /at most 16/);
  assert.throws(() => a2ui.chatMessage({ schemaVersion: 2, id: "m", key: "k", at, format: "text/html" }), /format/);
  assert.throws(() => a2ui.chatProgress({ key: "k", inReplyTo: "m", agent: "a", at, steps: Array.from({ length: 21 }, () => ({ label: "s", kind: "read", at })) }), /at most 20/);
  assert.throws(() => a2ui.chatProgress({ key: "k", inReplyTo: "m", agent: "a", at, state: "thinking" }), /A2A task states/);
  assert.throws(() => a2ui.workingOn({ agent: "a", since: at, task: "x".repeat(121) }), /120 characters/);
  assert.throws(() => a2ui.workingOn({ agent: "a", since: at, files: ["a\\b"] }), /path must be relative/);
});

test("a writer writes version 2 only when every reader advertises the hint (FR-10)", () => {
  assert.equal(a2ui.versionFor([{ "a2ui.records": "2" }, { "a2ui.records": "3" }]), 2);
  assert.equal(a2ui.versionFor([{ "a2ui.records": "2" }, {}]), 1);
  assert.equal(a2ui.versionFor([{ "a2ui.records": "two" }]), 1);
  assert.equal(a2ui.versionFor([]), 2, "no reader but the writer");
});

test("the builders shape the six components as the Java Surfaces does", () => {
  const status = a2ui.titleStatus("/working", "Agent working", "Ready");
  assert.deepEqual(a2ui.titleBar("bar", { path: "/app/title" }, "Claims desk", "briefcase", status, [a2ui.titleAction("share", "Share", "share", "share")], "bar-menu"), {
    id: "bar", component: "TitleBar", title: { path: "/app/title" }, subtitle: "Claims desk", icon: "briefcase", status: { from: "/working", labels: { working: "Agent working", idle: "Ready" } },
    actions: [{ id: "share", label: "Share", icon: "share", action: { name: "share" } }], menu: "bar-menu" });
  assert.deepEqual(Object.keys(a2ui.titleBar("bar", "Workbench")), ["id", "component", "title"]);
  const items = [a2ui.menuItem("new-chat", "New chat", "chat.new", { shortcut: "Ctrl+Shift+O" }), a2ui.submenu("share", "Share", [a2ui.menuItem("copy", "Copy link", "share.link")])];
  assert.deepEqual(a2ui.menu("more", a2ui.trigger("overflow", "More"), items), { id: "more", component: "Menu", trigger: { kind: "overflow", label: "More" }, items: [
    { id: "new-chat", label: "New chat", shortcut: "Ctrl+Shift+O", action: { name: "chat.new" } }, { id: "share", label: "Share", items: [{ id: "copy", label: "Copy link", action: { name: "share.link" } }] }] });
  assert.throws(() => a2ui.submenu("a", "A", [items[1]]), /one level/);
  assert.deepEqual(a2ui.split("main", "horizontal", "workbench-main", 720, [a2ui.pane("left", "tree", 0.25, 180, true, "Files"), a2ui.pane("right", "chat", 0.75)]), {
    id: "main", component: "Split", orientation: "horizontal", persist: "workbench-main", stackBelow: 720,
    panes: [{ id: "left", child: "tree", size: 0.25, min: 180, collapsible: true, label: "Files" }, { id: "right", child: "chat", size: 0.75 }] });
  assert.throws(() => a2ui.split("main", "horizontal", "", 0, [a2ui.pane("a", "x", 1)]), /two or three/);
  assert.deepEqual(a2ui.chat("chat", "workbench", "main", { suggestions: ["Summarise the newest file"], attach: true, format: "text/markdown", controls: ["copy", "retry", "stop", "feedback"], preview: "preview" }), {
    id: "chat", component: "Chat", agent: "workbench", key: "main", attach: true, controls: ["copy", "retry", "stop", "feedback"], format: "text/markdown", preview: "preview", suggestions: ["Summarise the newest file"] });
  assert.deepEqual(Object.keys(a2ui.chat("chat", "", "main")), ["id", "component", "key"]);
  assert.throws(() => a2ui.chat("chat", "a", "main", { controls: ["delete"] }), /controls/);
  assert.throws(() => a2ui.chat("chat", "a", "main", { colour: "red" }), /colour/);
  assert.deepEqual(a2ui.fileTree("tree", "/files", { working: "/working", upload: true, chat: "chat" }), { id: "tree", component: "FileTree", reads: "/files", chat: "chat", upload: true, working: "/working" });
  assert.throws(() => a2ui.fileTree("tree", "/files", { actions: ["burn"] }), /actions/);
  assert.deepEqual(a2ui.filePreview("preview", { path: "/selected/file" }, { files: "/files", csvRows: 500 }), { id: "preview", component: "FilePreview", file: { path: "/selected/file" }, csvRows: 500, files: "/files" });
  assert.throws(() => a2ui.filePreview("preview", "f-1", { maxBytes: 17000000 }), /16 MiB/);
  assert.throws(() => a2ui.filePreview("preview", "f-1", { kinds: ["text/html"] }), /kinds/);
});
