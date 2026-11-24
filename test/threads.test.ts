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
 * SPEC §6.1 (v0.1.38): an AgentCard's `threads`, the conversations its agent answers, in the TypeScript client. The
 * accept vector reads strictly and re-encodes byte for byte; each refusal vector is refused at decode for its own
 * rule; an empty list is the absent field, so a card without threads keeps its v0.1.37 bytes. A missing vector fails.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { Binder, agent, chatThread as chatThreadDecl } from "../src/agents.js";
import { dumps, loads } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import * as records from "../src/records.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8")) as { [k: string]: string };
const hex = (name: string): Uint8Array => {
  assert.ok(name in GOLDEN, `golden.json holds ${name}`);   // a missing vector fails, it never skips
  return Uint8Array.from(Buffer.from(GOLDEN[name]!, "hex"));
};

test("the threads vector reads strictly, re-encodes byte for byte, and is the ui card with three threads", () => {
  const raw = hex("agent_card_threads_cbor");
  const card = records.decodeRecord(raw, records.AGENT_CARD) as Dict;
  assert.deepEqual(dumps(card), raw);
  const keys = Object.keys(loads(raw) as Dict);
  assert.equal(keys[keys.length - 1], "threads", "threads is the last key, appended after spill");
  assert.deepEqual(card["threads"], [
    { space: "conversations", key: "main", scope: "tree" },
    { space: "conversations", key: "agent-research", scope: "exact" },
    { space: "findings", key: "", scope: "all" },
  ]);
  const rebuilt = [wire.chatThread("conversations", "main", "tree"), wire.chatThread("conversations", "agent-research"),
    wire.chatThread("findings", "", "all")];
  assert.deepEqual(dumps(rebuilt), dumps(card["threads"]!), "the builder encodes the Java threads byte for byte");
  const without: Dict = { ...card };
  delete without["threads"];
  assert.deepEqual(dumps(records.conform(without, records.AGENT_CARD)), hex("agent_card_ui_cbor"));
});

/** Each refusal vector and the rule its refusal names. */
const REFUSALS: Array<[string, RegExp]> = [
  ["adv_agent_card_threads_scope_cbor", /^\$\.threads\[\d+\]\.scope: /],
  ["adv_agent_card_threads_all_key_cbor", /^\$\.threads\[\d+\]\.key: empty when the scope is all/],
  ["adv_agent_card_threads_key_cbor", /^\$\.threads\[\d+\]\.key: 1 to 128/],
  ["adv_agent_card_threads_count_cbor", /^\$\.threads: names at most 16/],
  ["adv_agent_card_threads_twice_cbor", /^\$\.threads: repeats/],
  ["adv_agent_card_threads_empty_cbor", /threads/],
];

test("each threads refusal vector is refused at decode for its own rule", () => {
  for (const [name, reason] of REFUSALS) {
    assert.throws(() => records.decodeRecord(hex(name), records.AGENT_CARD),
      (e: unknown) => e instanceof records.UndecodableError && reason.test(e.message), name);
  }
});

test("an empty threads list is the absent field: the builder omits it and a reader refuses it written", () => {
  const identity = Identity.generate();
  const args: [string, Identity, string, string, string, string, string[], string[], string[], Dict, Dict] =
    ["zThreads", identity, "chat", "2026-11-23T00:00:00Z", "PT10M", "chats", [], [], [], {}, {}];
  const plain = wire.agentCard(...args);
  const empty = wire.agentCard(...args, null, null, null, null, []);
  assert.ok(!("threads" in empty));
  assert.deepEqual(dumps(records.conform(empty, records.AGENT_CARD)), dumps(records.conform(plain, records.AGENT_CARD)));
  assert.throws(() => records.decodeRecord(dumps({ ...plain, threads: [] }), records.AGENT_CARD),
    (e: unknown) => e instanceof records.UndecodableError && /^\$\.threads: written empty/.test(e.message));
  const one = wire.agentCard(...args, null, null, null, null, [wire.chatThread("conversations", "main")]);
  assert.deepEqual(Object.keys(one).slice(-1), ["threads"]);
  assert.deepEqual((records.decodeRecord(dumps(records.conform(one, records.AGENT_CARD)), records.AGENT_CARD) as Dict)["threads"],
    [{ space: "conversations", key: "main", scope: "exact" }]);
});

test("the builders refuse what a reader refuses", () => {
  assert.throws(() => wire.chatThread("", "main"), /thread\.space/);
  assert.throws(() => wire.chatThread("my space", "main"), /thread\.space/);
  assert.throws(() => wire.chatThread("s".repeat(129), "main"), /thread\.space/);
  assert.throws(() => wire.chatThread("conversations", "", "tree"), /thread\.key/);
  assert.throws(() => wire.chatThread("conversations", "a\tb"), /thread\.key/);
  assert.throws(() => wire.chatThread("conversations", "main", "all"), /thread\.key/);
  assert.throws(() => wire.chatThread("conversations", "main", "branch" as never), /thread\.scope/);
  assert.doesNotThrow(() => wire.chatThread("s".repeat(128), "k".repeat(128)));
  const identity = Identity.generate();
  const args: [string, Identity, string, string, string, string, string[], string[], string[], Dict, Dict] =
    ["zThreads", identity, "chat", "2026-11-23T00:00:00Z", "PT10M", "chats", [], [], [], {}, {}];
  const t = wire.chatThread("conversations", "main");
  assert.throws(() => wire.agentCard(...args, null, null, null, null, [t, { ...t }]), /repeats/);
  const many = Array.from({ length: 17 }, (_, i) => wire.chatThread("conversations", `k${i}`));
  assert.throws(() => wire.agentCard(...args, null, null, null, null, many), /at most 16/);
});

@chatThreadDecl({ space: "findings" })
@chatThreadDecl({ space: "conversations", key: "main", scope: "tree" })
@agent("chatter", { description: "Chats", goals: [] })
class Chatter {}

@agent("quiet", { description: "Quiet", goals: [] })
class Quiet {}

test("the binder lists a decorated agent's threads on its card, and none when it declares none", async () => {
  const peer = new Peer(Identity.generate(), "zThreads");
  const binder = new Binder(peer, { agentName: "chatter" });
  const chatter = binder.bind(new Chatter());
  const quiet = binder.bind(new Quiet());
  try {
    assert.deepEqual(chatter.card!["threads"], [
      { space: "conversations", key: "main", scope: "tree" },
      { space: "findings", key: "", scope: "all" },
    ]);
    assert.ok(!("threads" in quiet.card!));
  } finally {
    await chatter.close();
    await quiet.close();
    peer.close();
  }
});
