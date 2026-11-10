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
 * The AppCard level and the card spill in the TypeScript client (SPEC §6.1a.2, §6.1a.5, §9, v0.1.32;
 * ISSUE-AppCardOriginFormats FR-6, FR-7, FR-12 to FR-15, §9.8; AppCard origin and formats, 2026-11-09). The hint
 * `wire.appcard=2` opens the gate; above 65,536 bytes a card behind an open gate travels as a stub whose parts
 * document sits on the content swarm, and a reader resolves it on demand. The golden stubs and parts documents pin
 * the shapes and the root.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import * as c from "../src/capabilities/content.js";
import { dumps } from "../src/cbor.js";
import { instantIso, parseInstantMillis } from "../src/identity.js";
import { APPCARD_HINT, APPCARD_LEVEL, SpillRefusedError, appCardLevelOf } from "../src/peer.js";
import * as records from "../src/records.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import { Network, fleet, node, run } from "./content-fleet.js";
import type { Node } from "./content-fleet.js";

const GROUP = "zTypeScriptCardSpill";
const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8")) as { [k: string]: unknown };
const hex = (name: string): Uint8Array => {
  assert.ok(name in GOLDEN, `golden.json holds ${name}`);
  return Uint8Array.from(Buffer.from(String(GOLDEN[name]), "hex"));
};
const decode = (name: string, schema: records.Schema): Dict => records.decodeRecord(hex(name), schema) as Dict;
const size = (schema: records.Schema, card: Dict): number => dumps(records.conform(card, schema)).length;

// ------------------------------------------------------------------ vectors

test("the constants are the golden values and Java's", () => {
  assert.equal(wire.CARD_SPILL_THRESHOLD_BYTES, GOLDEN["card_spill_threshold_bytes"]);
  assert.equal(wire.CARD_SPILL_WARN_BYTES, GOLDEN["card_spill_warn_bytes"]);
  assert.equal(wire.CARD_SPILL_PIECE_SIZE, 65_536);
  assert.equal(wire.CARD_SPILL_MAX_FETCH_BYTES, 16_777_216);
  assert.equal(records.CARD_SPILL_ROOT_LENGTH, 59);
  assert.deepEqual([...records.APP_CARD_SPILL_SET], ["reads", "actions", "views", "ui"]);
  assert.deepEqual([...records.AGENT_CARD_SPILL_SET], ["actions", "ui"]);
});

test("each parts document reads strictly and its root over 65,536-byte pieces is its stub's root", () => {
  for (const [stubName, partsName, stubSchema, partsSchema] of [
    ["app_card_spill_cbor", "app_card_parts_cbor", records.APP_CARD, records.APP_CARD_PARTS],
    ["agent_card_spill_cbor", "agent_card_parts_cbor", records.AGENT_CARD, records.AGENT_CARD_PARTS],
  ] as const) {
    const document = hex(partsName);
    assert.deepEqual(dumps(records.decodeRecord(document, partsSchema)), document, partsName);
    const spill = decode(stubName, stubSchema)["spill"] as Dict;
    assert.equal(c.contentRoot(c.hashPieces(document, wire.CARD_SPILL_PIECE_SIZE)), spill["root"], stubName);
    assert.equal(spill["size"], document.length, stubName);
  }
});

test("completing a golden stub and stubbing the full card again give the vectors byte for byte", () => {
  for (const [stubName, partsName, stubSchema, partsSchema] of [
    ["app_card_spill_cbor", "app_card_parts_cbor", records.APP_CARD, records.APP_CARD_PARTS],
    ["agent_card_spill_cbor", "agent_card_parts_cbor", records.AGENT_CARD, records.AGENT_CARD_PARTS],
  ] as const) {
    const stub = decode(stubName, stubSchema);
    const full = wire.cardComplete(stub, decode(partsName, partsSchema));
    assert.ok(!("spill" in full));
    assert.deepEqual(dumps(records.conform(wire.cardParts(full), partsSchema)), hex(partsName), partsName);
    assert.deepEqual(dumps(records.conform(wire.cardStub(full, stub["spill"] as Dict), stubSchema)), hex(stubName), stubName);
  }
  const app = decode("app_card_spill_cbor", records.APP_CARD);
  const full = wire.cardComplete(app, decode("app_card_parts_cbor", records.APP_CARD_PARTS));
  assert.deepEqual(full["reads"], ["zApps/items", "zApps/orders"]);
  assert.throws(() => wire.cardStub(full, { ...(app["spill"] as Dict), parts: ["reads", "ui"] }), /every non-empty part/);
  assert.throws(() => wire.cardComplete(full, wire.cardParts(full)), /only a stub completes/);
  assert.throws(() => wire.cardParts(app), /resolve the card first/);
  assert.throws(() => wire.cardComplete(app, { reads: [], actions: [], views: ["v"] }), /holds \[views\]/);
});

// ------------------------------------------------------------------ the hint

test("the hint is canonical decimal text, read as a level, and a peer advertises level 2 unless told 1", () => {
  assert.equal(APPCARD_HINT, "wire.appcard");
  assert.equal(APPCARD_LEVEL, 2);
  for (const [text, level] of [[undefined, 1], ["", 1], ["2", 2], ["02", 1], ["1", 1], ["0", 1], ["x", 1], ["2 ", 1],
    ["10", 10], ["1234567890", 2_147_483_647]] as Array<[string | undefined, number]>) {
    assert.equal(appCardLevelOf(text), level, String(text));
  }
  const [a, b] = fleet(2, GROUP) as [Node, Node];
  assert.equal((b.peer.members.get(a.peer.identity.peerId)!["resourceHints"] as Dict)[APPCARD_HINT], "2");
  a.peer.appCardLevel = 1;
  a.peer.introduce();
  assert.ok(!(APPCARD_HINT in (b.peer.members.get(a.peer.identity.peerId)!["resourceHints"] as Dict)));
  assert.throws(() => { a.peer.appCardLevel = 3; }, /levels 1 to 2/);
});

// ------------------------------------------------------------------ publishing

/** An AgentCard of A's whose one action's description takes the card's encoding to `target` bytes. */
function agentCardOf(peer: Node["peer"], target: number, name = "researcher"): Dict {
  const build = (pad: number): Dict => wire.agentCard(GROUP, peer.identity, name, instantIso(peer.now() - (peer.now() % 1000)),
    "PT10M", "Researches a topic", ["research"], ["Task"], ["Finding"], {}, { Task: "tasks" }, null,
    [wire.cardAction("research", "d".repeat(pad), ["Task"], ["Finding"], "take", "tasks")]);
  let pad = Math.max(0, target - size(records.AGENT_CARD, build(0)));
  while (size(records.AGENT_CARD, build(pad)) > target) {
    pad -= 1;
  }
  assert.equal(size(records.AGENT_CARD, build(pad)), target, "the padding reaches the target exactly");
  return build(pad);
}

const held = (n: Node, id: unknown): Dict => n.peer.ads.get(String(id))!.ad;

test("a card of 65,536 bytes travels inline and one of 65,537 travels as a stub every member holds", () => {
  const [a, b] = fleet(2, GROUP) as [Node, Node];
  const inline = agentCardOf(a.peer, wire.CARD_SPILL_THRESHOLD_BYTES, "edge");
  a.peer.publishAd("AgentCard", inline);
  assert.ok(!("spill" in held(b, inline["id"])));
  const big = agentCardOf(a.peer, wire.CARD_SPILL_THRESHOLD_BYTES + 1);
  a.peer.publishAd("AgentCard", big);
  const stub = held(b, big["id"]);
  assert.deepEqual(stub["spill"] && (stub["spill"] as Dict)["parts"], ["actions"]);
  assert.ok(!("actions" in stub));
  assert.ok(c.isRoot((stub["spill"] as Dict)["root"]));
  assert.deepEqual(held(a, big["id"]), stub, "the issuer's own cache holds the stub");
  assert.equal(a.peer.cardsSpilled, 1);
  assert.equal(a.peer.cardsOversizeInline, 0);
});

test("a reader resolves a stub over the content swarm and a full card as itself", async () => {
  const [a, b] = fleet(2, GROUP) as [Node, Node];
  const big = agentCardOf(a.peer, 70_000);
  a.peer.publishAd("AgentCard", big);
  const stub = held(b, big["id"]);
  const resolving = b.peer.resolve(stub);
  run([a, b]);
  const full = await resolving;
  assert.deepEqual(dumps(records.conform(full, records.AGENT_CARD)), dumps(records.conform(
    { ...big, issued: stub["issued"] }, records.AGENT_CARD)));
  assert.equal(await b.peer.resolve(full), full);
  assert.equal(b.peer.spillsRefused + b.peer.spillsOverLimit, 0);
});

test("a publisher warns once per id and size past 57,344 bytes and says whether the card spills", () => {
  const [a] = fleet(1, GROUP) as [Node];
  const warnings: string[] = [];
  a.peer.onWarning = (message) => warnings.push(message);
  a.peer.publishAd("AgentCard", agentCardOf(a.peer, wire.CARD_SPILL_WARN_BYTES, "quiet"));
  assert.deepEqual(warnings, []);
  const warm = agentCardOf(a.peer, wire.CARD_SPILL_WARN_BYTES + 1, "warm");
  a.peer.publishAd("AgentCard", warm);
  // a refresh a second later encodes to the same size and stays quiet
  a.peer.publishAd("AgentCard", { ...warm, issued: instantIso(parseInstantMillis(warm["issued"]) + 1000) });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, new RegExp(`AgentCard ${String(warm["id"]).replace(/[/.]/g, "\\$&")} encodes to 57345 bytes`));
  assert.match(warnings[0]!, /65536-byte spill threshold/);
  assert.match(warnings[0]!, /travels inline/);
  a.peer.publishAd("AgentCard", agentCardOf(a.peer, 70_000, "warm"));
  assert.equal(warnings.length, 2);
  assert.match(warnings[1]!, /spills its large parts to the content swarm/);
});

/** An AppCard of A's with an origin and formats, and a views list that takes it past `target` bytes when asked. */
function appCardOf(peer: Node["peer"], name: string, views: string[] = []): Dict {
  return { id: `aspace://${GROUP}/app/${peer.identity.peerId}/${name}`, issuer: peer.identity.peerId, group: GROUP,
    issued: instantIso(peer.now() - (peer.now() % 1000)), ttl: "PT10M", name, kind: "fed", shape: "web", owner: "ops",
    reads: [], actions: [], idpClient: "", url: "https://apps.example.org/" + name, pkg: "", version: "1", views,
    origin: wire.appCardOrigin("console", `example-console/${name}`), formats: ["text/html"] };
}

test("a level-1 member closes the gate: the issuer strips the gated fields, keeps a large card inline, and reissues", () => {
  const network = new Network();
  const a = node(network, GROUP);
  const b = node(network, GROUP);
  b.peer.appCardLevel = 1;
  a.peer.introduce();
  b.peer.introduce();
  assert.ok(!a.peer.appCardGateOpen());
  const app = appCardOf(a.peer, "board");
  a.peer.publishAd("AppCard", app);
  const stripped = held(b, app["id"]);
  assert.ok(!("origin" in stripped) && !("formats" in stripped));
  assert.equal(a.peer.appCardsDowngraded, 1);
  const big = agentCardOf(a.peer, 70_000);
  a.peer.publishAd("AgentCard", big);
  assert.ok(!("spill" in held(b, big["id"])), "a closed gate sends a large card inline in full");
  assert.equal(a.peer.cardsOversizeInline, 1);
  assert.equal(a.peer.cardsSpilled, 0);
  // the level-1 member's advertisement shows level 2: the issuer reissues the full cards at once, strictly newer
  b.peer.appCardLevel = 2;
  b.peer.introduce();
  assert.ok(a.peer.appCardGateOpen());
  const restored = held(b, app["id"]);
  assert.deepEqual(restored["origin"], app["origin"]);
  assert.ok(Date.parse(String(restored["issued"])) > Date.parse(String(stripped["issued"])));
  assert.ok("spill" in held(b, big["id"]), "the large card now travels as a stub");
  // a level-1 member joins: every gated card goes out again without the gated fields
  const late = node(network, GROUP);
  late.peer.appCardLevel = 1;
  late.peer.introduce();
  assert.ok(!a.peer.appCardGateOpen());
  assert.ok(!("origin" in held(b, app["id"])));
  assert.ok(!("spill" in held(b, big["id"])));
  assert.equal(a.peer.appCardsDowngraded, 2);
});

test("an issuer at level 1 strips its own cards and reissues them in full when it returns to level 2", () => {
  const [a, b] = fleet(2, GROUP) as [Node, Node];
  a.peer.appCardLevel = 1;
  assert.ok(!a.peer.appCardGateOpen(), "an issuer below the level closes its own gate");
  const app = appCardOf(a.peer, "own");
  a.peer.publishAd("AppCard", app);
  assert.ok(!("origin" in held(b, app["id"])));
  a.peer.appCardLevel = 2;
  assert.deepEqual(held(b, app["id"])["origin"], app["origin"], "the setter reissues the full card at once");
});

test("a level-1 member whose advertisement lapses reopens the gate, and the issuer reissues the full card", () => {
  const clock = { millis: Date.now() };
  const now = (): number => clock.millis;
  const network = new Network();
  const a = node(network, GROUP, undefined, {}, now);
  const b = node(network, GROUP, undefined, {}, now);
  b.peer.appCardLevel = 1;
  a.peer.introduce();
  b.peer.introduce();
  const app: Dict = { ...appCardOf(a.peer, "lapse"), ttl: "PT1H" }; // outlives the member's lease
  a.peer.publishAd("AppCard", app);
  assert.ok(!("origin" in held(a, app["id"])));
  // the member leaves: past its PT10M lease, and heard on no link (the in-memory network is one dial link)
  network.peers.delete(b.peer.identity.peerId);
  (a.peer as unknown as { dialPeers: Set<string> }).dialPeers.delete(b.peer.identity.peerId);
  clock.millis += 11 * 60_000;
  assert.deepEqual(a.peer.expireMembers(), [b.peer.identity.peerId]);
  assert.deepEqual(held(a, app["id"])["origin"], app["origin"]);
});

test("a card that fails its schema is refused at publishAd and never kept for a reissue", () => {
  const network = new Network();
  const a = node(network, GROUP);
  const b = node(network, GROUP);
  a.peer.introduce();
  b.peer.introduce();
  assert.throws(() => a.peer.publishAd("AppCard", { ...appCardOf(a.peer, "old"), kind: "realm" }), /\$\.kind/);
  assert.ok(!a.peer.ads.has(String(appCardOf(a.peer, "old")["id"])));
  const app = appCardOf(a.peer, "kept");
  a.peer.publishAd("AppCard", app);
  b.peer.appCardLevel = 1;
  b.peer.introduce();
  assert.ok(!("origin" in held(b, app["id"])), "the valid card is reissued stripped");
  assert.doesNotThrow(() => { a.peer.appCardLevel = 1; });
});

test("a member heard before its level-1 advertisement: every card issued under the open gate goes out stripped", () => {
  const network = new Network();
  const a = node(network, GROUP);
  const b = node(network, GROUP);
  a.peer.introduce();
  b.peer.introduce();
  const first = appCardOf(a.peer, "first");
  a.peer.publishAd("AppCard", first);
  assert.ok("origin" in held(b, first["id"]));
  const late = node(network, GROUP);
  late.peer.appCardLevel = 1;
  late.peer.pullAds(); // a frame reaches the issuer before the member's advertisement
  const second = appCardOf(a.peer, "second");
  a.peer.publishAd("AppCard", second);
  assert.ok(!("origin" in held(b, second["id"])), "a member without an advertisement counts as level 1");
  late.peer.introduce();
  assert.ok(!("origin" in held(b, first["id"])), "the card issued under the open gate is reissued stripped");
});

test("a withdrawn card is never reissued when the members' level changes", () => {
  const [a, b] = fleet(2, GROUP) as [Node, Node];
  const app = appCardOf(a.peer, "gone");
  a.peer.publishAd("AppCard", app);
  const issued = held(b, app["id"])["issued"];
  a.peer.withdrawAd(String(app["id"]));
  b.peer.appCardLevel = 1;
  b.peer.introduce();
  assert.equal(held(b, app["id"])["issued"], issued, "the last card signed lapses at its ttl");
  assert.ok("origin" in held(b, app["id"]));
});

test("a publisher spills an AppCard's spill set and keeps origin and formats inline", async () => {
  const [a, b] = fleet(2, GROUP) as [Node, Node];
  const views = Array.from({ length: 64 }, (_, i) => `view-${i}-${"v".repeat(1100)}`);
  const app = appCardOf(a.peer, "wall", views);
  a.peer.publishAd("AppCard", app);
  const stub = held(b, app["id"]);
  assert.deepEqual((stub["spill"] as Dict)["parts"], ["views"]);
  assert.deepEqual(stub["views"], []);
  assert.ok(wire.fromOrigin(stub, "console", "example-console/*") && wire.handles(stub, "text/*"));
  const resolving = b.peer.resolve(stub);
  run([a, b]);
  assert.deepEqual((await resolving)["views"], views);
});

test("a card with nothing in its spill set travels inline, however large", () => {
  const [a, b] = fleet(2, GROUP) as [Node, Node];
  const card: Dict = { ...agentCardOf(a.peer, 1000, "verbose"), description: "w".repeat(70_000) };
  delete card["actions"];
  a.peer.publishAd("AgentCard", card);
  assert.ok(!("spill" in held(b, card["id"])));
  assert.equal(a.peer.cardsOversizeInline, 1);
});

test("a peer with no content swarm never spills and fails to resolve a stub", async () => {
  const network = new Network();
  const a = node(network, GROUP);
  a.peer.spillStore = null;
  a.peer.introduce();
  const big = agentCardOf(a.peer, 70_000);
  a.peer.publishAd("AgentCard", big);
  assert.ok(!("spill" in held(a, big["id"])));
  assert.equal(a.peer.cardsOversizeInline, 1);
  await assert.rejects(a.peer.resolve(decode("agent_card_spill_cbor", records.AGENT_CARD)), /no content swarm/);
  assert.equal(a.peer.spillsRefused + a.peer.spillsOverLimit, 0);
});

// ------------------------------------------------------------------ resolution failures

test("a stub above the fetch bound fails before any fetch and counts spillsOverLimit", async () => {
  const [, b] = fleet(2, GROUP) as [Node, Node];
  const stub = decode("agent_card_spill_cbor", records.AGENT_CARD);
  b.peer.spillMaxFetchBytes = 100;
  await assert.rejects(b.peer.resolve(stub), /above the fetch bound of 100/);
  assert.equal(b.peer.spillsOverLimit, 1);
  assert.equal(b.content.fetches.size, 0, "no fetch began");
});

test("a stub whose size is not its document's fails before the pieces arrive and counts spillsRefused", async () => {
  const [a, b] = fleet(2, GROUP) as [Node, Node];
  const big = agentCardOf(a.peer, 70_000);
  a.peer.publishAd("AgentCard", big);
  const stub = held(b, big["id"]);
  const spill = stub["spill"] as Dict;
  const lying = { ...stub, spill: { ...spill, size: Number(spill["size"]) + 1 } };
  await assert.rejects(b.peer.resolve(lying), (e: unknown) => e instanceof SpillRefusedError);
  assert.equal(b.peer.spillsRefused, 1);
  assert.equal(b.content.store.have(String(spill["root"])).size, 0, "not one piece was fetched");
  assert.ok(b.peer.ads.has(String(big["id"])), "the cached stub stays");
});

test("a stub whose size lies fails at once while another fetch of its root waits for pieces", async () => {
  const [a, b] = fleet(2, GROUP) as [Node, Node];
  b.peer.spillStore = new c.ContentSpillStore(b.content, 50);
  const stub = decode("agent_card_spill_cbor", records.AGENT_CARD);
  const spill = stub["spill"] as Dict;
  const root = String(spill["root"]);
  b.content.fetch(root); // a read of the same root that knows no length, begun before the manifest arrived
  a.content.publish(hex("agent_card_parts_cbor"), { pieceSize: wire.CARD_SPILL_PIECE_SIZE });
  const lying = { ...stub, spill: { ...spill, size: Number(spill["size"]) + 1 } };
  await assert.rejects(b.peer.resolve(lying), (e: unknown) => e instanceof SpillRefusedError);
  assert.equal(b.peer.spillsRefused, 1);
});

test("a document that does not complete its stub fails and counts spillsRefused", async () => {
  const [a, b] = fleet(2, GROUP) as [Node, Node];
  const document = hex("app_card_parts_cbor");
  const root = String(a.content.publish(document, { pieceSize: wire.CARD_SPILL_PIECE_SIZE })["root"]);
  const agentStub = { ...decode("agent_card_spill_cbor", records.AGENT_CARD),
    spill: { root, size: document.length, parts: ["actions", "ui"] } };
  const resolving = b.peer.resolve(agentStub);
  run([a, b]);
  await assert.rejects(resolving, /does not complete its stub/);
  assert.equal(b.peer.spillsRefused, 1);
});

test("resolve refuses a document of another length from any store, and counts spillsRefused", async () => {
  const [a] = fleet(1, GROUP) as [Node];
  const stub = decode("agent_card_spill_cbor", records.AGENT_CARD);
  const document = hex("agent_card_parts_cbor");
  a.peer.spillStore = { put: () => { throw new Error("unused"); }, release: () => {},
    get: async () => Uint8Array.from([...document, 0]) };
  await assert.rejects(a.peer.resolve(stub), (e: unknown) => e instanceof SpillRefusedError && /bytes; the stub states/.test(e.message));
  assert.equal(a.peer.spillsRefused, 1);
});

test("a reader resolves the golden stubs against their parts documents into each card's field order", async () => {
  const [a, b] = fleet(2, GROUP) as [Node, Node];
  for (const [stubName, partsName, stubSchema, partsSchema] of [
    ["app_card_spill_cbor", "app_card_parts_cbor", records.APP_CARD, records.APP_CARD_PARTS],
    ["agent_card_spill_cbor", "agent_card_parts_cbor", records.AGENT_CARD, records.AGENT_CARD_PARTS],
  ] as const) {
    a.content.publish(hex(partsName), { pieceSize: wire.CARD_SPILL_PIECE_SIZE });
    const stub = decode(stubName, stubSchema);
    const resolving = b.peer.resolve(stub);
    run([a, b]);
    const full = await resolving;
    const expected = dumps(records.conform(wire.cardComplete(stub, decode(partsName, partsSchema)), stubSchema));
    assert.deepEqual(dumps(full), expected, stubName);
  }
});

/** A memory store that records each root its owner unpins. */
class UnpinLog extends c.MemoryStore {
  readonly unpinned: string[] = [];
  override unpin(root: string): void {
    this.unpinned.push(root);
    super.unpin(root);
  }
}

test("the parts document goes up as application/cbor in 65,536-byte pieces under the card's id, unsealed", () => {
  const [a] = fleet(1, GROUP) as [Node];
  const big = agentCardOf(a.peer, 70_000);
  a.peer.publishAd("AgentCard", big);
  const root = String((held(a, big["id"])["spill"] as Dict)["root"]);
  const m = a.content.manifestOf(root)!;
  assert.equal(m["name"], big["id"]);
  assert.equal(m["mediaType"], "application/cbor");
  assert.equal(m["pieceSize"], wire.CARD_SPILL_PIECE_SIZE);
  assert.equal(m["sealing"], "none");
});

test("the publisher holds a parts document until the last card naming it expires, then releases it", () => {
  const clock = { millis: Date.now() };
  const store = new UnpinLog();
  const a = node(new Network(), GROUP, store, {}, () => clock.millis);
  a.peer.introduce();
  const big = agentCardOf(a.peer, 70_000);
  a.peer.publishAd("AgentCard", big);
  const root = String((held(a, big["id"])["spill"] as Dict)["root"]);
  const sweep = (): void => (a.peer as unknown as { sweepSpills(): void }).sweepSpills();
  clock.millis += 5 * 60_000;
  a.peer.publishAd("AgentCard", { ...big, issued: instantIso(clock.millis - (clock.millis % 1000)) });
  assert.equal(String((held(a, big["id"])["spill"] as Dict)["root"]), root, "a refresh that changes no part reuses the root");
  clock.millis += 6 * 60_000; // the first card has expired, the refresh has not
  sweep();
  assert.deepEqual(store.unpinned, []);
  clock.millis += 5 * 60_000;
  sweep();
  assert.deepEqual(store.unpinned, [root]);
});

test("a document nobody serves fails at the store's deadline, uncounted, and frees its fetch", async () => {
  const [, b] = fleet(2, GROUP) as [Node, Node];
  b.peer.spillStore = new c.ContentSpillStore(b.content, 50);
  await assert.rejects(b.peer.resolve(decode("agent_card_spill_cbor", records.AGENT_CARD)), /not served within 50 ms/);
  assert.equal(b.peer.spillsRefused + b.peer.spillsOverLimit, 0);
  assert.equal(b.content.fetches.size, 0);
});

test("a fetch that expects a length fails on a manifest of another length before any piece arrives", () => {
  const [a, b] = fleet(2, GROUP) as [Node, Node];
  const document = hex("app_card_parts_cbor");
  const root = String(a.content.publish(document, { pieceSize: wire.CARD_SPILL_PIECE_SIZE })["root"]);
  const f = b.content.fetch(root, document.length + 1);
  run([a, b]);
  assert.ok(f.done && !f.complete);
  assert.match(String(f.failure), new RegExp(`the artifact is ${document.length} bytes; the fetch expects ${document.length + 1}`));
  assert.equal(b.content.store.have(root).size, 0);
});

test("the package entry exposes the spill store, its refusal, the hint, and the cache bounds", async () => {
  const client = await import("../src/index.js");
  assert.equal(client.SpillRefusedError, SpillRefusedError);
  assert.equal(client.appCardLevelOf, appCardLevelOf);
  assert.equal(client.APPCARD_HINT, APPCARD_HINT);
  assert.equal(client.APPCARD_LEVEL, APPCARD_LEVEL);
  assert.equal(client.AD_CACHE_MAX_ENTRIES, 8_192);
  assert.equal(client.AD_CACHE_MAX_BYTES, 33_554_432);
  assert.equal(client.capabilities.ContentSpillStore, c.ContentSpillStore);
});
