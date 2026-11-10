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
 * PDT 2 phase 7, stores and challenges in TypeScript (srad/agentspaces-pdt2.md §3.2; P2-C-01, P2-S-07, P2-S-11, P2-F-03,
 * §10.9 F1): the `content-store` card of `asset_card_content_store_cbor` with its text values parsed, the choice of
 * stores, a `SignedPin` written by its requester and naming its stores, and the possession challenge of
 * `content_challenge_cbor` answered by a level-2 holder.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { fromHex } from "../src/bytes.js";
import { dumps } from "../src/cbor.js";
import { instantIso } from "../src/identity.js";
import * as records from "../src/records.js";
import * as pdt from "../src/pdt/index.js";
import type { Dict } from "../src/wire.js";
import { closeAll, fleetOf, run } from "./pdt-fleet.js";
import type { Node, V } from "./pdt-fleet.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf8"));
const { stores, storeRecords, tree } = pdt;

test("PDT 2 phase 7: the content-store card of asset_card_content_store_cbor reads strictly and parses its text values (P2-S-01, rule 19)", () => {
  const bytes = fromHex(GOLDEN["asset_card_content_store_cbor"]!);
  const card = records.readRecord(bytes, records.ASSET_CARD)!;
  assert.deepEqual(dumps(card), bytes);
  const read = stores.readStoreCard(card)!;
  assert.deepEqual([read.asset, read.capacity, read.free, read.maxObject, read.blind, read.leaseMax, read.leaseDefault,
    read.copiesMax, read.challenge, read.tier, read.policy, read.price, read.waiting],
  ["content-store:site-a", 2199023255552, 2145336164352, 68719476736, false, 31536000, 2592000, 3, true, "hot", "grant", 2, false]);
  assert.deepEqual([read.codecs, read.hashes, read.sealing, read.pin, read.delegates],
    [["dag-cbor", "raw"], ["sha2-256"], ["none", "sealed-nodes"], ["request", "invoke"], []]);
  const access = card["access"] as Dict;
  assert.equal(stores.readStoreCard({ ...card, access: { ...access, free: "01" } }), null, "no canonical decimal");
  assert.equal(stores.readStoreCard({ ...card, access: { ...access, blind: "yes" } }), null, "no boolean text");
  assert.equal(stores.readStoreCard({ ...card, access: { ...access, kind: "dataset" } }), null, "another kind");
  assert.equal(records.readRecord(dumps({ ...card, access: { ...access, free: 7 } }), records.ASSET_CARD), null,
    "a number in the text map makes the card undecodable for every receiver");
});

const card = (issuer: string, access: Dict, price?: string): pdt.stores.StoreCard => stores.readStoreCard({ issuer, asset: "content-store:x",
  issued: instantIso(1_000_000), ttl: "PT15M", access: { kind: "content-store", free: "1000", maxObject: "1000", blind: "false",
    ...access }, costHints: price === undefined ? {} : { pricePerGibMonth: price } })!;

test("PDT 2 phase 7: a requester chooses the cheapest stores with the most room that fit the root (P2-S-11)", () => {
  const now = 1_000_000;
  const cards = [card("a", { free: "500" }, "1"), card("b", { free: "900" }, "1"), card("c", {}, "0"), card("d", { blind: "true" }),
    card("e", { tier: "cold" }), card("f", { waiting: "authorizer" }), card("g", { free: "50" })];
  const issuers = (need: pdt.stores.Need): string[] => stores.chooseStores(cards, need, now).map((c) => c.issuer);
  assert.deepEqual(issuers({ bytes: 100, copies: 3 }), ["c", "e", "b"], "price, then free, then issuer; blind and waiting skipped");
  assert.deepEqual(issuers({ bytes: 100, copies: 9, sealed: true }), ["c", "d", "e", "b", "a"]);
  assert.deepEqual(issuers({ bytes: 100, copies: 2, tier: "cold" }), ["e"]);
  assert.deepEqual(issuers({ bytes: 100, copies: 9, maxPrice: 0 }), ["c", "e"]);
  assert.deepEqual(issuers({ bytes: 600, copies: 9 }), ["c", "e", "b"]);
  assert.deepEqual(issuers({ bytes: 100, copies: 9, avoid: new Set(["c"]) }), ["e", "b", "a"]);
  assert.deepEqual(stores.chooseStores(cards, { bytes: 1, copies: 1 }, now + 16 * 60_000), [], "an expired card");
});

/** Publishes a store card for a member, as a store peer's connector runtime does. */
function publishStore(n: Node, name: string, access: Dict = {}): void {
  const now = n.peer.now();
  n.peer.publishAd("AssetCard", { id: `aspace://${n.peer.group}/asset/content-store/${name}/${n.peer.identity.peerId}`,
    issuer: n.peer.identity.peerId, group: n.peer.group, issued: instantIso(now - (now % 1000)), ttl: "PT15M",
    asset: `content-store:${name}`, uri: `aspace://${n.peer.group}/store/${name}`, description: "a store", shape: "store",
    freshness: "PT10S", costHints: {}, access: { kind: "content-store", capacity: "1000000", free: "1000000", maxObject: "1000000",
      blind: "false", copiesMax: "3", challenge: "true", ...access } });
}

test("PDT 2 phase 7: storeFor writes one SignedPin its requester signed, naming the chosen store, within the hour (P2-S-11, F1, R2)", async () => {
  const nodes = fleetOf([{}, {}, {}]);
  const [a, s1, s2] = nodes as [Node, Node, Node];
  try {
    publishStore(s1, "one");
    publishStore(s2, "two", { free: "10" });
    await run(nodes, 1);
    const value = pdt.PMap.empty<string, V>(a.pdt.store).assoc("k", "v".repeat(100));
    const root = value.root();
    const requester = new pdt.stores.Stores(a.pdt.exchange!, a.peer.identity);
    assert.equal(requester.cards().length, 2);
    const pinning = requester.storeFor(root, { copies: 1 }, 7 * 24 * 3600);
    assert.deepEqual(pinning.stores.map((c) => c.issuer), [s1.peer.identity.peerId], "the store with room");
    await run(nodes, 2);
    const dto = s1.peer.states.get(pinning.entryId)!;
    const recordOf = dto["record"] as Dict;
    assert.equal(recordOf["type"], storeRecords.SIGNED_PIN_TYPE, "a client writes a SignedPin, never a bare StorePin");
    const signed = storeRecords.decodeSignedPin(s1.peer.payloadOf(dto)!);
    assert.ok(storeRecords.signedPinConsented(signed, a.peer.group));
    const pin = signed["pin"] as Dict;
    assert.deepEqual([pin["root"], pin["kind"], pin["requester"], pin["copies"], (pin["attrs"] as Dict)["pdt.stores"]],
      [root, "tree", a.peer.identity.peerId, 1, s1.peer.identity.peerId]);
    assert.deepEqual(recordOf["tags"], { requester: a.peer.identity.peerId, root });
    const now = a.peer.now();
    assert.ok(Number(signed["notAfter"]) <= now + stores.PIN_ENTRY_LEASE_MILLIS, "a store refuses a deadline past the hour");
    assert.ok(Number((recordOf["lease"] as Dict)["expiresAtMillis"]) <= now + stores.PIN_ENTRY_LEASE_MILLIS + 1000);
    assert.ok(a.pdt.exchange!.heldRoots().includes(root), "the requester holds the tree so the store can fetch it");
    assert.throws(() => requester.storeFor(root, { copies: 1, tier: "glacier" }, 60), /no content store fits/);
  } finally {
    closeAll(nodes);
  }
});

test("PDT 2 phase 7: the challenge of content_challenge_cbor reads strictly, and a level-2 holder answers the picks it holds (P2-S-07, row 15)", async () => {
  const bytes = fromHex(GOLDEN["content_challenge_cbor"]!);
  const challenge = tree.readTreeMessage(bytes)!;
  assert.deepEqual(dumps(challenge), bytes);
  assert.equal((challenge["picks"] as Dict[]).length, 2);
  assert.equal(tree.readTreeMessage(dumps({ ...challenge, picks: [] })), null, "no pick");
  assert.equal(tree.readTreeMessage(dumps({ ...challenge, picks: [{ cid: (challenge["picks"] as Dict[])[1]!["cid"], offset: 0 }] })),
    null, "a pick with an offset and no length");
  const nodes = fleetOf([{}, {}, {}, { level: 1 }]);
  const [a, holder, empty, old] = nodes as [Node, Node, Node, Node];
  try {
    const value = pdt.PMap.empty<string, V>(a.pdt.store).editor();
    for (let i = 0; i < 300; i++) {
      value.assoc(`k${i}`, `value ${i}`);
    }
    const root = value.done().root();
    for (const cid of a.pdt.store.reachable(root)) {
      holder.pdt.store.putVerified(cid, a.pdt.store.get(cid)!);
    }
    const passing = a.pdt.exchange!.challenge(root, holder.peer.identity.peerId);
    await run(nodes, 2);
    const passed = await passing;
    assert.equal(passed.passed, true, String(passed.failure));
    assert.ok(passed.proven > 1 && passed.proven <= tree.MAX_PICKS);
    const failing = a.pdt.exchange!.challenge(root, empty.peer.identity.peerId);
    await run(nodes, 2);
    const failed = await failing;
    assert.equal(failed.passed, false);
    assert.match(failed.failure!, /REJECT reason 1/);
    await assert.rejects(a.pdt.exchange!.challenge(root, old.peer.identity.peerId), /level 1/, "a challenge goes only to level 2");
  } finally {
    closeAll(nodes);
  }
});
