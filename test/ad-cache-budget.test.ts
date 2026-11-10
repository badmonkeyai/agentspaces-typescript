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
 * The advertisement cache's two bounds in the TypeScript client (SPEC §6.3, v0.1.32; ISSUE-AppCardOriginFormats
 * FR-11, §9.7; AppCard origin and formats, 2026-11-09): an entry count and a byte budget over the encoded
 * advertisements, as Java's AdCache keeps them. After the expired entries leave, the cache refuses a new id that
 * would pass either bound, and a newer version that would pass the byte budget while it keeps the version it holds;
 * it counts each refusal and evicts nothing live.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { Identity, instantIso, parseInstantMillis } from "../src/identity.js";
import { AD_CACHE_MAX_BYTES, AD_CACHE_MAX_ENTRIES, Peer } from "../src/peer.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";

const GROUP = "zTypeScriptAdCache";
const T0 = parseInstantMillis("2026-11-09T09:00:00Z");

class Clock {
  constructor(public millis: number) {}
  readonly now = (): number => this.millis;
}

const issuer = Identity.generate();

/** A signed AssetCard whose description pads it to grow or shrink. */
function asset(name: string, issued: number, description = "", ttl = "PT10M"): Dict {
  return wire.storedAd("AssetCard", { id: `aspace://${GROUP}/asset/${name}`, issuer: issuer.peerId, group: GROUP,
    issued: instantIso(issued), ttl, asset: name, uri: `s3://bucket/${name}`, description, shape: "table",
    freshness: "PT1H", costHints: {}, access: {} }, issuer);
}

const length = (stored: Dict): number => (stored["adBytes"] as Uint8Array).length;

test("the defaults are Java's: 8,192 advertisements and 32 MiB", () => {
  const peer = new Peer(Identity.generate(), GROUP);
  assert.equal(AD_CACHE_MAX_ENTRIES, 8_192);
  assert.equal(AD_CACHE_MAX_BYTES, 33_554_432);
  assert.equal(peer.adCacheMaxEntries, AD_CACHE_MAX_ENTRIES);
  assert.equal(peer.adCacheMaxBytes, AD_CACHE_MAX_BYTES);
  assert.equal(peer.adCacheBytes, 0);
  assert.equal(peer.adsRefusedCacheFull, 0);
});

test("a full cache refuses a new id and still takes a newer version of an id it holds", () => {
  const clock = new Clock(T0);
  const peer = new Peer(Identity.generate(), GROUP, clock.now);
  peer.adCacheMaxEntries = 2;
  assert.ok(peer.acceptAd(asset("a", T0)));
  assert.ok(peer.acceptAd(asset("b", T0)));
  assert.equal(peer.acceptAd(asset("c", T0)), null);
  assert.equal(peer.adsRefusedCacheFull, 1);
  assert.ok(!peer.ads.has(`aspace://${GROUP}/asset/c`));
  const newer = peer.acceptAd(asset("a", T0 + 1000, "a newer version"));
  assert.equal(newer?.ad["description"], "a newer version");
  assert.equal(peer.ads.size, 2);
  assert.equal(peer.adsRefusedCacheFull, 1);
});

test("the byte budget refuses what passes it, admits an exact fit, and keeps the held version of a growing card", () => {
  const clock = new Clock(T0);
  const peer = new Peer(Identity.generate(), GROUP, clock.now);
  const a = asset("a", T0);
  const b = asset("b", T0, "x".repeat(200));
  const small = asset("c", T0);
  peer.adCacheMaxBytes = length(a) + length(b) + length(small);
  assert.ok(peer.acceptAd(b));
  assert.equal(peer.acceptAd(asset("big", T0, "y".repeat(length(a) + length(small) + 1))), null, "a large new card");
  assert.equal(peer.adsRefusedCacheFull, 1);
  assert.ok(peer.acceptAd(a));
  assert.ok(peer.acceptAd(small), "a small card that fits exactly");
  assert.equal(peer.adCacheBytes, peer.adCacheMaxBytes);
  const grown = asset("a", T0 + 1000, "grown");
  assert.equal(peer.acceptAd(grown), null, "a newer version that grows past the budget");
  assert.equal(peer.adsRefusedCacheFull, 2);
  assert.equal(peer.ads.get(`aspace://${GROUP}/asset/a`)?.ad["issued"], instantIso(T0), "the held version stays");
  const shrunk = asset("b", T0 + 1000, "x");
  assert.ok(peer.acceptAd(shrunk), "a newer version that shrinks");
  assert.equal(peer.adCacheBytes, length(a) + length(shrunk) + length(small));
  assert.equal(peer.acceptAd(asset("b", T0 - 1000, "x".repeat(400))), peer.ads.get(`aspace://${GROUP}/asset/b`),
    "an older version leaves the held one and counts nothing");
  assert.equal(peer.adsRefusedCacheFull, 2);
});

test("the expired entries leave before a refusal, and the running sum follows them", () => {
  const clock = new Clock(T0);
  const peer = new Peer(Identity.generate(), GROUP, clock.now);
  const brief = asset("brief", T0, "", "PT1M");
  peer.adCacheMaxEntries = 1;
  assert.ok(peer.acceptAd(brief));
  assert.equal(peer.acceptAd(asset("next", T0)), null);
  clock.millis = T0 + 61_000;
  const next = asset("next", clock.millis);
  assert.ok(peer.acceptAd(next), "the lapsed card made room");
  assert.ok(!peer.ads.has(`aspace://${GROUP}/asset/brief`));
  assert.equal(peer.adCacheBytes, length(next));
  assert.equal(peer.adsRefusedCacheFull, 1);
});
