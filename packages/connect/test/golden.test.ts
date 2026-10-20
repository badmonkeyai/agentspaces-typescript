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
 * The connector entries against the golden vectors (srad/agentspaces-js.md
 * JS-C-01, JS-C-03, JS-N-01): the bytes `tools/golden/GoldenVectors.java`
 * writes for fixed `DataQuery`, `DataResult`, `AssetChange`,
 * `AssetInvocation`, and `AssetInvocationResult` values are what
 * `toPayload` of the TypeScript classes encodes to, and the canonical query
 * hash agrees with `DataQueryEntries.canonicalHash`.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { bytes, cbor, toPayload } from "@agentspaces/client";
import type { wire } from "@agentspaces/client";
import { AssetChange, AssetInvocation, AssetInvocationResult, DataQuery, DataResult, canonicalHash } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(
  readFileSync(join(here, "..", "..", "..", "..", "test", "golden.json"), "utf-8"));

const hex = (value: object): string => bytes.toHex(cbor.dumps(toPayload(value)));
const INVOCATION_ID = "6f1d2c3b-4a59-4e8f-9b7a-0c1d2e3f4a5b";

test("the data-query entries encode as DataQueryEntries.java does (golden data_query_cbor, data_result_cbor, asset_change_cbor)", () => {
  assert.ok(GOLDEN["data_query_cbor"] !== undefined, "the generator has run with the connector vectors");
  const hash = canonicalHash("orders", { region: "eu", limit: "10" });
  assert.equal(hash, GOLDEN["data_query_canonical_hash"]);
  assert.equal(hex(new DataQuery(hash, "orders", { region: "eu", limit: "10" }, "zPeer/analyst")), GOLDEN["data_query_cbor"]);
  assert.equal(hex(new DataResult(hash, "orders",
    [{ id: "1", region: "eu", amount: "120.00" }, { id: "3", region: "eu", amount: "45.50" }], null, "pg-connector")),
    GOLDEN["data_result_cbor"]);
  assert.equal(hex(new AssetChange("orders", "1", { id: "1", region: "eu", amount: "125.00" }, "pg-connector")),
    GOLDEN["asset_change_cbor"]);
});

test("the asset-invoke entries encode as AssetInvocations.java does (golden asset_invocation_cbor, asset_invocation_result_cbor)", () => {
  assert.ok(GOLDEN["asset_invocation_cbor"] !== undefined, "the generator has run with the connector vectors");
  assert.equal(hex(new AssetInvocation("do/Inventory", "reserveStock", { sku: "A-1", qty: "2" }, INVOCATION_ID)),
    GOLDEN["asset_invocation_cbor"]);
  assert.equal(hex(new AssetInvocationResult(INVOCATION_ID, "do/Inventory", "reserveStock", true, { reserved: "2" }, null)),
    GOLDEN["asset_invocation_result_cbor"]);
  // The bytes decode back to the same values through the field-picking readers.
  const decoded = AssetInvocation.from(cbor.loads(bytes.fromHex(GOLDEN["asset_invocation_cbor"]!)) as wire.Dict);
  assert.deepEqual(decoded, new AssetInvocation("do/Inventory", "reserveStock", { sku: "A-1", qty: "2" }, INVOCATION_ID));
});
