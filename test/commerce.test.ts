// The Bad Monkey console records as data (enterprise platform, spiral 3 S3-H-06): the entry types the console
// and its agents write into a group's `constraints`, `policy`, `decisions`, and `findings` spaces, named by the
// console namespace `https://badmonkey.ai/console#<Record>` so a TypeScript peer reads them with the same
// `Template` it uses for its own entries. A field the wire carries that a class here does not declare still
// arrives on the instance; the declared ones document the shape.
//
//     import { Constraint, rules } from "@agentspaces/client";
//     for (const c of new Space(peer, "constraints").readAll(new Template(Constraint))) console.log(c.template, c.a, c.b);
//     const counts = Object.fromEntries(Object.entries(rules(peer)).map(([k, v]) => [k, v.length]));



/** The commerce twins (SPEC §6.5a): the builders emit the Java field order and the golden vectors of agentspaces-commerce round-trip byte for byte. */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { dumps, loads } from "../src/cbor.js";
import { basis, cart, digest, item, itemsTotal, mandate, order } from "../src/commerce.js";

type Dict = { [k: string]: unknown };
const here = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(here, "..", "..", "..", "agentspaces-commerce", "src", "test", "resources", "vectors");   // from build/test
const hex = (name: string) => Uint8Array.from(Buffer.from(readFileSync(join(VECTORS, name + ".hex"), "utf8").trim(), "hex"));
const same = (a: Uint8Array, b: Uint8Array) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

test("the builders emit the Java field order", () => {
  const m = mandate("mnd-1", "checkout", "shopper", cart([item("claims.policies", "Policy data set, one month", 1, 19900)], 19900, "USD"),
    "https://merchant.example/.well-known/ucp", basis("apr-7"), { issuerSignedJwt: "eyJ.a.b" }, "issued", "2026-11-05T12:00:00Z");
  assert.deepEqual(Object.keys(m), ["schemaVersion", "id", "kind", "role", "cart", "counterparty", "basis", "credential", "state", "at"]);
  assert.deepEqual(Object.keys(m.cart.items[0]), ["sku", "title", "quantity", "unitPrice"]);
  assert.equal(itemsTotal(m.cart), 19900);
  assert.deepEqual(Object.keys(order("ord-1", "mnd-1", "completed", {}, "", "x")), ["schemaVersion", "id", "mandate", "status", "fulfillment", "permalink", "at"]);
  assert.throws(() => mandate("m", "refund", "shopper", m.cart, "", basis(), {}, "issued", ""), /kind/);
  assert.throws(() => order("o", "m", "shipped", {}, "", ""), /status/);
  assert.equal(digest("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
});

test("the golden vectors round-trip byte for byte", { skip: !existsSync(VECTORS) }, () => {
  const raw = hex("mandate_cbor");
  const m = loads(raw) as Dict;
  assert.ok(same(dumps(m as never), raw));
  const c = m["cart"] as Dict;
  const rebuilt = mandate(String(m["id"]), String(m["kind"]), String(m["role"]),
    cart((c["items"] as Dict[]).map(i => item(String(i["sku"]), String(i["title"]), Number(i["quantity"]), Number(i["unitPrice"]))), Number(c["total"]), String(c["currency"])),
    String(m["counterparty"]), basis(String((m["basis"] as Dict)["approval"]), String((m["basis"] as Dict)["decision"])), m["credential"] as Dict, String(m["state"]), m["at"]);
  assert.ok(same(dumps(rebuilt as never), raw), "the TypeScript builder encodes the Java mandate byte for byte");
  const rawOrder = hex("order_cbor");
  const o = loads(rawOrder) as Dict;
  assert.ok(same(dumps(order(String(o["id"]), String(o["mandate"]), String(o["status"]), o["fulfillment"] as Dict, String(o["permalink"]), o["at"]) as never), rawOrder));
  const cap = loads(hex("capability_commerce_cbor")) as Dict;
  assert.equal(cap["capabilityType"], "aspace:cap/commerce");
  assert.equal((cap["parameters"] as Dict)["role"], "merchant");
});
