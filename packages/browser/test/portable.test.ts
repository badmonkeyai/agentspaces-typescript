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
 * The portable rule for both entries (srad/agentspaces-js.md JS-P-01, as
 * `test/portable.test.ts` of the core checks its main entry): the page
 * entry's and the worker entry's module graphs, followed through the core
 * they import, reach no `node:` module and name no Node global. The
 * protocol helpers are checked here too, since they run on both sides.
 */

import assert from "node:assert/strict";
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { cbor } from "@agentspaces/client";
import { agentKeyName, databaseName, identityLockName, lockName, packMap, unpackMap, token } from "../src/protocol.js";

const here = dirname(fileURLToPath(import.meta.url));
const PKG = resolve(here, "..", "..");
const CORE_ENTRY = realpathSync(fileURLToPath(import.meta.resolve("@agentspaces/client")));

/** Every module the entry reaches through relative imports and through `@agentspaces/client`, with its source. */
function moduleGraph(entry: string): Map<string, string> {
  const seen = new Map<string, string>();
  const pending = [entry];
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (seen.has(file)) {
      continue;
    }
    const source = readFileSync(file, "utf-8");
    seen.set(file, source);
    for (const match of source.matchAll(/(?:import|export)[^'"]*?from\s+["']([^"']+)["']|import\s+["']([^"']+)["']/g)) {
      const spec = match[1] ?? match[2];
      if (spec.startsWith(".")) {
        pending.push(join(dirname(file), spec));
      } else if (spec === "@agentspaces/client") {
        pending.push(CORE_ENTRY);
      } else {
        assert.ok(spec.startsWith("@noble/"), `${file} imports ${spec}: only the core and the noble packages are expected`);
      }
    }
  }
  return seen;
}

for (const entry of ["index.js", "worker.js"]) {
  test(`the ${entry} entry imports no Node module and names no Node global (JS-P-01)`, () => {
    const graph = moduleGraph(join(PKG, "build", "src", entry));
    assert.ok(graph.size > 15, `the graph reaches the core (${graph.size} modules)`);
    for (const [file, source] of graph) {
      const name = file.substring(file.indexOf("build"));
      assert.ok(!file.includes(`${"/"}node${"/"}`), `${name}: the node adapters stay out of ${entry}`);
      assert.doesNotMatch(source, /from\s+["']node:/, `${name} imports a node: module`);
      assert.doesNotMatch(source, /import\s+["']node:/, `${name} imports a node: module`);
      const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
      assert.doesNotMatch(code, /\bBuffer\b/, `${name} names Buffer`);
      assert.doesNotMatch(code, /\bprocess\./, `${name} names process`);
      assert.doesNotMatch(code, /\brequire\(/, `${name} calls require`);
    }
  });
}

test("the lock, database, and key names follow the group and identity (JS-R-02, JS-P-08)", () => {
  assert.equal(lockName("zGroup", "zPeer"), "agentspaces:zGroup:zPeer");
  assert.equal(identityLockName("zGroup"), "agentspaces:zGroup:identity");
  assert.equal(databaseName("zGroup"), "agentspaces:zGroup");
  assert.equal(agentKeyName("resident"), "agents/resident/agent.key");
  assert.match(token(), /^[0-9a-f]{16}$/);
  assert.notEqual(token(), token());
});

test("maps cross the port as CBOR, so floats stay floats and integers integers", () => {
  const packed = packMap({ priority: 3, score: new cbor.CborDouble(2.5), name: "x", raw: new Uint8Array([1, 2]) });
  const back = unpackMap(packed);
  assert.equal(back["priority"], 3);
  assert.ok(back["score"] instanceof cbor.CborDouble);
  assert.equal((back["score"] as cbor.CborDouble).value, 2.5);
  assert.deepEqual(back["raw"], new Uint8Array([1, 2]));
  assert.deepEqual(unpackMap(null), {});
  assert.deepEqual(unpackMap(new Uint8Array()), {});
  assert.deepEqual(unpackMap(cbor.dumps([1, 2])), {}, "a non-map is the empty map");
});
