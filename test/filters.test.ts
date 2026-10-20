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
 * The portable field filter grammar (SPEC §7.2; srad/agentspaces-js.md
 * JS-V-03): the cases the Java FieldFilter decides, as the golden vector
 * `filter_grammar_cases` carries them once regenerated and as this inline
 * copy of the generator's list carries them meanwhile.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { CborDouble } from "../src/cbor.js";
import { Template, entry, parseFilter } from "../src/space.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = JSON.parse(readFileSync(join(here, "..", "..", "test", "golden.json"), "utf-8")) as
  { filter_grammar_cases?: { filter: string; value: unknown; matches: boolean }[]; filter_grammar_malformed?: string[] };

/** The generator's case list (tools/golden/GoldenVectors.java filterGrammarCases), with the Java verdicts. */
const CASES: [string, unknown, boolean][] = [
  ["priority>=3", 3, true], ["priority>=3", 2.5, false], ["priority=3", 3.0, true], ["priority=3", "3", true],
  ["priority<10", 9, true], ["priority<10", "9", true], ["priority<10", "abc", false], ["priority > 1.5", 2, true],
  ["topic=index", "index", true], ["topic!=index", "other", true], ["topic!=index", null, true],
  ["topic=index", null, false], ["name<m", "alpha", true], ["name>m", "alpha", false], ["name<=alpha", "alpha", true],
  ["region in eu, us", "us", true], ["region in eu, us", "ap", false], ["n in 1,2,3", 2.0, true],
  ["flag=true", true, true], ["flag!=true", false, true], ["topic=a=b", "a=b", true], ["count>=0", 0, true],
  ["count<-1", -2, true], ["ratio>=0.5", 0.75, true], ["ratio>=0.5", "0.25", false],
];

test("every grammar case decides as Java does", () => {
  for (const [clause, value, expected] of CASES) {
    const [, test] = parseFilter(clause);
    assert.equal(test(value), expected, `${clause} on ${JSON.stringify(value)}`);
    if (typeof value === "number") {
      assert.equal(test(new CborDouble(value)), expected, `${clause} on double ${value}`);
    }
  }
  for (const c of GOLDEN.filter_grammar_cases ?? []) {
    assert.equal(parseFilter(c.filter)[1](c.value), c.matches, `golden ${c.filter} on ${JSON.stringify(c.value)}`);
  }
});

test("a template takes clauses beside matchers and refuses a malformed one", () => {
  class Task {
    constructor(public topic = "", public priority = 0, public region = "") {}
  }
  entry("com.acme.Task#v1")(Task);
  const template = new Template(Task, { topic: "index" }, {}, ["priority>=3", "region in eu,us"]);
  assert.ok(template.matches({ topic: "index", priority: 5, region: "eu" }));
  assert.ok(!template.matches({ topic: "index", priority: 2, region: "eu" }));
  assert.ok(!template.matches({ topic: "index", priority: 5, region: "ap" }));
  assert.ok(!template.matches({ topic: "other", priority: 5, region: "eu" }));
  assert.throws(() => parseFilter("nonsense"), /malformed field filter/);
  assert.throws(() => parseFilter("=3"), /malformed field filter/);
  // the earliest operator wins: "!=x" is malformed, not the field "!" compared with "x"
  for (const clause of ["!=x", "<x", " in a,b", "topic!", "", ...(GOLDEN.filter_grammar_malformed ?? [])]) {
    assert.throws(() => parseFilter(clause), /malformed field filter/, `'${clause}'`);
  }
  assert.ok(parseFilter("a<b<=c")[1]("a"), "a < b<=c as strings");
  assert.ok(parseFilter("topic=a in b")[1]("a in b"));
});
