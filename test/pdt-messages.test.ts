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
 * A user reads the messages of the PDT package. A message says what went wrong and what to do, in plain words, and
 * names no internal design id such as PD-N-04 or P2-X-06. This guard parses every source file under `src/pdt` and
 * fails on a string or template literal that names an id. Comments stay out of its reach.
 */

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import ts from "typescript";

import { closeAll, fleetOf } from "./pdt-fleet.js";

const here = dirname(fileURLToPath(import.meta.url));
const PDT = join(here, "..", "..", "src", "pdt");

/** A design id: a prefix, one or two letter groups, and a number, as in PD-N-04 or P2-Q-SEC-05; or an ISSUE- name. */
const DESIGN_ID = /\b[A-Z][A-Z0-9]{1,3}-[A-Z](?:-[A-Z]{1,4})?-\d{1,3}\b|\bISSUE-[A-Z][A-Za-z]/;

function offences(source: string, name = "<source>"): string[] {
  const file = ts.createSourceFile(name, source, ts.ScriptTarget.ES2022, true);
  const out: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateHead(node)
      || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
      if (DESIGN_ID.test(node.text)) {
        const line = file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1;
        out.push(`${name}:${line}: ${JSON.stringify(node.text)}`);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return out;
}

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? sources(path) : entry.name.endsWith(".ts") ? [path] : [];
  });
}

test("no message in the PDT package names a design id", () => {
  const files = sources(PDT);
  assert.ok(files.length > 10, "the pdt package is where it was");
  const found = files.flatMap((f) => offences(readFileSync(f, "utf8"), relative(PDT, f)));
  assert.deepEqual(found, [], "string literals that name a design id; say what to do instead");
});

test("the guard finds an id in a string or template and skips one in a comment", () => {
  const source = [
    "// PD-N-04 in a comment",
    "/** P2-X-06 in a doc comment */",
    "export function f(x: number): void {",
    "  const a = \"bound (PD-N-04)\";",
    "  const b = `${x} (P2-Q-SEC-05)`;",
    "  const c = 'HKDF-SHA-256, UTF-8, PDT 2';",
    "  throw new Error(`see ISSUE-Motion`);",
    "}",
  ].join("\n");
  assert.deepEqual(offences(source).map((hit) => hit.split(":")[1]), ["4", "5", "7"]);
});

test("a db ref on a level-1 engine says which option to set", () => {
  const nodes = fleetOf([{ level: 1 }]);
  try {
    assert.throws(() => nodes[0]!.pdt.ref("refs", "graph", "db"),
      /a db ref needs the PDT feature level 2; set level: 2 in the PDT options/);
  } finally {
    closeAll(nodes);
  }
});
