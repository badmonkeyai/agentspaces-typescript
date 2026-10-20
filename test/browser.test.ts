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
 * JS-P-09 in browsers: serves the built core and the conformance module over
 * HTTP with an import map for the noble packages, loads it in headless
 * Chromium, Firefox, and WebKit through Playwright, and requires every check
 * to pass in each. The same module runs in Node first, as the reference.
 * A browser whose Playwright build is missing is skipped with a note unless
 * AGENTSPACES_BROWSERS_REQUIRED=1.
 */

import assert from "node:assert/strict";
import { readFileSync, existsSync, statSync } from "node:fs";
import { createServer, Server } from "node:http";
import { AddressInfo } from "node:net";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { runConformance } from "./browser/conformance.js";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, "..", ".."); // the package root: build/ and node_modules/ beneath it
const GOLDEN = JSON.parse(readFileSync(join(ROOT, "test", "golden.json"), "utf-8"));
const SOCIAL = JSON.parse(readFileSync(join(ROOT, "test", "social-golden.json"), "utf-8"));
const REQUIRED = process.env.AGENTSPACES_BROWSERS_REQUIRED === "1";

const PAGE = `<!doctype html><html><head><meta charset="utf-8">
<script type="importmap">{"imports": {
  "@noble/curves/": "/node_modules/@noble/curves/",
  "@noble/hashes/": "/node_modules/@noble/hashes/"
}}</script></head><body><script type="module">
import { runConformance } from "/build/test/browser/conformance.js";
const [golden, social] = await Promise.all([
  fetch("/test/golden.json").then((r) => r.json()),
  fetch("/test/social-golden.json").then((r) => r.json()),
]);
window.conformance = await runConformance(golden, social);
</script></body></html>`;

const TYPES: { [ext: string]: string } = {
  ".js": "text/javascript", ".json": "application/json", ".html": "text/html", ".map": "application/json",
};

function serve(): Promise<Server> {
  const server = createServer((request, response) => {
    const path = decodeURIComponent(new URL(request.url ?? "/", "http://x").pathname);
    if (path === "/") {
      response.writeHead(200, { "content-type": "text/html" }).end(PAGE);
      return;
    }
    const file = normalize(join(ROOT, path));
    if (!file.startsWith(ROOT) || !existsSync(file) || !statSync(file).isFile()) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream" })
      .end(readFileSync(file));
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok(server)));
}

test("the conformance subset passes in Node (the reference run)", async () => {
  const results = await runConformance(GOLDEN, SOCIAL);
  assert.deepEqual(results.filter((r) => !r.ok), []);
  assert.ok(results.length >= 10);
});

for (const engine of ["chromium", "firefox", "webkit"] as const) {
  test(`the conformance subset passes in ${engine} (JS-P-09)`, async (t) => {
    let playwright: typeof import("playwright");
    try {
      playwright = await import("playwright");
    } catch {
      if (REQUIRED) {
        throw new Error("playwright is not installed");
      }
      t.skip("playwright is not installed");
      return;
    }
    let browser;
    try {
      browser = await playwright[engine].launch();
    } catch (e) {
      if (REQUIRED) {
        throw e;
      }
      t.skip(`${engine} is not installed for Playwright (npx playwright install ${engine})`);
      return;
    }
    const server = await serve();
    try {
      const page = await browser.newPage();
      const errors: string[] = [];
      page.on("pageerror", (e) => errors.push(e.message));
      await page.goto(`http://127.0.0.1:${(server.address() as AddressInfo).port}/`);
      await page.waitForFunction(() => (globalThis as { conformance?: unknown }).conformance !== undefined,
        undefined, { timeout: 30_000 }).catch(() => undefined);
      const results = await page.evaluate(() => (globalThis as { conformance?: unknown }).conformance) as
        { name: string; ok: boolean; detail?: string }[] | undefined;
      assert.deepEqual(errors, [], `${engine} page errors`);
      assert.ok(results !== undefined, `${engine} ran the conformance module`);
      assert.deepEqual(results.filter((r) => !r.ok), [], `${engine} failures`);
      assert.ok(results.length >= 10);
    } finally {
      await browser.close();
      server.close();
    }
  });
}
