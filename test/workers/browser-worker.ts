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
 * The browser driver of the Java cross-language test (agentspaces-transport-http
 * BrowserFleetTest; srad/agentspaces-js.md JS-Q-REL-02, JS-Q-TST-02): serves
 * the built core and the page on the port the test chose (so the Java
 * listener's origin allowlist can name it), opens the page in a headless
 * browser through Playwright, waits for the page's result, and prints it as
 * one JSON line. Exit 0 when the page's Done went out.
 *
 *   node build/test/workers/browser-worker.js <engine> <pagePort> <scheme> <host> <port> <founding> <jobType> <doneType> [maxSeconds]
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, "..", "..", "..");
const [engine, pagePort, scheme, host, port, founding, jobType, doneType, maxSeconds] = process.argv.slice(2);

const PAGE = `<!doctype html><html><head><meta charset="utf-8">
<script type="importmap">{"imports": {
  "@noble/curves/": "/node_modules/@noble/curves/",
  "@noble/hashes/": "/node_modules/@noble/hashes/"
}}</script></head><body><script type="module" src="/build/test/workers/browser-page.js"></script></body></html>`;
const TYPES: { [ext: string]: string } = { ".js": "text/javascript", ".json": "application/json", ".html": "text/html" };

async function main(): Promise<number> {
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
  await new Promise<void>((ok) => server.listen(Number(pagePort), "127.0.0.1", ok));
  const playwright = await import("playwright");
  const browser = await playwright[engine as "chromium" | "firefox" | "webkit"].launch();
  try {
    const page = await browser.newPage();
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    const query = new URLSearchParams({ scheme, host, port, founding, jobType, doneType,
      maxSeconds: maxSeconds ?? "60" });
    await page.goto(`http://127.0.0.1:${pagePort}/?${query}`);
    await page.waitForFunction(() => (globalThis as { fleetResult?: unknown }).fleetResult !== undefined,
      undefined, { timeout: (Number(maxSeconds ?? 60) + 30) * 1000 });
    const result = await page.evaluate(() => (globalThis as { fleetResult?: unknown }).fleetResult) as
      { ok: boolean } & Record<string, unknown>;
    console.log(JSON.stringify({ engine, ...result, pageErrors: errors }));
    return result.ok ? 0 : 2;
  } finally {
    await browser.close();
    server.close();
  }
}

main().then((code) => process.exit(code), (e) => {
  console.log(JSON.stringify({ engine, ok: false, reason: String(e instanceof Error ? e.message : e) }));
  process.exit(1);
});
