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
 * The Playwright driver for JS-W-12, spawned by the Java {@code TwoBrowserWebRtcTest}: it bundles
 * the browser page with esbuild (so the browser needs no import map), serves it, launches two
 * headless Chromium pages — a dialer and an acceptor — pointed at the Java RELAY seed's ws port,
 * and prints the two pages' JSON results. Usage: node two-browser-driver.js <wsPort> <founding>.
 */

import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const [wsPort, founding, maxSeconds = "60", wantedPagePort = "0"] = process.argv.slice(2); // the page port the seed allowlisted

async function main(): Promise<number> {
  const esbuild = await import("esbuild");
  const bundle = await esbuild.build({
    entryPoints: [join(here, "two-browser-page.js")],
    bundle: true,
    format: "esm",
    platform: "browser",
    write: false,
    external: ["node-datachannel", "node-datachannel/polyfill"],
  });
  const script = bundle.outputFiles![0]!.text;
  const html = `<!doctype html><html><head><meta charset="utf-8"></head><body>`
    + `<script type="module">${script}</script></body></html>`;

  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" }).end(html);
  });
  await new Promise<void>((ok) => server.listen(Number(wantedPagePort), "127.0.0.1", ok));
  const pagePort = (server.address() as { port: number }).port;

  const playwright = await import("playwright");
  const browser = await playwright.chromium.launch();
  try {
    const results = await Promise.all((["acceptor", "dialer"] as const).map(async (role) => {
      // The acceptor opens first so it is waiting when the dialer arrives.
      if (role === "dialer") {
        await new Promise((r) => setTimeout(r, 1500));
      }
      const page = await browser.newPage();
      const errors: string[] = [];
      page.on("pageerror", (e) => errors.push(e.message));
      const query = new URLSearchParams({ role, scheme: "ws", host: "127.0.0.1", port: wsPort!, founding: founding!, maxSeconds });
      await page.goto(`http://127.0.0.1:${pagePort}/?${query}`);
      await page.waitForFunction(() => (window as { webrtcResult?: unknown }).webrtcResult !== undefined,
        undefined, { timeout: (Number(maxSeconds) + 30) * 1000 }).catch(() => undefined);
      const result = await page.evaluate(() => (window as { webrtcResult?: unknown }).webrtcResult);
      return { role, result, pageErrors: errors };
    }));
    console.log(JSON.stringify({ ok: results.every((r) => (r.result as { ok?: boolean })?.ok), results }));
    return results.every((r) => (r.result as { ok?: boolean })?.ok && r.pageErrors.length === 0) ? 0 : 2;
  } finally {
    await browser.close();
    server.close();
  }
}

main().then((code) => process.exit(code), (e) => {
  console.log(JSON.stringify({ ok: false, reason: String(e instanceof Error ? e.message : e) }));
  process.exit(1);
});
