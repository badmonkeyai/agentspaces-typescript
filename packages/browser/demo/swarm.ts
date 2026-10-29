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
 * The swarm demo (srad/large-networks-bulk-data.md LB-C-06, scenario 5). A hub that accepts
 * WebSocket and TCP, and two server peers that dial it over TCP, all hold one artifact: the hub
 * publishes it and the servers fetch it from the hub and each other. A browser page then fetches
 * it through its resident worker from all three at once, the hub directly and the servers through
 * the hub as a relay, and draws the bytes from each.
 *
 *     npm run build && node build/demo/swarm.js            # prints the URL to open
 *     node build/demo/swarm.js --check                     # runs the page in headless Chromium, prints the result
 *     node build/demo/swarm.js --check --screenshot swarm.png
 *     node build/demo/swarm.js --mebibytes 12 --port 7750
 */

import { createHash } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Identity, Peer, Space, capabilities } from "@agentspaces/client";
import { ServiceHost } from "@agentspaces/node";

const here = dirname(fileURLToPath(import.meta.url));
const PKG = join(here, "..", "..");
const GROUP = "zSwarmDemo";
const PIECE = 256 * 1024;

const arg = (name: string, fallback: string): string => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1]! : fallback;
};

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>AgentSpaces: a swarm in the browser</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:760px;margin:40px auto;color:#1d1d2b}
h1{font-size:22px;margin:0 0 4px} .sub{color:#666699;margin:0 0 24px}
.card{border:1px solid #e0e0ea;border-radius:8px;padding:16px 20px;margin:0 0 16px}
.row{display:flex;align-items:center;gap:12px;margin:6px 0} .who{width:110px;font-family:ui-monospace,monospace;font-size:13px}
.track{flex:1;height:14px;background:#efeff6;border-radius:7px;overflow:hidden} .fill{display:block;height:100%;background:#666699}
.num{width:80px;text-align:right;font-family:ui-monospace,monospace;font-size:13px}
button{font:inherit;padding:6px 16px;border-radius:6px;border:1px solid #666699;background:#666699;color:#fff;cursor:pointer}
button:disabled{opacity:.5;cursor:default} #done{margin-top:10px;font-family:ui-monospace,monospace;font-size:13px}
</style></head><body>
<h1>A swarm in the browser</h1>
<p class="sub">The page's worker fetches one artifact from every member that holds it, verifying each piece.</p>
<div class="card"><div id="status">connecting...</div><div id="artifact"></div></div>
<div class="card"><div id="overall"></div><div id="sources"></div><div id="pieces"></div>
<p><button id="go">Fetch</button></p><div id="done"></div></div>
<script type="module" src="/page.js"></script></body></html>`;

async function bundle(entry: string): Promise<string> {
  const esbuild = await import("esbuild");
  const result = await esbuild.build({ entryPoints: [entry], bundle: true, format: "esm", platform: "browser",
    write: false, logLevel: "silent" });
  return result.outputFiles[0]!.text;
}

/** A server peer: dial-only over TCP to the hub, holding pieces in memory. */
function holder(): { peer: Peer; content: capabilities.Content } {
  const peer = new Peer(Identity.generate(), GROUP);
  const content = new capabilities.Content(new capabilities.Pipes(peer), new Space(peer, "content"),
    new capabilities.MemoryStore(), { pieceSize: PIECE });
  content.run(100);
  return { peer, content };
}

async function main(): Promise<void> {
  const mebibytes = Number(arg("mebibytes", "12"));
  const size = Math.round(mebibytes * 1024 * 1024);
  if (Math.ceil(size / PIECE) > capabilities.INLINE_TABLE_PIECES) {
    throw new Error(`at most ${capabilities.INLINE_TABLE_PIECES * PIECE / 1024 / 1024} MiB at this piece size`);
  }
  const [page, worker] = await Promise.all([bundle(join(here, "swarm-page.js")), bundle(join(PKG, "build", "src", "worker.js"))]);

  let fleetJson = "{}";
  const http = createServer((request, response) => {
    const path = new URL(request.url ?? "/", "http://x").pathname;
    const body: { [path: string]: [string, string] } = {
      "/": ["text/html", PAGE], "/page.js": ["text/javascript", page], "/worker.js": ["text/javascript", worker],
      "/fleet.json": ["application/json", fleetJson],
    };
    const hit = body[path];
    if (hit === undefined) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-type": hit[0], "cache-control": "no-store" }).end(hit[1]);
  });
  await new Promise<void>((ok) => http.listen(Number(arg("port", "0")), "127.0.0.1", () => ok()));
  const origin = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;

  const hub = new ServiceHost(Identity.generate(), GROUP, { tickMillis: 250, spaces: ["content"], log: null,
    listeners: [{ scheme: "ws", bind: "127.0.0.1:0", origins: [origin] }, { scheme: "tcp", bind: "127.0.0.1:0" }] });
  await hub.start();
  const hubContent = new capabilities.Content(new capabilities.Pipes(hub.peer), new Space(hub.peer, "content"),
    new capabilities.MemoryStore(), { pieceSize: PIECE });
  hubContent.run(100);
  const data = new Uint8Array(size).map((_, i) => (i * 2654435761) >>> 24);
  const manifest = hubContent.publish(data, { name: "model.bin" });
  const root = String(manifest["root"]);

  const tcp = hub.addresses.get("tcp")!;
  const [host, port] = [tcp.slice(0, tcp.lastIndexOf(":")), Number(tcp.slice(tcp.lastIndexOf(":") + 1))];
  const servers = [holder(), holder()];
  for (const s of servers) {
    await s.peer.connectAny([{ host, port, scheme: "tcp" }]);
    s.peer.pullSpace("content");
  }
  for (const s of servers) {
    const fetch = s.content.fetch(root);
    if (!await fetch.await(120_000)) {
      throw new Error(`a server could not fetch the artifact: ${fetch.trace.slice(-4).join("; ")}`);
    }
  }
  const names: { [peerId: string]: string } = { [hub.peer.identity.peerId]: "hub" };
  servers.forEach((s, i) => { names[s.peer.identity.peerId] = `server-${i + 1}`; });
  fleetJson = JSON.stringify({ group: GROUP, seeds: [`ws://${hub.addresses.get("ws")}/aspace`], root, size, pieceSize: PIECE, names });
  const expected = createHash("sha256").update(data).digest("hex");
  console.log(`swarm demo: ${mebibytes} MiB held by the hub and two servers; open ${origin}/`);

  const close = async (): Promise<void> => {
    hubContent.stop();
    servers.forEach((s) => { s.content.stop(); s.peer.close(); });
    await hub.stop();
    http.close();
  };
  if (!process.argv.includes("--check")) {
    process.on("SIGINT", () => { void close().then(() => process.exit(0)); });
    return;
  }
  const { chromium } = await import("playwright");
  const browser = await chromium.launch();
  try {
    const tab = await browser.newPage();
    await tab.goto(`${origin}/?auto`);
    await tab.waitForFunction(() => (globalThis as { result?: unknown }).result !== undefined, undefined, { timeout: 180_000 });
    const result = await tab.evaluate(() => (globalThis as { result?: unknown }).result) as
      { ok: boolean; sha256?: string; sources?: { [name: string]: number } };
    const shot = arg("screenshot", "");
    if (shot !== "") {
      await tab.setViewportSize({ width: 860, height: 560 });
      await tab.screenshot({ path: shot, fullPage: true });
    }
    const ok = result.ok && result.sha256 === expected;
    console.log(JSON.stringify({ ...result, matches: result.sha256 === expected }));
    await browser.close();
    await close();
    process.exit(ok ? 0 : 1);
  } catch (e) {
    await browser.close();
    await close();
    throw e;
  }
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.stack ?? e.message : String(e));
  process.exit(1);
});
