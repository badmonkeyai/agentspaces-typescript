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
 * The resident host in Chromium, Firefox, and WebKit (srad/agentspaces-js.md
 * JS-R-02, JS-R-03, JS-R-07, JS-P-08): a local HTTP server serves the built
 * package and core with an import map for the noble packages, the worker
 * entry as one esbuild bundle, and the harness page of
 * `test/browser/harness.ts`; a `ServiceHost` of `@agentspaces/node` is the
 * `ws` hub the worker dials, with the page's origin on its allowlist. Each
 * engine gets its own hub and group and runs the scenarios in order: two
 * tabs share one PeerID and one connection, a write in one is read in the
 * other, the Web Lock refuses a second host for the identity, the pause
 * rule with a lease that lapses while paused, keys that persist across a
 * reload and the worker's death, and the dedicated-Worker fallback forced.
 * A browser whose Playwright build is missing is skipped with a note unless
 * AGENTSPACES_BROWSERS_REQUIRED=1.
 */

import assert from "node:assert/strict";
import { existsSync, readFileSync, statSync } from "node:fs";
import { createServer, Server } from "node:http";
import { AddressInfo } from "node:net";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { Identity } from "@agentspaces/client";
import { ServiceHost } from "@agentspaces/node";

import { TASK } from "./browser/harness.js";

const here = dirname(fileURLToPath(import.meta.url));
const PKG = resolve(here, "..", ".."); // packages/browser
const CORE = resolve(PKG, "..", ".."); // the workspace root: build/ and node_modules/ beneath it
const REQUIRED = process.env.AGENTSPACES_BROWSERS_REQUIRED === "1";
const SPACE = "tasks";

const PAGE = `<!doctype html><html><head><meta charset="utf-8">
<script type="importmap">{"imports": {
  "@agentspaces/client": "/core/build/src/index.js",
  "@noble/curves/": "/core/node_modules/@noble/curves/",
  "@noble/hashes/": "/core/node_modules/@noble/hashes/"
}}</script></head><body><script type="module">
import "/pkg/build/test/browser/harness.js";
window.ready = true;
</script></body></html>`;

const TYPES: { [ext: string]: string } = {
  ".js": "text/javascript", ".json": "application/json", ".html": "text/html", ".map": "application/json",
};

type Harness = typeof import("./browser/harness.js").harness;
type Page = import("playwright").Page;

/** The worker entry as one browser bundle: bare imports resolved, nothing left for an import map. */
async function bundleWorker(): Promise<string> {
  const esbuild = await import("esbuild");
  const result = await esbuild.build({
    entryPoints: [join(PKG, "build", "src", "worker.js")], bundle: true, format: "esm", platform: "browser",
    write: false, logLevel: "silent",
  });
  return result.outputFiles[0]!.text;
}

function serve(worker: string): Promise<Server> {
  const roots: { [prefix: string]: string } = { "/pkg/": PKG, "/core/": CORE };
  const server = createServer((request, response) => {
    const path = decodeURIComponent(new URL(request.url ?? "/", "http://x").pathname);
    if (path === "/" || path.startsWith("/?")) {
      response.writeHead(200, { "content-type": "text/html" }).end(PAGE);
      return;
    }
    if (path === "/worker.js") {
      response.writeHead(200, { "content-type": "text/javascript" }).end(worker);
      return;
    }
    const prefix = Object.keys(roots).find((p) => path.startsWith(p));
    if (prefix === undefined) {
      response.writeHead(404).end();
      return;
    }
    const root = roots[prefix]!;
    const file = normalize(join(root, path.substring(prefix.length - 1)));
    if (!file.startsWith(root) || !existsSync(file) || !statSync(file).isFile()) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream" }).end(readFileSync(file));
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok(server)));
}

const sleep = (millis: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, millis));

async function until(condition: () => boolean, what: string, millis = 15_000): Promise<void> {
  const deadline = Date.now() + millis;
  while (!condition()) {
    if (Date.now() > deadline) {
      throw new Error(`${what}: not met within ${millis} ms`);
    }
    await sleep(25);
  }
}

/** Runs one harness function in the page. */
async function call<K extends keyof Harness>(page: Page, name: K, ...args: Parameters<Harness[K]>): Promise<Awaited<ReturnType<Harness[K]>>> {
  return await page.evaluate(([n, a]) => {
    const h = (globalThis as unknown as { harness: { [k: string]: (...x: unknown[]) => unknown } }).harness;
    return h[n as string]!(...(a as unknown[]));
  }, [name, args] as [string, unknown[]]) as Awaited<ReturnType<Harness[K]>>;
}

async function openTab(context: import("playwright").BrowserContext, url: string, errors: string[]): Promise<Page> {
  const page = await context.newPage();
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(url);
  await page.waitForFunction(() => (globalThis as { ready?: boolean }).ready === true, undefined, { timeout: 30_000 });
  return page;
}

for (const engine of ["chromium", "firefox", "webkit"] as const) {
  test(`the resident host in ${engine} (JS-R-02, JS-R-03, JS-R-07, JS-P-08)`, async (t) => {
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
    let browser: import("playwright").Browser;
    try {
      browser = await playwright[engine].launch();
    } catch (e) {
      if (REQUIRED) {
        throw e;
      }
      t.skip(`${engine} is not installed for Playwright (npx playwright install ${engine})`);
      return;
    }
    const group = `zBrowserHost${engine}`;
    const server = await serve(await bundleWorker());
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const hub = new ServiceHost(Identity.generate(), group, {
      tickMillis: 100, listeners: [{ scheme: "ws", bind: "127.0.0.1:0", origins: [origin] }], spaces: [SPACE], log: null,
    });
    await hub.start();
    const seeds = [`ws://${hub.addresses.get("ws")}/aspace`];
    const options = { group, seeds, tickMillis: 250, pageTimeoutMillis: 4000, beatMillis: 1000 };
    const errors: string[] = [];
    const context = await browser.newContext();
    try {
      const tabA = await openTab(context, `${origin}/`, errors);
      const sharedAvailable = await call(tabA, "sharedWorkerAvailable");
      t.diagnostic(`${engine}: SharedWorker ${sharedAvailable ? "available" : "absent, dedicated Worker fallback"}`);
      const a = await call(tabA, "connect", "a", options);
      assert.ok(a.ok, `tab A connects: ${a.ok ? "" : a.error}`);
      assert.equal(a.shared, sharedAvailable, "the host is a SharedWorker exactly where the browser has one");
      assert.ok(a.peerId.startsWith("z"), "a PeerID");
      assert.ok(a.connected && !a.paused);
      t.diagnostic(`${engine}: navigator.storage.persist() -> ${String(a.persisted)}`);
      await until(() => hub.peer.inbound.size === 1, "the hub sees the host's one connection");
      await until(() => hub.peer.members.has(a.peerId), "the hub hears the host's advertisement");
      const hints = hub.peer.members.get(a.peerId)!["resourceHints"] as { [k: string]: string };
      assert.equal(hints["js.residency"], "resident", "JS-R-07: the host advertises its residency");

      await t.test("two tabs share one PeerID and one ws connection (JS-R-02)", async (st) => {
        if (!sharedAvailable) {
          st.skip(`${engine} has no SharedWorker; a second tab would be a second host, refused by the lock (next test)`);
          return;
        }
        const tabB = await openTab(context, `${origin}/?tab=b`, errors);
        const b = await call(tabB, "connect", "b", options);
        assert.ok(b.ok, `tab B connects: ${b.ok ? "" : b.error}`);
        assert.equal(b.peerId, a.peerId, "one identity");
        assert.equal(b.instance, a.instance, "one host instance");
        await sleep(300);
        assert.equal(hub.peer.inbound.size, 1, "one connection for two tabs");
        const status = await call(tabB, "status", "b");
        assert.equal(status.pages, 2);
        assert.equal(status.activePages, 2);
        (context as unknown as { tabB?: Page }).tabB = tabB;
      });
      const tabB = (context as unknown as { tabB?: Page }).tabB ?? null;

      await t.test("a write from one tab is read in the other, and reaches the hub", async (st) => {
        const id = await call(tabA, "write", "a", SPACE, "from-a", 3);
        await until(() => hub.peer.states.has(id), "the hub folds the write");
        if (tabB === null) {
          st.diagnostic("no second tab in this engine; the hub's replica stands in for it");
          const found = await call(tabA, "read", "a", SPACE, "from-a", 2000);
          assert.deepEqual(found, { topic: "from-a", priority: 3 });
          return;
        }
        const found = await call(tabB, "read", "b", SPACE, "from-a", 5000);
        assert.deepEqual(found, { topic: "from-a", priority: 3 });
        assert.deepEqual(await call(tabB, "readAll", "b", SPACE, 3), ["from-a"]);
        assert.deepEqual(await call(tabB, "readAll", "b", SPACE, 4), [], "the page-side template judges fields");
      });

      await t.test("a watch in one tab sees a write from the other, and a hub write", async () => {
        const watcher = tabB ?? tabA;
        const watcherName = tabB === null ? "a" : "b";
        await call(watcher, "watch", watcherName, SPACE);
        await call(tabA, "write", "a", SPACE, "watched", 1);
        hub.peer.writeEntry(SPACE, TASK, { topic: "from-hub", priority: 2 }, "hub");
        const deadline = Date.now() + 15_000;
        let seen: { kind: string; topic: string }[] = [];
        while (Date.now() < deadline) {
          seen = await call(watcher, "events", watcherName);
          if (seen.some((e) => e.topic === "watched") && seen.some((e) => e.topic === "from-hub")) {
            break;
          }
          await sleep(100);
        }
        assert.ok(seen.some((e) => e.kind === "WRITTEN" && e.topic === "watched"), `the tab's write: ${JSON.stringify(seen)}`);
        assert.ok(seen.some((e) => e.kind === "WRITTEN" && e.topic === "from-hub"), `the hub's write: ${JSON.stringify(seen)}`);
      });

      await t.test("the Web Lock refuses a second host for the same identity in the origin (JS-R-02)", async () => {
        const forced = await call(tabA, "connect", "forced", { ...options, shared: false, lockWaitMillis: 500 });
        assert.ok(!forced.ok, "a dedicated Worker over the same key store is refused");
        assert.match(forced.error, new RegExp(`another host holds the Web Lock agentspaces:${group}:${a.peerId}`));
        await sleep(300);
        assert.equal(hub.peer.inbound.size, 1, "the refused host never dialled");
      });

      await t.test("the pause rule: leases stop being renewed, the channel closes, nothing outlives its lease (JS-R-03)", async () => {
        const jobId = hub.peer.writeEntry(SPACE, TASK, { topic: "job", priority: 5 }, "hub");
        const taken = await call(tabA, "take", "a", SPACE, "job", 1000, 15_000, true);
        assert.equal(taken, jobId, "tab A holds the hub's job under a 1 s lease");
        await sleep(1600);
        assert.equal(await hub.peer.takeEntry(SPACE, TASK, "hub", 60_000, 300, 700, null, jobId), null,
          `while the host runs, the tick renews the claim past its lease: the hub cannot take it\n${(await call(tabA, "hostLog", "a")).join("\n")}`);
        const renewed = await call(tabA, "renew", jobId);
        assert.ok(renewed.ok, `an explicit renew succeeds while running: ${renewed.ok ? "" : renewed.error}`);
        // The last active page hides: the host pauses.
        if (tabB !== null) {
          await call(tabB, "pagehide", true);
        }
        await call(tabA, "pagehide", true);
        await until(() => hub.peer.inbound.size === 0, "the host closed its channel on pause");
        const paused = await call(tabA, "status", "a");
        assert.equal(paused.paused, true);
        assert.equal(paused.activePages, 0);
        const refused = await call(tabA, "renew", jobId);
        assert.ok(!refused.ok && /paused/.test(refused.error), `renewal is refused while paused: ${JSON.stringify(refused)}`);
        await sleep(1600); // the claim's lease lapses while the host is paused
        assert.equal(await hub.peer.takeEntry(SPACE, TASK, "hub", 60_000, 300, 1500, null, jobId), jobId,
          "the claim lapsed on time: the hub takes the job");
        // A page returns: the same identity resumes.
        await call(tabA, "pageshow");
        await until(() => hub.peer.inbound.size === 1, "the host dialled again on resume");
        const resumed = await call(tabA, "status", "a");
        assert.equal(resumed.peerId, a.peerId, "the same identity");
        assert.equal(resumed.paused, false);
        assert.equal(resumed.instance, a.instance, "the same worker");
        const completed = await call(tabA, "complete", jobId, "late");
        assert.ok(!completed.ok && /Current exact live claim required/.test(completed.error),
          `the lapsed claim cannot complete: ${JSON.stringify(completed)}`);
        const log = await call(tabA, "stateLog", "a");
        assert.ok(log.includes("paused:offline") && log.includes("running:connected"), `state events reached the page: ${log.join(" ")}`);
        if (tabB !== null) {
          await call(tabB, "pageshow");
        }
      });

      await t.test("keys persist across a reload, and the worker's death closes the channel (JS-P-08, JS-R-03)", async () => {
        assert.equal(await call(tabA, "storedPeerId", group), a.peerId, "IndexedDB holds the identity the host runs");
        await tabA.reload();
        await tabA.waitForFunction(() => (globalThis as { ready?: boolean }).ready === true, undefined, { timeout: 30_000 });
        const again = await call(tabA, "connect", "a", options);
        assert.ok(again.ok, `tab A reconnects after a reload: ${again.ok ? "" : again.error}`);
        assert.equal(again.peerId, a.peerId, "the same PeerID after a reload");
        await until(() => hub.peer.inbound.size === 1, "one connection after the reload");
        // Every page leaves: the worker loses its last client (a SharedWorker dies, a dedicated one is closed).
        if (tabB !== null) {
          await tabB.close({ runBeforeUnload: false });
        }
        await tabA.close({ runBeforeUnload: false });
        await until(() => hub.peer.inbound.size === 0, "the worker's end closed the channel", 20_000);
        const tabC = await openTab(context, `${origin}/?tab=c`, errors);
        const c = await call(tabC, "connect", "c", options);
        assert.ok(c.ok, `a new tab starts the host again: ${c.ok ? "" : c.error}`);
        assert.equal(c.peerId, a.peerId, "the same PeerID from IndexedDB");
        t.diagnostic(`${engine}: worker instance ${c.instance === a.instance ? "survived" : "restarted"} after the last tab closed`);
        await until(() => hub.peer.inbound.size === 1, "the new host dialled");
        assert.ok((await call(tabC, "readAll", "c", SPACE, 3)).includes("from-a"),
          "the restarted host restored its IndexedDB snapshot before dialling");
        assert.deepEqual(await call(tabC, "read", "c", SPACE, "from-a", 10_000), { topic: "from-a", priority: 3 });
        await call(tabC, "close", "c");
        await until(() => hub.peer.inbound.size === 0, "closing the last page's handle pauses the host");
        await tabC.close();
      });

      await t.test("a dedicated Worker is the fallback, forced here (JS-R-02)", async () => {
        const fresh = await browser.newContext();
        const base = hub.peer.inbound.size;
        try {
          const tab = await openTab(fresh, `${origin}/?tab=d`, errors);
          const d = await call(tab, "connect", "d", { ...options, shared: false });
          assert.ok(d.ok, `a dedicated Worker hosts: ${d.ok ? "" : d.error}`);
          assert.equal(d.shared, false);
          assert.notEqual(d.peerId, a.peerId, "a fresh context is a fresh identity");
          await until(() => hub.peer.inbound.size === base + 1, "the dedicated host dialled");
          const id = await call(tab, "write", "d", SPACE, "from-dedicated", 1);
          await until(() => hub.peer.states.has(id), "its write reaches the hub");
          const hints = hub.peer.members.get(d.peerId)!["resourceHints"] as { [k: string]: string };
          assert.equal(hints["js.residency"], "resident");
          await call(tab, "close", "d");
          await until(() => hub.peer.inbound.size === base, "detaching the only page ends the dedicated host");
        } finally {
          await fresh.close();
        }
      });

      assert.deepEqual(errors, [], `${engine} page errors`);
    } finally {
      await context.close();
      await browser.close();
      await hub.stop();
      server.close();
    }
  });
}
