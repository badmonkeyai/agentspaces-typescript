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
 * Runs the example Worker (`example/src/index.ts`, the demonstration of
 * JS-C-12) under workerd for the tests: bundles it with esbuild, writes a
 * workerd config with the two SQLite-backed Durable Object namespaces, the
 * `vars` of `wrangler.json` as text bindings, and SQLite storage on local
 * disk (so a restart keeps the cells' identities and state), and starts
 * `workerd serve`. Node only: this is the test harness, not the package.
 */

import { ChildProcess, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
/** The package root (`packages/workers`), from `build/test/workers/`. */
export const PACKAGE = resolve(here, "..", "..", "..");
/** The workspace root (`agentspaces-typescript`). */
export const ROOT = resolve(PACKAGE, "..", "..");
export const BIN = join(ROOT, "node_modules", ".bin");
export const EXAMPLE = join(PACKAGE, "example", "src", "index.ts");

/** Whether the binaries the run needs are installed. */
export function toolsPresent(): string | null {
  for (const binary of ["workerd", "esbuild"]) {
    if (!existsSync(join(BIN, binary))) {
      return `${binary} is not installed (npm install --save-dev ${binary} at the workspace root)`;
    }
  }
  return null;
}

export function freePort(): Promise<number> {
  return new Promise((ok) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as { port: number }).port;
      server.close(() => ok(port));
    });
  });
}

function run(command: string, args: string[], cwd: string): Promise<{ code: number; out: string; err: string }> {
  return new Promise((ok, fail) => {
    const child = spawn(command, args, { cwd });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.on("data", (d) => { err += d; });
    child.on("error", fail);
    child.on("close", (code) => ok({ code: code ?? -1, out, err }));
  });
}

export type WorkerdVars = { group: string; seeds: string; invite?: string; profile?: string };

/** A running workerd with the example Worker: its port, its output so far, and a stop. */
export type WorkerdRun = {
  port: number;
  dir: string;
  output: () => string;
  stop: () => Promise<void>;
  /** The Worker's `fetch` at a path. */
  get: (path: string) => Promise<unknown>;
  /** Removes the run's directory (the bundle, the config, the SQLite files); call after the last stop. */
  cleanup: () => void;
};

/** Bundles the example once into `dir/worker.mjs`. */
export async function bundleExample(dir: string): Promise<string> {
  const bundle = join(dir, "worker.mjs");
  const built = await run(join(BIN, "esbuild"), [EXAMPLE, "--bundle", "--format=esm", "--platform=neutral", "--target=es2022",
    "--main-fields=module,main", "--external:cloudflare:workers", `--outfile=${bundle}`, "--log-level=error"], ROOT);
  if (built.code !== 0) {
    throw new Error(`esbuild failed: ${built.err}`);
  }
  return bundle;
}

/**
 * Starts workerd on the bundle in `dir` (bundled there unless present),
 * with Durable Object storage under `dir/data`; `port` fixed so a restart
 * answers at the same address.
 */
export async function startWorkerd(vars: WorkerdVars, options: { dir?: string; port?: number } = {}): Promise<WorkerdRun> {
  const dir = options.dir ?? mkdtempSync(join(tmpdir(), "aspace-workers-"));
  mkdirSync(join(dir, "data"), { recursive: true });
  if (!existsSync(join(dir, "worker.mjs"))) {
    await bundleExample(dir);
  }
  const port = options.port ?? await freePort();
  const text = (name: string, value: string): string => `(name = "${name}", text = "${value.replace(/"/g, "\\\"")}")`;
  writeFileSync(join(dir, "config.capnp"), `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "main", worker = (
      modules = [(name = "worker.mjs", esModule = embed "worker.mjs")],
      compatibilityDate = "2026-10-01",
      durableObjectNamespaces = [
        (className = "Inventory", uniqueKey = "inventory-v1", enableSql = true),
        (className = "Fleet", uniqueKey = "fleet-v1", enableSql = true),
        (className = "Adjuster", uniqueKey = "adjuster-v1", enableSql = true)
      ],
      durableObjectStorage = (localDisk = "disk"),
      bindings = [
        (name = "INVENTORY", durableObjectNamespace = "Inventory"),
        (name = "FLEET", durableObjectNamespace = "Fleet"),
        (name = "ADJUSTER", durableObjectNamespace = "Adjuster"),
        ${text("AGENTSPACES_GROUP", vars.group)},
        ${text("AGENTSPACES_SEEDS", vars.seeds)},
        ${text("AGENTSPACES_INVITE", vars.invite ?? "")},
        ${text("AGENTSPACES_PROFILE", vars.profile ?? "dev-local")}
      ])),
    (name = "internet", network = (allow = ["private", "public"])),
    (name = "disk", disk = (path = "data", writable = true))
  ],
  sockets = [(name = "http", address = "127.0.0.1:${port}", http = (), service = "main")],
);
`);
  const server: ChildProcess = spawn(join(BIN, "workerd"), ["serve", join(dir, "config.capnp")], { cwd: dir });
  let output = "";
  server.stdout?.on("data", (d) => { output += d; });
  server.stderr?.on("data", (d) => { output += d; });
  const get = async (path: string): Promise<unknown> => {
    const response = await fetch(`http://127.0.0.1:${port}${path}`);
    const body = await response.text();
    try {
      return JSON.parse(body);
    } catch {
      throw new Error(`GET ${path} answered ${response.status}: ${body.slice(0, 300)}`);
    }
  };
  let up = false;
  for (let attempt = 0; attempt < 100 && !up; attempt++) {
    try {
      await get("/status");
      up = true;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  if (!up) {
    server.kill();
    throw new Error(`workerd did not answer on ${port}: ${output}`);
  }
  return {
    port, dir, get, output: () => output,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
    stop: () => new Promise<void>((done) => {
      if (server.exitCode !== null) {
        done();
        return;
      }
      server.once("exit", () => done());
      server.kill();
    }),
  };
}
