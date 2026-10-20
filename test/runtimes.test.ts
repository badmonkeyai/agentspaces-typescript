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
 * JS-P-09 in Deno, Bun, and workerd: each runs the conformance module of
 * `test/browser/conformance.ts` against the portable core and every check
 * must pass. Deno and Bun run the runner directly; workerd runs an esbuild
 * bundle of it as a module worker. A runtime whose binary is missing is
 * skipped with a note unless AGENTSPACES_RUNTIMES_REQUIRED=1.
 */

import assert from "node:assert/strict";
import { ChildProcess, spawn } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, "..", "..");
const RUNNER = join(ROOT, "test", "runtimes", "conformance-runner.mjs");
const WORKER = join(ROOT, "test", "runtimes", "conformance-worker.mjs");
const BIN = join(ROOT, "node_modules", ".bin");
const REQUIRED = process.env.AGENTSPACES_RUNTIMES_REQUIRED === "1";

type Result = { name: string; ok: boolean; detail?: string };

function run(command: string, args: string[]): Promise<{ code: number; out: string; err: string }> {
  return new Promise((ok, fail) => {
    const child = spawn(command, args, { cwd: ROOT });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.on("data", (d) => { err += d; });
    child.on("error", fail);
    child.on("close", (code) => ok({ code: code ?? -1, out, err }));
  });
}

function judge(results: Result[], runtime: string): void {
  assert.deepEqual(results.filter((r) => !r.ok), [], `${runtime} failures`);
  assert.ok(results.length >= 10, `${runtime} ran ${results.length} checks`);
}

function present(binary: string, t: { skip(message: string): void }): boolean {
  if (existsSync(join(BIN, binary))) {
    return true;
  }
  if (REQUIRED) {
    throw new Error(`${binary} is not installed`);
  }
  t.skip(`${binary} is not installed (npm install --save-dev ${binary})`);
  return false;
}

test("the conformance subset passes in Deno (JS-P-09)", async (t) => {
  if (!present("deno", t)) {
    return;
  }
  const { code, out, err } = await run(join(BIN, "deno"), ["run", "--allow-read", "--allow-env", RUNNER]);
  assert.equal(code, 0, err);
  judge(JSON.parse(out.trim().split("\n").pop()!), "deno");
});

test("the conformance subset passes in Bun (JS-P-09)", async (t) => {
  if (!present("bun", t)) {
    return;
  }
  const { code, out, err } = await run(join(BIN, "bun"), [RUNNER]);
  assert.equal(code, 0, err);
  judge(JSON.parse(out.trim().split("\n").pop()!), "bun");
});

function freePort(): Promise<number> {
  return new Promise((ok) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as { port: number }).port;
      server.close(() => ok(port));
    });
  });
}

test("the conformance subset passes in workerd (JS-P-09)", async (t) => {
  if (!present("workerd", t) || !present("esbuild", t)) {
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), "aspace-workerd-"));
  const bundle = join(dir, "worker.mjs");
  const built = await run(join(BIN, "esbuild"), [WORKER, "--bundle", "--format=esm",
    "--platform=neutral", "--main-fields=module,main", `--outfile=${bundle}`, "--log-level=error"]);
  assert.equal(built.code, 0, built.err);
  const port = await freePort();
  writeFileSync(join(dir, "config.capnp"), `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [(name = "main", worker = (modules = [(name = "worker.mjs", esModule = embed "worker.mjs")],
    compatibilityDate = "2026-10-01"))],
  sockets = [(name = "http", address = "127.0.0.1:${port}", http = (), service = "main")],
);
`);
  const server: ChildProcess = spawn(join(BIN, "workerd"), ["serve", join(dir, "config.capnp")], { cwd: dir });
  let stderr = "";
  server.stderr?.on("data", (d) => { stderr += d; });
  try {
    let results: Result[] | null = null;
    for (let attempt = 0; attempt < 50 && results === null; attempt++) {
      try {
        const response = await fetch(`http://127.0.0.1:${port}/`);
        results = await response.json() as Result[];
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    assert.ok(results !== null, `workerd answered (${stderr})`);
    judge(results, "workerd");
  } finally {
    server.kill();
  }
});
