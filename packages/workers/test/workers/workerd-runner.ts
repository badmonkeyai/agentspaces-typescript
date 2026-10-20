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
 * The runner the Java cross-language test drives (agentspaces-connect-core
 * `WorkerdCellConnectorTest`; srad/agentspaces-js.md JS-C-12): starts the
 * example Worker under workerd with the connector cell dialing a Java seed
 * over `ws`, seeds warehouse-7 with ten of A-100, wakes the cell, and prints
 * one JSON line per event on stdout: `up` with the cell's PeerID once it is
 * connected, `runs` whenever the inventory's run counter moves, `done` on
 * `stop` from stdin, SIGTERM, or after `maxSeconds`.
 *
 *   node packages/workers/build/test/workers/workerd-runner.js <group> <seed-url> [maxSeconds]
 */

import { createInterface } from "node:readline";
import { startWorkerd, toolsPresent } from "./workerd-run.js";

const sleep = (millis: number) => new Promise((resolve) => setTimeout(resolve, millis));

async function main(): Promise<number> {
  const [group, seed, maxSeconds] = process.argv.slice(2);
  const missing = toolsPresent();
  if (missing !== null) {
    console.log(JSON.stringify({ event: "error", reason: missing }));
    return 2;
  }
  const workerd = await startWorkerd({ group: group!, seeds: seed!, profile: "dev-local" });
  try {
    await workerd.get("/stock?object=warehouse-7&sku=A-100&qty=10");
    const status = await workerd.get("/wake") as Record<string, unknown>;
    console.log(JSON.stringify({ event: "up", peerId: status["peerId"], connected: status["connected"], port: workerd.port,
      assets: status["assets"] }));
    let stopping = false;
    const stop = (): void => { stopping = true; };
    process.on("SIGTERM", stop);
    createInterface({ input: process.stdin }).on("line", (line) => { if (line.trim() === "stop") { stop(); } });
    const deadline = Date.now() + Number(maxSeconds ?? 120) * 1000;
    let last = "";
    while (!stopping && Date.now() < deadline) {
      const runs = JSON.stringify({ event: "runs", ...(await workerd.get("/runs?object=warehouse-7") as object) });
      if (runs !== last) {
        console.log(runs);
        last = runs;
      }
      await sleep(250);
    }
    const runs = await workerd.get("/runs?object=warehouse-7") as Record<string, unknown>;
    console.log(JSON.stringify({ event: "done", ...runs }));
    return 0;
  } finally {
    await workerd.stop();
    workerd.cleanup();
    for (const line of workerd.output().split("\n")) {
      if (line.trim().length > 0) {
        console.log(JSON.stringify({ event: "log", line }));
      }
    }
  }
}

main().then((code) => process.exit(code), (e) => {
  console.log(JSON.stringify({ event: "error", reason: String(e instanceof Error ? e.message : e) }));
  process.exit(1);
});
