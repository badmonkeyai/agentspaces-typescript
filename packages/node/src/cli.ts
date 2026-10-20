#!/usr/bin/env node
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
 * `agentspaces-node run <fleet.yaml>` (srad/agentspaces-js.md JS-R-04) runs
 * the service host(s) a fleet file describes until `SIGTERM`;
 * `agentspaces-node id [keystore]` prints the PeerID of a keystore, creating
 * it when absent, so an operator can name the member in a Java fleet's
 * ordered-log member list.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { loadOrCreateIdentity } from "@agentspaces/client/node";
import { parseFleet, startFleet } from "./fleet.js";

const USAGE = `usage:
  agentspaces-node run <fleet.yaml>    run the service host(s) the fleet file describes
  agentspaces-node id [keystore-dir]   print the PeerID of a keystore (default ./keys), creating it when absent`;

export async function main(argv: string[]): Promise<number> {
  const [command, argument] = argv;
  if (command === "id") {
    const identity = loadOrCreateIdentity(resolve(argument ?? "keys"));
    console.log(identity.peerId);
    return 0;
  }
  if (command !== "run" || argument === undefined) {
    console.error(USAGE);
    return 2;
  }
  const path = resolve(argument);
  const config = parseFleet(readFileSync(path, "utf-8"));
  const fleet = await startFleet(config, dirname(path), { signals: false });
  for (const host of fleet.hosts) {
    console.error(`${host.peer.identity.peerId} in ${host.peer.group}: ${[...host.addresses].map(([s, a]) => `${s}://${a}`).join(", ") || "dial-only"}`);
  }
  await new Promise<void>((done) => {
    const stop = (): void => { void fleet.stop().then(done); };
    process.once("SIGTERM", stop);
    process.once("SIGINT", stop);
  });
  return 0;
}

if (process.argv[1] !== undefined && /cli\.js$/.test(process.argv[1])) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => {
    console.error(e instanceof Error ? e.message : String(e));
    process.exitCode = 1;
  });
}
