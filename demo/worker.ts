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
 * The TypeScript worker for the trilingual demo: joins the Java research
 * fleet, races the Python worker for tasks under the LEASE_RACE claim
 * lattice, and completes what it wins with findings attributed to ts-worker.
 *
 *     node build/demo/worker.js 127.0.0.1 7468
 */

import { loads } from "../src/cbor.js";
import { Identity, groupIdFromFounding } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import type { Dict } from "../src/wire.js";

const TASK_TYPE = "ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1";
const FINDING_TYPE = "ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1";

function sleep(millis: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, millis));
}

async function main(): Promise<number> {
  const host = process.argv[2] ?? "127.0.0.1";
  const port = Number(process.argv[3] ?? 7468);
  const identity = Identity.generate();
  const group = groupIdFromFounding("research-fleet-demo-v1");
  console.log(`typescript worker ${identity.peerId}`);

  // SPEC §4.2 v0.1.13: the worker acts as its own agent, with a key this peer
  // certifies and renews, so the fleet stores its work AGENT_ATTESTED.
  const agent = identity.renewingSubordinate("ts-worker", "PT24H");
  const peer = new Peer(identity, group);
  await peer.connect(host, port);
  await sleep(1000);

  let completed = 0;
  let idleStrikes = 0;
  const deadline = Date.now() + 90_000;
  while (idleStrikes < 2 && Date.now() < deadline) {
    const entryId = await peer.takeEntry("tasks", TASK_TYPE, "ts-worker",
      60_000, 600, 8_000, agent);
    if (entryId === null) {
      idleStrikes = completed > 0 ? idleStrikes + 1 : idleStrikes;
      continue;
    }
    idleStrikes = 0;
    const record = peer.states.get(entryId)!["record"] as Dict;
    const task = loads(Buffer.from(record["payload"] as Uint8Array)) as Dict;
    peer.completeEntry("tasks", entryId, agent);
    peer.writeEntry("tasks", FINDING_TYPE, {
      topic: task["topic"],
      summary: `researched in typescript: ${task["topic"]}`,
      worker: "ts-worker",
    }, "ts-worker", 3_600_000, agent);
    completed += 1;
    console.log(`  [ts] took and completed '${task["topic"]}' (${completed})`);
  }
  console.log(`typescript worker done: ${completed} tasks`);
  peer.close();
  return 0;
}

main().then((code) => process.exit(code));
