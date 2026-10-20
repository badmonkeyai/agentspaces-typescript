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
 * The Node worker of the Java cross-language ordered-take test
 * (agentspaces-capabilities TypeScriptOrderedTakeTest; srad/agentspaces-js.md
 * JS-V-05): dials a Java seed over tcp, joins by the founding, finds the
 * ordered log in the ads, takes the one Job through the log as a Raft
 * client, completes it, writes a Done, and prints one JSON line.
 *
 *   node build/test/workers/ordered-worker.js <host> <port> <founding> <jobType> <doneType> [maxSeconds]
 */

import { loads } from "../../src/cbor.js";
import { OrderedLog, Pipes } from "../../src/capabilities/index.js";
import { groupIdFromFounding, Identity } from "../../src/identity.js";
import { Peer } from "../../src/peer.js";
import "../../src/node/index.js";

const sleep = (millis: number) => new Promise((resolve) => setTimeout(resolve, millis));

async function main(): Promise<number> {
  const [host, port, founding, jobType, doneType, maxSeconds] = process.argv.slice(2);
  const peer = new Peer(Identity.generate(), groupIdFromFounding(founding));
  await peer.connect(host, Number(port));
  await sleep(1000);
  peer.pullAds();
  const log = new OrderedLog(new Pipes(peer));
  const deadline = Date.now() + Number(maxSeconds ?? 60) * 1000;
  let taken: string | null = null;
  let members = 0;
  while (taken === null && Date.now() < deadline) {
    members = log.members().length;
    taken = await log.take("jobs", jobType, "ts-worker", 60_000, 10_000);
  }
  if (taken === null) {
    console.log(JSON.stringify({ ok: false, reason: "no job taken through the log", logMembers: members,
      leader: log.leader(), reachable: [...peer.reachable].length }));
    peer.close();
    return 2;
  }
  const claim = peer.claims.get(taken)?.["claim"] as { epoch?: unknown } | undefined;
  peer.completeEntry("jobs", taken);
  const record = peer.states.get(taken)?.["record"] as { payload?: Uint8Array } | undefined;
  const payload = record?.payload instanceof Uint8Array ? loads(record.payload) as { jobId?: unknown } : {};
  peer.writeEntry("jobs", doneType, { jobId: String(payload.jobId ?? "job-1"), by: "typescript-ordered" }, "ts-worker", 600_000);
  await sleep(1500);
  console.log(JSON.stringify({ ok: true, taken, epoch: Number(claim?.epoch ?? 0), logMembers: members,
    leader: log.leader(), peerId: peer.identity.peerId }));
  peer.close();
  return 0;
}

main().then((code) => process.exit(code), (e) => {
  console.log(JSON.stringify({ ok: false, reason: String(e instanceof Error ? e.message : e) }));
  process.exit(1);
});
