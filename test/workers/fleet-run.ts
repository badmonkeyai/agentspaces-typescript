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
 * The fleet worker's logic over the portable core alone, shared by the Node
 * worker and the browser page (srad/agentspaces-js.md JS-Q-REL-02): dial the
 * seed over the named scheme, join by the founding, take the one Job the Java
 * side wrote, complete it, write a Done, and report what was counted.
 */

import { groupIdFromFounding, Identity } from "../../src/identity.js";
import { Peer } from "../../src/peer.js";

export type WorkerArgs = { scheme: string; host: string; port: number; founding: string; jobType: string;
  doneType: string; maxSeconds: number };

export type WorkerResult = { scheme: string; ok: boolean; reason?: string; taken?: string; jobsSeen?: number;
  sessionFramesSent?: number; malformedFrames?: number; channel?: string | null; peerId?: string };

const sleep = (millis: number) => new Promise((resolve) => setTimeout(resolve, millis));

export async function runFleetWorker(args: WorkerArgs): Promise<WorkerResult> {
  const { scheme, host, port, founding, jobType, doneType, maxSeconds } = args;
  const peer = new Peer(Identity.generate(), groupIdFromFounding(founding));
  try {
    await peer.connectAny([{ host, port, scheme }]);
    const deadline = Date.now() + maxSeconds * 1000;
    let taken: string | null = null;
    while (taken === null && Date.now() < deadline) {
      taken = await peer.takeEntry("jobs", jobType, "ts-worker", 60_000, 600, 10_000);
    }
    if (taken === null) {
      return { scheme, ok: false, reason: "no job taken", peerId: peer.identity.peerId };
    }
    const jobsSeen = peer.find(jobType).length; // the taken entry's payload stays readable until completed
    peer.completeEntry("jobs", taken);
    peer.writeEntry("jobs", doneType, { jobId: "job-1", by: "typescript-" + scheme }, "ts-worker", 600_000);
    await sleep(1500); // let the write and the completion reach the seed before the channel goes
    return { scheme, ok: true, taken, jobsSeen, sessionFramesSent: peer.sessionFramesSent,
      malformedFrames: peer.malformedFrames, channel: peer.currentChannel()?.scheme ?? null,
      peerId: peer.identity.peerId };
  } catch (e) {
    return { scheme, ok: false, reason: e instanceof Error ? e.message : String(e) };
  } finally {
    peer.close();
  }
}
