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
 * The council worker of the polyglot demo (L3L4-COVERAGE.md §6.6): a
 * TYPESCRIPT member of the Java coordinator's council. It joins the research
 * fleet, binds a decorated agent that takes the coordinator's tasks and votes
 * on its proposal, contributes its load to the push-sum epoch, answers
 * semantic queries over the pipe, and serves the remote action its card
 * declares. Start the Java CouncilFleet first, then:
 *
 *     node build/demo/council.js 127.0.0.1 7470 30 [max-seconds]
 */

import { Binder, agent, ballot, onDecision, spaceTake } from "../src/agents.js";
import type { Decision, Proposal } from "../src/agents.js";
import { Aggregate, Pipes, Semantic, Settle } from "../src/capabilities/index.js";
import { Identity, groupIdFromFounding } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import { entry } from "../src/space.js";

@entry("ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1")
class ResearchTask {
  constructor(public topic = "", public priority = 0) {}
}

@entry("ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1")
class Finding {
  constructor(public topic = "", public summary = "", public worker = "") {}
}

const state = { completed: 0, decided: null as Decision | null };

@agent("ts-researcher", { description: "Researches topics in TypeScript and sits on the council", goals: ["research", "vote"] })
class Councillor {
  @spaceTake(ResearchTask, "tasks", { lease: "30s", pollTimeout: "2s", produces: Finding,
    description: "Researches one topic in TypeScript" })
  research(task: ResearchTask): Finding {
    state.completed += 1;
    console.log(`  [ts] took and completed '${task.topic}' (${state.completed})`);
    return new Finding(task.topic, `researched in typescript: ${task.topic}`, "ts-worker");
  }

  @ballot("votes", { prefix: "council:" })
  judge(proposal: Proposal): string {
    console.log(`  [ts] ballot on ${proposal.proposalId}: yes`);
    return "yes";
  }

  @onDecision("votes", { prefix: "council:" })
  record(decision: Decision): null {
    state.decided = decision;
    console.log(`  [ts] decision ${decision.proposalId} -> ${decision.winner} ${JSON.stringify([...decision.tally])}`);
    return null;
  }
}

const sleep = (millis: number) => new Promise((resolve) => setTimeout(resolve, millis));

async function main(): Promise<number> {
  const host = process.argv[2] ?? "127.0.0.1";
  const port = Number(process.argv[3] ?? 7470);
  const value = Number(process.argv[4] ?? 30);
  const maxSeconds = Number(process.argv[5] ?? 90);
  const identity = Identity.generate();
  const group = groupIdFromFounding("research-fleet-demo-v1");
  console.log(`typescript council worker ${identity.peerId}`);
  const agentIdentity = identity.renewingSubordinate("ts-worker", "PT24H");
  const peer = new Peer(identity, group);
  await peer.connect(host, port);
  await sleep(1000);
  peer.pullAds();
  const pipes = new Pipes(peer);
  const aggregate = new Aggregate(pipes);
  new Semantic(pipes); // answers the coordinator's semantic queries from this peer's cache
  const bound = new Binder(peer, { agent: agentIdentity }).bind(new Councillor());
  aggregate.start("load", value);
  aggregate.run(250);
  let settled: number | null = null;
  const deadline = Date.now() + maxSeconds * 1000;
  try {
    while (Date.now() < deadline) {
      if (settled === null) {
        settled = await aggregate.awaitSettled("load", Settle.after(3, 0.01), 1000);
        if (settled !== null) {
          console.log(`  [ts] epoch load settled at ${settled.toFixed(3)}`);
        }
      }
      peer.pullSpace("tasks");
      peer.pullSpace("votes");
      await sleep(500);
    }
  } finally {
    await bound.close();
    aggregate.close();
    peer.close();
  }
  console.log(`typescript council worker done: ${state.completed} tasks, decision ${state.decided?.winner ?? "none"}, estimate ${settled}`);
  return state.completed >= 1 && state.decided !== null && settled !== null ? 0 : 1;
}

main().then((code) => process.exit(code));
