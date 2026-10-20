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
 * A Node voter for the cross-language ordered desk (srad/agentspaces-js.md
 * JS-V-11; the Java test `NodeVoterDeskTest`): a service host that listens
 * on tcp, dials the first Java voter and links to the second, and hosts the
 * `jobs` ordered log with the Java voters as the other members. It prints one
 * JSON line per event on stdout — `up` with its PeerID and address, `state`
 * on every role change, `committed` for every claim the log commits — and
 * stops on `stop` from stdin or SIGTERM.
 *
 * Arguments: seedHost seedPort secondPort founding listenPort javaMemberIds(comma-separated) [logDir]
 */

import { createInterface } from "node:readline";
import { Identity } from "@agentspaces/client";
import { OrderedLogHost } from "@agentspaces/ordered";
import { FileLogStore } from "../../src/file-log-store.js";
import { ServiceHost } from "../../src/host.js";

async function main(): Promise<number> {
  const [seedHost, seedPort, secondPort, founding, listenPort, memberIds, logDir] = process.argv.slice(2);
  const { groupIdFromFounding } = await import("@agentspaces/client");
  const identity = Identity.generate();
  const host = new ServiceHost(identity, groupIdFromFounding(founding), {
    tickMillis: 250,
    seeds: [{ host: seedHost, port: Number(seedPort) }],
    listeners: [{ scheme: "tcp", bind: `127.0.0.1:${listenPort}` }],
    spaces: ["jobs"],
    log: (line) => console.log(JSON.stringify({ event: "log", line })),
  });
  const members = [...memberIds.split(",").filter((m) => m.length > 0), identity.peerId];
  const ordered = new OrderedLogHost(host.peer, "jobs", members, {
    residency: "service", tickMillis: 250,
    store: logDir !== undefined ? new FileLogStore(logDir) : undefined,
  });
  await ordered.ready();
  let committed = 0;
  ordered.onCommitted((entryId, claim) => {
    committed += 1;
    console.log(JSON.stringify({ event: "committed", entryId, epoch: Number(claim["epoch"]), holder: String(claim["holder"]), committed }));
  });
  host.addDuty(ordered);
  await host.start();
  // A second link, to the other Java voter, so every Raft pipe has a direct route whichever
  // member leads and whichever dies.
  const dialer = host.peer.dialers.get("tcp")!;
  const second = await dialer.dial({ host: seedHost, port: Number(secondPort) });
  host.peer.acceptChannel(second);
  console.log(JSON.stringify({ event: "up", peerId: identity.peerId, tcp: host.addresses.get("tcp"), members }));
  let lastRole = "";
  const roles = setInterval(() => {
    const role = `${ordered.raft.currentRole()}@${ordered.raft.currentTerm()}`;
    if (role !== lastRole) {
      lastRole = role;
      console.log(JSON.stringify({ event: "state", role: ordered.raft.currentRole().toLowerCase(), term: ordered.raft.currentTerm(),
        leader: ordered.raft.leader(), committed }));
    }
  }, 100);
  await new Promise<void>((resolve) => {
    const stop = (): void => resolve();
    process.once("SIGTERM", stop);
    process.once("SIGINT", stop);
    createInterface({ input: process.stdin }).on("line", (line) => {
      if (line.trim() === "stop") {
        stop();
      }
    }).on("close", stop);
  });
  clearInterval(roles);
  await host.stop();
  console.log(JSON.stringify({ event: "down", committed, installed: ordered.claimsInstalled }));
  return 0;
}

main().then((code) => { process.exit(code); }, (e) => {
  console.log(JSON.stringify({ event: "error", message: e instanceof Error ? e.message : String(e) }));
  process.exit(1);
});
