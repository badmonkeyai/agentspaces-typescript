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
 * The Node worker of the Java cross-language connector test
 * (agentspaces-connect-core `TypeScriptConnectorTest`; srad/agentspaces-js.md
 * JS-C-01, JS-C-03, JS-C-10): dials a Java seed over tcp, joins by the
 * founding, and runs a TypeScript connector serving the `orders` table with
 * one invoke operation, `reserve`. It prints one JSON line per event on
 * stdout: `up` with its PeerID once the card is published, `stats` whenever
 * a counter moves (`executed`, `invoked`, `repeated`, `refused`), and stops
 * on `stop` from stdin, SIGTERM, or after `maxSeconds`.
 *
 *   node packages/connect/build/test/workers/connector-worker.js <host> <port> <founding> [maxSeconds]
 */

import { createInterface } from "node:readline";
import { Identity, Peer, groupIdFromFounding } from "@agentspaces/client";
import "@agentspaces/client/node";
import { ConnectorRuntime, TableAssetProvider } from "../../src/index.js";

const sleep = (millis: number) => new Promise((resolve) => setTimeout(resolve, millis));

async function main(): Promise<number> {
  const [host, port, founding, maxSeconds] = process.argv.slice(2);
  const peer = new Peer(Identity.generate(), groupIdFromFounding(founding!));
  await peer.connect(host!, Number(port));
  await sleep(1000);
  const reserved: string[] = [];
  const provider = new TableAssetProvider("orders", "postgres://ops/public.orders",
    "Customer order history with line items and settlement status", "com.example.OrderRow#v1", "PT5M",
    [{ id: "1", region: "eu", amount: "120.00" }, { id: "2", region: "us", amount: "80.00" },
      { id: "3", region: "eu", amount: "45.50" }],
    { reserve: (params, invocationId) => {
      reserved.push(invocationId);
      console.log(JSON.stringify({ event: "reserve", invocationId, qty: params["qty"] ?? "0", runs: reserved.length }));
      return { reserved: params["qty"] ?? "0", invocationId };
    } });
  const connector = new ConnectorRuntime(peer, provider, { connectorName: "ts-connector", pollTimeout: 500,
    log: (line) => console.log(JSON.stringify({ event: "log", line })) });
  connector.start();
  console.log(JSON.stringify({ event: "up", peerId: peer.identity.peerId, assets: connector.assets() }));
  let stopping = false;
  const stop = (): void => { stopping = true; };
  process.on("SIGTERM", stop);
  createInterface({ input: process.stdin }).on("line", (line) => { if (line.trim() === "stop") { stop(); } });
  const deadline = Date.now() + Number(maxSeconds ?? 120) * 1000;
  let last = "";
  while (!stopping && Date.now() < deadline) {
    const stats = JSON.stringify({ event: "stats", executed: connector.executed, servedFromSpace: connector.servedFromSpace,
      invoked: connector.invoked, repeated: connector.repeated, refused: connector.refused, runs: reserved.length });
    if (stats !== last) {
      console.log(stats);
      last = stats;
    }
    await sleep(250);
  }
  await connector.close();
  console.log(JSON.stringify({ event: "done", runs: reserved.length, invoked: connector.invoked, repeated: connector.repeated }));
  peer.close();
  return 0;
}

main().then((code) => process.exit(code), (e) => {
  console.log(JSON.stringify({ event: "error", reason: String(e instanceof Error ? e.message : e) }));
  process.exit(1);
});
