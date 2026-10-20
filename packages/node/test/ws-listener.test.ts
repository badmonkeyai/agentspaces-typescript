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
 * The `ws` listener (srad/agentspaces-js.md JS-R-04): the core's `ws` dialer
 * (Node 22's global WebSocket) reaches a service host through it and frames
 * flow both ways; a browser origin is refused until listed and admitted when
 * it is; the subprotocol is required.
 */

import assert from "node:assert/strict";
import test from "node:test";
import { WebSocket } from "ws";

import { Identity, Peer, SUBPROTOCOL } from "@agentspaces/client";
import { ServiceHost } from "../src/host.js";
import { originAllowed } from "../src/ws-listener.js";

const GROUP = "zWsHostGroup";
const TASK = "com.acme.Task#v1";
const sleep = (millis: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, millis));

async function until(condition: () => boolean, millis = 5000): Promise<void> {
  const deadline = Date.now() + millis;
  while (!condition()) {
    if (Date.now() > deadline) {
      throw new Error("condition not met in time");
    }
    await sleep(25);
  }
}

/** The status of an upgrade attempt with the given headers, or "open" when it succeeded. */
function attempt(url: string, headers: { [name: string]: string }, protocols: string[] = [SUBPROTOCOL]): Promise<string> {
  return new Promise((resolve) => {
    const socket = new WebSocket(url, protocols, { headers });
    socket.on("open", () => { socket.close(); resolve("open"); });
    socket.on("unexpected-response", (_request, response) => { resolve(String(response.statusCode)); socket.terminate(); });
    socket.on("error", (e) => resolve(e.message));
  });
}

test("the origin policy admits no-origin requests, listed origins, and * (OriginPolicy)", () => {
  assert.ok(originAllowed([], undefined));
  assert.ok(!originAllowed([], "https://app.example"));
  assert.ok(originAllowed(["https://app.example"], "https://app.example/"));
  assert.ok(originAllowed(["https://APP.example"], "https://app.example"));
  assert.ok(!originAllowed(["https://app.example"], "https://evil.example"));
  assert.ok(originAllowed(["*"], "https://anyone.example"));
});

test("a peer dials the ws listener with the core dialer and a browser is refused until its origin is listed", async () => {
  const host = new ServiceHost(Identity.generate(), GROUP, {
    tickMillis: 50, listeners: [{ scheme: "ws", bind: "127.0.0.1:0", origins: ["https://app.example"] }], spaces: ["tasks"], log: null,
  });
  await host.start();
  const address = host.addresses.get("ws")!;
  const port = Number(address.substring(address.lastIndexOf(":") + 1));
  const peer = new Peer(Identity.generate(), GROUP);
  try {
    await peer.connectAny([{ host: "127.0.0.1", port, scheme: "ws" }]);
    const id = peer.writeEntry("tasks", TASK, { topic: "over ws" }, "p");
    await until(() => host.peer.states.has(id));
    await until(() => peer.members.has(host.peer.identity.peerId));
    assert.equal(JSON.stringify(peer.members.get(host.peer.identity.peerId)!["endpoints"]),
      JSON.stringify([{ transport: "ws", address, priority: 0 }]));
    const url = `ws://127.0.0.1:${port}/`;
    assert.equal(await attempt(url, { origin: "https://evil.example" }), "403");
    assert.equal(await attempt(url, { origin: "https://app.example" }), "open");
    assert.equal(await attempt(url, {}), "open");
    assert.equal(await attempt(url, {}, ["other.1"]), "400", "the subprotocol is required");
  } finally {
    peer.close();
    await host.stop();
  }
});
