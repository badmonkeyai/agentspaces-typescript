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

/** JS-W-08: installing the binding advertises `Endpoint("webrtc", "sig", p)` after every stream endpoint. */

import assert from "node:assert/strict";
import test from "node:test";
import { Identity, Peer } from "@agentspaces/client";
import { WebRtcBinding } from "../src/binding.js";

test("a peer with the binding advertises a webrtc sig endpoint after its stream endpoints (JS-W-08)", async () => {
  const peer = new Peer(Identity.generate(), "zWebRtcGroup");
  peer.endpoints.push({ transport: "tcp", address: "127.0.0.1:7500", priority: 0 });
  let binding: WebRtcBinding;
  try {
    binding = await WebRtcBinding.install(peer);
  } catch (e) {
    if (String(e).includes("node-datachannel")) {
      return; // no implementation on this machine: the refusal names the package (JS-W-02)
    }
    throw e;
  }
  assert.deepEqual(peer.endpoints.map((e) => `${String(e["transport"])}:${String(e["address"])}:${String(e["priority"])}`),
    ["tcp:127.0.0.1:7500:0", "webrtc:sig:1"]);
  await WebRtcBinding.install(peer); // idempotent
  assert.equal(peer.endpoints.filter((e) => e["transport"] === "webrtc").length, 1);
  assert.ok(peer.dialableSchemes().includes("webrtc"));
  void binding;
  peer.close();
});
