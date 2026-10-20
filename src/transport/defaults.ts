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
 * Registers the dialers every runtime can run (srad/agentspaces-js.md
 * JS-H-06, JS-H-07) as the defaults a `Peer` starts with: `ws` and `wss` where
 * the runtime has a `WebSocket`, `http` and `https` where it has `fetch`.
 * `peer.ts` imports this module, so a program that imports the peer alone
 * gets them; the node entry adds `tcp`.
 */

import { registerDefaultDialer } from "../transport.js";
import { HttpDialer } from "./http.js";
import { WsDialer } from "./ws.js";

if (typeof (globalThis as { WebSocket?: unknown }).WebSocket === "function") {
  registerDefaultDialer(new WsDialer("ws"));
  registerDefaultDialer(new WsDialer("wss"));
}
if (typeof fetch === "function") {
  registerDefaultDialer(new HttpDialer("http"));
  registerDefaultDialer(new HttpDialer("https"));
}
