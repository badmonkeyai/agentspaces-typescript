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

// @agentspaces/automerge (srad/agentspaces-js.md JS-S-01, JS-S-03): the
// automerge-repo NetworkAdapter over a peer's capability pipes. This entry
// imports no Node module: it loads wherever the portable core does.
export { AgentSpacesNetworkAdapter, TYPE, DEFAULT_MAX_PAYLOAD_BYTES, ENVELOPE_HEADROOM_BYTES } from "./adapter.js";
export type { AgentSpacesNetworkAdapterOptions } from "./adapter.js";
