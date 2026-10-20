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
 * The `webrtc` binding of the AgentSpaces JavaScript client (SRAD srad/agentspaces-js.md §3.4,
 * §3.5, §4.3): {@link WebRtcBinding} over one RTCPeerConnection per connection, signalling over the
 * `aspace:cap/rtc-signal` capability pipe, attestation by signed DTLS fingerprint. Runs over the
 * global RTCPeerConnection in a browser and over node-datachannel's polyfill on Node.
 */

export { WebRtcBinding, loadRtc } from "./binding.js";
export type { WebRtcOptions } from "./binding.js";
export { WebRtcCounters } from "./counters.js";
export * as chunk from "./chunk.js";
export * as fingerprints from "./fingerprints.js";
export * as signal from "./signal.js";
