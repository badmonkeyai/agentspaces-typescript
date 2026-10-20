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

// Namespaces are re-exported as import-then-export rather than `export * as`, which
// Closure (shadow-cljs, the portal page) cannot parse.
// The portable core (srad/agentspaces-js.md §3.1): this entry imports no Node
// module, so it loads in browsers, Workers, Deno, and Bun. Node adapters live
// at "@agentspaces/client/node".
import * as cbor from "./cbor.js";
export { cbor };
import * as bytes from "./bytes.js";
export { bytes };
export { CryptoPort, cryptoPort, installCrypto, nobleCrypto } from "./crypto.js";
export * from "./platform.js";
export * from "./transport.js";
export { parseSeed, schemeOf, seedAddress, seedUrl } from "./seed.js";
export { Emitter, ContextStore, contextStore, installContextStores } from "./emitter.js";
import * as session from "./session.js";
export { session };
export { WsDialer, WsChannel, SUBPROTOCOL } from "./transport/ws.js";
export type { WebSocketLike } from "./transport/ws.js";
export { MemoryChannel, MemoryNetwork, settle } from "./transport/mem.js";
import * as serving from "./serving.js";
export { serving };
export { HttpDialer, HttpChannel, encodeBatch, decodeBatch } from "./transport/http.js";
import "./transport/defaults.js";
export * from "./identity.js";
import * as revocation from "./revocation.js";
export { revocation };
import * as wire from "./wire.js";
export { wire };
export { Peer } from "./peer.js";
export type { InviteJoined } from "./peer.js";
import * as social from "./social.js";
export { social };
import * as beacon from "./beacon.js";
export { beacon };
import * as vote from "./vote.js";
export { vote };
export * from "./space.js";
export * from "./agents.js";
export { JOIN_TICKET_TYPE, JOIN_TAG, KEY_TAG, JoinBinding, JoinTicket, KeyTickets } from "./join.js";
export type { JoinConfig, ResolvedPart } from "./join.js";
export { GLOBAL_KEY, REDUCE_KEY_TAG, REDUCE_TAG, STEPS_TAG, ReduceBinding, current as currentAccumulator,
  reductionTemplate, steps as accumulatorSteps } from "./reduce.js";
export type { ReduceConfig } from "./reduce.js";
import * as capabilities from "./capabilities/index.js";
export { capabilities };
