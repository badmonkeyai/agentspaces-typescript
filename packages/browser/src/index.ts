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
 * `@agentspaces/browser`: the resident host of the AgentSpaces JavaScript
 * client (srad/agentspaces-js.md §3.6 residency `resident`, JS-R-02,
 * JS-R-03, JS-P-08). This entry is the page side: `connect` and the remote
 * space handles, the IndexedDB key store, and the protocol names. The
 * worker side is `@agentspaces/browser/worker`, the script the SharedWorker
 * or Worker runs; `ResidentHost` is exported here too for a custom worker
 * script. Neither entry imports a Node module.
 */

export { connect, BrowserHost, RemoteSpace, RemoteTaken, RemoteSubscription } from "./page.js";
export type { ConnectOptions, RemoteTakeOptions } from "./page.js";
export { IndexedDbKeyStore, openDatabase, closeDatabase, deleteDatabase, KEYS_STORE, STATE_STORE } from "./idb.js";
export { LockElection } from "./lock.js";
export type { Held } from "./lock.js";
export {
  ResidentHost, DEFAULT_TICK_MILLIS, DEFAULT_LOCK_WAIT_MILLIS, DEFAULT_SNAPSHOT_MILLIS, DEFAULT_PAGE_TIMEOUT_MILLIS,
  DEFAULT_AGENT_NAME, AGENT_TTL, DRIFT_TICKS, DRIFT_FACTOR, RECOVERY_MILLIS, registerBrowserDialers,
} from "./host.js";
export type { ResidentHostOptions } from "./host.js";
export { lockName, identityLockName, databaseName, agentKeyName, packMap, unpackMap, PEER_KEY, PEER_PUB, SNAPSHOT } from "./protocol.js";
export type { HostConfig, HostState, WireEntry, PortLike, Request, Answer, Push } from "./protocol.js";
