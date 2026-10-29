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

// The cell host of the AgentSpaces JavaScript client (srad/agentspaces-js.md
// §3.8, §4.5, §4.7, §4.8): Durable Object cells on celld, workerd, and
// Cloudflare. This entry imports `cloudflare:workers`; a Node test of the
// providers, the manifest, `once`, or the key store imports those modules
// directly.
export { AgentSpacesCell, AgentSpacesConnectorCell, CellHost, RESIDENCY_HINT, SNAPSHOT_CHUNK_BYTES, STATE_TABLE }
  from "./cell.js";
export type { CellEntry, CellStatus, Where } from "./cell.js";
export { DEFAULT_IDLE_MILLIS, DEFAULT_INTRODUCE_MILLIS, DEFAULT_RECONNECT_MILLIS, DEFAULT_SNAPSHOT_MILLIS,
  DEFAULT_TICK_MILLIS, cellConfig, parseSeeds, profileOf } from "./config.js";
export type { CellConfig, CellProfile } from "./config.js";
export { Fleet, FleetSpace, FleetTaken, fleet } from "./fleet.js";
export type { FleetEntry } from "./fleet.js";
export { KEYS_TABLE, PEER_KEY, SqliteKeyStore, blobOf, bytesOf, loadOrCreateIdentity } from "./keystore.js";
export { DEFAULT_FRESHNESS, DEFAULT_TTL, OBJECT_PARAM, OP_PARAM, assetsOf, cardId, cardOf, cardTtl, routeMode, routeName,
  validateManifest } from "./manifest.js";
export type { AssetKind, AssetManifest, D1QuerySpec, D1Spec, DurableObjectSpec, KvSpec, ManifestAsset, OperationSpec,
  QueueSpec, R2Spec, RouteSpec, WorkersRuntime, WorkflowSpec } from "./manifest.js";
export { DEFAULT_ONCE_RETENTION, ONCE_TABLE, once, prune, recorded, recordedCount } from "./once.js";
export type { OnceOptions, OnceStorage } from "./once.js";
export { INVOCATION_HEADER, WorkersAssetProvider, rowOf, rowsOf, stringOf } from "./providers.js";
export { R2PieceStore, publishR2Object } from "./content.js";
export type { R2PublishOptions } from "./content.js";
export type { WorkersProviderOptions } from "./providers.js";
export type { CellEnv, CellStateLike, CellStorageLike, D1DatabaseLike, DurableObjectNamespaceLike, DurableObjectStubLike,
  FetcherLike, KVNamespaceLike, QueueLike, R2BucketLike, R2ObjectLike, SqlCursorLike, SqlStorageLike, SqlValue,
  WorkflowInstanceLike, WorkflowLike } from "./workers-types.js";
