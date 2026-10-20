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

// The connector runtime of the AgentSpaces JavaScript client
// (srad/agentspaces-js.md §4.7): the port of agentspaces-connect-core plus
// the aspace:cap/asset-invoke capability. Portable: no Node module is
// imported here, so the package loads in browsers, Workers, Deno, and Bun.
export { ASSET_CHANGE_TYPE, ASSET_INVOCATION_RESULT_TYPE, ASSET_INVOCATION_TYPE, ASSET_INVOKE_CAPABILITY,
  ASSET_INVOKE_VERSION, AssetChange, AssetInvocation, AssetInvocationResult, DATA_QUERY_CAPABILITY, DATA_QUERY_TYPE,
  DATA_RESULT_TYPE, DataQuery, DataResult, canonicalHash, canonicalStrings } from "./entries.js";
export type { InvokeError, StringMap } from "./entries.js";
export { TableAssetProvider, accessList, assetCard, invokeFailed, invokeResult, isMaterializing, queryFailed,
  queryResult } from "./provider.js";
export type { AssetProvider, Change, InvokeResult, MaterializingAssetProvider, QueryResult } from "./provider.js";
export { invokeScope, scopeAuthorizer, scopeName } from "./authorizer.js";
export type { Authorizer, Operation } from "./authorizer.js";
export { ASSET_CARD_TYPE, ConnectorRuntime, DEFAULT_DATA_SPACE, INLINE_PAYLOAD_LIMIT } from "./runtime.js";
export type { ConnectorOptions } from "./runtime.js";
export { DataQueryClient, assetCards, invoke } from "./client.js";
export type { DataQueryClientOptions, Fetched, InvokeOptions } from "./client.js";
