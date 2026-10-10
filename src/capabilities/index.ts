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
 * Layer 4 from TypeScript (L3L4-COVERAGE.md §6.5): the capability services
 * over the peer's PIPE_DATA pipes, in the protocols the Java providers speak.
 * Ordered takes (the Raft client), joins, and reduces are the plan's phase G
 * and are not here yet.
 */

export { Pipes } from "./pipes.js";
export { Aggregate, Settle } from "./aggregate.js";
export type { Estimate, Mode } from "./aggregate.js";
export { HashingEmbedder, Semantic, cosine, javaHash, textOf } from "./semantic.js";
export type { Match } from "./semantic.js";
export { actions, invoke, sharedFields } from "./remote.js";
export type { RemoteAction } from "./remote.js";
