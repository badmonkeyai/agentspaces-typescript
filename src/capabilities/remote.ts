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
 * Remote actions (RemoteActions, RemoteAction) from TypeScript: the actions
 * the fleet's AgentCards declare, each a take binding (a task space and the
 * schema it consumes and produces), invoked by writing the input into the
 * task space and awaiting the correlated result.
 */

import type { AgentIdentity } from "../identity.js";
import type { Peer } from "../peer.js";
import { EntryType, Space, Template, toPayload } from "../space.js";
import type { Dict } from "../wire.js";

export type RemoteAction = { card: Dict; agent: string; name: string; description: string;
  consumes: string; produces: string; space: string };

/**
 * Every invocable action the cached cards declare: a declared `take` action
 * with one consumed and one produced schema and a space, or, for a card
 * without declared actions, each (consumes, produces, binding) pair.
 */
export function actions(peer: Peer): RemoteAction[] {
  const found: RemoteAction[] = [];
  for (const card of peer.cards()) {
    const agent = String(card["agent"]);
    const declared = (card["actions"] as Dict[] | undefined) ?? [];
    if (declared.length > 0) {
      for (const a of declared) {
        const consumes = (a["consumes"] as string[]) ?? [];
        const produces = (a["produces"] as string[]) ?? [];
        if (a["kind"] === "take" && a["space"] && consumes.length === 1 && produces.length === 1) {
          found.push({ card, agent, name: String(a["name"]), description: String(a["description"] || card["description"] || ""),
            consumes: consumes[0]!, produces: produces[0]!, space: String(a["space"]) });
        }
      }
      continue;
    }
    const bindings = (card["spaceBindings"] as Dict | undefined) ?? {};
    for (const consumed of (card["consumes"] as string[] | undefined) ?? []) {
      const space = bindings[consumed];
      for (const produced of (card["produces"] as string[] | undefined) ?? []) {
        if (space) {
          found.push({ card, agent, name: `${agent.slice(agent.lastIndexOf("/") + 1)}_${consumed}`,
            description: String(card["description"] ?? ""), consumes: consumed, produces: produced, space: String(space) });
        }
      }
    }
  }
  return found;
}

/** Correlation.sharedFields: every field both carry is equal. */
export function sharedFields(input: Dict, candidate: Dict): boolean {
  return Object.entries(input).every(([k, v]) => !(k in candidate) || candidate[k] === v);
}

export type InvokeOptions<T> = { resultType?: EntryType<T>; timeoutMillis?: number; resultSpace?: string;
  lease?: number | string; agent?: AgentIdentity | null; agentName?: string };

/**
 * Writes `value` into the action's task space and resolves with the first
 * result (of the produced schema, decoded as `resultType` when given) not
 * present before the write whose shared fields match; null at the timeout.
 */
export async function invoke<T = Dict>(peer: Peer, action: RemoteAction, value: object,
                                       options: InvokeOptions<T> = {}): Promise<T | null> {
  const agent = options.agent ?? null;
  const agentName = options.agentName ?? "typescript";
  const taskSpace = new Space(peer, action.space, agent, agentName);
  const results = new Space(peer, options.resultSpace ?? action.space, agent, agentName);
  const template = new Template<T>(options.resultType ?? (action.produces as EntryType<T>));
  const input = toPayload(value);
  const baseline = new Set(results.entries(template, 1_000).map((e) => e.entryId));
  taskSpace.write(value, options.lease ?? "10m");
  const deadline = Date.now() + (options.timeoutMillis ?? 30_000);
  while (Date.now() < deadline) {
    for (const e of results.entries(template, 1_000)) {
      if (baseline.has(e.entryId)) {
        continue;
      }
      if (sharedFields(input, toPayload(e.value as object))) {
        return e.value;
      }
    }
    peer.pullSpace(results.name);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return null;
}
