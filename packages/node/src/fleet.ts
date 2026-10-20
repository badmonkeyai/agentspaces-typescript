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
 * The fleet file of `agentspaces-node run` (srad/agentspaces-js.md JS-R-04):
 * the `agentspaces:` subtree of the Java `FleetRuntime` YAML (the Spring
 * property shape, kebab-case), so one file describes a Java and a Node
 * member alike. Keys this host does not use are ignored, as the Java loader
 * ignores Node-only ones. The Node-only block is `ordered-logs` under a group:
 * the space, the fixed member list, and where the log is kept.
 */

import { isAbsolute, resolve } from "node:path";
import { parse } from "yaml";
import { Seed, groupIdFromFounding, parseSeed, residencyOf } from "@agentspaces/client";
import type { Residency } from "@agentspaces/client";
import { loadOrCreateIdentity } from "@agentspaces/client/node";
import { OrderedLogHost } from "@agentspaces/ordered";
import { FileLogStore } from "./file-log-store.js";
import { ListenerSpec, ServiceHost } from "./host.js";

export type OrderedLogConfig = { space: string; members: string[]; logDir: string | null };

export type GroupConfig = {
  name: string;
  /** The literal founding (`GroupId.fromFounding`), or the self-certifying id when `group-id` is given. */
  founding: string | null;
  groupId: string | null;
  seeds: Seed[];
  spaces: string[];
  orderedLogs: OrderedLogConfig[];
  /** A group after the first needs listeners of its own, or runs dial-only. */
  bind: string | null;
  wsBind: string | null;
};

export type FleetConfig = {
  keystore: string;
  bind: string | null;
  tickMillis: number;
  residency: Residency;
  ws: { bind: string; allowedOrigins: string[] } | null;
  groups: GroupConfig[];
};

type Tree = { [key: string]: unknown };

function tree(value: unknown): Tree {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Tree : {};
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : typeof value === "number" ? String(value) : null;
}

function list(value: unknown): unknown[] {
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value === "string") {
    return value.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  }
  return [];
}

/** Parses a fleet file's text; the `agentspaces:` subtree is required. */
export function parseFleet(yamlText: string): FleetConfig {
  const root = tree(parse(yamlText));
  const a = tree(root["agentspaces"]);
  if (Object.keys(a).length === 0) {
    throw new Error("the fleet file has no 'agentspaces:' section");
  }
  const ws = tree(tree(a["transport"])["ws"]);
  const groups = list(a["groups"]).map((g) => {
    const group = tree(g);
    const name = text(group["name"]);
    if (name === null) {
      throw new Error("every group needs a name");
    }
    const founding = text(group["founding"]);
    const groupId = text(group["group-id"] ?? group["groupId"]);
    if (founding === null && groupId === null) {
      throw new Error(`group '${name}' needs 'founding' or 'group-id'`);
    }
    return {
      name, founding, groupId,
      seeds: list(group["seeds"]).map((s) => parseSeed(String(s), 7500, null)),
      spaces: list(group["spaces"]).map((s) => text(typeof s === "object" ? tree(s)["name"] : s))
        .filter((s): s is string => s !== null),
      orderedLogs: list(group["ordered-logs"] ?? group["orderedLogs"]).map((o) => {
        const log = tree(o);
        const space = text(log["space"]);
        if (space === null) {
          throw new Error(`group '${name}': every ordered log names its space`);
        }
        return { space, members: list(log["members"]).map(String), logDir: text(log["log-dir"] ?? log["logDir"]) };
      }),
      bind: text(group["bind"]),
      wsBind: text(tree(group["ws"])["bind"]),
    } satisfies GroupConfig;
  });
  if (groups.length === 0) {
    throw new Error("the fleet file names no groups");
  }
  return {
    keystore: text(a["keystore"]) ?? "keys",
    bind: text(a["bind"]),
    tickMillis: Number(a["tick-millis"] ?? a["tickMillis"] ?? 1000),
    residency: residencyOf(a["residency"] ?? "service"),
    ws: text(ws["bind"]) === null ? null
      : { bind: text(ws["bind"])!, allowedOrigins: list(ws["allowed-origins"] ?? ws["allowedOrigins"]).map(String) },
    groups,
  };
}

export type RunningFleet = { hosts: ServiceHost[]; stop(): Promise<void> };

/**
 * Starts one service host per group: the first group takes the top-level listeners, a later
 * group its own `bind`/`ws.bind` or none. Every ordered log becomes an `OrderedLogHost` duty of
 * its group's host, over a `FileLogStore` under `log-dir` (the keystore directory by default).
 */
export async function startFleet(config: FleetConfig, baseDir: string,
                                 options: { log?: ((line: string) => void) | null; signals?: boolean } = {}): Promise<RunningFleet> {
  const under = (path: string): string => (isAbsolute(path) ? path : resolve(baseDir, path));
  const identity = loadOrCreateIdentity(under(config.keystore));
  const hosts: ServiceHost[] = [];
  for (const [index, group] of config.groups.entries()) {
    const listeners: ListenerSpec[] = [];
    const tcpBind = group.bind ?? (index === 0 ? config.bind : null);
    const wsBind = group.wsBind ?? (index === 0 ? config.ws?.bind ?? null : null);
    if (tcpBind !== null) {
      listeners.push({ scheme: "tcp", bind: tcpBind });
    }
    if (wsBind !== null) {
      listeners.push({ scheme: "ws", bind: wsBind, origins: config.ws?.allowedOrigins ?? [] });
    }
    const groupId = group.groupId ?? groupIdFromFounding(group.founding!);
    const host = new ServiceHost(identity, groupId, {
      tickMillis: config.tickMillis, seeds: group.seeds, listeners, spaces: group.spaces,
      log: options.log, signals: options.signals ?? false,
    });
    for (const log of group.orderedLogs) {
      const members = log.members.includes(identity.peerId) ? log.members : [...log.members, identity.peerId];
      const store = new FileLogStore(under(log.logDir ?? `${config.keystore}/ordered-log-${log.space}`));
      const ordered = new OrderedLogHost(host.peer, log.space, members,
        { store, residency: config.residency, tickMillis: config.tickMillis });
      await ordered.ready();
      host.addDuty(ordered);
    }
    hosts.push(host);
  }
  for (const host of hosts) {
    await host.start();
  }
  return {
    hosts,
    stop: async () => {
      for (const host of hosts) {
        await host.stop();
      }
    },
  };
}
