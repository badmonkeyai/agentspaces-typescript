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
 * A cell's configuration (srad/agentspaces-js.md §7.2, JS-R-05, JS-S-07):
 * the `vars` block of `wrangler.json` read from the environment,
 * `AGENTSPACES_GROUP`, `AGENTSPACES_SEEDS`, `AGENTSPACES_INVITE`, and
 * `AGENTSPACES_PROFILE`, so one file deploys unchanged to celld, workerd,
 * and Cloudflare. The profile decides the scheme a bare seed is dialed
 * with: `wss` under `attested`, `ws` under `dev-local`; a plaintext seed
 * under `attested` is refused, naming the rule. Every cadence is an option
 * with a default; nothing here caps the fleet.
 */

import { parseSeed, schemeOf } from "@agentspaces/client";
import type { Seed } from "@agentspaces/client";
import type { CellEnv } from "./workers-types.js";

/** The profiles a cell runs under: `attested` (the default) dials only `wss`; `dev-local` dials `ws` too. */
export type CellProfile = "attested" | "dev-local";

export type CellConfig = {
  /** The group the cell joins (`AGENTSPACES_GROUP`). */
  group: string;
  /** The seeds the cell dials, in order (`AGENTSPACES_SEEDS`, comma or whitespace separated). */
  seeds: Seed[];
  /** The join credential hint (`AGENTSPACES_INVITE`): an invite key with a delegation, or a credential as issued. */
  invite: string | null;
  /** `attested` or `dev-local` (`AGENTSPACES_PROFILE`). */
  profile: CellProfile;
  /** The cell's member name: the connector's `servedBy` and the holder of its takes; default the object's name, else `connector`. */
  name: string;
  /** The space queries and results flow through; default `data`. */
  dataSpace: string;
  /** The space invocations flow through; default the data space. */
  taskSpace: string;
  /** The space materialized changes go to; default the data space. */
  changeSpace: string;
  /** The alarm cadence while the cell is busy (a claim held, a query served); default 1 s. */
  tickMillis: number;
  /** The alarm cadence while idle; default the card refresh interval (half the card TTL), 60 s when no card. */
  idleMillis: number | null;
  /** The alarm cadence while disconnected; default 5 s. */
  reconnectMillis: number;
  /** How often the peer's state snapshot is written to SQLite; default 10 s. */
  snapshotMillis: number;
  /** How often the cell re-introduces itself while connected; default 5 minutes. */
  introduceMillis: number;
  /** The in-memory housekeeping tick while the object is live; default 1 s. */
  housekeepingMillis: number;
  /** How long a busy mark keeps the alarm at the busy cadence; default 5 s. */
  busyWindowMillis: number;
  /** Where the cell reports; default `console.log`, `null` for silence. */
  log: ((line: string) => void) | null;
};

export const DEFAULT_TICK_MILLIS = 1_000;
export const DEFAULT_RECONNECT_MILLIS = 5_000;
export const DEFAULT_SNAPSHOT_MILLIS = 10_000;
export const DEFAULT_INTRODUCE_MILLIS = 5 * 60_000;
export const DEFAULT_IDLE_MILLIS = 60_000;

const PLAINTEXT = new Set(["ws", "http", "tcp"]);

/** The seeds of `AGENTSPACES_SEEDS` under a profile: bare seeds get `wss` (`ws` under `dev-local`). */
export function parseSeeds(text: string, profile: CellProfile): Seed[] {
  const defaultScheme = profile === "dev-local" ? "ws" : "wss";
  const seeds: Seed[] = [];
  for (const item of text.split(/[\s,]+/).map((s) => s.trim()).filter((s) => s.length > 0)) {
    const seed = parseSeed(item, defaultScheme === "wss" ? 443 : 80, defaultScheme);
    if (profile !== "dev-local" && PLAINTEXT.has(schemeOf(seed))) {
      throw new Error(`profile ${profile} dials only attested schemes; seed ${item} is plaintext ${schemeOf(seed)}; `
        + "set AGENTSPACES_PROFILE=dev-local for development");
    }
    seeds.push(seed);
  }
  return seeds;
}

/** The profile a `vars` value names; anything but `dev-local` is `attested`. */
export function profileOf(value: unknown): CellProfile {
  return value === "dev-local" ? "dev-local" : "attested";
}

/**
 * Reads the `vars` of the environment into a configuration; `overrides`
 * win over the environment. Refuses a missing `AGENTSPACES_GROUP` or
 * `AGENTSPACES_SEEDS`, naming the variable.
 */
export function cellConfig(env: CellEnv, overrides: Partial<CellConfig> = {}): CellConfig {
  const profile = overrides.profile ?? profileOf(env["AGENTSPACES_PROFILE"]);
  const group = overrides.group ?? (typeof env["AGENTSPACES_GROUP"] === "string" ? env["AGENTSPACES_GROUP"] : "");
  if (group.length === 0) {
    throw new Error("AGENTSPACES_GROUP names the group this cell joins; it is not set");
  }
  let seeds = overrides.seeds;
  if (seeds === undefined) {
    const text = typeof env["AGENTSPACES_SEEDS"] === "string" ? env["AGENTSPACES_SEEDS"] : "";
    seeds = parseSeeds(text, profile);
    if (seeds.length === 0) {
      throw new Error("AGENTSPACES_SEEDS names the seeds this cell dials; it is not set");
    }
  }
  const inviteVar = env["AGENTSPACES_INVITE"];
  const invite = overrides.invite !== undefined ? overrides.invite
    : typeof inviteVar === "string" && inviteVar.trim().length > 0 ? inviteVar.trim() : null;
  const dataSpace = overrides.dataSpace ?? "data";
  return {
    group, seeds, invite, profile,
    name: overrides.name ?? "connector",
    dataSpace,
    taskSpace: overrides.taskSpace ?? dataSpace,
    changeSpace: overrides.changeSpace ?? dataSpace,
    tickMillis: overrides.tickMillis ?? DEFAULT_TICK_MILLIS,
    idleMillis: overrides.idleMillis ?? null,
    reconnectMillis: overrides.reconnectMillis ?? DEFAULT_RECONNECT_MILLIS,
    snapshotMillis: overrides.snapshotMillis ?? DEFAULT_SNAPSHOT_MILLIS,
    introduceMillis: overrides.introduceMillis ?? DEFAULT_INTRODUCE_MILLIS,
    housekeepingMillis: overrides.housekeepingMillis ?? DEFAULT_TICK_MILLIS,
    busyWindowMillis: overrides.busyWindowMillis ?? 5_000,
    log: overrides.log === undefined ? (line) => console.log(line) : overrides.log,
  };
}
