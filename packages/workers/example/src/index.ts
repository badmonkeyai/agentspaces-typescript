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
 * The worked demonstration of srad/celld-assetcard-analysis.md §7 as
 * srad/agentspaces-js.md JS-C-12 and JS-S-07 ask for it: a Durable Object
 * with state (`Inventory`, stock per warehouse in its own SQLite), exposed
 * through the connector cell (`Fleet`) as the AssetCard
 * `workers://inventory/do/Inventory` with one read (`getInventory`) and two
 * operations (`reserveStock`, `releaseStock`), each wrapped in `once` so a
 * retry under the same invocation id runs it once. The same bundle and
 * `wrangler.json` run on workerd (the package's test), celld, and
 * Cloudflare; the `vars` block names the group, the seeds, the invite, and
 * the profile.
 */

import { DurableObject } from "cloudflare:workers";
import { agent, entry, spaceTake } from "@agentspaces/client";
import { AgentSpacesCell, AgentSpacesConnectorCell, fleet, once } from "@agentspaces/workers";
import type { AssetManifest, CellEnv } from "@agentspaces/workers";

export interface Env extends CellEnv {
  INVENTORY: DurableObjectNamespace<Inventory>;
  FLEET: DurableObjectNamespace<Fleet>;
  ADJUSTER: DurableObjectNamespace<Adjuster>;
  AGENTSPACES_GROUP: string;
  AGENTSPACES_SEEDS: string;
  AGENTSPACES_INVITE: string;
  AGENTSPACES_PROFILE: string;
}

/** Stock per SKU in one warehouse; every operation runs once per invocation id. */
export class Inventory extends DurableObject<Env> {
  /** How many times an operation body ran, for the demonstration's proof. */
  private runs = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS stock (sku TEXT PRIMARY KEY, qty INTEGER NOT NULL)");
    ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, n INTEGER NOT NULL)");
  }

  /** Seeds the warehouse with stock (the demonstration's fixture). */
  async stock(sku: string, qty: number): Promise<void> {
    this.ctx.storage.sql.exec("INSERT OR REPLACE INTO stock (sku, qty) VALUES (?, ?)", sku, qty);
  }

  /** The read operation: the current stock. */
  async getInventory(_params: Record<string, string> = {}): Promise<{ sku: string; qty: number }[]> {
    return this.ctx.storage.sql.exec<{ sku: string; qty: number }>("SELECT sku, qty FROM stock ORDER BY sku").toArray();
  }

  /** The operation under a forced retry: the body runs once per invocation id. */
  async reserveStock(params: { sku: string; qty: string }, invocationId: string): Promise<Record<string, string>> {
    return once(this.ctx.storage, invocationId, () => this.adjust(params.sku, -Number(params.qty), "reserved"));
  }

  async releaseStock(params: { sku: string; qty: string }, invocationId: string): Promise<Record<string, string>> {
    return once(this.ctx.storage, invocationId, () => this.adjust(params.sku, Number(params.qty), "released"));
  }

  /** How many operation bodies ran in this object's life and across its SQLite (the proof of exactly once). */
  async runCount(): Promise<{ inMemory: number; durable: number }> {
    const row = this.ctx.storage.sql.exec<{ n: number }>("SELECT n FROM counters WHERE name = 'runs'").toArray()[0];
    return { inMemory: this.runs, durable: Number(row?.n ?? 0) };
  }

  private adjust(sku: string, delta: number, verb: string): Record<string, string> {
    const sql = this.ctx.storage.sql;
    const row = sql.exec<{ qty: number }>("SELECT qty FROM stock WHERE sku = ?", sku).toArray()[0];
    const before = Number(row?.qty ?? 0);
    if (before + delta < 0) {
      throw new Error(`only ${before} of ${sku} in stock`);
    }
    sql.exec("INSERT OR REPLACE INTO stock (sku, qty) VALUES (?, ?)", sku, before + delta);
    sql.exec("INSERT INTO counters (name, n) VALUES ('runs', 1) ON CONFLICT(name) DO UPDATE SET n = n + 1");
    this.runs += 1;
    return { sku, [verb]: String(Math.abs(delta)), remaining: String(before + delta) };
  }
}

/** The connector cell: one per deployment, named `connector`, publishing the inventory. */
export class Fleet extends AgentSpacesConnectorCell<Env> {
  protected manifest(_env: Env): AssetManifest {
    return {
      application: "inventory",
      runtime: "workerd",
      freshness: "PT30S",
      durableObjects: [{
        binding: "INVENTORY", className: "Inventory", shape: "aspace:InventoryState",
        description: "Persistent stock per warehouse",
        read: [{ name: "getInventory", params: [], description: "current stock", resultShape: "sku,qty" }],
        invoke: [{ name: "reserveStock", params: ["sku", "qty"], description: "reserve units" },
          { name: "releaseStock", params: ["sku", "qty"], description: "release units" }],
        objects: ["warehouse-7", "warehouse-9"],
      }],
    };
  }
}

// ---------------------------------------------------------------- agent cell

/** A damage report an adjuster estimates (the §7.2 agent cell, JS-S-05). */
@entry("aspace:DamageReport#v1")
export class DamageReport {
  constructor(readonly claimId: string, readonly photos: number) {}
}

@entry("aspace:DamageEstimate#v1")
export class DamageEstimate {
  constructor(readonly claimId: string, readonly estimate: string, readonly by: string) {}
}

/** An agent that takes reports from the `claims` space and writes estimates: work in its own name. */
@agent("damage-estimator", { description: "Estimates damage from a report's photos" })
export class DamageEstimator {
  estimated = 0;

  @spaceTake(DamageReport, "claims", { lease: "1m", pollTimeout: "1s" })
  estimate(report: DamageReport): DamageEstimate {
    this.estimated += 1;
    return new DamageEstimate(report.claimId, String(report.photos * 250), "damage-estimator");
  }
}

/** The agent cell: a member with its own identity, binding the estimator and publishing its AgentCard. */
export class Adjuster extends AgentSpacesCell<Env> {
  protected agents(_env: Env): object[] {
    return [new DamageEstimator()];
  }
}

/**
 * The Worker: `/wake` activates the connector (the cron does the same each
 * minute, so an evicted cell comes back on Cloudflare); `/stock` seeds a
 * warehouse; `/runs` reports how often an operation body ran; `/entries`
 * reads the data space through `fleet()` (JS-S-06); `/adjuster/wake` and
 * `/adjuster/status` reach the agent cell; everything else goes to the
 * connector cell.
 */
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/stock") {
      const object = url.searchParams.get("object") ?? "warehouse-7";
      await env.INVENTORY.getByName(object).stock(url.searchParams.get("sku") ?? "A-100",
        Number(url.searchParams.get("qty") ?? "10"));
      return Response.json({ object, stocked: true });
    }
    if (url.pathname === "/runs") {
      const object = url.searchParams.get("object") ?? "warehouse-7";
      return Response.json(await env.INVENTORY.getByName(object).runCount());
    }
    if (url.pathname.startsWith("/adjuster/")) {
      return env.ADJUSTER.getByName("adjuster").fetch(`https://cell${url.pathname.slice("/adjuster".length)}`);
    }
    if (url.pathname === "/entries") {
      const schema = url.searchParams.get("type") ?? "";
      const entries = await fleet(env).space(url.searchParams.get("space") ?? "data").entries(schema);
      return Response.json({ count: entries.length, entries: entries.map((e) => ({ entryId: e.entryId, issuer: e.issuer })) });
    }
    return env.FLEET.getByName("connector").fetch(request);
  },
  scheduled(_event: unknown, env: Env): Promise<Response> {
    return env.FLEET.getByName("connector").fetch("https://cell/wake");
  },
};
