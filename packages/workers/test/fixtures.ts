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
 * The §7.2 manifest with every kind of asset, shared by the manifest and
 * provider tests.
 */

import type { AssetManifest } from "../src/manifest.js";

/** The §7.2 manifest with every kind of asset. */
export function everything(): AssetManifest {
  return {
    application: "inventory", runtime: "celld", freshness: "PT30S",
    durableObjects: [{ binding: "INVENTORY", className: "Inventory", shape: "aspace:InventoryState",
      description: "Persistent stock per warehouse",
      read: [{ name: "getInventory", params: [], description: "current stock" }],
      invoke: [{ name: "reserveStock", params: ["sku", "qty"], description: "reserve units" },
        { name: "releaseStock", params: ["sku", "qty"], optional: ["reason"], description: "release units" }],
      objects: ["warehouse-7", "warehouse-9"] }],
    kv: [{ binding: "SETTINGS", description: "Feature settings", shape: "json", prefixes: ["public/", "flags/"] }],
    d1: [{ binding: "CATALOG", description: "Product catalog",
      queries: [{ name: "bySku", sql: "SELECT * FROM products WHERE sku = ?1", params: ["sku"], resultShape: "sku,name,price" },
        { name: "all", sql: "SELECT sku FROM products", params: [] }] }],
    r2: [{ binding: "IMAGES", description: "Product images", prefixes: ["public/"] }],
    queues: [{ binding: "EVENTS", description: "Stock events", shape: "aspace:StockEvent", params: ["sku", "delta"] }],
    workflows: [{ binding: "RESTOCK", description: "Restock workflow", params: ["sku", "qty"] }],
    routes: [
      { path: "/api/health", method: "GET", description: "health", shape: "json", base: "https://inventory.example" },
      { path: "/api/reindex", method: "POST", description: "reindex", shape: "json", idempotent: true, params: ["scope"],
        base: "https://inventory.example" },
      { group: "admin", name: "purge", path: "/admin/purge", method: "POST", description: "purge", shape: "json", service: "SELF" },
    ],
  };
}

