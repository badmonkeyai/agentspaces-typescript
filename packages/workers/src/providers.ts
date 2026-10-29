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
 * The Workers asset provider (srad/agentspaces-js.md JS-C-06, JS-C-07,
 * appendix F): one `AssetProvider` over the deployment's bindings, driven by
 * the manifest. Durable Object classes and listed instances answer the
 * allowlisted read and invoke operations by RPC on the stub, with the
 * invocation id as the last argument; KV answers `get` and `list` under the
 * declared prefixes; D1 runs only the named queries with the parameters
 * bound positionally; R2 answers `head`, `list`, and `get`; Queues take
 * `send`; Workflows take `create` and answer `status`; Worker routes take
 * GET as a read and POST as an invoke, with `Aspace-Invocation-Id` on the
 * request. A request naming an operation the card does not list, a
 * parameter the operation does not declare, or a key outside the declared
 * prefixes is refused with an error naming the rule, and nothing runs.
 */

import { bytes } from "@agentspaces/client";
import type { wire } from "@agentspaces/client";
import { INLINE_PAYLOAD_LIMIT, invokeFailed, invokeResult, queryFailed, queryResult } from "@agentspaces/connect";
import type { AssetProvider, InvokeError, InvokeResult, QueryResult, StringMap } from "@agentspaces/connect";
import { AssetManifest, ManifestAsset, OBJECT_PARAM, OP_PARAM, OperationSpec, RouteSpec, assetsOf, cardOf,
  routeMode, routeName, validateManifest } from "./manifest.js";
import type { CellEnv, D1DatabaseLike, DurableObjectNamespaceLike, FetcherLike, KVNamespaceLike, QueueLike,
  R2BucketLike, R2ObjectLike, WorkflowLike } from "./workers-types.js";
import { R2PieceStore, publishR2Object } from "./content.js";
import type { capabilities } from "@agentspaces/client";
type Content = capabilities.Content;

type Dict = wire.Dict;

/** The header a route receives the invocation id in (appendix F). */
export const INVOCATION_HEADER = "Aspace-Invocation-Id";

export type WorkersProviderOptions = {
  /** The `fetch` a route without a service binding is called through; default the global. */
  fetch?: (input: string | URL, init?: RequestInit) => Promise<Response>;
  /** The largest R2 body returned inline (base64); default the Java inline limit, 64 KiB. */
  maxInlineResultBytes?: number;
  /** The page size of a `list` when the request names none; default 100. A per-request size, not a cap. */
  listLimit?: number;
  /**
   * The content swarm of the cell's peer with an `R2PieceStore` over the same bucket binding
   * (srad/large-networks-bulk-data.md LB-C-05): an R2 `get` above `maxInlineResultBytes` is then
   * published as an artifact and answered with its root instead of an error.
   */
  artifacts?: { content: Content; store: R2PieceStore; pieceSize?: number } | null;
};

/** A refusal, before anything runs: the appendix F code, the rule, and the detail. */
type Refusal = { error: InvokeError; rule: string; detail: string };

/** A request judged against the manifest: the operation, the instance, and the declared parameters. */
type Judged = { spec: OperationSpec; object: string | null; params: StringMap };

function isRefusal(value: Judged | Refusal): value is Refusal {
  return (value as Refusal).rule !== undefined;
}

/** A value as the string a result row carries: strings as they are, the rest as JSON. */
export function stringOf(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return String(value);
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  return JSON.stringify(value);
}

/** One row: an object's fields as strings; a primitive under `value`. */
export function rowOf(value: unknown): StringMap {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const row: StringMap = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      row[k] = stringOf(v);
    }
    return row;
  }
  return { value: stringOf(value) };
}

/** Rows: an array's elements, else the one row of a value; nothing for null and undefined. */
export function rowsOf(value: unknown): StringMap[] {
  if (value === null || value === undefined) {
    return [];
  }
  return Array.isArray(value) ? value.map(rowOf) : [rowOf(value)];
}

export class WorkersAssetProvider implements AssetProvider {
  readonly manifest: AssetManifest;
  /** Queries and invocations that reached a binding. */
  executed = 0;
  /** Requests refused by a manifest rule before anything ran. */
  refused = 0;
  private assets = new Map<string, ManifestAsset>();
  private readonly fetcher: (input: string | URL, init?: RequestInit) => Promise<Response>;
  private readonly maxInlineResultBytes: number;
  private readonly listLimit: number;
  private readonly artifacts: { content: Content; store: R2PieceStore; pieceSize?: number } | null;

  constructor(private readonly env: CellEnv, manifest: AssetManifest, options: WorkersProviderOptions = {}) {
    this.manifest = validateManifest(manifest);
    this.fetcher = options.fetch ?? ((input, init) => fetch(input, init));
    this.maxInlineResultBytes = options.maxInlineResultBytes ?? INLINE_PAYLOAD_LIMIT;
    this.listLimit = options.listLimit ?? 100;
    this.artifacts = options.artifacts ?? null;
    this.assets = new Map(assetsOf(this.manifest).map((a) => [a.asset, a]));
  }

  /**
   * Resolves the instance lists given as functions and rebuilds the asset
   * table; the cell calls this before each card refresh so a newly created
   * object gains its card at the next cadence.
   */
  async refresh(): Promise<ManifestAsset[]> {
    const listed = new Map<string, string[]>();
    for (const spec of this.manifest.durableObjects ?? []) {
      if (typeof spec.objects === "function") {
        listed.set(spec.className, [...await spec.objects()]);
      }
    }
    const assets = assetsOf(this.manifest, listed);
    this.assets = new Map(assets.map((a) => [a.asset, a]));
    return assets;
  }

  /** The assets currently published, by name. */
  assetNames(): string[] {
    return [...this.assets.keys()];
  }

  /** The asset record by name, for inspection. */
  asset(name: string): ManifestAsset | undefined {
    return this.assets.get(name);
  }

  describeAssets(group: string, issuer: string, nowMillis: number): Dict[] {
    return [...this.assets.values()].map((asset) => cardOf(this.manifest, asset, group, issuer, nowMillis));
  }

  // ---------------------------------------------------------------- reads

  async query(name: string, parameters: StringMap): Promise<QueryResult> {
    const asset = this.assets.get(name);
    if (asset === undefined) {
      this.refused += 1;
      return queryFailed(`asset: no asset named '${name}'`);
    }
    const operation = parameters[OP_PARAM];
    if (operation === undefined) {
      this.refused += 1;
      return queryFailed(`read-ops: parameter '${OP_PARAM}' names the operation; the read-ops of '${name}' are `
        + `${[...asset.readOps.keys()].join(",") || "none"}`);
    }
    const judged = this.judge(asset, asset.readOps, "read-ops", operation, parameters);
    if (isRefusal(judged)) {
      this.refused += 1;
      return queryFailed(`${judged.rule}: ${judged.detail}`);
    }
    try {
      this.executed += 1;
      return queryResult(await this.read(asset, judged));
    } catch (e) {
      return queryFailed(`target: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  private async read(asset: ManifestAsset, judged: Judged): Promise<StringMap[]> {
    const op = judged.spec.name;
    switch (asset.kind) {
      case "do": {
        const stub = this.namespace(asset.binding!).getByName(judged.object!);
        return rowsOf(await this.call(stub, op, [judged.params]));
      }
      case "kv": {
        const kv = this.binding<KVNamespaceLike>(asset.binding!);
        const prefixes = (asset.access["prefixes"] ?? "").split(",").filter((p) => p.length > 0);
        if (op === "get") {
          const key = judged.params["key"]!;
          this.withinPrefixes(asset, prefixes, key);
          const value = await kv.get(key, "text");
          return value === null ? [] : [{ key, value }];
        }
        const limit = judged.params["limit"] === undefined ? this.listLimit : Number(judged.params["limit"]);
        const wanted = judged.params["prefix"];
        const scan = wanted === undefined ? (prefixes.length === 0 ? [""] : prefixes) : [wanted];
        const rows: StringMap[] = [];
        for (const prefix of scan) {
          this.withinPrefixes(asset, prefixes, prefix);
          const page = await kv.list({ prefix: prefix.length === 0 ? undefined : prefix, limit,
            cursor: judged.params["cursor"] });
          for (const key of page.keys) {
            rows.push({ key: key.name, expiration: stringOf(key.expiration) });
          }
          if (!page.list_complete && page.cursor !== undefined && rows.length > 0) {
            rows[rows.length - 1]!["cursor"] = page.cursor;
          }
        }
        return rows;
      }
      case "d1": {
        const d1 = this.binding<D1DatabaseLike>(asset.binding!);
        const query = (asset.source as { queries: { name: string; sql: string; params: string[] }[] }).queries
          .find((q) => q.name === op)!;
        const statement = d1.prepare(query.sql);
        const bound = query.params.length === 0 ? statement : statement.bind(...query.params.map((p) => judged.params[p]));
        return (await bound.all()).results.map(rowOf);
      }
      case "r2": {
        const r2 = this.binding<R2BucketLike>(asset.binding!);
        const prefixes = (asset.access["prefixes"] ?? "").split(",").filter((p) => p.length > 0);
        if (op === "head") {
          const key = judged.params["key"]!;
          this.withinPrefixes(asset, prefixes, key);
          const object = await r2.head(key);
          return object === null ? [] : [r2Row(object)];
        }
        if (op === "get") {
          const key = judged.params["key"]!;
          this.withinPrefixes(asset, prefixes, key);
          const object = await r2.get(key);
          if (object === null) {
            return [];
          }
          if (object.size > this.maxInlineResultBytes) {
            if (this.artifacts !== null && this.artifacts.store.bucket === r2) {
              // LB-C-05: the object becomes an artifact the fleet fetches piece by piece from this cell.
              const manifest = await publishR2Object(this.artifacts.content, this.artifacts.store, key,
                { pieceSize: this.artifacts.pieceSize });
              return [{ ...r2Row(object), root: String(manifest["root"]), pieces: String(manifest["pieces"]) }];
            }
            throw new Error(`object ${key} of ${object.size} bytes exceeds the ${this.maxInlineResultBytes}-byte inline `
              + "limit (maxInlineResultBytes); use head and fetch the body out of band, or give the provider artifacts");
          }
          return [{ ...r2Row(object), body: bytes.toBase64(new Uint8Array(await object.arrayBuffer())) }];
        }
        const limit = judged.params["limit"] === undefined ? this.listLimit : Number(judged.params["limit"]);
        const wanted = judged.params["prefix"];
        const scan = wanted === undefined ? (prefixes.length === 0 ? [""] : prefixes) : [wanted];
        const rows: StringMap[] = [];
        for (const prefix of scan) {
          this.withinPrefixes(asset, prefixes, prefix);
          const page = await r2.list({ prefix: prefix.length === 0 ? undefined : prefix, limit, cursor: judged.params["cursor"] });
          rows.push(...page.objects.map(r2Row));
          if (page.truncated && page.cursor !== undefined && rows.length > 0) {
            rows[rows.length - 1]!["cursor"] = page.cursor;
          }
        }
        return rows;
      }
      case "workflow": {
        const workflow = this.binding<WorkflowLike>(asset.binding!);
        const instance = await workflow.get(judged.params["id"]!);
        return [{ id: instance.id, ...rowOf(await instance.status()) }];
      }
      case "route":
        return rowsOf(await this.route(asset, op, judged.params, null));
      default:
        throw new Error(`asset kind ${String(asset.kind)} answers no reads`);
    }
  }

  // ---------------------------------------------------------- operations

  async invoke(name: string, operation: string, params: StringMap, invocationId: string): Promise<InvokeResult> {
    const asset = this.assets.get(name);
    if (asset === undefined) {
      this.refused += 1;
      return invokeFailed("unknown-operation", "asset", `no asset named '${name}'`);
    }
    const judged = this.judge(asset, asset.invokeOps, "invoke-ops", operation, params);
    if (isRefusal(judged)) {
      this.refused += 1;
      return invokeFailed(judged.error, judged.rule, judged.detail);
    }
    try {
      this.executed += 1;
      return invokeResult(await this.run(asset, judged, invocationId));
    } catch (e) {
      return invokeFailed("target-error", "target", e instanceof Error ? e.message : String(e));
    }
  }

  private async run(asset: ManifestAsset, judged: Judged, invocationId: string): Promise<StringMap> {
    const op = judged.spec.name;
    switch (asset.kind) {
      case "do": {
        const stub = this.namespace(asset.binding!).getByName(judged.object!);
        return rowOf(await this.call(stub, op, [judged.params, invocationId]));
      }
      case "queue": {
        const queue = this.binding<QueueLike>(asset.binding!);
        await queue.send({ invocationId, params: judged.params }, { contentType: "json" });
        return { sent: "true", invocationId };
      }
      case "workflow": {
        const workflow = this.binding<WorkflowLike>(asset.binding!);
        const instance = await workflow.create({ id: invocationId, params: judged.params });
        return { id: instance.id, ...rowOf(await instance.status()) };
      }
      case "route":
        return rowOf(await this.route(asset, op, judged.params, invocationId));
      default:
        throw new Error(`asset kind ${asset.kind} runs no operations`);
    }
  }

  // ------------------------------------------------------------ judging

  /**
   * JS-C-07: the operation must be on the card's list for the request's
   * side; a class card needs `object`, an instance card fixes it; every
   * other parameter must be a declared one and every declared one present.
   */
  private judge(asset: ManifestAsset, ops: Map<string, OperationSpec>, rule: "read-ops" | "invoke-ops",
                operation: string, parameters: StringMap): Judged | Refusal {
    const spec = ops.get(operation);
    if (spec === undefined) {
      return { error: "unknown-operation", rule, detail: `operation '${operation}' is not in the ${rule} of asset `
        + `'${asset.asset}' (${[...ops.keys()].join(",") || "none"})` };
    }
    let object: string | null = null;
    const rest: StringMap = {};
    for (const [key, value] of Object.entries(parameters)) {
      if (key === OP_PARAM) {
        continue;
      }
      if (key === OBJECT_PARAM) {
        if (asset.kind !== "do") {
          return { error: "bad-params", rule: "params", detail: `parameter '${OBJECT_PARAM}' is not declared by `
            + `'${operation}' on '${asset.asset}'` };
        }
        if (asset.object !== null && value !== asset.object) {
          return { error: "bad-params", rule: "object", detail: `asset '${asset.asset}' is the instance `
            + `'${asset.object}'; it does not serve '${value}'` };
        }
        object = value;
        continue;
      }
      if (!spec.params.includes(key) && !(spec.optional ?? []).includes(key)) {
        return { error: "bad-params", rule: "params", detail: `parameter '${key}' is not declared by '${operation}' `
          + `on '${asset.asset}' (declared: ${[...spec.params, ...(spec.optional ?? [])].join(",") || "none"})` };
      }
      rest[key] = value;
    }
    for (const name of spec.params) {
      if (rest[name] === undefined) {
        return { error: "bad-params", rule: "params", detail: `parameter '${name}' of '${operation}' on `
          + `'${asset.asset}' is missing` };
      }
    }
    if (asset.kind === "do") {
      object = asset.object ?? object;
      if (object === null) {
        return { error: "bad-params", rule: "object-param", detail: `asset '${asset.asset}' is a class card; name the `
          + `instance in parameter '${OBJECT_PARAM}'` };
      }
    }
    return { spec, object, params: rest };
  }

  private withinPrefixes(asset: ManifestAsset, prefixes: string[], key: string): void {
    if (prefixes.length > 0 && !prefixes.some((p) => key.startsWith(p))) {
      throw new Error(`prefixes: key '${key}' is outside the prefixes of '${asset.asset}' (${prefixes.join(",")})`);
    }
  }

  // ----------------------------------------------------------- bindings

  private binding<T>(name: string): T {
    const value = this.env[name];
    if (value === undefined || value === null) {
      throw new Error(`binding '${name}' is not in the environment`);
    }
    return value as T;
  }

  private namespace(name: string): DurableObjectNamespaceLike {
    const namespace = this.binding<DurableObjectNamespaceLike>(name);
    if (typeof namespace.getByName !== "function") {
      throw new Error(`binding '${name}' is not a Durable Object namespace`);
    }
    return namespace;
  }

  /** One RPC on a stub: the method must exist (the manifest named it; the class may still lack it). */
  private async call(stub: { [method: string]: unknown }, method: string, args: unknown[]): Promise<unknown> {
    if (typeof stub[method] !== "function") {
      throw new Error(`the object has no method '${method}'`);
    }
    // Called on the stub itself: an RPC proxy answers a property read with a callable and refuses
    // `apply` or `call` as methods of its own.
    return await (stub as { [m: string]: (...a: unknown[]) => unknown })[method]!(...args);
  }

  /** GET with the parameters as the query string, POST with them as a JSON body; the invocation id as a header. */
  private async route(asset: ManifestAsset, name: string, params: StringMap, invocationId: string | null): Promise<unknown> {
    const route = (asset.source as RouteSpec[]).find((r) => routeName(r) === name
      && (invocationId === null ? routeMode(r) === "read" : routeMode(r) === "invoke"))!;
    let url: URL;
    let through: (input: string | URL, init?: RequestInit) => Promise<Response>;
    if (route.service !== undefined) {
      const service = this.binding<FetcherLike>(route.service);
      url = new URL(route.path, "https://service");
      through = (input, init) => service.fetch(input, init);
    } else {
      if (route.base === undefined) {
        throw new Error(`route-base: route ${route.path} names neither a service binding nor a base URL`);
      }
      url = new URL(route.path, route.base);
      through = this.fetcher;
    }
    const headers: Record<string, string> = { accept: "application/json" };
    if (invocationId !== null) {
      headers[INVOCATION_HEADER] = invocationId;
    }
    let response: Response;
    if (route.method === "GET") {
      for (const [k, v] of Object.entries(params)) {
        url.searchParams.set(k, v);
      }
      response = await through(url, { method: "GET", headers });
    } else {
      headers["content-type"] = "application/json";
      response = await through(url, { method: "POST", headers, body: JSON.stringify(params) });
    }
    if (!response.ok) {
      throw new Error(`route ${route.method} ${route.path} answered ${response.status}`);
    }
    const text = await response.text();
    try {
      return text.length === 0 ? null : JSON.parse(text);
    } catch {
      return text;
    }
  }
}

function r2Row(object: R2ObjectLike): StringMap {
  return { key: object.key, size: String(object.size), etag: object.etag, uploaded: stringOf(object.uploaded),
    contentType: object.httpMetadata?.contentType ?? "" };
}
