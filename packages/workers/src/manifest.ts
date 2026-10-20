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
 * The connector cell's manifest (srad/agentspaces-js.md §3.8, JS-C-06,
 * JS-C-08, appendix F): what a deployment publishes and which operations it
 * allows. The manifest is the whole allowlist: the connector runs no SQL,
 * route, method, or binding it does not name (JS-C-07). `validateManifest`
 * refuses a manifest that could not be served honestly, naming the rule;
 * `assetsOf` normalises it into one record per card; `cardOf` renders a
 * record as an AssetCard with the SPEC §6.1a fields alone, the `access`
 * keys of appendix F, and the id `<application>:<asset>`, stable across
 * restarts and cell moves so a refresh replaces the earlier card.
 */

import { assetCard, ASSET_INVOKE_CAPABILITY, DATA_QUERY_CAPABILITY } from "@agentspaces/connect";
import type { StringMap } from "@agentspaces/connect";
import { parseDurationMillis } from "@agentspaces/client";
import type { wire } from "@agentspaces/client";

type Dict = wire.Dict;

/** One allowlisted operation: its name, the parameter names it takes, and what it answers. */
export interface OperationSpec {
  name: string;
  /** The parameters a request must carry, by name; anything else is refused (JS-C-07). */
  params: string[];
  /** Parameters a request may carry. */
  optional?: string[];
  description: string;
  resultShape?: string;
}

/** A Durable Object class and the instances the manifest lists by name. */
export interface DurableObjectSpec {
  binding: string;
  className: string;
  description: string;
  /** The entry schema of what the reads return. */
  shape: string;
  read?: OperationSpec[];
  invoke?: OperationSpec[];
  /** Listed instances, each published as its own card; a function is resolved at each refresh. */
  objects?: string[] | (() => Promise<string[]> | string[]);
}

export interface KvSpec {
  binding: string;
  description: string;
  shape: string;
  /** Key prefixes `get` and `list` may touch; empty allows every key. */
  prefixes?: string[];
}

export interface D1QuerySpec {
  name: string;
  /** The SQL the application author wrote, parameters bound positionally (`?1`, `?2`, ... or `?`). */
  sql: string;
  params: string[];
  description?: string;
  resultShape?: string;
}

export interface D1Spec {
  binding: string;
  description: string;
  queries: D1QuerySpec[];
}

export interface R2Spec {
  binding: string;
  description: string;
  /** Key prefixes `head`, `list`, and `get` may touch; empty allows every key. */
  prefixes?: string[];
}

export interface QueueSpec {
  binding: string;
  description: string;
  /** The message schema `send` carries. */
  shape: string;
  /** The parameter names a `send` must carry; empty accepts any string map. */
  params?: string[];
}

export interface WorkflowSpec {
  binding: string;
  description: string;
  /** The parameter names a `create` must carry. */
  params: string[];
  shape?: string;
}

/** One Worker route: GET as a read operation, POST as an invoke operation, grouped by `group` on one card. */
export interface RouteSpec {
  /** The operation name; default the last path segment. */
  name?: string;
  /** The card the route belongs to (`route/<group>`); default `default`. */
  group?: string;
  path: string;
  method: "GET" | "POST";
  description: string;
  shape: string;
  /** `read` for GET and `invoke` for POST unless given. */
  mode?: "read" | "invoke";
  params?: string[];
  optional?: string[];
  /** Whether a repeat under the same invocation id is harmless at the route; reported on the card. */
  idempotent?: boolean;
  /** A service binding to call through; default the global `fetch` against `base`. */
  service?: string;
  /** The absolute URL the path is resolved against when no service is named. */
  base?: string;
}

/** The runtimes a card may report. */
export type WorkersRuntime = "celld" | "workerd" | "cloudflare";

export interface AssetManifest {
  /** The uri authority: `workers://<application>/...`; also the card id prefix. */
  application: string;
  /** Reported on every card's access map; default `workerd`. */
  runtime?: WorkersRuntime;
  /** The card refresh cadence (ISO 8601); default `PT1M`, the TTL twice that (appendix F). */
  freshness?: string;
  /** The card TTL (ISO 8601); default twice the freshness. */
  ttl?: string;
  durableObjects?: DurableObjectSpec[];
  kv?: KvSpec[];
  d1?: D1Spec[];
  r2?: R2Spec[];
  queues?: QueueSpec[];
  workflows?: WorkflowSpec[];
  routes?: RouteSpec[];
}

/** The kinds of asset the connector publishes, as the uri's second segment names them. */
export type AssetKind = "do" | "kv" | "d1" | "r2" | "queue" | "workflow" | "route";

/** One normalised asset: everything a card and a request need, resolved from the manifest. */
export interface ManifestAsset {
  kind: AssetKind;
  /** The asset name, `<kind>/<name>` (a listed Durable Object instance: `do/<Class>/<name>`). */
  asset: string;
  uri: string;
  description: string;
  shape: string;
  readOps: Map<string, OperationSpec>;
  invokeOps: Map<string, OperationSpec>;
  /** Access keys beyond `mode`, `query`, `invoke`, `runtime`, `connector`, `read-ops`, `invoke-ops`. */
  access: StringMap;
  costHints: StringMap;
  /** The binding the operations run against (none for a route group). */
  binding: string | null;
  /** The fixed instance of a listed Durable Object card. */
  object: string | null;
  /** The manifest entry, for the provider's dispatch. */
  source: DurableObjectSpec | KvSpec | D1Spec | R2Spec | QueueSpec | WorkflowSpec | RouteSpec[];
}

const SAFE_SEGMENT = /^[A-Za-z0-9._-]{1,128}$/;
/** The two parameter names the protocol itself uses (appendix F). */
export const OP_PARAM = "op";
export const OBJECT_PARAM = "object";

/** The default freshness and TTL of a card (appendix F). */
export const DEFAULT_FRESHNESS = "PT1M";
export const DEFAULT_TTL = "PT2M";

function refuse(rule: string, detail: string): never {
  throw new Error(`manifest rule ${rule}: ${detail}`);
}

function checkSegment(rule: string, what: string, value: unknown): string {
  if (typeof value !== "string" || !SAFE_SEGMENT.test(value)) {
    refuse(rule, `${what} '${String(value)}' must match ${SAFE_SEGMENT}`);
  }
  return value;
}

function checkOps(asset: string, ops: OperationSpec[] | undefined, kind: "read" | "invoke"): void {
  const seen = new Set<string>();
  for (const op of ops ?? []) {
    checkSegment("operation-name", `${kind} operation of ${asset}`, op.name);
    if (seen.has(op.name)) {
      refuse("operation-name", `${kind} operation '${op.name}' of ${asset} is listed twice`);
    }
    seen.add(op.name);
    checkParams(`${asset}.${op.name}`, [...op.params, ...(op.optional ?? [])]);
  }
}

function checkParams(where: string, params: string[]): void {
  const seen = new Set<string>();
  for (const name of params) {
    checkSegment("parameter-name", `parameter of ${where}`, name);
    if (name === OP_PARAM || name === OBJECT_PARAM) {
      refuse("parameter-name", `parameter '${name}' of ${where} is reserved by the protocol`);
    }
    if (seen.has(name)) {
      refuse("parameter-name", `parameter '${name}' of ${where} is listed twice`);
    }
    seen.add(name);
  }
}

/**
 * Refuses a manifest the connector could not serve honestly: an unsafe
 * application or name, a duplicate asset or operation, a reserved or
 * duplicate parameter name, a route without a leading slash or with a
 * method other than GET or POST, a D1 query without SQL. Returns the
 * manifest for chaining.
 */
export function validateManifest(manifest: AssetManifest): AssetManifest {
  checkSegment("application", "application", manifest.application);
  if (manifest.runtime !== undefined && !["celld", "workerd", "cloudflare"].includes(manifest.runtime)) {
    refuse("runtime", `runtime '${String(manifest.runtime)}' is not celld, workerd, or cloudflare`);
  }
  const assets = new Set<string>();
  const claim = (asset: string): void => {
    if (assets.has(asset)) {
      refuse("asset-name", `asset '${asset}' is listed twice`);
    }
    assets.add(asset);
  };
  for (const spec of manifest.durableObjects ?? []) {
    checkSegment("binding", "Durable Object binding", spec.binding);
    checkSegment("class-name", "Durable Object class", spec.className);
    claim(`do/${spec.className}`);
    checkOps(`do/${spec.className}`, spec.read, "read");
    checkOps(`do/${spec.className}`, spec.invoke, "invoke");
    if (Array.isArray(spec.objects)) {
      for (const name of spec.objects) {
        checkSegment("object-name", `instance of ${spec.className}`, name);
        claim(`do/${spec.className}/${name}`);
      }
    }
  }
  for (const spec of manifest.kv ?? []) {
    checkSegment("binding", "KV binding", spec.binding);
    claim(`kv/${spec.binding}`);
  }
  for (const spec of manifest.d1 ?? []) {
    checkSegment("binding", "D1 binding", spec.binding);
    claim(`d1/${spec.binding}`);
    const names = new Set<string>();
    for (const query of spec.queries) {
      checkSegment("operation-name", `query of d1/${spec.binding}`, query.name);
      if (names.has(query.name)) {
        refuse("operation-name", `query '${query.name}' of d1/${spec.binding} is listed twice`);
      }
      names.add(query.name);
      if (typeof query.sql !== "string" || query.sql.trim().length === 0) {
        refuse("d1-sql", `query '${query.name}' of d1/${spec.binding} has no SQL`);
      }
      checkParams(`d1/${spec.binding}.${query.name}`, query.params);
    }
  }
  for (const spec of manifest.r2 ?? []) {
    checkSegment("binding", "R2 binding", spec.binding);
    claim(`r2/${spec.binding}`);
  }
  for (const spec of manifest.queues ?? []) {
    checkSegment("binding", "Queue binding", spec.binding);
    claim(`queue/${spec.binding}`);
    checkParams(`queue/${spec.binding}.send`, spec.params ?? []);
  }
  for (const spec of manifest.workflows ?? []) {
    checkSegment("binding", "Workflow binding", spec.binding);
    claim(`workflow/${spec.binding}`);
    checkParams(`workflow/${spec.binding}.create`, spec.params);
  }
  const routeNames = new Map<string, Set<string>>();
  for (const route of manifest.routes ?? []) {
    if (typeof route.path !== "string" || !route.path.startsWith("/")) {
      refuse("route-path", `route path '${String(route.path)}' must start with /`);
    }
    if (route.method !== "GET" && route.method !== "POST") {
      refuse("route-method", `route ${route.path} uses ${String(route.method)}; only GET and POST are allowed`);
    }
    const group = checkSegment("route-group", "route group", route.group ?? "default");
    const name = checkSegment("operation-name", `route ${route.path}`, routeName(route));
    const names = routeNames.get(group) ?? new Set<string>();
    if (names.has(name)) {
      refuse("operation-name", `route operation '${name}' of route/${group} is listed twice`);
    }
    names.add(name);
    routeNames.set(group, names);
    checkParams(`route/${group}.${name}`, [...(route.params ?? []), ...(route.optional ?? [])]);
    if (route.service !== undefined) {
      checkSegment("binding", `service of route ${route.path}`, route.service);
    }
  }
  for (const group of routeNames.keys()) {
    claim(`route/${group}`);
  }
  return manifest;
}

/** The operation name of a route: the given name, else the last path segment. */
export function routeName(route: RouteSpec): string {
  if (route.name !== undefined) {
    return route.name;
  }
  const segments = route.path.split("/").filter((s) => s.length > 0);
  return segments[segments.length - 1] ?? "";
}

/** The mode of a route: `read` for GET, `invoke` for POST, unless given. */
export function routeMode(route: RouteSpec): "read" | "invoke" {
  return route.mode ?? (route.method === "GET" ? "read" : "invoke");
}

function opsMap(ops: OperationSpec[] | undefined): Map<string, OperationSpec> {
  return new Map((ops ?? []).map((op) => [op.name, op]));
}

/**
 * The assets a manifest publishes, one record per card: a Durable Object
 * class and each listed instance (`objects` resolved by the caller into
 * `listed`), a KV namespace, a D1 database, an R2 bucket, a Queue, a
 * Workflow, and a route group.
 */
export function assetsOf(manifest: AssetManifest, listed: Map<string, string[]> = new Map()): ManifestAsset[] {
  const application = manifest.application;
  const uri = (asset: string): string => `workers://${application}/${asset}`;
  const out: ManifestAsset[] = [];
  for (const spec of manifest.durableObjects ?? []) {
    const classAsset = `do/${spec.className}`;
    const readOps = opsMap(spec.read);
    const invokeOps = opsMap(spec.invoke);
    const objects = listed.get(spec.className) ?? (Array.isArray(spec.objects) ? spec.objects : []);
    out.push({ kind: "do", asset: classAsset, uri: uri(classAsset), description: spec.description, shape: spec.shape,
      readOps, invokeOps, access: { consistency: "single-writer", "object-param": OBJECT_PARAM },
      costHints: { objects: String(objects.length) }, binding: spec.binding, object: null, source: spec });
    for (const name of objects) {
      const asset = `${classAsset}/${name}`;
      out.push({ kind: "do", asset, uri: uri(asset), description: `${spec.description} (${name})`, shape: spec.shape,
        readOps, invokeOps, access: { consistency: "single-writer", "object-param": OBJECT_PARAM, object: name },
        costHints: {}, binding: spec.binding, object: name, source: spec });
    }
  }
  for (const spec of manifest.kv ?? []) {
    const asset = `kv/${spec.binding}`;
    const access: StringMap = {};
    if ((spec.prefixes ?? []).length > 0) {
      access["prefixes"] = spec.prefixes!.join(",");
    }
    out.push({ kind: "kv", asset, uri: uri(asset), description: spec.description, shape: spec.shape,
      readOps: opsMap([{ name: "get", params: ["key"], description: "the value under one key" },
        { name: "list", params: [], optional: ["prefix", "limit", "cursor"], description: "the keys under a prefix" }]),
      invokeOps: new Map(), access, costHints: {}, binding: spec.binding, object: null, source: spec });
  }
  for (const spec of manifest.d1 ?? []) {
    const asset = `d1/${spec.binding}`;
    out.push({ kind: "d1", asset, uri: uri(asset), description: spec.description,
      shape: `table:${spec.queries.map((q) => q.resultShape === undefined ? q.name : `${q.name}(${q.resultShape})`).join(";")}`,
      readOps: opsMap(spec.queries.map((q) => ({ name: q.name, params: q.params, description: q.description ?? q.name,
        resultShape: q.resultShape }))),
      invokeOps: new Map(), access: {}, costHints: { queries: String(spec.queries.length) }, binding: spec.binding,
      object: null, source: spec });
  }
  for (const spec of manifest.r2 ?? []) {
    const asset = `r2/${spec.binding}`;
    const access: StringMap = { result: "block" };
    if ((spec.prefixes ?? []).length > 0) {
      access["prefixes"] = spec.prefixes!.join(",");
    }
    out.push({ kind: "r2", asset, uri: uri(asset), description: spec.description, shape: "object",
      readOps: opsMap([{ name: "head", params: ["key"], description: "one object's metadata" },
        { name: "list", params: [], optional: ["prefix", "limit", "cursor"], description: "the objects under a prefix" },
        { name: "get", params: ["key"], description: "one object with its body as a block" }]),
      invokeOps: new Map(), access, costHints: {}, binding: spec.binding, object: null, source: spec });
  }
  for (const spec of manifest.queues ?? []) {
    const asset = `queue/${spec.binding}`;
    out.push({ kind: "queue", asset, uri: uri(asset), description: spec.description, shape: spec.shape,
      readOps: new Map(), invokeOps: opsMap([{ name: "send", params: spec.params ?? [], description: "enqueue one message" }]),
      access: {}, costHints: {}, binding: spec.binding, object: null, source: spec });
  }
  for (const spec of manifest.workflows ?? []) {
    const asset = `workflow/${spec.binding}`;
    out.push({ kind: "workflow", asset, uri: uri(asset), description: spec.description, shape: spec.shape ?? "parameters",
      readOps: opsMap([{ name: "status", params: ["id"], description: "one instance's status" }]),
      invokeOps: opsMap([{ name: "create", params: spec.params, description: "start one instance" }]),
      access: {}, costHints: {}, binding: spec.binding, object: null, source: spec });
  }
  const groups = new Map<string, RouteSpec[]>();
  for (const route of manifest.routes ?? []) {
    const group = route.group ?? "default";
    groups.set(group, [...(groups.get(group) ?? []), route]);
  }
  for (const [group, routes] of groups) {
    const asset = `route/${group}`;
    const readOps = new Map<string, OperationSpec>();
    const invokeOps = new Map<string, OperationSpec>();
    const idempotent: string[] = [];
    for (const route of routes) {
      const spec: OperationSpec = { name: routeName(route), params: route.params ?? [], optional: route.optional,
        description: route.description };
      (routeMode(route) === "read" ? readOps : invokeOps).set(spec.name, spec);
      if (route.idempotent) {
        idempotent.push(spec.name);
      }
    }
    const access: StringMap = {};
    if (idempotent.length > 0) {
      access["idempotent"] = idempotent.join(",");
    }
    out.push({ kind: "route", asset, uri: uri(asset), description: routes.map((r) => r.description).join("; "),
      shape: routes[0]!.shape, readOps, invokeOps, access, costHints: {}, binding: null, object: null, source: routes });
  }
  return out;
}

/** The card id of an asset: `<application>:<asset>`, stable across restarts and moves (appendix F). */
export function cardId(application: string, asset: string): string {
  return `${application}:${asset}`;
}

/**
 * One asset as an AssetCard (SPEC §6.1a fields alone): `uri`
 * `workers://<application>/<kind>/<name>`, the declared shape, the
 * refresh cadence as `freshness`, the cheap counts as `costHints`, and the
 * appendix F `access` keys: `mode`, `query`, `invoke`, `read-ops`,
 * `invoke-ops`, `runtime`, `connector=cell`, plus the asset's own.
 */
export function cardOf(manifest: AssetManifest, asset: ManifestAsset, group: string, issuer: string,
                       nowMillis: number): Dict {
  const reads = [...asset.readOps.keys()];
  const invokes = [...asset.invokeOps.keys()];
  const mode = reads.length > 0 && invokes.length > 0 ? "read-only,invoke" : invokes.length > 0 ? "invoke" : "read-only";
  const access: StringMap = { mode, runtime: manifest.runtime ?? "workerd", connector: "cell", ...asset.access };
  if (reads.length > 0) {
    access["query"] = DATA_QUERY_CAPABILITY;
    access["read-ops"] = reads.join(",");
  }
  if (invokes.length > 0) {
    access["invoke"] = ASSET_INVOKE_CAPABILITY;
    access["invoke-ops"] = invokes.join(",");
  }
  return assetCard(group, issuer, nowMillis, cardTtl(manifest), asset.asset, asset.uri, asset.description,
    asset.shape, manifest.freshness ?? DEFAULT_FRESHNESS, asset.costHints, access, cardId(manifest.application, asset.asset));
}

/** The card TTL: the manifest's, else twice its freshness, else `PT2M` (appendix F). */
export function cardTtl(manifest: AssetManifest): string {
  if (manifest.ttl !== undefined) {
    return manifest.ttl;
  }
  if (manifest.freshness === undefined) {
    return DEFAULT_TTL;
  }
  return `PT${Math.max(1, Math.round((2 * parseDurationMillis(manifest.freshness)) / 1000))}S`;
}
