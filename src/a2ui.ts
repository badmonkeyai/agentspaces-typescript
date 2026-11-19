/*
 * Copyright 2026 Bad Monkey, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The open A2UI records and component builders of agentspaces-a2ui in the TypeScript client (SPEC §6.1a.7).
 * The four records an application's agents write beside its surfaces,
 * `ChatMessage` (versions 1 and 2), `SharedFile` (versions 1 and 2), `WorkingOn` and `ChatProgress`, as `@entry`
 * classes whose fields are in Java's declared order, so a record encodes to the bytes the Java vectors pin; a version
 * 2 field is left out of a version 1 record. Each factory refuses what the Java constructor refuses. The
 * builders shape the components of the open catalogs as `Surfaces` does in Java: `titleBar`, `menu`, `split` of
 * agentspaces-viz, and `chat`, `fileTree`, `filePreview` of agentspaces-widgets. They hold each component to A2UI 1.0
 * as Java does: a binding is `{ "@path": ... }`, an id is an identifier, and a component's kept keys carry their `@`.
 */

import { entry } from "./space.js";

/** The open namespace of the records. */
export const A2UI_NAMESPACE = "https://badmonkey.ai/agentspaces/a2ui/v1/";
/** The member hint a reader of version 2 advertises, and its value. */
export const A2UI_RECORDS_HINT = "a2ui.records";
export const A2UI_RECORDS_VERSION = "2";
/** The A2A task states, in the specification's order. */
export const TASK_STATES = ["submitted", "working", "input-required", "completed", "failed", "canceled"] as const;
export type TaskState = (typeof TASK_STATES)[number];
export const PLAIN = "text/plain";
export const MARKDOWN = "text/markdown";
export const MAX_CITES = 16;
export const MAX_STEPS = 20;
export const MAX_TASK = 120;
export const STEP_KINDS = ["read", "tool", "write"] as const;

/** Whether a writer may write version 2: every reader's hints carry `a2ui.records` at 2 or later (and there may be none). */
export function writesV2(readerHints: Iterable<Record<string, string>>): boolean {
  for (const h of readerHints) {
    const v = h[A2UI_RECORDS_HINT];
    if (v === undefined || !/^\d{1,9}$/.test(v) || Number(v) < 2) return false;
  }
  return true;
}

/** The version a writer writes for these readers: 2 when every one reads it, else 1. */
export const versionFor = (readerHints: Iterable<Record<string, string>>): 1 | 2 => (writesV2(readerHints) ? 2 : 1);

/** A path in a tree of files: relative, `/`-separated, at most 512 bytes, no empty, `.` or `..` segment, no backslash or control character. */
export function validPath(path: string): boolean {
  if (!path || new TextEncoder().encode(path).length > 512 || path.startsWith("/")) return false;
  for (const ch of path) {
    const c = ch.codePointAt(0)!;
    if (ch === "\\" || c < 0x20 || c === 0x7f) return false;
  }
  return path.split("/").every(s => s !== "" && s !== "." && s !== "..");
}

const requirePath = (path: string, what: string): string => {
  if (!validPath(path)) throw new RangeError(`${what} path must be relative and /-separated, at most 512 bytes, with no empty, . or .. segment and no backslash or control character: ${path}`);
  return path;
};
const requireState = (state: string): string => {
  if (!(TASK_STATES as readonly string[]).includes(state)) throw new RangeError(`state must be one of the A2A task states ${TASK_STATES.join(", ")}: ${state}`);
  return state;
};
const version = (v: number, record: string): 1 | 2 => {
  if (v !== 1 && v !== 2) throw new RangeError(`a ${record} has schemaVersion 1 or 2: ${v}`);
  return v;
};

export interface From { kind: "person" | "agent"; name: string; peer: string }
export interface Cite { file: string; path: string; name: string }

/** One line of a thread in `conversations`; version 2 adds `format` and `cites`. */
@entry(A2UI_NAMESPACE + "ChatMessage")
export class ChatMessage {
  schemaVersion: 1 | 2 = 1;
  id = "";
  key = "";
  from: From = { kind: "person", name: "", peer: "" };
  text = "";
  attachments: string[] = [];
  inReplyTo = "";
  at = "";
  format?: string;
  cites?: Cite[];
}

/** A line, checked as the Java record checks it; a version 2 line takes `format` (plain by default) and `cites`. */
export function chatMessage(v: { schemaVersion?: number; id: string; key: string; from?: Partial<From>; text?: string; attachments?: string[];
  inReplyTo?: string; at: string; format?: string; cites?: Array<Partial<Cite>> }): ChatMessage {
  const m = new ChatMessage();
  m.schemaVersion = version(v.schemaVersion ?? 1, "ChatMessage");
  m.id = v.id;
  m.key = v.key;
  const kind = v.from?.kind || "person";
  if (kind !== "person" && kind !== "agent") throw new RangeError(`a chat message is from a person or an agent: ${kind}`);
  m.from = { kind, name: v.from?.name ?? "", peer: v.from?.peer ?? "" };
  m.text = v.text ?? "";
  m.attachments = [...(v.attachments ?? [])];
  m.inReplyTo = v.inReplyTo ?? "";
  m.at = v.at;
  if (m.schemaVersion === 1) {
    if (v.format !== undefined || v.cites !== undefined) throw new RangeError("a version 1 ChatMessage carries no format and no cites; write version 2 for them");
    delete m.format;
    delete m.cites;
  } else {
    const format = v.format ?? PLAIN;
    if (format !== PLAIN && format !== MARKDOWN) throw new RangeError(`format must be text/plain or text/markdown: ${format}`);
    const cites = (v.cites ?? []).map(c => {
      if (!c.file) throw new RangeError("a cite names its file");
      return { file: c.file, path: c.path ? requirePath(c.path, "a cite's") : "", name: c.name ?? "" };
    });
    if (cites.length > MAX_CITES) throw new RangeError(`a ChatMessage cites at most 16 files: ${cites.length}`);
    m.format = format;
    m.cites = cites;
  }
  return m;
}

/** A file on the content swarm in `shared`; version 2 adds `path` and `replaces`. */
@entry(A2UI_NAMESPACE + "SharedFile")
export class SharedFile {
  schemaVersion: 1 | 2 = 1;
  id = "";
  name = "";
  mediaType = "application/octet-stream";
  bytes = 0;
  root = "";
  sha256 = "";
  by = "";
  sharedWith: string[] = [];
  at = "";
  path?: string;
  replaces?: string;
}

export function sharedFile(v: { schemaVersion?: number; id: string; name: string; mediaType?: string; bytes?: number; root?: string; sha256?: string; by?: string;
  sharedWith?: string[]; at: string; path?: string; replaces?: string }): SharedFile {
  const f = new SharedFile();
  f.schemaVersion = version(v.schemaVersion ?? 1, "SharedFile");
  if (!v.name || !v.name.trim()) throw new RangeError("a shared file has a name");
  if ((v.bytes ?? 0) < 0) throw new RangeError("a file's size is not negative");
  f.id = v.id;
  f.name = v.name;
  f.mediaType = v.mediaType && v.mediaType.trim() ? v.mediaType : "application/octet-stream";
  f.bytes = v.bytes ?? 0;
  f.root = v.root ?? "";
  f.sha256 = v.sha256 ?? "";
  f.by = v.by ?? "";
  f.sharedWith = [...(v.sharedWith ?? [])];
  f.at = v.at;
  if (f.schemaVersion === 1) {
    if (v.path !== undefined || v.replaces !== undefined) throw new RangeError("a version 1 SharedFile carries no path and no replaces; write version 2 for them");
    delete f.path;
    delete f.replaces;
  } else {
    f.path = v.path ? requirePath(v.path, "a shared file's") : "";
    f.replaces = v.replaces ?? "";
  }
  return f;
}

/** What an agent holds while it works, in `views`: one per agent and key, leased 60 s and renewed every 20 s. */
@entry(A2UI_NAMESPACE + "WorkingOn")
export class WorkingOn {
  schemaVersion = 1;
  id = "";
  agent = "";
  key = "";
  files: string[] = [];
  task = "";
  state = "working";
  since = "";
}

/** The one entry an agent keeps per key. */
export const workingOnId = (agent: string, key: string): string => `working-${agent}-${key}`;

export function workingOn(v: { agent: string; key?: string; files?: string[]; task?: string; state?: string; since: string; id?: string }): WorkingOn {
  const w = new WorkingOn();
  w.id = v.id ?? workingOnId(v.agent, v.key ?? "");
  w.agent = v.agent;
  w.key = v.key ?? "";
  w.files = (v.files ?? []).map(p => requirePath(p, "a held file's"));
  w.task = v.task ?? "";
  if (w.task.length > MAX_TASK) throw new RangeError(`a task line is at most 120 characters: ${w.task.length}`);
  w.state = requireState(v.state ?? "working");
  w.since = v.since;
  return w;
}

export interface Step { label: string; kind: (typeof STEP_KINDS)[number]; ref: string; at: string }

/** An agent's progress on one line of a chat, in `views`: one per line, leased 30 s and renewed every 10 s while working. */
@entry(A2UI_NAMESPACE + "ChatProgress")
export class ChatProgress {
  schemaVersion = 1;
  id = "";
  key = "";
  inReplyTo = "";
  agent = "";
  state = "submitted";
  steps: Step[] = [];
  at = "";
}

/** The one entry per line. */
export const chatProgressId = (inReplyTo: string): string => `progress-${inReplyTo}`;

export function chatProgress(v: { key: string; inReplyTo: string; agent: string; state?: string; steps?: Array<Partial<Step>>; at: string; id?: string }): ChatProgress {
  const p = new ChatProgress();
  p.id = v.id ?? chatProgressId(v.inReplyTo);
  p.key = v.key;
  p.inReplyTo = v.inReplyTo;
  p.agent = v.agent;
  p.state = requireState(v.state ?? "submitted");
  const steps = (v.steps ?? []).map(s => {
    if (!(STEP_KINDS as readonly string[]).includes(String(s.kind))) throw new RangeError(`a step's kind is read, tool or write: ${s.kind}`);
    if (!s.at) throw new RangeError("a step has its time");
    return { label: s.label ?? "", kind: s.kind as Step["kind"], ref: s.ref ?? "", at: s.at };
  });
  if (steps.length > MAX_STEPS) throw new RangeError(`a progress entry keeps at most 20 steps: ${steps.length}`);
  p.steps = steps;
  p.at = v.at;
  return p;
}

// ---- the component builders, each the shape Surfaces writes in Java, held to A2UI 1.0 as Java holds them

type Component = Record<string, unknown>;

/** An A2UI 1.0 data binding: a JSON pointer into the surface's data model. v0.9.1's `{ path }` is not one. */
export type Binding = { "@path": string };

/**
 * A2UI 1.0's component envelope keys (spec §2.9): the only `@`-prefixed keys at a component's top level. `id` and
 * `component` stay bare. The open catalogs declare the first three on every component, so a builder takes them as options.
 */
export const ENVELOPE_KEYS = ["@catalogId", "@accessibility", "@metadata", "@checks"] as const;

const ID = /^[\p{Alphabetic}_][\p{Alphabetic}\p{Nd}_]*$/u;

/**
 * Refuses a component id A2UI 1.0 refuses, naming a form it takes: an id is a Unicode identifier (UAX #31), so
 * `barMenu` and `bar_menu` pass and `bar-menu` does not. Returns the id. Java's pen checks the same rule as it writes.
 */
export function componentId(id: string): string {
  const s = String(id ?? "");
  if (!ID.test(s)) {
    const words = s.split(/[^\p{Alphabetic}\p{Nd}_]+/u).filter(w => w);
    const hint = words.length ? words.reduce((a, b) => a + b[0].toUpperCase() + b.slice(1)) : "root";
    throw new RangeError(`component id '${s}' is not an A2UI 1.0 identifier (UAX #31): use letters, digits and _ only, such as ${hint}`);
  }
  return s;
}

/** A key in 1.0's reserved single-`@` namespace, `^@([^@]|$)`; a doubled `@@` is a literal. */
const reserved = (key: string): boolean => key.startsWith("@") && !key.startsWith("@@");

/**
 * Walks a value to its leaves as Java's `Surfaces.binding` does: v0.9.1's `{ path }` binding and `{ call }` function call
 * are refused, naming where they sit, as is a key in 1.0's reserved `@` namespace other than `@path` and `@call` (a
 * literal one is written doubled, `@@type`). An action's `context` is a record whose keys are names, so an entry called
 * `path` there passes, and its values are walked like any other.
 */
function binding(where: string, value: unknown, keysAreNames = false): void {
  if (Array.isArray(value)) {
    value.forEach((v, i) => binding(`${where}[${i}]`, v));
    return;
  }
  if (value === null || typeof value !== "object") return;
  const m = value as Record<string, unknown>;
  if (!keysAreNames && "path" in m && !("@path" in m)) throw new RangeError(`${where} binds with A2UI 1.0's {"@path": ...}, not v0.9.1's {"path": ...}`);
  if (!keysAreNames && "call" in m && !("@call" in m)) throw new RangeError(`${where} calls a function with A2UI 1.0's {"@call": ...}, not v0.9.1's {"call": ...}`);
  for (const [k, v] of Object.entries(m)) {
    if (reserved(k) && k !== "@path" && k !== "@call") throw new RangeError(`${where}.${k} is a reserved A2UI 1.0 key; a literal key that starts with @ is written @${k}`);
    binding(`${where}.${k}`, v, k === "context" && !keysAreNames && "name" in m);
  }
}

/**
 * Holds one built component to A2UI 1.0, as Java's `Surfaces.bindings` does: its id is an identifier, its kept keys
 * carry their `@` (a bare `catalogId`, `accessibility`, `metadata` or `checks` is refused, naming the `@` key), no
 * other top-level key starts with a single `@`, and every property is walked by {@link binding}. Returns the component.
 */
function checked(m: Component): Component {
  const name = String(m.component);
  componentId(String(m.id));
  for (const [k, v] of Object.entries(m)) {
    if ((ENVELOPE_KEYS as readonly string[]).includes("@" + k)) throw new RangeError(`${name}.${k} is A2UI 1.0's @${k} envelope key, not ${k}`);
    if (reserved(k) && !(ENVELOPE_KEYS as readonly string[]).includes(k)) throw new RangeError(`${name}.${k} is a reserved A2UI 1.0 key; a component's top level takes only ${ENVELOPE_KEYS.join(", ")}`);
    if (k !== "id" && k !== "component") binding(`${name}.${k}`, v);
  }
  return m;
}

const comp = (id: string, component: string): Component => ({ id, component });
const putText = (m: Component, key: string, value: string | undefined | null) => { if (value && value.trim()) m[key] = value; };
const sorted = (options: Record<string, unknown>): Record<string, unknown> => Object.fromEntries(Object.keys(options).sort().map(k => [k, options[k]]));

/**
 * Refuses an option a component does not take, or a word outside its list, as the Java builders check the catalog.
 * The envelope keys the open catalogs declare on every component (`@catalogId`, `@accessibility`, `@metadata`) are
 * taken, and a bare one is refused naming its `@` key.
 */
function check(component: string, options: Record<string, unknown>, known: Record<string, readonly string[] | null>, max: Record<string, number> = {}) {
  for (const [k, v] of Object.entries(options)) {
    if (k === "@catalogId" || k === "@accessibility" || k === "@metadata") continue;
    if (!(k in known) && (ENVELOPE_KEYS as readonly string[]).includes("@" + k)) throw new RangeError(`${component}.${k} is A2UI 1.0's @${k} envelope key, not ${k}`);
    if (!(k in known)) throw new RangeError(`${component} has no property ${k}; it takes ${Object.keys(known).join(", ")}`);
    const words = known[k];
    if (words) for (const w of Array.isArray(v) ? v : [v]) if (!words.includes(String(w))) throw new RangeError(`${component}.${k} takes ${words.join(", ")}, not ${w}`);
    if (typeof v === "number" && k in max && v > max[k]) throw new RangeError(`${component}.${k} is at most ${max[k]}${max[k] === 16777216 ? " (16 MiB)" : ""}: ${v}`);
  }
}

/** The page's one bar: a title (a literal or `{ "@path": ... }`), a subtitle, an icon, a status, buttons, and a menu by id. */
export function titleBar(id: string, title: string | Binding, subtitle = "", icon = "", status?: Component | null, actions: Component[] = [], menu = ""): Component {
  const m = comp(id, "TitleBar");
  m.title = title;
  putText(m, "subtitle", subtitle);
  putText(m, "icon", icon);
  if (status && Object.keys(status).length) m.status = status;
  if (actions.length) m.actions = [...actions];
  putText(m, "menu", menu);
  return checked(m);
}

/** A title bar's status: the path of the WorkingOn rows, and the words for working and for idle. */
export function titleStatus(from: string, working = "", idle = ""): Component {
  const labels: Component = {};
  putText(labels, "working", working);
  putText(labels, "idle", idle);
  return Object.keys(labels).length ? { from, labels } : { from };
}

/** A button in a header: its id, its words, an icon name (blank for none), and the action it dispatches. */
export function titleAction(id: string, label: string, icon: string, actionName: string): Component {
  const m: Component = { id, label };
  putText(m, "icon", icon);
  m.action = { name: actionName };
  return m;
}

/** A menu behind a trigger, over items, or over the items a data model path holds. */
export function menu(id: string, trigger: Component, items: Component[] | string): Component {
  const m = comp(id, "Menu");
  m.trigger = trigger;
  m.items = Array.isArray(items) ? [...items] : items;
  return checked(m);
}

/** What opens a menu: `button`, `overflow`, or `context`, and its words. */
export function trigger(kind: "button" | "overflow" | "context", label = ""): Component {
  const m: Component = { kind };
  putText(m, "label", label);
  return m;
}

/** A menu item that dispatches an action, with `shortcut`, `group`, `disabled`, `checked` or an action `context` in `more`. */
export function menuItem(id: string, label: string, actionName: string, more: Record<string, unknown> = {}): Component {
  const m: Component = { id, label };
  const action: Component = { name: actionName };
  for (const [k, v] of Object.entries(more)) {
    if (k === "context") action.context = v;
    else if (v !== null && v !== undefined && !(typeof v === "string" && !v.trim())) m[k] = v;
  }
  m.action = action;
  binding("Menu.items[]", m);
  return m;
}

/** A submenu: an item whose items open beside it, one level deep. */
export function submenu(id: string, label: string, items: Component[]): Component {
  for (const i of items) if ("items" in i) throw new RangeError(`a menu has one level of submenu: ${i.id} holds items of its own`);
  const m: Component = { id, label, items: [...items] };
  binding("Menu.items[]", m);
  return m;
}

/** Two or three panes, side by side or one over another, kept under `persist`, stacked below `stackBelow` pixels. */
export function split(id: string, orientation: "horizontal" | "vertical" | "" = "horizontal", persist = "", stackBelow = 0, panes: Component[] = []): Component {
  if (panes.length < 2 || panes.length > 3) throw new RangeError(`a split has two or three panes: ${panes.length}`);
  const o = orientation || "horizontal";
  if (o !== "horizontal" && o !== "vertical") throw new RangeError(`a split's orientation is horizontal or vertical: ${orientation}`);
  const m = comp(id, "Split");
  m.orientation = o;
  putText(m, "persist", persist);
  if (stackBelow > 0) m.stackBelow = stackBelow;
  m.panes = [...panes];
  return checked(m);
}

/** One pane of a split: its id, its child (blank for an empty pane), its share, its minimum in pixels, whether it collapses, and its name. */
export function pane(id: string, child: string, size: number, min = 0, collapsible = false, label = ""): Component {
  const m: Component = { id };
  putText(m, "child", child);
  m.size = size;
  if (min > 0) m.min = min;
  if (collapsible) m.collapsible = true;
  putText(m, "label", label);
  return m;
}

const CHAT = { reads: null, progress: null, files: null, suggestions: null, placeholder: null, attach: null, format: [PLAIN, MARKDOWN], controls: ["copy", "retry", "stop", "feedback"],
  max: null, preview: null, writeAction: null } as const;
const TREE = { working: null, label: null, upload: null, preview: null, chat: null, actions: ["ask", "download", "share", "rename", "remove"], badges: ["working", "new", "changed", "agent"],
  agents: null, flat: null, accept: null, maxBytes: null, reads: null } as const;
const PREVIEW = { files: null, maxBytes: null, csvRows: null, kinds: ["text/plain", "text/markdown", "text/csv", "image/png", "image/jpeg", "application/pdf"] } as const;

/** The one agentic chat of agentspaces-widgets: the agent named over the thread, its key, and its other options. */
export function chat(id: string, agent: string, key: string, options: Record<string, unknown> = {}): Component {
  check("Chat", options, CHAT, { max: 1000 });
  suggestions(options.suggestions);
  const m = comp(id, "Chat");
  putText(m, "agent", agent);
  m.key = key ?? "";
  return checked(Object.assign(m, sorted(options)));
}

/**
 * A Chat's `suggestions` is a list of strings, or one binding `{ "@path": "/..." }` to the rows the agent writes, as the
 * catalog's `oneOf` says; anything else is refused here, and an old form is named by {@link binding}.
 */
function suggestions(value: unknown): void {
  if (value === undefined || value === null) return;
  binding("Chat.suggestions", value);
  if (Array.isArray(value) && value.every(v => typeof v === "string")) return;
  const m = value as Record<string, unknown>;
  if (m && typeof m === "object" && !Array.isArray(m) && Object.keys(m).length === 1 && typeof m["@path"] === "string" && (m["@path"] as string).startsWith("/")) return;
  throw new RangeError(`Chat.suggestions is a list of strings or one binding {"@path": "/..."} to the agent's rows, not ${JSON.stringify(value)}`);
}

/** A tree of files over the SharedFile rows at `reads`. */
export function fileTree(id: string, reads = "/files", options: Record<string, unknown> = {}): Component {
  check("FileTree", options, TREE);
  const m = comp(id, "FileTree");
  m.reads = reads || "/files";
  return checked(Object.assign(m, sorted(options)));
}

/** One file by its media type: a file id, or `{ "@path": ... }` where a tree puts the person's choice. */
export function filePreview(id: string, file: string | Binding, options: Record<string, unknown> = {}): Component {
  check("FilePreview", options, PREVIEW, { maxBytes: 16777216, csvRows: 5000 });
  const m = comp(id, "FilePreview");
  m.file = file;
  return checked(Object.assign(m, sorted(options)));
}
