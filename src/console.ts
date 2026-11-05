// The Bad Monkey console records as data (enterprise platform, spiral 3 S3-H-06): the entry types the console
// and its agents write into a group's `constraints`, `policy`, `decisions`, and `findings` spaces, named by the
// console namespace `https://badmonkey.ai/console#<Record>` so a TypeScript peer reads them with the same
// `Template` it uses for its own entries. A field the wire carries that a class here does not declare still
// arrives on the instance; the declared ones document the shape.
//
//     import { Constraint, rules } from "@agentspaces/client";
//     for (const c of new Space(peer, "constraints").readAll(new Template(Constraint))) console.log(c.template, c.a, c.b);
//     const counts = Object.fromEntries(Object.entries(rules(peer)).map(([k, v]) => [k, v.length]));
import type { Peer } from "./peer.js";
import { Space, Template, entry } from "./space.js";
import type { EntryType } from "./space.js";

export const CONSOLE_NAMESPACE = "https://badmonkey.ai/console#";

/** The wire schema name of a console record, by its record name. */
export const consoleType = (name: string): string => CONSOLE_NAMESPACE + name;

/** The conditions a rule book names, one version at a time. */
@entry(consoleType("Vocabulary"))
export class Vocabulary {
  schemaVersion = 1;
  book = "";
  version = 0;
  hash = "";
  conditions: Record<string, string> = {};
}

/** One compiled sentence of a rule book: a template over two conditions, guards, window, key, enforcement. */
@entry(consoleType("Constraint"))
export class Constraint {
  schemaVersion = 1;
  book = "";
  version = 0;
  unit = "";
  template = "";
  a = "";
  aGuard: string[] = [];
  b = "";
  bGuard: string[] = [];
  n = 0;
  within = "";
  key = "";
  enforcement: string[] = [];
  jury: Record<string, unknown> = {};
}

/** A configuration version the console carries to an agent instance. */
@entry(consoleType("AgentConfiguration"))
export class AgentConfiguration {
  schemaVersion = 1;
  agent = "";
  instance = "";
  group = "";
  version = 0;
  hash = "";
  body: Record<string, unknown> = {};
  scope: Record<string, unknown> = {};
  approval = "";
  publishedBy = "";
  publishedAt: unknown = null;
}

/** A jury's verdict on one unit of a rule book under a key. */
@entry(consoleType("JuryDecision"))
export class JuryDecision {
  schemaVersion = 1;
  book = "";
  version = 0;
  unit = "";
  key = "";
  motion = "";
  verdict = "";
  ballots: Record<string, unknown>[] = [];
  at: unknown = null;
}

/** What the console or an agent noticed, with what to do about it. */
@entry(consoleType("Finding"))
export class ConsoleFinding {
  schemaVersion = 1;
  id = "";
  kind = "";
  subject = "";
  severity = "";
  text = "";
  suggested = "";
  at: unknown = null;
}

export type ConsoleRecordName = "Vocabulary" | "Constraint" | "AgentConfiguration" | "JuryDecision" | "Finding";

/** Where the console writes each record, by record name. */
export const CONSOLE_SPACES: Record<ConsoleRecordName, string> = {
  Vocabulary: "constraints",
  Constraint: "constraints",
  AgentConfiguration: "policy",
  JuryDecision: "decisions",
  Finding: "findings",
};

const TYPES: Record<ConsoleRecordName, EntryType<unknown>> = { Vocabulary, Constraint, AgentConfiguration, JuryDecision, Finding: ConsoleFinding };

/**
 * The rule entries of the peer's group as data: the values per record name, from the space the console writes each
 * into. A late joiner holds nothing of a space until it pulls it, so each space named is pulled before the read;
 * what the pull brings arrives on a later call.
 */
export function rules(peer: Peer, limit = 100,
                      names: ConsoleRecordName[] = ["Vocabulary", "Constraint", "AgentConfiguration", "JuryDecision"]): Record<string, unknown[]> {
  const spaces = new Map<string, Space>();
  const out: Record<string, unknown[]> = {};
  for (const name of names) {
    const spaceName = CONSOLE_SPACES[name];
    let space = spaces.get(spaceName);
    if (!space) {
      peer.pullSpace(spaceName);
      space = new Space(peer, spaceName);
      spaces.set(spaceName, space);
    }
    out[name] = space.readAll(new Template(TYPES[name]), limit);
  }
  return out;
}

// ---- spiral 4 (S4-B-02): the standard entries of the Apps tier, under their own namespace

export const APPS_NAMESPACE = "https://badmonkey.ai/ns/apps/v1/";
/** The wire schema name of a standard Apps entry, by its record name. */
export const appsType = (name: string): string => APPS_NAMESPACE + name;
/** The group space each standard entry lives in. */
export const APPS_SPACES: Record<string, string> = { ChatMessage: "conversations", ResearchRequest: "research", ResearchResult: "research",
  SharedObject: "shared", SharedFile: "shared" };

/** One line of a thread in a group's `conversations` space. */
@entry(appsType("ChatMessage"))
export class ChatMessage {
  schemaVersion = 1;
  id = "";
  key = "";
  from: { kind: "person" | "agent"; name: string; peer: string } = { kind: "person", name: "", peer: "" };
  text = "";
  attachments: string[] = [];
  inReplyTo = "";
  at = "";
}

/** A question over named sources for named agents under a budget and a deadline, in `research`. */
@entry(appsType("ResearchRequest"))
export class ResearchRequest {
  schemaVersion = 1;
  id = "";
  key = "";
  question = "";
  sources: string[] = [];
  agents: string[] = [];
  budget: { scope: string; limit: number; currency: string } = { scope: "", limit: 0, currency: "USD" };
  deadline = "";
  requestedBy = "";
  at = "";
}

/** One agent's answer to a ResearchRequest, with citations and shared objects, in `research`. */
@entry(appsType("ResearchResult"))
export class ResearchResult {
  schemaVersion = 1;
  id = "";
  request = "";
  agent = "";
  text = "";
  citations: Array<{ asset: string; record: string; at: string }> = [];
  objects: string[] = [];
  confidence: number | null = null;
  at = "";
}

/** A reference to an entry, never a copy, in `shared`. */
@entry(appsType("SharedObject"))
export class SharedObject {
  schemaVersion = 1;
  id = "";
  type = "";
  key = "";
  title = "";
  summary = "";
  by = "";
  sharedWith: string[] = [];
  entry: { group: string; space: string; id: string } | null = null;
  at = "";
}

/** A file on the content swarm, named by its root and digest, in `shared`. */
@entry(appsType("SharedFile"))
export class SharedFile {
  schemaVersion = 1;
  id = "";
  name = "";
  mediaType = "application/octet-stream";
  bytes = 0;
  root = "";
  sha256 = "";
  by = "";
  sharedWith: string[] = [];
  at = "";
}

// ---- spiral 4 (S4-B-16): the A2UI records of agentspaces-a2ui, named by the console as before

/** One A2UI envelope of a surface in a group's `views` space. */
@entry(consoleType("Surface"))
export class Surface {
  schemaVersion = 1;
  app = "";
  surfaceId = "";
  catalogId = "";
  seq = 0;
  message: Record<string, unknown> = {};
  version = "v0.9.1";
  at = "";
}

/** A renderer's action on a surface, with the session it came through. */
@entry(consoleType("SurfaceAction"))
export class SurfaceAction {
  schemaVersion = 1;
  app = "";
  surfaceId = "";
  session = "";
  action: Record<string, unknown> = {};
  at = "";
}

// ---- spiral 4 §3.6 (S4-P-03): the prompt library on the client side

export const PROMPTS_KIND = "bma-console/prompts";
export const PROMPTS_INSTANCE = "prompts";
export const PROMPT_HINT_PREFIX = "prompt.";
const PLACEHOLDER = /\{([a-zA-Z_][a-zA-Z0-9_.-]*)\}/g;

export interface PromptVariable { name: string; type?: string; required?: boolean; example?: string }
export interface PromptEntry { id: string; version: number; hash: string; kind: string; text: string; variables: PromptVariable[] }
export interface PromptSet { schemaVersion?: number; group: string; prompts: PromptEntry[]; publishedBy?: string; publishedAt?: unknown }

/**
 * The text with its `{placeholders}` filled from `values`; a required variable that is missing is refused, an
 * optional one is filled with an empty string (the Java `Prompt.render` rule).
 */
export function renderPrompt(text: string, variables: PromptVariable[], values: Record<string, unknown> = {}): string {
  for (const v of variables ?? []) {
    const value = values[v.name];
    if (v.required && (value === undefined || value === null || String(value).trim() === "")) throw new Error("the prompt needs {" + v.name + "}");
  }
  return (text ?? "").replace(PLACEHOLDER, (_m, name: string) => (values[name] === undefined || values[name] === null ? "" : String(values[name])));
}

/**
 * The group's `PromptSet` in force: the newest `AgentConfiguration` of kind `bma-console/prompts` in the `policy`
 * space, as the console published it, or null before any arrived.
 */
export function promptSet(peer: Peer, limit = 64): PromptSet | null {
  peer.pullSpace(CONSOLE_SPACES.AgentConfiguration);
  const space = new Space(peer, CONSOLE_SPACES.AgentConfiguration);
  let newest: AgentConfiguration | null = null;
  for (const c of space.readAll(new Template(AgentConfiguration), limit) as AgentConfiguration[]) {
    if (c.agent === PROMPTS_KIND && c.instance === PROMPTS_INSTANCE && (!newest || c.version > newest.version)) newest = c;
  }
  return newest ? (newest.body as unknown as PromptSet) : null;
}

/** A reference to a prompt of the library: the version in force through `loader`, or the fallback the agent ships with. */
export class PromptRef {
  constructor(readonly ref: string, readonly fallback: string = "", private readonly loader: () => PromptSet | null = () => null) {}

  entry(): PromptEntry | undefined {
    return (this.loader()?.prompts ?? []).find(e => e.id === this.ref);
  }

  get version(): number { return this.entry()?.version ?? 0; }

  get text(): string { return this.entry()?.text ?? this.fallback; }

  render(values: Record<string, unknown> = {}): string {
    const e = this.entry();
    return e ? renderPrompt(e.text, e.variables ?? [], values) : renderPrompt(this.fallback, [], values);
  }

  /** The `prompt.<id>=<version>` pair an agent reports as a hint. */
  get hint(): [string, string] { return [PROMPT_HINT_PREFIX + this.ref, String(this.version)]; }
}

/** A `PromptRef` reading the peer's group for its set on every use. */
export const prompt = (peer: Peer, ref: string, fallback = ""): PromptRef => new PromptRef(ref, fallback, () => promptSet(peer));

