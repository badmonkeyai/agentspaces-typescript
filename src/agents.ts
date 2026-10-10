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
 * The programming model, TypeScript-shaped (L3L4-COVERAGE.md §6.5): stage-3
 * decorators on the methods of a plain class, and a `Binder` that runs the
 * loops the Java `AgentBinder` runs for the annotations, on Promises over a
 * `Peer`. TypeScript keeps no parameter types at runtime, so the cue type is
 * the decorator's first argument:
 *
 *     @agent("researcher", { description: "Researches topics", goals: ["research"] })
 *     class Researcher {
 *       @spaceTake(Task, "tasks", { lease: "2s", where: { priority: gte(1) } })
 *       async research(task: Task): Promise<Finding> { return new Finding(task.topic, "researched"); }
 *
 *       @spaceNotify(Finding, "findings")
 *       audit(finding: Finding): Receipt | null { return new Receipt(finding.topic); }
 *
 *       @bidFunction(Task, "tasks")
 *       price(task: Task): number { return task.priority > 3 ? 1 : 10; }
 *
 *       @ballot("decisions")
 *       judge(proposal: Proposal): string | null { return "approve"; }
 *
 *       @onDecision("decisions", { resultSpace: "ledger" })
 *       record(decision: Decision): Verdict { return new Verdict(decision.proposalId, decision.winner); }
 *     }
 *
 *     const bound = new Binder(peer, { agent: identity.renewingSubordinate("ts-worker", "PT24H") }).bind(new Researcher());
 *     await bound.close();
 *
 * The return value is the next entry (`null` writes nothing, or abstains), a
 * `Tagged` written with its tags, an array of entries (the fork, each written
 * on its own), or a `Motion` opening a vote once per proposal id. `@propose`
 * opens a vote from a cue once per key; `@spaceJoin` (LOCAL mode) fires once
 * per key when every required part is present. A
 * take completes in its space with the result, where a remote caller awaits
 * it, or in `resultSpace`; a notify fires once per entry; a ballot casts once
 * per proposal; a decision fires once per proposal when the quorum closes;
 * the AgentCard, with the declared actions, is published on bind.
 */

import { AgentIdentity, instantIso } from "./identity.js";
import type { Peer } from "./peer.js";
import { COMPLETED, Class, Contribution, EntryType, EventKind, Motion, Space, SpaceEvent, TakeContext, Tagged, Template,
  WRITTEN, durationMillis, fromPayload, schemaOf, toPayload } from "./space.js";
import { Aggregate, Settle } from "./capabilities/aggregate.js";
import * as votes from "./vote.js";
import * as wire from "./wire.js";
import type { Dict } from "./wire.js";

export type { Decision, Proposal } from "./vote.js";

// -------------------------------------------------------------- decorators

const META = Symbol.for("agentspaces.binding");
const SPEC = Symbol.for("agentspaces.spec");

type Verb = "take" | "notify" | "bid" | "ballot" | "decision" | "estimate" | "propose" | "join";
type Binding = { verb: Verb; cue?: EntryType; space: string; produces?: EntryType | EntryType[]; [attr: string]: unknown };
type Spec = { name: string; description: string; goals: string[] };
type Method = (this: unknown, ...args: never[]) => unknown;
type MethodDecorator = (value: Method, context: ClassMethodDecoratorContext) => void;

function mark(binding: Binding): MethodDecorator {
  return (value, _context) => {
    (value as unknown as { [META]?: Binding })[META] = binding;
  };
}

/** Names the agent, as `@AgentSpec` does: the card's name, description, and goals. */
export function agent(name: string, options: { description?: string; goals?: string[] } = {}) {
  return <C extends Class>(value: C, _context?: ClassDecoratorContext): C => {
    (value as unknown as { [SPEC]?: Spec })[SPEC] = { name, description: options.description ?? "",
      goals: options.goals ?? [] };
    return value;
  };
}

export type TakeOptions = { lease?: number | string; pollTimeout?: number | string; resultSpace?: string;
  resultLease?: number | string; produces?: EntryType | EntryType[]; tags?: { [k: string]: unknown };
  where?: { [k: string]: unknown }; description?: string };

/** The kill-tolerant worker: take one matching entry under a lease, call, complete with the result. */
export function spaceTake(cue: EntryType, space: string, options: TakeOptions = {}): MethodDecorator {
  return mark({ verb: "take", cue, space, lease: options.lease ?? "10m", pollTimeout: options.pollTimeout ?? "1s",
    resultSpace: options.resultSpace, resultLease: options.resultLease ?? "1h", produces: options.produces,
    tags: options.tags, where: options.where, description: options.description ?? "" });
}

export type NotifyOptions = { resultSpace?: string; resultLease?: number | string; produces?: EntryType | EntryType[];
  tags?: { [k: string]: unknown }; where?: { [k: string]: unknown }; on?: EventKind | EventKind[]; description?: string };

/**
 * Choreography: called once per matching entry and event kind, never
 * consuming it. `on` is one kind or several of WRITTEN, TAKEN, COMPLETED,
 * EXPIRED (the write lease lapsed: a leased entry as a timer), and
 * REAPPEARED (a take claim lapsed).
 */
export function spaceNotify(cue: EntryType, space: string, options: NotifyOptions = {}): MethodDecorator {
  const kinds = options.on === undefined ? [WRITTEN] : Array.isArray(options.on) ? options.on : [options.on];
  if (kinds.length === 0) {
    throw new Error("@spaceNotify needs at least one event kind");
  }
  return mark({ verb: "notify", cue, space, resultSpace: options.resultSpace, resultLease: options.resultLease ?? "1h",
    produces: options.produces, tags: options.tags, where: options.where, on: kinds,
    description: options.description ?? "" });
}

/** The price of work under AUCTION: a number per entry, the lowest wins. */
export function bidFunction(cue: EntryType, space: string): MethodDecorator {
  return mark({ verb: "bid", cue, space });
}

/** One signed ballot per proposal: return the option, or null to abstain. */
export function ballot(space: string, options: { prefix?: string; lease?: number | string } = {}): MethodDecorator {
  return mark({ verb: "ballot", space, prefix: options.prefix ?? "", lease: options.lease ?? "1h" });
}

/**
 * Reacts once per aggregate epoch (by prefix, or every epoch) when its
 * estimate has settled under the rule, as `@OnEstimate` does; the method
 * receives an `Estimate` and may return an entry for `resultSpace`. Needs a
 * `new Binder(peer, { aggregate })`.
 */
export function onEstimate(options: { epochs?: string; ticks?: number; tolerance?: number; resultSpace?: string;
  resultLease?: number | string; produces?: EntryType } = {}): MethodDecorator {
  return mark({ verb: "estimate", space: "", epochs: options.epochs ?? "", ticks: options.ticks ?? 0,
    tolerance: options.tolerance ?? 0, resultSpace: options.resultSpace, resultLease: options.resultLease ?? "1h",
    produces: options.produces });
}

export type PartSpec = { type: EntryType; space?: string; key?: string; keyTag?: string; optional?: boolean;
  atLeast?: number; where?: { [k: string]: unknown }; tags?: { [k: string]: unknown } };

/** One part of a join (`@Part`): its entry class and, optionally, its space, key field or key tag, and filters. */
export function part(type: EntryType, options: Omit<PartSpec, "type"> = {}): PartSpec {
  return { type, ...options };
}

export type JoinOptions = { within?: number | string; resultSpace?: string; resultLease?: number | string;
  maxOpen?: number; produces?: EntryType; description?: string };

/**
 * The fan-in (`@SpaceJoin` in LOCAL mode): once per key, when every required
 * part is readable, the method receives a `Joined` and its return is
 * dispatched as a take's is. A key is forgotten after `within` if it never
 * completes; the fleet-wide LEASED and ORDERED modes are not available here.
 */
export function spaceJoin(space: string, key: string, parts: PartSpec[], options: JoinOptions = {}): MethodDecorator {
  return mark({ verb: "join", space, key, parts, within: options.within ?? "1h", resultSpace: options.resultSpace,
    resultLease: options.resultLease ?? "1h", maxOpen: options.maxOpen ?? 10_000, produces: options.produces,
    description: options.description ?? "" });
}

export type ProposeOptions = { prefix?: string; key?: string | string[]; keyTag?: string; lease?: number | string;
  where?: { [k: string]: unknown }; tags?: { [k: string]: unknown }; description?: string };

/**
 * Opens a vote from a cue (`@Propose`): the method receives the cue and
 * returns the question (or `null` to ask nothing, or a `Motion`); the
 * proposal id is `prefix` plus the key fields joined by `:` (or the key tag),
 * opened once per id.
 */
export function propose(cue: EntryType, space: string, vote: string, options: string[], quorum: number,
                        extra: ProposeOptions = {}): MethodDecorator {
  const keys = typeof extra.key === "string" ? [extra.key] : [...(extra.key ?? [])];
  if (keys.length > 0 && extra.keyTag) {
    throw new Error("@propose names both key and keyTag; choose one");
  }
  if (options.length < 2 || quorum <= 0) {
    throw new Error("@propose needs at least two options and a positive quorum");
  }
  return mark({ verb: "propose", cue, space, vote, options, quorum, prefix: extra.prefix ?? "", keys,
    keyTag: extra.keyTag, lease: extra.lease ?? "1h", where: extra.where, tags: extra.tags,
    description: extra.description ?? "" });
}

/** What a join method receives (`Joined` in Java): the key and the parts by class. */
export class Joined {
  constructor(readonly key: string, private readonly byType: Map<EntryType, unknown[]>) {}

  get<T>(type: EntryType<T>): T {
    const found = this.byType.get(type) ?? [];
    if (found.length === 0) {
      throw new Error(`no ${typeof type === "string" ? type : type.name} part for key '${this.key}'`);
    }
    return found[0] as T;
  }

  find<T>(type: EntryType<T>): T | null {
    return (this.byType.get(type)?.[0] as T | undefined) ?? null;
  }

  all<T>(type: EntryType<T>): T[] {
    return [...((this.byType.get(type) ?? []) as T[])];
  }

  has(type: EntryType): boolean {
    return (this.byType.get(type)?.length ?? 0) > 0;
  }
}

/** Reacts once when a proposal's quorum closes it. */
export function onDecision(space: string, options: { prefix?: string; resultSpace?: string;
  resultLease?: number | string; produces?: EntryType } = {}): MethodDecorator {
  return mark({ verb: "decision", space, prefix: options.prefix ?? "", resultSpace: options.resultSpace,
    resultLease: options.resultLease ?? "1h", produces: options.produces });
}

// ------------------------------------------------------------------ binder

/** A bound agent: its loops and watches, closed together. */
export class Bound {
  card: Dict | null = null;
  running = true;
  readonly loops: Promise<void>[] = [];
  readonly subscriptions: Array<{ close(): void }> = [];

  constructor(readonly name: string) {}

  async close(): Promise<void> {
    this.running = false;
    for (const s of this.subscriptions) {
      s.close();
    }
    await Promise.allSettled(this.loops);
  }
}

export type BinderOptions = { agent?: AgentIdentity | null; agentName?: string; publishCard?: boolean; cardTtl?: string;
  aggregate?: Aggregate | null; voteSpace?: string | null };

/**
 * Runs decorated agents over one peer. `agent` (an `AgentIdentity`) makes
 * every record the agent's own attested one; the peer-signed `agentName`
 * otherwise. `publishCard` sends the AgentCard on bind.
 */
export class Binder {
  readonly agent: AgentIdentity | null;
  readonly agentName: string;
  readonly publishCard: boolean;
  readonly cardTtl: string;
  readonly aggregate: Aggregate | null;
  /** Where a `Motion` naming no space is proposed. */
  readonly voteSpace: string | null;
  private readonly spaces = new Map<string, Space>();

  constructor(readonly peer: Peer, options: BinderOptions = {}) {
    this.agent = options.agent ?? null;
    this.agentName = options.agentName ?? "typescript";
    this.publishCard = options.publishCard ?? true;
    this.cardTtl = options.cardTtl ?? "PT10M";
    this.aggregate = options.aggregate ?? null;
    this.voteSpace = options.voteSpace ?? null;
  }

  space(name: string): Space {
    let space = this.spaces.get(name);
    if (space === undefined) {
      space = new Space(this.peer, name, this.agent, this.agentName);
      this.spaces.set(name, space);
    }
    return space;
  }

  bind(instance: object): Bound {
    const type = instance.constructor as unknown as { [SPEC]?: Spec; name: string };
    const spec: Spec = type[SPEC] ?? { name: type.name.charAt(0).toLowerCase() + type.name.slice(1),
      description: "", goals: [] };
    const bound = new Bound(spec.name);
    const methods = bindings(instance);
    const consumes: string[] = [];
    const produces: string[] = [];
    const spaceBindings: Dict = {};
    const actions: Dict[] = [];
    // Bids first, so AUCTION spaces are priced before any take runs.
    for (const [, method, binding] of methods) {
      if (binding.verb === "bid") {
        const cue = binding.cue!;
        this.space(binding.space).bidFunction = (payload) => Number(method.call(instance, fromPayload(cue, payload) as never));
      }
    }
    for (const [name, method, binding] of methods) {
      if (binding.verb === "bid") {
        continue;
      }
      if (binding.verb === "join") {
        const parts = binding.parts as PartSpec[];
        for (const p of parts) {
          consumes.push(schemaOf(p.type));
        }
        const produced = producedSchemas(binding.produces);
        produces.push(...produced);
        actions.push(wire.cardAction(name, String(binding["description"] ?? ""), parts.map((p) => schemaOf(p.type)),
          produced, "join", binding.space));
        this.startJoin(bound, instance, method, binding);
        continue;
      }
      if (binding.verb === "propose") {
        const schema = schemaOf(binding.cue!);
        consumes.push(schema);
        if (!(votes.PROPOSAL_TYPE in spaceBindings)) {
          spaceBindings[votes.PROPOSAL_TYPE] = String(binding.vote);
        }
        actions.push(wire.cardAction(name, String(binding["description"] ?? ""), [schema], [votes.PROPOSAL_TYPE],
          "propose", binding.space));
        this.startPropose(bound, instance, method, binding);
        continue;
      }
      if (binding.verb === "take" || binding.verb === "notify") {
        const schema = schemaOf(binding.cue!);
        const produced = producedSchemas(binding.produces);
        consumes.push(schema);
        produces.push(...produced);
        if (binding.verb === "take") {
          spaceBindings[schema] = binding.space;
          this.startTake(bound, instance, method, binding);
        } else {
          this.startNotify(bound, instance, method, binding);
        }
        actions.push(wire.cardAction(name, String(binding["description"] ?? ""), [schema], produced,
          binding.verb, binding.space));
      } else if (binding.verb === "ballot") {
        this.startBallot(bound, instance, method, binding);
      } else if (binding.verb === "decision") {
        this.startDecision(bound, instance, method, binding);
      } else if (binding.verb === "estimate") {
        this.startEstimate(bound, instance, method, binding);
      }
    }
    if (this.publishCard) {
      bound.card = this.publish(spec, consumes, produces, spaceBindings, actions);
    }
    return bound;
  }

  // ----------------------------------------------------------------- card

  private publish(spec: Spec, consumes: string[], produces: string[], spaceBindings: Dict, actions: Dict[]): Dict {
    const now = this.peer.now();
    const issued = instantIso(now - (now % 1000));
    let localName = spec.name;
    let agentKey: Uint8Array | null = null;
    let certificate: Dict | null = null;
    if (this.agent !== null) {
      // The card names the certified agent: its own name, as the Java binder does.
      localName = this.agent.agentId.slice(this.agent.agentId.lastIndexOf("/") + 1);
      agentKey = this.agent.publicRaw;
      certificate = this.agent.certificateCovering(now);
    }
    const card = wire.agentCard(this.peer.group, this.peer.identity, localName, issued, this.cardTtl,
      spec.description, spec.goals, [...new Set(consumes)], [...new Set(produces)], {}, spaceBindings,
      agentKey, actions.length > 0 ? actions : null, certificate);
    this.peer.publishAd("AgentCard", card);
    return card;
  }

  // ---------------------------------------------------------------- loops

  /**
   * The dispatch of a method's return (AgentBinder.dispatch): nothing for
   * null; each element of an array on its own (the fork); a `Motion` proposed
   * in its vote space; a `Tagged` written with its tags; any other value
   * written as the next entry.
   */
  private writeResult(result: unknown, binding: Binding, fallback: Space, label = ""): string | null {
    if (result === null || result === undefined) {
      return null;
    }
    if (Array.isArray(result)) {
      for (const element of result) {
        if (Array.isArray(element)) {
          throw new Error(`${label} returned a fork inside a fork`);
        }
        this.writeResult(element, binding, fallback, label);
      }
      return null;
    }
    if (result instanceof Motion) {
      this.move(result, label);
      return null;
    }
    if (result instanceof Contribution) {
      if (this.aggregate === null) {
        throw new Error(`${label} returned a Contribution and the binder has no aggregate`);
      }
      this.aggregate.start(result.epochId, result.value, result.mode);
      return null;
    }
    const target = binding.resultSpace ? this.space(String(binding.resultSpace)) : fallback;
    if (result instanceof Tagged) {
      return target.write(result.value, (binding.resultLease as number | string) ?? "1h", result.tags);
    }
    return target.write(result as object, (binding.resultLease as number | string) ?? "1h");
  }

  private move(motion: Motion, label: string): void {
    const space = motion.space ?? this.voteSpace;
    if (!space) {
      throw new Error(`${label} returned a Motion naming no space and the binder has no voteSpace`);
    }
    votes.propose(this.peer, space, motion.proposalId, motion.question, motion.options, motion.quorum,
      durationMillis(motion.lease), this.agent, this.agentName);
  }

  private startTake(bound: Bound, instance: object, method: Method, binding: Binding): void {
    const space = this.space(binding.space);
    const template = new Template(binding.cue!, (binding.where as Dict) ?? {}, (binding.tags as Dict) ?? {});
    const loop = async () => {
      while (bound.running) {
        let taken;
        try {
          taken = await space.take(template, binding.lease as number | string, binding.pollTimeout as number | string);
        } catch {
          await sleep(500);
          continue;
        }
        if (taken === null) {
          continue;
        }
        let result: unknown;
        try {
          result = await TakeContext.run(taken, () => method.call(instance, taken.value as never));
        } catch {
          continue; // the lease lapses and the entry reappears for another worker
        }
        try {
          if (result === null || result === undefined || result instanceof Motion || result instanceof Contribution
              || Array.isArray(result) || binding.resultSpace) {
            // The take is finished first: a failed open or fork cannot make a
            // completed task reappear (ISSUE-Motion FR-4).
            taken.complete(null);
            this.writeResult(result, binding, space, `${bound.name}.${method.name}`);
          } else if (result instanceof Tagged) {
            taken.complete(result.value, (binding.resultLease as number | string) ?? "1h", result.tags);
          } else {
            taken.complete(result as object, (binding.resultLease as number | string) ?? "1h");
          }
        } catch {
          // the completion is retried by nobody: the lease lapses
        }
      }
    };
    bound.loops.push(loop());
  }

  private startNotify(bound: Bound, instance: object, method: Method, binding: Binding): void {
    const space = this.space(binding.space);
    const template = new Template(binding.cue!, (binding.where as Dict) ?? {}, (binding.tags as Dict) ?? {});
    const wanted = new Set(binding.on as EventKind[]);
    bound.subscriptions.push(space.watch(template, (event: SpaceEvent<unknown>) => {
      if (!wanted.has(event.kind)) {
        return;
      }
      // Off the delivery path, as the Java binder runs reactions.
      void Promise.resolve().then(async () => {
        try {
          this.writeResult(await method.call(instance, event.entry.value as never), binding, space);
        } catch {
          // a failed reaction writes nothing
        }
      });
    }));
  }

  private startBallot(bound: Bound, instance: object, method: Method, binding: Binding): void {
    const space = this.space(binding.space);
    const prefix = String(binding.prefix ?? "");
    const castFor = new Set<string>();
    const leaseMillis = durationMillis((binding.lease as number | string) ?? "1h");
    bound.subscriptions.push(space.watch(new Template<Dict>(votes.PROPOSAL_TYPE), (event) => {
      const proposal = event.entry.value;
      const pid = proposal["proposalId"];
      if (typeof pid !== "string" || !pid.startsWith(prefix) || castFor.has(pid)) {
        return;
      }
      castFor.add(pid);
      void Promise.resolve().then(async () => {
        let option: unknown;
        try {
          option = await method.call(instance, { proposalId: pid, question: String(proposal["question"] ?? ""),
            options: ((proposal["options"] as unknown[]) ?? []).map(String),
            quorum: Number(proposal["quorum"] ?? 0) } as never);
        } catch {
          return;
        }
        if (option !== null && option !== undefined) {
          votes.cast(this.peer, space.name, pid, String(option), leaseMillis, this.agent, this.agentName);
        }
      });
    }));
  }

  private startDecision(bound: Bound, instance: object, method: Method, binding: Binding): void {
    const space = this.space(binding.space);
    const prefix = String(binding.prefix ?? "");
    const fired = new Set<string>();
    const check = (pid: string) => {
      if (!pid.startsWith(prefix) || fired.has(pid)) {
        return;
      }
      const decided = votes.decision(this.peer.states, pid);
      if (decided === null) {
        return;
      }
      fired.add(pid);
      void Promise.resolve().then(async () => {
        try {
          this.writeResult(await method.call(instance, decided as never), binding, space);
        } catch {
          // a failed reaction writes nothing
        }
      });
    };
    const onEvent = (event: SpaceEvent<Dict>) => check(String(event.entry.value["proposalId"] ?? ""));
    bound.subscriptions.push(space.watch(new Template<Dict>(votes.BALLOT_TYPE), onEvent));
    bound.subscriptions.push(space.watch(new Template<Dict>(votes.PROPOSAL_TYPE), onEvent));
  }

  private startPropose(bound: Bound, instance: object, method: Method, binding: Binding): void {
    const cueSpace = this.space(binding.space);
    const template = new Template(binding.cue!, (binding.where as Dict) ?? {}, (binding.tags as Dict) ?? {});
    const keys = binding.keys as string[];
    const keyTag = binding.keyTag as string | undefined;
    const prefix = String(binding.prefix ?? "");
    const vote = String(binding.vote);
    const opened = new Set<string>();
    const label = `${bound.name}.${method.name}`;
    bound.subscriptions.push(cueSpace.watch(template, (event: SpaceEvent<unknown>) => {
      if (event.kind !== WRITTEN) {
        return;
      }
      let key: string | null = null;
      if (keyTag) {
        key = event.entry.tags[keyTag] === undefined ? null : String(event.entry.tags[keyTag]);
      } else if (keys.length > 0) {
        const payload = toPayload(event.entry.value as object);
        const parts = keys.map((k) => payload[k]);
        key = parts.some((p) => p === undefined || p === null) ? null : parts.map(String).join(":");
      }
      if ((keys.length > 0 || keyTag) && key === null) {
        return;
      }
      const proposalId = key === null ? null : prefix + key;
      if (proposalId !== null) {
        if (opened.has(proposalId)) {
          return;
        }
        opened.add(proposalId);
      }
      void Promise.resolve().then(async () => {
        try {
          if (proposalId !== null && votes.proposals(this.peer.states).has(proposalId)) {
            return;
          }
          const result = await method.call(instance, event.entry.value as never);
          if (result === null || result === undefined) {
            if (proposalId !== null) {
              opened.delete(proposalId);
            }
            return;
          }
          if (result instanceof Motion) {
            this.move(new Motion(result.proposalId, result.question, result.options, result.quorum,
              result.space ?? vote, result.lease), label);
            return;
          }
          if (proposalId === null) {
            throw new Error(`${label} names no key and returned no Motion`);
          }
          votes.propose(this.peer, vote, proposalId, String(result), binding.options as string[],
            Number(binding.quorum), durationMillis((binding.lease as number | string) ?? "1h"), this.agent, this.agentName);
        } catch {
          if (proposalId !== null) {
            opened.delete(proposalId);
          }
        }
      });
    }));
  }

  private startJoin(bound: Bound, instance: object, method: Method, binding: Binding): void {
    const joinSpace = this.space(binding.space);
    const parts = binding.parts as PartSpec[];
    const withinMillis = durationMillis(binding.within as number | string);
    const maxOpen = Number(binding.maxOpen ?? 10_000);
    type KeyState = { parts: Map<EntryType, unknown[]>; seen: Set<string>; since: number };
    const state = new Map<string, KeyState>();
    const fired = new Set<string>();
    const label = `${bound.name}.${method.name}`;
    const keyOf = (p: PartSpec, value: unknown, tags: Dict): string | null => {
      if (p.keyTag) {
        return tags[p.keyTag] === undefined ? null : String(tags[p.keyTag]);
      }
      const field = p.key ?? String(binding.key);
      const v = toPayload(value as object)[field];
      return v === undefined || v === null ? null : String(v);
    };
    const complete = (st: KeyState): boolean =>
      parts.every((p) => p.optional || (st.parts.get(p.type)?.length ?? 0) >= Math.max(1, p.atLeast ?? 1));
    const fire = (key: string) => {
      const st = state.get(key);
      state.delete(key);
      if (st === undefined) {
        return;
      }
      void Promise.resolve().then(async () => {
        try {
          this.writeResult(await method.call(instance, new Joined(key, st.parts) as never), binding, joinSpace, label);
        } catch {
          fired.delete(key); // the next part fires it again
        }
      });
    };
    for (const p of parts) {
      const space = p.space ? this.space(p.space) : joinSpace;
      const template = new Template(p.type, (p.where as Dict) ?? {}, (p.tags as Dict) ?? {});
      bound.subscriptions.push(space.watch(template, (event: SpaceEvent<unknown>) => {
        if (event.kind !== WRITTEN) {
          return;
        }
        const key = keyOf(p, event.entry.value, event.entry.tags);
        if (key === null || fired.has(key)) {
          return;
        }
        const now = this.peer.now();
        for (const [k, st] of [...state]) {
          if (now - st.since > withinMillis) {
            state.delete(k); // a key that never completed within the window is forgotten
          }
        }
        let st = state.get(key);
        if (st === undefined) {
          if (state.size >= maxOpen) {
            state.delete(state.keys().next().value!);
          }
          st = { parts: new Map(), seen: new Set(), since: now };
          state.set(key, st);
        }
        if (st.seen.has(event.entry.entryId)) {
          return;
        }
        st.seen.add(event.entry.entryId);
        let list = st.parts.get(p.type);
        if (list === undefined) {
          list = [];
          st.parts.set(p.type, list);
        }
        list.push(event.entry.value);
        if (complete(st)) {
          fired.add(key);
          fire(key);
        }
      }));
    }
  }

  private startEstimate(bound: Bound, instance: object, method: Method, binding: Binding): void {
    if (this.aggregate === null) {
      throw new Error(`${method.name} needs an aggregate: new Binder(peer, { aggregate })`);
    }
    const prefix = String(binding.epochs ?? "");
    const space = binding.resultSpace ? this.space(String(binding.resultSpace)) : null;
    const close = this.aggregate.onEstimate((id) => id.startsWith(prefix),
      Settle.after(Number(binding.ticks ?? 0), Number(binding.tolerance ?? 0)), (estimate) => {
        void Promise.resolve().then(async () => {
          try {
            const result = await method.call(instance, estimate as never);
            if (space !== null && result !== null && result !== undefined) {
              space.write(result as object, (binding.resultLease as number | string) ?? "1h");
            }
          } catch {
            // a failed reaction writes nothing
          }
        });
      });
    bound.subscriptions.push({ close });
  }
}

// (the estimate loop lives on the Binder below)

function producedSchemas(declared: EntryType | EntryType[] | undefined): string[] {
  if (declared === undefined) {
    return [];
  }
  return (Array.isArray(declared) ? declared : [declared]).map(schemaOf);
}

function bindings(instance: object): Array<[string, Method, Binding]> {
  const found: Array<[string, Method, Binding]> = [];
  let proto: object | null = Object.getPrototypeOf(instance);
  const seen = new Set<string>();
  while (proto !== null && proto !== Object.prototype) {
    for (const name of Object.getOwnPropertyNames(proto)) {
      if (name === "constructor" || seen.has(name)) {
        continue;
      }
      const value = (proto as { [k: string]: unknown })[name];
      const binding = typeof value === "function" ? (value as { [META]?: Binding })[META] : undefined;
      if (binding !== undefined) {
        seen.add(name);
        found.push([name, value as Method, binding]);
      }
    }
    proto = Object.getPrototypeOf(proto);
  }
  return found.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
}

const sleep = (millis: number) => new Promise((resolve) => setTimeout(resolve, millis));
