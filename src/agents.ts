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
 *
 *       @orderedTake(Payment, "payments", { lease: "30s" })
 *       confirm(payment: Payment): Receipt { return new Receipt(payment.id); }   // completed once, fleet-wide
 *
 *       @spaceJoin("intake", "claimId", [part(Fraud), part(Coverage)], { mode: "LEASED" })
 *       assemble(j: Joined): Assessment { return new Assessment(j.key, j.get(Fraud).score); }
 *
 *       @spaceReduce(Payment, Balance, "ledger", { key: "account" })
 *       apply(balance: Balance | null, payment: Payment): Balance { return Balance.plus(balance, payment); }
 *     }
 *
 *     const bound = new Binder(peer, { agent: identity.renewingSubordinate("ts-worker", "PT24H") }).bind(new Researcher());
 *     await bound.close();
 *
 * The return value is the next entry (`null` writes nothing, or abstains), a
 * `Tagged` written with its tags, an array of entries (the fork, each written
 * on its own), or a `Motion` opening a vote once per proposal id. `@propose`
 * opens a vote from a cue once per key; `@spaceJoin` fires once per key when
 * every required part is present, in memory (LOCAL), through a leased
 * `JoinTicket` (LEASED), or through a ticket the ordered log decides
 * (ORDERED); `@orderedTake` is a take whose claim the ordered log commits, so
 * the entry completes at most once fleet-wide; `@spaceReduce` folds elements
 * per key into an accumulator entry beside them. A take completes in its
 * space with the result, where a remote caller awaits it, or in
 * `resultSpace`; a notify fires once per entry; a ballot casts once per
 * proposal; a decision fires once per proposal when the quorum closes; the
 * AgentCard, with the declared actions, is published on bind. A verb the
 * host's residency cannot carry (JS-R-01) is refused at bind time, naming the
 * verb, the residency, and the package that supplies a host that can.
 */

import type { OrderedLog } from "./capabilities/ordered.js";
import { AgentIdentity, instantIso } from "./identity.js";
import { CommittedSource, JoinBinding, JoinMode, Joined, ResolvedPart, pause, takenOf } from "./join.js";
import type { Peer } from "./peer.js";
import { Residency, platform, requireResidency } from "./platform.js";
import { ReduceBinding, ReduceMode } from "./reduce.js";
import { COMPLETED, Class, Contribution, EntryType, EventKind, Motion, Space, SpaceEvent, TakeContext, Tagged, Template,
  Taken, WRITTEN, durationMillis, fromPayload, schemaOf, toPayload } from "./space.js";
import { Aggregate, Settle } from "./capabilities/aggregate.js";
import * as votes from "./vote.js";
import * as wire from "./wire.js";
import type { Dict } from "./wire.js";

export type { Decision, Proposal } from "./vote.js";
export { Joined } from "./join.js";
export type { JoinMode } from "./join.js";
export type { ReduceMode } from "./reduce.js";

// -------------------------------------------------------------- decorators

const META = Symbol.for("agentspaces.binding");
const SPEC = Symbol.for("agentspaces.spec");

type Verb = "take" | "orderedTake" | "notify" | "bid" | "ballot" | "decision" | "estimate" | "propose" | "join"
  | "reduce";
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

/**
 * The exactly-once worker (`@OrderedTake`): `@spaceTake`'s contract, with
 * the take routed through the ordered log's Raft client instead of the
 * space's own claim race, so the log's commit order decides every take
 * identically on every member and each entry is completed at most once,
 * fleet-wide. A take lost to a leader election is resubmitted on the next
 * poll. Needs a `new Binder(peer, { ordered: new OrderedLog(new Pipes(peer)) })`;
 * an attested agent's claims are signed with its own key, as its completions are.
 */
export function orderedTake(cue: EntryType, space: string, options: TakeOptions = {}): MethodDecorator {
  return mark({ verb: "orderedTake", cue, space, lease: options.lease ?? "30s", pollTimeout: options.pollTimeout ?? "2s",
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

export type JoinOptions = { mode?: JoinMode; name?: string; within?: number | string; resultSpace?: string;
  resultLease?: number | string; maxOpen?: number; produces?: EntryType; description?: string;
  /** The part subscriptions' lease, renewed at half-lease while bound. */
  lease?: number | string;
  /** LEASED and ORDERED: the ticket's write lease. */
  ticketLease?: number | string;
  /** LEASED and ORDERED: the ticket's take lease; the firing must complete within it. */
  takeLease?: number | string;
  /** LEASED and ORDERED: how long one poll for a ticket waits. */
  pollTimeout?: number | string };

/**
 * The fan-in (`@SpaceJoin`): once per key, when every required part is
 * readable, the method receives a `Joined` and its return is dispatched as a
 * take's is. A key is forgotten after `within` if it never completes, and
 * found again in the space when its last part arrives. `mode` is the "once"
 * rule: LOCAL keeps an in-memory set (once per joiner); LEASED writes a
 * `JoinTicket` per key and takes it under a lease (once per lease race per
 * ticket, at least once fleet-wide; needs a resident, service, or cell
 * host); ORDERED takes the ticket through the ordered log, where the first
 * committed ticket claim per key fires (needs `new Binder(peer, { ordered })`).
 */
export function spaceJoin(space: string, key: string, parts: PartSpec[], options: JoinOptions = {}): MethodDecorator {
  const mode = options.mode ?? "LOCAL";
  if (mode !== "LOCAL" && mode !== "LEASED" && mode !== "ORDERED") {
    throw new Error(`@spaceJoin mode must be LOCAL, LEASED, or ORDERED: ${String(mode)}`);
  }
  for (const p of parts) {
    if (p.key && p.keyTag) {
      throw new Error(`part ${schemaOf(p.type)} names both key and keyTag; choose one`);
    }
  }
  return mark({ verb: "join", space, key, parts, mode, name: options.name ?? "", within: options.within ?? "1h",
    resultSpace: options.resultSpace, resultLease: options.resultLease ?? "1h", maxOpen: options.maxOpen ?? 10_000,
    produces: options.produces, description: options.description ?? "", lease: options.lease ?? "1h",
    ticketLease: options.ticketLease ?? "10m", takeLease: options.takeLease ?? "30s",
    pollTimeout: options.pollTimeout ?? "1s" });
}

export type ReduceOptions = { name?: string; key?: string; keyTag?: string; where?: { [k: string]: unknown };
  tags?: { [k: string]: unknown }; mode?: ReduceMode; lease?: number | string; pollTimeout?: number | string;
  accumulatorLease?: number | string; subscriptionLease?: number | string; maxOpen?: number;
  produces?: EntryType | EntryType[]; description?: string };

/**
 * The persistent accumulator (`@SpaceReduce`): a fold over an unbounded
 * stream of elements per key, whose state is an entry in the elements'
 * space. The method takes the current accumulator (`null` on a key's first
 * step) and one element and returns the new accumulator; the binder takes
 * the element under a lease, invokes the method, and completes the element
 * with the new accumulator as the result, in one atomic step, so an element
 * is never folded twice. The return is the accumulator, a `Tagged`
 * accumulator, or an array holding exactly one accumulator and any side
 * outputs, written after it; `null` consumes the element and leaves the
 * accumulator as it was. `key` names the element's field carrying the key,
 * `keyTag` its tag; neither folds every element into one accumulator. The
 * accumulator's lease is the key's idle timeout. Needs a resident, service,
 * or cell host; ORDERED needs `new Binder(peer, { ordered })`.
 */
export function spaceReduce(element: EntryType, accumulator: EntryType, space: string,
                            options: ReduceOptions = {}): MethodDecorator {
  if (options.key && options.keyTag) {
    throw new Error("@spaceReduce names both key and keyTag; choose one");
  }
  const mode = options.mode ?? "LEASED";
  if (mode !== "LEASED" && mode !== "ORDERED") {
    throw new Error(`@spaceReduce mode must be LEASED or ORDERED: ${String(mode)}`);
  }
  return mark({ verb: "reduce", cue: element, space, accumulator, name: options.name ?? "", key: options.key ?? "",
    keyTag: options.keyTag ?? "", where: options.where, tags: options.tags, mode, lease: options.lease ?? "30s",
    pollTimeout: options.pollTimeout ?? "1s", accumulatorLease: options.accumulatorLease ?? "24h",
    subscriptionLease: options.subscriptionLease ?? "1h", maxOpen: options.maxOpen ?? 10_000,
    produces: options.produces, description: options.description ?? "" });
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

/** Reacts once when a proposal's quorum closes it. */
export function onDecision(space: string, options: { prefix?: string; resultSpace?: string;
  resultLease?: number | string; produces?: EntryType } = {}): MethodDecorator {
  return mark({ verb: "decision", space, prefix: options.prefix ?? "", resultSpace: options.resultSpace,
    resultLease: options.resultLease ?? "1h", produces: options.produces });
}

// ------------------------------------------------------------------ binder

/** A bound agent: its loops, watches, and join and reduce bindings, closed together. */
export class Bound {
  card: Dict | null = null;
  running = true;
  readonly loops: Promise<void>[] = [];
  readonly subscriptions: Array<{ close(): void }> = [];
  /** The join and reduce runtimes, by the name their tickets carry. */
  readonly bindings: Array<JoinBinding | ReduceBinding> = [];

  constructor(readonly name: string) {}

  async close(): Promise<void> {
    this.running = false;
    for (const s of this.subscriptions) {
      s.close();
    }
    await Promise.allSettled(this.bindings.map((b) => b.close()));
    await Promise.allSettled(this.loops);
  }
}

export type BinderOptions = { agent?: AgentIdentity | null; agentName?: string; publishCard?: boolean; cardTtl?: string;
  aggregate?: Aggregate | null; voteSpace?: string | null;
  /** The ordered log's Raft client, for `@orderedTake` and the ORDERED join and reduce modes. */
  ordered?: OrderedLog | null;
  /**
   * On a voter host, the coordinator's committed-claim hook (`OrderedLogHost.onCommitted`), so
   * ORDERED joins and reduces judge the first ticket per key in log order as Java's do.
   */
  committed?: CommittedSource | null;
  /** The residency of the running host (§3.6); `platform().residency` when the host declares none. */
  residency?: Residency };

/**
 * Runs decorated agents over one peer. `agent` (an `AgentIdentity`) makes
 * every record the agent's own attested one; the peer-signed `agentName`
 * otherwise. `publishCard` sends the AgentCard on bind. `ordered` is the
 * Raft client the ordered verbs claim through; `residency` is what the host
 * declares, judged at bind time against each verb (JS-R-01).
 */
export class Binder {
  readonly agent: AgentIdentity | null;
  readonly agentName: string;
  readonly publishCard: boolean;
  readonly cardTtl: string;
  readonly aggregate: Aggregate | null;
  /** Where a `Motion` naming no space is proposed. */
  readonly voteSpace: string | null;
  readonly ordered: OrderedLog | null;
  readonly committed: CommittedSource | null;
  readonly residency: Residency;
  private readonly spaces = new Map<string, Space>();

  constructor(readonly peer: Peer, options: BinderOptions = {}) {
    this.agent = options.agent ?? null;
    this.agentName = options.agentName ?? "typescript";
    this.publishCard = options.publishCard ?? true;
    this.cardTtl = options.cardTtl ?? "PT10M";
    this.aggregate = options.aggregate ?? null;
    this.voteSpace = options.voteSpace ?? null;
    this.ordered = options.ordered ?? null;
    this.committed = options.committed ?? null;
    this.residency = options.residency ?? platform().residency;
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
    // Refusals first (JS-R-01): a verb this host cannot carry, or one wired
    // without what it needs, fails before any loop starts.
    for (const [name, , binding] of methods) {
      this.judge(bound, name, binding);
    }
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
    try {
      this.start(bound, instance, methods, consumes, produces, spaceBindings, actions);
    } catch (e) {
      void bound.close(); // a refusal leaves nothing of the agent running
      throw e;
    }
    if (this.publishCard) {
      bound.card = this.publish(spec, consumes, produces, spaceBindings, actions);
    }
    return bound;
  }

  private start(bound: Bound, instance: object, methods: Array<[string, Method, Binding]>, consumes: string[],
                produces: string[], spaceBindings: Dict, actions: Dict[]): void {
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
      if (binding.verb === "reduce") {
        const schema = schemaOf(binding.cue!);
        const produced = [schemaOf(binding.accumulator as EntryType), ...producedSchemas(binding.produces)];
        consumes.push(schema);
        produces.push(...produced);
        actions.push(wire.cardAction(name, String(binding["description"] ?? ""), [schema], [...new Set(produced)],
          "reduce", binding.space));
        this.startReduce(bound, instance, method, binding);
        continue;
      }
      if (binding.verb === "orderedTake") {
        const schema = schemaOf(binding.cue!);
        const produced = producedSchemas(binding.produces);
        consumes.push(schema);
        produces.push(...produced);
        spaceBindings[schema] = binding.space;
        actions.push(wire.cardAction(name, String(binding["description"] ?? ""), [schema], produced,
          "ordered-take", binding.space));
        this.startOrderedTake(bound, instance, method, binding);
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
  }

  /**
   * The bind-time refusals of the ordered and fleet-wide verbs: the residency
   * table of §3.6 (JS-R-01), the ordered log a verb claims through, and the
   * attributes the Java binder rejects.
   */
  private judge(bound: Bound, name: string, binding: Binding): void {
    const label = `${bound.name}.${name}`;
    if (binding.verb === "orderedTake") {
      this.requireOrdered("@orderedTake", label);
    } else if (binding.verb === "join") {
      const mode = binding.mode as JoinMode;
      if (mode !== "LOCAL") {
        requireResidency(this.residency, "keeper", `@spaceJoin ${mode} at ${label}`);
      }
      if (mode === "ORDERED") {
        this.requireOrdered("@spaceJoin ORDERED", label);
      }
    } else if (binding.verb === "reduce") {
      const mode = binding.mode as ReduceMode;
      requireResidency(this.residency, "keeper", `@spaceReduce ${mode} at ${label}`);
      if (mode === "ORDERED") {
        this.requireOrdered("@spaceReduce ORDERED", label);
      }
      if (durationMillis(binding.accumulatorLease as number | string) < durationMillis(binding.lease as number | string)) {
        throw new Error(`@spaceReduce at ${label}: accumulatorLease ${String(binding.accumulatorLease)} is shorter`
          + ` than the take lease ${String(binding.lease)}`);
      }
    }
  }

  private requireOrdered(what: string, label: string): OrderedLog {
    if (this.ordered === null) {
      throw new Error(`${what} at ${label} needs an ordered log: new Binder(peer, { ordered: new OrderedLog(`
        + `new Pipes(peer)) }), with a log advertised in the group`);
    }
    return this.ordered;
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
        await this.finishTake(bound, instance, method, binding, space, taken);
      }
    };
    bound.loops.push(loop());
  }

  /** The action and the completion of one taken entry, shared by `@spaceTake` and `@orderedTake`. */
  private async finishTake(bound: Bound, instance: object, method: Method, binding: Binding, space: Space,
                           taken: Taken<unknown>): Promise<void> {
    let result: unknown;
    try {
      result = await TakeContext.run(taken, () => method.call(instance, taken.value as never));
    } catch {
      return; // the lease lapses and the entry reappears for another worker
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

  /**
   * The `@orderedTake` loop (AgentBinder.startOrderedTakeLoop): `@spaceTake`'s
   * loop with the claim submitted through the ordered log and adopted only
   * when the log committed this holder's claim for the generation it asked
   * for (OrderedTakes.take); the holder signs the claim with its own key when
   * the binder runs as an attested agent.
   */
  private startOrderedTake(bound: Bound, instance: object, method: Method, binding: Binding): void {
    const ordered = this.requireOrdered("@orderedTake", `${bound.name}.${method.name}`);
    const space = this.space(binding.space);
    const template = new Template(binding.cue!, (binding.where as Dict) ?? {}, (binding.tags as Dict) ?? {});
    const leaseMillis = durationMillis(binding.lease as number | string);
    const pollMillis = durationMillis(binding.pollTimeout as number | string);
    const loop = async () => {
      while (bound.running) {
        let entryId: string | null;
        try {
          entryId = await ordered.take(space.name, template.schema, space.agentName, leaseMillis, pollMillis,
            space.agent, (payload, tags) => template.matches(payload, tags));
        } catch {
          await pause(this.peer, 200); // a leader election in flight: the next poll resubmits
          continue;
        }
        if (entryId === null) {
          continue;
        }
        // The crash idiom, exactly once: no complete, the take lease lapses,
        // and the log's next committed claim reassigns the entry.
        await this.finishTake(bound, instance, method, binding, space, takenOf(space, entryId, template, leaseMillis));
      }
    };
    bound.loops.push(loop());
  }

  private startNotify(bound: Bound, instance: object, method: Method, binding: Binding): void {
    const space = this.space(binding.space);
    const template = new Template(binding.cue!, (binding.where as Dict) ?? {}, (binding.tags as Dict) ?? {});
    const wanted = new Set(binding.on as EventKind[]);
    // A leased subscription the binder renews at half-lease (JS-V-01), as the Java binder does.
    const notifyLease = durationMillis((binding.lease as number | string) ?? "1h");
    const subscription = space.notify(template, (event: SpaceEvent<unknown>) => {
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
    }, notifyLease);
    const renewal = this.peer.every(Math.max(250, Math.floor(notifyLease / 2)), () => subscription.renew());
    subscription.on("close", () => renewal.stop());
    bound.subscriptions.push(subscription);
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

  /** Resolves a `@spaceJoin` and starts its binding (AgentBinder.startJoin). */
  private startJoin(bound: Bound, instance: object, method: Method, binding: Binding): void {
    const joinSpace = this.space(binding.space);
    const label = `${bound.name}.${method.name}`;
    const mode = binding.mode as JoinMode;
    const name = String(binding.name ?? "") || label;
    this.requireUniqueName(bound, name, "@spaceJoin", label);
    const parts: ResolvedPart[] = (binding.parts as PartSpec[]).map((p) => ({
      type: p.type, space: p.space ? this.space(p.space) : joinSpace, where: (p.where as Dict) ?? {},
      tags: (p.tags as Dict) ?? {}, keyField: p.keyTag ? null : (p.key ?? String(binding.key)),
      keyTag: p.keyTag ?? null, optional: p.optional ?? false, atLeast: Math.max(1, p.atLeast ?? 1) }));
    const joined = new JoinBinding({ name, mode, space: joinSpace, parts,
      withinMillis: durationMillis(binding.within as number | string), maxOpen: Number(binding.maxOpen ?? 10_000),
      subscriptionLeaseMillis: durationMillis((binding.lease as number | string) ?? "1h"),
      ticketLeaseMillis: durationMillis((binding.ticketLease as number | string) ?? "10m"),
      takeLeaseMillis: durationMillis((binding.takeLease as number | string) ?? "30s"),
      pollTimeoutMillis: durationMillis((binding.pollTimeout as number | string) ?? "1s"),
      ordered: mode === "ORDERED" ? this.ordered : null, committed: mode === "ORDERED" ? this.committed : null },
    (bag: Joined) => method.call(instance, bag as never),
    (result: unknown) => this.writeResult(result, binding, joinSpace, label));
    joined.start();
    bound.bindings.push(joined);
  }

  /** Resolves a `@spaceReduce` and starts its binding (AgentBinder.startReduce). */
  private startReduce(bound: Bound, instance: object, method: Method, binding: Binding): void {
    const space = this.space(binding.space);
    const label = `${bound.name}.${method.name}`;
    const mode = binding.mode as ReduceMode;
    const name = String(binding.name ?? "") || label;
    this.requireUniqueName(bound, name, "@spaceReduce", label);
    const accumulatorLease = (binding.accumulatorLease as number | string) ?? "24h";
    const reduce = new ReduceBinding({ name, mode, space, elementType: binding.cue!,
      elementWhere: (binding.where as Dict) ?? {}, elementTags: (binding.tags as Dict) ?? {},
      accumulatorType: binding.accumulator as EntryType, keyField: String(binding.key ?? "") || null,
      keyTag: String(binding.keyTag ?? "") || null,
      takeLeaseMillis: durationMillis((binding.lease as number | string) ?? "30s"),
      pollTimeoutMillis: durationMillis((binding.pollTimeout as number | string) ?? "1s"),
      accumulatorLeaseMillis: durationMillis(accumulatorLease),
      subscriptionLeaseMillis: durationMillis((binding.subscriptionLease as number | string) ?? "1h"),
      maxOpen: Number(binding.maxOpen ?? 10_000), ordered: mode === "ORDERED" ? this.ordered : null,
      committed: mode === "ORDERED" ? this.committed : null },
    (accumulator: unknown, element: unknown) => method.call(instance, accumulator as never, element as never),
    (other: unknown) => this.writeResult(other, { ...binding, resultSpace: undefined, resultLease: accumulatorLease },
      space, label));
    reduce.start();
    bound.bindings.push(reduce);
  }

  /** A join and a reduce of one name on one agent would share tickets: refused, as the Java binder refuses it. */
  private requireUniqueName(bound: Bound, name: string, what: string, label: string): void {
    if (bound.bindings.some((b) => b.name === name)) {
      throw new Error(`${what} at ${label} is named '${name}' like another join or reduce on this agent;`
        + " tickets would collide, name one of them");
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
