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
 * The `aspace:cap/ordered-log` voter in TypeScript (srad/agentspaces-js.md
 * JS-V-06, JS-V-10): Raft's core over the capability pipes, a port of the
 * Java `RaftLog` message for message and rule for rule (randomized election
 * timeouts in ticks, replication, commit on majority within the leader's
 * term, leader-hint forwarding of client submits, the fixed member set of
 * ASF-005, the per-sender client rate of JS-V-05), with one addition: the
 * term, the vote, and the entries are written to a {@link LogStore} before
 * any reply that depends on them leaves, so a restarted voter never votes
 * twice in a term and never loses an acknowledged entry.
 */

import { cbor, wire } from "@agentspaces/client";

type Dict = wire.Dict;
import { LogEntry, LogStore, MemoryLogStore } from "./store.js";

const { dumps, loads } = cbor;

/** The capability type URI (RaftLog.TYPE). */
export const TYPE = "aspace:cap/ordered-log";
/** The authorizer's operations the log asks about. */
export type Operation = "RAFT_VOTER" | "RAFT_CLIENT";
/** Client submits one non-member may make per second (RaftLog.CLIENT_SUBMITS_PER_SECOND). */
export const CLIENT_SUBMITS_PER_SECOND = 32;

export type Role = "FOLLOWER" | "CANDIDATE" | "LEADER";

/** Where frames go and come from: the capability pipes of one group. */
export interface RaftPipes {
  readonly peerId: string;
  send(to: string, payload: Uint8Array): void;
  onFrame(handler: (from: string, payload: Uint8Array) => void): void;
}

export type RaftOptions = {
  store?: LogStore;
  /** Epoch milliseconds, for the client budget and the advertised lease. */
  clock?: () => number;
  /** The tick period the driver runs at, in milliseconds (RaftLog.DEFAULT_TICK_PERIOD = 1 s). */
  tickMillis?: number;
  /** The election timeout in ticks is 5 + random(5): a seedable source for tests. */
  random?: () => number;
  /** Who may drive or submit (the profile's authorizer); the default admits the member set and any client. */
  authorizer?: (peer: string, operation: Operation) => boolean;
};

/** RaftMessages.Frame: exactly one field set, every other null, in Java record order. */
export function frame(kind: "requestVote" | "voteReply" | "appendEntries" | "appendReply" | "clientSubmit",
                      body: Dict): Uint8Array {
  const out: Dict = { requestVote: null, voteReply: null, appendEntries: null, appendReply: null, clientSubmit: null };
  out[kind] = body;
  return dumps(out);
}

function num(value: unknown): number {
  return typeof value === "bigint" ? Number(value) : typeof value === "number" ? value : Number.NaN;
}

export class RaftLog {
  readonly members: string[];
  private readonly store: LogStore;
  private readonly clock: () => number;
  private tickMillis: number;
  private readonly random: () => number;
  private readonly authorizer: (peer: string, operation: Operation) => boolean;
  private readonly applied: (command: Uint8Array, index: number) => void;

  private role: Role = "FOLLOWER";
  private term = 0;
  private votedFor: string | null = null;
  private log: LogEntry[] = [];
  private commitIndex = 0;
  private lastApplied = 0;
  private leaderHint: string | null = null;
  private electionElapsed = 0;
  private electionTimeout: number;
  private readonly votesGranted = new Set<string>();
  private readonly nextIndex = new Map<string, number>();
  private readonly matchIndex = new Map<string, number>();
  private readonly clientBudgets = new Map<string, [number, number]>();
  private loaded: Promise<void>;
  /** Writes in flight: a reply that depends on durable state awaits this chain. */
  private durable: Promise<void> = Promise.resolve();
  clientSubmits = 0;
  clientSubmitsRefused = 0;

  constructor(private readonly pipes: RaftPipes, members: string[],
              applied: (command: Uint8Array, index: number) => void, options: RaftOptions = {}) {
    if (!members.includes(pipes.peerId)) {
      throw new Error("member set must include self");
    }
    this.members = [...members];
    this.applied = applied;
    this.store = options.store ?? new MemoryLogStore();
    this.clock = options.clock ?? Date.now;
    this.tickMillis = options.tickMillis ?? 1000;
    this.random = options.random ?? Math.random;
    this.authorizer = options.authorizer ?? ((peer, operation) => operation === "RAFT_CLIENT"
      || this.members.includes(peer));
    this.electionTimeout = this.newElectionTimeout();
    this.loaded = this.store.load().then((state) => {
      this.term = state.term;
      this.votedFor = state.votedFor;
      this.log = state.entries;
    });
    pipes.onFrame((from, payload) => { void this.onFrame(from, payload); });
  }

  /** Resolves once the store has been read; the driver awaits it before the first tick. */
  ready(): Promise<void> {
    return this.loaded;
  }

  private suspended = false;

  /**
   * Releases this member's voter duty (srad/agentspaces-js.md JS-R-06): it steps down to a
   * follower, ignores frames and ticks, and so counts as absent while its host's tick drifts;
   * the others elect around it. {@link resume} rejoins with the durable term and vote intact.
   */
  suspend(): void {
    this.suspended = true;
    this.role = "FOLLOWER";
    this.leaderHint = null;
  }

  resume(): void {
    this.suspended = false;
    this.electionElapsed = 0;
  }

  isSuspended(): boolean {
    return this.suspended;
  }

  get self(): string {
    return this.pipes.peerId;
  }

  currentTerm(): number {
    return this.term;
  }

  isLeader(): boolean {
    return this.role === "LEADER";
  }

  currentRole(): Role {
    return this.role;
  }

  leader(): string | null {
    return this.role === "LEADER" ? this.self : this.leaderHint;
  }

  committed(): number {
    return this.commitIndex;
  }

  logLength(): number {
    return this.log.length;
  }

  /** The cadence the driver really runs at (RaftLog.driverCadence), for the advertised lease. */
  driverCadence(tickMillis: number): void {
    if (!(tickMillis > 0)) {
      throw new Error(`cadence must be positive: ${tickMillis}`);
    }
    this.tickMillis = tickMillis;
  }

  /** RaftLog.describe: the capability advertisement's parameters (the host adds the envelope fields). */
  parameters(): { [key: string]: string } {
    const parameters: { [key: string]: string } = { members: String(this.members.length),
      role: this.role.toLowerCase(), term: String(this.term) };
    if (this.role === "LEADER") {
      parameters["leaseUntil"] = new Date(this.clock() + this.tickMillis * this.electionTimeout).toISOString()
        .replace(/\.000Z$/, "Z");
    }
    return parameters;
  }

  /** RaftLog.submit: appends when leading, forwards under the leader hint, or returns false. */
  async submit(command: Uint8Array): Promise<boolean> {
    if (this.role === "LEADER") {
      const entry: LogEntry = { term: this.term, command };
      this.log.push(entry);
      await this.appendDurably(this.log.length, [entry]); // durable before any append carries it
      this.advanceCommit();
      this.broadcastAppends();
      this.applyCommitted();
      return true;
    }
    if (this.leaderHint !== null) {
      this.send(this.leaderHint, frame("clientSubmit", { command }));
      return true;
    }
    return false;
  }

  /** One tick of the driver: heartbeats when leading, the election timer otherwise. */
  async tick(): Promise<void> {
    await this.loaded;
    if (this.suspended) {
      return;
    }
    if (this.role === "LEADER") {
      for (const member of this.members) {
        if (member !== this.self) {
          this.send(member, this.appendFor(member));
        }
      }
    } else {
      this.electionElapsed++;
      if (this.electionElapsed >= this.electionTimeout) {
        await this.startElection();
      }
    }
    this.applyCommitted();
  }

  private async onFrame(from: string, payload: Uint8Array): Promise<void> {
    await this.loaded;
    if (this.suspended) {
      return; // absent, as far as the others can tell
    }
    let decoded: Dict;
    try {
      decoded = loads(payload) as Dict;
    } catch {
      return;
    }
    if (typeof decoded !== "object" || decoded === null) {
      return;
    }
    if (!this.members.includes(from)) {
      // ASF-005 and JS-V-05: a non-member may only submit, when permitted, within the rate.
      const submit = decoded["clientSubmit"] as Dict | null;
      const command = submit?.["command"];
      if (!(command instanceof Uint8Array) || !this.authorizer(from, "RAFT_CLIENT") || !this.clientBudgetAdmits(from)) {
        this.clientSubmitsRefused++;
        return;
      }
      this.clientSubmits++;
      await this.submit(command);
      return;
    }
    if (!this.authorizer(from, "RAFT_VOTER")) {
      return;
    }
    if (decoded["requestVote"]) {
      await this.onRequestVote(from, decoded["requestVote"] as Dict);
    } else if (decoded["voteReply"]) {
      await this.onVoteReply(from, decoded["voteReply"] as Dict);
    } else if (decoded["appendEntries"]) {
      await this.onAppendEntries(from, decoded["appendEntries"] as Dict);
    } else if (decoded["appendReply"]) {
      await this.onAppendReply(from, decoded["appendReply"] as Dict);
    } else if (decoded["clientSubmit"] && (decoded["clientSubmit"] as Dict)["command"] instanceof Uint8Array) {
      await this.submit((decoded["clientSubmit"] as Dict)["command"] as Uint8Array);
    }
    this.applyCommitted();
  }

  private clientBudgetAdmits(from: string): boolean {
    const second = Math.floor(this.clock() / 1000);
    let bucket = this.clientBudgets.get(from);
    if (bucket === undefined || bucket[0] !== second) {
      bucket = [second, 0];
      this.clientBudgets.set(from, bucket);
    }
    if (bucket[1] >= CLIENT_SUBMITS_PER_SECOND) {
      return false;
    }
    bucket[1]++;
    if (this.clientBudgets.size > 4096) {
      for (const [peer, b] of this.clientBudgets) {
        if (b[0] < second - 60) {
          this.clientBudgets.delete(peer);
        }
      }
    }
    return true;
  }

  private async onRequestVote(from: string, request: Dict): Promise<void> {
    const requestTerm = num(request["term"]);
    if (requestTerm > this.term) {
      await this.becomeFollower(requestTerm);
    }
    const lastLogTerm = this.lastLogTerm();
    const upToDate = num(request["lastLogTerm"]) > lastLogTerm
      || (num(request["lastLogTerm"]) === lastLogTerm && num(request["lastLogIndex"]) >= this.log.length);
    const candidate = String(request["candidate"]);
    const grant = requestTerm === this.term && upToDate && (this.votedFor === null || this.votedFor === candidate);
    if (grant) {
      this.votedFor = candidate;
      this.electionElapsed = 0;
      await this.saveTermVoteDurably(); // the vote is durable before the reply leaves
    }
    this.send(from, frame("voteReply", { term: this.term, granted: grant }));
  }

  private async onVoteReply(from: string, reply: Dict): Promise<void> {
    const replyTerm = num(reply["term"]);
    if (replyTerm > this.term) {
      await this.becomeFollower(replyTerm);
      return;
    }
    if (this.role !== "CANDIDATE" || replyTerm !== this.term || reply["granted"] !== true) {
      return;
    }
    if (this.votesGranted.has(from)) {
      return;
    }
    this.votesGranted.add(from);
    if (this.votesGranted.size > this.members.length / 2) {
      this.role = "LEADER";
      this.leaderHint = this.self;
      for (const member of this.members) {
        this.nextIndex.set(member, this.log.length + 1);
        this.matchIndex.set(member, 0);
      }
      this.matchIndex.set(this.self, this.log.length);
      for (const member of this.members) {
        if (member !== this.self) {
          this.send(member, this.appendFor(member));
        }
      }
    }
  }

  private async onAppendEntries(from: string, append: Dict): Promise<void> {
    const appendTerm = num(append["term"]);
    if (appendTerm > this.term || (appendTerm === this.term && this.role !== "FOLLOWER")) {
      await this.becomeFollower(appendTerm);
    }
    if (appendTerm < this.term) {
      this.send(from, frame("appendReply", { term: this.term, follower: this.self, success: false, matchIndex: 0 }));
      return;
    }
    this.leaderHint = String(append["leader"]);
    this.electionElapsed = 0;
    const prevLogIndex = num(append["prevLogIndex"]);
    const prevMatches = prevLogIndex === 0
      || (prevLogIndex <= this.log.length && this.log[prevLogIndex - 1].term === num(append["prevLogTerm"]));
    if (!prevMatches) {
      this.send(from, frame("appendReply", { term: this.term, follower: this.self, success: false, matchIndex: 0 }));
      return;
    }
    let index = prevLogIndex;
    const entries = (append["entries"] as Dict[] | undefined) ?? [];
    let firstChange = -1;
    const incoming: LogEntry[] = [];
    for (const raw of entries) {
      index++;
      const entry: LogEntry = { term: num(raw["term"]), command: raw["command"] as Uint8Array };
      if (index <= this.log.length) {
        if (this.log[index - 1].term !== entry.term) {
          this.log.length = index - 1;
          this.log.push(entry);
          if (firstChange < 0) {
            firstChange = index;
          }
          incoming.push(entry);
        }
      } else {
        this.log.push(entry);
        if (firstChange < 0) {
          firstChange = index;
        }
        incoming.push(entry);
      }
    }
    if (firstChange > 0) {
      await this.appendDurably(firstChange, this.log.slice(firstChange - 1)); // durable before the ack
    }
    this.commitIndex = Math.max(this.commitIndex, Math.min(num(append["leaderCommit"]), this.log.length));
    this.send(from, frame("appendReply", { term: this.term, follower: this.self, success: true, matchIndex: index }));
  }

  private async onAppendReply(from: string, reply: Dict): Promise<void> {
    const replyTerm = num(reply["term"]);
    if (replyTerm > this.term) {
      await this.becomeFollower(replyTerm);
      return;
    }
    if (this.role !== "LEADER" || replyTerm !== this.term) {
      return;
    }
    // The follower identity is the authenticated frame sender; the reply's own field is payload (ASF-005).
    if (reply["success"] === true) {
      this.matchIndex.set(from, num(reply["matchIndex"]));
      this.nextIndex.set(from, num(reply["matchIndex"]) + 1);
      this.advanceCommit();
    } else {
      this.nextIndex.set(from, Math.max(1, (this.nextIndex.get(from) ?? 1) - 1));
    }
  }

  private async startElection(): Promise<void> {
    this.role = "CANDIDATE";
    this.term++;
    this.votedFor = this.self;
    this.votesGranted.clear();
    this.votesGranted.add(this.self);
    this.electionElapsed = 0;
    this.electionTimeout = this.newElectionTimeout();
    await this.saveTermVoteDurably(); // the candidacy is durable before any request leaves
    const request = frame("requestVote", { term: this.term, candidate: this.self, lastLogIndex: this.log.length,
      lastLogTerm: this.lastLogTerm() });
    for (const member of this.members) {
      if (member !== this.self) {
        this.send(member, request);
      }
    }
  }

  private async becomeFollower(newTerm: number): Promise<void> {
    let changed = false;
    if (newTerm > this.term) {
      this.term = newTerm;
      this.votedFor = null;
      changed = true;
    }
    this.role = "FOLLOWER";
    this.votesGranted.clear();
    this.electionElapsed = 0;
    this.electionTimeout = this.newElectionTimeout();
    if (changed) {
      await this.saveTermVoteDurably();
    }
  }

  private appendFor(member: string): Uint8Array {
    const next = this.nextIndex.get(member) ?? this.log.length + 1;
    const prevIndex = next - 1;
    const prevTerm = prevIndex === 0 ? 0 : this.log[prevIndex - 1].term;
    const entries = this.log.slice(prevIndex).map((e) => ({ term: e.term, command: e.command }));
    return frame("appendEntries", { term: this.term, leader: this.self, prevLogIndex: prevIndex, prevLogTerm: prevTerm,
      entries, leaderCommit: this.commitIndex });
  }

  private broadcastAppends(): void {
    if (this.role !== "LEADER") {
      return;
    }
    for (const member of this.members) {
      if (member !== this.self) {
        this.send(member, this.appendFor(member));
      }
    }
  }

  private advanceCommit(): void {
    this.matchIndex.set(this.self, this.log.length);
    for (let candidate = this.log.length; candidate > this.commitIndex; candidate--) {
      if (this.log[candidate - 1].term !== this.term) {
        continue;
      }
      let votes = 0;
      for (const member of this.members) {
        if ((this.matchIndex.get(member) ?? 0) >= candidate) {
          votes++;
        }
      }
      if (votes > this.members.length / 2) {
        this.commitIndex = candidate;
        break;
      }
    }
  }

  private applyCommitted(): void {
    while (this.lastApplied < this.commitIndex) {
      this.lastApplied++;
      const entry = this.log[this.lastApplied - 1];
      try {
        this.applied(entry.command, this.lastApplied);
      } catch {
        // a listener's failure never stops the log
      }
    }
  }

  private lastLogTerm(): number {
    return this.log.length === 0 ? 0 : this.log[this.log.length - 1].term;
  }

  private newElectionTimeout(): number {
    return 5 + Math.floor(this.random() * 5);
  }

  private send(to: string, payload: Uint8Array): void {
    this.pipes.send(to, payload);
  }

  /** Chains a durable write; a write that fails leaves the log a follower with the write's state unchanged. */
  private saveTermVoteDurably(): Promise<void> {
    const term = this.term;
    const votedFor = this.votedFor;
    this.durable = this.durable.then(() => this.store.saveTermVote(term, votedFor));
    return this.durable;
  }

  private appendDurably(fromIndex: number, entries: LogEntry[]): Promise<void> {
    this.durable = this.durable.then(() => this.store.append(fromIndex, entries));
    return this.durable;
  }
}

/** The wire name of a frame kind, for diagnostics. */
export function kindOf(payload: Uint8Array): string | null {
  try {
    const decoded = loads(payload) as Dict;
    for (const kind of ["requestVote", "voteReply", "appendEntries", "appendReply", "clientSubmit"]) {
      if (decoded[kind]) {
        return kind;
      }
    }
  } catch {
    // not a frame
  }
  return null;
}

