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
import { wire } from "@agentspaces/client";
type Dict = wire.Dict;
import { LogStore } from "./store.js";
/** The capability type URI (RaftLog.TYPE). */
export declare const TYPE = "aspace:cap/ordered-log";
/** The authorizer's operations the log asks about. */
export type Operation = "RAFT_VOTER" | "RAFT_CLIENT";
/** Client submits one non-member may make per second (RaftLog.CLIENT_SUBMITS_PER_SECOND). */
export declare const CLIENT_SUBMITS_PER_SECOND = 32;
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
export declare function frame(kind: "requestVote" | "voteReply" | "appendEntries" | "appendReply" | "clientSubmit", body: Dict): Uint8Array;
export declare class RaftLog {
    private readonly pipes;
    readonly members: string[];
    private readonly store;
    private readonly clock;
    private tickMillis;
    private readonly random;
    private readonly authorizer;
    private readonly applied;
    private role;
    private term;
    private votedFor;
    private log;
    private commitIndex;
    private lastApplied;
    private leaderHint;
    private electionElapsed;
    private electionTimeout;
    private readonly votesGranted;
    private readonly nextIndex;
    private readonly matchIndex;
    private readonly clientBudgets;
    private loaded;
    /** Writes in flight: a reply that depends on durable state awaits this chain. */
    private durable;
    clientSubmits: number;
    clientSubmitsRefused: number;
    constructor(pipes: RaftPipes, members: string[], applied: (command: Uint8Array, index: number) => void, options?: RaftOptions);
    /** Resolves once the store has been read; the driver awaits it before the first tick. */
    ready(): Promise<void>;
    private suspended;
    /**
     * Releases this member's voter duty (srad/agentspaces-js.md JS-R-06): it steps down to a
     * follower, ignores frames and ticks, and so counts as absent while its host's tick drifts;
     * the others elect around it. {@link resume} rejoins with the durable term and vote intact.
     */
    suspend(): void;
    resume(): void;
    isSuspended(): boolean;
    get self(): string;
    currentTerm(): number;
    isLeader(): boolean;
    currentRole(): Role;
    leader(): string | null;
    committed(): number;
    logLength(): number;
    /** The cadence the driver really runs at (RaftLog.driverCadence), for the advertised lease. */
    driverCadence(tickMillis: number): void;
    /** RaftLog.describe: the capability advertisement's parameters (the host adds the envelope fields). */
    parameters(): {
        [key: string]: string;
    };
    /** RaftLog.submit: appends when leading, forwards under the leader hint, or returns false. */
    submit(command: Uint8Array): Promise<boolean>;
    /** One tick of the driver: heartbeats when leading, the election timer otherwise. */
    tick(): Promise<void>;
    private onFrame;
    private clientBudgetAdmits;
    private onRequestVote;
    private onVoteReply;
    private onAppendEntries;
    private onAppendReply;
    private startElection;
    private becomeFollower;
    private appendFor;
    private broadcastAppends;
    private advanceCommit;
    private applyCommitted;
    private lastLogTerm;
    private newElectionTimeout;
    private send;
    /** Chains a durable write; a write that fails leaves the log a follower with the write's state unchanged. */
    private saveTermVoteDurably;
    private appendDurably;
}
/** The wire name of a frame kind, for diagnostics. */
export declare function kindOf(payload: Uint8Array): string | null;
export {};
