/**
 * The durable state of a Raft voter (srad/agentspaces-js.md JS-V-06,
 * JS-F-04): the term, the vote, and the log, written before any reply that
 * depends on them leaves, so a voter that restarts never votes twice in a
 * term and never loses an acknowledged entry. One shape for Java and
 * JavaScript, so membership change and snapshots later land once in both.
 */
/** One replicated log entry (RaftMessages.LogEntry). */
export type LogEntry = {
    term: number;
    command: Uint8Array;
};
export type LogState = {
    term: number;
    votedFor: string | null;
    entries: LogEntry[];
};
export interface LogStore {
    /** What the store holds; an empty store is term 0, no vote, no entries. */
    load(): Promise<LogState>;
    /** Persists the term and vote; returns once they are durable. */
    saveTermVote(term: number, votedFor: string | null): Promise<void>;
    /** Appends entries from 1-based index `fromIndex` (truncating any entries at or after it first). */
    append(fromIndex: number, entries: LogEntry[]): Promise<void>;
    /** Removes entries at and after 1-based `index`. */
    truncateFrom(index: number): Promise<void>;
}
/** A store in memory: the default for tests and for hosts that accept amnesia on restart. */
export declare class MemoryLogStore implements LogStore {
    private state;
    /** How many durable writes happened, for tests that check write-before-reply. */
    writes: number;
    /** A fault a test injects: thrown by the next write when set. */
    failNextWrite: Error | null;
    constructor(initial?: Partial<LogState>);
    load(): Promise<LogState>;
    private write;
    saveTermVote(term: number, votedFor: string | null): Promise<void>;
    append(fromIndex: number, entries: LogEntry[]): Promise<void>;
    truncateFrom(index: number): Promise<void>;
}
