/**
 * A member of an ordered log on a `Peer` (srad/agentspaces-js.md JS-V-06,
 * JS-V-07, JS-V-10): the voter wired to the peer's `aspace:cap/ordered-log`
 * pipe, the coordinator that installs each committed claim into the peer's
 * replica as `OrderedTakes.onCommand` does, and the capability advertisement
 * that tells clients who leads. A peer hosts at most one log per group; a
 * host whose residency cannot carry a voter is refused at construction.
 */
import { Peer } from "@agentspaces/client";
import type { Residency, wire } from "@agentspaces/client";
import { RaftLog, RaftOptions } from "./raft.js";
type Dict = wire.Dict;
export type OrderedLogHostOptions = RaftOptions & {
    /** The residency to judge the voter duty by; the platform's by default. */
    residency?: Residency;
    /** How often the advertisement is refreshed when nothing changed; 60 s by default (its TTL is 15 min). */
    advertiseEveryMillis?: number;
};
export declare class OrderedLogHost {
    readonly peer: Peer;
    readonly space: string;
    readonly raft: RaftLog;
    private readonly committedListeners;
    private lastAdvertised;
    private lastAdvertisedAt;
    private readonly advertiseEvery;
    /** Committed commands that were not well-formed claim commands, or were not authentic. */
    commandsDropped: number;
    /** Committed claims installed, and those heard for an epoch the replica had already decided. */
    claimsInstalled: number;
    claimsRepeated: number;
    /**
     * @param peer    the peer this log runs on
     * @param space   the space whose takes the log orders
     * @param members every member's PeerID, the same list on every member (fixed at construction, as in Java)
     */
    constructor(peer: Peer, space: string, members: string[], options?: OrderedLogHostOptions);
    /** Resolves once the voter's store has been read. */
    ready(): Promise<void>;
    /** One tick of the host's driver: the voter's tick, then the advertisement when it changed or aged. */
    tick(): Promise<void>;
    /** The cadence the host really ticks at, for the advertised lease (RaftLog.driverCadence). */
    driverCadence(tickMillis: number): void;
    /** Publishes the `aspace:cap/ordered-log` advertisement (RaftLog.describe) when its parameters changed or it aged. */
    advertise(force?: boolean): boolean;
    /** Hears every authentic claim the log commits, in log order (OrderedTakes.onCommitted). */
    onCommitted(listener: (entryId: string, claim: Dict) => void): () => void;
    /** JS-R-06: releases the voter duty while the host's tick drifts; {@link resume} takes it back. */
    suspend(): void;
    resume(): void;
    /**
     * OrderedTakes.onCommand: a committed ClaimCommand installs its claim exactly as the holder
     * signed it when its epoch is the next one for the entry; a duplicate, stale, or conflicting
     * generation installs nothing but is still announced when authentic, in the log's order.
     */
    private apply;
    private notify;
    /** Forgets this host so the peer may host another log of the group; the voter stops ticking. */
    close(): void;
}
export {};
