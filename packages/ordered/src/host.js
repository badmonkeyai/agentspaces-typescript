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
 * A member of an ordered log on a `Peer` (srad/agentspaces-js.md JS-V-06,
 * JS-V-07, JS-V-10): the voter wired to the peer's `aspace:cap/ordered-log`
 * pipe, the coordinator that installs each committed claim into the peer's
 * replica as `OrderedTakes.onCommand` does, and the capability advertisement
 * that tells clients who leads. A peer hosts at most one log per group; a
 * host whose residency cannot carry a voter is refused at construction.
 */
import { capabilities, cbor, deriveId, platform, requireResidency } from "@agentspaces/client";
import { RaftLog, TYPE } from "./raft.js";
const { Pipes } = capabilities;
const { dumps, loads } = cbor;
/** The logs hosted in this runtime, one per peer and group (JS-V-10). */
const hosted = new Map();
export class OrderedLogHost {
    peer;
    space;
    raft;
    committedListeners = [];
    lastAdvertised = "";
    lastAdvertisedAt = 0;
    advertiseEvery;
    /** Committed commands that were not well-formed claim commands, or were not authentic. */
    commandsDropped = 0;
    /** Committed claims installed, and those heard for an epoch the replica had already decided. */
    claimsInstalled = 0;
    claimsRepeated = 0;
    /**
     * @param peer    the peer this log runs on
     * @param space   the space whose takes the log orders
     * @param members every member's PeerID, the same list on every member (fixed at construction, as in Java)
     */
    constructor(peer, space, members, options = {}) {
        this.peer = peer;
        this.space = space;
        requireResidency(options.residency ?? platform().residency, "voter", `voter for ordered log '${space}'`);
        const key = `${peer.identity.peerId}@${peer.group}`;
        const existing = hosted.get(key);
        if (existing !== undefined) {
            throw new Error(`this peer already hosts the ordered log of group ${peer.group} (space '${existing.space}'); `
                + "a peer hosts at most one ordered log per group");
        }
        const pipes = new Pipes(peer);
        this.raft = new RaftLog({
            peerId: peer.identity.peerId,
            send: (to, payload) => pipes.send(to, TYPE, payload),
            onFrame: (handler) => pipes.onCapability(TYPE, handler),
        }, members, (command) => this.apply(command), options);
        this.advertiseEvery = options.advertiseEveryMillis ?? 60_000;
        hosted.set(key, this);
    }
    /** Resolves once the voter's store has been read. */
    ready() {
        return this.raft.ready();
    }
    /** One tick of the host's driver: the voter's tick, then the advertisement when it changed or aged. */
    async tick() {
        await this.raft.tick();
        this.advertise();
    }
    /** The cadence the host really ticks at, for the advertised lease (RaftLog.driverCadence). */
    driverCadence(tickMillis) {
        this.raft.driverCadence(tickMillis);
    }
    /** Publishes the `aspace:cap/ordered-log` advertisement (RaftLog.describe) when its parameters changed or it aged. */
    advertise(force = false) {
        const parameters = this.raft.parameters();
        const now = this.peer.now();
        const snapshot = JSON.stringify(parameters);
        if (!force && snapshot === this.lastAdvertised && now - this.lastAdvertisedAt < this.advertiseEvery) {
            return false;
        }
        const issued = new Date(now).toISOString().replace(/\.\d{3}Z$/, "Z");
        this.peer.publishAd("CapabilityAdvertisement", {
            id: `aspace://${this.peer.group}/cap/ordered-log/${this.peer.identity.peerId}`,
            issuer: this.peer.identity.peerId,
            group: this.peer.group,
            issued,
            ttl: "PT15M",
            capabilityType: TYPE,
            version: "0.1",
            binding: "pipe",
            parameters,
            costHints: {},
        });
        this.lastAdvertised = snapshot;
        this.lastAdvertisedAt = now;
        return true;
    }
    /** Hears every authentic claim the log commits, in log order (OrderedTakes.onCommitted). */
    onCommitted(listener) {
        this.committedListeners.push(listener);
        return () => {
            const at = this.committedListeners.indexOf(listener);
            if (at >= 0) {
                this.committedListeners.splice(at, 1);
            }
        };
    }
    /** JS-R-06: releases the voter duty while the host's tick drifts; {@link resume} takes it back. */
    suspend() {
        this.raft.suspend();
        this.advertise(true);
    }
    resume() {
        this.raft.resume();
        this.advertise(true);
    }
    /**
     * OrderedTakes.onCommand: a committed ClaimCommand installs its claim exactly as the holder
     * signed it when its epoch is the next one for the entry; a duplicate, stale, or conflicting
     * generation installs nothing but is still announced when authentic, in the log's order.
     */
    apply(command) {
        let parsed;
        try {
            parsed = loads(command);
        }
        catch {
            this.commandsDropped += 1;
            return;
        }
        const entryId = parsed?.["entryId"];
        const claim = parsed?.["claim"];
        const holderKey = parsed?.["holderKey"];
        if (typeof entryId !== "string" || claim === null || typeof claim !== "object"
            || !(holderKey instanceof Uint8Array) || holderKey.length !== 32 || !(parsed["signature"] instanceof Uint8Array)
            || claim["entryId"] !== entryId // ASF-002: a claim signed for one entry never commits against another
            || String(claim["holder"] ?? "").split("/")[0] !== deriveId(holderKey)) {
            this.commandsDropped += 1;
            return;
        }
        const signed = { claim, holderKey, signature: parsed["signature"] };
        if (parsed["holderCertificate"] != null) {
            signed["holderCertificate"] = parsed["holderCertificate"];
        }
        const held = this.peer.claims.get(entryId)?.["claim"];
        const committedEpoch = held === undefined ? 0 : Number(epochOf(held));
        if (Number(epochOf(claim)) !== committedEpoch + 1) {
            // The log already decided this generation, or gossip delivered the claim first: nothing to
            // install, but listeners on the committed order still hear every authentic claim.
            this.claimsRepeated += 1;
            if (this.peer.applyCommittedClaim(this.space, entryId, signed) || sameClaim(held, claim)) {
                this.notify(entryId, claim);
            }
            return;
        }
        if (!this.peer.applyCommittedClaim(this.space, entryId, signed)) {
            this.commandsDropped += 1; // the replica's claim verifier refused it: not authentic
            return;
        }
        this.claimsInstalled += 1;
        this.notify(entryId, claim);
    }
    notify(entryId, claim) {
        for (const listener of [...this.committedListeners]) {
            try {
                listener(entryId, claim);
            }
            catch {
                // a listener's failure never stops the log
            }
        }
    }
    /** Forgets this host so the peer may host another log of the group; the voter stops ticking. */
    close() {
        this.raft.suspend();
        const key = `${this.peer.identity.peerId}@${this.peer.group}`;
        if (hosted.get(key) === this) {
            hosted.delete(key);
        }
    }
}
function epochOf(claim) {
    const epoch = claim["epoch"];
    return typeof epoch === "bigint" ? Number(epoch) : Number(epoch ?? 0);
}
function sameClaim(held, claim) {
    if (held === undefined) {
        return false;
    }
    try {
        const a = dumps(held);
        const b = dumps(claim);
        return a.length === b.length && a.every((byte, i) => byte === b[i]);
    }
    catch {
        return false;
    }
}
