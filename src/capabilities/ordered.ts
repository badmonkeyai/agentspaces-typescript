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
 * The Raft client of the ordered log (srad/agentspaces-js.md JS-V-05;
 * reviews/L3L4-COVERAGE.md "a Raft client, not a Raft voter"): a peer at any
 * residency submits a signed claim command to the log's leader (named by the
 * leader's `aspace:cap/ordered-log` advertisement, or forwarded by any member
 * of the log) and observes the commit through the space, where the committed
 * claim arrives as a signed claim delta. An ordered take is therefore exactly
 * once fleet-wide: the log decides each generation, and only the holder the
 * log committed completes. This is the client half of `OrderedTakes`; the
 * voter lives in `@agentspaces/ordered`.
 */

import { dumps, loads } from "../cbor.js";
import { AgentIdentity, parseInstantMillis, spaceIdLocal } from "../identity.js";
import type { Peer } from "../peer.js";
import * as wire from "../wire.js";
import type { Dict } from "../wire.js";
import { Pipes } from "./pipes.js";

/** The capability type URI (RaftLog.TYPE). */
export const ORDERED_LOG_TYPE = "aspace:cap/ordered-log";

/** A member's view of the log, from its advertisement. */
export type LogMember = { peer: string; role: string; term: number; leaseUntilMillis: number | null };

/** RaftMessages.Frame carrying one ClientSubmit, in Java record order (every other field null). */
export function clientSubmitFrame(command: Uint8Array): Uint8Array {
  return dumps({ requestVote: null, voteReply: null, appendEntries: null, appendReply: null,
    clientSubmit: { command } });
}

/**
 * OrderedTakes.ClaimCommand: the claim, the holder's peer key, the holder's
 * signature over the claim's canonical bytes, and (for an agent holder) the
 * certificate covering the claim's stamp, omitted otherwise.
 */
export function claimCommand(entryId: string, claim: Dict, peerPublicRaw: Uint8Array, signature: Uint8Array,
                             holderCertificate: Dict | null): Uint8Array {
  const command: Dict = { entryId, claim, holderKey: peerPublicRaw, signature };
  if (holderCertificate !== null) {
    command["holderCertificate"] = holderCertificate;
  }
  return dumps(command);
}

export class OrderedLog {
  constructor(private readonly pipes: Pipes) {}

  get peer(): Peer {
    return this.pipes.peer;
  }

  /** The log's members as their current advertisements describe them. */
  members(): LogMember[] {
    const now = this.peer.now();
    const out: LogMember[] = [];
    for (const entry of this.peer.ads.values()) {
      if (entry.type !== "CapabilityAdvertisement" || entry.expires <= now
          || entry.ad["capabilityType"] !== ORDERED_LOG_TYPE) {
        continue;
      }
      const parameters = (entry.ad["parameters"] ?? {}) as Dict;
      let leaseUntil: number | null = null;
      try {
        leaseUntil = parameters["leaseUntil"] == null ? null : parseInstantMillis(parameters["leaseUntil"]);
      } catch {
        leaseUntil = null;
      }
      out.push({ peer: entry.issuer, role: String(parameters["role"] ?? ""), term: Number(parameters["term"] ?? 0),
        leaseUntilMillis: leaseUntil });
    }
    return out;
  }

  /** The leader whose lease has not lapsed, by the highest term, or null. */
  leader(): string | null {
    const now = this.peer.now();
    const leaders = this.members().filter((m) => m.role === "leader"
      && (m.leaseUntilMillis === null || m.leaseUntilMillis > now)).sort((a, b) => b.term - a.term);
    return leaders.length > 0 ? leaders[0].peer : null;
  }

  /**
   * Where a submit goes: the leader when this peer can reach it, else any
   * reachable member of the log, which forwards it under its leader hint.
   */
  submitTarget(): string | null {
    const leader = this.leader();
    if (leader !== null && this.peer.reachable.has(leader)) {
      return leader;
    }
    const member = this.members().find((m) => this.peer.reachable.has(m.peer));
    return member?.peer ?? null;
  }

  /** Submits one command; returns whether a target was known. */
  submit(command: Uint8Array): boolean {
    const target = this.submitTarget();
    if (target === null) {
      return false;
    }
    this.pipes.send(target, ORDERED_LOG_TYPE, clientSubmitFrame(command));
    return true;
  }

  /**
   * OrderedTakes.take as a client: claims a matching live entry through the
   * log and returns its id once the log committed this peer's claim for the
   * generation it asked for, or null at the timeout. The caller completes
   * the entry as after any take.
   */
  async take(space: string, typeName: string, agentName = "ts-worker", leaseMillis = 60_000,
             timeoutMillis = 15_000, agent: AgentIdentity | null = null,
             matches: ((payload: Dict, tags: Dict) => boolean) | null = null): Promise<string | null> {
    const peer = this.peer;
    const holder = agent !== null ? agent.agentId : peer.identity.agent(agentName);
    const spaceId = spaceIdLocal(`${peer.group}/${space}`);
    const deadline = Date.now() + timeoutMillis;
    let lastPull = 0;
    while (Date.now() < deadline) {
      if (Date.now() - lastPull >= 600) {
        lastPull = Date.now();
        peer.pullAds();
        peer.pullSpace(space);
      }
      await peer.awaitFold(Math.min(600, deadline - Date.now()));
      const now = peer.now();
      for (const [entryId, dto] of peer.states) {
        const record = dto["record"] as Dict | undefined;
        if (!record || record["type"] !== typeName || dto["completed"] || record["spaceId"] !== spaceId) {
          continue;
        }
        const lease = (dto["leaseValue"] ?? record["lease"]) as Dict | undefined;
        if (!lease || Number(lease["expiresAtMillis"]) <= now) {
          continue;
        }
        const current = peer.claims.get(entryId)?.["claim"] as Dict | undefined;
        if (current && Number(current["expiresAtMillis"]) > now) {
          continue;
        }
        const payload = loads((record["payload"] as Uint8Array) ?? new Uint8Array([0xf6])) as Dict;
        if (matches !== null && !matches(payload ?? {}, (record["tags"] as Dict) ?? {})) {
          continue;
        }
        const epoch = current ? Number(current["epoch"]) + 1 : 1;
        const claim = wire.takeClaim(entryId, spaceId, epoch, wire.hlcNow(holder, now), holder, 0.0,
          now + leaseMillis);
        const signed = wire.signedClaim(claim, peer.identity, agent);
        const command = claimCommand(entryId, claim, peer.identity.publicRaw, signed["signature"] as Uint8Array,
          (signed["holderCertificate"] as Dict | undefined) ?? null);
        if (!this.submit(command)) {
          break; // no member of the log reachable yet: pull the ads again
        }
        // Wait for the log to decide this generation, for a bounded attempt: a command lost to a
        // leader election is resubmitted on the next scan (OrderedTakes.take).
        const attemptDeadline = Math.min(deadline, Date.now() + 3000);
        while (Date.now() < attemptDeadline) {
          await peer.awaitFold(Math.min(600, attemptDeadline - Date.now()));
          const decided = peer.claims.get(entryId)?.["claim"] as Dict | undefined;
          if (decided && Number(decided["epoch"]) >= epoch) {
            if (decided["holder"] === holder && Number(decided["epoch"]) === epoch
                && !peer.states.get(entryId)?.["completed"]) {
              return entryId;
            }
            break; // someone else won this generation; try another entry
          }
          if (Date.now() - lastPull >= 600) {
            lastPull = Date.now();
            peer.pullSpace(space);
          }
        }
        break; // re-scan (and resubmit when still undecided)
      }
    }
    return null;
  }
}
