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
 * The QUORUM tally (SPEC §8, TECH-SPEC §8.4), as Java's VoteCapability.tally
 * counts it, over the ballot states a Peer has folded. Ballots are ordinary
 * entries of the reserved type below; the voter is the entry's authenticated
 * issuer, and a ballot whose declared `voter` differs from it is a forgery.
 *
 * Counting follows a granularity (QA4 A4-7 phase 2). Under PEER the counted
 * identity is the issuer's peer, so one peer is one counted ballot however
 * many names it writes; under AGENT each permitted agent counts once, and only
 * an AGENT_ATTESTED record (one whose state carried a certificate the two-key
 * rule accepted) is eligible, because a peer-asserted name is exactly what that
 * granularity exists to distrust.
 */
import { readDocument } from "./cbor.js";
import type { Dict } from "./wire.js";
import { Peer, leaseExpiryOf, present } from "./peer.js";
import { AgentIdentity, spaceIdLocal } from "./identity.js";

export const BALLOT_TYPE = "ai.badmonkey.agentspaces.capabilities.vote.VoteCapability$Ballot#v1";
export const PROPOSAL_TYPE = "ai.badmonkey.agentspaces.capabilities.vote.VoteCapability$Proposal#v1";
export type Granularity = "PEER" | "AGENT";

/**
 * The live entries of `type` in the vote space `space`, each as its record, its state and its decoded
 * value: present, unlapsed, and of that space alone, as Java's VoteCapability reads its own vote space
 * (HLC round six, 2026-11-08, R9). An entry whose value no read can decode is skipped.
 */
function liveValues(peer: Peer, space: string, type: string): Array<[Dict, Dict, Dict]> {
  const spaceId = spaceIdLocal(`${peer.group}/${space}`);
  const now = peer.now();
  const found: Array<[Dict, Dict, Dict]> = [];
  for (const dto of peer.states.values()) {
    const record = (dto["record"] as Dict) ?? {};
    if (record["type"] !== type || record["spaceId"] !== spaceId || !present(dto) || leaseExpiryOf(dto) <= now) {
      continue;
    }
    const read = readDocument(record["payload"] as Uint8Array);
    if (read !== null && typeof read.value === "object" && read.value !== null) {
      found.push([record, dto, read.value as Dict]);
    }
  }
  return found;
}

/** The live ballot records for one proposal in the vote space `space`, in stored order. */
export function ballots(peer: Peer, space: string, proposalId: string): Array<[Dict, Dict, Dict]> {
  return liveValues(peer, space, BALLOT_TYPE).filter(([, , ballot]) => ballot["proposalId"] === proposalId);
}

/**
 * Votes per option. `permits(issuerAgentId)` is the authorizer's per-agent
 * answer (everyone, by default); `options` zero-fills and spoils ballots for
 * options the proposal does not offer, when known.
 */
export function tally(peer: Peer, space: string, proposalId: string,
                      options: string[] | null = null, granularity: Granularity = "PEER",
                      permits: ((issuer: string) => boolean) | null = null): Map<string, number> {
  const result = new Map<string, number>();
  for (const option of options ?? []) {
    result.set(option, 0);
  }
  const counted = new Set<string>();
  for (const [record, dto, ballot] of ballots(peer, space, proposalId)) {
    const issuer = record["issuer"];
    if (typeof issuer !== "string" || ballot["voter"] !== issuer) {
      continue; // declared voter is not the authenticated writer: forged
    }
    const option = String(ballot["option"]);
    if (options !== null && !options.includes(option)) {
      continue; // spoiled
    }
    if (granularity === "AGENT" && (dto["agentCertificate"] ?? null) === null) {
      continue; // per-agent counting trusts only the agent's own key
    }
    if (permits !== null && !permits(issuer)) {
      continue;
    }
    const key = granularity === "AGENT" ? issuer : issuer.split("/", 1)[0];
    if (counted.has(key)) {
      continue;
    }
    counted.add(key);
    result.set(option, (result.get(option) ?? 0) + 1);
  }
  return result;
}

// ------------------------------------------------------- proposals and casts

/** A proposal as the fleet writes it (SPEC §8.4). */
export type Proposal = { proposalId: string; question: string; options: string[]; quorum: number };

/** The open proposals by id, from the live Proposal records of the vote space `space`. */
export function proposals(peer: Peer, space: string): Map<string, Proposal> {
  const found = new Map<string, Proposal>();
  for (const [, , p] of liveValues(peer, space, PROPOSAL_TYPE)) {
    if (typeof p["proposalId"] === "string" && !found.has(p["proposalId"])) {
      found.set(p["proposalId"], { proposalId: p["proposalId"], question: String(p["question"] ?? ""),
        options: ((p["options"] as unknown[]) ?? []).map(String), quorum: Number(p["quorum"] ?? 0) });
    }
  }
  return found;
}

/**
 * Opens a proposal: a Proposal entry in the vote space, in Java field order;
 * idempotent on the id. Returns the entry id, or null when already open.
 */
export function propose(peer: Peer, space: string, proposalId: string, question: string,
                        options: string[], quorum: number, leaseMillis = 3_600_000,
                        agent: AgentIdentity | null = null, agentName = "typescript"): string | null {
  if (proposals(peer, space).has(proposalId)) {
    return null;
  }
  return peer.writeEntry(space, PROPOSAL_TYPE, { proposalId, question, options, quorum },
    agentName, leaseMillis, agent);
}

/**
 * Casts this agent's ballot: a Ballot entry whose `voter` is the
 * authenticated writer (a tally skips any other); the first per voter counts.
 */
export function cast(peer: Peer, space: string, proposalId: string, option: string,
                     leaseMillis = 3_600_000, agent: AgentIdentity | null = null,
                     agentName = "typescript"): string {
  const voter = agent !== null ? agent.agentId : peer.identity.agent(agentName);
  return peer.writeEntry(space, BALLOT_TYPE, { proposalId, option, voter }, agentName, leaseMillis, agent);
}

/** A closed vote: the winner and the counts. */
export type Decision = { proposalId: string; winner: string; tally: Map<string, number> };

/**
 * The QUORUM decision as Java closes it (SPEC §8.4): once distinct counted
 * voters reach the quorum, the option with the most votes wins, ties broken
 * to the lexicographically first option. Null while open or unknown.
 */
export function decision(peer: Peer, space: string, proposalId: string, granularity: Granularity = "PEER",
                         permits: ((issuer: string) => boolean) | null = null): Decision | null {
  const proposal = proposals(peer, space).get(proposalId);
  if (proposal === undefined) {
    return null;
  }
  const counts = tally(peer, space, proposalId, proposal.options, granularity, permits);
  let voters = 0;
  for (const n of counts.values()) {
    voters += n;
  }
  if (voters === 0 || voters < proposal.quorum) {
    return null;
  }
  const winner = [...proposal.options].sort((a, b) => {
    const diff = (counts.get(b) ?? 0) - (counts.get(a) ?? 0);
    return diff !== 0 ? diff : a < b ? -1 : a > b ? 1 : 0;
  })[0];
  return { proposalId, winner, tally: counts };
}

// ------------------------------------------------------------ MAJORITY_GOSSIP

/** The push-sum epoch that carries one option's preference share (VoteCapability.epoch). */
export function preferenceEpoch(voteId: string, option: string): string {
  return `vote:${voteId}:${option}`;
}

/**
 * VoteCapability.castPreference (JS-V-04): an approximate preference through
 * push-sum, 1 to the chosen option's average and 0 to the others; every
 * participant casts over the same aggregator and ticks it to convergence.
 */
export function castPreference(aggregate: { start(epochId: string, value: number): void }, voteId: string,
                               options: string[], preference: string): void {
  for (const option of options) {
    aggregate.start(preferenceEpoch(voteId, option), option === preference ? 1 : 0);
  }
}

/** VoteCapability.leader: the option with the highest estimated share, or null before any estimate. */
export function leader(aggregate: { estimate(epochId: string): number | null }, voteId: string,
                       options: string[]): string | null {
  let best: string | null = null;
  let bestShare = -1;
  for (const option of options) {
    const estimate = aggregate.estimate(preferenceEpoch(voteId, option));
    if (estimate !== null && estimate > bestShare) {
      bestShare = estimate;
      best = option;
    }
  }
  return best;
}

