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
 * The in-memory fleet the verb tests run on: peers wired to each other
 * without sockets (an addressed frame reaches its peer, a rumor every other
 * peer, as test/layer4.test.ts wires them), with a hold that keeps chosen
 * deltas from one peer until released (a part that has not replicated
 * there yet), and three Raft voters from `@agentspaces/ordered` whose
 * applied commands install claims by the OrderedTakes.onCommand rule and
 * gossip them, so a root-package `OrderedLog` client takes through a real
 * log. Not a test file: the suites import it.
 */

import { RaftLog, RaftPipes } from "@agentspaces/ordered";

import { dumps, loads } from "../src/cbor.js";
import { ORDERED_LOG_TYPE } from "../src/capabilities/ordered.js";
import { Identity, deriveId, instantIso } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";

export type Internals = { fold(dto: Dict): void; foldClaim(entryId: string, signed: Dict): void;
  handle(env: Dict): void; send(kind: string, body: Buffer, to?: string | null): void };

export const internals = (peer: Peer): Internals => peer as unknown as Internals;

/** Peers by id; an addressed frame goes to its peer, a rumor to every other; held frames wait for a release. */
export class Network {
  readonly peers = new Map<string, NetPeer>();
  /** Per target peer: which rumored record types to hold, and the frames held. */
  readonly holds = new Map<string, { types: Set<string>; held: Dict[] }>();

  /** Keeps every space delta carrying a record of one of `types` from reaching `target` until `release`. */
  hold(target: NetPeer, ...types: string[]): void {
    this.holds.set(target.identity.peerId, { types: new Set(types), held: [] });
  }

  /** Delivers what was held for `target` and stops holding. */
  release(target: NetPeer): void {
    const hold = this.holds.get(target.identity.peerId);
    this.holds.delete(target.identity.peerId);
    for (const env of hold?.held ?? []) {
      internals(target).handle(env);
    }
  }

  private heldType(env: Dict): string | null {
    if (env["kind"] !== "RUMOR") {
      return null;
    }
    try {
      const rumor = loads(env["body"] as Uint8Array) as Dict;
      if (!String(rumor["streamId"] ?? "").startsWith("space:")) {
        return null;
      }
      const delta = loads(rumor["payload"] as Uint8Array) as Dict;
      const record = (delta["state"] as Dict | null)?.["record"] as Dict | undefined;
      return record === undefined ? null : String(record["type"]);
    } catch {
      return null;
    }
  }

  deliver(target: NetPeer, env: Dict): void {
    const hold = this.holds.get(target.identity.peerId);
    const type = hold === undefined ? null : this.heldType(env);
    if (hold !== undefined && type !== null && hold.types.has(type)) {
      hold.held.push(env);
      return;
    }
    if (target.accepts(env)) {
      internals(target).handle(env);
    }
  }
}

export class NetPeer extends Peer {
  constructor(readonly network: Network, group: string, now: () => number = Date.now) {
    super(Identity.generate(), group, now);
    network.peers.set(this.identity.peerId, this);
    const self = this as unknown as Internals;
    self.send = (kind: string, body: Buffer, to: string | null = null) => {
      const env = wire.envelope(this.group, kind, this.identity.peerId,
        wire.hlcNow(this.identity.peerId, this.now()), body, to);
      const targets = to !== null ? [network.peers.get(to)!]
        : [...network.peers.values()].filter((p) => p.identity.peerId !== this.identity.peerId);
      for (const target of targets) {
        if (target !== undefined) {
          network.deliver(target, env);
        }
      }
      if (kind === "RUMOR" && to === null) {
        const rumor = loads(body) as Dict;
        if (String(rumor["streamId"] ?? "").startsWith("space:")) {
          const delta = loads(Buffer.from(rumor["payload"] as Uint8Array)) as Dict;
          if (delta["claimEntry"] && typeof delta["claim"] === "object" && delta["claim"] !== null) {
            self.foldClaim(String(delta["claimEntry"]), delta["claim"] as Dict);
          }
          if (delta["state"] !== null && typeof delta["state"] === "object") {
            self.fold(delta["state"] as Dict);
          }
        }
      }
    };
  }

  override pullSpace(_space: string): void {}
  override pullRevocations(): void {}
}

/** `n` peers of one group that have introduced themselves to each other. */
export function fleet(group: string, n: number, now: () => number = Date.now): NetPeer[] {
  const network = new Network();
  const peers = Array.from({ length: n }, () => new NetPeer(network, group, now));
  for (const p of peers) {
    p.introduce();
  }
  return peers;
}

export const sleep = (millis: number) => new Promise((resolve) => setTimeout(resolve, millis));

export async function until(timeoutMillis: number, condition: () => boolean): Promise<boolean> {
  const deadline = Date.now() + timeoutMillis;
  while (Date.now() < deadline) {
    if (condition()) {
      return true;
    }
    await sleep(25);
  }
  return condition();
}

/** The ordered log of a fleet: three voters on the peers' pipes, driven by a tick loop until stopped. */
export class OrderedFleet {
  readonly logs = new Map<string, RaftLog>();
  /** Commands the appliers refused as not the next generation of their entry (entryId:epoch). */
  readonly rejected: string[] = [];
  /** Commands the appliers installed (entryId:epoch), on the first voter to apply each. */
  readonly installed: string[] = [];
  private running = true;
  private driver: Promise<void> | null = null;

  constructor(readonly voters: NetPeer[], readonly spaceName: string) {
    const ids = voters.map((v) => v.identity.peerId);
    let next = 7;
    const random = () => { next = (next * 1103515245 + 12345) % 2147483648; return next / 2147483648; };
    for (const voter of voters) {
      const pipes: RaftPipes = {
        peerId: voter.identity.peerId,
        send: (to, payload) => voter.sendPipe(to, ORDERED_LOG_TYPE, payload),
        onFrame: (handler) => { voter.pipeHandlers.set(ORDERED_LOG_TYPE, handler); },
      };
      this.logs.set(voter.identity.peerId, new RaftLog(pipes, ids, this.applier(voter), { random }));
    }
  }

  /**
   * OrderedTakes.onCommand: a pure function of committed state. The holder key
   * must be the claim holder's peer key and the claim bound to its entry; the
   * claim installs iff its epoch is exactly one past the epoch committed for
   * the entry, and then gossips as a signed claim delta, which is how a Raft
   * client observes the commit.
   */
  private applier(voter: NetPeer): (command: Uint8Array) => void {
    return (command) => {
      let parsed: Dict;
      try {
        parsed = loads(command) as Dict;
      } catch {
        return;
      }
      const claim = parsed["claim"] as Dict | undefined;
      const holderKey = parsed["holderKey"];
      const entryId = String(parsed["entryId"] ?? "");
      if (!claim || !(holderKey instanceof Uint8Array) || !(parsed["signature"] instanceof Uint8Array)
          || claim["entryId"] !== entryId || !String(claim["holder"]).startsWith(deriveId(holderKey) + "/")) {
        return;
      }
      const committed = Number((voter.claims.get(entryId)?.["claim"] as Dict | undefined)?.["epoch"] ?? 0);
      const epoch = Number(claim["epoch"]);
      if (epoch !== committed + 1) {
        this.rejected.push(`${entryId}:${epoch}`);
        return; // duplicate, stale, or conflicting generation: the log already decided
      }
      const signed: Dict = { claim, holderKey, signature: parsed["signature"] };
      if (parsed["holderCertificate"] !== undefined && parsed["holderCertificate"] !== null) {
        signed["holderCertificate"] = parsed["holderCertificate"];
      }
      internals(voter).foldClaim(entryId, signed); // the space's own verifier: an inauthentic command is dropped
      if (Number((voter.claims.get(entryId)?.["claim"] as Dict | undefined)?.["epoch"]) !== epoch) {
        return;
      }
      if (!this.installed.includes(`${entryId}:${epoch}`)) {
        this.installed.push(`${entryId}:${epoch}`);
      }
      internals(voter).send("RUMOR", Buffer.from(wire.rumorBody(`space:${this.spaceName}`,
        `c:${entryId}:${String(claim["stamp"])}`, 6, wire.claimDelta(entryId, signed))));
    };
  }

  /** Elects a leader, advertises the log, and keeps ticking (and re-advertising) until `stop`. */
  async start(): Promise<void> {
    for (const log of this.logs.values()) {
      await log.ready();
    }
    this.driver = this.drive();
    const elected = await until(10_000, () => [...this.logs.values()].some((l) => l.isLeader()));
    if (!elected) {
      throw new Error("no leader elected");
    }
    this.advertise();
  }

  leader(): NetPeer | null {
    for (const voter of this.voters) {
      if (this.logs.get(voter.identity.peerId)!.isLeader()) {
        return voter;
      }
    }
    return null;
  }

  /** The ordered-log capability advertisement of every voter, as the Java host publishes it (RaftLog.describe). */
  advertise(): void {
    for (const voter of this.voters) {
      const now = voter.now();
      const log = this.logs.get(voter.identity.peerId)!;
      voter.publishAd("CapabilityAdvertisement", { id: `aspace://${voter.group}/cap/ordered-log/${voter.identity.peerId}`,
        issuer: voter.identity.peerId, group: voter.group, issued: instantIso(now - (now % 1000)), ttl: "PT10M",
        capabilityType: ORDERED_LOG_TYPE, parameters: log.parameters() });
    }
  }

  /** Submits a command to the leader as a client would, through the pipes of `from`. */
  submitFrom(from: NetPeer, command: Uint8Array): void {
    const leader = this.leader() ?? this.voters[0]!;
    from.sendPipe(leader.identity.peerId, ORDERED_LOG_TYPE, dumps({ requestVote: null, voteReply: null,
      appendEntries: null, appendReply: null, clientSubmit: { command } }));
  }

  private async drive(): Promise<void> {
    let ticks = 0;
    while (this.running) {
      for (const log of this.logs.values()) {
        await log.tick();
      }
      if (++ticks % 100 === 0) {
        this.advertise();
      }
      await sleep(15);
    }
  }

  async stop(): Promise<void> {
    this.running = false;
    await this.driver;
  }
}
