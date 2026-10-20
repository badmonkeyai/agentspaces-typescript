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
 * The service host (srad/agentspaces-js.md JS-R-04, JS-R-06, JS-R-07): a
 * Node process that listens on `tcp` and `ws`, dials its seeds, ticks at a
 * fixed period and reports its true cadence to the duties it carries, serves
 * anti-entropy and relays rumors through the core `Peer`, advertises its
 * endpoints and `js.residency=service`, drops to visitor duties while its
 * tick drifts and takes them back when it recovers, and drains on `SIGTERM`
 * within a bound.
 */

import { Identity, Peer, Seed } from "@agentspaces/client";
import type { FrameChannel, Listener, ListenerHandle, Residency } from "@agentspaces/client";
import { TcpListener } from "@agentspaces/client/node";
import { WsListener } from "./ws-listener.js";

/** One listener the host opens: its scheme, the bind address, and what it advertises (the bind by default). */
export type ListenerSpec = {
  scheme: "tcp" | "ws";
  bind: string;
  /** The address other members dial, when the bind is not it (a NAT, a container, `:0`). */
  advertise?: string;
  /** Browser origins the `ws` listener admits (OriginPolicy); empty refuses every browser until named. */
  origins?: string[];
};

/** A duty the host carries and must release while it drifts (JS-R-06): an ordered-log host, a keeper. */
export interface Duty {
  tick?(): Promise<void> | void;
  suspend(): void;
  resume(): void;
  /** Releases what the duty holds for good (a log host forgets its registration); called by `stop`. */
  close?(): void;
}

export type ServiceHostOptions = {
  tickMillis?: number;
  seeds?: Seed[];
  listeners?: ListenerSpec[];
  /** The spaces this host serves and pulls (registered as a Java member registers its spaces). */
  spaces?: string[];
  /** How long `stop` waits for the duties to drain; 10 s by default (JS-R-04). */
  drainMillis?: number;
  /** Install `SIGTERM`/`SIGINT` handlers that stop the host; off by default so a test owns its signals. */
  signals?: boolean;
  /** Where the host reports; `console.error` by default, `null` for silence. */
  log?: ((line: string) => void) | null;
  /** The clock, for tests of the drift rule. */
  clock?: () => number;
};

/** Consecutive drifting ticks before the host drops to visitor duties, and the quiet span that restores them. */
export const DRIFT_TICKS = 3;
export const DRIFT_FACTOR = 2;
export const RECOVERY_MILLIS = 60_000;

export class ServiceHost {
  readonly peer: Peer;
  readonly tickMillis: number;
  /** `service` while the tick keeps its cadence, `visitor` while it drifts (JS-R-06). */
  residency: Residency = "service";
  ticks = 0;
  /** Ticks that arrived later than twice the period, in total and in the current run. */
  drifts = 0;
  private consecutiveDrifts = 0;
  private lastDriftAt = 0;
  private lastTickAt = 0;
  private timer: NodeJS.Timeout | null = null;
  private readonly duties: Duty[] = [];
  private readonly bound: ListenerHandle[] = [];
  private readonly seeds: Seed[];
  private readonly listeners: ListenerSpec[];
  private readonly spaces: string[];
  private readonly drainMillis: number;
  private readonly signals: boolean;
  private readonly log: (line: string) => void;
  private readonly clock: () => number;
  private stopping: Promise<void> | null = null;
  private readonly signalHandler = (): void => { void this.stop(); };

  constructor(identity: Identity, group: string, options: ServiceHostOptions = {}) {
    this.clock = options.clock ?? Date.now;
    this.peer = new Peer(identity, group, this.clock);
    this.tickMillis = options.tickMillis ?? 1000;
    this.seeds = options.seeds ?? [];
    this.listeners = options.listeners ?? [];
    this.spaces = options.spaces ?? [];
    this.drainMillis = options.drainMillis ?? 10_000;
    this.signals = options.signals ?? false;
    this.log = options.log === null ? () => undefined : options.log ?? ((line) => console.error(line));
    this.peer.resourceHints["js.residency"] = "service"; // JS-R-07: what this host is, for operators; never trusted for safety
  }

  /** The addresses the listeners bound, by scheme, once started. */
  readonly addresses = new Map<string, string>();

  /** Adds a duty the host ticks and suspends while drifting; an ordered-log host registers itself this way. */
  addDuty(duty: Duty): void {
    this.duties.push(duty);
    if (this.residency === "visitor") {
      duty.suspend();
    }
  }

  async start(): Promise<void> {
    for (const spec of this.listeners) {
      const listener: Listener = spec.scheme === "tcp" ? new TcpListener() : new WsListener(spec.origins ?? []);
      const handle = await listener.listen(spec.bind, (channel: FrameChannel) => { this.peer.acceptChannel(channel); });
      this.bound.push(handle);
      const address = spec.advertise ?? handle.address ?? spec.bind;
      this.addresses.set(spec.scheme, address);
      this.peer.endpoints.push({ transport: spec.scheme, address, priority: this.peer.endpoints.length });
    }
    for (const space of this.spaces) {
      this.peer.pullSpace(space);
    }
    if (this.seeds.length > 0) {
      await this.peer.connectAny(this.seeds);
    } else {
      this.peer.introduce(); // a hub with no seeds introduces itself to whoever connects
    }
    this.lastTickAt = this.clock();
    this.timer = setInterval(() => { void this.tick(); }, this.tickMillis);
    if (this.signals) {
      process.once("SIGTERM", this.signalHandler);
      process.once("SIGINT", this.signalHandler);
    }
    this.log(`agentspaces-node ${this.peer.identity.peerId} up in ${this.peer.group}: `
      + ([...this.addresses].map(([s, a]) => `${s}://${a}`).join(", ") || "dial-only"));
  }

  /**
   * One tick: the drift rule, then the peer's housekeeping (lapsed members, an anti-entropy
   * round every ten ticks, the advertisement every five minutes), then each duty's tick with
   * the cadence this host really keeps.
   */
  async tick(): Promise<void> {
    const now = this.clock();
    this.observeCadence(now);
    this.ticks += 1;
    this.peer.expireMembers();
    if (this.ticks % 10 === 0) {
      this.peer.antiEntropyRound();
    }
    if (this.ticks % 300 === 0) {
      this.peer.introduce();
    }
    for (const duty of this.duties) {
      try {
        await duty.tick?.();
      } catch (e) {
        this.log(`duty tick failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }

  /**
   * JS-R-06: a tick later than twice the period, three times running, drops the host to visitor
   * duties (voters and keepers release their roles); sixty seconds without a drift restores them.
   */
  observeCadence(now: number): void {
    const gap = now - this.lastTickAt;
    this.lastTickAt = now;
    if (this.ticks > 0 && gap > DRIFT_FACTOR * this.tickMillis) {
      this.drifts += 1;
      this.consecutiveDrifts += 1;
      this.lastDriftAt = now;
      if (this.consecutiveDrifts >= DRIFT_TICKS && this.residency !== "visitor") {
        this.residency = "visitor";
        this.log(`tick drifted ${this.consecutiveDrifts} times (last gap ${gap} ms over a ${this.tickMillis} ms period): `
          + "dropping to visitor duties");
        for (const duty of this.duties) {
          duty.suspend();
        }
      }
    } else {
      this.consecutiveDrifts = 0;
      if (this.residency === "visitor" && now - this.lastDriftAt >= RECOVERY_MILLIS) {
        this.residency = "service";
        this.log("tick cadence recovered for 60 s: resuming service duties");
        for (const duty of this.duties) {
          duty.resume();
        }
      }
    }
  }

  /** Stops ticking, closes the listeners and every connection, within the drain bound; idempotent. */
  stop(): Promise<void> {
    this.stopping ??= this.drain();
    return this.stopping;
  }

  private async drain(): Promise<void> {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.signals) {
      process.removeListener("SIGTERM", this.signalHandler);
      process.removeListener("SIGINT", this.signalHandler);
    }
    const deadline = this.clock() + this.drainMillis;
    for (const duty of this.duties.splice(0)) {
      try {
        duty.suspend();
        duty.close?.();
      } catch {
        // a duty's failure never blocks the drain
      }
    }
    for (const handle of this.bound.splice(0)) {
      handle();
    }
    this.peer.close();
    if (this.clock() > deadline) {
      this.log("drain exceeded its bound");
    }
    this.log(`agentspaces-node ${this.peer.identity.peerId} stopped`);
  }
}
