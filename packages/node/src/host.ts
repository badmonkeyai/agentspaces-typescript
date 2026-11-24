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
 * Node process that listens on `tcp` and `ws`, dials its seeds, runs its
 * housekeeping as due work on its peer's loop (and ticks at its period while
 * it carries duties, reporting its true cadence to them), serves
 * anti-entropy and relays rumors through the core `Peer`, advertises its
 * endpoints and `js.residency=service`, drops to visitor duties while its
 * tick drifts and takes them back when it recovers, and drains on `SIGTERM`
 * within a bound.
 */

import { Identity, Peer, Seed } from "@agentspaces/client";
import type { LoopHealth } from "@agentspaces/client";
import type { ReplicationOptions } from "@agentspaces/client";
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
  /** The wall clock (stamps and expiries); the drift rule reads the peer's monotonic clock. */
  clock?: () => number;
} & ReplicationOptions;

/** Consecutive drifting ticks before the host drops to visitor duties, and the quiet span that restores them. */
export const DRIFT_TICKS = 3;
export const DRIFT_FACTOR = 2;
export const RECOVERY_MILLIS = 60_000;
/** How often the host runs an anti-entropy round, and re-advertises itself (half its ten-minute lease), by time. */
export const ANTI_ENTROPY_MILLIS = 10_000;
export const INTRODUCE_MILLIS = 300_000;
/** The host's work on its peer's loop. */
export const HOST_TASK = "service-host";

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
  private started = false;
  private inFlight: Promise<void> | null = null;
  private nextAntiEntropyAt = 0;
  private nextIntroduceAt = 0;
  private unhookMembers: (() => void) | null = null;
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
    this.peer.configureReplication(options); // audit, auditBudget and horizon (srad/replication-by-entry.md §7.2)
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
    if (this.duties.length === 1) {
      this.lastTickAt = this.peer.monotonic(); // the cadence is judged from here: the idle host's long sleeps were no drift
    }
    if (this.started) {
      this.peer.loop.wake(HOST_TASK); // a duty ticks at the host's period from now on
    }
  }

  /** The host loop's report (due work on the peer's loop, watched by the watchdog): runs, lateness, re-arms. */
  loopHealth(): LoopHealth {
    return this.peer.loop.health();
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
    // The cadence rule is a local period: judged on the monotonic clock (SPEC v0.1.36 §9.5), so a wall step is no late
    // tick, and a step back does not hold the recovery off for its length.
    this.lastTickAt = this.peer.monotonic();
    const mono = this.peer.monotonic();
    this.nextAntiEntropyAt = mono + ANTI_ENTROPY_MILLIS;
    this.nextIntroduceAt = mono + INTRODUCE_MILLIS;
    this.started = true;
    // Due work, not a fixed-rate ticker (SPEC v0.1.36 §9.5): the host runs when a member's advertisement lapses, an
    // anti-entropy round or the advertisement falls due, or the view changes; a host that carries duties (a Raft
    // voter, whose heartbeat is its base period) runs every tickMillis, as Java's ordered-log nodes are a registered
    // exception to the idle-wake goal.
    this.peer.loop.add(HOST_TASK, (now) => this.runDue(now));
    this.unhookMembers = this.peer.onMembersChanged(() => this.peer.loop.wake(HOST_TASK));
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
    const now = this.peer.monotonic();
    if (this.duties.length > 0) {
      this.observeCadence(now); // the cadence is the duties' period; an idle host sleeps between due runs
    }
    this.ticks += 1;
    this.housekeeping();
    for (const duty of this.duties) {
      try {
        await duty.tick?.();
      } catch (e) {
        this.log(`duty tick failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }

  /** Lapsed members, then the anti-entropy round and the advertisement when due by time (EL-P-07). */
  private housekeeping(): void {
    this.peer.expireMembers();
    const mono = this.peer.monotonic();
    if (mono >= this.nextAntiEntropyAt) {
      // Paced by time: counted in ticks, a host whose tick drifted ran its rounds that much less often.
      this.nextAntiEntropyAt = Math.max(this.nextAntiEntropyAt + ANTI_ENTROPY_MILLIS, mono + 1);
      this.peer.antiEntropyRound();
    }
    if (mono >= this.nextIntroduceAt) {
      this.nextIntroduceAt = Math.max(this.nextIntroduceAt + INTRODUCE_MILLIS, mono + 1);
      this.peer.introduce();
    }
  }

  /** One run on the loop: the host's tick (never two at once), then its next deadline. */
  private runDue(now: number): number | null {
    if (this.inFlight === null) {
      this.inFlight = this.tick().finally(() => { this.inFlight = null; });
    } else {
      // The previous run's duties are still awaited: the housekeeping runs, the duties wait for the next period, and
      // the loop never re-arms at a deadline already past (which would spin).
      this.housekeeping();
      return now + this.tickMillis;
    }
    if (this.duties.length > 0) {
      return now + this.tickMillis;
    }
    const expiry = this.peer.nextMemberExpiry();
    const lapse = expiry === null ? Number.POSITIVE_INFINITY
      : now + Math.max(this.tickMillis, expiry - this.peer.now() + 1);
    return Math.min(this.nextAntiEntropyAt, this.nextIntroduceAt, lapse);
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
    if (this.started) {
      this.started = false;
      this.peer.loop.remove(HOST_TASK);
      this.unhookMembers?.();
      this.unhookMembers = null;
    }
    if (this.signals) {
      process.removeListener("SIGTERM", this.signalHandler);
      process.removeListener("SIGINT", this.signalHandler);
    }
    const deadline = this.peer.monotonic() + this.drainMillis;
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
    if (this.peer.monotonic() > deadline) {
      this.log("drain exceeded its bound");
    }
    this.log(`agentspaces-node ${this.peer.identity.peerId} stopped`);
  }
}
