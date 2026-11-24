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
 * The push-sum aggregate (SPEC §8.2, PushSumAggregate) from TypeScript: AVG
 * by push-sum, SUM and COUNT by the gossiped roster, MIN and MAX by extremum
 * frames; estimates, settle rules, and estimate listeners.
 *
 *     const aggregate = new Aggregate(pipes);
 *     aggregate.start("load", 12.5);
 *     aggregate.run();                          // a round every ROUND_PERIOD_MILLIS (1 s), as Java's
 *     const value = await aggregate.awaitSettled("load", Settle.after("5s", 0.01), 20_000);
 *
 * Timing (SPEC v0.1.36 §8, §9.5): a round every second by default, on the peer's timers; an epoch whose estimate has
 * not moved for {@link QUIET_MILLIS} goes quiet (no shares until a share moves it again) and is forgotten after
 * {@link RETENTION_MILLIS} without activity; a settle rule is a span (`Settle.after("40s", tol)`) or a count of
 * rounds (`Settle.after(40, tol)`, read as 40 rounds of one second).
 */

import { CborDouble, canonicalMap, dumps } from "../cbor.js";
import { instantIso } from "../identity.js";
import { AGGREGATE_FRAME, readRecord } from "../records.js";
import * as wire from "../wire.js";
import type { Dict } from "../wire.js";
import type { Pipes } from "./pipes.js";
import { durationMillis } from "../space.js";
import { monotonicMillis } from "../time.js";

export const TYPE = "aspace:cap/aggregate";
export type Mode = "avg" | "sum" | "count" | "min" | "max";

/** One protocol round (Java's PushSumAggregate.ROUND_PERIOD): a share per epoch per second. */
export const ROUND_PERIOD_MILLIS = 1_000;
/** An epoch whose estimate has not moved for this long stops sharing until a share moves it (Java: 30 s). */
export const QUIET_MILLIS = 30_000;
/** An epoch with no activity for this long is forgotten (Java: one hour). */
export const RETENTION_MILLIS = 60 * 60_000;

/**
 * When an estimate counts as settled: present and within `tolerance` of the previous round's value for `ticks`
 * consecutive rounds (the count form, rounds of {@link ROUND_PERIOD_MILLIS}), or, with a span, for that span of time
 * (`spanMillis`, counted in rounds of one second, the span rounded up), in which case an epoch that went quiet settles
 * at its last move plus the span with no further share (SPEC §8, v0.1.36).
 */
export class Settle {
  static readonly FIRST = new Settle(0, 0);

  constructor(readonly ticks: number, readonly tolerance: number, readonly spanMillis: number | null = null) {
    if (ticks < 0 || tolerance < 0 || (spanMillis !== null && !(spanMillis >= 0))) {
      throw new Error("ticks, span and tolerance are not negative");
    }
  }

  /**
   * A span (`"40s"`, `"PT40S"`) settles after that long without a move; a number is the count form, read as that many
   * rounds of one second (Java's `settleTicks`).
   */
  static after(spanOrTicks: number | string, tolerance: number): Settle {
    if (typeof spanOrTicks === "string") {
      return Settle.span(durationMillis(spanOrTicks), tolerance);
    }
    return new Settle(spanOrTicks, tolerance);
  }

  /** The span form in milliseconds. */
  static span(millis: number, tolerance: number): Settle {
    return new Settle(Math.ceil(Math.max(0, millis) / ROUND_PERIOD_MILLIS), tolerance, Math.max(0, millis));
  }

  stable(previous: number | null, current: number): boolean {
    if (previous === null) {
      return false;
    }
    const scale = Math.max(Math.abs(previous), Math.abs(current), 1e-12);
    return Math.abs(current - previous) <= this.tolerance * scale;
  }
}

export type Estimate = { epochId: string; mode: Mode; value: number; ticks: number };

type Watch = { epochs: (id: string) => boolean; settle: Settle; listener: (e: Estimate) => void;
  tracks: Map<string, { last: number | null; stable: number; fired: boolean; seen: number; movedAt: number }> };

/** One node's share of every epoch it joined or heard about. */
export class Aggregate {
  readonly selfToken: bigint;
  exchanged = false;
  private readonly epochs = new Map<string, { value: number; weight: number }>();
  private readonly rosters = new Map<string, Set<bigint>>();
  private readonly extrema = new Map<string, { max: boolean; value: number }>();
  private readonly declared = new Map<string, Mode>();
  private readonly ticks = new Map<string, number>();
  private readonly watches: Watch[] = [];
  private timer: { stop(): void } | null = null;
  /** When each epoch's estimate last moved or a share reached it, on the monotonic clock (quiet and retention). */
  private readonly activeAt = new Map<string, number>();
  private readonly lastEstimate = new Map<string, number | null>();
  /** Epochs forgotten after the retention, and rounds in which a quiet epoch shared nothing. */
  evicted = 0;
  quietRounds = 0;
  /** Frames heard per epoch: the evidence a settle rule needs. */
  private readonly received = new Map<string, number>();

  constructor(readonly pipes: Pipes, advertise = true) {
    this.selfToken = wire.rosterToken(pipes.peer.identity.peerId);
    pipes.onCapability(TYPE, (from, payload) => this.onFrame(from, payload));
    if (advertise) {
      this.advertise();
    }
  }

  /** This node's CapabilityAdvertisement for the aggregate, in Java field order. */
  describe(): Dict {
    const peer = this.pipes.peer;
    const now = peer.now();
    return { id: `aspace://${peer.group}/cap/aggregate/${peer.identity.peerId}`, issuer: peer.identity.peerId,
      group: peer.group, issued: instantIso(now - (now % 1000)), ttl: "PT15M", capabilityType: TYPE,
      version: "0.1", binding: "pipe", parameters: canonicalMap({ modes: "sum,avg,count,min,max" }), costHints: {} };
  }

  /** Publishes the advertisement on the ads stream, so other members' participant rules admit this node. */
  advertise(): void {
    this.pipes.peer.publishAd("CapabilityAdvertisement", this.describe());
  }

  /**
   * The reachable members that advertise the aggregate. A share pushed to a
   * member without one is mass lost (the receiver never mixes it back), so a
   * share goes only to a member whose advertisement is live.
   */
  participants(): string[] {
    const peer = this.pipes.peer;
    const now = peer.now();
    const advertised = new Set([...peer.ads.values()]
      .filter((e) => e.type === "CapabilityAdvertisement" && e.expires > now && e.ad["capabilityType"] === TYPE)
      .map((e) => e.issuer));
    return this.pipes.members().filter((m) => advertised.has(m));
  }

  /** Joins an epoch with this node's value under `mode`. */
  start(epochId: string, value: number, mode: Mode = "avg"): void {
    this.declared.set(epochId, mode);
    this.touch(epochId);
    if (mode === "avg" || mode === "sum") {
      const e = this.epoch(epochId);
      e.value += value;
      e.weight += 1;
    }
    if (mode === "sum" || mode === "count") {
      this.roster(epochId).add(this.selfToken);
    }
    if (mode === "min" || mode === "max") {
      this.mergeExtremum(epochId, mode === "max", value);
    }
  }

  /** The epochs this node joined or heard about. */
  knownEpochIds(): Set<string> {
    return this.knownEpochs();
  }

  /** The monotonic clock of the peer's timers. */
  private mono(): number {
    const peer = this.pipes.peer as { monotonic?: () => number };
    return typeof peer.monotonic === "function" ? peer.monotonic() : monotonicMillis();
  }

  /** Notes activity on an epoch (a start, a share heard, a move of its estimate). */
  private touch(epochId: string): void {
    this.activeAt.set(epochId, this.mono());
  }

  /** Whether an epoch is quiet: its estimate has not moved, and nothing reached it, for QUIET_MILLIS. */
  isQuiet(epochId: string): boolean {
    return this.mono() - (this.activeAt.get(epochId) ?? this.mono()) >= QUIET_MILLIS;
  }

  /** Moves each epoch's activity on a move of its estimate, and forgets the epochs past their retention. */
  private ageEpochs(): void {
    const now = this.mono();
    for (const epochId of this.knownEpochs()) {
      const estimate = this.estimate(epochId);
      const before = this.lastEstimate.get(epochId) ?? null;
      if (!this.activeAt.has(epochId) || (estimate !== null && (before === null || moved(before, estimate)))) {
        this.activeAt.set(epochId, now);
      }
      this.lastEstimate.set(epochId, estimate);
      if (now - this.activeAt.get(epochId)! >= RETENTION_MILLIS) {
        this.forget(epochId);
      }
    }
  }

  private forget(epochId: string): void {
    this.epochs.delete(epochId);
    this.rosters.delete(epochId);
    this.extrema.delete(epochId);
    this.declared.delete(epochId);
    this.ticks.delete(epochId);
    this.received.delete(epochId);
    this.activeAt.delete(epochId);
    this.lastEstimate.delete(epochId);
    for (const watch of this.watches) {
      watch.tracks.delete(epochId);
    }
    this.evicted += 1;
  }

  /** One protocol round: halve each push-sum mass and push the other half to one sampled member. */
  tick(): void {
    this.ageEpochs();
    const participants = this.participants();
    if (participants.length === 0) {
      // Mass held is mass kept: halve only when a participant takes the other half.
      this.exchanged = true;
      this.evaluateWatches(this.pipes.members().length === 0);
      return;
    }
    const targets = [participants[Math.floor(Math.random() * participants.length)]!];
    const frames: Dict[] = [];
    // A quiet epoch shares nothing (SPEC §8, v0.1.17/v0.1.36): its mass stays here until a share moves it again.
    const quiet = new Set([...this.knownEpochs()].filter((id) => this.isQuiet(id)));
    this.quietRounds += quiet.size;
    for (const [epochId, e] of this.epochs) {
      if (quiet.has(epochId)) {
        continue;
      }
      e.value /= 2;
      e.weight /= 2;
      frames.push(wire.aggregateShareFrame(epochId, e.value, e.weight));
    }
    for (const [epochId, ex] of this.extrema) {
      if (!Number.isNaN(ex.value) && !quiet.has(epochId)) {
        frames.push(wire.aggregateExtremumFrame(epochId, ex.max, ex.value));
      }
    }
    for (const [epochId, members] of this.rosters) {
      if (!quiet.has(epochId)) {
        frames.push(wire.aggregateRosterFrame(epochId, [...members].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))));
      }
    }
    for (const to of targets) {
      for (const frame of frames) {
        this.pipes.send(to, TYPE, dumps(frame));
      }
    }
    this.exchanged = true;
    this.evaluateWatches(false);
  }

  /**
   * Runs a round every `intervalMillis` (one second by default, Java's `ROUND_PERIOD`; it was 300 ms, which settled a
   * count-form rule more than three times sooner than Java's) on the peer's timers, until `close()`.
   */
  run(intervalMillis = ROUND_PERIOD_MILLIS): void {
    if (this.timer === null) {
      this.timer = this.pipes.peer.every(intervalMillis, () => this.tick());
    }
  }

  close(): void {
    if (this.timer !== null) {
      this.timer.stop();
      this.timer = null;
    }
  }

  /** The current estimate under the declared mode (AVG for epochs only heard about), or null before any exchange. */
  estimate(epochId: string): number | null {
    const mode = this.declared.get(epochId) ?? "avg";
    if (mode === "avg") {
      return this.mean(epochId);
    }
    if (mode === "sum") {
      const mean = this.mean(epochId);
      const n = this.rosters.get(epochId)?.size ?? 0;
      return mean === null || n === 0 ? null : mean * n;
    }
    if (mode === "count") {
      const n = this.rosters.get(epochId)?.size ?? 0;
      return n === 0 ? null : n;
    }
    const ex = this.extrema.get(epochId);
    return ex === undefined || Number.isNaN(ex.value) ? null : ex.value;
  }

  /** Resolves when the epoch's estimate settles under the rule, on the protocol tick; null at the timeout. */
  awaitSettled(epochId: string, settle: Settle = Settle.FIRST, timeoutMillis = 30_000): Promise<number | null> {
    return new Promise((resolve) => {
      const timers = this.pipes.peer.timers;
      const close = this.onEstimate((e) => e === epochId, settle, (estimate) => {
        timers.clearTimeout(timer);
        close();
        resolve(estimate.value);
      });
      const timer = timers.setTimeout(() => { close(); resolve(null); }, timeoutMillis);
    });
  }

  /** Calls `listener` once per matching epoch when its estimate has settled, evaluated on the tick. Returns a closer. */
  onEstimate(epochs: (id: string) => boolean, settle: Settle, listener: (e: Estimate) => void): () => void {
    const watch: Watch = { epochs, settle, listener, tracks: new Map() };
    this.watches.push(watch);
    return () => {
      const i = this.watches.indexOf(watch);
      if (i >= 0) {
        this.watches.splice(i, 1);
      }
    };
  }

  private knownEpochs(): Set<string> {
    return new Set([...this.epochs.keys(), ...this.rosters.keys(), ...this.extrema.keys(), ...this.declared.keys()]);
  }

  /**
   * A tick counts toward a settle rule only when this node heard a frame for
   * the epoch since the track last judged it: halving keeps the local ratio,
   * so a node nobody pushes to is stable by construction and says nothing
   * about the fleet. A node with nobody to exchange with judges every tick.
   */
  private evaluateWatches(alone: boolean): void {
    for (const epochId of this.knownEpochs()) {
      const ticks = (this.ticks.get(epochId) ?? 0) + 1;
      this.ticks.set(epochId, ticks);
      const now = this.estimate(epochId);
      const receipts = this.received.get(epochId) ?? 0;
      for (const watch of [...this.watches]) {
        if (!watch.epochs(epochId)) {
          continue;
        }
        let track = watch.tracks.get(epochId);
        if (track === undefined) {
          track = { last: null, stable: 0, fired: false, seen: 0, movedAt: this.mono() };
          watch.tracks.set(epochId, track);
        }
        if (track.fired || now === null) {
          continue;
        }
        const span = watch.settle.spanMillis;
        if (receipts <= track.seen && !alone) {
          // No new evidence: the count's streak neither grows nor resets. A span settles on that silence once the
          // epoch was heard at all, at its last move plus the span (SPEC §8, v0.1.36).
          if (span === null || track.last === null || receipts === 0 || this.mono() - track.movedAt < span
              || !watch.settle.stable(track.last, now)) {
            continue;
          }
          track.stable = Math.max(track.stable, 1);
        } else {
          track.seen = receipts;
          const stable = watch.settle.stable(track.last, now);
          track.stable = stable ? track.stable + 1 : 0;
          if (!stable) {
            track.movedAt = this.mono();
          }
          track.last = now;
        }
        if (span !== null ? track.last !== null && this.mono() - track.movedAt >= span && track.stable >= 1
          : track.stable >= watch.settle.ticks) {
          track.fired = true;
          const estimate: Estimate = { epochId, mode: this.declared.get(epochId) ?? "avg", value: now, ticks };
          queueMicrotask(() => watch.listener(estimate));
        }
      }
    }
  }

  private epoch(epochId: string): { value: number; weight: number } {
    let e = this.epochs.get(epochId);
    if (e === undefined) {
      e = { value: 0, weight: 0 };
      this.epochs.set(epochId, e);
    }
    return e;
  }

  private roster(epochId: string): Set<bigint> {
    let r = this.rosters.get(epochId);
    if (r === undefined) {
      r = new Set();
      this.rosters.set(epochId, r);
    }
    return r;
  }

  private mean(epochId: string): number | null {
    const e = this.epochs.get(epochId);
    return e === undefined || e.weight === 0 || !this.exchanged ? null : e.value / e.weight;
  }

  private mergeExtremum(epochId: string, max: boolean, value: number): void {
    const ex = this.extrema.get(epochId);
    if (ex === undefined) {
      this.extrema.set(epochId, { max, value });
    } else if (Number.isNaN(ex.value) || (ex.max ? value > ex.value : value < ex.value)) {
      ex.value = value;
    }
  }

  private onFrame(_from: string, payload: Uint8Array): void {
    // HLC round seven, 2026-11-08: a frame decodes as Java's fromWire reads it, under its annex I
    // schema and the canonical-bytes rule, or it is dropped unheard
    const frame = readRecord(payload, AGGREGATE_FRAME);
    if (frame === null) {
      return;
    }
    this.exchanged = true;
    const share = frame["share"] as Dict | null;
    const extremum = frame["extremum"] as Dict | null;
    const roster = frame["roster"] as Dict | null;
    const heard = [share, extremum, frame["histogram"] as Dict | null, roster]
      .find((part) => part && typeof part["epochId"] === "string");
    if (heard) {
      const id = String(heard["epochId"]);
      this.received.set(id, (this.received.get(id) ?? 0) + 1);
      if (share !== null && share !== undefined) {
        this.touch(id); // a share moves the epoch: it shares again (quiet ends on the first activity)
      }
    }
    if (share && typeof share["epochId"] === "string") {
      const value = (share["value"] as CborDouble).value;
      const weight = (share["weight"] as CborDouble).value;
      if (Number.isFinite(value) && Number.isFinite(weight) && weight >= 0) {
        const e = this.epoch(share["epochId"]);
        e.value += value;
        e.weight += weight;
      }
    } else if (extremum && typeof extremum["epochId"] === "string") {
      this.mergeExtremum(extremum["epochId"], extremum["max"] as boolean, (extremum["value"] as CborDouble).value);
    } else if (roster && typeof roster["epochId"] === "string" && roster["members"] !== null) {
      const members = this.roster(roster["epochId"]);
      for (const m of roster["members"] as Array<number | bigint>) {
        members.add(BigInt(m));
      }
    }
  }
}

/** Whether an estimate moved between two rounds (relative, absolute below 1e-9, as the settle rule judges). */
function moved(previous: number, current: number): boolean {
  const scale = Math.max(Math.abs(previous), Math.abs(current), 1e-9);
  return Math.abs(current - previous) > 1e-9 * scale;
}
