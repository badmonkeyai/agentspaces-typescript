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
 *     aggregate.run(300);                       // ticks on a timer
 *     const value = await aggregate.awaitSettled("load", Settle.after(3, 0.01), 20_000);
 */

import { CborDouble, CborValue, canonicalMap, dumps, loads } from "../cbor.js";
import { instantIso } from "../identity.js";
import * as wire from "../wire.js";
import type { Dict } from "../wire.js";
import type { Pipes } from "./pipes.js";

export const TYPE = "aspace:cap/aggregate";
export type Mode = "avg" | "sum" | "count" | "min" | "max";

/** When an estimate counts as settled: unchanged within `tolerance` for `ticks` consecutive ticks. */
export class Settle {
  static readonly FIRST = new Settle(0, 0);

  constructor(readonly ticks: number, readonly tolerance: number) {
    if (ticks < 0 || tolerance < 0) {
      throw new Error("ticks and tolerance are not negative");
    }
  }

  static after(ticks: number, tolerance: number): Settle {
    return new Settle(ticks, tolerance);
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
  tracks: Map<string, { last: number | null; stable: number; fired: boolean; seen: number }> };

function num(value: CborValue | undefined): number {
  if (value instanceof CborDouble) {
    return value.value;
  }
  if (typeof value === "number") {
    return value;
  }
  if (typeof value === "bigint") {
    return Number(value);
  }
  return Number.NaN;
}

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
  private timer: NodeJS.Timeout | null = null;
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

  /** One protocol round: halve each push-sum mass and push the other half to one sampled member. */
  tick(): void {
    const participants = this.participants();
    if (participants.length === 0) {
      // Mass held is mass kept: halve only when a participant takes the other half.
      this.exchanged = true;
      this.evaluateWatches(this.pipes.members().length === 0);
      return;
    }
    const targets = [participants[Math.floor(Math.random() * participants.length)]!];
    const frames: Dict[] = [];
    for (const [epochId, e] of this.epochs) {
      e.value /= 2;
      e.weight /= 2;
      frames.push(wire.aggregateShareFrame(epochId, e.value, e.weight));
    }
    for (const [epochId, ex] of this.extrema) {
      if (!Number.isNaN(ex.value)) {
        frames.push(wire.aggregateExtremumFrame(epochId, ex.max, ex.value));
      }
    }
    for (const [epochId, members] of this.rosters) {
      frames.push(wire.aggregateRosterFrame(epochId, [...members].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))));
    }
    for (const to of targets) {
      for (const frame of frames) {
        this.pipes.send(to, TYPE, dumps(frame));
      }
    }
    this.exchanged = true;
    this.evaluateWatches(false);
  }

  /** Ticks on a timer until `close()`. */
  run(intervalMillis = 300): void {
    if (this.timer === null) {
      this.timer = setInterval(() => this.tick(), intervalMillis);
    }
  }

  close(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
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
      const close = this.onEstimate((e) => e === epochId, settle, (estimate) => {
        clearTimeout(timer);
        close();
        resolve(estimate.value);
      });
      const timer = setTimeout(() => { close(); resolve(null); }, timeoutMillis);
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
          track = { last: null, stable: 0, fired: false, seen: 0 };
          watch.tracks.set(epochId, track);
        }
        if (track.fired || now === null) {
          continue;
        }
        if (receipts <= track.seen && !alone) {
          continue; // no new evidence: the streak neither grows nor resets
        }
        track.seen = receipts;
        track.stable = watch.settle.stable(track.last, now) ? track.stable + 1 : 0;
        track.last = now;
        if (track.stable >= watch.settle.ticks) {
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
    let frame: Dict;
    try {
      frame = loads(Buffer.from(payload)) as Dict;
    } catch {
      return;
    }
    if (typeof frame !== "object" || frame === null) {
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
    }
    if (share && typeof share["epochId"] === "string") {
      const value = num(share["value"]);
      const weight = num(share["weight"]);
      if (Number.isFinite(value) && Number.isFinite(weight) && weight >= 0) {
        const e = this.epoch(share["epochId"]);
        e.value += value;
        e.weight += weight;
      }
    } else if (extremum && typeof extremum["epochId"] === "string") {
      this.mergeExtremum(extremum["epochId"], Boolean(extremum["max"]), num(extremum["value"]));
    } else if (roster && typeof roster["epochId"] === "string") {
      const members = this.roster(roster["epochId"]);
      for (const m of (roster["members"] as CborValue[]) ?? []) {
        members.add(BigInt(m as number | bigint));
      }
    }
  }
}
