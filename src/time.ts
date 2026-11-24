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
 * Time for the TypeScript peer (event-loop parity, SPEC v0.1.36 §9.5; srad/agentspaces-event-loop.md §3.1 to §3.9).
 *
 * - **Two time bases.** Stamps, leases and expiries a peer reads stay on the wall clock (`Peer.now`, `Platform.clock`);
 *   local periods (how long since the last anti-entropy round, a backoff, a timer's lateness) run on a monotonic
 *   clock, so a wall step neither drops a view nor keeps a silent member ({@link monotonicOf}).
 * - **Virtual time for tests** ({@link VirtualTime}): one object that is the wall clock, the monotonic clock and the
 *   {@link TimerPort}; a test advances it and every due timer runs in time order, with no sleep and no real timer.
 * - **Due work** ({@link DueLoop}): one sequential loop per peer or host that runs each of its tasks when the task's
 *   own deadline falls due or when something wakes it, and sleeps in between, in place of a fixed-rate ticker. A task
 *   returns its next deadline; running a task early is always safe (it judges its own state), which is what a wake,
 *   the backstop and a wall step rely on.
 * - **The watchdog** ({@link Watchdog}): a check from outside each loop's own timer, on a fixed 2 s tick, that the
 *   loop keeps running; a loop that lost its timer or stopped running its due tasks is re-armed without losing them.
 *
 * Nothing here touches the wire.
 */

import type { Repeating, TimerPort } from "./platform.js";

/** The runtime's monotonic milliseconds: `performance.now()` where it exists (every runtime this core targets). */
export function monotonicMillis(): number {
  const perf = (globalThis as { performance?: { now(): number } }).performance;
  return perf !== undefined ? perf.now() : Date.now();
}

/** The monotonic clock of a timer port: its own `now()` (a virtual clock's), else the runtime's. */
export function monotonicOf(timers: TimerPort): () => number {
  return typeof timers.now === "function" ? () => timers.now!() : monotonicMillis;
}

/** A change of more than this in (wall - monotonic) between two looks is a wall step (SPEC §9.5; TS-6). */
export const WALL_STEP_MILLIS = 1_000;

/**
 * Notices wall-clock steps: an NTP step either way, or a suspend, which the monotonic clock does not count on macOS or
 * Linux. A slew (at most 500 ppm) is not a step.
 */
export class WallStepDetector {
  private offset: number;

  constructor(private readonly wall: () => number, private readonly mono: () => number) {
    this.offset = wall() - mono();
  }

  /** The step since the last look, in milliseconds (positive forward), or 0 when the clocks moved together. */
  look(): number {
    const offset = this.wall() - this.mono();
    const step = offset - this.offset;
    this.offset = offset;
    return Math.abs(step) > WALL_STEP_MILLIS ? step : 0;
  }
}

// ------------------------------------------------------------------------------------------------- virtual time

type VirtualTimer = { id: number; at: number; seq: number; fn: () => void; period: number | null; stopped: boolean };

/**
 * Virtual time (EL-C-08 for this client): the wall clock, the monotonic clock and the timers of one test, in one
 * object. Nothing runs until the test calls {@link advance} (or {@link advanceAsync} for code that awaits between
 * timers); then every timer due within the span runs in time order, each at its own instant, timers scheduled by a
 * run included. {@link stepWall} moves the wall clock alone, as an NTP step or a suspend does.
 *
 *     const time = new VirtualTime();
 *     const peer = new Peer(identity, group, time.wall);
 *     peer.timers = time;
 *     time.advance(30_000);
 */
export class VirtualTime implements TimerPort {
  private mono: number;
  private wallOffset: number;
  private seq = 0;
  private nextId = 1;
  private readonly timers = new Map<number, VirtualTimer>();
  /** Timer runs so far, for tests that assert an idle peer wakes rarely. */
  runs = 0;

  constructor(startWallMillis = Date.UTC(2026, 10, 22, 12, 0, 0), startMonoMillis = 1_000) {
    this.mono = startMonoMillis;
    this.wallOffset = startWallMillis - startMonoMillis;
  }

  /** The monotonic clock (the TimerPort's `now`). */
  now(): number {
    return this.mono;
  }

  /** The wall clock, bound, for `new Peer(identity, group, time.wall)` and `platform({ clock: time.wall })`. */
  readonly wall = (): number => this.mono + this.wallOffset;

  setTimeout(fn: () => void, millis: number): unknown {
    const id = this.nextId++;
    this.timers.set(id, { id, at: this.mono + Math.max(0, millis), seq: this.seq++, fn, period: null, stopped: false });
    return id;
  }

  clearTimeout(handle: unknown): void {
    if (typeof handle === "number") {
      this.timers.delete(handle);
    }
  }

  every(periodMillis: number, fn: () => void): Repeating {
    const period = Math.max(1, periodMillis);
    const id = this.nextId++;
    const timer: VirtualTimer = { id, at: this.mono + period, seq: this.seq++, fn, period, stopped: false };
    this.timers.set(id, timer);
    const timers = this.timers;
    return {
      lastDriftMillis: 0,
      lateRuns: 0,
      stop(): void {
        timer.stopped = true;
        timers.delete(id);
      },
    };
  }

  /** Timers armed and not yet run (repeating ones count once). */
  pending(): number {
    return this.timers.size;
  }

  /** The instant of the earliest armed timer on the monotonic clock, or null. */
  nextAt(): number | null {
    let best: number | null = null;
    for (const t of this.timers.values()) {
      best = best === null ? t.at : Math.min(best, t.at);
    }
    return best;
  }

  /** Moves both clocks `millis` forward, running each timer due within the span at its instant; returns the runs. */
  advance(millis: number): number {
    const until = this.mono + Math.max(0, millis);
    let ran = 0;
    for (;;) {
      const next = this.earliest(until);
      if (next === null) {
        break;
      }
      this.mono = Math.max(this.mono, next.at);
      this.fire(next);
      ran += 1;
    }
    this.mono = until;
    return ran;
  }

  /**
   * As {@link advance}, but lets promise continuations run after each timer and at each step of `stepMillis`, for code
   * that awaits between timers (a take's settle window, a binder's loop).
   */
  async advanceAsync(millis: number, stepMillis = 50): Promise<number> {
    const until = this.mono + Math.max(0, millis);
    let ran = 0;
    for (;;) {
      await flushMicrotasks();
      const horizon = Math.min(until, this.mono + Math.max(1, stepMillis));
      const next = this.earliest(horizon);
      if (next === null) {
        if (this.mono >= until) {
          break;
        }
        this.mono = horizon;
        continue;
      }
      this.mono = Math.max(this.mono, next.at);
      this.fire(next);
      ran += 1;
    }
    await flushMicrotasks();
    return ran;
  }

  /** Moves the wall clock alone by `millis` (forward or back), as an NTP step or a suspend does; no timer runs. */
  stepWall(millis: number): void {
    this.wallOffset += millis;
  }

  private earliest(until: number): VirtualTimer | null {
    let best: VirtualTimer | null = null;
    for (const t of this.timers.values()) {
      if (t.at <= until && (best === null || t.at < best.at || (t.at === best.at && t.seq < best.seq))) {
        best = t;
      }
    }
    return best;
  }

  private fire(timer: VirtualTimer): void {
    if (timer.period === null) {
      this.timers.delete(timer.id);
    } else {
      timer.at += timer.period;
      timer.seq = this.seq++;
    }
    this.runs += 1;
    timer.fn();
  }
}

/** Lets queued promise continuations run (a few turns of the microtask queue and one macrotask turn). */
export async function flushMicrotasks(): Promise<void> {
  for (let i = 0; i < 8; i++) {
    await Promise.resolve();
  }
}

// ------------------------------------------------------------------------------------------------------ due work

/** A task of a {@link DueLoop}: runs at `now` (monotonic) and returns its next deadline, or null to wait for a wake. */
export type DueRun = (nowMono: number) => number | null;

type DueTask = { name: string; run: DueRun; due: number | null; runs: number; failures: number; lastRunAt: number | null };

/** What a loop reports about itself (the watchdog's and an operator's view). */
export type LoopHealth = {
  /** Whether the loop is started and not stopped. */
  running: boolean;
  /** Task runs so far, and timer wakes of the loop. */
  runs: number;
  wakes: number;
  /** Runs that threw; the task was retried after {@link DueLoop.retryMillis}. */
  failures: number;
  /** How late the loop's last timer wake fired against the deadline it was armed for, in milliseconds. */
  lastLateMillis: number;
  /** Backstop wakes that found a task past its deadline and not run: a missed wake, which is a bug. */
  missedWakes: number;
  /** Times the watchdog re-armed this loop because its timer had not fired long past its deadline. */
  reinitialised: number;
  /** Wall steps the loop saw (each asked every task again). */
  wallSteps: number;
  /** Watchdog ticks that came back far later than their period: a suspend the monotonic clock counted, or a freeze. */
  lateWakes: number;
  /** The tasks whose deadline passed more than the watchdog's grace ago without a run. */
  overdue: string[];
  /** The earliest armed deadline on the monotonic clock, or null when idle. */
  nextDue: number | null;
};

export type DueLoopOptions = {
  /** The wall clock, for the wall-step check; `Date.now` by default. */
  wall?: () => number;
  /** The longest the loop sleeps whatever its tasks say (the backstop); 60 s by default. */
  backstopMillis?: number;
  /** How long after a failed run the task runs again; 1 s by default. */
  retryMillis?: number;
  /** Called once per wall step (forward positive) before every task is asked again. */
  onWallStep?: (stepMillis: number) => void;
  /**
   * Called when the watchdog's tick came back `lateMillis` past its period ({@link LATE_WAKE_MILLIS} or more): the
   * process was suspended on a runtime whose monotonic clock counts the suspend (no wall step shows), or frozen.
   */
  onLateWake?: (lateMillis: number) => void;
  /** Where a failed run is reported; nowhere by default. */
  log?: (line: string) => void;
  /** A name for logs. */
  name?: string;
};

/**
 * Due work for one peer or host (srad/agentspaces-event-loop.md §3.2, §3.3; DW-1): a sequential loop over named
 * tasks, each run when its deadline falls due or when {@link wake} asks it, on one timer armed at the earliest
 * deadline (never later than the backstop). A run that is not due must do nothing and return its deadline, so running
 * a task early is always safe. The loop checks for a wall step on every wake and asks every task again on one, since
 * tasks anchor deadlines on wall-clock expiries.
 *
 * The loop is a single sequential process: its runs never overlap (a run scheduled while another runs waits for it),
 * and it holds no state another loop reads.
 */
export class DueLoop {
  readonly backstopMillis: number;
  readonly retryMillis: number;
  private readonly tasks = new Map<string, DueTask>();
  private readonly mono: () => number;
  private readonly steps: WallStepDetector;
  private handle: unknown = null;
  private armedFor: number | null = null;
  private running = false;
  private stopped = false;
  private wakeQueued = false;
  private stats = { runs: 0, wakes: 0, failures: 0, lastLateMillis: 0, missedWakes: 0, reinitialised: 0, wallSteps: 0,
    lateWakes: 0 };

  constructor(readonly timers: TimerPort, private readonly options: DueLoopOptions = {}) {
    this.mono = monotonicOf(timers);
    this.backstopMillis = options.backstopMillis ?? 60_000;
    this.retryMillis = options.retryMillis ?? 1_000;
    this.steps = new WallStepDetector(options.wall ?? Date.now, this.mono);
  }

  /** The loop's monotonic clock. */
  now(): number {
    return this.mono();
  }

  /** Adds (or replaces) a task, due at `firstDue` (now by default; null waits for a wake). */
  add(name: string, run: DueRun, firstDue: number | null = this.mono()): this {
    this.tasks.set(name, { name, run, due: firstDue, runs: 0, failures: 0, lastRunAt: null });
    this.arm();
    return this;
  }

  remove(name: string): void {
    this.tasks.delete(name);
    this.arm();
  }

  has(name: string): boolean {
    return this.tasks.has(name);
  }

  /** Asks a task (every task with no name) to run at once, on the next turn of the runtime's timers. */
  wake(name?: string): void {
    if (this.stopped) {
      return;
    }
    if (this.paused) {
      const now = this.mono();
      for (const task of this.tasks.values()) {
        if (name === undefined || task.name === name) {
          task.due = task.due === null ? now : Math.min(task.due, now); // runs on resume
        }
      }
      return;
    }
    const now = this.mono();
    for (const task of this.tasks.values()) {
      if (name === undefined || task.name === name) {
        task.due = task.due === null ? now : Math.min(task.due, now);
      }
    }
    if (!this.wakeQueued && !this.running) {
      this.wakeQueued = true;
      this.clear();
      this.armedFor = now;
      this.handle = this.timers.setTimeout(() => this.onTimer(), 0);
    }
  }

  /** Moves a task's deadline (earlier or later); null waits for a wake. */
  reschedule(name: string, due: number | null): void {
    const task = this.tasks.get(name);
    if (task !== undefined) {
      task.due = due;
      this.arm();
    }
  }

  /** The task's current deadline on the monotonic clock, or null. */
  dueOf(name: string): number | null {
    return this.tasks.get(name)?.due ?? null;
  }

  /** Runs every task now, whatever its deadline (a hand-driven tick; safe by DW-1). */
  runAll(): void {
    const now = this.mono();
    for (const task of this.tasks.values()) {
      task.due = now;
    }
    this.runDue();
  }

  /** Stops the loop for good: its timer is cleared and nothing runs again. */
  stop(): void {
    this.stopped = true;
    this.clear();
  }

  get isStopped(): boolean {
    return this.stopped;
  }

  private paused = false;

  /** Holds the loop's timer, keeping its tasks and their deadlines (a peer that closes and may dial again). */
  pause(): void {
    this.paused = true;
    this.clear();
    this.wakeQueued = false;
  }

  /** Re-arms a paused loop at its earliest deadline; every deadline already past runs at once. */
  resume(): void {
    if (!this.paused || this.stopped) {
      return;
    }
    this.paused = false;
    this.steps.look(); // a pause is no wall step
    this.arm();
  }

  get isPaused(): boolean {
    return this.paused;
  }

  /** The loop's own report (the watchdog's view), judged now. */
  health(graceMillis = 2 * WATCHDOG_PERIOD_MILLIS): LoopHealth {
    const now = this.mono();
    const overdue = [...this.tasks.values()]
      .filter((t) => t.due !== null && now - t.due > graceMillis)
      .map((t) => t.name);
    return { running: !this.stopped && !this.paused, ...this.stats, overdue, nextDue: this.nextDue() };
  }

  /**
   * The watchdog's check (§3.9): a loop whose earliest deadline passed more than `graceMillis` ago without a run lost
   * its timer or stopped running; it is re-armed at once, its tasks kept. Returns whether it had to.
   */
  check(graceMillis = 2 * WATCHDOG_PERIOD_MILLIS): boolean {
    if (this.stopped || this.paused || this.running) {
      return false;
    }
    const now = this.mono();
    if (this.noticeWallStep(now)) {
      // A suspend ends with the watchdog's tick, often before the loop's own timer: answer it at once.
      this.clear();
      this.wakeQueued = false;
      this.armedFor = now;
      this.handle = this.timers.setTimeout(() => this.onTimer(), 0);
      return false;
    }
    const next = this.nextDue();
    if (next === null || now - next <= graceMillis) {
      return false;
    }
    this.stats.reinitialised += 1;
    this.options.log?.(`${this.options.name ?? "loop"}: no run ${Math.round(now - next)} ms past its deadline; re-armed`);
    this.clear();
    this.wakeQueued = false;
    this.armedFor = now;
    this.handle = this.timers.setTimeout(() => this.onTimer(), 0);
    return true;
  }

  private nextDue(): number | null {
    let next: number | null = null;
    for (const task of this.tasks.values()) {
      if (task.due !== null) {
        next = next === null ? task.due : Math.min(next, task.due);
      }
    }
    return next;
  }

  private clear(): void {
    if (this.handle !== null) {
      this.timers.clearTimeout(this.handle);
      this.handle = null;
    }
    this.armedFor = null;
  }

  /** Arms the one timer at the earliest deadline, never later than the backstop. */
  private arm(): void {
    if (this.stopped || this.paused || this.running || this.wakeQueued) {
      return;
    }
    const now = this.mono();
    const next = this.nextDue();
    const at = Math.min(next ?? Number.POSITIVE_INFINITY, now + this.backstopMillis);
    if (this.armedFor !== null && this.armedFor === at) {
      return;
    }
    this.clear();
    this.armedFor = at;
    const handle = this.timers.setTimeout(() => this.onTimer(), Math.max(0, at - now));
    unrefIfPossible(handle);
    this.handle = handle;
  }

  private onTimer(): void {
    this.handle = null;
    this.wakeQueued = false;
    if (this.stopped || this.paused) {
      return;
    }
    const now = this.mono();
    this.stats.wakes += 1;
    if (this.armedFor !== null) {
      this.stats.lastLateMillis = Math.max(0, now - this.armedFor);
    }
    const backstop = this.armedFor !== null && (this.nextDue() ?? Number.POSITIVE_INFINITY) > this.armedFor;
    this.armedFor = null;
    if (this.noticeWallStep(now)) {
      // every task is due again
    } else if (backstop) {
      // Woken by the backstop with nothing due: run nothing. A task that was due and not run is a missed wake.
      for (const task of this.tasks.values()) {
        if (task.due !== null && task.due < now - this.backstopMillis) {
          this.stats.missedWakes += 1;
        }
      }
    }
    this.runDue();
  }

  /**
   * The watchdog's tick came back `lateMillis` past its period: reports it, asks every task again (their deadlines
   * passed in the gap) and re-arms at once. A wall step seen on the same look was already answered.
   */
  lateWake(lateMillis: number): void {
    if (this.stopped || this.paused) {
      return;
    }
    this.stats.lateWakes += 1;
    try {
      this.options.onLateWake?.(lateMillis);
    } catch (e) {
      this.options.log?.(`${this.options.name ?? "loop"}: late-wake hook failed: ${String(e)}`);
    }
    if (this.running) {
      return; // the run in progress re-arms on its way out
    }
    const now = this.mono();
    for (const task of this.tasks.values()) {
      task.due = task.due === null ? null : Math.min(task.due, now);
    }
    this.clear();
    this.wakeQueued = false;
    this.armedFor = now;
    this.handle = this.timers.setTimeout(() => this.onTimer(), 0);
  }

  /** Looks for a wall step; on one, reports it and makes every task due now (§3.6). Returns whether it saw one. */
  private noticeWallStep(now: number): boolean {
    const step = this.steps.look();
    if (step === 0) {
      return false;
    }
    this.stats.wallSteps += 1;
    try {
      this.options.onWallStep?.(step);
    } catch (e) {
      this.options.log?.(`${this.options.name ?? "loop"}: wall-step hook failed: ${String(e)}`);
    }
    for (const task of this.tasks.values()) {
      task.due = now; // a wall step asks every deadline anchored to wall time again
    }
    return true;
  }

  private runDue(): void {
    if (this.running) {
      return;
    }
    this.running = true;
    try {
      // A task a run makes due (a wake inside a run) runs in the same pass, at most a bounded number of times.
      for (let pass = 0; pass < 4; pass++) {
        const now = this.mono();
        const due = [...this.tasks.values()].filter((t) => t.due !== null && t.due <= now);
        if (due.length === 0) {
          break;
        }
        for (const task of due) {
          if (this.tasks.get(task.name) !== task || this.stopped) {
            continue;
          }
          task.due = null;
          task.runs += 1;
          task.lastRunAt = now;
          this.stats.runs += 1;
          let next: number | null;
          try {
            next = task.run(now);
          } catch (e) {
            task.failures += 1;
            this.stats.failures += 1;
            this.options.log?.(`${this.options.name ?? "loop"}: task ${task.name} failed: `
              + `${e instanceof Error ? e.message : String(e)}`);
            next = now + this.retryMillis;
          }
          if (task.due === null || (next !== null && next < task.due)) {
            task.due = next;
          }
        }
      }
    } finally {
      this.running = false;
      this.wakeQueued = false;
      if (!this.stopped) {
        this.arm();
      }
    }
  }
}

/** On Node a timer must not keep the process alive by itself; elsewhere timers have no unref. */
function unrefIfPossible(handle: unknown): void {
  const maybe = handle as { unref?: () => void } | null;
  if (maybe !== null && typeof maybe === "object" && typeof maybe.unref === "function") {
    maybe.unref();
  }
}

// ------------------------------------------------------------------------------------------------------ watchdog

/** The watchdog's fixed tick (srad/agentspaces-event-loop.md §3.9: every 2 s, from outside the loops). */
export const WATCHDOG_PERIOD_MILLIS = 2_000;
/**
 * A watchdog tick this late past its period is a late wake: longer than the 30 s keepalive bound a 0.6.0 member judges
 * by, so the members have most likely dropped this peer (as a forward wall step of that length, SPEC §9.5).
 */
export const LATE_WAKE_MILLIS = 30_000;

/**
 * The watchdog (§3.9, owner feedback of 2026-11-21): a redundant check, on a fixed tick and outside each loop's own
 * timer, that every registered {@link DueLoop} keeps running its due work; one that lost its timer or stopped is
 * re-armed without losing its tasks ({@link DueLoop.check}). A JavaScript runtime runs one thread, so a loop wedged
 * inside a run cannot be preempted; the check sees it once the run returns, counts it, and the host's cadence rule
 * (JS-R-06) answers a sustained overrun.
 */
export class Watchdog {
  private readonly loops = new Set<DueLoop>();
  private ticker: Repeating | null = null;
  private readonly mono: () => number;
  private lastCheckAt: number | null = null;
  checks = 0;
  reinitialised = 0;
  /** Ticks that came back {@link LATE_WAKE_MILLIS} or more past their period. */
  lateWakes = 0;

  constructor(private readonly timers: TimerPort, readonly periodMillis = WATCHDOG_PERIOD_MILLIS) {
    this.mono = monotonicOf(timers);
  }

  /** Watches a loop; the watchdog's tick starts with the first loop and stops with the last. */
  watch(loop: DueLoop): () => void {
    this.loops.add(loop);
    if (this.ticker === null) {
      this.ticker = this.timers.every(this.periodMillis, () => this.checkAll());
    }
    return () => this.unwatch(loop);
  }

  unwatch(loop: DueLoop): void {
    this.loops.delete(loop);
    if (this.loops.size === 0 && this.ticker !== null) {
      this.ticker.stop();
      this.ticker = null;
      this.lastCheckAt = null; // a tick that starts again later is no late wake
    }
  }

  /** One check of every watched loop; returns how many it re-armed. */
  checkAll(): number {
    this.checks += 1;
    const now = this.mono();
    const late = this.lastCheckAt === null ? 0 : now - this.lastCheckAt - this.periodMillis;
    this.lastCheckAt = now;
    if (late >= LATE_WAKE_MILLIS) {
      this.lateWakes += 1;
    }
    let rearmed = 0;
    for (const loop of [...this.loops]) {
      if (loop.isStopped) {
        this.loops.delete(loop);
        continue;
      }
      if (loop.isPaused) {
        continue;
      }
      if (late >= LATE_WAKE_MILLIS) {
        loop.lateWake(late); // first: a resume is answered before any re-arm is judged
      }
      if (loop.check(2 * this.periodMillis)) {
        rearmed += 1;
      }
    }
    this.reinitialised += rearmed;
    if (this.loops.size === 0 && this.ticker !== null) {
      this.ticker.stop();
      this.ticker = null;
      this.lastCheckAt = null;
    }
    return rearmed;
  }

  get watched(): number {
    return this.loops.size;
  }
}
