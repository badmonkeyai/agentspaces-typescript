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
 * The page side of the resident host (srad/agentspaces-js.md JS-R-02, §6.2
 * `PortBridge`): `connect` starts or joins the worker, says hello, asks the
 * browser to persist the origin's storage, and returns a {@link BrowserHost}
 * whose spaces carry the core's verbs over the port. Templates stay the
 * core's `Template` (function matchers included): the host filters by
 * schema and the page judges the rest, and a take claims the exact entry
 * the page chose, so what the page matched is what it holds. The page tells
 * the host when it hides and returns (`pagehide`, `pageshow`, `freeze`,
 * `resume`) and beats while attached, which is what the host's pause rule
 * (JS-R-03) runs on.
 */

import { Emitter, Template, cbor, durationMillis, groupIdFromFounding, schemaOf, toPayload } from "@agentspaces/client";
import type { Entry, EventKind, Residency, SpaceEvent } from "@agentspaces/client";
import {
  Answer, Envelope, HostConfig, HostState, PortLike, Push, Request, WireEntry, packMap, token, unpackMap,
} from "./protocol.js";

type Dict = { [key: string]: cbor.CborValue };

export type ConnectOptions = Omit<HostConfig, "group"> & {
  /** The GroupID, or `founding` for the literal-founding form (`groupIdFromFounding`). */
  group?: string;
  founding?: string;
  /** The worker script: `new URL("./worker.js", import.meta.url)` under a bundler, or a served path. */
  worker: string | URL;
  /** How the worker script is loaded; `module` by default. */
  workerType?: "module" | "classic";
  /** A SharedWorker when the browser has one (the default); `false` forces a dedicated Worker. */
  shared?: boolean;
  /** The SharedWorker's name; `agentspaces:<group>` by default, so one group is one worker per origin. */
  name?: string;
  /** Ask `navigator.storage.persist()` for the origin; on by default. */
  persist?: boolean;
  /** How often the page beats; 5 s by default. */
  beatMillis?: number;
  /** How long `connect` waits for the host to be up and dialled; 30 s by default. */
  helloTimeoutMillis?: number;
};

interface WindowLike {
  addEventListener(type: string, listener: (event: { persisted?: boolean }) => void): void;
  removeEventListener(type: string, listener: (event: { persisted?: boolean }) => void): void;
}

type ErrorEventLike = { message?: string; filename?: string; lineno?: number };
type WorkerHandle = { port: PortLike; terminate: () => void; onerror: (listener: (error: Error) => void) => void };

function describe(event: ErrorEventLike | unknown): Error {
  const e = (event ?? {}) as ErrorEventLike;
  const where = e.filename ? ` (${e.filename}:${e.lineno ?? "?"})` : "";
  return new Error(`the worker script failed: ${e.message ?? "no message"}${where}`);
}

function spawn(options: ConnectOptions, group: string): { handle: WorkerHandle; shared: boolean } {
  const g = globalThis as unknown as {
    SharedWorker?: new (url: string, options: { type: string; name: string }) =>
      { port: PortLike & { start(): void }; onerror: ((event: unknown) => void) | null };
    Worker?: new (url: string, options: { type: string }) =>
      PortLike & { terminate(): void; onerror: ((event: unknown) => void) | null };
  };
  const url = String(options.worker);
  const type = options.workerType ?? "module";
  const shared = (options.shared ?? true) && typeof g.SharedWorker === "function";
  if (shared) {
    const worker = new g.SharedWorker!(url, { type, name: options.name ?? `agentspaces:${group}` });
    worker.port.start();
    return { shared: true, handle: { port: worker.port, terminate: () => worker.port.close?.(),
      onerror: (listener) => { worker.onerror = (event) => listener(describe(event)); } } };
  }
  if (typeof g.Worker !== "function") {
    throw new Error("this runtime has neither SharedWorker nor Worker; the resident host needs one");
  }
  const worker = new g.Worker(url, { type });
  return { shared: false, handle: { port: worker, terminate: () => worker.terminate(),
    onerror: (listener) => { worker.onerror = (event) => listener(describe(event)); } } };
}

/**
 * Starts (or joins) the resident host for `group` and attaches this page to it. Resolves once the
 * host holds its lock and has dialled a seed; rejects naming the lock when another host holds
 * the identity in this origin, or with the dial's failure.
 */
export async function connect(options: ConnectOptions): Promise<BrowserHost> {
  const group = options.group ?? (options.founding !== undefined ? groupIdFromFounding(options.founding) : null);
  if (group === null) {
    throw new Error("connect needs a group or a founding");
  }
  const { handle, shared } = spawn(options, group);
  const host = new BrowserHost(handle, options, group, shared);
  try {
    await host.hello();
  } catch (e) {
    host.dispose();
    throw e;
  }
  return host;
}

/** A page's handle on the resident host: the host's identity and state, and its spaces. */
export class BrowserHost extends Emitter {
  readonly pageId = token();
  /** Whether the host runs in a SharedWorker shared with the origin's other pages. */
  readonly shared: boolean;
  /** The outcome of `navigator.storage.persist()`: granted, refused, or `null` while unanswered or where the API is absent. */
  persisted: boolean | null = null;
  state: HostState | null = null;
  private nextId = 1;
  private readonly pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>();
  private readonly subscriptions = new Map<number, RemoteSubscription<unknown>>();
  private readonly config: HostConfig;
  private active = true;
  private beat: unknown = null;
  private closed = false;
  private readonly lifecycle: Array<[string, (event: { persisted?: boolean }) => void]> = [];

  constructor(private readonly handle: WorkerHandle, private readonly options: ConnectOptions,
              readonly group: string, shared: boolean) {
    super();
    this.shared = shared;
    const { worker: _worker, workerType: _type, shared: _shared, name: _name, persist: _persist,
      beatMillis: _beat, helloTimeoutMillis: _hello, founding: _founding, ...config } = options;
    this.config = { ...config, group };
    handle.port.onmessage = (event) => this.onMessage(event.data);
    handle.port.onmessageerror = () => undefined;
  }

  get peerId(): string {
    return this.state?.peerId ?? "";
  }

  /** The host's residency now: `resident`, or `visitor` while its tick drifts (JS-R-06). */
  get residency(): Residency {
    return this.state?.residency ?? "resident";
  }

  /** The host's own token: the same across pages of one worker, new after the worker restarts. */
  get instance(): string {
    return this.state?.instance ?? "";
  }

  get paused(): boolean {
    return this.state?.paused ?? true;
  }

  get connected(): boolean {
    return this.state?.connected ?? false;
  }

  /** @internal the first exchange: configure or join the host, then watch the page's lifecycle. */
  async hello(): Promise<void> {
    this.askPersistence();
    this.active = true; // a hidden page is still active: only pagehide and freeze pause the host (JS-R-03)
    const timeout = this.options.helloTimeoutMillis ?? 30_000;
    const failure = new Promise<never>((_, reject) => this.handle.onerror(reject));
    this.state = await Promise.race([
      this.request({ t: "hello", config: this.config, pageId: this.pageId, active: this.active }, timeout),
      failure,
    ]) as HostState;
    this.watchLifecycle();
    const beatMillis = this.options.beatMillis ?? 5000;
    this.beat = globalThis.setInterval(() => {
      this.request({ t: "beat", active: this.active }).catch(() => undefined);
    }, beatMillis);
  }

  /**
   * Asks the browser to persist the origin's storage, never waiting on the answer: Firefox puts
   * the question to the user, and a page must not hang on a prompt. The answer lands in
   * `persisted` and as a `"persisted"` event.
   */
  private askPersistence(): void {
    const storage = (globalThis as { navigator?: { storage?: { persist?: () => Promise<boolean> } } }).navigator?.storage;
    if (this.options.persist === false || typeof storage?.persist !== "function") {
      return;
    }
    storage.persist.call(storage).then((granted) => {
      this.persisted = granted;
      this.emit("persisted", granted);
    }, () => {
      this.persisted = false;
      this.emit("persisted", false);
    });
  }

  private watchLifecycle(): void {
    const w = globalThis as unknown as WindowLike;
    if (typeof w.addEventListener !== "function") {
      return;
    }
    const away = (event: { persisted?: boolean }): void => {
      this.active = false;
      this.request({ t: "activity", active: false }).catch(() => undefined);
      if (event.persisted === false) {
        this.request({ t: "detach" }).catch(() => undefined); // the page is going for good
      }
    };
    const back = (): void => {
      this.active = true;
      this.request({ t: "activity", active: true }).catch(() => undefined);
    };
    for (const [type, listener] of [["pagehide", away], ["freeze", away], ["pageshow", back], ["resume", back]] as const) {
      w.addEventListener(type, listener);
      this.lifecycle.push([type, listener]);
    }
  }

  private onMessage(data: unknown): void {
    if (data === null || typeof data !== "object") {
      return;
    }
    if ("id" in data) {
      const answer = data as Answer;
      const waiter = this.pending.get(answer.id);
      if (waiter === undefined) {
        return;
      }
      this.pending.delete(answer.id);
      if (answer.ok) {
        waiter.resolve(answer.value);
      } else {
        waiter.reject(new Error(answer.error));
      }
      return;
    }
    const push = data as Push;
    switch (push.ev) {
      case "event":
        this.subscriptions.get(push.sub)?.deliver(push.kind, push.entry);
        break;
      case "closed":
        this.subscriptions.get(push.sub)?.ended(push.reason);
        this.subscriptions.delete(push.sub);
        break;
      case "state":
        this.state = push.state;
        this.emit("state", push.state);
        break;
      default:
        break;
    }
  }

  /** @internal one request to the host, answered or failed within `timeoutMillis`. */
  request(request: Request, timeoutMillis = 60_000): Promise<unknown> {
    if (this.closed) {
      return Promise.reject(new Error("this page has left the host"));
    }
    const id = this.nextId++;
    const envelope: Envelope = { ...request, id };
    return new Promise((resolve, reject) => {
      const timer = globalThis.setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`the host did not answer ${request.t} within ${timeoutMillis} ms`));
      }, timeoutMillis);
      this.pending.set(id, {
        resolve: (value) => { globalThis.clearTimeout(timer); resolve(value); },
        reject: (error) => { globalThis.clearTimeout(timer); reject(error); },
      });
      try {
        this.handle.port.postMessage(envelope);
      } catch (e) {
        this.pending.delete(id);
        globalThis.clearTimeout(timer);
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  /** The host's current state, asked for. */
  async status(): Promise<HostState> {
    this.state = await this.request({ t: "status" }) as HostState;
    return this.state;
  }

  /** Asks the host to snapshot its state to IndexedDB now. */
  async snapshot(): Promise<void> {
    await this.request({ t: "snapshot" });
  }

  space(name: string): RemoteSpace {
    return new RemoteSpace(this, name);
  }

  /** @internal */
  track(subscription: RemoteSubscription<unknown>, key: number): void {
    this.subscriptions.set(key, subscription);
  }

  /** @internal */
  untrack(key: number): void {
    this.subscriptions.delete(key);
  }

  /**
   * Detaches this page: the host closes the page's subscriptions and, if no other page is active,
   * pauses. A SharedWorker lives on for the other pages; a dedicated Worker ends.
   */
  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    try {
      await this.request({ t: "detach" }, 5000);
    } catch {
      // a host that is gone has nothing to detach from
    }
    this.dispose();
  }

  /** @internal drops the listeners, the beat, and the port without talking to the host. */
  dispose(): void {
    this.closed = true;
    if (this.beat !== null) {
      globalThis.clearInterval(this.beat as ReturnType<typeof setInterval>);
      this.beat = null;
    }
    const w = globalThis as unknown as WindowLike;
    for (const [type, listener] of this.lifecycle.splice(0)) {
      w.removeEventListener(type, listener);
    }
    for (const subscription of [...this.subscriptions.values()]) {
      subscription.ended("closed");
    }
    this.subscriptions.clear();
    for (const [id, waiter] of [...this.pending]) {
      this.pending.delete(id);
      waiter.reject(new Error("this page has left the host"));
    }
    this.handle.port.onmessage = null;
    this.handle.terminate();
  }
}

/** Options of a remote take. */
export type RemoteTakeOptions = {
  /** Have the host renew the claim at half-lease while it runs (never while paused); off by default. */
  keepAlive?: boolean;
  /** How long one exact-entry claim attempt waits for the fabric to settle; 1.5 s by default. */
  claimMillis?: number;
};

/** One space of the host's group, from a page: the layer-3 verbs over the port. */
export class RemoteSpace {
  constructor(readonly host: BrowserHost, readonly name: string) {}

  /** Writes `value` as the host's agent, for `lease`, with `tags`; the entry id. */
  async write(value: object, lease: number | string = "10m", tags: Dict = {}): Promise<string> {
    return await this.host.request({ t: "write", space: this.name, schema: schemaOf(value.constructor as never),
      payload: packMap(toPayload(value)), leaseMillis: durationMillis(lease), tags: packMap(tags) }) as string;
  }

  /** Every live entry matching the template, with its metadata, judged on the page. */
  async entries<T>(template: Template<T>, limit = 100, includeTaken = true): Promise<Entry<T>[]> {
    const wire = await this.host.request({ t: "entries", space: this.name, schema: template.schema,
      limit: Math.max(limit, 1) * 4, includeTaken }) as WireEntry[];
    const found: Entry<T>[] = [];
    for (const entry of wire) {
      const decoded = decodeEntry(template, entry);
      if (decoded !== null) {
        found.push(decoded);
        if (found.length >= limit) {
          break;
        }
      }
    }
    return found;
  }

  async readAll<T>(template: Template<T>, limit = 100): Promise<T[]> {
    return (await this.entries(template, limit)).map((e) => e.value);
  }

  /** The first match, waiting up to `timeout` (pulling the space through the host) for one. */
  async read<T>(template: Template<T>, timeout: number | string | null = null): Promise<T | null> {
    const deadline = Date.now() + (timeout === null ? 0 : durationMillis(timeout));
    for (;;) {
      const found = await this.entries(template, 1);
      if (found.length > 0) {
        return found[0]!.value;
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        return null;
      }
      await this.host.request({ t: "pull", space: this.name });
      await this.host.request({ t: "awaitFold", millis: Math.min(remaining, 200) });
    }
  }

  /**
   * An exclusive take of one matching entry: the page picks a candidate it matched and the host
   * claims exactly that entry under the claim lattice; a lost race moves to the next candidate
   * until `timeout`.
   */
  async take<T>(template: Template<T>, lease: number | string = "1m", timeout: number | string = "15s",
                options: RemoteTakeOptions = {}): Promise<RemoteTaken<T> | null> {
    const leaseMillis = durationMillis(lease);
    const deadline = Date.now() + durationMillis(timeout);
    const claimMillis = options.claimMillis ?? 1500;
    for (;;) {
      const candidates = await this.entries(template, 100, false);
      for (const candidate of candidates) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) {
          return null;
        }
        const entryId = await this.host.request({ t: "take", space: this.name, schema: template.schema,
          entryId: candidate.entryId, leaseMillis, timeoutMillis: Math.min(claimMillis, remaining),
          keepAlive: options.keepAlive ?? false }) as string | null;
        if (entryId !== null) {
          return new RemoteTaken<T>(this, entryId, candidate.value, leaseMillis);
        }
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        return null;
      }
      await this.host.request({ t: "pull", space: this.name });
      await this.host.request({ t: "awaitFold", millis: Math.min(remaining, 300) });
    }
  }

  /** Delivers WRITTEN, TAKEN, COMPLETED, EXPIRED, and REAPPEARED events for matching entries as the host folds them. */
  watch<T>(template: Template<T>, listener?: (event: SpaceEvent<T>) => void): RemoteSubscription<T> {
    const subscription = new RemoteSubscription<T>(this, template);
    if (listener) {
      subscription.on("event", listener);
    }
    subscription.register();
    return subscription;
  }

  events<T>(template: Template<T>): RemoteSubscription<T> {
    return this.watch(template);
  }

  /** The leased subscription (JS-V-01): lapses after `lease` on the host unless renewed. */
  notify<T>(template: Template<T>, listener: (event: SpaceEvent<T>) => void, lease: number | string = "1h"): RemoteSubscription<T> {
    const subscription = this.watch(template, listener);
    subscription.renew(lease);
    return subscription;
  }

  /** Renews the write lease of an entry the host's agent wrote. */
  async renew(entryId: string, lease: number | string = "10m"): Promise<void> {
    await this.host.request({ t: "renewEntry", space: this.name, entryId, leaseMillis: durationMillis(lease) });
  }
}

/** A take held through the host. */
export class RemoteTaken<T> {
  constructor(readonly space: RemoteSpace, readonly entryId: string, readonly value: T, readonly leaseMillis: number) {}

  /** Completes the take, writing `result` first (into the take space or `resultSpace`); refused once the claim lapsed. */
  async complete(result: object | null = null, lease: number | string = "1h", tags: Dict = {},
                 resultSpace: RemoteSpace | null = null): Promise<string | null> {
    const wire = result === null ? null : {
      space: (resultSpace ?? this.space).name, schema: schemaOf(result.constructor as never),
      payload: packMap(toPayload(result)), leaseMillis: durationMillis(lease), tags: packMap(tags),
    };
    return await this.space.host.request({ t: "complete", space: this.space.name, entryId: this.entryId, result: wire }) as string | null;
  }

  /** Extends the claim (a fresh epoch under the lattice); refused while the host is paused or once the claim lapsed. */
  async renew(lease: number | string | null = null): Promise<void> {
    await this.space.host.request({ t: "renewClaim", space: this.space.name, entryId: this.entryId,
      leaseMillis: lease === null ? this.leaseMillis : durationMillis(lease) });
  }
}

/** A watch over the port: `"event"` and `"close"`, the async iterator, `renew`, and `close`. */
export class RemoteSubscription<T> extends Emitter {
  private key: number | null = null;
  private opening: Promise<number> | null = null;
  private closed = false;
  private readonly queue: Array<SpaceEvent<T>> = [];
  private wake: (() => void) | null = null;

  constructor(readonly space: RemoteSpace, readonly template: Template<T>) {
    super();
  }

  get open(): boolean {
    return !this.closed;
  }

  /** @internal registers the host-side watch. */
  register(): Promise<number> {
    this.opening ??= this.space.host.request({ t: "watch", space: this.space.name, schema: this.template.schema })
      .then((key) => {
        this.key = key as number;
        if (this.closed) {
          this.space.host.request({ t: "unwatch", sub: this.key }).catch(() => undefined);
        } else {
          this.space.host.track(this as RemoteSubscription<unknown>, this.key);
        }
        return this.key;
      });
    return this.opening;
  }

  /** @internal an event from the host, judged against the page's template. */
  deliver(kind: EventKind, wire: WireEntry): void {
    const entry = decodeEntry(this.template, wire);
    if (entry === null || this.closed) {
      return;
    }
    const event: SpaceEvent<T> = { kind, entry: { ...entry, completed: kind === "COMPLETED", taken: kind === "TAKEN" } };
    if (this.iterating) {
      this.queue.push(event);
      this.wake?.();
    }
    this.emit("event", event);
  }

  /** @internal the host ended the subscription (its lease lapsed, the page detached). */
  ended(reason: string): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    if (this.key !== null) {
      this.space.host.untrack(this.key);
    }
    this.wake?.();
    this.emit("close", reason);
  }

  /** Sets or extends the host-side lease (the same length again when none is given). */
  renew(lease: number | string | null = null): void {
    const millis = lease === null ? this.leaseMillis : durationMillis(lease);
    if (millis === null || this.closed) {
      return;
    }
    this.leaseMillis = millis;
    this.register().then((key) => this.space.host.request({ t: "watchLease", sub: key, leaseMillis: millis }))
      .catch(() => undefined);
  }

  private leaseMillis: number | null = null;

  close(reason = "closed"): void {
    if (this.closed) {
      return;
    }
    const key = this.key;
    this.ended(reason);
    if (key !== null) {
      this.space.host.request({ t: "unwatch", sub: key }).catch(() => undefined);
    }
  }

  private iterating = false;

  /** The events as an async iterator, queued from the first `for await` on. */
  async *[Symbol.asyncIterator](): AsyncIterableIterator<SpaceEvent<T>> {
    this.iterating = true;
    while (!this.closed || this.queue.length > 0) {
      if (this.queue.length === 0) {
        await new Promise<void>((resolve) => { this.wake = resolve; });
        this.wake = null;
        continue;
      }
      yield this.queue.shift()!;
    }
  }
}

/** A port entry judged and decoded by the page's template; `null` when it does not match. */
function decodeEntry<T>(template: Template<T>, wire: WireEntry): Entry<T> | null {
  const payload = unpackMap(wire.payload);
  const tags = unpackMap(wire.tags);
  if (!template.matches(payload, tags)) {
    return null;
  }
  return { entryId: wire.entryId, value: template.decode(payload), tags, issuer: wire.issuer,
    expiresAtMillis: wire.expiresAtMillis, completed: wire.completed, taken: wire.taken };
}
