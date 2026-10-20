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
 * The resident host in Node, without a browser (srad/agentspaces-js.md
 * JS-R-02, JS-R-03, JS-P-08): in-memory stand-ins for IndexedDB, Web Locks,
 * and a MessagePort pair carry the host's own code over Node 22's global
 * WebSocket to a `ServiceHost` hub, so the identity bootstrap, the lock
 * election, the pause rule, the subscription lease, the silent-page sweep,
 * and the snapshot round trip are proven deterministically here and in the
 * three engines by `test/resident.test.ts`.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Identity, Template, agent, cbor, deriveId, entry, spaceNotify } from "@agentspaces/client";
import { ServiceHost } from "@agentspaces/node";

// ------------------------------------------------------------- the stand-ins

type Listener = ((event: unknown) => void) | null;

class FakeRequest<T = unknown> {
  result!: T;
  error: { message?: string } | null = null;
  onsuccess: Listener = null;
  onerror: Listener = null;

  constructor(run: () => T) {
    queueMicrotask(() => {
      try {
        this.result = run();
        this.onsuccess?.({});
      } catch (e) {
        this.error = { message: e instanceof Error ? e.message : String(e) };
        this.onerror?.({});
      }
    });
  }
}

type Stores = Map<string, Map<string, unknown>>;

class FakeDatabase {
  onversionchange: Listener = null;
  constructor(readonly stores: Stores) {}
  objectStoreNames = { contains: (name: string): boolean => this.stores.has(name) };
  createObjectStore(name: string): void {
    this.stores.set(name, new Map());
  }
  transaction(names: string | string[]): {
    objectStore(name: string): unknown; oncomplete: Listener; onerror: Listener; onabort: Listener; error: null;
  } {
    const transaction = {
      oncomplete: null as Listener, onerror: null as Listener, onabort: null as Listener, error: null,
      objectStore: (name: string) => {
        const map = this.stores.get(name)!;
        return {
          get: (key: string) => new FakeRequest(() => map.get(key)),
          put: (value: unknown, key: string) => new FakeRequest(() => { map.set(key, value); }),
          delete: (key: string) => new FakeRequest(() => { map.delete(key); }),
          getAllKeys: () => new FakeRequest(() => [...map.keys()]),
        };
      },
    };
    void names;
    setTimeout(() => transaction.oncomplete?.({}), 0);
    return transaction;
  }
  close(): void { /* nothing to release */ }
}

const databases = new Map<string, Stores>();
const fakeIndexedDB = {
  open(name: string): FakeRequest<FakeDatabase> & { onupgradeneeded: Listener; onblocked: Listener } {
    const fresh = !databases.has(name);
    const stores = databases.get(name) ?? new Map();
    databases.set(name, stores);
    const request = Object.assign(new FakeRequest(() => new FakeDatabase(stores)), { onupgradeneeded: null as Listener, onblocked: null as Listener });
    if (fresh) {
      const success = (): void => undefined;
      queueMicrotask(() => { request.onupgradeneeded?.({}); success(); });
    }
    return request;
  },
  deleteDatabase(name: string): FakeRequest<void> {
    return new FakeRequest(() => { databases.delete(name); });
  },
};

const lockHolders = new Map<string, Array<() => void>>();
const fakeLocks = {
  request(name: string, options: { ifAvailable?: boolean; signal?: AbortSignal }, callback: (lock: unknown) => Promise<unknown>): Promise<unknown> {
    const run = async (): Promise<unknown> => {
      try {
        return await callback({ name });
      } finally {
        const waiters = lockHolders.get(name)!;
        const next = waiters.shift();
        if (next === undefined) {
          lockHolders.delete(name);
        } else {
          next();
        }
      }
    };
    if (!lockHolders.has(name)) {
      lockHolders.set(name, []);
      return run();
    }
    if (options.ifAvailable) {
      return callback(null);
    }
    return new Promise((resolve, reject) => {
      const waiter = (): void => { resolve(run()); };
      lockHolders.get(name)!.push(waiter);
      options.signal?.addEventListener("abort", () => {
        const waiters = lockHolders.get(name);
        const index = waiters?.indexOf(waiter) ?? -1;
        if (index >= 0) {
          waiters!.splice(index, 1);
          reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
        }
      });
    });
  },
  async query(): Promise<{ held: { name: string }[] }> {
    return { held: [...lockHolders.keys()].map((name) => ({ name })) };
  },
};

Object.defineProperty(globalThis, "indexedDB", { value: fakeIndexedDB, configurable: true, writable: true });
Object.defineProperty(globalThis, "navigator", { value: { locks: fakeLocks }, configurable: true, writable: true });

const { ResidentHost, DRIFT_TICKS, RECOVERY_MILLIS } = await import("../src/host.js");
const { IndexedDbKeyStore, STATE_STORE } = await import("../src/idb.js");
const { PEER_KEY, PEER_PUB, SNAPSHOT, agentKeyName, databaseName } = await import("../src/protocol.js");
type PortLike = import("../src/protocol.js").PortLike;
type HostState = import("../src/protocol.js").HostState;

/** Two linked ports, each delivering to the other as a browser would: a structured clone, asynchronously. */
function pair(): [PortLike, PortLike] {
  const make = (): PortLike & { peer: PortLike | null } => ({
    peer: null, onmessage: null,
    postMessage(message: unknown): void {
      const copy = structuredClone(message);
      const target = this.peer!;
      queueMicrotask(() => target.onmessage?.({ data: copy }));
    },
  });
  const a = make();
  const b = make();
  a.peer = b;
  b.peer = a;
  return [a, b];
}

/** A page's side of the port: numbered requests and the pushes the host sends. */
class FakePage {
  private next = 1;
  private readonly waiting = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  readonly pushes: unknown[] = [];
  constructor(readonly port: PortLike) {
    port.onmessage = (event) => {
      const data = event.data as { id?: number; ok?: boolean; value?: unknown; error?: string; ev?: string };
      if (typeof data.id === "number") {
        const waiter = this.waiting.get(data.id)!;
        this.waiting.delete(data.id);
        if (data.ok) {
          waiter.resolve(data.value);
        } else {
          waiter.reject(new Error(data.error));
        }
      } else {
        this.pushes.push(data);
      }
    };
  }
  request(request: object): Promise<unknown> {
    const id = this.next++;
    return new Promise((resolve, reject) => {
      this.waiting.set(id, { resolve, reject });
      this.port.postMessage({ ...request, id });
    });
  }
}

const GROUP = "zResidentHostNode";
const TASK = "com.acme.browser.Task#v1";
const sleep = (millis: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, millis));

async function until(condition: () => boolean, what: string, millis = 5000): Promise<void> {
  const deadline = Date.now() + millis;
  while (!condition()) {
    if (Date.now() > deadline) {
      throw new Error(`${what}: not met within ${millis} ms`);
    }
    await sleep(20);
  }
}

async function hub(): Promise<{ hub: ServiceHost; seeds: string[] }> {
  const service = new ServiceHost(Identity.generate(), GROUP, {
    tickMillis: 100, listeners: [{ scheme: "ws", bind: "127.0.0.1:0" }], spaces: ["tasks"], log: null,
  });
  await service.start();
  return { hub: service, seeds: [`ws://${service.addresses.get("ws")}/aspace`] };
}

function attachPage(host: InstanceType<typeof ResidentHost>): FakePage {
  const [pagePort, hostPort] = pair();
  host.attach(hostPort);
  return new FakePage(pagePort);
}

test("the host mints its identity once into the key store, takes the lock, and refuses a second host (JS-P-08, JS-R-02)", async () => {
  const { hub: service, seeds } = await hub();
  const database = databaseName(GROUP) + ":one";
  const first = new ResidentHost({ shared: true, log: null });
  const page = attachPage(first);
  try {
    const state = await page.request({ t: "hello", config: { group: GROUP, seeds, database, tickMillis: 100 }, pageId: "p1", active: true }) as HostState;
    assert.ok(state.peerId.startsWith("z"));
    assert.equal(state.residency, "resident");
    assert.equal(state.paused, false);
    assert.equal(state.connected, true);
    const keys = new IndexedDbKeyStore(database);
    assert.equal(deriveId((await keys.load(PEER_PUB))!), state.peerId, "peer.pub holds the running identity");
    assert.equal(Identity.fromPkcs8((await keys.load(PEER_KEY))!).peerId, state.peerId, "peer.key holds its private key");
    assert.ok((await keys.load(agentKeyName("resident"))) !== null, "the agent key is stored too");
    assert.ok(await fakeLocks.query().then((q) => q.held.some((l) => l.name === `agentspaces:${GROUP}:${state.peerId}`)));
    await until(() => service.peer.inbound.size === 1, "the hub sees one connection");
    await until(() => service.peer.members.has(state.peerId), "the hub hears the host");
    assert.equal((service.peer.members.get(state.peerId)!["resourceHints"] as { [k: string]: string })["js.residency"], "resident");

    const second = new ResidentHost({ shared: false, log: null });
    const other = attachPage(second);
    await assert.rejects(
      other.request({ t: "hello", config: { group: GROUP, seeds, database, lockWaitMillis: 150 }, pageId: "p2", active: true }),
      new RegExp(`another host holds the Web Lock agentspaces:${GROUP}:${state.peerId}`));
    assert.equal(service.peer.inbound.size, 1, "the refused host never dialled");

    await assert.rejects(page.request({ t: "hello", config: { group: "zOther", seeds }, pageId: "p3", active: true }), /serves group/);
  } finally {
    await first.stop();
    await service.stop();
  }
});

test("the pause rule: the last active page's loss closes the channel and stops renewals; a return resumes the identity (JS-R-03)", async () => {
  const { hub: service, seeds } = await hub();
  const database = databaseName(GROUP) + ":pause";
  const host = new ResidentHost({ shared: true, log: null });
  const a = attachPage(host);
  const b = attachPage(host);
  try {
    const config = { group: GROUP, seeds, database, tickMillis: 100 };
    const state = await a.request({ t: "hello", config, pageId: "a", active: true }) as HostState;
    await b.request({ t: "hello", config, pageId: "b", active: true });
    await until(() => service.peer.inbound.size === 1, "connected");
    const jobId = service.peer.writeEntry("tasks", TASK, { topic: "job", priority: 1 }, "hub");
    const taken = await a.request({ t: "take", space: "tasks", schema: TASK, entryId: jobId, leaseMillis: 600,
      timeoutMillis: 5000, keepAlive: true });
    assert.equal(taken, jobId);
    await sleep(1000);
    assert.equal(await service.peer.takeEntry("tasks", TASK, "hub", 60_000, 200, 500, null, jobId), null,
      "renewed past its lease while running");
    // One page hides: still running. Both hide: paused.
    await a.request({ t: "activity", active: false });
    await sleep(150);
    assert.equal(service.peer.inbound.size, 1, "one active page keeps the host running");
    await b.request({ t: "activity", active: false });
    await until(() => service.peer.inbound.size === 0, "the channel closed cleanly on pause");
    const paused = await a.request({ t: "status" }) as HostState;
    assert.equal(paused.paused, true);
    assert.equal(paused.reason, "no active page");
    await assert.rejects(a.request({ t: "renewClaim", space: "tasks", entryId: jobId, leaseMillis: 600 }), /paused/);
    await assert.rejects(a.request({ t: "write", space: "tasks", schema: TASK, payload: cbor.dumps({ topic: "x" }), leaseMillis: 1000, tags: cbor.dumps({}) }), /paused/);
    await sleep(900); // the claim lapses while paused
    assert.equal(await service.peer.takeEntry("tasks", TASK, "hub", 60_000, 200, 1500, null, jobId), jobId,
      "the claim did not outlive its lease: the hub takes the job");
    assert.equal(host.pauses, 1);
    await b.request({ t: "activity", active: true });
    await until(() => service.peer.inbound.size === 1, "dialled again on resume");
    const resumed = await b.request({ t: "status" }) as HostState;
    assert.equal(resumed.peerId, state.peerId, "the same identity");
    assert.equal(resumed.paused, false);
    assert.equal(host.resumes, 2, "the hello's resume and this one");
    await assert.rejects(a.request({ t: "complete", space: "tasks", entryId: jobId, result: null }), /Current exact live claim required/);
    assert.ok(a.pushes.some((p) => (p as { ev: string; state?: HostState }).ev === "state" && (p as { state: HostState }).state.paused),
      "pages hear the pause");
  } finally {
    await host.stop();
    await service.stop();
  }
});

test("subscriptions: events flow to the page, a notify lease lapses on time, a detached page's watches close, a silent page is dropped", async () => {
  const { hub: service, seeds } = await hub();
  const database = databaseName(GROUP) + ":subs";
  const host = new ResidentHost({ shared: true, log: null });
  const a = attachPage(host);
  const b = attachPage(host);
  try {
    const config = { group: GROUP, seeds, database, tickMillis: 100, pageTimeoutMillis: 400 };
    await a.request({ t: "hello", config, pageId: "a", active: true });
    await b.request({ t: "hello", config, pageId: "b", active: true });
    const sub = await a.request({ t: "watch", space: "tasks", schema: TASK }) as number;
    const leased = await b.request({ t: "watch", space: "tasks", schema: TASK }) as number;
    await b.request({ t: "watchLease", sub: leased, leaseMillis: 300 });
    const id = await b.request({ t: "write", space: "tasks", schema: TASK, payload: cbor.dumps({ topic: "t", priority: 2 }),
      leaseMillis: 60_000, tags: cbor.dumps({ region: "eu" }) }) as string;
    await until(() => a.pushes.some((p) => (p as { ev: string }).ev === "event"), "the event reached page A");
    const event = a.pushes.find((p) => (p as { ev: string }).ev === "event") as { sub: number; kind: string; entry: { entryId: string; payload: Uint8Array; tags: Uint8Array } };
    assert.equal(event.sub, sub);
    assert.equal(event.kind, "WRITTEN");
    assert.equal(event.entry.entryId, id);
    assert.equal(JSON.stringify(cbor.loads(event.entry.payload)), JSON.stringify({ topic: "t", priority: 2 }));
    assert.equal(JSON.stringify(cbor.loads(event.entry.tags)), JSON.stringify({ region: "eu" }));
    await until(() => b.pushes.some((p) => (p as { ev: string; reason?: string }).ev === "closed" && (p as { reason: string }).reason === "lapsed"),
      "the leased watch lapsed on the host");
    await until(() => service.peer.states.has(id), "the write reached the hub");
    await a.request({ t: "detach" });
    assert.equal(host.status().pages, 1);
    // Page B stops beating: the sweep drops it, and with no page active the host pauses.
    await until(() => host.status().pages === 0, "the silent page was dropped", 3000);
    await until(() => service.peer.inbound.size === 0, "no page left: paused");
  } finally {
    await host.stop();
    await service.stop();
  }
});

test("the snapshot round trip: a change is saved soon after, and a fresh host restores it before dialling (JS-R-02)", async () => {
  const { hub: service, seeds } = await hub();
  const database = databaseName(GROUP) + ":snapshot";
  const first = new ResidentHost({ shared: true, log: null });
  first.dirtySnapshotMillis = 50;
  const page = attachPage(first);
  const config = { group: GROUP, seeds, database, tickMillis: 100 };
  const state = await page.request({ t: "hello", config, pageId: "a", active: true }) as HostState;
  const id = await page.request({ t: "write", space: "tasks", schema: TASK, payload: cbor.dumps({ topic: "kept", priority: 1 }),
    leaseMillis: 600_000, tags: cbor.dumps({}) }) as string;
  const store = new IndexedDbKeyStore(database, STATE_STORE);
  await sleep(150);
  const bytes = await store.load(SNAPSHOT);
  assert.ok(bytes !== null, "the dirty snapshot was saved");
  assert.ok(((cbor.loads(bytes) as { states: unknown[] }).states).length >= 1);
  await first.stop();
  await service.stop(); // no hub: what the second host reads comes from IndexedDB alone
  const second = new ResidentHost({ shared: true, log: null });
  const again = attachPage(second);
  try {
    await assert.rejects(again.request({ t: "hello", config, pageId: "b", active: true }), /no seed answered/, "no hub to dial");
    assert.equal(second.identity!.peerId, state.peerId, "the same identity from the store");
    assert.ok(second.peer!.states.has(id), "the replica was restored from the snapshot");
    // The failed hello detached the page (its port answers nothing more); the host's own space reads the replica.
    assert.deepEqual(second.space("tasks").entries(new Template(TASK)).map((e) => e.entryId), [id], "readable without a hub");
  } finally {
    await second.stop();
  }
});

@entry(TASK)
class Task {
  constructor(public topic = "", public priority = 0) {}
}

@agent("watcher")
class Watcher {
  seen = 0;

  @spaceNotify(Task, "tasks")
  notice(_task: Task): null {
    this.seen += 1;
    return null;
  }
}

test("a host whose tick drifts three times drops to visitor duties (bindings closed, holds left to lapse, hint updated) and recovers after 60 s of cadence (JS-R-06)", async () => {
  const { hub: service, seeds } = await hub();
  const database = databaseName(GROUP) + ":drift";
  const host = new ResidentHost({ shared: true, log: null });
  const page = attachPage(host);
  try {
    const config = { group: GROUP, seeds, database, tickMillis: 1000 };
    const state = await page.request({ t: "hello", config, pageId: "a", active: true }) as HostState;
    await until(() => service.peer.inbound.size === 1, "connected");
    const watcher = new Watcher();
    const bound = host.bind(watcher);
    assert.equal(host.bindings.length, 1);
    const jobId = service.peer.writeEntry("tasks", TASK, { topic: "drift", priority: 1 }, "hub");
    assert.equal(await page.request({ t: "take", space: "tasks", schema: TASK, entryId: jobId, leaseMillis: 3000,
      timeoutMillis: 5000, keepAlive: true }), jobId);
    await sleep(3500);
    assert.equal(await service.peer.takeEntry("tasks", TASK, "hub", 60_000, 200, 500, null, jobId), null,
      "a resident host renews its hold on the 1 s tick");
    // The cadence, observed: three ticks later than twice the period, back to back.
    let now = Date.now();
    for (let i = 0; i < DRIFT_TICKS - 1; i++) {
      now += 2500;
      host.observeCadence(now);
      assert.equal(host.residency, "resident", `${i + 1} drift(s) is not yet a drop`);
    }
    now += 2500;
    host.observeCadence(now);
    assert.equal(host.residency, "visitor");
    assert.equal(host.drifts, DRIFT_TICKS);
    assert.equal(host.peer!.resourceHints["js.residency"], "visitor", "the hint the next advertisement carries");
    assert.equal(bound.running, false, "the worker-side binding is closed");
    assert.equal(host.bindings.length, 0);
    assert.equal(host.suspended.length, 1);
    assert.ok((await page.request({ t: "log" }) as string[]).some((l) => /dropping to visitor duties/.test(l)), "the drift is logged");
    assert.equal(host.status().residency, "visitor");
    await until(() => (service.peer.members.get(state.peerId)!["resourceHints"] as { [k: string]: string })["js.residency"] === "visitor",
      "the hub heard the new hint");
    // The hold's lease passes with no renewal (a renewing host would never let the count reach zero).
    await until(() => host.holdCount() === 0, "the hold lapsed and was forgotten", 8000);
    assert.equal(await service.peer.takeEntry("tasks", TASK, "hub", 60_000, 200, 1500, null, jobId), jobId,
      "a visitor renews nothing: the hub takes the job");
    // Good ticks for less than a minute keep it a visitor; a minute past the last drift restores it. The
    // real tick ran during the sleep (its gaps against the cadence above are no drift), so the fake
    // cadence re-bases on the clock it last observed and steps on from there.
    now = Date.now();
    let good = 0;
    while (host.residency === "visitor" && good < 80) {
      now += 1000;
      host.observeCadence(now);
      good += 1;
      if (good === RECOVERY_MILLIS / 1000 - 1) {
        assert.equal(host.residency, "visitor", "59 good ticks are not yet a minute past the drift");
      }
    }
    assert.equal(host.residency, "resident");
    assert.ok(good >= RECOVERY_MILLIS / 1000 && good <= RECOVERY_MILLIS / 1000 + 10, `recovered after ${good} good ticks`);
    assert.equal(host.peer!.resourceHints["js.residency"], "resident");
    assert.equal(host.suspended.length, 0);
    assert.equal(host.bindings.length, 1, "the suspended agent is bound again");
    assert.ok(host.bindings[0]!.bound.running && host.bindings[0]!.bound !== bound, "a fresh binding of the same instance");
    await until(() => (service.peer.members.get(state.peerId)!["resourceHints"] as { [k: string]: string })["js.residency"] === "resident",
      "the hub heard the recovery");
    service.peer.writeEntry("tasks", TASK, { topic: "after", priority: 1 }, "hub");
    await until(() => watcher.seen >= 1, "the re-bound agent reacts again");
  } finally {
    await host.stop();
    await service.stop();
  }
});
