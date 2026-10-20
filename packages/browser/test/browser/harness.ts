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
 * The page module of the resident-host browser tests: loaded into each tab
 * by `test/resident.test.ts`, it exposes `window.harness`, a set of plain
 * functions Playwright's `page.evaluate` can call (class instances cannot
 * cross that boundary), each over the page-side API of
 * `@agentspaces/browser`. Hosts, takes, and watched events are kept here by
 * name so one call's result feeds the next.
 */

import { Template, deriveId, entry } from "@agentspaces/client";
import { BrowserHost, ConnectOptions, IndexedDbKeyStore, PEER_PUB, RemoteTaken, connect, databaseName, deleteDatabase } from "../../src/index.js";

export const TASK = "com.acme.browser.Task#v1";

@entry(TASK)
class Task {
  constructor(public topic = "", public priority = 0) {}
}

const hosts = new Map<string, BrowserHost>();
const takes = new Map<string, RemoteTaken<Task>>();
const events = new Map<string, { kind: string; topic: string }[]>();
const states = new Map<string, string[]>();

function host(name: string): BrowserHost {
  const found = hosts.get(name);
  if (found === undefined) {
    throw new Error(`no host ${name}`);
  }
  return found;
}

function dispatch(type: string, persisted: boolean): void {
  const g = globalThis as unknown as {
    PageTransitionEvent?: new (type: string, init: { persisted: boolean }) => Event;
    dispatchEvent(event: Event): boolean;
  };
  const event = typeof g.PageTransitionEvent === "function"
    ? new g.PageTransitionEvent(type, { persisted }) : new Event(type);
  g.dispatchEvent(event);
}

const message = (e: unknown): string => (e instanceof Error ? e.message : String(e));

export const harness = {
  sharedWorkerAvailable(): boolean {
    return typeof (globalThis as { SharedWorker?: unknown }).SharedWorker === "function";
  },

  async connect(name: string, options: Omit<ConnectOptions, "worker">): Promise<{ ok: true; peerId: string; shared: boolean;
    instance: string; persisted: boolean | null; paused: boolean; connected: boolean } | { ok: false; error: string }> {
    try {
      const h = await connect({ ...options, worker: "/worker.js" });
      hosts.set(name, h);
      states.set(name, []);
      h.on("state", (s: { paused: boolean; connected: boolean }) => {
        states.get(name)!.push(`${s.paused ? "paused" : "running"}:${s.connected ? "connected" : "offline"}`);
      });
      return { ok: true, peerId: h.peerId, shared: h.shared, instance: h.instance, persisted: h.persisted,
        paused: h.paused, connected: h.connected };
    } catch (e) {
      return { ok: false, error: message(e) };
    }
  },

  async write(name: string, space: string, topic: string, priority: number, lease: string = "10m"): Promise<string> {
    return host(name).space(space).write(new Task(topic, priority), lease);
  },

  async readAll(name: string, space: string, minPriority = 0): Promise<string[]> {
    const found = await host(name).space(space).readAll(new Template(Task, { priority: (v: unknown) => Number(v) >= minPriority }));
    return found.map((t) => t.topic);
  },

  async read(name: string, space: string, topic: string, timeoutMillis: number): Promise<{ topic: string; priority: number } | null> {
    const found = await host(name).space(space).read(new Template(Task, { topic }), timeoutMillis);
    return found === null ? null : { topic: found.topic, priority: found.priority };
  },

  async take(name: string, space: string, topic: string, leaseMillis: number, timeoutMillis: number,
             keepAlive: boolean): Promise<string | null> {
    const taken = await host(name).space(space).take(new Template(Task, { topic }), leaseMillis, timeoutMillis, { keepAlive });
    if (taken === null) {
      return null;
    }
    takes.set(taken.entryId, taken);
    return taken.entryId;
  },

  async complete(entryId: string, resultTopic: string | null = null): Promise<{ ok: true; resultId: string | null } | { ok: false; error: string }> {
    try {
      const taken = takes.get(entryId);
      if (taken === undefined) {
        throw new Error(`no take ${entryId}`);
      }
      return { ok: true, resultId: await taken.complete(resultTopic === null ? null : new Task(resultTopic, 9)) };
    } catch (e) {
      return { ok: false, error: message(e) };
    }
  },

  async renew(entryId: string): Promise<{ ok: true } | { ok: false; error: string }> {
    try {
      await takes.get(entryId)!.renew();
      return { ok: true };
    } catch (e) {
      return { ok: false, error: message(e) };
    }
  },

  watch(name: string, space: string, lease: string | null = null): void {
    const list: { kind: string; topic: string }[] = [];
    events.set(name, list);
    const listener = (event: { kind: string; entry: { value: Task } }): void => {
      list.push({ kind: event.kind, topic: event.entry.value.topic });
    };
    const s = host(name).space(space);
    const subscription = lease === null ? s.watch(new Template(Task), listener) : s.notify(new Template(Task), listener, lease);
    subscription.on("close", (reason: string) => list.push({ kind: "CLOSE", topic: reason }));
  },

  events(name: string): { kind: string; topic: string }[] {
    return events.get(name) ?? [];
  },

  stateLog(name: string): string[] {
    return states.get(name) ?? [];
  },

  async status(name: string): Promise<{ peerId: string; paused: boolean; connected: boolean; pages: number; activePages: number;
    instance: string; shared: boolean; reason: string | null; residency: string; drifts: number }> {
    const s = await host(name).status();
    return { peerId: s.peerId, paused: s.paused, connected: s.connected, pages: s.pages, activePages: s.activePages,
      instance: s.instance, shared: s.shared, reason: s.reason, residency: s.residency, drifts: s.drifts };
  },

  async hostLog(name: string): Promise<string[]> {
    return await host(name).request({ t: "log" }) as string[];
  },

  pagehide(persisted = true): void {
    dispatch("pagehide", persisted);
  },

  pageshow(): void {
    dispatch("pageshow", true);
  },

  async close(name: string): Promise<void> {
    await host(name).close();
    hosts.delete(name);
  },

  /** The PeerID the key store holds, read straight from IndexedDB: the persistence proof. */
  async storedPeerId(group: string): Promise<string | null> {
    const pub = await new IndexedDbKeyStore(databaseName(group)).load(PEER_PUB);
    return pub === null ? null : deriveId(pub);
  },

  async reset(group: string): Promise<void> {
    await deleteDatabase(databaseName(group));
  },
};

(globalThis as { harness?: typeof harness }).harness = harness;
