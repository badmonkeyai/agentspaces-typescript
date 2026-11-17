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
 * Each space's audited set kept as a {@link HashTrie} beside the replica's own maps (SPEC annex I.6, *The audited
 * set*; srad/replication-by-entry.md RE-L-01). The peer keeps its states, claims and acknowledged lines in maps keyed
 * by entry id, as before; every change to them names the id here, and the trie of the id's space takes the slot's new
 * lines the next time it is read. A present entry whose write lease lapses leaves the set by the clock alone, so the
 * ids of present entries wait in a heap by expiry and are judged again when it passes.
 *
 * A space gets a trie only once an audit or a probe reads it, so a member that never meets a `wire.ae=2` partner pays
 * nothing for it.
 */

import { HashTrie, slotLines } from "./trie.js";
import type { SlotHolding } from "./trie.js";

/** What one entry id holds now, as the replica judges it, and when a present entry lapses. */
export interface Holding extends SlotHolding {
  /** The space the id belongs to (a state's or a claim's SpaceId, else an acknowledged line's), or null. */
  spaceId: string | null;
  /** The expiry of a present entry whose lease has not lapsed, so the set drops its lines then; else null. */
  liveUntil: number | null;
}

/** What the audited sets read of the replica. */
export interface ReplicaView {
  holding(id: string, now: number): Holding;
  /** Every id with a state, a claim or an acknowledged line in a space. */
  idsOf(spaceId: string): Iterable<string>;
  now(): number;
}

/** A min-heap of (expiry, id), with stale pairs skipped when they surface. */
class ExpiryHeap {
  private readonly items: [number, string][] = [];

  push(at: number, id: string): void {
    const items = this.items;
    items.push([at, id]);
    let i = items.length - 1;
    while (i > 0) {
      const parent = (i - 1) >> 1;
      if (items[parent]![0] <= at) {
        break;
      }
      [items[i], items[parent]] = [items[parent]!, items[i]!];
      i = parent;
    }
  }

  peek(): [number, string] | undefined {
    return this.items[0];
  }

  pop(): [number, string] | undefined {
    const items = this.items;
    const top = items[0];
    const last = items.pop();
    if (items.length > 0 && last !== undefined) {
      items[0] = last;
      let i = 0;
      for (;;) {
        const l = 2 * i + 1;
        const r = l + 1;
        let least = i;
        if (l < items.length && items[l]![0] < items[least]![0]) {
          least = l;
        }
        if (r < items.length && items[r]![0] < items[least]![0]) {
          least = r;
        }
        if (least === i) {
          break;
        }
        [items[i], items[least]] = [items[least]!, items[i]!];
        i = least;
      }
    }
    return top;
  }

  get size(): number {
    return this.items.length;
  }

  clear(): void {
    this.items.length = 0;
  }
}

export class AuditedSets {
  private readonly tries = new Map<string, HashTrie>();
  /** The space whose trie holds each id's slot. */
  private readonly placed = new Map<string, string>();
  private readonly dirty = new Set<string>();
  /** Each present, unlapsed entry in a trie, by id, to the expiry it was filed under. */
  private readonly liveUntil = new Map<string, number>();
  private readonly lapses = new ExpiryHeap();

  constructor(private readonly view: ReplicaView) {}

  /** A state, a claim or an acknowledged line of the id changed; read again before the next audit. */
  touched(id: string): void {
    if (this.tries.size > 0) {
      this.dirty.add(id);
    }
  }

  /** Whether a space has a trie yet. */
  has(spaceId: string): boolean {
    return this.tries.has(spaceId);
  }

  /** The current trie of a space, built on its first read. */
  trieFor(spaceId: string): HashTrie {
    let trie = this.tries.get(spaceId);
    if (trie === undefined) {
      trie = new HashTrie();
      this.tries.set(spaceId, trie);
      for (const id of this.view.idsOf(spaceId)) {
        this.dirty.add(id);
      }
    }
    this.sync();
    return trie;
  }

  /** Applies every change named since the last read, and every lapse whose time has come. */
  sync(): void {
    const now = this.view.now();
    for (let top = this.lapses.peek(); top !== undefined && top[0] <= now; top = this.lapses.peek()) {
      this.lapses.pop();
      if (this.liveUntil.get(top[1]) === top[0]) {
        this.dirty.add(top[1]);
      }
    }
    if (this.dirty.size === 0) {
      return;
    }
    const ids = [...this.dirty];
    this.dirty.clear();
    for (const id of ids) {
      this.update(id, now);
    }
    if (this.lapses.size > 4 * Math.max(16, this.liveUntil.size)) {
      // Renewals file an id again under its new expiry; the stale pairs are dropped once they outnumber the live.
      this.lapses.clear();
      for (const [id, at] of this.liveUntil) {
        this.lapses.push(at, id);
      }
    }
  }

  private update(id: string, now: number): void {
    const holding = this.view.holding(id, now);
    const before = this.placed.get(id);
    if (before !== undefined && before !== holding.spaceId) {
      this.tries.get(before)?.remove(id);
      this.placed.delete(id);
    }
    this.liveUntil.delete(id);
    const trie = holding.spaceId === null ? undefined : this.tries.get(holding.spaceId);
    if (trie === undefined) {
      return;
    }
    if (holding.liveUntil !== null) {
      this.liveUntil.set(id, holding.liveUntil);
      this.lapses.push(holding.liveUntil, id);
    }
    const lines = slotLines(id, holding);
    trie.put(id, lines);
    if (trie.get(id) !== undefined) {
      this.placed.set(id, holding.spaceId!);
    } else {
      this.placed.delete(id);
    }
  }
}

/**
 * A map that names each key whose value it sets or deletes, with the value before and after, so the peer's state,
 * claim and acknowledgement maps feed the audited sets from every place that changes them, without each place having
 * to remember to.
 */
export class TrackedMap<K, V> extends Map<K, V> {
  private onChange: ((key: K, before: V | undefined, after: V | undefined) => void) | null = null;

  /** Installs the listener; set after construction, since Map's constructor may call set before fields exist. */
  track(onChange: (key: K, before: V | undefined, after: V | undefined) => void): this {
    this.onChange = onChange;
    return this;
  }

  override set(key: K, value: V): this {
    const before = this.onChange === null ? undefined : super.get(key);
    super.set(key, value);
    this.onChange?.(key, before, value);
    return this;
  }

  override delete(key: K): boolean {
    if (!super.has(key)) {
      return false;
    }
    const before = super.get(key);
    super.delete(key);
    this.onChange?.(key, before, undefined);
    return true;
  }

  override clear(): void {
    const held = [...super.entries()];
    super.clear();
    for (const [key, before] of held) {
      this.onChange?.(key, before, undefined);
    }
  }
}
