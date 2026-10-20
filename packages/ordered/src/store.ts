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
 * The durable state of a Raft voter (srad/agentspaces-js.md JS-V-06,
 * JS-F-04): the term, the vote, and the log, written before any reply that
 * depends on them leaves, so a voter that restarts never votes twice in a
 * term and never loses an acknowledged entry. One shape for Java and
 * JavaScript, so membership change and snapshots later land once in both.
 */

/** One replicated log entry (RaftMessages.LogEntry). */
export type LogEntry = { term: number; command: Uint8Array };

export type LogState = { term: number; votedFor: string | null; entries: LogEntry[] };

export interface LogStore {
  /** What the store holds; an empty store is term 0, no vote, no entries. */
  load(): Promise<LogState>;
  /** Persists the term and vote; returns once they are durable. */
  saveTermVote(term: number, votedFor: string | null): Promise<void>;
  /** Appends entries from 1-based index `fromIndex` (truncating any entries at or after it first). */
  append(fromIndex: number, entries: LogEntry[]): Promise<void>;
  /** Removes entries at and after 1-based `index`. */
  truncateFrom(index: number): Promise<void>;
}

/** A store in memory: the default for tests and for hosts that accept amnesia on restart. */
export class MemoryLogStore implements LogStore {
  private state: LogState = { term: 0, votedFor: null, entries: [] };
  /** How many durable writes happened, for tests that check write-before-reply. */
  writes = 0;
  /** A fault a test injects: thrown by the next write when set. */
  failNextWrite: Error | null = null;

  constructor(initial?: Partial<LogState>) {
    if (initial) {
      this.state = { term: initial.term ?? 0, votedFor: initial.votedFor ?? null,
        entries: [...(initial.entries ?? [])] };
    }
  }

  async load(): Promise<LogState> {
    return { term: this.state.term, votedFor: this.state.votedFor, entries: [...this.state.entries] };
  }

  private write(): void {
    if (this.failNextWrite !== null) {
      const error = this.failNextWrite;
      this.failNextWrite = null;
      throw error;
    }
    this.writes++;
  }

  async saveTermVote(term: number, votedFor: string | null): Promise<void> {
    this.write();
    this.state.term = term;
    this.state.votedFor = votedFor;
  }

  async append(fromIndex: number, entries: LogEntry[]): Promise<void> {
    this.write();
    this.state.entries.length = Math.max(0, fromIndex - 1);
    this.state.entries.push(...entries.map((e) => ({ term: e.term, command: new Uint8Array(e.command) })));
  }

  async truncateFrom(index: number): Promise<void> {
    this.write();
    this.state.entries.length = Math.max(0, index - 1);
  }
}
