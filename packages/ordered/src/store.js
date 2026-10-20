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
/** A store in memory: the default for tests and for hosts that accept amnesia on restart. */
export class MemoryLogStore {
    state = { term: 0, votedFor: null, entries: [] };
    /** How many durable writes happened, for tests that check write-before-reply. */
    writes = 0;
    /** A fault a test injects: thrown by the next write when set. */
    failNextWrite = null;
    constructor(initial) {
        if (initial) {
            this.state = { term: initial.term ?? 0, votedFor: initial.votedFor ?? null,
                entries: [...(initial.entries ?? [])] };
        }
    }
    async load() {
        return { term: this.state.term, votedFor: this.state.votedFor, entries: [...this.state.entries] };
    }
    write() {
        if (this.failNextWrite !== null) {
            const error = this.failNextWrite;
            this.failNextWrite = null;
            throw error;
        }
        this.writes++;
    }
    async saveTermVote(term, votedFor) {
        this.write();
        this.state.term = term;
        this.state.votedFor = votedFor;
    }
    async append(fromIndex, entries) {
        this.write();
        this.state.entries.length = Math.max(0, fromIndex - 1);
        this.state.entries.push(...entries.map((e) => ({ term: e.term, command: new Uint8Array(e.command) })));
    }
    async truncateFrom(index) {
        this.write();
        this.state.entries.length = Math.max(0, index - 1);
    }
}
