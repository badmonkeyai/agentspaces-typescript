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
 * The file-backed `LogStore` of a Node voter (srad/agentspaces-js.md
 * JS-V-06): a directory holding `term-vote` (rewritten whole, through a
 * temporary file and a rename, and fsynced) and `entries` (append-only
 * records of `term`, `length`, `command`, each fsynced before the call
 * returns), the layout `FileLogStore.java` uses, so a voter restarted from
 * it keeps its vote and its entries. A torn tail record is dropped on load.
 */

import { closeSync, existsSync, fsyncSync, ftruncateSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeSync } from "node:fs";
import { join } from "node:path";
import type { LogEntry, LogState, LogStore } from "@agentspaces/ordered";

const TERM_VOTE = "term-vote";
const ENTRIES = "entries";
const HEADER = 8 + 4; // term (int64 big-endian) + command length (uint32 big-endian)
const TRAILER = 4; // CRC32 of term, length, and command

/** CRC-32 (IEEE), as `java.util.zip.CRC32` computes it. */
function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export class FileLogStore implements LogStore {
  /** The byte offset at which each 1-based entry begins, so an append at an earlier index truncates there. */
  private offsets: number[] = [];
  private length = 0;
  /** Writes made durable (for tests of the durability rule). */
  writes = 0;

  constructor(readonly directory: string) {
    mkdirSync(directory, { recursive: true });
  }

  async load(): Promise<LogState> {
    let term = 0;
    let votedFor: string | null = null;
    const termPath = join(this.directory, TERM_VOTE);
    if (existsSync(termPath)) {
      const bytes = readFileSync(termPath);
      if (bytes.length >= 1 + 8 + 2 && bytes[0] === 1) {
        term = Number(bytes.readBigInt64BE(1));
        const voteLength = bytes.readUInt16BE(9);
        votedFor = voteLength === 0 ? null : bytes.subarray(11, 11 + voteLength).toString("utf-8");
      }
    }
    const entries: LogEntry[] = [];
    this.offsets = [];
    const entriesPath = join(this.directory, ENTRIES);
    let whole = 0;
    if (existsSync(entriesPath)) {
      const bytes = readFileSync(entriesPath);
      let at = 0;
      while (at + HEADER <= bytes.length) {
        const entryTerm = Number(bytes.readBigInt64BE(at));
        const commandLength = bytes.readUInt32BE(at + 8);
        const end = at + HEADER + commandLength + TRAILER;
        if (end > bytes.length) {
          break; // a torn tail
        }
        const body = bytes.subarray(at, at + HEADER + commandLength);
        if (bytes.readUInt32BE(at + HEADER + commandLength) !== crc32(body)) {
          break; // a corrupt tail
        }
        this.offsets.push(at);
        entries.push({ term: entryTerm, command: new Uint8Array(bytes.subarray(at + HEADER, at + HEADER + commandLength)) });
        at = end;
        whole = at;
      }
      if (whole < bytes.length) {
        this.truncateFile(entriesPath, whole);
      }
    }
    this.length = whole;
    return { term, votedFor, entries };
  }

  async saveTermVote(term: number, votedFor: string | null): Promise<void> {
    const vote = Buffer.from(votedFor ?? "", "utf-8");
    const bytes = Buffer.alloc(1 + 8 + 2 + vote.length);
    bytes[0] = 1;
    bytes.writeBigInt64BE(BigInt(term), 1);
    bytes.writeUInt16BE(vote.length, 9);
    vote.copy(bytes, 11);
    const path = join(this.directory, TERM_VOTE);
    const temporary = `${path}.tmp`;
    const fd = openSync(temporary, "w");
    try {
      writeSync(fd, bytes);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temporary, path);
    this.writes += 1;
  }

  async append(fromIndex: number, entries: LogEntry[]): Promise<void> {
    if (fromIndex < 1 || fromIndex > this.offsets.length + 1) {
      throw new Error(`append at ${fromIndex} on a log of ${this.offsets.length}`);
    }
    const path = join(this.directory, ENTRIES);
    if (fromIndex <= this.offsets.length) {
      this.length = this.offsets[fromIndex - 1];
      this.truncateFile(path, this.length);
      this.offsets.length = fromIndex - 1;
    }
    const fd = openSync(path, "a");
    try {
      for (const entry of entries) {
        const body = Buffer.alloc(HEADER + entry.command.length);
        body.writeBigInt64BE(BigInt(entry.term), 0);
        body.writeUInt32BE(entry.command.length, 8);
        Buffer.from(entry.command).copy(body, HEADER);
        const trailer = Buffer.alloc(TRAILER);
        trailer.writeUInt32BE(crc32(body), 0);
        this.offsets.push(this.length);
        writeSync(fd, body);
        writeSync(fd, trailer);
        this.length += body.length + trailer.length;
      }
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    this.writes += 1;
  }

  async truncateFrom(index: number): Promise<void> {
    if (index < 1 || index > this.offsets.length) {
      return;
    }
    const path = join(this.directory, ENTRIES);
    this.truncateFile(path, this.offsets[index - 1]);
    this.offsets.length = index - 1;
    this.length = statSync(path).size;
    this.writes += 1;
  }

  private truncateFile(path: string, size: number): void {
    const fd = openSync(path, "r+");
    try {
      ftruncateSync(fd, size);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }
}
