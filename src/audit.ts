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
 * The trie audit of SPEC annex I.6 (v0.1.35, `wire.ae=2`; srad/replication-by-entry.md §3.2 to §3.4, RE-L-01), both
 * halves, as Java's `TrieAudit` runs them. As the partner it answers a round's opening with the roots of the space
 * streams whose stream hashes differ, keeps the bounded sessions those roots open, and answers request nodes within
 * them. As the asker it checks each answer against the fingerprint its parent gave, asks for the children that
 * differ, and fetches by id the entries an answer of lines names that its own set lacks.
 *
 * The fetch is the asker's queue of the ids its audits found: bodies of at most 4,096 ids under its budget, a few in
 * flight per partner, the next sent as each answer lands. An answer that counts a remainder sends the ids it left out
 * to the same partner at once; an id the partner neither sent nor counted, or whose answer never came, goes to the
 * next member in view after a jittered backoff; and an id every member left out waits for an audit to name it again,
 * so no repair is given up for good (ROBUSTNESS.md §10).
 *
 * Everything reads the clock the host gives it, and replies go out only after the state they depend on is updated,
 * since an in-process transport may deliver the partner's answer before the send returns.
 */

import { equals, utf8 } from "./bytes.js";
import { dumps } from "./cbor.js";
import type { CborValue } from "./cbor.js";
import * as records from "./records.js";
import {
  HashTrie, LEAF_MAX, NODES_BYTES, PATH_MAX, childCount, childFingerprint, entryIdOf, fingerprintOf,
} from "./trie.js";
import type { DigestFields } from "./wire.js";

type Dict = { [key: string]: CborValue };

/** Sessions a partner keeps open per asker by default and at most (annex I.6, *Sessions*). */
export const SESSIONS_DEFAULT = 4;
export const SESSIONS_FLOOR = 1;
export const SESSIONS_CEILING = 4;
/** Exchanges a session holds at most before it closes. */
export const EXCHANGES_MAX = 64;
/** How long a session lives with no exchange. */
export const IDLE_MILLIS = 30_000;
/** The budget an asker puts on its requests by default: 1 MiB, annex I.6's default. */
export const BUDGET_DEFAULT = 1 << 20;
/** The smallest budget an asker may set: a few nodes' worth, so every exchange still makes progress. */
export const BUDGET_FLOOR = 4 << 10;
/** The largest budget an asker may set, and the cap this member puts on an answer: half the 8 MiB frame. */
export const BUDGET_CEILING = 4 << 20;
/** Fetch bodies an asker keeps in flight per partner, so a join of many budgeted answers continues at once. */
export const FETCH_WINDOW = 4;
/** The shortest wait for a fetch's answer before its ids are asked of another member. */
export const FETCH_WAIT_FLOOR_MILLIS = 5_000;
/** The backoff before an id a partner left out is asked again: doubled per attempt up to the ceiling, jittered. */
export const RETRY_BASE_MILLIS = 1_000;
export const RETRY_CEILING_MILLIS = 30_000;
/** How long an id every member in view left out waits for an audit to name it again before it is forgotten. */
export const PARKED_MILLIS = 600_000;
/** Ids an asker keeps wanted per stream at most; past it the eldest waiting id goes, and a later audit finds it. */
export const WANTED_MAX = 1 << 17;
/** The fewest ids a fetch body names once a partner's answers have been cut by the budget. */
export const FETCH_IDS_FLOOR = 64;
/** How long an asker accepts the answer to a fetch: a copy after its wait is still applied when it is newer. */
export const LATE_COPY_MILLIS = 2 * IDLE_MILLIS;
/** Partners whose descents, sessions, openings and fetches this member tracks at most; the least recent go first. */
export const PARTNERS_MAX = 64;
/**
 * Openings a partner's root answers are owed for, at most: two, so that the answers to a round and to the opening a
 * continuation or a probe sent just after it are both read, and no older opening admits a root.
 */
export const ROOTS_OWED_MAX = 2;
/** Distinct (partner, reason) pairs logged once, at most. */
const LOGGED_MAX = 1024;

/** The reasons a refusal or a fallback is counted under, one key each, as Java's `TrieAudit.REFUSALS`. */
export const REFUSALS = [
  "undecodable", "lacks-hint", "request-without-session", "session-busy", "session-cooling", "session-capped",
  "unsolicited-answer", "fingerprint-mismatch", "shape-mismatch", "descent-capped", "repeated-request",
  "text-fallback",
] as const;

/** A tree node as the wire carries it: a request (`count`) or an answer (`nodes` or `lines`). */
export interface TreeNode {
  path: Uint8Array;
  count?: number;
  nodes?: Uint8Array;
  lines?: string;
}

/** What the audit needs of the peer it runs in. */
export interface AuditHost {
  /**
   * The trie of a stream this member audits, kept current; null for a stream it holds without a trie (the text digest
   * alone), undefined for one it does not hold.
   */
  trieFor(stream: string): HashTrie | null | undefined;
  /** Sends a DIGEST body to a member. */
  sendDigest(to: string, fields: DigestFields): void;
  /** Whether a member's current card carries `wire.ae=2` (and this member audits). */
  audits(member: string): boolean;
  now(): number;
  random(): number;
  /** Where a refusal is logged, once per member and reason. */
  log?(message: string): void;
}

/** One fetch body sent: its partner, its stream and ids, and when it went. */
export class Batch {
  late = false;
  private idSet: Set<string> | null = null;

  constructor(readonly partner: string, readonly stream: string, readonly ids: readonly string[],
              readonly sentAt: number) {}

  names(id: string): boolean {
    if (this.idSet === null) {
      this.idSet = new Set(this.ids);
    }
    return this.idSet.has(id);
  }
}

interface Session { lastMillis: number; exchanges: number }
/**
 * The rounds this member opened with a partner and not yet idled out, and the root answers each stream has taken
 * from them: a partner answers an opening with one root per stream that differs, so each opening admits one root
 * per stream and no more.
 */
interface Opened { at: number; openings: number; roots: Map<string, number> }
interface Expected { fingerprint: Uint8Array; count: number }
interface Pending { key: string; path: Uint8Array; count: number }

/** The asker's descent of one stream with one partner, from a root answer to the end of the round. */
class Descent {
  readonly expected = new Map<string, Expected>();
  pending: Pending[] = [];
  readonly inFlight = new Map<string, Pending>();
  lastMillis = 0;
  /** Answer bodies accepted, the root's included; the partner closes its session at the same bound. */
  exchanges = 0;
}

/** An entry id this member wants, and where it stands. */
class Wanted {
  /** The member it is ready for or in flight at; null while it waits to be asked again. */
  at: string | null = null;
  /** The body it is in flight in; null while it is ready or waits. */
  in: Batch | null = null;
  /** The members that left it out since an audit last named it. */
  readonly asked = new Set<string>();
  attempts = 0;
  dueAt = 0;
  /** When every member in view left it out; zero while it is not parked. */
  parkedAt = 0;
}

/** The audit's signals, counters that only grow (RE-F-03), and a few gauges. */
export interface AuditSignals {
  roundsAudited: number; sessionsOpened: number; rootsAnswered: number; requestsAnswered: number;
  nodesAnswered: number; answerBytesSent: number; requestsSent: number; answersReceived: number;
  answerBytesReceived: number; idsFetched: number; fetchesAnswered: number; openSessions: number;
  refusals: { [reason: string]: number }; fetchContinued: number; fetchRequeued: number; fetchTimedOut: number;
  fetchParked: number; fetchQueueFull: number; fetchQueued: number; fingerprintsChecked: number;
}

const pathKey = (path: Uint8Array): string => Array.from(path, (n) => n.toString(16)).join("");

const textOf = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/** The count a decoded node carries as a number; a count past a safe integer reads as infinite. */
function countOf(node: TreeNode): number {
  const count = node.count as number | bigint | undefined;
  if (typeof count === "bigint") {
    return count > BigInt(Number.MAX_SAFE_INTEGER) ? Number.POSITIVE_INFINITY : Number(count);
  }
  return count ?? 0;
}

/** Bytes of a tree node as the wire encodes it. */
export function encodedSize(node: TreeNode): number {
  return dumps(records.conform(node as unknown as Dict, records.TREE_NODE)).length;
}

/**
 * The partner's answer for one request (annex I.6, step 4): `lines` when its own count there or the request's count
 * is at most 32, `nodes` otherwise, except that lines which alone pass `cap` are answered as `nodes` so the asker
 * descends further. Every slot holds a line of at least four bytes, so a count past a quarter of the cap passes it
 * without being read.
 */
export function answerFor(trie: HashTrie, path: Uint8Array, askerCount: number, cap: number): TreeNode {
  const mine = trie.node(path);
  if (mine.count === 0) {
    return { path, lines: "" };
  }
  if (!mine.inner) {
    return { path, lines: textOf(mine.preimage) };
  }
  // The lines' bytes are known without a walk (their preimage is one byte shorter), so lines that would pass the cap
  // are answered as nodes at once: before, each such request walked up to the cap's worth of lines and threw them
  // away, and one body of 256 of them cost a partner of a million entries about 140 ms (adversarial review of
  // 2026-11-15). The answer is the one the walk gave.
  if (askerCount <= LEAF_MAX && mine.count * 4 <= cap && mine.bytes - 1 <= cap - 32) {
    const lines = trie.lines(path, cap - 32);
    return lines === null ? { path, nodes: mine.preimage } : { path, lines: textOf(lines) };
  }
  return { path, nodes: mine.preimage };
}

/** The children of an inner answer whose count at the partner is above 0 and that differ from this member's own. */
export function childrenThatDiffer(trie: HashTrie, path: Uint8Array, nodes: Uint8Array):
    { path: Uint8Array; expected: Expected; ownCount: number }[] {
  const out: { path: Uint8Array; expected: Expected; ownCount: number }[] = [];
  for (let c = 0; c < 16; c++) {
    const count = childCount(nodes, c);
    if (count === 0) {
      continue; // entries the partner lacks: its own round brings them
    }
    const child = new Uint8Array(path.length + 1);
    child.set(path);
    child[path.length] = c;
    const theirs = childFingerprint(nodes, c).slice();
    const own = trie.node(child);
    if (own.count === count && own.fingerprint !== null && equals(own.fingerprint, theirs)) {
      continue;
    }
    out.push({ path: child, expected: { fingerprint: theirs, count: count < 0 ? Number.POSITIVE_INFINITY : count },
      ownCount: own.count });
  }
  return out;
}

/**
 * The entry ids of the partner's lines under a path that this member's own lines there lack. Each line is looked up
 * in the one slot it names, so the cost follows the answer, not this member's own set under the path: a member of
 * many entries meets a partner of few every round, and gathering and sorting its whole set to compare a root of a
 * few lines cost it 0.34 s per round at 200,000 entries (adversarial review of 2026-11-15). The ids are the ones the
 * comparison with every own line gave, since a line names its slot's id.
 */
export function missingIds(trie: HashTrie, path: Uint8Array, lines: string): string[] {
  if (lines.length === 0) {
    return [];
  }
  const ids = new Set<string>();
  for (const line of lines.split("\n")) {
    const id = entryIdOf(line);
    if (id !== null && !ids.has(id) && !trie.holdsLine(id, line, path)) {
      ids.add(id);
    }
  }
  return [...ids];
}

/** Whether an inner preimage's sixteen counts sum to exactly the count its parent gave. */
function countsSumTo(nodes: Uint8Array, expected: number): boolean {
  let sum = 0;
  for (let c = 0; c < 16; c++) {
    const count = childCount(nodes, c);
    if (count < 0) {
      return false;
    }
    sum += count;
  }
  return sum === expected;
}

/** A map whose least recently touched key goes once it holds more than `max`. */
class Lru<V> extends Map<string, V> {
  constructor(private readonly max: number) {
    super();
  }

  touch(key: string, make: () => V): V {
    let value = super.get(key);
    if (value !== undefined) {
      super.delete(key);
    } else {
      value = make();
    }
    super.set(key, value);
    while (this.size > this.max) {
      this.delete(this.keys().next().value!);
    }
    return value;
  }

  override set(key: string, value: V): this {
    super.delete(key);
    super.set(key, value);
    while (this.size > this.max) {
      this.delete(this.keys().next().value!);
    }
    return this;
  }
}

/** Both halves of the annex I.6 audit for one peer. */
export class TrieAudit {
  private sessionsMaxValue = SESSIONS_DEFAULT;
  private budgetValue = BUDGET_DEFAULT;
  private fetchWindowValue = FETCH_WINDOW;

  private readonly refusalCounts = new Map<string, number>();
  private readonly logged = new Set<string>();
  private readonly counters = {
    roundsAudited: 0, sessionsOpened: 0, rootsAnswered: 0, requestsAnswered: 0, nodesAnswered: 0,
    answerBytesSent: 0, requestsSent: 0, answersReceived: 0, answerBytesReceived: 0, idsFetched: 0,
    fetchesAnswered: 0, fetchContinued: 0, fetchRequeued: 0, fetchTimedOut: 0, fetchParked: 0, fetchQueueFull: 0,
    fingerprintsChecked: 0,
  };

  private readonly sessions = new Lru<Map<string, Session>>(PARTNERS_MAX);
  private readonly cooling = new Lru<Set<string>>(PARTNERS_MAX);
  private readonly rotation = new Lru<number>(PARTNERS_MAX);
  private readonly descents = new Lru<Map<string, Descent>>(PARTNERS_MAX);
  private readonly opened = new Lru<Opened>(PARTNERS_MAX);
  // The fetch queue. Not bounded by eviction, since an id whose partner were evicted would never be asked again: it
  // holds only members this member fetched from, and a member that leaves the view gives its ids back.
  private readonly wanted = new Map<string, Map<string, Wanted>>();
  private readonly ready = new Map<string, Map<string, Set<string>>>();
  private readonly inFlight = new Map<string, Batch[]>();
  private readonly late = new Map<string, Batch[]>();
  private readonly answerMillis = new Lru<number>(PARTNERS_MAX);
  private readonly answerYield = new Lru<number>(PARTNERS_MAX);

  constructor(private readonly host: AuditHost) {}

  // ---- configuration (RE-F-03: each pace has a floor, a ceiling and a setter)

  get sessionsMax(): number {
    return this.sessionsMaxValue;
  }

  set sessionsMax(max: number) {
    if (!Number.isInteger(max) || max < SESSIONS_FLOOR || max > SESSIONS_CEILING) {
      throw new RangeError(`audit sessions must be from ${SESSIONS_FLOOR} to ${SESSIONS_CEILING}, not ${max}`);
    }
    this.sessionsMaxValue = max;
  }

  get budget(): number {
    return this.budgetValue;
  }

  set budget(bytes: number) {
    if (!Number.isInteger(bytes) || bytes < BUDGET_FLOOR || bytes > BUDGET_CEILING) {
      throw new RangeError(`the audit budget must be from ${BUDGET_FLOOR} to ${BUDGET_CEILING} bytes, not ${bytes}`);
    }
    this.budgetValue = bytes;
  }

  get fetchWindow(): number {
    return this.fetchWindowValue;
  }

  set fetchWindow(bodies: number) {
    if (!Number.isInteger(bodies) || bodies < 1 || bodies > 16) {
      throw new RangeError(`the fetch window must be from 1 to 16 bodies, not ${bodies}`);
    }
    this.fetchWindowValue = bodies;
  }

  // ---- counting

  /** Counts a refusal under its one key, and logs it once per member and reason. */
  refuse(from: string | null, stream: string | null, reason: string): void {
    this.refusalCounts.set(reason, (this.refusalCounts.get(reason) ?? 0) + 1);
    const key = `${from ?? "?"}|${reason}`;
    if (!this.logged.has(key)) {
      this.logged.add(key);
      if (this.logged.size > LOGGED_MAX) {
        this.logged.delete(this.logged.values().next().value!);
      }
      this.host.log?.(`anti-entropy ${reason} from ${from ?? "?"}${stream === null ? "" : ` on ${stream}`}; `
        + "counted, logged once per member");
    }
  }

  refusals(): { [reason: string]: number } {
    return Object.fromEntries([...this.refusalCounts].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  }

  signals(): AuditSignals {
    let open = 0;
    for (const byStream of this.sessions.values()) {
      open += byStream.size;
    }
    let queued = 0;
    for (const byId of this.wanted.values()) {
      queued += byId.size;
    }
    return { ...this.counters, openSessions: open, refusals: this.refusals(), fetchQueued: queued };
  }

  // ---- the asker opens a round

  /** Notes that this member opened a round with a partner, so a root answer from it is expected. */
  opening(partner: string): void {
    const now = this.host.now();
    this.expire(now);
    const opened = this.opened.touch(partner, () => ({ at: now, openings: 0, roots: new Map() }));
    opened.at = now;
    opened.openings += 1;
  }

  /**
   * Whether a root answer for a stream from a partner answers an opening this member sent, and takes it if so. A root
   * starts the stream's descent afresh with its exchange count at zero, so before this a partner that sent a root in
   * every body kept the asker descending past the 64-exchange bound for as long as the opening lived (adversarial
   * review of 2026-11-15); now an opening admits one root per stream, and a further one is unsolicited.
   */
  private takeRoot(from: string, stream: string): boolean {
    const opened = this.opened.get(from);
    if (opened === undefined) {
      return false;
    }
    // Only the last openings are owed a root: an opening whose hashes were equal draws none, and its credit must not
    // let a partner send a burst of roots later.
    const taken = Math.max(opened.roots.get(stream) ?? 0, opened.openings - ROOTS_OWED_MAX);
    if (taken >= opened.openings) {
      return false;
    }
    opened.roots.set(stream, taken + 1);
    return true;
  }

  /** Whether this member opened a round with a partner that has not idled out. */
  openedWith(partner: string): boolean {
    this.expire(this.host.now());
    return this.opened.has(partner);
  }

  // ---- the partner answers an opening

  /**
   * The partner's answer to an opening's stream hashes, for the space streams this member audits with the asker: a
   * root per stream whose hash differs, unless the stream waits for a later round. Streams whose hashes are equal
   * close their session. The streams are visited from a starting point that moves each round, so when the asker's
   * sessions are at their bound no stream waits for ever.
   */
  roots(from: string, differs: string[], equal: string[]): { [stream: string]: TreeNode[] } {
    const now = this.host.now();
    const tree: { [stream: string]: TreeNode[] } = {};
    const waited: [string, string][] = [];
    this.expire(now);
    const open = this.sessions.touch(from, () => new Map());
    for (const stream of equal) {
      open.delete(stream); // annex I.6: an opening that shows the hashes equal closes the session
    }
    const turn = (this.rotation.get(from) ?? 0) + 1;
    this.rotation.set(from, turn);
    const start = differs.length === 0 ? 0 : turn % differs.length;
    for (let i = 0; i < differs.length; i++) {
      const stream = differs[(start + i) % differs.length]!;
      const trie = this.host.trieFor(stream);
      if (trie === null || trie === undefined) {
        continue;
      }
      const root = trie.node(new Uint8Array(0));
      if (!root.inner) {
        // A root answered by lines finishes the stream for the round and takes no session.
        open.delete(stream);
        tree[stream] = [{ path: new Uint8Array(0), lines: textOf(root.preimage) }];
        continue;
      }
      let session = open.get(stream);
      if (session === undefined) {
        if (this.cooling.get(from)?.delete(stream)) {
          waited.push([stream, "session-cooling"]); // a capped session waits a full round
          continue;
        }
        if (open.size >= this.sessionsMaxValue) {
          waited.push([stream, "session-busy"]);
          continue;
        }
        session = { lastMillis: now, exchanges: 0 };
        open.set(stream, session);
        this.counters.sessionsOpened += 1;
      }
      // A reopening reuses the session and counts toward its bound, so reopening never resets it.
      session.lastMillis = now;
      session.exchanges += 1;
      if (session.exchanges >= EXCHANGES_MAX) {
        this.capped(from, stream, open);
      }
      tree[stream] = [{ path: new Uint8Array(0), nodes: root.preimage }];
    }
    if (open.size === 0) {
      this.sessions.delete(from);
    }
    for (const [stream, reason] of waited) {
      this.refuse(from, stream, reason);
    }
    const streams = Object.keys(tree);
    if (streams.length > 0) {
      this.counters.roundsAudited += 1;
      this.counters.rootsAnswered += streams.length;
      for (const nodes of Object.values(tree)) {
        this.counters.answerBytesSent += preimageBytes(nodes);
      }
    }
    return tree;
  }

  private capped(from: string, stream: string, open: Map<string, Session>): void {
    open.delete(stream);
    this.cooling.touch(from, () => new Set()).add(stream);
    this.refusalCounts.set("session-capped", (this.refusalCounts.get("session-capped") ?? 0) + 1);
  }

  /** Forgets every session idle for IDLE_MILLIS and every descent and opening as long untouched. */
  private expire(now: number): void {
    for (const [from, byStream] of [...this.sessions]) {
      for (const [stream, session] of [...byStream]) {
        if (now - session.lastMillis >= IDLE_MILLIS) {
          byStream.delete(stream);
        }
      }
      if (byStream.size === 0) {
        this.sessions.delete(from);
      }
    }
    for (const [from, byStream] of [...this.descents]) {
      for (const [stream, descent] of [...byStream]) {
        if (now - descent.lastMillis >= IDLE_MILLIS) {
          byStream.delete(stream);
        }
      }
      if (byStream.size === 0) {
        this.descents.delete(from);
      }
    }
    for (const [from, opened] of [...this.opened]) {
      if (now - opened.at >= IDLE_MILLIS) {
        this.opened.delete(from);
      }
    }
  }

  // ---- a body's tree

  /**
   * Handles the `tree` of a body: request nodes as the partner, answer nodes as the asker, each stream on its own,
   * the replies sent once the whole body is read.
   *
   * @param textRound whether this member's round with the sender went out in the hashed text form, since it had not
   *                  yet read the sender's card as one on `wire.ae=2`
   * @returns the streams of a round this member opened whose root came back although it keeps no trie for them, or
   *          although it opened the round in the text form; the caller answers those by the text form, as a `want`
   */
  onTree(from: string, tree: { [stream: string]: TreeNode[] }, budget: number | null, textRound: boolean): string[] {
    const answers: { [stream: string]: TreeNode[] } = {};
    const requests: { [stream: string]: TreeNode[] } = {};
    const fetch: [string, string[]][] = [];
    const fallback: string[] = [];
    for (const stream of Object.keys(tree).sort()) {
      const nodes = tree[stream]!;
      const trie = this.host.trieFor(stream);
      if (trie === undefined) {
        continue; // a stream this member does not hold says nothing to it
      }
      if (trie === null) {
        // The partner audits the stream and this member keeps the text digest alone, so the opening's hashes were
        // of two kinds and could never match: a root is answered by the text form.
        if (nodes.some((n) => n.count === undefined && n.path.length === 0) && this.openedWith(from)) {
          fallback.push(stream);
        }
        continue;
      }
      const auditOpen = textRound && this.openedWith(from);
      const asked: TreeNode[] = [];
      const answered: TreeNode[] = [];
      for (const node of nodes) {
        if (textRound && !auditOpen && node.count === undefined && node.path.length === 0) {
          // The sender read this member's card as one on wire.ae=2 before this member read the sender's, so it
          // compared a text hash with its trie and answered a root. The root says only that the stream differs,
          // which is what a want says: answered by the text form, as a want is.
          if (!fallback.includes(stream)) {
            fallback.push(stream);
          }
          continue;
        }
        (node.count !== undefined ? asked : answered).push(node);
      }
      if (asked.length > 0) {
        const reply = this.answerRequests(from, stream, trie, asked, budget);
        if (reply !== null) {
          answers[stream] = reply;
        }
      }
      if (answered.length > 0) {
        this.descend(from, stream, trie, answered, requests, fetch);
      }
    }
    if (Object.keys(answers).length > 0) {
      this.host.sendDigest(from, { tree: answers as unknown as { [stream: string]: Dict[] } });
    }
    if (Object.keys(requests).length > 0) {
      this.counters.requestsSent += 1;
      this.host.sendDigest(from, { tree: requests as unknown as { [stream: string]: Dict[] }, budget: this.budgetValue });
    }
    for (const [stream, ids] of fetch) {
      this.want(from, stream, ids);
    }
    for (const stream of fallback) {
      this.refuse(from, stream, "text-fallback");
    }
    return fallback;
  }

  /**
   * The partner's answer to request nodes within the session open for the asker and the stream, each node in the
   * order asked, up to the budget; null when no session is open, which drops and counts the requests.
   */
  private answerRequests(from: string, stream: string, trie: HashTrie, asked: TreeNode[],
                         askedBudget: number | null): TreeNode[] | null {
    const now = this.host.now();
    this.expire(now);
    const open = this.sessions.get(from);
    const session = open?.get(stream);
    if (session === undefined) {
      this.refuse(from, stream, "request-without-session");
      return null;
    }
    session.lastMillis = now;
    session.exchanges += 1;
    if (session.exchanges >= EXCHANGES_MAX) {
      this.capped(from, stream, open!); // this exchange is answered; a later one finds the session closed
      if (open!.size === 0) {
        this.sessions.delete(from);
      }
    }
    const cap = askedBudget === null ? BUDGET_CEILING : Math.min(askedBudget, BUDGET_CEILING);
    // The body's own bytes beside its nodes: the map, the stream name, the list head and the other fields.
    let used = 64 + stream.length;
    const reply: TreeNode[] = [];
    // An honest asker names each path once per session, so a repeated path is answered once: otherwise each copy
    // would cost a walk under it, and one small body could ask for hundreds of walks of the whole space.
    const seen = new Set<string>();
    let repeated = false;
    for (const request of asked) {
      const key = pathKey(request.path);
      if (seen.has(key)) {
        repeated = true;
        continue;
      }
      seen.add(key);
      const answer = answerFor(trie, request.path, countOf(request), cap);
      const size = encodedSize(answer);
      if (reply.length > 0 && used + size > cap) {
        break; // the rest wait for the budget: the asker asks them again in the next exchange
      }
      used += size;
      reply.push(answer);
    }
    if (repeated) {
      this.refuse(from, stream, "repeated-request");
    }
    this.counters.requestsAnswered += 1;
    this.counters.nodesAnswered += reply.length;
    this.counters.answerBytesSent += preimageBytes(reply);
    return reply;
  }

  /**
   * The asker's side of one stream's answers: check each against what its parent gave, compare it with this member's
   * own node, queue the children that differ, and collect the ids an answer of lines names that this member lacks.
   */
  private descend(from: string, stream: string, trie: HashTrie, answered: TreeNode[],
                  requests: { [stream: string]: TreeNode[] }, fetch: [string, string[]][]): void {
    const now = this.host.now();
    const refused: string[] = [];
    const accepted: TreeNode[] = [];
    this.expire(now);
    const byStream = this.descents.touch(from, () => new Map());
    let descent = byStream.get(stream);
    let exchanged = false;
    for (const answer of answered) {
      const key = pathKey(answer.path);
      const bytes = answer.nodes ?? utf8(answer.lines ?? "");
      if (answer.path.length === 0) {
        if (!this.takeRoot(from, stream)) {
          refused.push("unsolicited-answer"); // no opening, or a root more than the openings asked for
          continue;
        }
        // A root answer starts the stream's descent afresh: the partner's set may have moved since the last round.
        descent = new Descent();
        byStream.set(stream, descent);
        exchanged = true;
      } else {
        const expected = descent?.expected.get(key);
        if (expected === undefined || !descent!.inFlight.has(key)) {
          refused.push("unsolicited-answer"); // a late answer of a descent that moved on, or none asked
          continue;
        }
        exchanged = true;
        descent!.expected.delete(key);
        descent!.inFlight.delete(key);
        if (answer.nodes !== undefined || expected.count <= LEAF_MAX) {
          this.counters.fingerprintsChecked += 1;
          if (!equals(fingerprintOf(bytes), expected.fingerprint)) {
            refused.push("fingerprint-mismatch"); // the partner's set moved between two exchanges
            continue;
          }
        }
        if (answer.nodes !== undefined && !countsSumTo(answer.nodes, expected.count)) {
          refused.push("shape-mismatch"); // no honest set lists children that do not sum to their parent's count
          continue;
        }
      }
      if (answer.nodes !== undefined && answer.path.length >= PATH_MAX) {
        refused.push("shape-mismatch"); // a node at 64 nibbles is a leaf whatever its count
        continue;
      }
      descent!.lastMillis = now;
      this.counters.answersReceived += 1;
      this.counters.answerBytesReceived += bytes.length;
      accepted.push(answer);
    }
    if (exchanged) {
      descent!.exchanges += 1;
    }
    const differs: { path: Uint8Array; expected: Expected; ownCount: number }[] = [];
    const ids = new Set<string>();
    for (const answer of accepted) {
      if (answer.nodes !== undefined) {
        differs.push(...childrenThatDiffer(trie, answer.path, answer.nodes));
      } else {
        for (const id of missingIds(trie, answer.path, answer.lines ?? "")) {
          ids.add(id);
        }
      }
    }
    const next: TreeNode[] = [];
    // Only a body that answered something moves the descent. A body whose every answer was refused (unsolicited, a
    // root no opening is owed) asks nothing: before, it re-sent every request in flight without counting an
    // exchange, so a partner sending such bodies drew up to 256 request nodes per body for ever, past the 64-exchange
    // bound (adversarial review of 2026-11-15).
    if (exchanged && descent !== undefined && byStream.get(stream) === descent) {
      // No more can be asked in a descent than its remaining exchanges carry, so a partner listing ever more
      // children that differ cannot make the queue grow without bound.
      const room = Math.max(0, EXCHANGES_MAX - descent.exchanges) * records.TREE_NODES_MAX;
      let dropped = false;
      for (const child of differs) {
        if (descent.pending.length >= room) {
          dropped = true; // the next round's descent finds what is left
          break;
        }
        const key = pathKey(child.path);
        descent.expected.set(key, child.expected);
        descent.pending.push({ key, path: child.path, count: child.ownCount });
      }
      // A request this exchange left unanswered was left out for the budget: it is asked again first.
      for (const left of descent.inFlight.values()) {
        if (descent.expected.has(left.key)) {
          descent.pending.unshift(left);
        }
      }
      descent.inFlight.clear();
      if (descent.exchanges >= EXCHANGES_MAX) {
        // The partner's session closed with this exchange; what is left waits for the next round's root.
        if (dropped || descent.pending.length > 0) {
          refused.push("descent-capped");
        }
        descent.pending = [];
      }
      while (descent.pending.length > 0 && next.length < records.TREE_NODES_MAX) {
        const ask = descent.pending.shift()!;
        if (descent.inFlight.has(ask.key) || !descent.expected.has(ask.key)) {
          continue;
        }
        descent.inFlight.set(ask.key, ask);
        next.push({ path: ask.path, count: ask.count });
      }
      if (descent.pending.length === 0 && descent.inFlight.size === 0) {
        byStream.delete(stream); // nothing left to ask: the stream is done for the round
      }
    }
    if (byStream.size === 0) {
      this.descents.delete(from);
    }
    for (const reason of refused) {
      this.refuse(from, stream, reason);
    }
    if (next.length > 0) {
      requests[stream] = next;
    }
    if (ids.size > 0) {
      fetch.push([stream, [...ids]]);
    }
  }

  // ---- the fetch, the asker's side (annex I.6, The fetch; RE-I-01 to RE-I-03)

  /**
   * Queues the ids an audit with a partner found and sends what the window allows. An id already ready for or in
   * flight at a member stays there; one that waits to be asked again goes to this partner, whose audit has just
   * named it, and forgets which members left it out, since the audit is new evidence.
   */
  want(partner: string, stream: string, ids: Iterable<string>): void {
    const now = this.host.now();
    let byId = this.wanted.get(stream);
    if (byId === undefined) {
      byId = new Map();
      this.wanted.set(stream, byId);
    }
    let queue: Set<string> | null = null;
    for (const id of ids) {
      let w = byId.get(id);
      if (w === undefined) {
        if (byId.size >= WANTED_MAX && !this.evictWaiting(byId)) {
          this.counters.fetchQueueFull += 1; // a later audit names it again
          continue;
        }
        w = new Wanted();
        byId.set(id, w);
      } else if (w.at !== null) {
        continue;
      }
      w.at = partner;
      w.parkedAt = 0;
      w.asked.clear();
      if (queue === null) {
        let queues = this.ready.get(partner);
        if (queues === undefined) {
          queues = new Map();
          this.ready.set(partner, queues);
        }
        queue = queues.get(stream) ?? new Set();
        queues.set(stream, queue);
      }
      queue.add(id);
    }
    this.send(this.pump(partner, now));
  }

  private evictWaiting(byId: Map<string, Wanted>): boolean {
    for (const [id, w] of byId) {
      if (w.at === null) {
        byId.delete(id);
        this.counters.fetchQueueFull += 1;
        return true;
      }
    }
    return false;
  }

  /** The fetch bodies the window lets go to a partner now, each of at most 4,096 ids of one stream. */
  private pump(partner: string, now: number): Batch[] {
    const queues = this.ready.get(partner);
    if (queues === undefined) {
      return [];
    }
    let flying = this.inFlight.get(partner);
    if (flying === undefined) {
      flying = [];
      this.inFlight.set(partner, flying);
    }
    const out: Batch[] = [];
    const yieldOf = this.answerYield.get(partner);
    const perBody = yieldOf === undefined ? records.IDS_MAX
      : Math.max(FETCH_IDS_FLOOR, Math.min(records.IDS_MAX, 2 * yieldOf));
    for (const [stream, queue] of [...queues]) {
      if (flying.length >= this.fetchWindowValue) {
        break;
      }
      const byId = this.wanted.get(stream);
      while (flying.length < this.fetchWindowValue && queue.size > 0) {
        const ids: string[] = [];
        for (const id of queue) {
          if (ids.length >= perBody) {
            break;
          }
          ids.push(id);
        }
        for (const id of ids) {
          queue.delete(id);
        }
        const batch = new Batch(partner, stream, ids, now);
        for (const id of ids) {
          const w = byId?.get(id);
          if (w !== undefined) {
            w.in = batch;
          }
        }
        flying.push(batch);
        out.push(batch);
      }
      if (queue.size === 0) {
        queues.delete(stream);
      }
    }
    if (queues.size === 0) {
      this.ready.delete(partner);
    }
    if (flying.length === 0) {
      this.inFlight.delete(partner);
    }
    return out;
  }

  private send(batches: Batch[]): void {
    for (const batch of batches) {
      this.counters.idsFetched += batch.ids.length;
      this.host.sendDigest(batch.partner, { ids: { [batch.stream]: [...batch.ids] }, budget: this.budgetValue });
    }
  }

  /**
   * Whether a PULL_RESP from a partner answers a fetch this member sent: the stream of a body in flight at the partner
   * that the answer names, or one whose wait passed and whose late copy is still taken. Null for an answer that names
   * no such stream.
   */
  fetchAnswer(from: string, streams: Set<string>): string | null {
    if (streams.size === 0) {
      return null;
    }
    this.expireFetches(this.host.now());
    for (const byPartner of [this.inFlight, this.late]) {
      for (const batch of byPartner.get(from) ?? []) {
        if (streams.has(batch.stream)) {
          return batch.stream;
        }
      }
    }
    return null;
  }

  /**
   * Takes the body an answer settles: among the bodies in flight at the partner for the stream, the one whose ids the
   * answer carried most of, the eldest on a tie; failing those, a late one the same way. Matching by content keeps an
   * answer from being booked against another body when answers come back out of order or a frame is lost.
   */
  settle(from: string, stream: string, received: Set<string>): Batch | null {
    const batch = takeBest(this.inFlight, from, stream, received);
    if (batch !== null) {
      this.answerMillis.set(from, this.host.now() - batch.sentAt);
      return batch;
    }
    return takeBest(this.late, from, stream, received);
  }

  /**
   * What a fetch's answer brought: the ids it carried are no longer wanted, and the ids of the body it left out are
   * asked again, at once of the same partner when it counted a remainder and made progress, else after a jittered
   * backoff of the next member in view.
   */
  fetched(from: string, batch: Batch, received: Set<string>, left: number): void {
    const now = this.host.now();
    const byId = this.wanted.get(batch.stream);
    let out: Batch[] = [];
    if (byId !== undefined) {
      let progress = 0;
      for (const id of received) {
        const w = byId.get(id);
        if (w === undefined) {
          continue;
        }
        const ours = batch.names(id);
        if (ours) {
          progress += 1;
        }
        // An id in flight in another body stays; that body's answer settles it.
        if (w.at === null || (w.in === batch && ours)) {
          byId.delete(id);
        }
      }
      const missing = batch.ids.filter((id) => byId.get(id)?.in === batch);
      if (!batch.late && left > 0 && progress > 0) {
        this.answerYield.set(from, progress);
      }
      if (missing.length > 0) {
        if (left > 0 && progress > 0) {
          // The continuation: the partner holds them and ran out of budget, so they go to it again at once, first.
          let queues = this.ready.get(from);
          if (queues === undefined) {
            queues = new Map();
            this.ready.set(from, queues);
          }
          const front = new Set(missing);
          for (const id of queues.get(batch.stream) ?? []) {
            front.add(id);
          }
          const reordered = new Map<string, Set<string>>([[batch.stream, front]]);
          for (const [stream, queue] of queues) {
            if (stream !== batch.stream) {
              reordered.set(stream, queue);
            }
          }
          queues.clear();
          for (const [stream, queue] of reordered) {
            queues.set(stream, queue);
          }
          for (const id of missing) {
            const w = byId.get(id)!;
            w.in = null;
            w.at = from;
          }
          this.counters.fetchContinued += missing.length;
        } else {
          for (const id of missing) {
            this.requeue(byId.get(id)!, from, now);
          }
        }
      }
      if (byId.size === 0) {
        this.wanted.delete(batch.stream);
      }
    }
    if (!batch.late) {
      out = this.pump(from, now);
    }
    this.send(out);
  }

  private requeue(w: Wanted, leftOutBy: string, now: number): void {
    w.in = null;
    w.at = null;
    w.asked.add(leftOutBy);
    w.attempts += 1;
    const base = Math.min(RETRY_CEILING_MILLIS, RETRY_BASE_MILLIS * 2 ** Math.min(w.attempts - 1, 5));
    w.dueAt = now + base / 2 + this.host.random() * base; // half to one and a half times the base
    this.counters.fetchRequeued += 1;
  }

  private waitFor(partner: string): number {
    const last = this.answerMillis.get(partner);
    const wait = last === undefined ? FETCH_WAIT_FLOOR_MILLIS : 4 * last;
    return Math.max(FETCH_WAIT_FLOOR_MILLIS, Math.min(LATE_COPY_MILLIS, wait));
  }

  /** Moves every body whose wait passed to late, asking its ids again of another member; forgets old late bodies. */
  private expireFetches(now: number): void {
    for (const [partner, batches] of [...this.inFlight]) {
      const wait = this.waitFor(partner);
      for (const batch of [...batches]) {
        if (now - batch.sentAt < wait) {
          continue;
        }
        batches.splice(batches.indexOf(batch), 1);
        batch.late = true;
        this.counters.fetchTimedOut += 1;
        const lateOnes = this.late.get(partner) ?? [];
        lateOnes.push(batch);
        this.late.set(partner, lateOnes);
        const byId = this.wanted.get(batch.stream);
        for (const id of batch.ids) {
          const w = byId?.get(id);
          if (w !== undefined && w.in === batch) {
            this.requeue(w, partner, now);
          }
        }
      }
      if (batches.length === 0) {
        this.inFlight.delete(partner);
      }
    }
    for (const [partner, batches] of [...this.late]) {
      const kept = batches.filter((batch) => now - batch.sentAt <= LATE_COPY_MILLIS);
      if (kept.length === 0) {
        this.late.delete(partner);
      } else {
        this.late.set(partner, kept);
      }
    }
  }

  /**
   * The fetch queue's turn on a round (RE-I-03): bodies whose answer did not come are asked of another member, ids
   * whose backoff passed go to the next member in view that has not left them out and that audits with this member,
   * an id every such member left out is parked until an audit names it again, and a member that left the view gives
   * back what was ready for it.
   */
  retry(view: string[]): void {
    const now = this.host.now();
    this.expireFetches(now);
    const members = view.filter((member) => this.host.audits(member));
    if (members.length > 0) {
      const turn = Math.floor(this.host.random() * members.length);
      members.push(...members.splice(0, turn));
    }
    const inView = new Set(members);
    for (const [partner, queues] of [...this.ready]) {
      if (inView.has(partner)) {
        continue;
      }
      for (const [stream, queue] of queues) {
        const byId = this.wanted.get(stream);
        for (const id of queue) {
          const w = byId?.get(id);
          if (w !== undefined && w.in === null) {
            w.at = null;
            w.dueAt = now;
          }
        }
      }
      this.ready.delete(partner);
    }
    const touched = new Set<string>();
    for (const [stream, byId] of this.wanted) {
      for (const [id, w] of [...byId]) {
        if (w.at !== null) {
          continue;
        }
        if (w.parkedAt !== 0) {
          if (now - w.parkedAt >= PARKED_MILLIS) {
            byId.delete(id); // the audit is the liveness path; it names the id again if it is missing
          }
          continue;
        }
        if (w.dueAt > now) {
          continue;
        }
        const next = members.find((member) => !w.asked.has(member));
        if (next === undefined) {
          w.parkedAt = now;
          w.asked.clear();
          this.counters.fetchParked += 1;
          continue;
        }
        w.at = next;
        let queues = this.ready.get(next);
        if (queues === undefined) {
          queues = new Map();
          this.ready.set(next, queues);
        }
        const queue = queues.get(stream) ?? new Set<string>();
        queues.set(stream, queue);
        queue.add(id);
        touched.add(next);
      }
    }
    for (const [stream, byId] of [...this.wanted]) {
      if (byId.size === 0) {
        this.wanted.delete(stream);
      }
    }
    // Every member with ids ready: a body whose wait passed freed a place in its partner's window.
    for (const member of this.ready.keys()) {
      touched.add(member);
    }
    const out: Batch[] = [];
    for (const member of touched) {
      out.push(...this.pump(member, now));
    }
    this.send(out);
  }

  /** Counts a fetch body this member answered. */
  fetchAnswered(): void {
    this.counters.fetchesAnswered += 1;
  }

  /** Forgets every per-partner state of a member that left the view; its queued ids go to others. */
  memberLeft(member: string): void {
    this.sessions.delete(member);
    this.descents.delete(member);
    this.opened.delete(member);
    this.cooling.delete(member);
  }
}

function takeBest(byPartner: Map<string, Batch[]>, from: string, stream: string, received: Set<string>): Batch | null {
  const batches = byPartner.get(from);
  if (batches === undefined) {
    return null;
  }
  let best: Batch | null = null;
  let bestShared = -1;
  for (const batch of batches) {
    if (batch.stream !== stream) {
      continue;
    }
    let shared = 0;
    for (const id of received) {
      if (batch.names(id)) {
        shared += 1;
      }
    }
    if (shared > bestShared) { // strictly more, so the eldest wins a tie
      best = batch;
      bestShared = shared;
    }
  }
  if (best !== null) {
    batches.splice(batches.indexOf(best), 1);
    if (batches.length === 0) {
      byPartner.delete(from);
    }
  }
  return best;
}

function preimageBytes(nodes: TreeNode[]): number {
  let bytes = 0;
  for (const node of nodes) {
    bytes += node.nodes !== undefined ? node.nodes.length : (node.lines?.length ?? 0);
  }
  return bytes;
}

/** Whether an inner preimage is the size the annex fixes; a decoded `nodes` always is (records.ts checks it). */
export function isInnerPreimage(nodes: Uint8Array): boolean {
  return nodes.length === NODES_BYTES;
}
