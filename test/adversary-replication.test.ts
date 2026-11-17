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
 * The adversarial review of the TypeScript annex I.6 audit and the horizon (2026-11-15, deferred from phase 6 of
 * srad/replication-by-entry.md), as the Java adversaries of §10.6 and §10.7 broke Java. Each test names the defect it
 * showed before its fix:
 *
 * - a body whose every answer the asker refused (unsolicited, or a root no opening was owed) re-sent every request in
 *   flight without counting an exchange, so a partner sending such bodies drew up to 256 request nodes per body for
 *   ever, past the 64-exchange bound;
 * - a partner that sent a root answer in every body restarted the asker's descent at exchange zero, so one opening
 *   kept the asker descending past the 64-exchange bound for as long as the opening lived;
 * - an answer of lines made the asker gather and sort its whole own set under the path to compare it, 0.34 s per
 *   round at 200,000 entries against a partner of a few;
 * - a request the partner answered by nodes still walked up to the cap's worth of lines first and threw them away;
 * - any member could send a PULL_RESP naming a remainder and draw this peer's full text digests, up to 64 times per
 *   round, though this peer had asked it nothing;
 * - a probe whose hash differed rebuilt and rehashed the whole text digest of every space it named, to compare the
 *   other kind, on every probe, about 21 ms at 20,000 entries and linear in the space.
 *
 * Each fix keeps the bytes on the wire: the answers, the ids and the transcripts are the ones before, which the
 * equivalence tests below check against the rule they replaced.
 */

import assert from "node:assert/strict";
import test from "node:test";

import * as audit from "../src/audit.js";
import { TrieAudit } from "../src/audit.js";
import type { TreeNode } from "../src/audit.js";
import { Identity } from "../src/identity.js";
import { HorizonMode, LAPSED_GRACE_MILLIS } from "../src/horizon.js";
import { Peer } from "../src/peer.js";
import type { Repeating, TimerPort } from "../src/platform.js";
import { MemoryNetwork, settle } from "../src/transport/mem.js";
import { HashTrie, LEAF_MAX, entryIdOf } from "../src/trie.js";
import * as serving from "../src/serving.js";
import * as wire from "../src/wire.js";
import type { Dict, DigestFields } from "../src/wire.js";
import "../src/node/index.js";

const ROOT = new Uint8Array(0);
const STREAM = "space:x";
const HASH = "a".repeat(64);

/** A trie of `n` slots named `<prefix><i>`, each with one state line of a 64-character hash. */
function trieOf(n: number, prefix = "e"): HashTrie {
  const trie = new HashTrie();
  for (let i = 0; i < n; i++) {
    trie.put(`${prefix}${i}`, [`e:${prefix}${i}=${HASH}`]);
  }
  return trie;
}

class Harness {
  now = 1_800_000_000_000;
  readonly sent: { to: string; fields: DigestFields }[] = [];
  readonly tries = new Map<string, HashTrie>();
  readonly audit = new TrieAudit({
    trieFor: (stream) => this.tries.get(stream),
    sendDigest: (to, fields) => this.sent.push({ to, fields }),
    audits: () => true,
    now: () => this.now,
    random: () => 0.5,
  });

  /** The tree requests sent since `mark`. */
  requests(mark = 0): TreeNode[][] {
    return this.sent.slice(mark).map((s) => s.fields.tree?.[STREAM] as unknown as TreeNode[] | undefined)
      .filter((t): t is TreeNode[] => t !== undefined);
  }
}

/** Counts the lines `HashTrie.lines` reads while `run` runs: what a comparison or an answer walked of a set. */
function linesRead(run: () => void): number {
  const original = HashTrie.prototype.lines;
  let read = 0;
  HashTrie.prototype.lines = function (this: HashTrie, path: Uint8Array, maxBytes?: number): Uint8Array | null {
    const out = original.call(this, path, maxBytes);
    read += out === null ? (maxBytes ?? 0) : out.length;
    return out;
  };
  try {
    run();
  } finally {
    HashTrie.prototype.lines = original;
  }
  return read;
}

const textOf = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

test("Adversary: a root answer in every body no longer keeps the asker descending past one opening's bound", () => {
  const asker = new Harness();
  asker.tries.set(STREAM, new HashTrie()); // an empty set: every child of the partner's root differs
  const partner = trieOf(40);
  const root: TreeNode = { path: ROOT, nodes: partner.node(ROOT).preimage };
  asker.audit.opening("p");
  // A hostile partner sends a root in each of 200 bodies within one opening, and never answers a request.
  for (let i = 0; i < 200; i++) {
    asker.audit.onTree("p", { [STREAM]: [root] }, null, false);
  }
  // Before the fix every root restarted the descent at zero exchanges and drew a fresh body of requests: 200 bodies.
  assert.equal(asker.requests().length, 1, "one opening admits one root per stream");
  assert.equal(asker.audit.refusals()["unsolicited-answer"], 199);
  // Each new opening is owed one root, and an opening whose root never came lends no credit to a later burst.
  for (let i = 0; i < 10; i++) {
    asker.audit.opening("p");
  }
  const mark = asker.sent.length;
  for (let i = 0; i < 20; i++) {
    asker.audit.onTree("p", { [STREAM]: [root] }, null, false);
  }
  assert.equal(asker.requests(mark).length, audit.ROOTS_OWED_MAX, "at most the last two openings are owed a root");
});

test("Adversary: bodies of refused answers mid-descent draw no requests", () => {
  const asker = new Harness();
  asker.tries.set(STREAM, new HashTrie());
  const partner = trieOf(400);
  asker.audit.opening("p");
  asker.audit.onTree("p", { [STREAM]: [{ path: ROOT, nodes: partner.node(ROOT).preimage }] }, null, false);
  assert.equal(asker.requests().length, 1, "the root drew the first requests");
  // The partner never answers them; it sends 200 bodies, each an answer at a path the asker never asked.
  const mark = asker.sent.length;
  for (let i = 0; i < 200; i++) {
    const path = Uint8Array.of(i % 16, (i >> 4) % 16, 3);
    asker.audit.onTree("p", { [STREAM]: [{ path, lines: `e:x${i}=1` }] }, null, false);
  }
  // Before the fix each body re-sent the 16 requests in flight, uncounted: 200 bodies of requests.
  assert.equal(asker.requests(mark).length, 0);
  assert.equal(asker.audit.refusals()["unsolicited-answer"], 200);
  // The descent is still there for the partner's real answers.
  const answers: TreeNode[] = asker.requests()[0]!.map((r) => {
    const own = partner.node(r.path);
    return own.inner ? { path: r.path, nodes: own.preimage } : { path: r.path, lines: textOf(own.preimage) };
  });
  asker.audit.onTree("p", { [STREAM]: answers }, null, false);
  assert.ok(asker.sent.length > mark, "the real answers move the descent on");
});

test("Adversary: two openings in flight still read both roots, in either order", () => {
  const asker = new Harness();
  asker.tries.set(STREAM, new HashTrie());
  const partner = trieOf(40);
  const root: TreeNode = { path: ROOT, nodes: partner.node(ROOT).preimage };
  asker.audit.opening("p"); // a round
  asker.audit.opening("p"); // a continuation's or a probe's opening just after it
  asker.audit.onTree("p", { [STREAM]: [root] }, null, false);
  asker.audit.onTree("p", { [STREAM]: [root] }, null, false);
  assert.equal(asker.requests().length, 2);
  assert.equal(asker.audit.refusals()["unsolicited-answer"], undefined, "an honest pair of answers is no refusal");
});

test("Adversary: comparing a partner's lines costs the asker what the answer holds, not its own set", () => {
  const asker = new Harness();
  const own = trieOf(20_000);
  asker.tries.set(STREAM, own);
  // A partner of three entries answers its root by lines: two the asker holds and one it lacks.
  const lines = ["e:e7=" + HASH, "e:e9=" + HASH, "e:fresh=" + HASH].sort();
  asker.audit.opening("p");
  const started = performance.now();
  const read = linesRead(() => asker.audit.onTree("p", { [STREAM]: [{ path: ROOT, lines: lines.join("\n") }] }, null, false));
  const millis = performance.now() - started;
  // Before the fix the asker read all 20,000 of its lines, about 1.5 MB, sorted them, and split them into a set.
  assert.equal(read, 0, "no walk of the asker's own set");
  const fetched = asker.sent.flatMap((s) => (s.fields.ids?.[STREAM] ?? []) as string[]);
  assert.deepEqual(fetched, ["fresh"]);
  console.log(`a root of 3 lines against 20,000 own entries: compared in ${millis.toFixed(1)} ms`);
});

test("Adversary: the per-slot comparison names exactly the ids the comparison with every own line named", () => {
  let seed = 11;
  const random = (): number => {
    seed = (seed * 1103515245 + 12345) % 2 ** 31;
    return seed / 2 ** 31;
  };
  /** The rule replaced: every own line under the path in a set, and the partner's lines not in it. */
  const oracle = (trie: HashTrie, path: Uint8Array, lines: string): string[] => {
    const ownLines = trie.lines(path)!;
    const mine = new Set(ownLines.length === 0 ? [] : textOf(ownLines).split("\n"));
    const ids = new Set<string>();
    for (const line of lines.split("\n")) {
      const id = entryIdOf(line);
      if (!mine.has(line) && id !== null) {
        ids.add(id);
      }
    }
    return [...ids].sort();
  };
  for (let round = 0; round < 40; round++) {
    const trie = new HashTrie();
    const theirs = new Map<string, string[]>();
    for (let i = 0; i < 300; i++) {
      const id = `id-${Math.floor(random() * 400)}`;
      const own = [`e:${id}=${Math.floor(random() * 3)}`];
      if (random() < 0.3) {
        own.push(`c:${id}=k${Math.floor(random() * 2)}`);
      }
      trie.put(id, own);
      // The partner's slot: the same lines, another version, or a claim more; some ids only the partner holds.
      const other = random() < 0.6 ? own : [`e:${id}=${Math.floor(random() * 3)}`];
      theirs.set(random() < 0.1 ? `${id}-only` : id, other.map((l) => (random() < 0.1 ? l.replace(id, `${id}-only`) : l)));
    }
    for (let depth = 0; depth < 3; depth++) {
      const path = Uint8Array.from({ length: depth }, () => Math.floor(random() * 16));
      // Lines from anywhere, under the path or not, as a hostile partner may send them.
      const lines = [...new Set([...theirs.values()].flat())].filter(() => random() < 0.5);
      const text = lines.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))).join("\n");
      assert.deepEqual(audit.missingIds(trie, path, text).sort(), oracle(trie, path, text));
    }
  }
});

test("Adversary: a request answered by nodes walks no lines it could not send", () => {
  // Sixteen children of about 6,250 slots: four bytes a slot fits a 64 KiB cap, but their 85-byte lines never do.
  const trie = trieOf(100_000);
  const cap = 64 << 10;
  const requests: TreeNode[] = Array.from({ length: 16 }, (_, c) => ({ path: Uint8Array.of(c), count: 0 }));
  for (const request of requests) {
    assert.ok(trie.node(request.path).count * 4 <= cap, "the count alone would let the walk start");
  }
  let answers: TreeNode[] = [];
  const read = linesRead(() => {
    answers = requests.map((r) => audit.answerFor(trie, r.path, 0, cap));
  });
  // Before the fix each of the 16 walked up to 64 KiB of lines and threw them away: about 1 MB for nothing.
  assert.equal(read, 0);
  assert.ok(answers.every((a) => a.nodes !== undefined));
});

test("Adversary: the byte totals stay exact through any history, and answers equal the walking rule's", () => {
  let seed = 5;
  const random = (): number => {
    seed = (seed * 1103515245 + 12345) % 2 ** 31;
    return seed / 2 ** 31;
  };
  /** The rule replaced: lines when the walk under the cap succeeds, nodes otherwise. */
  const oracle = (trie: HashTrie, path: Uint8Array, askerCount: number, cap: number): TreeNode => {
    const mine = trie.node(path);
    if (mine.count === 0) {
      return { path, lines: "" };
    }
    if (!mine.inner) {
      return { path, lines: textOf(mine.preimage) };
    }
    if (askerCount <= LEAF_MAX && mine.count * 4 <= cap) {
      const lines = trie.lines(path, cap - 32);
      return lines === null ? { path, nodes: mine.preimage } : { path, lines: textOf(lines) };
    }
    return { path, nodes: mine.preimage };
  };
  const trie = new HashTrie();
  for (let step = 0; step < 4_000; step++) {
    const id = `id-${Math.floor(random() * 600)}-${"é".repeat(Math.floor(random() * 3))}`;
    const pick = random();
    if (pick < 0.25) {
      trie.remove(id);
    } else {
      const lines = [`e:${id}=${"0".repeat(1 + Math.floor(random() * 40))}`];
      if (pick > 0.8) {
        lines.push(`c:${id}=claim${Math.floor(random() * 9)}`);
      }
      trie.put(id, lines);
    }
    if (step % 200 === 199) {
      for (let probe = 0; probe < 20; probe++) {
        const path = Uint8Array.from({ length: Math.floor(random() * 3) }, () => Math.floor(random() * 16));
        const node = trie.node(path);
        const all = trie.lines(path)!;
        assert.equal(node.count === 0 ? 0 : node.bytes - 1, all.length, "bytes are the lines' preimage plus one");
        const cap = [256, 2_048, 8_192, 1 << 20][Math.floor(random() * 4)]!;
        const askerCount = random() < 0.7 ? Math.floor(random() * 33) : 40;
        assert.deepEqual(audit.answerFor(trie, path, askerCount, cap), oracle(trie, path, askerCount, cap));
      }
    }
  }
});

/** A peer that records what it sends and can send a body of its choosing. */
class Probe extends Peer {
  readonly sent: { kind: string; to: string | null; body: Uint8Array }[] = [];

  protected override send(kind: string, body: Uint8Array, to: string | null = null, scope: "all" | "dial" = "all"): void {
    this.sent.push({ kind, to, body });
    super.send(kind, body, to, scope);
  }

  /** Sends any body to a member, as a hostile peer would. */
  sendRaw(kind: string, body: Uint8Array, to: string): void {
    super.send(kind, body, to);
  }
}

test("Adversary: an unsolicited PULL_RESP naming a remainder draws nothing from this peer", async () => {
  const net = new MemoryNetwork();
  const hub = new Probe(Identity.generate(), "zAdversaryTs");
  hub.endpoints.push({ transport: "mem", address: "hub:1", priority: 0 });
  const close = await net.listen("hub:1", (channel) => hub.acceptChannel(channel));
  hub.pullSpace("tasks");
  const hostile = new Probe(Identity.generate(), "zAdversaryTs");
  hostile.registerDialer(net.dialer());
  try {
    await hostile.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    hostile.pullSpace("tasks");
    await settle();
    hub.introduce();
    hostile.introduce();
    await settle();
    for (let i = 0; i < 20; i++) {
      hub.writeEntry("tasks", "com.acme.Task#v1", { n: i }, "hub");
    }
    await settle();
    const target = hub.identity.peerId;
    const mark = hub.sent.length;
    const before = hub.pacing.pullContinued;
    // Twenty bodies of a few bytes, each claiming that the hub's pull of the space was cut by a budget.
    for (let i = 0; i < 20; i++) {
      hostile.sendRaw("PULL_RESP", wire.pullRespBody({}, { "space:tasks": 5, ads: 3 }), target);
    }
    await settle();
    const drawn = hub.sent.slice(mark).filter((f) => f.to === hostile.identity.peerId && f.kind === "DIGEST");
    // Before the fix the hub continued each one: 20 continuations, each a full text digest or a new opening.
    assert.equal(hub.pacing.pullContinued, before, "no continuation of a pull the hub never sent");
    assert.equal(drawn.length, 0);
    assert.equal(hub.pacing.remainderUnsolicited, 20);
  } finally {
    close();
    hub.close();
    hostile.close();
  }
});

test("Adversary: a budgeted pull still continues through its remainders while rounds run", async () => {
  const net = new MemoryNetwork();
  const hub = new Probe(Identity.generate(), "zAdversaryTs2");
  hub.endpoints.push({ transport: "mem", address: "hub:1", priority: 0 });
  const close = await net.listen("hub:1", (channel) => hub.acceptChannel(channel));
  hub.pullSpace("tasks");
  for (let i = 0; i < 200; i++) {
    hub.writeEntry("tasks", "com.acme.Task#v1", { n: i, pad: "x".repeat(2_000) }, "hub");
  }
  const late = new Probe(Identity.generate(), "zAdversaryTs2");
  late.auditBudget = 16 << 10;
  late.registerDialer(net.dialer());
  try {
    await late.connectAny([{ host: "hub", port: 1, scheme: "mem" }]);
    await settle();
    hub.introduce();
    late.introduce();
    await settle();
    late.pullSpace("tasks");
    const start = Date.now();
    while (late.states.size < 200) {
      if (Date.now() - start > 30_000) {
        throw new Error(`the join stopped at ${late.states.size} of 200`);
      }
      late.antiEntropyRound(); // a round clears the partners whose answer to a round is awaited
      await settle();
    }
    assert.ok(late.pacing.pullContinued > 0, "the join went on by its remainders");
    assert.equal(late.pacing.remainderUnsolicited, 0, "no answer of the join was taken for unsolicited");
    console.log(`budgeted join of 200 x 2 KB with rounds running: ${Date.now() - start} ms, `
      + `${late.pacing.pullContinued} continuations`);
  } finally {
    close();
    hub.close();
    late.close();
  }
});


test("Adversary: a probe whose hash differs compares the text kind without rebuilding an unchanged digest", () => {
  const a = new Probe(Identity.generate(), "zAdversaryTs3");
  const b = new Probe(Identity.generate(), "zAdversaryTs3");
  a.pullSpace("tasks");
  const ids: string[] = [];
  for (let i = 0; i < 300; i++) {
    ids.push(a.writeEntry("tasks", "com.acme.Task#v1", { n: i }, "w"));
  }
  const reader = a as unknown as {
    acceptPeerAd(payload: Uint8Array): void; onProbeHashes(from: string, ping: Dict): void;
    acknowledgeLine(line: string, spaceId: string): void; acknowledgedLines(space: string): string;
  };
  reader.acceptPeerAd(wire.signedPeerAd((b as unknown as { selfAd(): Dict }).selfAd(), b.identity));
  assert.ok(a.audits(b.identity.peerId));
  /** The digest as the rule builds it, from the maps alone. */
  const fresh = (): string => {
    const summary = new Map<string, string>();
    for (const [id, dto] of a.states) {
      summary.set(`e:${id}`, serving.stateHash(dto));
    }
    for (const [id, signed] of a.claims) {
      if (a.states.has(id)) {
        summary.set(`c:${id}`, serving.claimHash(signed["claim"] as Dict));
      }
    }
    return serving.digestLines(summary) + reader.acknowledgedLines("tasks");
  };
  const first = a.spaceDigest("tasks");
  const started = performance.now();
  for (let i = 0; i < 50; i++) {
    reader.onProbeHashes(b.identity.peerId, { nonce: i, hashes: { "space:tasks": new Uint8Array(32) } });
  }
  const millis = (performance.now() - started) / 50;
  // Before the fix every call built a new digest of every state; now an unchanged replica returns the one it built.
  assert.equal(a.spaceDigest("tasks"), first, "no rebuild while nothing changed");
  console.log(`a probe whose hash differs, 300 entries: ${millis.toFixed(2)} ms each`);
  // Every kind of change moves it, and it is what the rule builds afresh.
  const checks: [string, () => void][] = [
    ["a write", () => { ids.push(a.writeEntry("tasks", "com.acme.Task#v1", { n: 1_000 }, "w")); }],
    ["a renewal", () => a.renewEntry("tasks", ids[0]!, 3_600_000)],
    ["a cancel", () => a.cancelEntry("tasks", ids[1]!)],
    ["an acknowledgement", () => reader.acknowledgeLine(`e:gone=${HASH}`, a.states.get(ids[2]!)!["record"]!["spaceId" as never] as string)],
    ["a collection", () => { a.states.delete(ids[3]!); }],
  ];
  for (const [what, change] of checks) {
    const before = new TextDecoder().decode(a.spaceDigest("tasks"));
    change();
    const after = new TextDecoder().decode(a.spaceDigest("tasks"));
    assert.notEqual(after, before, `${what} changes the digest`);
    assert.equal(after, fresh(), `${what}: the kept digest is the one the rule builds`);
  }
});

/** Timers the test runs by hand. */
class ManualTimers implements TimerPort {
  setTimeout(): unknown {
    return null;
  }

  clearTimeout(): void {
    // nothing is scheduled to clear
  }

  every(): Repeating {
    return { lastDriftMillis: 0, lateRuns: 0, stop: () => {} };
  }
}

/** A member on a shared settable clock whose rumors are handed over by the test. */
class Clocked extends Peer {
  readonly rumors: Uint8Array[] = [];
  private counter = 0;

  constructor(private readonly clock: { millis: number }) {
    super(Identity.generate(), "zAdversaryHorizon", () => clock.millis);
    this.timers = new ManualTimers();
  }

  protected override send(kind: string, body: Uint8Array): void {
    if (kind === "RUMOR") {
      this.rumors.push(body);
    }
  }

  deliver(sender: Peer, body: Uint8Array): void {
    const stamp = `${this.clock.millis}:${this.counter++}:${sender.identity.peerId}`;
    (this as unknown as { onFrame(frame: Uint8Array): void }).onFrame(wire.encodeFrame(
      wire.envelope("zAdversaryHorizon", "RUMOR", sender.identity.peerId, stamp, body, this.identity.peerId),
      sender.identity));
  }

  meet(other: Peer): void {
    const ad = (other as unknown as { selfAd(): Dict }).selfAd();
    this.deliver(other, wire.rumorBody("peers", `peer:${other.identity.peerId}:${this.clock.millis}`, 6,
      wire.signedPeerAd(ad, other.identity)));
  }
}

const MINUTE = 60_000;

test("Adversary (guard): a vouched writer that leaves the view and comes back starts a new stay", () => {
  const clock = { millis: 1_800_000_000_000 };
  const a = new Clocked(clock);
  const b = new Clocked(clock);
  a.meet(b);
  a.writeEntry("tasks", "com.acme.Task#v1", { n: 0 }, "w", 60 * MINUTE); // the longest lease: one hour
  for (let round = 0; round < 4; round++) {
    a.collectTombstones();
    clock.millis += 1_000;
  }
  clock.millis += 65 * MINUTE;
  a.collectTombstones();
  assert.equal(a.horizonModeOf("tasks"), "PER_ENTRY");
  // b's card lapses and b leaves the view; while out of sight it could have renewed anything. It comes back.
  clock.millis += 11 * MINUTE;
  (a as unknown as { dialPeers: Set<string> }).dialPeers.delete(b.identity.peerId); // its link dropped
  assert.deepEqual(a.expireMembers(), [b.identity.peerId]);
  a.meet(b);
  const id = b.writeEntry("tasks", "com.acme.Task#v1", { n: 1 }, "w", MINUTE);
  const expiry = clock.millis + MINUTE;
  b.cancelEntry("tasks", id);
  for (const body of b.rumors) {
    a.deliver(b, body);
  }
  assert.ok(a.states.has(id));
  clock.millis = expiry + 11 * MINUTE;
  a.collectTombstones();
  assert.ok(a.states.has(id), "a writer back for less than one maximum lease and the grace is not vouched for");
  clock.millis = expiry + 120 * MINUTE;
  a.collectTombstones();
  assert.equal(a.states.has(id), false, "collected at the legacy horizon");
});

test("Adversary (guard): a clock that steps back while settling never brings the per-entry rule in early", () => {
  const mode = new HorizonMode();
  let now = 1_800_000_000_000;
  const maxLease = 60 * MINUTE;
  for (let round = 0; round <= 3; round++) {
    mode.judge(now, true, 1_000, maxLease);
    now += 1_000;
  }
  assert.equal(mode.mode, "SETTLING");
  now -= 30 * MINUTE; // the clock steps back half an hour
  mode.judge(now, true, 1_000, maxLease);
  now += maxLease + LAPSED_GRACE_MILLIS - 1;
  assert.equal(mode.judge(now, true, 1_000, maxLease), "legacy", "the wait counts from the step back");
  assert.equal(mode.judge(now + 1, true, 1_000, maxLease), "per-entry");
  // One judgement with an unhinted view drops it at once, and the streak starts over.
  assert.equal(mode.judge(now + 2, false, 1_000, maxLease), "legacy");
  assert.equal(mode.mode, "LEGACY");
  assert.equal(mode.judge(now + 1_000, true, 1_000, maxLease), "legacy");
  assert.equal(mode.mode, "WAITING");
});
