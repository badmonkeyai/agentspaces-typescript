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
 * The annex I.6 audit's own rules, on TrieAudit with a fake host and a fake clock (srad/replication-by-entry.md
 * RE-T-04, RE-T-05, RE-I-01 to RE-I-03; ROBUSTNESS.md §10): the trie's canonical shape over histories, the session
 * bounds, the asker's checks of each answer, the budget on answers, and the fetch queue's re-queue, next member,
 * jittered backoff, parking, continuation and late copies.
 */

import assert from "node:assert/strict";
import test from "node:test";

import * as audit from "../src/audit.js";
import { TrieAudit } from "../src/audit.js";
import type { TreeNode } from "../src/audit.js";
import { HashTrie, LEAF_MAX } from "../src/trie.js";
import type { DigestFields } from "../src/wire.js";
import "../src/node/index.js";

const ROOT = new Uint8Array(0);

/** A trie of `n` slots named `<prefix><i>`, each with one state line. */
function trieOf(n: number, prefix = "e", version = "0"): HashTrie {
  const trie = new HashTrie();
  for (let i = 0; i < n; i++) {
    trie.put(`${prefix}${i}`, [`e:${prefix}${i}=${version}`]);
  }
  return trie;
}

class Harness {
  now = 1_800_000_000_000;
  readonly sent: { to: string; fields: DigestFields }[] = [];
  readonly tries = new Map<string, HashTrie>();
  readonly members = new Set<string>();
  readonly audit = new TrieAudit({
    trieFor: (stream) => this.tries.get(stream),
    sendDigest: (to, fields) => this.sent.push({ to, fields }),
    audits: (member) => this.members.has(member),
    now: () => this.now,
    random: () => 0.5,
  });
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

test("the trie's shape is a function of the set: equal sets by any history give equal roots", () => {
  let seed = 7;
  const random = (): number => {
    seed = (seed * 1103515245 + 12345) % 2 ** 31;
    return seed / 2 ** 31;
  };
  for (let round = 0; round < 3; round++) {
    const model = new Map<string, string>();
    const a = new HashTrie();
    for (let step = 0; step < 1500; step++) {
      const id = `id-${Math.floor(random() * 120)}`;
      if (random() < 0.35) {
        a.remove(id);
        model.delete(id);
      } else {
        const line = `e:${id}=${Math.floor(random() * 4)}`;
        a.put(id, [line]);
        model.set(id, line);
      }
    }
    // The same set built in another order, and from scratch, has the same stream hash and the same nodes.
    const b = new HashTrie();
    for (const [id, line] of [...model].reverse()) {
      b.put(id, [line]);
    }
    assert.equal(a.size, model.size);
    assert.equal(hex(a.streamHash()), hex(b.streamHash()));
    for (let c = 0; c < 16; c++) {
      const path = Uint8Array.of(c);
      assert.equal(hex(a.node(path).preimage), hex(b.node(path).preimage));
    }
    // A different set never shares the hash.
    const id = [...model.keys()][0]!;
    b.put(id, [`${model.get(id)!}x`]);
    assert.notEqual(hex(a.streamHash()), hex(b.streamHash()));
  }
});

test("a leaf splits past 32 slots and collapses back at 32", () => {
  const trie = trieOf(LEAF_MAX);
  assert.equal(trie.node(ROOT).inner, false);
  trie.put("extra", ["e:extra=0"]);
  assert.equal(trie.node(ROOT).inner, true);
  assert.equal(trie.node(ROOT).count, 33);
  trie.remove("extra");
  assert.equal(trie.node(ROOT).inner, false);
  assert.equal(hex(trie.streamHash()), hex(trieOf(LEAF_MAX).streamHash()));
});

test("a partner keeps at most four sessions per asker; the fifth stream waits and is counted", () => {
  const h = new Harness();
  const streams = ["space:a", "space:b", "space:c", "space:d", "space:e"];
  for (const s of streams) {
    h.tries.set(s, trieOf(40, s));
  }
  const roots = h.audit.roots("asker", streams, []);
  assert.equal(Object.keys(roots).length, 4);
  assert.equal(h.audit.refusals()["session-busy"], 1);
  assert.equal(h.audit.signals().openSessions, 4);
  // An opening that shows a stream equal closes its session, so the waiting stream gets one.
  const next = h.audit.roots("asker", streams.filter((s) => s !== "space:a"), ["space:a"]);
  assert.equal(Object.keys(next).length, 4);
  assert.ok("space:e" in next);
});

test("a session idles out after 30 s, closes at 64 exchanges, and a capped stream waits one round", () => {
  const h = new Harness();
  h.tries.set("space:a", trieOf(40));
  h.audit.roots("asker", ["space:a"], []);
  h.now += 30_000;
  assert.equal(h.audit.signals().openSessions, 1, "idle sessions go at the next exchange");
  h.audit.roots("asker", ["space:a"], []);
  assert.equal(h.audit.signals().sessionsOpened, 2, "the idle one went; a new one opened");
  for (let i = 1; i < audit.EXCHANGES_MAX; i++) {
    h.audit.roots("asker", ["space:a"], []);
  }
  assert.equal(h.audit.refusals()["session-capped"], 1);
  assert.deepEqual(Object.keys(h.audit.roots("asker", ["space:a"], [])), [], "the capped stream cools a round");
  assert.equal(h.audit.refusals()["session-cooling"], 1);
  assert.deepEqual(Object.keys(h.audit.roots("asker", ["space:a"], [])), ["space:a"]);
});

test("a root answered by lines takes no session; a request without one is refused", () => {
  const h = new Harness();
  h.tries.set("space:a", trieOf(10));
  const roots = h.audit.roots("asker", ["space:a"], []);
  assert.equal(typeof roots["space:a"]![0]!.lines, "string");
  assert.equal(h.audit.signals().openSessions, 0);
  h.audit.onTree("asker", { "space:a": [{ path: Uint8Array.of(1), count: 3 }] }, null, false);
  assert.equal(h.sent.length, 0);
  assert.equal(h.audit.refusals()["request-without-session"], 1);
});

test("a request naming one path twice is answered once for it", () => {
  const h = new Harness();
  h.tries.set("space:a", trieOf(300));
  h.audit.roots("asker", ["space:a"], []);
  h.audit.onTree("asker", { "space:a": [{ path: Uint8Array.of(3), count: 1 }, { path: Uint8Array.of(3), count: 1 }] },
    null, false);
  const answers = h.sent[0]!.fields.tree!["space:a"]!;
  assert.equal(answers.length, 1);
  assert.equal(h.audit.refusals()["repeated-request"], 1);
});

test("answers stop at the budget, the first always carried, and the asker asks the rest next", () => {
  const partner = new Harness();
  const asker = new Harness();
  partner.tries.set("space:a", trieOf(3000, "p"));
  asker.tries.set("space:a", new HashTrie());
  asker.audit.opening("partner");
  const roots = partner.audit.roots("asker", ["space:a"], []);
  asker.audit.onTree("partner", roots as { [s: string]: TreeNode[] }, null, false);
  const request = asker.sent.find((s) => s.fields.tree !== undefined)!;
  const asked = request.fields.tree!["space:a"]! as unknown as TreeNode[];
  assert.equal(asked.length, 16);
  partner.audit.onTree("asker", { "space:a": asked }, audit.BUDGET_FLOOR, false);
  const answered = partner.sent.at(-1)!.fields.tree!["space:a"]! as unknown as TreeNode[];
  assert.ok(answered.length >= 1 && answered.length < 16, `${answered.length} answers under a 4 KiB budget`);
  asker.sent.length = 0;
  asker.audit.onTree("partner", { "space:a": answered }, null, false);
  const again = asker.sent.find((s) => s.fields.tree !== undefined)!.fields.tree!["space:a"]! as unknown as TreeNode[];
  const left = asked.slice(answered.length).map((n) => n.path[0]);
  for (const nibble of left) {
    assert.ok(again.some((n) => n.path.length === 1 && n.path[0] === nibble), `path ${nibble} asked again`);
  }
});

test("the asker refuses an answer it never asked, one whose fingerprint fails, and counts that do not sum", () => {
  const partner = new Harness();
  const asker = new Harness();
  partner.tries.set("space:a", trieOf(300, "p"));
  asker.tries.set("space:a", trieOf(300, "q"));
  asker.audit.onTree("partner", { "space:a": [{ path: ROOT, nodes: partner.tries.get("space:a")!.node(ROOT).preimage }] },
    null, false);
  assert.equal(asker.audit.refusals()["unsolicited-answer"], 1, "a root from a partner it opened nothing with");
  asker.audit.opening("partner");
  const root = partner.audit.roots("asker", ["space:a"], []);
  asker.audit.onTree("partner", root as { [s: string]: TreeNode[] }, null, false);
  const asked = asker.sent.at(-1)!.fields.tree!["space:a"]! as unknown as TreeNode[];
  // A forged answer for the first path asked: lines whose fingerprint is not the one the root gave.
  asker.audit.onTree("partner", { "space:a": [{ path: asked[0]!.path, lines: "e:forged=1" }] }, null, false);
  assert.equal(asker.audit.refusals()["fingerprint-mismatch"], 1);
});

test("the fetch: at most 4,096 ids a body, re-queued after a jittered backoff to the next member, then parked", () => {
  const h = new Harness();
  h.members.add("p1").add("p2");
  const ids = Array.from({ length: 5000 }, (_, i) => `id${i}`);
  h.audit.want("p1", "space:a", ids);
  const bodies = h.sent.filter((s) => s.to === "p1");
  assert.deepEqual(bodies.map((b) => b.fields.ids!["space:a"]!.length), [4096, 904]);
  assert.ok(bodies.every((b) => b.fields.budget === audit.BUDGET_DEFAULT));
  // p1 answers both bodies with none of their ids and no remainder: it does not hold them. An answer that carried
  // nothing is booked against the eldest body, as Java books it, so each answer settles one body.
  for (let i = 0; i < 2; i++) {
    const body = h.audit.settle("p1", "space:a", new Set());
    assert.ok(body !== null);
    h.audit.fetched("p1", body!, new Set(), 0);
  }
  assert.equal(h.audit.signals().fetchRequeued, 5000);
  h.sent.length = 0;
  h.audit.retry(["p1", "p2"]);
  assert.equal(h.sent.length, 0, "the backoff has not passed");
  h.now += 1_500; // the first backoff is half to one and a half times one second
  h.audit.retry(["p1", "p2"]);
  assert.ok((h.sent.length as number) === 2 && h.sent.every((s) => s.to === "p2"), "asked of the next member that has not left them out");
  for (let i = 0; i < 2; i++) {
    h.audit.fetched("p2", h.audit.settle("p2", "space:a", new Set())!, new Set(), 0);
  }
  h.now += 5_000;
  h.sent.length = 0;
  h.audit.retry(["p1", "p2"]);
  assert.equal(h.audit.signals().fetchParked, 5000, "every member left them out: parked for an audit to name again");
  assert.equal(h.sent.length, 0);
  // An audit names one again: it goes to that partner at once.
  h.audit.want("p1", "space:a", ["id4999"]);
  assert.ok(h.sent.some((s) => s.to === "p1" && s.fields.ids!["space:a"]!.includes("id4999")));
});

test("an answer cut by the budget continues at once with the same partner; a lost answer is asked elsewhere", () => {
  const h = new Harness();
  h.members.add("p1").add("p2");
  h.audit.want("p1", "space:a", ["a", "b", "c", "d"]);
  const batch = h.audit.settle("p1", "space:a", new Set(["a"]))!;
  h.sent.length = 0;
  h.audit.fetched("p1", batch, new Set(["a"]), 3);
  assert.equal(h.audit.signals().fetchContinued, 3);
  assert.deepEqual(h.sent.map((s) => [s.to, s.fields.ids!["space:a"]]), [["p1", ["b", "c", "d"]]]);
  // That answer never comes: past the wait its ids go to another member, and a late copy is still taken.
  h.now += audit.FETCH_WAIT_FLOOR_MILLIS;
  h.sent.length = 0;
  h.audit.retry(["p1", "p2"]);
  assert.equal(h.audit.signals().fetchTimedOut, 1);
  h.now += 2_000;
  h.audit.retry(["p1", "p2"]);
  assert.ok(h.sent.some((s) => s.to === "p2"));
  assert.equal(h.audit.fetchAnswer("p1", new Set(["space:a"])), "space:a", "the late copy is still an answer");
  h.now += audit.LATE_COPY_MILLIS + 1;
  assert.equal(h.audit.fetchAnswer("p1", new Set(["space:a"])), null, "and is forgotten past the late-copy window");
});
