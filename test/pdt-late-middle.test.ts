// A loaded version that a loaded head supersedes through a version still loading is no head (Java's Refs.heads; its
// spoiler scenario SC-I4). With the middle of a chain late, headsAmong read base links only among the loaded versions,
// so the version below the late one was read as a head and merged in: a key a later version removed came back for that
// read, and swapMulti's merge would write it back for every reader.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as pdt from "../src/pdt/index.js";

const head = (label: string, seq: number, ...base: string[]): pdt.Head =>
  ({ root: `r-${label}`, base: base.map((b) => `r-${b}`), seq, size: 0, kind: "map", mode: "multi", issuer: "zA/a",
    issued: `${1000 + seq}:0:zA`, entryId: `e-${label}`, expiresAtMillis: 0 });

// A <- X <- H, and F beside them; X is still loading here, the rest loaded
const a = head("a", 1);
const x = head("x", 2, "a");
const h = head("h", 3, "x");
const f = head("f", 4);
const live = [a, x, h, f];
const roots = (heads: pdt.Head[]) => new Set(heads.map((v) => v.root));

/** Runs the real Refs.heads over a stand-in engine whose live and loadable versions the test lays out. */
function headsWith(loaded: (v: pdt.Head) => boolean): pdt.Head[] {
  const proto = (pdt.Refs as unknown as { prototype: Record<string, (...args: unknown[]) => unknown> }).prototype;
  const engine = {
    liveEntries: () => live,
    loadable: (_state: unknown, v: pdt.Head) => loaded(v),
    withoutLateSuperseded: proto["withoutLateSuperseded"],
  };
  return proto["heads"]!.call(engine, { ignoredEntries: new Set<string>() }) as pdt.Head[];
}

test("the rule alone reads the version below a late middle as a head", () => {
  assert.deepEqual(roots(pdt.headsAmong([a, h, f])), roots([a, h, f]));
});

test("a late middle version makes no ancestor a head", () => {
  assert.deepEqual(roots(headsWith((v) => v !== x)), roots([h, f]), "A is superseded by H through X, still loading");
});

test("the fold finds every version a loaded one supersedes through live ones", () => {
  const folded = pdt.supersededBy([a, h, f], live);
  assert.ok(folded.has(`${a.root}\n${a.entryId}`) && folded.has(`${x.root}\n${x.entryId}`));
  assert.ok(!folded.has(`${h.root}\n${h.entryId}`) && !folded.has(`${f.root}\n${f.entryId}`));
});

test("with nothing loading the heads are the rule's own", () => {
  assert.deepEqual(roots(headsWith(() => true)), roots([h, f]));
});
