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
 * HLC round five, 2026-11-08: the space sweep. A live console page spent 95% of its main thread in
 * Space.sweep, which read and decoded the payload of every lapsed entry on every tick, judged
 * leases by the record's first lease, kept every state forever, folded rumors of spaces it never
 * joined, and listed withdrawn entries. These tests pin each of the five fixes and bound the cost
 * of one sweep over ten thousand delivered entries.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { CborDecimal, CborDouble, dumps, loads } from "../src/cbor.js";
import type { CborValue } from "../src/cbor.js";
import { Identity, instantIso } from "../src/identity.js";
import { Peer, leaseExpiryOf } from "../src/peer.js";
import * as pdt from "../src/pdt/index.js";
import type { Repeating, TimerPort } from "../src/platform.js";
import { ANY_TYPE, EXPIRED, Space, Template } from "../src/space.js";
import type { SpaceEvent } from "../src/space.js";
import { MemoryNetwork, settle } from "../src/transport/mem.js";
import type { OrderedLog } from "../src/capabilities/ordered.js";
import { JOIN_TAG, JOIN_TICKET_TYPE, KEY_TAG, KeyTickets } from "../src/join.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const GROUP = "zTsSweep";
const NOW = 1_800_000_000_000;
const TASK = "com.acme.Task#v1";
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/** Timers the test runs by hand: `tick()` runs every repeating task once. */
class ManualTimers implements TimerPort {
  private readonly tasks = new Set<() => void>();

  setTimeout(): unknown {
    return null;
  }

  clearTimeout(): void {
    // nothing is scheduled to clear
  }

  every(_periodMillis: number, fn: () => void): Repeating {
    this.tasks.add(fn);
    return { lastDriftMillis: 0, lateRuns: 0, stop: () => this.tasks.delete(fn) };
  }

  tick(): void {
    for (const fn of [...this.tasks]) {
      fn();
    }
  }
}

/** A peer on a settable clock and hand-run timers, whose sends go nowhere. */
class ClockPeer extends Peer {
  private frameCounter = 0;
  readonly manual = new ManualTimers();

  constructor(private readonly clock = { millis: NOW }) {
    super(Identity.generate(), GROUP, () => clock.millis);
    this.timers = this.manual;
  }

  set millis(value: number) {
    this.clock.millis = value;
  }

  protected send(): void {
    // captured nowhere: these tests read the replica
  }

  /** Signs a frame as `sender` and hands it to the peer's reader. */
  deliver(sender: Identity, kind: string, body: Uint8Array): void {
    const stamp = `${this.clock.millis}:${this.frameCounter++}:${sender.peerId}`;
    (this as unknown as { onFrame(frame: Uint8Array): void }).onFrame(
      wire.encodeFrame(wire.envelope(GROUP, kind, sender.peerId, stamp, body, this.identity.peerId), sender));
  }
}

/** Counts the payload reads of `peer`, the step before every payload decode. */
function countPayloadReads(peer: Peer): { count: number } {
  const counter = { count: 0 };
  const read = peer.payloadOf.bind(peer);
  peer.payloadOf = (dto: Dict) => {
    counter.count += 1;
    return read(dto);
  };
  return counter;
}

/** A payload the size of a console dashboard row: two dozen named fields. */
function row(i: number): Dict {
  const fields: Dict = { job: i };
  for (let f = 0; f < 24; f++) {
    fields[`field${f}`] = `value ${f} of row ${i}, as a dashboard row carries it`;
  }
  return fields;
}

/**
 * `n` entries in the space `tasks`, held as a replica holds them: one signed write and `n - 1`
 * copies of it under their own ids and payloads (the sweep reads states and never verifies them).
 */
function hold(peer: Peer, n: number, leaseMillis: number,
              payload: (i: number) => Dict = (i) => ({ job: i })): string[] {
  const first = peer.writeEntry("tasks", TASK, payload(0), "w", leaseMillis);
  const dto = peer.states.get(first)!;
  const ids = [first];
  for (let i = 1; i < n; i++) {
    const entryId = `${first}-${i}`;
    peer.states.set(entryId, { ...dto, record: { ...(dto["record"] as Dict), entryId, payload: dumps(payload(i)) } });
    ids.push(entryId);
  }
  return ids;
}

test("a sweep reads no payload of an entry whose EXPIRED every watcher has judged (10000 entries)", () => {
  const peer = new ClockPeer();
  const space = new Space(peer, "tasks");
  const expired: string[] = [];
  space.watch(new Template(ANY_TYPE), (e: SpaceEvent<unknown>) => {
    if (e.kind === EXPIRED) {
      expired.push(e.entry.entryId);
    }
  });
  space.watch(new Template(TASK, { job: -1 }), () => assert.fail("no entry matches job -1"));
  hold(peer, 10_000, 1000);
  const reads = countPayloadReads(peer);
  peer.millis = NOW + 1001;
  space.sweep();
  assert.equal(expired.length, 10_000, "each lapsed entry reports EXPIRED once");
  assert.equal(reads.count, 10_000, "one payload read per entry serves both watchers");
  reads.count = 0;
  space.sweep();
  space.sweep();
  assert.equal(reads.count, 0, "a judged EXPIRED is never decoded again, matched or not");
  assert.equal(expired.length, 10_000);
});

test("a renewed entry is live past its first lease: no EXPIRED, and entries() lists it at the renewed expiry", () => {
  const peer = new ClockPeer();
  const space = new Space(peer, "tasks");
  const kinds: string[] = [];
  space.watch(new Template(TASK), (e: SpaceEvent<unknown>) => kinds.push(e.kind));
  const id = peer.writeEntry("tasks", TASK, { job: 1 }, "w", 1000);
  peer.renewEntry("tasks", id, MINUTE);
  peer.millis = NOW + 5000;
  space.sweep();
  assert.deepEqual(kinds, ["WRITTEN"]);
  const listed = space.entries(new Template(TASK));
  assert.deepEqual(listed.map((e) => e.entryId), [id]);
  assert.equal(listed[0]!.expiresAtMillis, NOW + MINUTE);
  peer.millis = NOW + MINUTE;
  space.sweep();
  assert.deepEqual(kinds, ["WRITTEN", "EXPIRED"], "the renewed lease lapses in its turn");
});

test("states shrink once a lapse passes its grace and a withdrawal passes twice the longest lease; neither returns", () => {
  const peer = new ClockPeer();
  const space = new Space(peer, "tasks");
  space.watch(new Template(TASK), () => {});
  const lapsed = peer.writeEntry("tasks", TASK, { job: 1 }, "w", 1000);
  const withdrawn = peer.writeEntry("tasks", TASK, { job: 2 }, "w", 1000);
  const long = peer.writeEntry("tasks", TASK, { job: 3 }, "w", HOUR);
  const bulky = peer.writeEntry("tasks", TASK, { job: 4, text: "x".repeat(wire.INLINE_PAYLOAD_LIMIT) }, "w", 1000);
  const block = String((peer.states.get(bulky)!["record"] as Dict)["payloadRef"]);
  assert.ok(peer.blocks.has(block), "a payload past the inline limit rides in a block");
  peer.cancelEntry("tasks", withdrawn);
  const withdrawnState = peer.states.get(withdrawn)!;
  const lapsedState = peer.states.get(lapsed)!;
  const holder = Identity.generate();
  const claim = wire.signedClaim(wire.takeClaim(lapsed, String((lapsedState["record"] as Dict)["spaceId"]), 1,
    `${NOW}:0:${holder.agent("worker")}`, holder.agent("worker"), 0.0, NOW + 500), holder, null);
  peer.restoreSnapshot({ group: GROUP, states: [], claims: { [lapsed]: claim } });
  assert.ok(peer.claims.has(lapsed));
  // The longest lease seen is an hour: a lapsed entry keeps min(2 h, 5 min) past its expiry, a withdrawn one 2 h.
  peer.millis = NOW + 1000 + 5 * MINUTE - 1;
  peer.manual.tick();
  assert.deepEqual([...peer.states.keys()].sort(), [lapsed, withdrawn, long, bulky].sort(), "nothing is past its horizon yet");
  peer.millis = NOW + 1000 + 5 * MINUTE;
  peer.manual.tick();
  assert.deepEqual([...peer.states.keys()].sort(), [withdrawn, long].sort(), "the lapsed entries went after their grace");
  assert.equal(peer.claims.has(lapsed), false, "its claim went with it");
  assert.equal(peer.blocks.has(block), false, "a collected entry releases the block no other entry names");
  const marks = (space as unknown as { watchers: Map<number, { judged: Map<string, Set<string>> }> }).watchers;
  for (const watcher of marks.values()) {
    assert.equal(watcher.judged.has(lapsed), false, "a watcher forgets what it judged of a collected entry");
  }
  peer.millis = NOW + 1000 + 2 * HOUR - 1;
  peer.manual.tick();
  assert.deepEqual([...peer.states.keys()], [withdrawn], "the withdrawal keeps its tombstone for two longest leases");
  peer.millis = NOW + 1000 + 2 * HOUR;
  peer.manual.tick();
  assert.equal(peer.states.size, 0);
  // SPEC §7.3: a state re-offered past the collection horizon is refused, so a tombstone never returns.
  peer.restoreSnapshot({ group: GROUP, states: [withdrawnState, lapsedState], claims: {} });
  assert.equal(peer.states.size, 0, "a collected entry is not resurrected");
});

test("a rumor for a space this peer never joined is relayed undecoded and never folded", async () => {
  const peer = new ClockPeer();
  const writer = Identity.generate();
  const elsewhere = wire.entryDelta("elsewhere", GROUP, TASK, dumps({ job: 1 }), writer, "w", MINUTE, null, NOW);
  peer.deliver(writer, "RUMOR", elsewhere.body);
  assert.equal(peer.states.has(elsewhere.entryId), false, "an unjoined space folds nothing");
  peer.deliver(writer, "RUMOR", wire.rumorBody("space:elsewhere", "w:1", 6, Uint8Array.of(0xff)));
  assert.equal(peer.deltasUndecodable, 0, "an unjoined space's delta is never decoded");
  const pulled = wire.entryDelta("elsewhere", GROUP, TASK, dumps({ job: 2 }), writer, "w", MINUTE, null, NOW);
  const state = (loads((loads(pulled.body) as Dict)["payload"] as Uint8Array) as Dict)["state"] as Dict;
  peer.deliver(writer, "PULL_RESP", dumps({ deltas: { "space:elsewhere": dumps({ states: [state], claims: {} }) } }));
  assert.equal(peer.states.has(pulled.entryId), false, "an unasked answer for an unjoined space folds nothing");
  peer.pullSpace("tasks");
  const tasks = wire.entryDelta("tasks", GROUP, TASK, dumps({ job: 3 }), writer, "w", MINUTE, null, NOW);
  peer.deliver(writer, "RUMOR", tasks.body);
  assert.ok(peer.states.has(tasks.entryId), "a pulled space folds");
  new Space(peer, "board");
  const board = wire.entryDelta("board", GROUP, TASK, dumps({ job: 4 }), writer, "w", MINUTE, null, NOW);
  peer.deliver(writer, "RUMOR", board.body);
  assert.ok(peer.states.has(board.entryId), "a space opened as a Space folds");
  const written = peer.writeEntry("notes", TASK, { job: 5 }, "w", MINUTE);
  const notes = wire.entryDelta("notes", GROUP, TASK, dumps({ job: 6 }), writer, "w", MINUTE, null, NOW);
  peer.deliver(writer, "RUMOR", notes.body);
  assert.ok(peer.states.has(written) && peer.states.has(notes.entryId), "a space written to folds");

  // A hub that never joined `elsewhere` still carries it from one member to another.
  const net = new MemoryNetwork();
  const hub = new Peer(Identity.generate(), GROUP);
  hub.endpoints.push({ transport: "mem", address: "hub:9", priority: 0 });
  const closeListener = await net.listen("hub:9", (channel) => hub.acceptChannel(channel));
  const [a, b] = [new Peer(Identity.generate(), GROUP), new Peer(Identity.generate(), GROUP)];
  try {
    for (const member of [a, b]) {
      member.registerDialer(net.dialer());
      await member.connectAny([{ host: "hub", port: 9, scheme: "mem" }]);
    }
    b.pullSpace("elsewhere");
    await settle();
    const id = a.writeEntry("elsewhere", TASK, { job: 7 }, "a");
    await settle();
    assert.equal(hub.states.has(id), false, "the hub relays without folding");
    assert.ok(b.states.has(id), "the member that joined folds what the hub relayed");
  } finally {
    closeListener();
    [hub, a, b].forEach((p) => p.close());
  }
});

/** A peer on a settable clock whose rumors land in `rumors`, so a test hands them to another peer. */
class RumorPeer extends Peer {
  readonly rumors: Uint8Array[] = [];

  constructor(private readonly clock: { millis: number }) {
    super(Identity.generate(), GROUP, () => clock.millis);
    this.timers = new ManualTimers();
  }

  protected send(kind: string, body: Uint8Array): void {
    if (kind === "RUMOR") {
      this.rumors.push(body);
    }
  }
}

/** A ClockPeer that records the spaces it pulls. */
class PullingPeer extends ClockPeer {
  readonly pulls: string[] = [];

  override pullSpace(space: string): void {
    this.pulls.push(space);
    super.pullSpace(space);
  }
}

test("a PDT facade binds its ref space when built and pulls each space a ref first names, so no rumor is scanned", async () => {
  // HLC round six, 2026-11-08 (R11): a Java facade holds its refSpace from the start. The TypeScript
  // facade opens its ref space (`refs` unless `space` names another) when it is built and pulls it,
  // and opens and pulls the space of a ref when ref() first names it. Anti-entropy then carries the
  // heads that arrived before, and the peer never scans the bytes of a rumor of a space it has not joined.
  const clock = { millis: NOW };
  const writer = new RumorPeer(clock);
  const written = new pdt.Pdt(writer);
  const reader = new PullingPeer(clock);
  const facade = new pdt.Pdt(reader);
  const bound = new PullingPeer(clock);
  const boards = new pdt.Pdt(bound, { space: "boards" });
  try {
    assert.deepEqual(reader.pulls, ["refs"], "the default ref space is pulled when the facade is built");
    assert.deepEqual(bound.pulls, ["boards"], "a named ref space is pulled when the facade is built");
    // a head of the bound space folds before any ref names it
    const facts = await written.ref<pdt.PMap<string, pdt.CborValue>>("refs", "facts", "map").swap((m) => m.assoc("sky", "blue"));
    const factsRumor = writer.rumors.at(-1)!;
    const factsId = String((loads(factsRumor) as Dict)["itemId"]).split(":")[1]!;
    reader.deliver(writer.identity, "RUMOR", factsRumor);
    assert.ok(reader.states.has(factsId), "the bound ref space folds its heads from the start");
    const theirs = facade.ref<pdt.PMap<string, pdt.CborValue>>("refs", "facts", "map");
    assert.equal((await theirs.deref()).root(), facts.root());
    assert.deepEqual(reader.pulls, ["refs"], "a ref in the bound space pulls nothing more");
    // a head of a space no ref named yet stays relayed and undecoded
    await written.ref<pdt.PMap<string, pdt.CborValue>>("notes", "todo", "map").swap((m) => m.assoc("milk", 1));
    const todoRumor = writer.rumors.at(-1)!;
    const todoId = String((loads(todoRumor) as Dict)["itemId"]).split(":")[1]!;
    const reads = countPayloadReads(reader);
    reader.deliver(writer.identity, "RUMOR", todoRumor);
    assert.equal(reader.states.has(todoId), false, "a head of a space not opened folds nothing");
    assert.equal(reads.count, 0);
    // the first ref of that space opens and pulls it once, and the pull's answer carries the head
    const todo = facade.ref<pdt.PMap<string, pdt.CborValue>>("notes", "todo", "map");
    facade.ref<pdt.PMap<string, pdt.CborValue>>("notes", "done", "map");
    assert.deepEqual(reader.pulls, ["refs", "notes"]);
    const state = ((loads((loads(todoRumor) as Dict)["payload"] as Uint8Array) as Dict)["state"]) as Dict;
    reader.deliver(writer.identity, "PULL_RESP", dumps({ deltas: { "space:notes": dumps({ states: [state], claims: {} }) } }));
    assert.ok(reader.states.has(todoId), "the pulled space folds the head");
    assert.equal((await todo.deref()).get("milk"), 1);
  } finally {
    written.close();
    facade.close();
    boards.close();
    [writer, reader, bound].forEach((p) => p.close());
  }
});

test("entries(), find(), and take() leave out a withdrawn entry", async () => {
  const peer = new ClockPeer();
  const space = new Space(peer, "tasks");
  const id = peer.writeEntry("tasks", TASK, { job: 1 }, "w", MINUTE);
  assert.equal(space.entries(new Template(TASK)).length, 1);
  peer.cancelEntry("tasks", id);
  assert.deepEqual(space.entries(new Template(TASK)), []);
  assert.deepEqual(peer.find(TASK), []);
  const real = new Peer(Identity.generate(), GROUP);
  const realSpace = new Space(real, "tasks");
  const cancelled = real.writeEntry("tasks", TASK, { job: 2 }, "w", MINUTE);
  real.cancelEntry("tasks", cancelled);
  assert.equal(await realSpace.take(new Template(TASK), "1m", "700ms"), null, "a withdrawn entry is never taken");
  real.close();
});

test("one sweep over 10000 delivered entries stays within a bound", () => {
  const peer = new ClockPeer();
  const space = new Space(peer, "tasks");
  space.watch(new Template(ANY_TYPE), () => {});
  hold(peer, 10_000, 1000, row);
  peer.millis = NOW + 1001;
  space.sweep(); // delivers every EXPIRED once
  const times: number[] = [];
  for (let run = 0; run < 7; run++) {
    const start = performance.now();
    space.sweep();
    times.push(performance.now() - start);
  }
  times.sort((x, y) => x - y);
  const median = times[3]!;
  assert.ok(median < 15, `the median sweep over 10000 delivered entries took ${median.toFixed(2)} ms`);
});

test("the longest lease counts a take's hold, so a withdrawal outlives two holds (HLC round five, 2026-11-08)", () => {
  // Java's ReplicatedSpace observes the lease of every claim it merges and of its own takes, so a
  // space of short writes and long holds keeps its tombstones for two holds.
  const peer = new ClockPeer();
  new Space(peer, "tasks");
  const id = peer.writeEntry("tasks", TASK, { job: 1 }, "w", 1000);
  const spaceId = String((peer.states.get(id)!["record"] as Dict)["spaceId"]);
  const holder = Identity.generate();
  const claim = wire.signedClaim(wire.takeClaim(id, spaceId, 1, `${NOW}:0:${holder.agent("worker")}`,
    holder.agent("worker"), 0.0, NOW + 10 * MINUTE), holder, null);
  peer.restoreSnapshot({ group: GROUP, states: [], claims: { [id]: claim } });
  assert.ok(peer.claims.has(id));
  peer.cancelEntry("tasks", id);
  peer.millis = NOW + 1000 + 20 * MINUTE - 1;
  peer.manual.tick();
  assert.ok(peer.states.has(id), "the tombstone stays two ten-minute holds past the expiry");
  peer.millis = NOW + 1000 + 20 * MINUTE;
  peer.manual.tick();
  assert.equal(peer.states.has(id), false);

  // This peer's own take counts as well.
  const own = new ClockPeer();
  new Space(own, "tasks");
  const mine = own.writeEntry("tasks", TASK, { job: 2 }, "w", 1000);
  const ownSpaceId = String((own.states.get(mine)!["record"] as Dict)["spaceId"]);
  const worker = own.identity.agent("worker");
  own.claims.set(mine, wire.signedClaim(wire.takeClaim(mine, ownSpaceId, 1, `${NOW}:0:${worker}`, worker, 0.0,
    NOW + 500), own.identity, null));
  own.renewClaim("tasks", mine, 10 * MINUTE, own.identity.subordinate("worker", instantIso(NOW)));
  own.cancelEntry("tasks", mine);
  own.millis = NOW + 1000 + 20 * MINUTE - 1;
  own.manual.tick();
  assert.ok(own.states.has(mine), "a hold this peer renews counts toward the horizon");
});

/** A rumor carrying `writer`'s entry in `tasks` with its state's lease and record lease patched, the state re-signed. */
function leaseRumor(writer: Identity, leaseValue: (lease: Dict) => CborValue,
                    recordLease: (lease: Dict) => CborValue | undefined = (l) => l):
    { entryId: string; body: Uint8Array } {
  const { entryId, body } = wire.entryDelta("tasks", GROUP, TASK, dumps({ job: 1 }), writer, "w", MINUTE, null, NOW);
  const state = (loads((loads(body) as Dict)["payload"] as Uint8Array) as Dict)["state"] as Dict;
  const record = { ...(state["record"] as Dict) };
  const patchedRecordLease = recordLease(record["lease"] as Dict);
  if (patchedRecordLease === undefined) {
    delete record["lease"];
  } else {
    record["lease"] = patchedRecordLease;
  }
  const signed = wire.signState({ ...state, record, leaseValue: leaseValue(state["leaseValue"] as Dict) }, writer, null, NOW);
  return { entryId, body: wire.rumorBody("space:tasks", `w:${entryId}`, 6, dumps({ state: signed, claimEntry: null, claim: null })) };
}

test("a lease that is no exact LeaseInfo never lands and counts as undecodable, coercions included", () => {
  // HLC round five, 2026-11-08: a member-signed lease whose expiry was text, a float, NaN, or past
  // a long made an entry that never lapsed and that no collection dropped; Java refuses each. HLC
  // round six, 2026-11-08 (F1): a lease Java once read only by coercing a field (a float or text
  // expiry, a kind as its index, a field LeaseInfo does not hold) is undecodable as well.
  const expiry = (value: CborValue) => (lease: Dict) => ({ ...lease, expiresAtMillis: value });
  const field = (key: string, value: CborValue) => (lease: Dict) => ({ ...lease, [key]: value });
  const same = (lease: Dict) => lease;
  const cases: [string, (lease: Dict) => CborValue, (lease: Dict) => CborValue | undefined,
    "undecodable" | "held"][] = [
    ["non-numeric text expiry", expiry("soon"), same, "undecodable"],
    ["NaN expiry", expiry(new CborDouble(NaN)), same, "undecodable"],
    ["infinite expiry", expiry(new CborDouble(Infinity)), same, "undecodable"],
    ["expiry past a long", expiry(1n << 63n), same, "undecodable"],
    ["float expiry below one", expiry(new CborDouble(0.5)), same, "undecodable"],
    ["empty text expiry", expiry(""), same, "undecodable"],
    ["exponent text expiry", expiry("1e13"), same, "undecodable"],
    ["boolean expiry", expiry(true), same, "undecodable"],
    ["holder with two slashes", field("holder", "a/b/c"), same, "undecodable"],
    ["holder that is no text", field("holder", 5), same, "undecodable"],
    ["unknown kind", field("kind", "READ"), same, "undecodable"],
    ["kind index past TAKE", field("kind", 2), same, "undecodable"],
    ["float kind", field("kind", new CborDouble(0)), same, "undecodable"],
    ["lease that is no map", () => "x", same, "undecodable"],
    ["record without its lease", same, () => undefined, "undecodable"],
    ["record lease with a bad holder", same, field("holder", "nope"), "undecodable"],
    ["float expiry", expiry(new CborDouble(NOW + MINUTE + 0.5)), same, "undecodable"],
    ["integral float expiry", expiry(new CborDouble(NOW + MINUTE)), same, "undecodable"],
    ["decimal text expiry", expiry(String(NOW + MINUTE)), same, "undecodable"],
    ["padded text expiry", expiry(`\t+${NOW + MINUTE}\n`), same, "undecodable"],
    ["kind index", field("kind", 0), same, "undecodable"],
    ["kind index as text", field("kind", "1"), same, "undecodable"],
    ["a field LeaseInfo does not hold", field("extra", 1), same, "undecodable"],
    // HLC round five, 2026-11-08 (E8): Jackson reads a decimal into a long exactly, refusing one
    // past a long before it truncates toward zero, so the double nearest the decimal decides nothing.
    ["decimal expiry that truncates to zero", expiry(new CborDecimal(-20, 99999999999999999999n)), same, "undecodable"],
    ["decimal expiry just past a long", expiry(new CborDecimal(-1, 92233720368547758075n)), same, "undecodable"],
    ["decimal expiry", expiry(new CborDecimal(-1, BigInt(NOW + MINUTE) * 10n + 5n)), same, "undecodable"],
    ["integral decimal expiry", expiry(new CborDecimal(0, NOW + MINUTE)), same, "undecodable"],
    ["the longest expiry a long holds", expiry((1n << 63n) - 1n), same, "held"],
    ["float expiry in the record's lease", same, expiry(new CborDouble(NOW + MINUTE + 0.5)), "undecodable"],
  ];
  for (const [name, leaseValue, recordLease, outcome] of cases) {
    const peer = new ClockPeer();
    new Space(peer, "tasks");
    const { entryId, body } = leaseRumor(Identity.generate(), leaseValue, recordLease);
    peer.deliver(Identity.generate(), "RUMOR", body);
    assert.equal(peer.states.has(entryId), outcome === "held", `${name}: held`);
    assert.equal(peer.deltasUndecodable, outcome === "undecodable" ? 1 : 0, `${name}: undecodable`);
  }
});

test("a withdrawn ticket is no longer the lock an ORDERED reduce drains under", () => {
  // HLC round five, 2026-11-08: the lock rule judged only completion and the lease, so a cancelled
  // ticket held its key until its lease ran out, where Java's live reads skip it at once.
  const peer = new ClockPeer();
  const space = new Space(peer, "tasks");
  let committed: (entryId: string, claim: Dict) => void = () => {};
  const tickets = new KeyTickets("sum", space, MINUTE, MINUTE, {} as OrderedLog, 16, (listener) => {
    committed = listener;
    return () => {};
  });
  tickets.start();
  const tags = { [JOIN_TAG]: "sum", [KEY_TAG]: "k" };
  const first = peer.writeEntry("tasks", JOIN_TICKET_TYPE, { key: "k" }, "w", MINUTE, null, tags);
  const second = peer.writeEntry("tasks", JOIN_TICKET_TYPE, { key: "k" }, "w", MINUTE, null, tags);
  committed(first, { stamp: `${NOW}:0:${peer.identity.agent("w")}`, epoch: 1 });
  committed(second, { stamp: `${NOW}:1:${peer.identity.agent("w")}`, epoch: 1 });
  assert.equal(tickets.earliestLive("k"), first);
  peer.cancelEntry("tasks", first);
  assert.equal(tickets.earliestLive("k"), second, "the withdrawn ticket gives the lock up");
  tickets.close();
});
