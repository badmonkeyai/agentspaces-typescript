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
 * Defects of 2026-11-11, found by a TLS exactly-once driver:
 *
 * 1. takeEntry ended its settle window at the first fold of any entry, so in a busy space it judged the
 *    race before a rival claim arrived and kept a claim it had lost (two takers ran one task).
 * 2. joinByGroupId dialed tcp only, sent GROUP_AD_WANT once, and kept the `aspace://` prefix as the group.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import { Space } from "../src/space.js";
import type { FrameChannel } from "../src/transport.js";
import { MemoryNetwork } from "../src/transport/mem.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(
  join(here, "..", "..", "test", "golden.json"), "utf-8"));

const GROUP = "zTsTakeSettle";
const TASK = "com.acme.Task#v1";
const OTHER = "com.acme.Other#v1";
const MINUTE = 60_000;

/** A member whose rumors land in `rumors` and who hears another's by hand. */
class Member extends Peer {
  readonly rumors: Uint8Array[] = [];
  readonly space: Space;
  private frameCounter = 0;

  constructor() {
    super(Identity.generate(), GROUP);
    this.space = new Space(this, "tasks"); // a peer folds rumors only for a space it has opened
  }

  protected override send(kind: string, body: Uint8Array): void {
    if (kind === "RUMOR") {
      this.rumors.push(body);
    }
  }

  deliver(sender: Peer, body: Uint8Array): void {
    const stamp = wire.hlcNow(sender.identity.peerId, Date.now() + this.frameCounter++);
    (this as unknown as { onFrame(frame: Uint8Array): void }).onFrame(wire.encodeFrame(
      wire.envelope(GROUP, "RUMOR", sender.identity.peerId, stamp, body, this.identity.peerId), sender.identity));
  }

  hear(sender: Member, from = 0): void {
    for (const body of sender.rumors.slice(from)) {
      this.deliver(sender, body);
    }
  }
}

const pause = (millis: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, millis));

test("a fold of another entry does not end the take's settle window, so a rival claim inside it wins", async () => {
  const writer = new Member();
  const taker = new Member();
  const rival = new Member();
  try {
    const id = writer.writeEntry("tasks", TASK, { job: 1 }, "w", 30 * MINUTE);
    taker.hear(writer);
    const before = taker.rumors.length;
    const settleMillis = 400;
    const taking = taker.takeEntry("tasks", TASK, "worker", MINUTE, settleMillis, 2_000);
    while (taker.rumors.length === before) {
      await pause(5); // until the taker has published its claim
    }

    // Unrelated entries fold early in the window, as they do in a busy space.
    for (let i = 0; i < 2; i++) {
      const sent = writer.rumors.length;
      writer.writeEntry("tasks", OTHER, { noise: i }, "w", 30 * MINUTE);
      taker.hear(writer, sent);
      await pause(20);
    }

    // The rival claimed first (an earlier stamp, same epoch and bid), and its claim lands mid-window.
    await pause(100);
    const spaceId = String((taker.states.get(id)!["record"] as Dict)["spaceId"]);
    const worker = rival.identity.agent("worker");
    const stamp = `${Date.now() - 10_000}:0:${worker}`;
    const signed = wire.signedClaim(wire.takeClaim(id, spaceId, 1, stamp, worker, 0.0, Date.now() + MINUTE),
      rival.identity, null);
    taker.deliver(rival, wire.rumorBody("space:tasks", `c:${id}:${stamp}`, 6, wire.claimDelta(id, signed)));

    assert.equal(await taking, null, "the taker lost the race and holds nothing");
    assert.equal((taker.claims.get(id)!["claim"] as Dict)["holder"], worker, "the rival's claim is the winner here");
  } finally {
    [writer, taker, rival].forEach((p) => p.close());
  }
});

test("joinByGroupId reads the join URI, dials the given scheme, and asks again until a seed answers", async () => {
  const group = GOLDEN["founding_group_id"]!;
  const net = new MemoryNetwork();
  const seed = Identity.generate();
  const wants: Dict[] = [];
  const closeListener = await net.listen("hub:9", (channel: FrameChannel) => {
    channel.onFrame((frame) => {
      const env = wire.decodeFrame(frame);
      if (env === null || env["kind"] !== "GROUP_AD_WANT") {
        return;
      }
      wants.push(env);
      if (wants.length < 2) {
        return; // the seed misses the first want, as a seed that is still founding the group does
      }
      channel.send(wire.encodeFrame(wire.envelope(group, "GROUP_AD", seed.peerId,
        wire.hlcNow(seed.peerId, Date.now()), Buffer.from(GOLDEN["signed_group_ad_cbor"]!, "hex"),
        String(env["from"])), seed));
    });
  });
  const joiner = new Peer(Identity.generate(), "unset");
  joiner.registerDialer(net.dialer());
  try {
    const founding = await joiner.joinByGroupId("hub", 9, `aspace://${group}/tasks`, 8_000, "mem");
    assert.equal(joiner.group, group, "the group is the bare id, not the URI");
    assert.ok(wants.length >= 2, "the want went out again after the first slice");
    for (const want of wants) {
      assert.equal(want["group"], group, "every want names the bare id");
    }
    assert.equal(((founding["advertisement"] as Dict)["group"]), group);
  } finally {
    closeListener();
    joiner.close();
  }
});

test("joinByGroupId refuses a URI that carries no GroupId", async () => {
  const joiner = new Peer(Identity.generate(), "unset");
  await assert.rejects(joiner.joinByGroupId("hub", 9, "aspace://", 100, "mem"), /no GroupId/);
});
