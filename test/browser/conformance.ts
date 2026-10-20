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
 * The conformance subset of JS-P-09, written against the portable core alone
 * so it runs unchanged in a browser, a Worker, or Node: the Java golden
 * vectors for identity, frames, records, founding, and the social
 * derivations, a CBOR round trip of every golden structure, and a `Peer`
 * answering a probe over an in-memory frame channel. `test/browser.test.ts`
 * loads it in Chromium, Firefox, and WebKit; `test/portable.test.ts` runs it
 * in Node.
 */

import { equals, fromHex, toHex, utf8 } from "../../src/bytes.js";
import { dumps, loads } from "../../src/cbor.js";
import { Identity, deriveId, groupIdFromFounding, spaceIdLocal, verifySignedGroupAd } from "../../src/identity.js";
import { Peer } from "../../src/peer.js";
import { GroupSecret } from "../../src/social.js";
import { Space, Template, entry } from "../../src/space.js";
import { ChannelEvents, FrameChannel } from "../../src/transport.js";
import * as wire from "../../src/wire.js";

export type Result = { name: string; ok: boolean; detail?: string };

type Golden = { [key: string]: string };

export async function runConformance(golden: Golden, social: Golden): Promise<Result[]> {
  const results: Result[] = [];
  const hex = (name: string): Uint8Array => fromHex(golden[name]);
  const check = async (name: string, fn: () => void | Promise<void>): Promise<void> => {
    try {
      await fn();
      results.push({ name, ok: true });
    } catch (e) {
      results.push({ name, ok: false, detail: e instanceof Error ? e.message : String(e) });
    }
  };
  const same = (actual: Uint8Array, expected: Uint8Array, what: string): void => {
    if (!equals(actual, expected)) {
      throw new Error(`${what}: ${toHex(actual).slice(0, 48)}... is not ${toHex(expected).slice(0, 48)}...`);
    }
  };
  const is = (actual: unknown, expected: unknown, what: string): void => {
    if (actual !== expected) {
      throw new Error(`${what}: ${String(actual)} is not ${String(expected)}`);
    }
  };
  const identity = (): Identity => Identity.fromPkcs8(hex("private_key_pkcs8"));

  await check("identity and derivations match Java", () => {
    const id = identity();
    same(id.publicRaw, hex("public_key_raw"), "public key");
    is(id.peerId, golden["peer_id"], "peer id");
    is(deriveId(hex("public_key_raw")), golden["peer_id"], "derived id");
    is(groupIdFromFounding("research-fleet-demo-v1"), golden["group_id"], "group id");
    is(spaceIdLocal(golden["group_id"] + "/tasks"), golden["space_id"], "space id");
  });

  await check("ping envelope bytes, signature, and frame match Java", () => {
    const id = identity();
    same(wire.pingBody(42), hex("ping_body_cbor"), "ping body");
    const env = wire.envelope(golden["group_id"], "PING", golden["peer_id"],
      golden["hlc_encoded"], hex("ping_body_cbor"), golden["peer_id"]);
    same(dumps(env), hex("ping_envelope_cbor"), "envelope");
    same(id.sign(dumps(env)), hex("ping_envelope_signature"), "signature");
    same(wire.encodeFrame(env, id), hex("ping_frame_cbor"), "frame");
  });

  await check("Java frames verify and a tampered one is refused", () => {
    const env = wire.decodeFrame(hex("ping_frame_cbor"));
    is(env?.["kind"], "PING", "kind");
    const tampered = hex("ping_frame_cbor");
    tampered[tampered.length - 1] ^= 0x01;
    is(wire.decodeFrame(tampered), null, "tampered frame");
  });

  await check("membership intro matches Java", () => {
    const id = identity();
    const ad = wire.peerAdvertisement(golden["group_id"], id, "2026-01-01T00:00:00Z");
    ad["endpoints"] = [{ transport: "tcp", address: "127.0.0.1:7460", priority: 0 }];
    same(dumps(ad), hex("peer_ad_cbor"), "peer ad");
    same(wire.signedPeerAd(ad, id), hex("signed_peer_ad_cbor"), "signed peer ad");
  });

  await check("space write view and record signature match Java", () => {
    const id = identity();
    const payload = dumps({ topic: "golden vectors", priority: 3 });
    same(payload, hex("task_payload_cbor"), "payload");
    const view = wire.signView("11111111-2222-3333-4444-555555555555",
      golden["space_id"], "GoldenVectors$ResearchTask#v1", payload,
      id.agent("python"), golden["hlc_encoded"]);
    same(dumps(view), hex("sign_view_cbor"), "sign view");
    same(id.sign(dumps(view)), hex("record_signature"), "record signature");
  });

  await check("the founding document derives the self-certifying GroupID", () => {
    is(verifySignedGroupAd(hex("signed_group_ad_cbor")), golden["founding_group_id"], "founding");
    is(verifySignedGroupAd(hex("adv_group_ad_forged_signature_cbor")), null, "forged founding");
  });

  await check("every golden CBOR structure re-encodes byte for byte", () => {
    let count = 0;
    for (const [name, value] of Object.entries(golden)) {
      if (!name.endsWith("_cbor") || name.startsWith("adv_") || typeof value !== "string") {
        continue;
      }
      const bytes = fromHex(value);
      same(dumps(loads(bytes)), bytes, name);
      count++;
    }
    if (count < 20) {
      throw new Error(`only ${count} structures checked`);
    }
  });

  await check("the social derivations match Java and Python", () => {
    const s = GroupSecret.of(fromHex(social["secret_hex"]));
    same(s.invitePublicKey(), fromHex(social["invite_public_key_hex"]), "invite key");
    same(s.contentKey(), fromHex(social["content_key_hex"]), "content key");
    is(s.code(), social["code"], "lookup code");
  });

  await check("a fresh identity signs and verifies", () => {
    const id = Identity.generate();
    const message = utf8("portable");
    if (!Identity.verify(id.publicRaw, message, id.sign(message))) {
      throw new Error("own signature refused");
    }
    if (Identity.verify(id.publicRaw, utf8("other"), id.sign(message))) {
      throw new Error("signature over another message accepted");
    }
  });

  await check("a peer answers a probe over an in-memory frame channel", async () => {
    const sent: Uint8Array[] = [];
    const events = new ChannelEvents();
    const channel: FrameChannel = {
      scheme: "mem", remote: "mem:1", attestedPeer: () => null,
      send: (frame) => { sent.push(frame); },
      onFrame: (r) => events.onFrame(r),
      onClose: (l) => events.onClose(l),
      close: () => events.close("closed"),
    };
    const peer = new Peer(Identity.generate(), "browser-group");
    peer.registerDialer({ scheme: "mem", dial: async () => channel });
    await peer.connectAny([{ host: "x", port: 1, scheme: "mem" }]);
    const other = Identity.generate();
    const before = sent.length;
    events.deliver(wire.encodeFrame(wire.envelope("browser-group", "PING", other.peerId,
      wire.hlcNow(other.peerId), wire.pingBody(9), peer.identity.peerId), other));
    is(wire.decodeFrame(sent[before])?.["kind"], "ACK", "reply");
    peer.close();
  });

  await check("a space writes, filters, watches, and sweeps on the platform timers", async () => {
    class Task {
      constructor(public topic = "", public priority = 0) {}
    }
    entry("com.acme.Task#v1")(Task);
    const peer = new Peer(Identity.generate(), "browser-group");
    const space = new Space(peer, "tasks");
    const seen: string[] = [];
    const watch = space.watch(new Template(Task, { priority: 2 }), (e) => seen.push(`${e.kind}:${e.entry.value.topic}`));
    space.write(new Task("one", 1), "10m", { region: "eu" });
    space.write(new Task("two", 2), "10m", { region: "us" });
    is(space.readAll(new Template(Task, {}, { region: "eu" })).map((x) => x.topic).join(), "one", "tag filter");
    await new Promise((r) => setTimeout(r, 400)); // the 250 ms sweep runs at least once
    is(seen.join(), "WRITTEN:two", "watch");
    watch.close();
    peer.close();
  });

  return results;
}
