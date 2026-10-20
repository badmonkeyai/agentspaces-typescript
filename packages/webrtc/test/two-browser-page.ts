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
 * The page each of the two browsers runs for JS-W-12: it joins the Java RELAY seed over `wss`/`ws`,
 * installs the webrtc binding, and — the dialer — opens a direct `webrtc` connection to the other
 * browser once it appears in the membership, then both exchange a frame. The result lands on
 * `window.webrtcResult` for the Playwright driver to read. Bundled by esbuild so the browser needs
 * no import map.
 */

import { Peer, Identity, groupIdFromFounding } from "@agentspaces/client";
import type { FrameChannel } from "@agentspaces/client";
import { WebRtcBinding } from "@agentspaces/webrtc";

declare global {
  interface Window {
    webrtcResult?: { ok: boolean; role: string; peerId: string; got?: string; reason?: string; [extra: string]: unknown };
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function run(): Promise<Window["webrtcResult"]> {
  const params = new URLSearchParams(location.search);
  const role = params.get("role") ?? "acceptor";          // "dialer" or "acceptor"
  const scheme = params.get("scheme") ?? "ws";
  const host = params.get("host") ?? "127.0.0.1";
  const port = Number(params.get("port"));
  const founding = params.get("founding") ?? "";
  const maxSeconds = Number(params.get("maxSeconds") ?? 60);

  const peer = new Peer(Identity.generate(), groupIdFromFounding(founding));
  let inbound: FrameChannel | null = null;
  const binding = await WebRtcBinding.install(peer, {}, (channel) => {
    inbound = channel;
  });
  await peer.connectAny([{ host, port, scheme }]);
  const deadline = Date.now() + maxSeconds * 1000;

  if (role === "acceptor") {
    // Wait for the dialer's channel, then echo one frame back.
    while (inbound === null && Date.now() < deadline) {
      await sleep(100);
    }
    if (inbound === null) {
      return { ok: false, role, peerId: peer.identity.peerId, reason: "no inbound channel",
        counters: JSON.parse(JSON.stringify(binding.counters)), reachable: [...peer.reachable], relays: peer.relayMembers(),
        members: [...peer.members.keys()] };
    }
    const channel = inbound as FrameChannel;
    const got = await new Promise<string>((resolve) => {
      channel.onFrame((f) => resolve(new TextDecoder().decode(f)));
    });
    channel.send(new TextEncoder().encode("pong from " + peer.identity.peerId.slice(0, 8)));
    await sleep(1000);
    return { ok: got.startsWith("ping"), role, peerId: peer.identity.peerId, got };
  }

  // Dialer: wait until the other browser's advertisement (the one with a `webrtc` endpoint, JS-W-08)
  // arrives through the seed, then open webrtc to it and exchange; the seed itself is never the target.
  let target: string | null = null;
  while (target === null && Date.now() < deadline) {
    for (const [id, ad] of peer.members) {
      const endpoints = (ad["endpoints"] as { transport?: unknown }[] | undefined) ?? [];
      if (id !== peer.identity.peerId && endpoints.some((e) => e.transport === "webrtc")) {
        target = id;
        break;
      }
    }
    if (target === null) {
      await sleep(100);
    }
  }
  if (target === null) {
    return { ok: false, role, peerId: peer.identity.peerId, reason: "the other browser never appeared" };
  }
  try {
    const channel = await binding.connect(target);
    const got = await new Promise<string>((resolve, reject) => {
      channel.onFrame((f) => resolve(new TextDecoder().decode(f)));
      channel.send(new TextEncoder().encode("ping from " + peer.identity.peerId.slice(0, 8)));
      setTimeout(() => reject(new Error("no echo")), 15000);
    });
    return { ok: got.startsWith("pong"), role, peerId: peer.identity.peerId, got };
  } catch (e) {
    console.log(JSON.stringify({ diag: "dialer", counters: binding.counters, reachable: [...peer.reachable], relays: peer.relayMembers(),
      members: [...peer.members.keys()] }));
    return { ok: false, role, peerId: peer.identity.peerId, reason: e instanceof Error ? e.message : String(e) };
  }
}

run().then((result) => {
  window.webrtcResult = result;
}, (e) => {
  window.webrtcResult = { ok: false, role: "?", peerId: "?", reason: String(e) };
});
