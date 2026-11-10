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
 * An in-memory fleet of peers with content swarms, for the tests: every frame a peer sends reaches the others
 * synchronously, and each writer folds its own space deltas, so a swarm runs without sockets or timers.
 */

import { Content, MemoryStore, Pipes } from "../src/capabilities/index.js";
import * as c from "../src/capabilities/content.js";
import { loads } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import { Space } from "../src/space.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";

type Internals = { fold(dto: Dict): void; handle(env: Dict): void;
  send(kind: string, body: Uint8Array, to?: string | null): void };

export class Network {
  readonly peers = new Map<string, NetPeer>();
}

export class NetPeer extends Peer {
  constructor(readonly network: Network, group: string, now: () => number = Date.now) {
    super(Identity.generate(), group, now);
    network.peers.set(this.identity.peerId, this);
    const self = this as unknown as Internals;
    self.send = (kind: string, body: Uint8Array, to: string | null = null) => {
      const env = wire.envelope(this.group, kind, this.identity.peerId,
        wire.hlcNow(this.identity.peerId, this.now()), body, to);
      const targets = to !== null ? [network.peers.get(to)!]
        : [...network.peers.values()].filter((p) => p.identity.peerId !== this.identity.peerId);
      for (const target of targets) {
        if (target.accepts(env)) {
          (target as unknown as Internals).handle(env);
        }
      }
      if (kind === "RUMOR" && to === null) {
        const rumor = loads(body) as Dict;
        if (String(rumor["streamId"] ?? "").startsWith("space:")) {
          const delta = loads(rumor["payload"] as Uint8Array) as Dict;
          if (delta["state"] !== null && typeof delta["state"] === "object") {
            self.fold(delta["state"] as Dict);
          }
        }
      }
    };
  }

  override pullSpace(_space: string): void {}
  override pullRevocations(): void {}
}

export type Node = { peer: NetPeer; space: Space; content: Content };

export function node(network: Network, group: string, store: c.PieceStore = new MemoryStore(),
                     options: c.ContentOptions = {}, now: () => number = Date.now): Node {
  const peer = new NetPeer(network, group, now);
  const space = new Space(peer, "content");
  let seed = 7;
  const random = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
  const content = new Content(new Pipes(peer), space, store, { pieceSize: 64 * 1024, random, ...options });
  return { peer, space, content };
}

export function fleet(n: number, group: string, options: c.ContentOptions = {}): Node[] {
  const network = new Network();
  const nodes = Array.from({ length: n }, () => node(network, group, new MemoryStore(), options));
  for (const { peer } of nodes) {
    peer.introduce();
  }
  return nodes;
}

export function run(nodes: Node[], rounds = 20): void {
  for (let r = 0; r < rounds; r++) {
    for (const { content } of nodes) {
      content.tick();
    }
  }
}
