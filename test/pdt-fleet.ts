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
 * An in-memory fleet of PDT facades for the tests (srad/agentspaces-pdt.md groups X and R; PDT 2 phase 7 shares it
 * with the level-2 tests): peers that hand each frame to the others in process, each with a content swarm, a tree
 * exchange, and a Pdt facade; `run` ticks every member and waits for every queued frame.
 */

import { Content, MemoryStore, Pipes } from "../src/capabilities/index.js";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import * as pdt from "../src/pdt/index.js";
import { Space } from "../src/space.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

export type V = pdt.CborValue;
const GROUP = "zTypeScriptPdt";

type Internals = { fold(dto: Dict): void; handle(env: Dict): void; send(kind: string, body: Uint8Array, to?: string | null): void };

export class Network {
  readonly peers = new Map<string, NetPeer>();
  /** While true, frames queue instead of arriving; `flush` delivers them (two writers that have not seen each other). */
  holding = false;
  private readonly held: (() => void)[] = [];

  deliver(fn: () => void): void {
    if (this.holding) {
      this.held.push(fn);
    } else {
      fn();
    }
  }

  flush(): void {
    this.holding = false;
    for (const fn of this.held.splice(0)) {
      fn();
    }
  }
}

export class NetPeer extends Peer {
  constructor(readonly network: Network) {
    super(Identity.generate(), GROUP);
    network.peers.set(this.identity.peerId, this);
    const self = this as unknown as Internals;
    self.send = (kind: string, body: Uint8Array, to: string | null = null) => {
      const env = wire.envelope(this.group, kind, this.identity.peerId,
        wire.hlcNow(this.identity.peerId, this.now()), body, to);
      network.deliver(() => {
        const targets = to !== null ? [network.peers.get(to)!]
          : [...network.peers.values()].filter((p) => p.identity.peerId !== this.identity.peerId);
        for (const target of targets) {
          if (target !== undefined && target.accepts(env)) {
            (target as unknown as Internals).handle(env);
          }
        }
      });
    };
  }

  override pullSpace(_space: string): void {}
  override pullRevocations(): void {}
}

export type Node = { peer: NetPeer; space: Space; content: Content; pdt: pdt.Pdt };

export function node(network: Network, options: pdt.PdtOptions = {}): Node {
  const peer = new NetPeer(network);
  const space = new Space(peer, "content");
  let seed = 7;
  const random = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
  const content = new Content(new Pipes(peer), space, new MemoryStore(), { pieceSize: 64 * 1024, random });
  const p = new pdt.Pdt(peer, { content, ...options });
  return { peer, space, content, pdt: p };
}

export function fleet(n: number, options: pdt.PdtOptions = {}): Node[] {
  return fleetOf(Array.from({ length: n }, () => options));
}

/** A fleet of one member per options, every member introduced and its advertisement in every cache. */
export function fleetOf(each: pdt.PdtOptions[]): Node[] {
  const network = new Network();
  const nodes = each.map((options) => node(network, options));
  for (const { peer } of nodes) {
    peer.introduce();
  }
  for (const { pdt: p } of nodes) {
    p.advertise(); // every member now exists, so every advertisement reaches every cache
  }
  return nodes;
}

export async function run(nodes: Node[], rounds = 10): Promise<void> {
  for (let r = 0; r < rounds; r++) {
    for (const { content, pdt: p } of nodes) {
      content.tick();
      p.tick();
    }
    for (const { pdt: p } of nodes) {
      await p.exchange!.settled();
    }
    await new Promise((resolve) => setImmediate(resolve));
  }
}

export function closeAll(nodes: Node[]): void {
  for (const n of nodes) {
    n.pdt.close();
    n.content.stop();
    n.peer.close();
  }
}

