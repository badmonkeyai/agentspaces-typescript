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
 * The capability pipes (TECH-SPEC §8, CapabilityPipes): one PIPE_DATA
 * envelope per frame, addressed to a member, carrying `{capability, payload}`;
 * handlers by capability type on the receiving side.
 */

import type { Peer } from "../peer.js";

/** The multiplexer over a `Peer`: at most one per peer, shared by the capabilities built on it. */
export class Pipes {
  constructor(readonly peer: Peer) {}

  onCapability(capabilityType: string, handler: (from: string, payload: Uint8Array) => void): void {
    this.peer.pipeHandlers.set(capabilityType, handler);
  }

  send(to: string, capabilityType: string, payload: Uint8Array): void {
    this.peer.sendPipe(to, capabilityType, payload);
  }

  /**
   * The members a frame can reach (those that signed a frame on our
   * connection), this peer excluded. A member known only from the peers
   * stream is left out: a dial-only peer cannot address it directly.
   */
  members(): string[] {
    return [...this.peer.reachable].filter((m) => m !== this.peer.identity.peerId);
  }

  /** `n` members at random (PeerSampler.randomMembers). */
  randomMembers(n: number): string[] {
    const ids = this.members();
    for (let i = ids.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [ids[i], ids[j]] = [ids[j]!, ids[i]!];
    }
    return ids.slice(0, n);
  }
}
