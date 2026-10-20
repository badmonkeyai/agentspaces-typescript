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
 * The in-memory transport (`mem`): frame channels joined in pairs inside one
 * process, delivered a microtask later like a socket would, so peers in one
 * runtime (a test, a page and its worker, a fleet simulation) link through the
 * same `Peer` paths as over a network. A {@link MemoryNetwork} holds listeners
 * by address and hands out the dialer that reaches them.
 */

import { Seed } from "../seed.js";
import { ChannelEvents, Dialer, FrameChannel, Listener } from "../transport.js";

export class MemoryChannel implements FrameChannel {
  readonly scheme = "mem";
  readonly events = new ChannelEvents();
  private other: MemoryChannel | null = null;
  /** Frames sent on this end, for assertions. */
  sent = 0;
  /** The PeerID this end proves, when a test wants an attested link; null otherwise. */
  attested: string | null = null;

  constructor(readonly remote: string) {}

  /** Joins two ends; each delivers what the other sends and ends when the other ends. */
  static pair(remoteOfA: string, remoteOfB: string): [MemoryChannel, MemoryChannel] {
    const a = new MemoryChannel(remoteOfA);
    const b = new MemoryChannel(remoteOfB);
    a.other = b;
    b.other = a;
    return [a, b];
  }

  attestedPeer(): string | null {
    return this.attested;
  }

  send(frame: Uint8Array): void {
    const other = this.other;
    if (other === null || this.events.closed) {
      return; // dropped, as on a lost socket
    }
    this.sent += 1;
    const copy = frame.slice();
    queueMicrotask(() => other.events.deliver(copy));
  }

  onFrame(receiver: (frame: Uint8Array) => void): void {
    this.events.onFrame(receiver);
  }

  onClose(listener: (reason: string) => void): void {
    this.events.onClose(listener);
  }

  close(): void {
    if (this.events.closed) {
      return;
    }
    this.events.close("closed");
    const other = this.other;
    this.other = null;
    queueMicrotask(() => other?.events.close("peer closed"));
  }
}

/** Listeners by `host:port`, and the dialer that connects to them. */
export class MemoryNetwork implements Listener {
  readonly scheme = "mem";
  private readonly listeners = new Map<string, (channel: FrameChannel) => void>();
  /** Dials refused because no listener was bound at the address. */
  refused = 0;

  listen(bind: string, onAccept: (channel: FrameChannel) => void): Promise<() => void> {
    this.listeners.set(bind, onAccept);
    return Promise.resolve(() => { this.listeners.delete(bind); });
  }

  dialer(): Dialer {
    return {
      scheme: "mem",
      dial: async (seed: Seed): Promise<FrameChannel> => {
        const address = `${seed.host}:${seed.port}`;
        const accept = this.listeners.get(address);
        if (accept === undefined) {
          this.refused += 1;
          throw new Error(`mem://${address}: connection refused`);
        }
        const [ours, theirs] = MemoryChannel.pair(address, `dial:${address}`);
        accept(theirs);
        return ours;
      },
    };
  }
}

/** Lets every microtask-delivered frame land: a few turns of the event loop. */
export function settle(turns = 4): Promise<void> {
  let p = Promise.resolve();
  for (let i = 0; i < turns; i++) {
    p = p.then(() => new Promise<void>((resolve) => setTimeout(resolve, 0)));
  }
  return p;
}
