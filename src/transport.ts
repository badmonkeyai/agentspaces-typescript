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
 * The frame channel seam (srad/agentspaces-js.md §3.2, JS-P-05): the
 * TypeScript counterpart of the Java `TransportConnection`. A channel carries
 * whole frames, reliably and in order; a dialer opens channels for one
 * scheme. `Peer` holds channels and picks a dialer by each seed's scheme,
 * skipping schemes no dialer serves (SPEC §5.5). The core registers the
 * dialers every runtime can run; `@agentspaces/client/node` adds `tcp`.
 */

import { Seed } from "./seed.js";

export type { Seed } from "./seed.js";

/** One reliable, ordered, whole-frame connection. */
export interface FrameChannel {
  /** The scheme it was opened with: "tcp", "ws", "wss", "http", "https", "webrtc", ... */
  readonly scheme: string;
  /** The remote address as dialed or accepted. */
  readonly remote: string;
  /** The PeerID the channel proved, or null when unattested. */
  attestedPeer(): string | null;
  /** Sends one frame; never throws for a closed channel (the frame is dropped, as on a lost socket). */
  send(frame: Uint8Array): void;
  /** Registers the one receiver; frames that arrived before it are delivered to it in order. */
  onFrame(receiver: (frame: Uint8Array) => void): void;
  /** Registers a listener for the channel's end; fires once, at once if it has already ended. */
  onClose(listener: (reason: string) => void): void;
  /** Ends the channel; idempotent. */
  close(): void;
}

/** Opens channels for one scheme. */
export interface Dialer {
  readonly scheme: string;
  /**
   * Expands one seed into the seeds to try in order, for instance one per
   * address a hostname resolves to (DB-X-03). Optional; the default is the
   * seed itself.
   */
  expand?(seed: Seed, resolve: boolean): Promise<Seed[]>;
  /** Opens a channel, or rejects with the dial's error. */
  dial(seed: Seed): Promise<FrameChannel>;
}

/** Accepts channels for one scheme; only service hosts register one (JS-H-11). */
/** What `listen` resolves with: the closer, and the address bound (so `:0` picks a port a host can advertise). */
export type ListenerHandle = (() => void) & { address?: string };

export interface Listener {
  readonly scheme: string;
  listen(bind: string, onAccept: (channel: FrameChannel) => void): Promise<ListenerHandle>;
}

const defaults = new Map<string, Dialer>();

/** The package that dials each scheme the design names, for the refusal of JS-Q-AVL-03. */
export const DIALER_PACKAGES: { [scheme: string]: string } = {
  tcp: "@agentspaces/client/node or @agentspaces/node",
  ws: "@agentspaces/client",
  wss: "@agentspaces/client",
  http: "@agentspaces/client",
  https: "@agentspaces/client",
  webrtc: "@agentspaces/webrtc",
};

/** Registers a dialer every `Peer` built afterwards starts with; replaces one of the same scheme. */
export function registerDefaultDialer(dialer: Dialer): void {
  defaults.set(dialer.scheme.toLowerCase(), dialer);
}

/** The dialers a new `Peer` starts with. */
export function defaultDialers(): Dialer[] {
  return [...defaults.values()];
}

/**
 * A FrameChannel's bookkeeping, for implementations: the one receiver with
 * the frames that came before it, and the close listeners with the reason.
 */
export class ChannelEvents {
  private receiver: ((frame: Uint8Array) => void) | null = null;
  private early: Uint8Array[] = [];
  private readonly closeListeners: ((reason: string) => void)[] = [];
  private closedReason: string | null = null;

  get closed(): boolean {
    return this.closedReason !== null;
  }

  onFrame(receiver: (frame: Uint8Array) => void): void {
    this.receiver = receiver;
    const early = this.early;
    this.early = [];
    for (const frame of early) {
      receiver(frame);
    }
  }

  deliver(frame: Uint8Array): void {
    if (this.closedReason !== null) {
      return;
    }
    if (this.receiver === null) {
      this.early.push(frame);
    } else {
      this.receiver(frame);
    }
  }

  onClose(listener: (reason: string) => void): void {
    if (this.closedReason !== null) {
      listener(this.closedReason);
    } else {
      this.closeListeners.push(listener);
    }
  }

  /** Marks the channel ended and fires each listener once; later calls do nothing. */
  close(reason: string): void {
    if (this.closedReason !== null) {
      return;
    }
    this.closedReason = reason;
    this.early = [];
    for (const listener of this.closeListeners.splice(0)) {
      try {
        listener(reason);
      } catch {
        // a listener's failure never stops the others
      }
    }
  }
}
