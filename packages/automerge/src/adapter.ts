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
 * The automerge-repo `NetworkAdapter` over an AgentSpaces fleet
 * (srad/agentspaces-js.md JS-S-01, JS-S-03): the members a peer's pipes can
 * reach become the Repo's peers, under their AgentSpaces PeerID, and the
 * Repo's messages travel as signed `PIPE_DATA` frames of capability
 * `aspace:cap/automerge`. The adapter adds nothing to a message: the payload
 * is the library's own CBOR encoding of the `Message` (`cbor.encode` from
 * `@automerge/automerge-repo`, the bytes its WebSocket adapter puts on a
 * socket), so AgentSpaces supplies signing, membership, and the link, and
 * the document format is Automerge's alone.
 *
 *     const repo = new Repo({ network: [new AgentSpacesNetworkAdapter(pipes)] });
 *
 * Membership is the pipes' reachable set: a member that answers this
 * adapter's greeting is a `peer-candidate`; one that leaves the set, or
 * says it is leaving, is `peer-disconnected`. The adapter has no timer of
 * the fleet's: it sweeps the set on a period of its own and on every frame
 * it receives, so a late joiner is greeted the moment its first frame lands.
 */

import { NetworkAdapter, cbor } from "@automerge/automerge-repo";
import type { Message, PeerId, PeerMetadata } from "@automerge/automerge-repo";
import { capabilities, wire } from "@agentspaces/client";

/** The capability type of the frames (SPEC §8 pipes; srad/agentspaces-js.md §4.8). */
export const TYPE = "aspace:cap/automerge";

/**
 * Headroom under the fleet's frame cap (`wire.MAX_FRAME_BYTES`, 8 MiB) for
 * the PIPE_DATA envelope: the capability name, the signer, the stamp, the
 * signature, and a session tag, which together stay far under this.
 */
export const ENVELOPE_HEADROOM_BYTES = 64 * 1024;

/** The largest payload the adapter sends by default: the frame cap less the envelope headroom. */
export const DEFAULT_MAX_PAYLOAD_BYTES = wire.MAX_FRAME_BYTES - ENVELOPE_HEADROOM_BYTES;

export type AgentSpacesNetworkAdapterOptions = {
  /** How often the reachable set is swept for arrivals and departures, in milliseconds (250). */
  sweepMillis?: number;
  /**
   * The largest encoded message the adapter sends; above it the message is
   * refused with an error naming the size and this bound, never chunked (a
   * transport drops an oversize frame silently). Defaults to
   * {@link DEFAULT_MAX_PAYLOAD_BYTES}; it cannot exceed the frame cap.
   */
  maxPayloadBytes?: number;
  /** Called instead of throwing when a message is refused for its size. */
  onRefused?: (message: Message, bytes: number, error: Error) => void;
};

/**
 * The greeting the adapter exchanges before a member becomes a peer, in the
 * shape of the library's BroadcastChannel adapter: `arrive` to everyone
 * reachable, `welcome` back to the one that arrived, `leave` on disconnect.
 * They share the `Message` encoding, under types the Repo never sends.
 */
type Greeting = {
  type: "arrive" | "welcome" | "leave";
  senderId: PeerId;
  targetId?: PeerId;
  peerMetadata?: PeerMetadata;
};

const GREETINGS = new Set(["arrive", "welcome", "leave"]);

/** One `Repo`'s network over one peer's pipes; at most one per `Pipes`, since the capability type has one handler. */
export class AgentSpacesNetworkAdapter extends NetworkAdapter {
  readonly sweepMillis: number;
  readonly maxPayloadBytes: number;
  /** Frames that did not decode as a message, for assertions. */
  dropped = 0;
  /** Frames received that carried a Repo message. */
  received = 0;
  private readonly onRefused: AgentSpacesNetworkAdapterOptions["onRefused"];
  /** The members that became `peer-candidate`, with the metadata they announced. */
  private readonly known = new Map<string, PeerMetadata>();
  /** The members this adapter has greeted since they last appeared. */
  private readonly greeted = new Set<string>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private connected = false;
  private readonly readyPromise: Promise<void>;
  private resolveReady: () => void = () => undefined;

  constructor(readonly pipes: capabilities.Pipes, options: AgentSpacesNetworkAdapterOptions = {}) {
    super();
    this.sweepMillis = options.sweepMillis ?? 250;
    this.maxPayloadBytes = Math.min(options.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES, wire.MAX_FRAME_BYTES);
    if (this.sweepMillis <= 0 || this.maxPayloadBytes <= 0) {
      throw new Error("sweepMillis and maxPayloadBytes are positive");
    }
    this.onRefused = options.onRefused;
    this.readyPromise = new Promise<void>((resolve) => { this.resolveReady = resolve; });
  }

  /** The AgentSpaces PeerID this adapter speaks under: the one the Repo should be constructed with. */
  get fleetPeerId(): PeerId {
    return this.pipes.peer.identity.peerId as PeerId;
  }

  /** The members that are peers of the Repo right now. */
  peers(): PeerId[] {
    return [...this.known.keys()] as PeerId[];
  }

  isReady(): boolean {
    return this.connected;
  }

  whenReady(): Promise<void> {
    return this.readyPromise;
  }

  /**
   * Takes the pipes' capability handler, greets every reachable member, and
   * starts the sweep. Ready at once: the fleet connection is the peer's
   * affair, and a member that is not there yet is greeted when it appears.
   */
  connect(peerId: PeerId, peerMetadata?: PeerMetadata): void {
    this.peerId = peerId;
    this.peerMetadata = peerMetadata ?? {};
    this.pipes.onCapability(TYPE, (from, payload) => this.onFrame(from, payload));
    this.connected = true;
    this.timer = setInterval(() => this.sweep(), this.sweepMillis);
    this.sweep();
    this.resolveReady();
  }

  /** Encodes the message as the library does and sends it, addressed, as one signed frame. */
  send(message: Message): void {
    if (!this.connected) {
      return;
    }
    const payload: Uint8Array = cbor.encode(message);
    if (payload.length > this.maxPayloadBytes) {
      const error = new Error(`@agentspaces/automerge: a ${message.type} message`
        + (message.documentId ? ` for document ${message.documentId}` : "")
        + ` of ${payload.length} bytes exceeds maxPayloadBytes ${this.maxPayloadBytes}`
        + ` (the fleet's frame cap is ${wire.MAX_FRAME_BYTES}); refused, not chunked`);
      if (this.onRefused) {
        this.onRefused(message, payload.length, error);
        return;
      }
      throw error;
    }
    this.pipes.send(message.targetId, TYPE, payload);
  }

  /** Says goodbye to every peer, drops them locally, stops the sweep, and closes. */
  disconnect(): void {
    if (!this.connected) {
      return;
    }
    for (const peerId of this.known.keys()) {
      this.sendGreeting({ type: "leave", senderId: this.fleetPeerId, targetId: peerId as PeerId });
    }
    this.connected = false;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    for (const peerId of [...this.known.keys()]) {
      this.forget(peerId);
    }
    this.greeted.clear();
    this.emit("close");
  }

  /**
   * One pass over the reachable set: a peer no longer in it is disconnected;
   * a member not yet greeted gets an `arrive`. Public so a host can sweep
   * right after `peer.expireMembers()`.
   */
  sweep(): void {
    if (!this.connected) {
      return;
    }
    const members = new Set(this.pipes.members());
    for (const peerId of [...this.known.keys()]) {
      if (!members.has(peerId)) {
        this.forget(peerId);
      }
    }
    for (const peerId of [...this.greeted]) {
      if (!members.has(peerId)) {
        this.greeted.delete(peerId);
      }
    }
    for (const member of members) {
      if (!this.greeted.has(member)) {
        this.greeted.add(member);
        this.sendGreeting({ type: "arrive", senderId: this.fleetPeerId, targetId: member as PeerId,
          peerMetadata: this.peerMetadata });
      }
    }
  }

  private sendGreeting(greeting: Greeting): void {
    this.pipes.send(String(greeting.targetId), TYPE, cbor.encode(greeting));
  }

  private candidate(peerId: string, peerMetadata: PeerMetadata): void {
    if (this.known.has(peerId)) {
      return;
    }
    this.known.set(peerId, peerMetadata);
    this.emit("peer-candidate", { peerId: peerId as PeerId, peerMetadata });
  }

  private forget(peerId: string): void {
    if (this.known.delete(peerId)) {
      this.emit("peer-disconnected", { peerId: peerId as PeerId });
    }
  }

  /**
   * A frame from `from`, the PeerID that signed it. A greeting makes or
   * unmakes a peer; anything else is handed to the Repo with `senderId` set
   * to the signer, whatever the bytes claim: the signature is the identity.
   */
  private onFrame(from: string, payload: Uint8Array): void {
    if (!this.connected) {
      return;
    }
    let decoded: unknown;
    try {
      decoded = cbor.decode(payload);
    } catch {
      this.dropped += 1;
      return;
    }
    if (typeof decoded !== "object" || decoded === null || typeof (decoded as { type?: unknown }).type !== "string") {
      this.dropped += 1;
      return;
    }
    const type = (decoded as { type: string }).type;
    if (GREETINGS.has(type)) {
      const greeting = decoded as Greeting;
      if (type === "leave") {
        this.forget(from);
        this.greeted.delete(from);
        return;
      }
      if (type === "arrive") {
        this.sendGreeting({ type: "welcome", senderId: this.fleetPeerId, targetId: from as PeerId,
          peerMetadata: this.peerMetadata });
      }
      this.candidate(from, greeting.peerMetadata ?? {});
      this.sweep(); // its first frame may precede the sweep that would have greeted it
      return;
    }
    if (!this.known.has(from)) {
      // A message before the greeting completed: the sender knows us, so it answered an arrive we
      // have not folded yet, or a stale welcome was lost. Admit it with empty metadata.
      this.candidate(from, {});
    }
    this.received += 1;
    this.emit("message", { ...(decoded as Message), senderId: from as PeerId });
  }
}
