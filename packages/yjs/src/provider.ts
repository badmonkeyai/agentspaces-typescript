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
 * The Yjs provider over an AgentSpaces fleet (srad/agentspaces-js.md
 * JS-S-02, JS-S-03): per document the y-protocols sync messages (step 1,
 * step 2, update) and awareness updates travel as signed `PIPE_DATA` frames
 * of capability `aspace:cap/yjs`, addressed to the members the peer's pipes
 * reach, with the document's name as the room beside them.
 *
 *     const provider = new AgentSpacesProvider(pipes, "room", doc);
 *
 * The payload is a two-field CBOR map `{room, message}` where `message` is
 * what y-websocket writes on its socket: one varUint for the outer kind
 * ({@link MESSAGE_SYNC}, {@link MESSAGE_AWARENESS}, {@link MESSAGE_QUERY_AWARENESS})
 * and then the y-protocols bytes, untouched. AgentSpaces adds signing,
 * membership, and the link; the document format stays Yjs's.
 *
 * Every member is a peer of every other, so both sides open with step 1
 * when they meet and each answers with step 2; a received update is applied
 * under an origin naming its sender and re-sent to everyone else only if it
 * changed the document, so a hub relays for the dial-only members behind it
 * and a mesh's echoes die out. Awareness goes the same way, deduplicated by
 * its clocks, and when a member leaves, the clients whose latest news came
 * through it are retired, as a y-websocket server retires a connection's.
 */

import * as Y from "yjs";
import * as syncProtocol from "y-protocols/sync";
import * as awarenessProtocol from "y-protocols/awareness";
import * as encoding from "lib0/encoding";
import * as decoding from "lib0/decoding";
import { Emitter, capabilities, cbor, wire } from "@agentspaces/client";

/** The capability type of the frames (SPEC §8 pipes; srad/agentspaces-js.md §4.8). */
export const TYPE = "aspace:cap/yjs";

/** The outer message kinds, numbered as y-websocket numbers them (2 is its auth kind, unused here). */
export const MESSAGE_SYNC = 0;
export const MESSAGE_AWARENESS = 1;
export const MESSAGE_QUERY_AWARENESS = 3;

/** Headroom under the fleet's frame cap (`wire.MAX_FRAME_BYTES`) for the PIPE_DATA envelope and the room. */
export const ENVELOPE_HEADROOM_BYTES = 64 * 1024;

/** The largest payload the provider sends by default: the frame cap less the envelope headroom. */
export const DEFAULT_MAX_PAYLOAD_BYTES = wire.MAX_FRAME_BYTES - ENVELOPE_HEADROOM_BYTES;

export type Kind = "sync" | "awareness";

export type AgentSpacesProviderOptions = {
  /** The awareness to share; the provider makes and owns one on the document when absent. */
  awareness?: awarenessProtocol.Awareness;
  /** Whether to connect in the constructor (true). */
  connect?: boolean;
  /** How often the reachable set is swept, in milliseconds (250); the first provider on a `Pipes` sets it. */
  sweepMillis?: number;
  /**
   * The largest payload the provider sends; above it the message is refused
   * with an error naming the room, the kind, the size, and this bound, never
   * chunked (a transport drops an oversize frame silently). Defaults to
   * {@link DEFAULT_MAX_PAYLOAD_BYTES}; it cannot exceed the frame cap.
   */
  maxPayloadBytes?: number;
  /** Called instead of throwing when a message is refused for its size. */
  onRefused?: (room: string, kind: Kind, bytes: number, error: Error) => void;
};

/** The transaction origin of a receipt: the provider that applied it and the member it came from. */
type Receipt = { provider: AgentSpacesProvider; from: string };

function receiptOf(origin: unknown, provider: AgentSpacesProvider): Receipt | null {
  return typeof origin === "object" && origin !== null && (origin as Receipt).provider === provider
    ? (origin as Receipt) : null;
}

/**
 * One peer's multiplexer for the capability: the single handler the pipes
 * allow per type, routing by room to the providers, and the sweep of the
 * reachable set they share. One per `Pipes`, made on first use.
 */
class Router {
  private static readonly routers = new WeakMap<capabilities.Pipes, Router>();

  static for(pipes: capabilities.Pipes, sweepMillis: number): Router {
    let router = Router.routers.get(pipes);
    if (router === undefined) {
      router = new Router(pipes, sweepMillis);
      Router.routers.set(pipes, router);
    }
    return router;
  }

  readonly providers = new Map<string, AgentSpacesProvider>();
  /** The members greeted since they last appeared in the reachable set. */
  readonly greeted = new Set<string>();
  /** Frames for no room of ours, or that did not decode. */
  dropped = 0;
  private timer: ReturnType<typeof setInterval> | null = null;

  private constructor(readonly pipes: capabilities.Pipes, readonly sweepMillis: number) {
    pipes.onCapability(TYPE, (from, payload) => this.onFrame(from, payload));
  }

  register(provider: AgentSpacesProvider): void {
    if (this.providers.has(provider.room)) {
      throw new Error(`@agentspaces/yjs: room '${provider.room}' already has a provider on this peer`);
    }
    this.providers.set(provider.room, provider);
    if (this.timer === null) {
      this.timer = setInterval(() => this.sweep(), this.sweepMillis);
    }
    this.sweep();
    for (const member of this.greeted) {
      provider.greet(member);
    }
  }

  unregister(provider: AgentSpacesProvider): void {
    if (this.providers.get(provider.room) !== provider) {
      return;
    }
    this.providers.delete(provider.room);
    if (this.providers.size === 0) {
      if (this.timer !== null) {
        clearInterval(this.timer);
        this.timer = null;
      }
      this.greeted.clear();
    }
  }

  /** One pass over the reachable set: departures are forgotten by every provider, arrivals greeted. */
  sweep(): void {
    const members = new Set(this.pipes.members());
    for (const member of [...this.greeted]) {
      if (!members.has(member)) {
        this.greeted.delete(member);
        for (const provider of this.providers.values()) {
          provider.forget(member);
        }
      }
    }
    for (const member of members) {
      if (!this.greeted.has(member)) {
        this.greeted.add(member);
        for (const provider of this.providers.values()) {
          provider.greet(member);
        }
      }
    }
  }

  private onFrame(from: string, payload: Uint8Array): void {
    let room: unknown;
    let message: unknown;
    try {
      const frame = cbor.loads(payload) as { room?: unknown; message?: unknown };
      room = frame?.room;
      message = frame?.message;
    } catch {
      this.dropped += 1;
      return;
    }
    if (typeof room !== "string" || !(message instanceof Uint8Array)) {
      this.dropped += 1;
      return;
    }
    if (!this.greeted.has(from)) {
      this.sweep(); // its first frame may precede the sweep that would have greeted it
    }
    const provider = this.providers.get(room);
    if (provider === undefined) {
      this.dropped += 1;
      return;
    }
    provider.receive(from, message);
  }
}

/** One document's provider: the room, the doc, its awareness, over one peer's pipes. */
export class AgentSpacesProvider extends Emitter {
  readonly awareness: awarenessProtocol.Awareness;
  readonly maxPayloadBytes: number;
  /** Whether a step 2 has been received since connecting: this doc has heard a member's full state. */
  synced = false;
  /** Messages received for this room. */
  received = 0;
  private connected = false;
  private readonly ownsAwareness: boolean;
  private readonly onRefused: AgentSpacesProviderOptions["onRefused"];
  private readonly router: Router;
  /** The awareness clients whose latest accepted news came through each member, retired when it leaves. */
  private readonly controlled = new Map<string, Set<number>>();
  /** The members whose step 2 has been heard since they were greeted: their sync with us is open. */
  private readonly heardStep2 = new Set<string>();
  /** The members whose step 1 was answered with one of ours, so a crossing costs one round, not more. */
  private readonly reopened = new Set<string>();
  private readonly updateHandler = (update: Uint8Array, origin: unknown): void => this.onDocUpdate(update, origin);
  private readonly awarenessHandler = (changes: { added: number[]; updated: number[]; removed: number[] }, origin: unknown): void =>
    this.onAwarenessUpdate(changes, origin);

  constructor(readonly pipes: capabilities.Pipes, readonly room: string, readonly doc: Y.Doc,
              options: AgentSpacesProviderOptions = {}) {
    super();
    this.maxPayloadBytes = Math.min(options.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES, wire.MAX_FRAME_BYTES);
    const sweepMillis = options.sweepMillis ?? 250;
    if (sweepMillis <= 0 || this.maxPayloadBytes <= 0) {
      throw new Error("sweepMillis and maxPayloadBytes are positive");
    }
    this.router = Router.for(pipes, sweepMillis);
    if (this.router.providers.has(room)) {
      // Refused before an awareness (and its check interval) exists, so a refused provider leaves nothing behind.
      throw new Error(`@agentspaces/yjs: room '${room}' already has a provider on this peer`);
    }
    this.ownsAwareness = options.awareness === undefined;
    this.awareness = options.awareness ?? new awarenessProtocol.Awareness(doc);
    this.onRefused = options.onRefused;
    if (options.connect ?? true) {
      this.connect();
    }
  }

  /** The AgentSpaces PeerID this provider speaks under. */
  get peerId(): string {
    return this.pipes.peer.identity.peerId;
  }

  /** The members this provider syncs with right now. */
  members(): string[] {
    return this.connected ? [...this.router.greeted] : [];
  }

  isConnected(): boolean {
    return this.connected;
  }

  /** Frames that reached this peer for no room of its own, or that did not decode (shared by the peer's providers). */
  get dropped(): number {
    return this.router.dropped;
  }

  /** Listens to the document and the awareness, joins the room, and greets every reachable member. */
  connect(): void {
    if (this.connected) {
      return;
    }
    this.connected = true;
    this.doc.on("update", this.updateHandler);
    this.awareness.on("update", this.awarenessHandler);
    this.router.register(this);
    this.emit("status", { status: "connected" });
  }

  /** Retires this client's awareness state for the others, leaves the room, and stops listening. */
  disconnect(): void {
    if (!this.connected) {
      return;
    }
    awarenessProtocol.removeAwarenessStates(this.awareness, [this.doc.clientID], "local"); // broadcast while listening
    this.router.unregister(this);
    this.doc.off("update", this.updateHandler);
    this.awareness.off("update", this.awarenessHandler);
    this.controlled.clear();
    this.heardStep2.clear();
    this.reopened.clear();
    this.connected = false;
    this.synced = false;
    this.emit("status", { status: "disconnected" });
  }

  /** Disconnects and destroys the awareness the provider made; the document is the application's. */
  destroy(): void {
    this.disconnect();
    if (this.ownsAwareness) {
      this.awareness.destroy();
    }
    this.removeAllListeners();
  }

  /** Opens with a member: step 1 of the sync, then every awareness state this peer holds. */
  greet(member: string): void {
    if (!this.connected) {
      return;
    }
    this.sendTo(member, step1(this.doc), "sync");
    this.sendStates(member, false);
  }

  /** Every awareness state this peer holds, to one member; nothing when it holds none. */
  private sendStates(member: string, answering: boolean): void {
    const clients = [...this.awareness.getStates().keys()];
    if (clients.length > 0) {
      this.sendTo(member, awarenessMessage(this.awareness, clients), "awareness", answering);
    }
  }

  /** A member left: the awareness states heard from it are retired, and the retirement travels on. */
  forget(member: string): void {
    this.heardStep2.delete(member);
    this.reopened.delete(member);
    const clients = this.controlled.get(member);
    this.controlled.delete(member);
    if (clients !== undefined && clients.size > 0) {
      awarenessProtocol.removeAwarenessStates(this.awareness, [...clients], { provider: this, from: member } satisfies Receipt);
    }
  }

  /** One message from `from`, the PeerID that signed the frame, in y-websocket's framing. */
  receive(from: string, message: Uint8Array): void {
    if (!this.connected) {
      return;
    }
    this.received += 1;
    const decoder = decoding.createDecoder(message);
    const kind = decoding.readVarUint(decoder);
    const receipt: Receipt = { provider: this, from };
    if (kind === MESSAGE_SYNC) {
      const encoder = encoding.createEncoder();
      encoding.writeVarUint(encoder, MESSAGE_SYNC);
      const step = syncProtocol.readSyncMessage(decoder, encoder, this.doc, receipt);
      if (encoding.length(encoder) > 1) {
        this.sendTo(from, encoding.toUint8Array(encoder), "sync", true); // a step 2 answering their step 1
      }
      if (step === syncProtocol.messageYjsSyncStep1) {
        // Their step 1 opens a sync with us: a greeting of ours may have found no provider on their
        // side yet (one made after the peer connected), so open ours too, once, unless they already
        // answered one; and give them our awareness states, as a y-websocket server does on a
        // connection. Two greetings that cross cost each side one extra step 1 and an empty step 2.
        if (!this.heardStep2.has(from) && !this.reopened.has(from)) {
          this.reopened.add(from);
          this.sendTo(from, step1(this.doc), "sync", true);
        }
        this.sendStates(from, true);
      } else if (step === syncProtocol.messageYjsSyncStep2) {
        this.heardStep2.add(from);
        if (!this.synced) {
          this.synced = true;
          this.emit("sync", true);
          this.emit("synced", true);
        }
      }
    } else if (kind === MESSAGE_AWARENESS) {
      // Applied under the receipt: the update event then reports what was accepted, and from whom.
      awarenessProtocol.applyAwarenessUpdate(this.awareness, decoding.readVarUint8Array(decoder), receipt);
    } else if (kind === MESSAGE_QUERY_AWARENESS) {
      this.sendStates(from, true);
    }
  }

  /** A document change: this peer's own goes to everyone, a received one on to everyone but its sender. */
  private onDocUpdate(update: Uint8Array, origin: unknown): void {
    const encoder = encoding.createEncoder();
    encoding.writeVarUint(encoder, MESSAGE_SYNC);
    syncProtocol.writeUpdate(encoder, update);
    this.broadcast(encoding.toUint8Array(encoder), "sync", receiptOf(origin, this)?.from);
  }

  /**
   * An awareness change: this peer's own goes to everyone, a received one on
   * to everyone but its sender. A received change also attributes the client
   * ids it accepted to the member it came from (an echo of news already held
   * is rejected by the clocks and attributes nothing), so a member's
   * departure retires exactly the clients whose latest news came through it.
   */
  private onAwarenessUpdate(changes: { added: number[]; updated: number[]; removed: number[] }, origin: unknown): void {
    const receipt = receiptOf(origin, this);
    if (receipt !== null) {
      this.attribute(receipt.from, [...changes.added, ...changes.updated]);
    }
    for (const client of changes.removed) {
      for (const clients of this.controlled.values()) {
        clients.delete(client);
      }
    }
    const clients = [...changes.added, ...changes.updated, ...changes.removed];
    this.broadcast(awarenessMessage(this.awareness, clients), "awareness", receipt?.from);
  }

  /** Makes `member` the one controlling `clients`: the member whose news of each is the latest accepted. */
  private attribute(member: string, clients: number[]): void {
    let mine = this.controlled.get(member);
    if (mine === undefined) {
      mine = new Set();
      this.controlled.set(member, mine);
    }
    for (const client of clients) {
      if (client === this.doc.clientID) {
        continue; // this peer's own state is nobody else's to retire
      }
      for (const [other, theirs] of this.controlled) {
        if (other !== member) {
          theirs.delete(client);
        }
      }
      mine.add(client);
    }
  }

  private broadcast(message: Uint8Array, kind: Kind, except?: string): void {
    for (const member of this.router.greeted) {
      if (member !== except) {
        this.sendTo(member, message, kind);
      }
    }
  }

  /**
   * One frame to one member: the room and the message in a CBOR map. Over
   * the bound, the message is refused by name; a refusal while answering a
   * member's frame is reported through `onRefused` or the `refused` event
   * rather than thrown into the peer's frame handling.
   */
  private sendTo(member: string, message: Uint8Array, kind: Kind, answering = false): void {
    const payload = cbor.dumps({ room: this.room, message });
    if (payload.length > this.maxPayloadBytes) {
      const error = new Error(`@agentspaces/yjs: a ${kind} message for room '${this.room}' of ${payload.length} bytes`
        + ` exceeds maxPayloadBytes ${this.maxPayloadBytes} (the fleet's frame cap is ${wire.MAX_FRAME_BYTES});`
        + " refused, not chunked");
      if (this.onRefused) {
        this.onRefused(this.room, kind, payload.length, error);
      } else if (answering) {
        this.emit("refused", error);
      } else {
        throw error;
      }
      return;
    }
    this.pipes.send(member, TYPE, payload);
  }
}

/** Step 1 of the sync (this doc's state vector), in y-websocket's framing. */
function step1(doc: Y.Doc): Uint8Array {
  const encoder = encoding.createEncoder();
  encoding.writeVarUint(encoder, MESSAGE_SYNC);
  syncProtocol.writeSyncStep1(encoder, doc);
  return encoding.toUint8Array(encoder);
}

/** An awareness message for `clients`, in y-websocket's framing. */
function awarenessMessage(awareness: awarenessProtocol.Awareness, clients: number[]): Uint8Array {
  const encoder = encoding.createEncoder();
  encoding.writeVarUint(encoder, MESSAGE_AWARENESS);
  encoding.writeVarUint8Array(encoder, awarenessProtocol.encodeAwarenessUpdate(awareness, clients));
  return encoding.toUint8Array(encoder);
}
