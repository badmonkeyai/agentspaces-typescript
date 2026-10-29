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
 * The port protocol between a page and the resident host
 * (srad/agentspaces-js.md JS-R-02, §6.2 `PortBridge`): requests carry an id
 * and a tag, answers carry the id and a value or an error, and the host
 * pushes events (space events, subscription closes, host state) without an
 * id. Every entry payload and tag map crosses the port as its CBOR bytes, so
 * a float stays a float and an integer an integer whichever side encodes it;
 * everything else is a structured clone of plain values. Nothing here
 * touches a browser global, so the module loads in Node for its tests.
 */

import { cbor } from "@agentspaces/client";
import type { EventKind, Residency } from "@agentspaces/client";

/** The Web Lock one host per identity per origin holds (JS-R-02). */
export function lockName(group: string, peerId: string): string {
  return `agentspaces:${group}:${peerId}`;
}

/** The Web Lock the identity bootstrap runs under, so two hosts starting at once mint one key. */
export function identityLockName(group: string): string {
  return `agentspaces:${group}:identity`;
}

/** The IndexedDB database a group's host keeps its keys and state in, unless configured. */
export function databaseName(group: string): string {
  return `agentspaces:${group}`;
}

/** The key names in the key store: the file layout of `@agentspaces/node` (`peer.key`, `peer.pub`). */
export const PEER_KEY = "peer.key";
export const PEER_PUB = "peer.pub";
export const SNAPSHOT = "snapshot";

/** The agent key under the key store, by the agent's local name. */
export function agentKeyName(localName: string): string {
  return `agents/${localName}/agent.key`;
}

/** What a page tells the host on its first message; the first page's hello configures the host. */
export type HostConfig = {
  group: string;
  /** Seeds in the `scheme://host:port/path` text form the core parses. */
  seeds: string[];
  /** The IndexedDB database; `agentspaces:<group>` by default. */
  database?: string;
  /** The local name of the host's agent (`<peerId>/<name>` signs its writes and claims); `resident` by default. */
  agentName?: string;
  /** The host's housekeeping period; 1 s by default. */
  tickMillis?: number;
  /** How long to wait for the Web Lock before refusing; 3 s by default, `null` waits for good. */
  lockWaitMillis?: number | null;
  /** How often the host snapshots its state to IndexedDB while running; 30 s by default. */
  snapshotMillis?: number;
  /** Pages silent for this long are dropped as gone; three beats by default. */
  pageTimeoutMillis?: number;
  /**
   * The content swarm in the host (srad/large-networks-bulk-data.md LB-C-06): present turns it
   * on, so a fetch runs in the worker over the origin private file system and reports progress
   * to the pages; absent leaves it off.
   */
  content?: ContentConfig;
};

/** The host's content swarm. */
export type ContentConfig = {
  /** `opfs` (the default, falling back to memory where the origin private file system cannot be written) or `memory`. */
  store?: "opfs" | "memory";
  /** The OPFS directory; `agentspaces-content:<group>` by default. */
  storeName?: string;
  /** The space manifests and holdings live in; `content` by default. */
  space?: string;
  /** The publisher's piece size; 1 MiB by default. */
  pieceSize?: number;
  /** Payload bytes above which the host's spaces escalate a write to an artifact; 4 MiB by default. */
  escalateAbove?: number;
};

/** A fetch's progress as it crosses the port. */
export type WireProgress = {
  root: string;
  piecesVerified: number;
  pieces: number;
  bytesReceived: number;
  /** Bytes verified per source, by PeerID. */
  bySource: { [peerId: string]: number };
  done: boolean;
  failure: string | null;
};

/** An artifact as a page sees it: the manifest's identity and size. */
export type WireManifest = { root: string; name: string | null; size: number; pieces: number; mediaType: string | null };

/** What the host reports about itself. */
export type HostState = {
  peerId: string;
  group: string;
  /** Whether the host runs in a SharedWorker (pages share it) or a dedicated Worker (one page). */
  shared: boolean;
  /** A random token minted when this host instance started; a new one means the worker restarted. */
  instance: string;
  /** `resident`, or `visitor` while the tick drifts (JS-R-06). */
  residency: Residency;
  /** Ticks that arrived later than twice the period, in total. */
  drifts: number;
  paused: boolean;
  connected: boolean;
  /** Pages attached, and pages that are active (not hidden by `pagehide` or `freeze`). */
  pages: number;
  activePages: number;
  /** The reason for the last pause, when paused. */
  reason: string | null;
  /** The content swarm's store kind (`opfs` or `memory`), or null when the swarm is off. */
  contentStore?: string | null;
};

/** An entry as it crosses the port: the record's own payload and tag bytes, with its metadata. */
export type WireEntry = {
  entryId: string;
  payload: Uint8Array;
  tags: Uint8Array;
  issuer: string;
  expiresAtMillis: number;
  completed: boolean;
  taken: boolean;
};

/** A space event as it crosses the port. */
export type WireEvent = { ev: "event"; sub: number; kind: EventKind; entry: WireEntry };
/** A host-side subscription ended (its lease lapsed, or the host closed it). */
export type WireClosed = { ev: "closed"; sub: number; reason: string };
/** The host's state changed (paused, resumed, connected, pages). */
export type WireState = { ev: "state"; state: HostState };
/** A fetch the page asked for made progress, completed, or failed. */
export type WireContent = { ev: "content"; progress: WireProgress };
export type Push = WireEvent | WireClosed | WireState | WireContent;

/** A result the page writes with a completion, in port form. */
export type WireResult = { space: string; schema: string; payload: Uint8Array; leaseMillis: number; tags: Uint8Array };

/** Requests, by tag. */
export type Request =
  | { t: "hello"; config: HostConfig; pageId: string; active: boolean }
  | { t: "beat"; active: boolean }
  | { t: "activity"; active: boolean }
  | { t: "detach" }
  | { t: "status" }
  | { t: "log" }
  | { t: "snapshot" }
  | { t: "write"; space: string; schema: string; payload: Uint8Array; leaseMillis: number; tags: Uint8Array }
  | { t: "entries"; space: string; schema: string; limit: number; includeTaken: boolean }
  | { t: "pull"; space: string }
  | { t: "awaitFold"; millis: number }
  | { t: "take"; space: string; schema: string; entryId: string; leaseMillis: number; timeoutMillis: number; keepAlive: boolean }
  | { t: "complete"; space: string; entryId: string; result: WireResult | null }
  | { t: "renewClaim"; space: string; entryId: string; leaseMillis: number }
  | { t: "renewEntry"; space: string; entryId: string; leaseMillis: number }
  | { t: "watch"; space: string; schema: string }
  | { t: "watchLease"; sub: number; leaseMillis: number }
  | { t: "unwatch"; sub: number }
  | { t: "contentPublish"; bytes: Uint8Array; name: string | null; mediaType: string | null; pieceSize: number | null }
  | { t: "contentFetch"; root: string }
  | { t: "contentRead"; root: string }
  | { t: "contentList" }
  | { t: "contentDescribe"; root: string };

export type Envelope = Request & { id: number };
export type Answer = { id: number; ok: true; value: unknown } | { id: number; ok: false; error: string };

/** A port either side talks on: a `MessagePort`, a `Worker`, or a worker's own global scope. */
export interface PortLike {
  postMessage(message: unknown): void;
  onmessage: ((event: { data: unknown }) => void) | null;
  onmessageerror?: ((event: unknown) => void) | null;
  start?(): void;
  close?(): void;
}

type Dict = { [key: string]: cbor.CborValue };

/** A map as port bytes. */
export function packMap(value: Dict): Uint8Array {
  return cbor.dumps(value);
}

/** Port bytes as a map; an empty or absent value is the empty map. */
export function unpackMap(bytes: Uint8Array | null | undefined): Dict {
  if (bytes === null || bytes === undefined || bytes.length === 0) {
    return {};
  }
  const value = cbor.loads(bytes);
  return value !== null && typeof value === "object" && !(value instanceof Uint8Array) && !Array.isArray(value)
    && !(value instanceof cbor.CborDouble) ? value as Dict : {};
}

/** A short random token, for page and instance ids. */
export function token(): string {
  const bytes = new Uint8Array(8);
  (globalThis as { crypto: { getRandomValues(a: Uint8Array): Uint8Array } }).crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
