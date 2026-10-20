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
 * The `ws` and `wss` dialers of the portable core (srad/agentspaces-js.md
 * JS-H-06; ISSUE-Websocket §9.9) on the runtime's global `WebSocket`: one
 * binary message is one frame, with no length prefix; subprotocol
 * `aspace.1`; a text message closes with 1003 and an oversize one with 1009.
 * Runs in browsers, Node 22, Deno, Bun, and workerd. The TLS trust decision
 * is the runtime's (a browser's roots, Node's), so a `wss` listener a browser
 * dials presents a certificate the browser trusts; identity binds in band by
 * session attestation.
 */

import { MAX_FRAME_BYTES } from "../wire.js";
import { Seed, seedAddress } from "../seed.js";
import { ChannelEvents, Dialer, FrameChannel } from "../transport.js";

/** The subprotocol both ends negotiate: the binding version in token syntax. */
export const SUBPROTOCOL = "aspace.1";
export const DIAL_TIMEOUT_MILLIS = 10_000;

/** A `WebSocket`-shaped object, so a test can supply its own. */
export interface WebSocketLike {
  binaryType: string;
  readonly protocol: string;
  readonly readyState: number;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: { code?: number; reason?: string }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  send(data: Uint8Array): void;
  close(code?: number, reason?: string): void;
}

export class WsChannel implements FrameChannel {
  private readonly events = new ChannelEvents();

  constructor(readonly scheme: string, private readonly socket: WebSocketLike, readonly remote: string) {
    socket.onmessage = (event) => {
      const data = event.data;
      if (data instanceof ArrayBuffer) {
        this.deliver(new Uint8Array(data));
      } else if (ArrayBuffer.isView(data)) {
        // A copy: a runtime may hand a view of a buffer it reuses for the next message.
        this.deliver(new Uint8Array(data.buffer, data.byteOffset, data.byteLength).slice());
      } else if (typeof Blob !== "undefined" && data instanceof Blob) {
        data.arrayBuffer().then((buffer) => this.deliver(new Uint8Array(buffer)));
      } else {
        this.closeWith(1003, "text messages are not frames");
      }
    };
    socket.onclose = (event) => this.events.close(`closed (${event.code ?? "?"})`);
    socket.onerror = () => { /* the close that follows ends the channel */ };
  }

  private deliver(frame: Uint8Array): void {
    if (frame.length > MAX_FRAME_BYTES) {
      this.closeWith(1009, "frame too large");
      return;
    }
    this.events.deliver(new Uint8Array(frame));
  }

  attestedPeer(): string | null {
    return null;
  }

  send(frame: Uint8Array): void {
    if (this.events.closed || frame.length === 0 || frame.length > MAX_FRAME_BYTES) {
      return;
    }
    try {
      this.socket.send(frame);
    } catch {
      // a socket that is closing drops the frame, as a lost socket would
    }
  }

  onFrame(receiver: (frame: Uint8Array) => void): void {
    this.events.onFrame(receiver);
  }

  onClose(listener: (reason: string) => void): void {
    this.events.onClose(listener);
  }

  close(): void {
    this.closeWith(1000, "");
  }

  private closeWith(code: number, reason: string): void {
    try {
      this.socket.close(code, reason);
    } catch {
      // already closed
    }
    this.events.close(`closed by this end (${code})`);
  }
}

/** Opens the runtime's `WebSocket`; tests may substitute a factory. */
export type WebSocketFactory = (url: string, protocols: string[]) => WebSocketLike;

/** Dials `ws` or `wss` seeds. */
export class WsDialer implements Dialer {
  constructor(readonly scheme: "ws" | "wss",
              private readonly factory: WebSocketFactory = (url, protocols) =>
                new (globalThis as unknown as { WebSocket: new (u: string, p: string[]) => WebSocketLike })
                  .WebSocket(url, protocols)) {
    if (typeof (globalThis as { WebSocket?: unknown }).WebSocket !== "function" && factory === undefined) {
      throw new Error("this runtime has no WebSocket; the ws and wss dialers need one");
    }
  }

  dial(seed: Seed): Promise<FrameChannel> {
    const url = `${this.scheme}://${seedAddress({ ...seed, path: seed.path ?? "/aspace" })}`;
    return new Promise<FrameChannel>((resolve, reject) => {
      let socket: WebSocketLike;
      try {
        socket = this.factory(url, [SUBPROTOCOL]);
      } catch (e) {
        reject(e instanceof Error ? e : new Error(String(e)));
        return;
      }
      socket.binaryType = "arraybuffer";
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          socket.close(1000, "dial timeout");
          reject(new Error(`WebSocket dial to ${url} timed out`));
        }
      }, DIAL_TIMEOUT_MILLIS);
      socket.onopen = () => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        if (socket.protocol !== SUBPROTOCOL) {
          socket.close(1002, "subprotocol");
          reject(new Error(`${url} did not select ${SUBPROTOCOL}`));
          return;
        }
        resolve(new WsChannel(this.scheme, socket, url));
      };
      socket.onerror = () => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(new Error(`cannot open a WebSocket to ${url}`));
        }
      };
      socket.onclose = (event) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(new Error(`WebSocket to ${url} closed before opening (${event.code ?? "?"})`));
        }
      };
    });
  }
}
