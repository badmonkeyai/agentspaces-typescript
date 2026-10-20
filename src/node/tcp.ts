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
 * The `tcp` binding for Node (srad/agentspaces-js.md JS-P-06): frames with
 * the stream bindings' 4-byte big-endian length prefix, at most 8 MiB, over
 * `node:net`. Dialing expands a hostname to every address it resolves to
 * (DB-X-03); listening accepts channels for a service host (JS-H-11).
 */

import { lookup } from "node:dns/promises";
import { AddressInfo, Server, Socket, connect, createServer, isIP } from "node:net";
import { concat, int32be, readInt32be } from "../bytes.js";
import { Seed, seedAddress } from "../seed.js";
import { ChannelEvents, Dialer, FrameChannel, Listener, ListenerHandle } from "../transport.js";
import { MAX_FRAME_BYTES } from "../wire.js";

/** One TCP connection carrying length-prefixed frames. */
export class TcpChannel implements FrameChannel {
  readonly scheme = "tcp";
  private readonly events = new ChannelEvents();

  constructor(private readonly socket: Socket, readonly remote: string) {
    socket.on("data", (chunk: Uint8Array | string) =>
      this.onData(typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk));
    socket.on("close", () => this.events.close("closed"));
    socket.on("error", () => { /* the close that follows ends the channel */ });
  }

  attestedPeer(): string | null {
    return null;
  }

  send(frame: Uint8Array): void {
    if (this.events.closed || this.socket.destroyed) {
      return;
    }
    if (frame.length <= 0 || frame.length > MAX_FRAME_BYTES) {
      return; // never put an unframeable frame on the stream
    }
    this.socket.write(concat(int32be(frame.length), frame));
  }

  onFrame(receiver: (frame: Uint8Array) => void): void {
    this.events.onFrame(receiver);
  }

  onClose(listener: (reason: string) => void): void {
    this.events.onClose(listener);
  }

  close(): void {
    this.socket.destroy();
    this.events.close("closed by this end");
  }

  /**
   * The receive buffer: chunks are appended into a buffer that doubles when full, so an 8 MiB
   * frame arriving in many small reads costs one copy per doubling, not one per read; a frame is
   * sliced out once whole. A corrupt or hostile length prefix poisons the whole stream (there is
   * no way to resynchronize, and a non-positive length would loop here forever, ASF-014/016), so
   * the connection is dropped; leases recover.
   */
  private buffer = new Uint8Array(0);
  private buffered = 0;

  private onData(chunk: Uint8Array): void {
    this.append(chunk);
    let offset = 0;
    while (this.buffered - offset >= 4) {
      const length = readInt32be(this.buffer, offset);
      if (length <= 0 || length > MAX_FRAME_BYTES) {
        this.buffer = new Uint8Array(0);
        this.buffered = 0;
        this.socket.destroy();
        return;
      }
      if (this.buffered - offset < 4 + length) {
        break;
      }
      const frame = this.buffer.slice(offset + 4, offset + 4 + length);
      offset += 4 + length;
      this.events.deliver(frame);
    }
    if (offset > 0) {
      // Keep what remains at the front; the capacity stays for the next frame.
      this.buffer.copyWithin(0, offset, this.buffered);
      this.buffered -= offset;
    }
  }

  private append(chunk: Uint8Array): void {
    const needed = this.buffered + chunk.length;
    if (needed > this.buffer.length) {
      let capacity = Math.max(this.buffer.length * 2, 64 * 1024);
      while (capacity < needed) {
        capacity *= 2;
      }
      const grown = new Uint8Array(Math.min(capacity, 4 + MAX_FRAME_BYTES + chunk.length + this.buffered));
      grown.set(this.buffer.subarray(0, this.buffered), 0);
      this.buffer = grown;
    }
    this.buffer.set(chunk, this.buffered);
    this.buffered += chunk.length;
  }
}

/** Dials `tcp` seeds; a hostname expands to one seed per resolved address (DB-X-03). */
export class TcpDialer implements Dialer {
  readonly scheme = "tcp";

  /** DB-X-03: a hostname becomes one seed per address it resolves to, in the resolver's order. */
  async expand(seed: Seed, resolve: boolean): Promise<Seed[]> {
    if (!resolve || isIP(seed.host) !== 0 || seed.host === "localhost") {
      return [seed];
    }
    const addresses = await lookup(seed.host, { all: true });
    if (addresses.length === 0) {
      return [seed];
    }
    return addresses.map((a) => ({ ...seed, host: a.address }));
  }

  dial(seed: Seed): Promise<FrameChannel> {
    return new Promise((resolve, reject) => {
      // The channel exists only once connected: a refused dial also emits close,
      // and that close must reach nobody (one reconnect chain per peer).
      const socket = connect({ host: seed.host, port: seed.port });
      let settled = false;
      // The channel wraps the socket synchronously in the connect callback, so the
      // first bytes the seed sends are buffered before any await can intervene.
      socket.once("connect", () => {
        settled = true;
        socket.removeListener("error", onError);
        resolve(new TcpChannel(socket, seedAddress(seed)));
      });
      const onError = (error: Error): void => {
        if (!settled) {
          settled = true;
          socket.destroy();
          reject(error);
        }
      };
      socket.on("error", onError);
    });
  }
}

/** Accepts `tcp` channels on a bind address (`host:port`). */
export class TcpListener implements Listener {
  readonly scheme = "tcp";

  listen(bind: string, onAccept: (channel: FrameChannel) => void): Promise<ListenerHandle> {
    const colon = bind.lastIndexOf(":");
    const host = colon > 0 ? bind.substring(0, colon).replace(/^\[|\]$/g, "") : "0.0.0.0";
    const port = Number(colon >= 0 ? bind.substring(colon + 1) : bind);
    return new Promise((resolve, reject) => {
      const server: Server = createServer((socket) => {
        onAccept(new TcpChannel(socket, `${socket.remoteAddress}:${socket.remotePort}`));
      });
      server.once("error", reject);
      server.listen(port, host, () => {
        server.removeListener("error", reject);
        const address = server.address() as AddressInfo;
        resolve(Object.assign(() => server.close(), { address: `${host}:${address.port}` }));
      });
    });
  }
}
