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
 * The `http` and `https` dialers of the portable core (srad/agentspaces-js.md
 * JS-H-07, appendix C) over `fetch`, for networks whose proxies refuse the
 * WebSocket upgrade: `POST P/open`, uploads of up to 64 frames or 1 MiB with
 * a rising `Aspace-Seq` (a batch whose answer was lost is repeated with the
 * same number), a long-poll download with `Aspace-Ack`, `DELETE` on close.
 * Bodies carry the stream bindings' 4-byte length prefix per frame.
 */

import { concat, int32be, readInt32be } from "../bytes.js";
import { MAX_FRAME_BYTES } from "../wire.js";
import { Seed, seedAddress } from "../seed.js";
import { ChannelEvents, Dialer, FrameChannel } from "../transport.js";

export const MEDIA_TYPE = "application/vnd.agentspaces.frames";
const MAX_BATCH_FRAMES = 64;
const UPLOAD_BYTES = 1024 * 1024;
const MAX_BODY = 9 * 1024 * 1024;

export interface HttpDialerOptions {
  /** How long a download request is held by the listener (default 25 s); the request timeout adds 15 s. */
  longPollMillis?: number;
  /** A session silent this long ends (default 60 s). */
  idleTimeoutMillis?: number;
  /** The `fetch` to use (the global by default). */
  fetch?: typeof fetch;
}

/**
 * Encodes frames as one exchange body; refuses, before any copy, what `decodeBatch` would
 * (an empty or oversize frame, too many frames, a body over the bound).
 */
export function encodeBatch(frames: Uint8Array[]): Uint8Array {
  if (frames.length > MAX_BATCH_FRAMES) {
    throw new Error(`more than ${MAX_BATCH_FRAMES} frames in one body`);
  }
  let total = 0;
  for (const frame of frames) {
    if (frame.length === 0 || frame.length > MAX_FRAME_BYTES) {
      throw new Error(`frame of ${frame.length} bytes: a frame is 1 to ${MAX_FRAME_BYTES} bytes`);
    }
    total += 4 + frame.length;
  }
  if (total > MAX_BODY) {
    throw new Error(`body of ${total} bytes exceeds ${MAX_BODY}`);
  }
  return concat(...frames.flatMap((f) => [int32be(f.length), f]));
}

/** Decodes an exchange body; a malformed one throws. */
export function decodeBatch(body: Uint8Array): Uint8Array[] {
  if (body.length > MAX_BODY) {
    throw new Error(`body exceeds ${MAX_BODY} bytes`);
  }
  const frames: Uint8Array[] = [];
  let offset = 0;
  while (offset < body.length) {
    if (body.length - offset < 4) {
      throw new Error("truncated length prefix");
    }
    const length = readInt32be(body, offset);
    offset += 4;
    if (length <= 0 || length > MAX_FRAME_BYTES || length > body.length - offset) {
      throw new Error(`bad frame length ${length}`);
    }
    frames.push(body.slice(offset, offset + length));
    offset += length;
    if (frames.length > MAX_BATCH_FRAMES) {
      throw new Error(`more than ${MAX_BATCH_FRAMES} frames in one body`);
    }
  }
  return frames;
}

export class HttpChannel implements FrameChannel {
  private readonly events = new ChannelEvents();
  private readonly outbound: Uint8Array[] = [];
  private wake: (() => void) | null = null;
  private stopping = false;
  private readonly longPoll: number;
  private readonly idle: number;
  private readonly doFetch: typeof fetch;

  constructor(readonly scheme: string, private readonly session: string, options: HttpDialerOptions) {
    this.longPoll = options.longPollMillis ?? 25_000;
    this.idle = options.idleTimeoutMillis ?? 60_000;
    // Called as a free function: a browser's fetch throws "Illegal invocation" as a method of another object.
    const doFetch = options.fetch ?? globalThis.fetch;
    this.doFetch = (input, init) => doFetch(input, init);
    void this.uploadLoop();
    void this.downloadLoop();
  }

  get remote(): string {
    return this.session;
  }

  attestedPeer(): string | null {
    return null;
  }

  send(frame: Uint8Array): void {
    if (this.events.closed || frame.length === 0 || frame.length > MAX_FRAME_BYTES) {
      return;
    }
    this.outbound.push(frame);
    this.wake?.();
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
    this.stopping = true;
    this.wake?.();
    this.events.close("closed by this end");
    this.doFetch(this.session, { method: "DELETE" }).catch(() => undefined);
  }

  private end(reason: string): void {
    this.stopping = true;
    this.wake?.();
    this.events.close(reason);
  }

  private async request(url: string, init: RequestInit, timeoutMillis: number): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMillis);
    try {
      return await this.doFetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  private async uploadLoop(): Promise<void> {
    let seq = 0;
    let lastSuccess = Date.now();
    while (!this.stopping) {
      if (this.outbound.length === 0) {
        await new Promise<void>((resolve) => { this.wake = resolve; setTimeout(resolve, 1000); });
        this.wake = null;
        continue;
      }
      const batch: Uint8Array[] = [];
      let bytes = 0;
      while (this.outbound.length > 0 && batch.length < MAX_BATCH_FRAMES
          && (batch.length === 0 || bytes + this.outbound[0].length <= UPLOAD_BYTES)) {
        const frame = this.outbound.shift()!;
        batch.push(frame);
        bytes += frame.length;
      }
      seq++;
      const body = encodeBatch(batch);
      while (!this.stopping) {
        try {
          const response = await this.request(`${this.session}/up`, {
            method: "POST", body: new Uint8Array(body).buffer,
            headers: { "content-type": MEDIA_TYPE, "aspace-seq": String(seq) },
          }, 30_000);
          if (response.status === 204) {
            lastSuccess = Date.now();
            break;
          }
          this.end(`upload answered ${response.status}`);
          return;
        } catch {
          if (Date.now() - lastSuccess > this.idle) {
            this.end("upload idle timeout");
            return;
          }
          await new Promise((r) => setTimeout(r, 500)); // the same batch again, with the same number
        }
      }
    }
  }

  private async downloadLoop(): Promise<void> {
    let ack = 0;
    let lastSuccess = Date.now();
    while (!this.stopping) {
      try {
        const response = await this.request(`${this.session}/down`, {
          method: "GET", headers: { "aspace-ack": String(ack) },
        }, this.longPoll + 15_000);
        lastSuccess = Date.now();
        if (response.status === 204) {
          continue;
        }
        if (response.status !== 200) {
          this.end(`download answered ${response.status}`);
          return;
        }
        const seq = Number(response.headers.get("aspace-seq") ?? -1);
        const frames = decodeBatch(new Uint8Array(await response.arrayBuffer()));
        if (seq === ack + 1) {
          for (const frame of frames) {
            this.events.deliver(frame);
          }
          ack = seq;
        }
      } catch {
        if (this.stopping) {
          return;
        }
        if (Date.now() - lastSuccess > this.idle) {
          this.end("download idle timeout");
          return;
        }
        await new Promise((r) => setTimeout(r, 500));
      }
    }
  }
}

/** Dials `http` or `https` seeds. */
export class HttpDialer implements Dialer {
  constructor(readonly scheme: "http" | "https", private readonly options: HttpDialerOptions = {}) {}

  async dial(seed: Seed): Promise<FrameChannel> {
    const base = `${this.scheme}://${seedAddress({ ...seed, path: seed.path ?? "/aspace/h" })}`;
    const doFetch = this.options.fetch ?? globalThis.fetch;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    let response: Response;
    try {
      response = await doFetch(`${base}/open`, { method: "POST", signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
    const location = response.headers.get("location");
    if (response.status !== 201 || location === null) {
      throw new Error(`${base}/open answered ${response.status}`);
    }
    return new HttpChannel(this.scheme, new URL(location, `${base}/open`).toString(), this.options);
  }
}
