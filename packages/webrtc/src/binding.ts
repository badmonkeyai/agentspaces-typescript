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
 * The `webrtc` binding of the AgentSpaces JavaScript client (SRAD srad/agentspaces-js.md §3.4,
 * §3.5, §4.3): one RTCPeerConnection per connection with one data channel (`aspace/1`, negotiated
 * id 0, ordered, reliable), signalling as signed `PIPE_DATA` of `aspace:cap/rtc-signal` sent
 * directly when the target is reachable and inside a `RELAY_FRAME` otherwise, and attestation by
 * the DTLS fingerprint each side signs. It runs over the global `RTCPeerConnection` in a browser
 * and over `node-datachannel`'s polyfill on Node; registration fails naming the package when
 * neither exists (JS-W-02).
 */

import { ChannelEvents } from "@agentspaces/client";
import type { Dialer, FrameChannel, Peer, Seed } from "@agentspaces/client";
import * as chunk from "./chunk.js";
import * as fp from "./fingerprints.js";
import * as sig from "./signal.js";
import { WebRtcCounters } from "./counters.js";

/** The subset of the WebRTC API the binding uses, shared by the browser global and the Node polyfill. */
interface RtcApi {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  readonly PeerConnection: new (config: any) => RtcPeerConnection;
  generateCertificate(algorithm: object): Promise<unknown>;
  readonly package: string;
}

interface RtcDataChannel {
  binaryType: string;
  bufferedAmount: number;
  bufferedAmountLowThreshold: number;
  readonly readyState: string;
  onopen: (() => void) | null;
  onclose: (() => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onbufferedamountlow: (() => void) | null;
  send(data: Uint8Array): void;
  close(): void;
}

interface RtcPeerConnection {
  localDescription: { sdp: string; type: string } | null;
  remoteDescription: { sdp: string; type: string } | null;
  onicecandidate: ((ev: { candidate: { candidate: string; sdpMid: string | null } | null }) => void) | null;
  oniceconnectionstatechange: (() => void) | null;
  iceConnectionState: string;
  createDataChannel(label: string, options: object): RtcDataChannel;
  createOffer(): Promise<{ type: string; sdp: string }>;
  createAnswer(): Promise<{ type: string; sdp: string }>;
  setLocalDescription(description?: { type: string; sdp: string }): Promise<void>;
  setRemoteDescription(description: { type: string; sdp: string }): Promise<void>;
  addIceCandidate(candidate: { candidate: string; sdpMid: string | null }): Promise<void>;
  close(): void;
}

/** ICE servers and the bounds of the binding (SRAD §4.3); every value a property, none caps anything. */
export interface WebRtcOptions {
  iceServers?: { urls: string | string[]; username?: string; credential?: string }[];
  dialTimeoutMillis?: number;
  pauseAbove?: number;
  resumeBelow?: number;
  sendBlockedMillis?: number;
  maxFrame?: number;
  offersPerPeerPerMinute?: number;
  candidatesPerSession?: number;
  maxSignalBytes?: number;
  /** The relay offload (JS-W-11): dial a member once more than this many frames crossed a relay to or from it in a minute; 30. */
  offloadFramesPerMinute?: number;
  /** How long after a failed offload dial before the next to the same member; 5 minutes. */
  offloadRetryMillis?: number;
}

const DEFAULTS = {
  dialTimeoutMillis: 15_000,
  pauseAbove: 4 * 1024 * 1024,
  resumeBelow: 1024 * 1024,
  sendBlockedMillis: 30_000,
  maxFrame: chunk.MAX_FRAME,
  offersPerPeerPerMinute: 6,
  candidatesPerSession: 64,
  maxSignalBytes: 64 * 1024,
  offloadFramesPerMinute: 30,
  offloadRetryMillis: 300_000,
};

const LABEL = "aspace/1";
const CHANNEL_ID = 0;

/** Resolves the WebRTC implementation, or throws naming the package (JS-W-02). */
export async function loadRtc(): Promise<RtcApi> {
  const g = globalThis as unknown as { RTCPeerConnection?: unknown };
  if (typeof g.RTCPeerConnection === "function") {
    const PeerConnection = g.RTCPeerConnection as RtcApi["PeerConnection"];
    return {
      PeerConnection,
      generateCertificate: (algorithm) =>
        (g.RTCPeerConnection as unknown as { generateCertificate(a: object): Promise<unknown> })
          .generateCertificate(algorithm),
      package: "the global RTCPeerConnection",
    };
  }
  try {
    const ndc = await import("node-datachannel/polyfill");
    const PeerConnection = ndc.RTCPeerConnection as unknown as RtcApi["PeerConnection"];
    return {
      PeerConnection,
      generateCertificate: (algorithm) =>
        (ndc.RTCPeerConnection as unknown as { generateCertificate(a: object): Promise<unknown> })
          .generateCertificate(algorithm),
      package: "node-datachannel",
    };
  } catch {
    throw new Error("@agentspaces/webrtc found no RTCPeerConnection: run in a browser, or install the"
      + " optional peer dependency node-datachannel for Node");
  }
}

/** One open webrtc connection: appendix B chunks out with backpressure, reassembly in, remote attested. */
class WebRtcChannel implements FrameChannel {
  readonly scheme = "webrtc";
  readonly remote: string;
  private readonly events = new ChannelEvents();
  private readonly reassembler: chunk.Reassembler;
  private readonly capacity: number;
  private sending = Promise.resolve();
  private resumeWaiters: (() => void)[] = [];

  constructor(private readonly dc: RtcDataChannel, private readonly pc: RtcPeerConnection,
              private readonly attested: string, private readonly options: Required<WebRtcOptions>,
              private readonly counters: WebRtcCounters, remoteMaxMessageSize: number,
              private readonly onProtocol: (reason: string) => void) {
    this.remote = `sig/${attested}`;
    this.capacity = chunk.payloadCapacity(remoteMaxMessageSize);
    this.reassembler = new chunk.Reassembler(options.maxFrame, this.capacity);
    dc.binaryType = "arraybuffer";
    dc.bufferedAmountLowThreshold = options.resumeBelow;
    dc.onbufferedamountlow = () => {
      const waiters = this.resumeWaiters;
      this.resumeWaiters = [];
      for (const w of waiters) {
        w();
      }
    };
    dc.onmessage = (ev) => this.onMessage(ev.data);
    dc.onclose = () => this.events.close("channel closed");
  }

  attestedPeer(): string | null {
    return this.attested;
  }

  private onMessage(data: unknown): void {
    let bytes: Uint8Array;
    if (data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data);
    } else if (ArrayBuffer.isView(data)) {
      bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    } else {
      this.onProtocol("string message on the channel");
      return;
    }
    this.counters.received(bytes.length);
    let frame: Uint8Array | null;
    try {
      frame = this.reassembler.accept(bytes);
    } catch (e) {
      this.counters.fail("protocol");
      this.onProtocol(e instanceof Error ? e.message : String(e));
      return;
    }
    if (frame !== null) {
      this.events.deliver(frame);
    }
  }

  send(frame: Uint8Array): void {
    if (this.events.closed || frame.length === 0 || frame.length > this.options.maxFrame) {
      return;
    }
    const chunks = chunk.split(frame, this.capacity, this.options.maxFrame);
    // Serialize sends so the backpressure wait of one frame precedes the next frame's chunks.
    this.sending = this.sending.then(() => this.sendChunks(chunks)).catch(() => undefined);
  }

  private async sendChunks(chunks: Uint8Array[]): Promise<void> {
    for (const c of chunks) {
      if (this.events.closed) {
        return;
      }
      await this.awaitWritable();
      try {
        this.dc.send(c);
        this.counters.sent(c.length);
      } catch {
        return; // a closing channel drops the chunk, as a lost socket would
      }
    }
  }

  private awaitWritable(): Promise<void> {
    if (this.dc.bufferedAmount <= this.options.pauseAbove) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.resumeWaiters = this.resumeWaiters.filter((w) => w !== onLow);
        this.counters.fail("blocked");
        this.close();
        reject(new Error(`webrtc send paused longer than ${this.options.sendBlockedMillis} ms`));
      }, this.options.sendBlockedMillis);
      const onLow = () => {
        clearTimeout(timer);
        resolve();
      };
      this.resumeWaiters.push(onLow);
    });
  }

  onFrame(receiver: (frame: Uint8Array) => void): void {
    this.events.onFrame(receiver);
  }

  onClose(listener: (reason: string) => void): void {
    this.events.onClose(listener);
  }

  close(): void {
    try {
      this.dc.close();
    } catch {
      // already closing
    }
    try {
      this.pc.close();
    } catch {
      // already closing
    }
    this.events.close("closed by this end");
  }
}

interface Session {
  readonly sid: Uint8Array;
  readonly key: string;
  readonly target: string;
  readonly offerer: boolean;
  pc: RtcPeerConnection;
  dc: RtcDataChannel;
  remoteDescribed: boolean;
  candidatesReceived: number;
  queuedCandidates: { cand: string; mid: string }[];
  timer: ReturnType<typeof setTimeout> | null;
  resolve: (channel: FrameChannel) => void;
  reject: (error: Error) => void;
  settled: boolean;
}

/**
 * The binding on one {@link Peer}: {@link #connect} dials a member by signalling, and inbound
 * offers open channels handed to {@code onAccept}. One instance per peer.
 */
export class WebRtcBinding {
  readonly counters = new WebRtcCounters();
  private readonly options: Required<WebRtcOptions>;
  private readonly sessions = new Map<string, Session>();
  private readonly offerTimes = new Map<string, number[]>();
  /** Per member, when the last offload dial started: the backoff of JS-W-11. */
  private readonly offloadAttempted = new Map<string, number>();
  private onAccept: (channel: FrameChannel) => void;

  private constructor(private readonly peer: Peer, private readonly rtc: RtcApi,
                      options: WebRtcOptions, onAccept?: (channel: FrameChannel) => void) {
    this.options = { iceServers: options.iceServers ?? [], ...DEFAULTS, ...stripUndefined(options) };
    this.onAccept = onAccept ?? ((channel) => this.peer.acceptChannel(channel));
  }

  /**
   * Installs the binding on a peer: resolves the WebRTC implementation (JS-W-02), registers the
   * rtc-signal capability handler, and registers a `webrtc` dialer so the core's package map is
   * satisfied. Rejects naming the package when no implementation exists.
   */
  static async install(peer: Peer, options: WebRtcOptions = {},
                       onAccept?: (channel: FrameChannel) => void): Promise<WebRtcBinding> {
    const rtc = await loadRtc();
    const binding = new WebRtcBinding(peer, rtc, options, onAccept);
    peer.pipeHandlers.set(sig.CAPABILITY, (from, payload) => binding.onSignal(from, payload));
    // JS-W-02: a `webrtc` dialer so the core's package map is satisfied; the seed's host carries the
    // target PeerID, since a webrtc endpoint names the member to signal, not an address to dial.
    peer.registerDialer(binding.dialer());
    // JS-W-11: the core counts the frames a relay carries for each pair and tells; this binding
    // decides, from the count alone, whether to open the direct channel (`offload`).
    if (typeof peer.onRelayed === "function") {
      peer.onRelayed((member, frames) => binding.offload(member, frames));
    }
    // JS-W-08: a peer with a webrtc acceptor advertises Endpoint("webrtc", "sig", p), p after every
    // stream endpoint, so a member that can signal knows this one accepts; a dialer without the
    // binding skips the scheme. The advertisement is re-introduced when the peer is already in.
    if (!peer.endpoints.some((e) => e["transport"] === "webrtc")) {
      peer.endpoints.push({ transport: "webrtc", address: "sig", priority: peer.endpoints.length });
      if (peer.connected()) {
        peer.introduce();
      }
    }
    return binding;
  }

  /**
   * The relay offload (SRAD srad/agentspaces-js.md JS-W-11): once more than
   * `offloadFramesPerMinute` frames crossed a relay to or from a member in a sliding minute, and
   * the member advertises a `webrtc` endpoint, is not reachable here, has no signalling in
   * progress, and no failed dial inside `offloadRetryMillis`, dial it and hand the open channel to
   * the peer as a link, so the next frames go direct and the relay carries none. A failed dial
   * leaves the relay path as it was and starts the backoff. The dial is deferred off the frame
   * that tripped it, so a send never nests a dial.
   */
  offload(member: string, framesInLastMinute: number): void {
    if (framesInLastMinute <= this.options.offloadFramesPerMinute || member === this.peer.identity.peerId) {
      return;
    }
    if (this.peer.reachable.has(member)) {
      return;
    }
    const endpoints = (this.peer.members.get(member)?.["endpoints"] ?? []) as { [key: string]: unknown }[];
    if (!Array.isArray(endpoints) || !endpoints.some((e) => e?.["transport"] === "webrtc")) {
      return;
    }
    for (const s of this.sessions.values()) {
      if (s.target === member && !s.settled) {
        return;
      }
    }
    const now = Date.now();
    const attempted = this.offloadAttempted.get(member);
    if (attempted !== undefined && now - attempted < this.options.offloadRetryMillis) {
      return;
    }
    this.offloadAttempted.set(member, now);
    this.counters.offloadAttempts += 1;
    queueMicrotask(() => {
      this.connect(member).then((channel) => {
        this.counters.offloadOpened += 1;
        this.offloadAttempted.delete(member);
        this.peer.acceptChannel(channel);
      }, () => {
        this.counters.offloadFailed += 1;
      });
    });
  }

  /** A {@link Dialer} over {@link #connect}; the seed's host is the target member's PeerID. */
  dialer(): Dialer {
    return {
      scheme: "webrtc",
      dial: (seed: Seed) => this.connect(seed.host),
    };
  }

  /** Sets who receives an inbound channel; the default hands it to {@code peer.acceptChannel}. */
  accept(onAccept: (channel: FrameChannel) => void): void {
    this.onAccept = onAccept;
  }

  /** Dials a member by signalling; resolves with the open channel or rejects within the dial timeout. */
  connect(target: string): Promise<FrameChannel> {
    for (const s of this.sessions.values()) {
      if (s.target === target && !s.settled) {
        return Promise.reject(new Error(`webrtc signalling with ${target} already in progress`));
      }
    }
    const sid = randomSid();
    return new Promise<FrameChannel>((resolve, reject) => {
      const session = this.newSession(sid, target, true, resolve, reject);
      this.sessions.set(session.key, session);
      this.counters.sessionsOffered += 1;
      this.startOffer(session).catch((e) => this.finish(session, sig.END_FAILED,
        e instanceof Error ? e.message : String(e), true));
    });
  }

  private newSession(sid: Uint8Array, target: string, offerer: boolean,
                     resolve: (c: FrameChannel) => void, reject: (e: Error) => void): Session {
    const session: Session = {
      sid, key: sig.sessionKey(sid), target, offerer,
      pc: undefined as unknown as RtcPeerConnection, dc: undefined as unknown as RtcDataChannel,
      remoteDescribed: false, candidatesReceived: 0, queuedCandidates: [], timer: null,
      resolve, reject, settled: false,
    };
    session.timer = setTimeout(() => this.finish(session, sig.END_TIMEOUT,
      `no channel within ${this.options.dialTimeoutMillis} ms`, true), this.options.dialTimeoutMillis);
    return session;
  }

  private async newPeerConnection(session: Session): Promise<void> {
    // JS-W-04: an ECDSA P-256 certificate per connection. A browser mints one explicitly; the Node
    // polyfill has no generateCertificate and libdatachannel mints its own ECDSA cert, whose
    // fingerprint is already in the SDP, so fall back to the engine's default when minting is absent.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const config: any = { iceServers: this.options.iceServers };
    try {
      config.certificates = [await this.rtc.generateCertificate({ name: "ECDSA", namedCurve: "P-256" })];
    } catch {
      // the engine presents its own per-connection certificate; its fingerprint is in the SDP
    }
    const pc = new this.rtc.PeerConnection(config);
    session.pc = pc;
    pc.onicecandidate = (ev) => {
      if (session.settled) {
        return;
      }
      if (ev.candidate && ev.candidate.candidate) {
        this.send(session.target, sig.candidate(session.sid, ev.candidate.candidate, ev.candidate.sdpMid ?? ""));
      } else {
        this.send(session.target, sig.candidate(session.sid, "", ""));
      }
    };
    pc.oniceconnectionstatechange = () => {
      if (pc.iceConnectionState === "failed") {
        this.finish(session, sig.END_FAILED, "ice failed", true);
      }
    };
    session.dc = pc.createDataChannel(LABEL, { negotiated: true, id: CHANNEL_ID, ordered: true });
  }

  private async startOffer(session: Session): Promise<void> {
    await this.newPeerConnection(session);
    const offer = await session.pc.createOffer();
    await session.pc.setLocalDescription(offer);
    const sdp = session.pc.localDescription?.sdp ?? offer.sdp;
    this.bindOpen(session, sdp);
    this.send(session.target, sig.offer(session.sid, sdp, fp.fingerprintsOf(sdp)));
  }

  private async startAnswer(session: Session, offer: sig.RtcSignal): Promise<void> {
    if (!fp.matches(offer.sdp!, offer.fp!)) {
      this.counters.fail("fingerprint");
      this.finish(session, sig.END_REFUSED, "offer fingerprints differ from the signed fp", true);
      return;
    }
    await this.newPeerConnection(session);
    await session.pc.setRemoteDescription({ type: "offer", sdp: offer.sdp! });
    session.remoteDescribed = true;
    this.flushCandidates(session);
    const answer = await session.pc.createAnswer();
    await session.pc.setLocalDescription(answer);
    const sdp = session.pc.localDescription?.sdp ?? answer.sdp;
    this.bindOpen(session, sdp);
    this.counters.sessionsAnswered += 1;
    this.send(session.target, sig.answer(session.sid, sdp, fp.fingerprintsOf(sdp)));
  }

  private bindOpen(session: Session, localSdp: string): void {
    session.dc.onopen = () => {
      if (session.settled) {
        return;
      }
      session.settled = true;
      if (session.timer) {
        clearTimeout(session.timer);
      }
      const remoteMax = maxMessageSize(session.pc.remoteDescription?.sdp);
      const channel = new WebRtcChannel(session.dc, session.pc, session.target, this.options,
        this.counters, remoteMax, (reason) => this.finish(session, sig.END_PROTOCOL, reason, true));
      this.counters.opened(selectedCandidateType(session.pc) ?? "unknown");
      this.sessions.delete(session.key);
      if (session.offerer) {
        session.resolve(channel);
      } else {
        this.onAccept(channel);
      }
    };
  }

  private onSignal(from: string, payload: Uint8Array): void {
    if (!payload || payload.length > this.options.maxSignalBytes) {
      this.counters.drop("size");
      return;
    }
    const signal = sig.decode(payload);
    if (signal === null || sig.malformed(signal) !== null) {
      this.counters.drop("malformed");
      return;
    }
    if (signal.kind === "OFFER") {
      this.onOffer(from, signal);
      return;
    }
    const session = this.sessions.get(sig.sessionKey(signal.sid));
    if (session === undefined) {
      this.counters.drop("unknown-session");
      return;
    }
    if (session.target !== from) {
      this.counters.drop("wrong-origin");
      return;
    }
    if (signal.kind === "ANSWER") {
      this.onAnswer(session, signal);
    } else if (signal.kind === "CAND") {
      this.onCandidate(session, signal);
    } else if (signal.kind === "END") {
      this.finish(session, signal.code ?? sig.END_NORMAL, `remote END(${signal.code})`, false);
    }
  }

  private onOffer(from: string, offer: sig.RtcSignal): void {
    if (!this.admitOffer(from)) {
      this.counters.drop("rate");
      return;
    }
    if (this.sessions.has(sig.sessionKey(offer.sid))) {
      this.counters.drop("duplicate");
      return;
    }
    // Appendix B tie rule: when both offer at once, the lower PeerID keeps its offer.
    for (const pending of this.sessions.values()) {
      if (pending.offerer && pending.target === from && !pending.settled) {
        if (this.peer.identity.peerId < from) {
          this.counters.drop("tie");
          this.send(from, sig.end(offer.sid, sig.END_REFUSED));
          return;
        }
        this.finish(pending, sig.END_NORMAL, "tie: answering the lower PeerID instead", true);
      }
    }
    const session = this.newSession(offer.sid, from, false, () => undefined, () => undefined);
    this.sessions.set(session.key, session);
    this.startAnswer(session, offer).catch((e) => this.finish(session, sig.END_FAILED,
      e instanceof Error ? e.message : String(e), true));
  }

  private onAnswer(session: Session, answer: sig.RtcSignal): void {
    if (session.remoteDescribed || !session.offerer) {
      return;
    }
    if (!fp.matches(answer.sdp!, answer.fp!)) {
      this.counters.fail("fingerprint");
      this.finish(session, sig.END_REFUSED, "answer fingerprints differ from the signed fp", true);
      return;
    }
    session.pc.setRemoteDescription({ type: "answer", sdp: answer.sdp! })
      .then(() => {
        session.remoteDescribed = true;
        this.flushCandidates(session);
      })
      .catch((e) => this.finish(session, sig.END_FAILED, String(e), true));
  }

  private onCandidate(session: Session, signal: sig.RtcSignal): void {
    if (++session.candidatesReceived > this.options.candidatesPerSession) {
      this.counters.drop("candidates");
      return;
    }
    if ((signal.cand ?? "") === "") {
      return;
    }
    if (!session.remoteDescribed) {
      session.queuedCandidates.push({ cand: signal.cand!, mid: signal.mid ?? "" });
      return;
    }
    session.pc.addIceCandidate({ candidate: signal.cand!, sdpMid: signal.mid ?? null }).catch(() => undefined);
  }

  private flushCandidates(session: Session): void {
    for (const c of session.queuedCandidates.splice(0)) {
      session.pc.addIceCandidate({ candidate: c.cand, sdpMid: c.mid || null }).catch(() => undefined);
    }
  }

  private admitOffer(from: string): boolean {
    const now = Date.now();
    const times = (this.offerTimes.get(from) ?? []).filter((t) => now - t < 60_000);
    if (times.length >= this.options.offersPerPeerPerMinute) {
      this.offerTimes.set(from, times);
      return false;
    }
    times.push(now);
    this.offerTimes.set(from, times);
    return true;
  }

  private send(to: string, signal: sig.RtcSignal): void {
    if (!this.peer.sendPipeOrRelay(to, sig.CAPABILITY, sig.encode(signal))) {
      this.counters.drop("no-route");
    }
  }

  private finish(session: Session, code: number, reason: string, signal: boolean): void {
    if (session.settled && this.sessions.get(session.key) !== session) {
      // already resolved with a channel; its close path takes over
    }
    this.sessions.delete(session.key);
    if (session.timer) {
      clearTimeout(session.timer);
    }
    if (!session.settled) {
      session.settled = true;
      if (!session.offerer && code !== sig.END_NORMAL) {
        this.counters.fail(code === sig.END_TIMEOUT ? "timeout" : code === sig.END_REFUSED ? "refused" : "failed");
      } else if (session.offerer) {
        this.counters.fail(code === sig.END_TIMEOUT ? "timeout" : code === sig.END_REFUSED ? "refused"
          : code === sig.END_PROTOCOL ? "protocol" : code === sig.END_NORMAL ? "closed" : "failed");
      }
      session.reject(new Error(`webrtc to ${session.target}: ${reason}`));
    }
    if (signal) {
      this.send(session.target, sig.end(session.sid, code));
    }
    try {
      session.pc?.close();
    } catch {
      // already closing
    }
  }

  /** Sessions pending, for tests. */
  pendingSessions(): number {
    return this.sessions.size;
  }

  /** Ends every pending session; open channels close on their own. */
  close(): void {
    for (const session of [...this.sessions.values()]) {
      this.finish(session, sig.END_NORMAL, "binding closed", true);
    }
  }
}

function stripUndefined<T extends object>(value: T): Partial<T> {
  const out: Partial<T> = {};
  for (const [k, v] of Object.entries(value)) {
    if (v !== undefined) {
      (out as Record<string, unknown>)[k] = v;
    }
  }
  return out;
}

function randomSid(): Uint8Array {
  const sid = new Uint8Array(sig.SID_LENGTH);
  globalThis.crypto.getRandomValues(sid); // Node 22 and every browser expose a global WebCrypto
  return sid;
}

function maxMessageSize(sdp: string | undefined): number {
  if (!sdp) {
    return 65536;
  }
  const m = /a=max-message-size:(\d+)/.exec(sdp);
  return m ? Number(m[1]) : 65536;
}

function selectedCandidateType(pc: RtcPeerConnection): string | null {
  const local = (pc as unknown as { sctp?: { transport?: { iceTransport?: {
    getSelectedCandidatePair?(): { local?: { type?: string } } | null } } } });
  try {
    const pair = local.sctp?.transport?.iceTransport?.getSelectedCandidatePair?.();
    return pair?.local?.type ?? null;
  } catch {
    return null;
  }
}
