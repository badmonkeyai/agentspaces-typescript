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
 * The signalling bodies of SRAD srad/agentspaces-js.md §3.5 and appendix B (JS-W-03, JS-F-02): the
 * payload of a `PIPE_DATA` frame of capability {@link CAPABILITY}, a CBOR map in the canonical order
 * of wire version 3. Encoded through the core codec so the bytes match the Java `RtcSignal` record
 * exactly (indefinite map, component order `v, fp, mid, sdp, sid, cand, code, kind`, absent keys
 * omitted). A receiver reads the body as Java's `fromWire` reads the record (HLC round seven,
 * 2026-11-08; SPEC annex I): an unknown key, a field of the wrong type, a field out of order, or bytes
 * other than the record's own encoding make the body undecodable, so a later field needs a new version.
 */

import { cbor, records } from "@agentspaces/client";
import { normalize } from "./fingerprints.js";

export const CAPABILITY = "aspace:cap/rtc-signal";
export const VERSION = 1;
export const SID_LENGTH = 16;
export const MAX_SDP = 16 * 1024;
export const MAX_CAND = 1024;
export const MAX_FINGERPRINTS = 4;
export const END_NORMAL = 0;
export const END_REFUSED = 1;
export const END_TIMEOUT = 2;
export const END_PROTOCOL = 3;
export const END_FAILED = 4;

export type SignalKind = "OFFER" | "ANSWER" | "CAND" | "END";

export interface RtcSignal {
  v: number;
  sid: Uint8Array;
  kind: SignalKind;
  fp?: string[];
  mid?: string;
  sdp?: string;
  cand?: string;
  code?: number;
}

export function offer(sid: Uint8Array, sdp: string, fp: string[]): RtcSignal {
  return { v: VERSION, sid, kind: "OFFER", sdp, fp };
}

export function answer(sid: Uint8Array, sdp: string, fp: string[]): RtcSignal {
  return { v: VERSION, sid, kind: "ANSWER", sdp, fp };
}

export function candidate(sid: Uint8Array, cand: string, mid: string): RtcSignal {
  return { v: VERSION, sid, kind: "CAND", cand, mid };
}

export function end(sid: Uint8Array, code: number): RtcSignal {
  return { v: VERSION, sid, kind: "END", code };
}

/**
 * Encodes a signal into its canonical CBOR body. The keys are inserted in the Java record's
 * component order (`v, fp, mid, sdp, sid, cand, code, kind`), absent ones omitted, so the core
 * codec's insertion-order map encoding yields the same bytes as the Java codec.
 */
export function encode(signal: RtcSignal): Uint8Array {
  const body: { [key: string]: cbor.CborValue } = { v: signal.v };
  if (signal.fp !== undefined) {
    body["fp"] = signal.fp;
  }
  if (signal.mid !== undefined) {
    body["mid"] = signal.mid;
  }
  if (signal.sdp !== undefined) {
    body["sdp"] = signal.sdp;
  }
  body["sid"] = signal.sid;
  if (signal.cand !== undefined) {
    body["cand"] = signal.cand;
  }
  if (signal.code !== undefined) {
    body["code"] = signal.code;
  }
  body["kind"] = signal.kind;
  return cbor.dumps(body);
}

/**
 * Decodes a signal body under the RtcSignal record (HLC round seven, 2026-11-08), or returns null when
 * the body is undecodable: no RtcSignal in the wire encoding, or one whose `sid` or `kind` is null,
 * which Java's malformed check refuses with the same count.
 */
export function decode(bytes: Uint8Array): RtcSignal | null {
  const m = records.readRecord(bytes, records.RTC_SIGNAL);
  if (m === null || !(m["sid"] instanceof Uint8Array) || typeof m["kind"] !== "string") {
    return null;
  }
  const signal: RtcSignal = { v: m["v"] as number, sid: m["sid"], kind: m["kind"] as SignalKind };
  if (m["fp"] !== undefined) {
    signal.fp = m["fp"] as string[];
  }
  if (m["mid"] !== undefined) {
    signal.mid = m["mid"] as string;
  }
  if (m["sdp"] !== undefined) {
    signal.sdp = m["sdp"] as string;
  }
  if (m["cand"] !== undefined) {
    signal.cand = m["cand"] as string;
  }
  if (m["code"] !== undefined) {
    signal.code = m["code"] as number;
  }
  return signal;
}

/** Why this signal is not well-formed per appendix B, or null when it is. */
export function malformed(signal: RtcSignal): string | null {
  if (signal.v !== VERSION) {
    return `v ${signal.v}`;
  }
  if (!(signal.sid instanceof Uint8Array) || signal.sid.length !== SID_LENGTH) {
    return "sid";
  }
  switch (signal.kind) {
    case "OFFER":
    case "ANSWER":
      if (signal.sdp === undefined || signal.sdp.length === 0 || signal.sdp.length > MAX_SDP) {
        return "sdp";
      }
      if (signal.fp === undefined || signal.fp.length === 0 || signal.fp.length > MAX_FINGERPRINTS
          || signal.fp.some((f) => normalize(f) === null)) {
        return "fp";
      }
      return null;
    case "CAND":
      if (signal.cand === undefined || signal.cand.length > MAX_CAND || signal.mid === undefined) {
        return "cand";
      }
      return null;
    case "END":
      if (signal.code === undefined || signal.code < 0) {
        return "code";
      }
      return null;
    default:
      return `kind ${signal.kind}`;
  }
}

/** The session id as lowercase hex, the key of a pending session. */
export function sessionKey(sid: Uint8Array): string {
  return Array.from(sid, (b) => b.toString(16).padStart(2, "0")).join("");
}
