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
 * The DTLS certificate fingerprints of a session description (RFC 8122 `a=fingerprint` lines), in
 * the form the signed `fp` list carries: `"sha-256 " + uppercase colon-separated hex` (SRAD
 * srad/agentspaces-js.md JS-W-04, appendix B). The twin of the Java `Fingerprints` class. A remote
 * SDP whose fingerprint lines differ from the remote's signed `fp` is refused; DTLS then refuses a
 * certificate whose fingerprint differs from the SDP.
 */

const LINE = /^a=fingerprint:\s*([A-Za-z0-9-]+)\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+)\s*$/;
const ENTRY = /^([A-Za-z0-9-]+)\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+)$/;

/** The fingerprints an SDP presents, normalized, in order of appearance without duplicates. */
export function fingerprintsOf(sdp: string): string[] {
  const out: string[] = [];
  for (const raw of sdp.split(/\r?\n/)) {
    const m = LINE.exec(raw.trim());
    if (m) {
      const entry = `${m[1]!.toLowerCase()} ${m[2]!.toUpperCase()}`;
      if (!out.includes(entry)) {
        out.push(entry);
      }
    }
  }
  return out;
}

/** The normalized form of one `fp` entry, or null when it is not one. */
export function normalize(entry: string | null | undefined): string | null {
  if (entry == null) {
    return null;
  }
  const m = ENTRY.exec(entry.trim());
  return m ? `${m[1]!.toLowerCase()} ${m[2]!.toUpperCase()}` : null;
}

/** Whether the SDP's fingerprint lines are exactly the signed `fp` list, as sets. */
export function matches(sdp: string, fp: string[]): boolean {
  const signed = new Set<string>();
  for (const entry of fp) {
    const n = normalize(entry);
    if (n === null) {
      return false;
    }
    signed.add(n);
  }
  const presented = new Set(fingerprintsOf(sdp));
  if (presented.size === 0 || presented.size !== signed.size) {
    return false;
  }
  for (const entry of presented) {
    if (!signed.has(entry)) {
      return false;
    }
  }
  return true;
}
