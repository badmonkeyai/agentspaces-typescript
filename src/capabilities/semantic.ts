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
 * Semantic discovery (SPEC §8, SemanticDiscovery) from TypeScript: the
 * hashing embedder the Java default uses (Java's `String.hashCode` over the
 * same tokens, so the vectors agree), local ranking of the cached
 * advertisements, and the query pipe to other members.
 */

import { dumps, loads } from "../cbor.js";
import type { Dict } from "../wire.js";
import type { Pipes } from "./pipes.js";

export const TYPE = "aspace:cap/semantic-discovery";
export const MIN_SCORE = 0.2;
const TOKENS = /[^\p{L}\p{N}#/.-]+/u;

/** Java's String.hashCode: UTF-16 code units, 31-multiplicative, int32. */
export function javaHash(text: string): number {
  let h = 0;
  for (let i = 0; i < text.length; i++) {
    h = (Math.imul(31, h) + text.charCodeAt(i)) | 0;
  }
  return h;
}

/** HashingEmbedder: a signed bag of hashed tokens, L2-normalized. */
export class HashingEmbedder {
  readonly identity = "hashing";

  constructor(readonly dimensions = 256) {
    if (dimensions <= 0) {
      throw new Error("dimensions must be positive");
    }
  }

  embed(text: string | null): number[] {
    const vector = new Array<number>(this.dimensions).fill(0);
    if (text === null) {
      return vector;
    }
    for (const token of text.toLowerCase().split(TOKENS)) {
      if (token === "") {
        continue;
      }
      const h = javaHash(token);
      const bucket = ((h % this.dimensions) + this.dimensions) % this.dimensions; // floorMod
      vector[bucket] += ((h >>> 31) & 1) === 0 ? 1 : -1;
    }
    const norm = Math.sqrt(vector.reduce((acc, v) => acc + v * v, 0));
    return norm > 0 ? vector.map((v) => v / norm) : vector;
  }
}

export function cosine(a: number[], b: number[]): number {
  if (a.length !== b.length) {
    return 0;
  }
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i]! * b[i]!;
    na += a[i]! * a[i]!;
    nb += b[i]! * b[i]!;
  }
  return na === 0 || nb === 0 ? 0 : dot / (Math.sqrt(na) * Math.sqrt(nb));
}

const str = (v: unknown): string => (v === undefined || v === null ? "" : String(v));
const join = (v: unknown): string => (Array.isArray(v) ? v.map(String).join(" ") : "");

/** SemanticDiscovery.textOf: what an advertisement is indexed by. */
export function textOf(adType: string, ad: Dict): string {
  if (adType === "AgentCard") {
    let text = `${str(ad["description"])} ${join(ad["goals"])} ${join(ad["consumes"])} ${join(ad["produces"])}`;
    for (const action of (ad["actions"] as Dict[] | undefined) ?? []) {
      text += ` ${str(action["name"])} ${str(action["description"])}`;
    }
    return text;
  }
  if (adType === "AssetCard") {
    return `${str(ad["description"])} ${str(ad["asset"])} ${str(ad["uri"])} ${str(ad["shape"])}`;
  }
  if (adType === "CapabilityAdvertisement") {
    return `${str(ad["capabilityType"])} ${str(ad["binding"])} ${JSON.stringify(ad["parameters"] ?? {})}`;
  }
  if (adType === "SpaceAdvertisement") {
    return `${str(ad["spaceName"])} ${join(ad["schemaHints"])}`;
  }
  return str(ad["id"]);
}

export type Match = { adType: string; ad: Dict; score: number };

/** Queries over the peer's advertisement cache, local and remote. */
export class Semantic {
  private nonce = 0;
  private readonly pending = new Map<number, () => void>();

  constructor(readonly pipes: Pipes, readonly embedder = new HashingEmbedder()) {
    pipes.onCapability(TYPE, (from, payload) => this.onFrame(from, payload));
  }

  /** Local-first ranking of the cached advertisements by cosine score. */
  query(text: string, limit = 10): Match[] {
    if (limit <= 0) {
      throw new Error("limit must be positive");
    }
    const q = this.embedder.embed(text);
    const now = this.pipes.peer.now();
    const matches: Match[] = [];
    for (const entry of this.pipes.peer.ads.values()) {
      if (entry.expires <= now) {
        continue;
      }
      const score = cosine(q, this.embedder.embed(textOf(entry.type, entry.ad)));
      if (score >= MIN_SCORE) {
        matches.push({ adType: entry.type, ad: entry.ad, score });
      }
    }
    return matches.sort((a, b) => b.score - a.score).slice(0, limit);
  }

  /** Asks up to three members for their best matches (SemQuery), folds the hits into the cache, then ranks locally. */
  async remoteQuery(text: string, limit = 10, timeoutMillis = 2_000): Promise<Match[]> {
    const targets = this.pipes.randomMembers(3);
    if (targets.length > 0) {
      const nonce = ++this.nonce;
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => { this.pending.delete(nonce); resolve(); }, timeoutMillis);
        this.pending.set(nonce, () => { clearTimeout(timer); this.pending.delete(nonce); resolve(); });
        const frame = dumps({ nonce, text, limit });
        for (const target of targets) {
          this.pipes.send(target, TYPE, frame);
        }
      });
    }
    return this.query(text, limit);
  }

  private onFrame(from: string, payload: Uint8Array): void {
    let frame: Dict;
    try {
      frame = loads(Buffer.from(payload)) as Dict;
    } catch {
      return;
    }
    if (typeof frame !== "object" || frame === null) {
      return;
    }
    if (typeof frame["text"] === "string") {
      this.answer(from, frame);
    } else if (Array.isArray(frame["hits"])) {
      for (const hit of frame["hits"] as Dict[]) {
        if (typeof hit === "object" && hit !== null && hit["adType"]) {
          this.pipes.peer.acceptAd(hit);
        }
      }
      this.pending.get(Number(frame["nonce"] ?? -1))?.();
    }
  }

  private answer(from: string, query: Dict): void {
    const q = this.embedder.embed(String(query["text"]));
    const now = this.pipes.peer.now();
    const scored: Array<{ score: number; stored: Dict }> = [];
    for (const entry of this.pipes.peer.ads.values()) {
      if (entry.expires <= now) {
        continue;
      }
      const score = cosine(q, this.embedder.embed(textOf(entry.type, entry.ad)));
      if (score >= MIN_SCORE) {
        scored.push({ score, stored: entry.stored });
      }
    }
    scored.sort((a, b) => b.score - a.score);
    const limit = Math.max(1, Math.min(Number(query["limit"] ?? 10), 16));
    const hits = scored.slice(0, limit).map(({ stored }) => ({ adType: stored["adType"], adBytes: stored["adBytes"],
      publicKey: stored["publicKey"], signature: stored["signature"] }));
    this.pipes.send(from, TYPE, dumps({ nonce: query["nonce"] ?? 0, hits }));
  }
}
