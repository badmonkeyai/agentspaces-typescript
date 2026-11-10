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
 * A requester's view of the group's content stores (PDT 2 phase 7, P2-C-01; srad/agentspaces-pdt2.md §3.2), a port of
 * Java's `Stores` and `StoreChooser`: it reads the `content-store` AssetCards the `ads` stream carried, whose `access`
 * and `costHints` hold text values (§6.10.3 rule 19), chooses stores for a root by price, free space, blind holding,
 * and tier, and writes one `SignedPin` entry that names them under `pdt.stores`, signed by this member as the pin's
 * requester (§10.9, F1): a store takes only a `SignedPin`, and no client writes a bare `StorePin`. The entry lapses
 * when its signature does, at most {@link PIN_ENTRY_LEASE_MILLIS} after it is written, inside the deadline a store
 * accepts (§10.11).
 */

import type { Identity } from "../identity.js";
import { spaceIdLocal } from "../identity.js";
import type { Dict } from "../wire.js";
import * as cids from "./cids.js";
import { KIND_SN, kindOf } from "./nodes.js";
import { KIND_ARTIFACT, KIND_TREE, SIGNED_PIN_TYPE, STORE_RECEIPT_TYPE, decodeStoreReceipt, signPin, signedPinTags, storePin,
  storeReceiptViolation } from "./store-records.js";
import type { TreeExchange } from "./tree.js";

/** The `access.kind` of a content store's card. */
export const KIND = "content-store";
/** The `costHints` key a store's owner sets to a price per GiB-month. */
export const PRICE_HINT = "pricePerGibMonth";
/** The pin attribute that names the stores a requester chose, comma separated. */
export const STORES_ATTR = "pdt.stores";
/** The `access` key a store whose policy is `grant` sets while it waits for an authorizer (§10.9, F2). */
export const WAITING_ACCESS = "waiting";
/** The longest a pin entry waits for a taker, and so the furthest deadline a requester signs (§10.11). */
export const PIN_ENTRY_LEASE_MILLIS = 60 * 60 * 1000;

/** A content store's card as a requester reads it, every text value of §3.2.1 parsed. */
export interface StoreCard {
  readonly issuer: string;
  readonly asset: string;
  readonly expiresAt: number;
  readonly capacity: number;
  readonly free: number;
  readonly maxObject: number;
  readonly codecs: string[];
  readonly hashes: string[];
  readonly blind: boolean;
  readonly sealing: string[];
  readonly leaseMax: number;
  readonly leaseDefault: number;
  readonly copiesMax: number;
  readonly pin: string[];
  readonly challenge: boolean;
  readonly tier: string | null;
  readonly delegates: string[];
  readonly policy: string | null;
  readonly waiting: boolean;
  /** The price per GiB-month, 0 when the owner set none. */
  readonly price: number;
}

const CANONICAL_DECIMAL = /^(?:0|[1-9][0-9]{0,18})$/;
const decimal = (text: unknown): number | null => (typeof text === "string" && CANONICAL_DECIMAL.test(text) ? Number(text) : null);
const list = (text: unknown): string[] => (typeof text === "string" && text.length > 0 ? text.split(",") : []);
const flag = (text: unknown): boolean | null => (text === "true" ? true : text === "false" ? false : null);

/**
 * A content store's card read from an AssetCard as the `ads` stream holds it (§3.2.1, rule 19): null for a card of
 * another kind, or one whose free space, largest object, price, or blind flag is not text in its one form.
 */
export function readStoreCard(card: Dict): StoreCard | null {
  const access = (card["access"] ?? {}) as Dict;
  const costHints = (card["costHints"] ?? {}) as Dict;
  if (access["kind"] !== KIND) {
    return null;
  }
  const free = decimal(access["free"]), maxObject = decimal(access["maxObject"]), blind = flag(access["blind"]);
  const price = costHints[PRICE_HINT] === undefined ? 0 : decimal(costHints[PRICE_HINT]);
  if (free === null || maxObject === null || blind === null || price === null) {
    return null;
  }
  const issued = Date.parse(String(card["issued"]));
  const ttl = /^PT(\d+)([SMH])$/.exec(String(card["ttl"]));
  const ttlMillis = ttl === null ? 0 : Number(ttl[1]) * { S: 1000, M: 60_000, H: 3_600_000 }[ttl[2] as "S" | "M" | "H"];
  return { issuer: String(card["issuer"]), asset: String(card["asset"]), expiresAt: issued + ttlMillis,
    capacity: decimal(access["capacity"]) ?? 0, free, maxObject, codecs: list(access["codecs"]), hashes: list(access["hashes"]),
    blind, sealing: list(access["sealing"]), leaseMax: decimal(access["leaseMax"]) ?? 0,
    leaseDefault: decimal(access["leaseDefault"]) ?? 0, copiesMax: decimal(access["copiesMax"]) ?? 1, pin: list(access["pin"]),
    challenge: flag(access["challenge"]) === true, tier: typeof access["tier"] === "string" ? access["tier"] : null,
    delegates: list(access["delegates"]), policy: typeof access["policy"] === "string" ? access["policy"] : null,
    waiting: Object.hasOwn(access, WAITING_ACCESS), price };
}

/** What a root needs from its stores (Java's StoreChooser.Need). */
export interface Need {
  bytes: number;
  copies: number;
  /** Whether the content is sealed, so a blind store may hold it. */
  sealed?: boolean;
  tier?: string | null;
  maxPrice?: number | null;
  avoid?: ReadonlySet<string>;
}

/**
 * The stores to ask, best first (Java's StoreChooser.choose): live cards of stores that fit the bytes, hold the content
 * blind only when it is sealed, match the tier and the price, and wait for no authorizer, cheapest first, then the most
 * free space, then the issuer; at most `need.copies`, one per store.
 */
export function chooseStores(cards: Iterable<StoreCard>, need: Need, now: number): StoreCard[] {
  const fit = [...cards].filter((c) => c.expiresAt > now && !c.waiting && !(need.avoid?.has(c.issuer) ?? false)
    && c.free >= need.bytes && c.maxObject >= need.bytes && !(c.blind && !need.sealed)
    && (need.tier == null || need.tier === c.tier) && (need.maxPrice == null || c.price <= need.maxPrice));
  fit.sort((a, b) => a.price - b.price || b.free - a.free || (a.issuer < b.issuer ? -1 : a.issuer > b.issuer ? 1 : 0));
  const chosen = new Map<string, StoreCard>();
  for (const card of fit) {
    if (chosen.size === need.copies) {
      break;
    }
    if (!chosen.has(card.issuer)) {
      chosen.set(card.issuer, card);
    }
  }
  return [...chosen.values()];
}

/** The pin written and the stores it names. */
export interface Pinning { readonly signed: Dict; readonly entryId: string; readonly stores: StoreCard[] }

/** A requester's view of the stores over one tree exchange, signing as `identity`, which must be the peer's own. */
export class Stores {
  constructor(private readonly exchange: TreeExchange, private readonly identity: Identity) {
    if (identity.peerId !== exchange.selfId) {
      throw new Error("a pin's requester is this peer, so the stores sign with its own identity");
    }
  }

  /** The live content-store cards the `ads` stream carried. */
  cards(): StoreCard[] {
    const now = this.exchange.peer.now();
    const out: StoreCard[] = [];
    for (const cached of this.exchange.peer.ads.values()) {
      if (cached.type !== "AssetCard" || cached.expires <= now) {
        continue;
      }
      const card = readStoreCard(cached.ad);
      if (card !== null) {
        out.push(card);
      }
    }
    return out;
  }

  /**
   * Chooses stores for a root and writes the pin (P2-S-11, P2-C-01): a tree this peer holds complete, which it then holds
   * so the stores can fetch it, or an artifact whose manifest it knows. Stores whose live receipts name the root come
   * first and need no room, so writing the same root again renews its lease (P2-S-04). Throws when no store fits.
   */
  storeFor(root: string, need: Omit<Need, "bytes" | "sealed">, leaseSeconds: number): Pinning {
    const tree = cids.parse(root).codec === cids.DAG_CBOR;
    let bytes = 0;
    let sealed: boolean;
    const store = this.exchange.store;
    if (tree) {
      if (!store.complete(root)) {
        throw new Error(`tree root ${root} is not complete in this peer's store`);
      }
      for (const cid of store.reachable(root)) {
        bytes += store.get(cid)?.length ?? 0;
      }
      sealed = kindOf(store.get(root)!, root) === KIND_SN;
      this.exchange.holdTree(root);
    } else {
      const manifest = this.exchange.content.manifestOf(root);
      if (manifest === null) {
        throw new Error(`no manifest for artifact root ${root}`);
      }
      bytes = Number(manifest["size"]);
      sealed = manifest["hashing"] === "sealed";
    }
    const now = this.exchange.peer.now();
    const holders = new Set(this.receipts(root).map((r) => String(r["holder"])));
    const cards = this.cards();
    const chosen = chooseStores(cards.filter((c) => holders.has(c.issuer)), { ...need, bytes: 0, sealed }, now);
    if (chosen.length < need.copies) {
      const avoid = new Set([...(need.avoid ?? []), ...chosen.map((c) => c.issuer)]);
      chosen.push(...chooseStores(cards, { ...need, copies: need.copies - chosen.length, bytes, sealed, avoid }, now));
    }
    if (chosen.length === 0) {
      throw new Error(`no content store fits ${bytes} bytes of ${root}`);
    }
    const lease = Math.max(1, Math.floor(leaseSeconds));
    const terms = storePin({ root, kind: tree ? KIND_TREE : KIND_ARTIFACT, lease, copies: chosen.length, requester: this.identity.peerId,
      attrs: { [STORES_ATTR]: chosen.map((c) => c.issuer).join(",") } });
    const entryLease = Math.min(lease * 1000, PIN_ENTRY_LEASE_MILLIS);
    const signed = signPin(terms, this.exchange.peer.group, now + entryLease, this.identity);
    const space = this.exchange.content.space;
    const entryId = this.exchange.peer.writeEntry(space.name, SIGNED_PIN_TYPE, signed, space.agentName, entryLease, space.agent,
      signedPinTags(signed));
    return { signed, entryId, stores: chosen };
  }

  /** The live receipts for a root, one per store, each signed by the holder it names (Java's Stores.claims). */
  receipts(root: string): Dict[] {
    const peer = this.exchange.peer;
    const spaceId = spaceIdLocal(`${peer.group}/${this.exchange.content.space.name}`);
    const now = peer.now();
    const byHolder = new Map<string, Dict>();
    for (const dto of peer.states.values()) {
      const record = dto["record"] as Dict | null | undefined;
      if (record == null || record["spaceId"] !== spaceId || record["type"] !== STORE_RECEIPT_TYPE
          || ((record["tags"] ?? {}) as Dict)["root"] !== root) {
        continue;
      }
      const payload = peer.payloadOf(dto);
      let receipt: Dict;
      try {
        receipt = decodeStoreReceipt(payload!);
      } catch {
        continue;
      }
      const holder = String(receipt["holder"]);
      if (storeReceiptViolation(receipt) !== null || receipt["root"] !== root || Number(receipt["until"]) <= now
          || String(record["issuer"]).split("/")[0] !== holder) {
        continue;
      }
      const kept = byHolder.get(holder);
      if (kept === undefined || Number(receipt["until"]) > Number(kept["until"])) {
        byHolder.set(holder, receipt);
      }
    }
    return [...byHolder.values()];
  }
}
