/**
 * The commerce records (SPEC §6.5a, §7.6; the open `agentspaces-commerce` module): a `Mandate` is an AP2 Checkout or
 * Payment Mandate carried as an entry of a group's `commerce` space, an `Order` the UCP order it led to. The builders
 * emit the Java field order, so a record built here encodes byte for byte as the Java one; `digest` is the base64url
 * SHA-256 the AP2 bindings use (`checkout_hash`, `transaction_id`).
 */
import { createHash } from "node:crypto";

export const CAPABILITY_COMMERCE = "aspace:cap/commerce";
export const SPACE_COMMERCE = "commerce";
export const ROLES = ["merchant", "shopper", "payment"] as const;
export const KINDS = ["checkout", "payment"] as const;
export const STATES = ["issued", "settled", "refused", "expired"] as const;
export const ORDER_STATUSES = ["incomplete", "requires_escalation", "ready_for_complete", "complete_in_progress", "completed", "canceled"] as const;
export const VCT_CHECKOUT = "mandate.checkout.1";
export const VCT_CHECKOUT_OPEN = "mandate.checkout.open.1";
export const VCT_PAYMENT = "mandate.payment.1";
export const VCT_PAYMENT_OPEN = "mandate.payment.open.1";

export interface Item { sku: string; title: string; quantity: number; unitPrice: number }
export interface Cart { items: Item[]; total: number; currency: string }
export interface Basis { approval: string; decision: string }
export interface Mandate { schemaVersion: number; id: string; kind: string; role: string; cart: Cart; counterparty: string; basis: Basis; credential: Record<string, unknown>; state: string; at: unknown }
export interface Order { schemaVersion: number; id: string; mandate: string; status: string; fulfillment: Record<string, unknown>; permalink: string; at: unknown }

/** One cart item: the UCP item id, the title, the quantity, the unit price in minor units. */
export function item(sku: string, title: string, quantity: number, unitPrice: number): Item {
  if (quantity < 1) throw new Error("an item's quantity is at least one");
  return { sku, title: title ?? "", quantity, unitPrice };
}

export function cart(items: Item[], total: number, currency: string): Cart {
  if (items.length > 64) throw new Error("a cart carries at most 64 items");
  if (currency.length !== 3) throw new Error("the currency is an ISO 4217 code: " + currency);
  return { items: [...items], total, currency };
}

export const basis = (approval = "", decision = ""): Basis => ({ approval: approval ?? "", decision: decision ?? "" });

export function mandate(id: string, kind: string, role: string, c: Cart, counterparty: string, b: Basis, credential: Record<string, unknown>, state: string, at: unknown): Mandate {
  if (!(KINDS as readonly string[]).includes(kind)) throw new Error("kind must be one of " + KINDS.join(", "));
  if (!(ROLES as readonly string[]).includes(role)) throw new Error("role must be one of " + ROLES.join(", "));
  if (!(STATES as readonly string[]).includes(state)) throw new Error("state must be one of " + STATES.join(", "));
  return { schemaVersion: 1, id, kind, role, cart: c, counterparty: counterparty ?? "", basis: b ?? basis(), credential: { ...(credential ?? {}) }, state, at };
}

export function order(id: string, mandateId: string, status: string, fulfillment: Record<string, unknown>, permalink: string, at: unknown): Order {
  if (!(ORDER_STATUSES as readonly string[]).includes(status)) throw new Error("status must be one of " + ORDER_STATUSES.join(", "));
  return { schemaVersion: 1, id, mandate: mandateId ?? "", status, fulfillment: { ...(fulfillment ?? {}) }, permalink: permalink ?? "", at };
}

export const itemsTotal = (c: Cart): number => c.items.reduce((sum, i) => sum + i.quantity * i.unitPrice, 0);

/** The base64url SHA-256 of a string's UTF-8 bytes, no padding. */
export const digest = (s: string): string => createHash("sha256").update(s, "utf8").digest("base64url");
