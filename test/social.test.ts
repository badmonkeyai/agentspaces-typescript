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
 * The social invite golden vector (agentspaces-bootstrap-social/golden/
 * social-golden.json, vendored as test/social-golden.json): every
 * derivation of SRAD appendix F and every CBOR record of JoinCredentials,
 * byte for byte from TypeScript. Ed25519 is deterministic, so the credential
 * string itself must match. When the sibling golden exists beside this
 * checkout, the vendored copy must still equal it.
 */

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { dumps, loads } from "../src/cbor.js";
import { Identity, verifySignedGroupAd } from "../src/identity.js";
import {
  DEFAULT_HOST,
  GroupSecret,
  InviteKey,
  base32CrockfordDecode,
  base32CrockfordEncode,
  credentialHash,
  credentialView,
  delegate,
  delegatedCredentialAdmits,
  delegationGroup,
  delegationHash,
  describeDelegation,
  hintsFor,
  issueDelegated,
  parseDelegatedCredential,
} from "../src/social.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const VENDORED = join(here, "..", "..", "test", "social-golden.json");
const SIBLING = join(here, "..", "..", "..", "agentspaces-bootstrap-social", "golden", "social-golden.json");
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(VENDORED, "utf-8"));

function hex(name: string): Buffer {
  return Buffer.from(GOLDEN[name], "hex");
}

/** Bytes as a Buffer, so Node's strict deepEqual compares content, not the view's class. */
function b(bytes: Uint8Array): Buffer {
  return Buffer.from(bytes);
}

function secret(): GroupSecret {
  return GroupSecret.of(hex("secret_hex"));
}

test("the vendored golden equals the sibling project's copy when it is there", () => {
  if (!existsSync(SIBLING)) {
    return; // a checkout of the client alone
  }
  assert.deepEqual(JSON.parse(readFileSync(SIBLING, "utf-8")), GOLDEN,
    "test/social-golden.json drifted from agentspaces-bootstrap-social/golden/social-golden.json");
});

test("the group secret derives the golden code, invite key, and content key", () => {
  const s = secret();
  assert.equal(s.code(), GOLDEN["code"]);
  assert.equal(s.code().length, 16);
  assert.deepEqual(b(s.inviteSeed()), hex("invite_private_seed_hex"));
  assert.deepEqual(b(s.invitePublicKey()), hex("invite_public_key_hex"));
  assert.deepEqual(b(s.inviteIdentity().publicRaw), hex("invite_public_key_hex"));
  assert.deepEqual(b(s.contentKey()), hex("content_key_hex"));
  assert.equal(s.contentKeyBase64(), Buffer.from(hex("content_key_hex")).toString("base64"));
  assert.equal(s.contentKey().length, 32);
});

test("the founder and candidate seeds give the golden PeerIds", () => {
  assert.equal(Identity.fromSeed(hex("founder_seed_hex")).peerId, GOLDEN["founder_peer_id"]);
  assert.equal(Identity.fromSeed(hex("candidate_seed_hex")).peerId, GOLDEN["candidate_peer_id"]);
  assert.throws(() => Identity.fromSeed(new Uint8Array(16)), /32 bytes/);
});

test("the golden founding verifies to the golden group id", () => {
  const signed = loads(Buffer.from(GOLDEN["founding_cbor_base64"], "base64")) as Dict;
  assert.equal(verifySignedGroupAd(signed), GOLDEN["group_id"]);
  assert.equal((signed["advertisement"] as Dict)["issuer"], GOLDEN["founder_peer_id"]);
});

test("the delegation decodes to the golden group, founder, expiry, and label, and hashes right", () => {
  const info = describeDelegation(GOLDEN["delegation_base64"]);
  assert.ok(info !== null);
  assert.equal(info.group, GOLDEN["group_id"]);
  assert.equal(info.founder, GOLDEN["founder_peer_id"]);
  assert.equal(info.notAfterMillis, Date.parse(GOLDEN["delegation_not_after"]));
  assert.equal(info.label, GOLDEN["delegation_label"]);
  assert.deepEqual(b(info.inviteKey), hex("invite_public_key_hex"));
  assert.equal(delegationGroup(GOLDEN["delegation_base64"]), GOLDEN["group_id"]);
  assert.deepEqual(b(delegationHash(GOLDEN["delegation_base64"]) as Uint8Array), hex("delegation_hash_hex"));
  // The hash of the credential's embedded delegation is the same hash: one revocation kills the key.
  assert.deepEqual(b(delegationHash(GOLDEN["credential"]) as Uint8Array), hex("delegation_hash_hex"));
  assert.equal(delegationHash("not base64 cbor"), null);
  assert.throws(() => delegationGroup("AAAA"), /not a delegation/);
});

test("the delegation re-signs byte for byte from the founder seed", () => {
  const founder = Identity.fromSeed(hex("founder_seed_hex"));
  const again = delegate(founder, GOLDEN["group_id"], hex("invite_public_key_hex"),
    Date.parse(GOLDEN["delegation_not_after"]), GOLDEN["delegation_label"]);
  assert.equal(again, GOLDEN["delegation_base64"]);
});

test("issueDelegated reproduces the golden credential exactly", () => {
  const credential = issueDelegated(GOLDEN["delegation_base64"], secret().inviteSeed(),
    GOLDEN["candidate_peer_id"]);
  assert.equal(credential, GOLDEN["credential"]);
  assert.ok(credential.startsWith("d1:"));
  // The identity form signs the same.
  assert.equal(issueDelegated(GOLDEN["delegation_base64"], secret().inviteIdentity(),
    GOLDEN["candidate_peer_id"]), GOLDEN["credential"]);
  assert.deepEqual(b(credentialHash(credential)), hex("credential_hash_hex"));
  assert.equal(Buffer.from(credentialView(GOLDEN["candidate_peer_id"], GOLDEN["group_id"])).toString("hex"),
    GOLDEN["credential_view_cbor_hex"]);
  const parsed = parseDelegatedCredential(credential);
  assert.ok(parsed !== null);
  assert.equal(parsed.delegation.group, GOLDEN["group_id"]);
  assert.equal(parsed.signature.length, 64);
  // The hint a holder presents is that credential under aspace:join.
  const key = InviteKey.parse(GOLDEN["invite_key_compact"]);
  assert.deepEqual(hintsFor(key, GOLDEN["delegation_base64"], GOLDEN["candidate_peer_id"]),
    { "aspace:join": GOLDEN["credential"] });
});

test("the delegated credential admits the candidate and nobody else (JoinCredentials.verify)", () => {
  const now = Date.parse(GOLDEN["founding_issued"]);
  const notAfter = Date.parse(GOLDEN["delegation_not_after"]);
  const ok = (candidate: string, issuer: string, group: string, at: number): boolean =>
    delegatedCredentialAdmits(GOLDEN["credential"], candidate, issuer, group, at);
  assert.ok(ok(GOLDEN["candidate_peer_id"], GOLDEN["founder_peer_id"], GOLDEN["group_id"], now));
  assert.ok(ok(GOLDEN["candidate_peer_id"], GOLDEN["founder_peer_id"], GOLDEN["group_id"], notAfter + 9 * 60_000),
    "ten minutes of skew after expiry");
  assert.ok(!ok(GOLDEN["candidate_peer_id"], GOLDEN["founder_peer_id"], GOLDEN["group_id"], notAfter + 11 * 60_000),
    "expired");
  assert.ok(!ok(Identity.generate().peerId, GOLDEN["founder_peer_id"], GOLDEN["group_id"], now), "another candidate");
  assert.ok(!ok(GOLDEN["candidate_peer_id"], Identity.generate().peerId, GOLDEN["group_id"], now), "another founder");
  assert.ok(!ok(GOLDEN["candidate_peer_id"], GOLDEN["founder_peer_id"], "zOther", now), "another group");
  assert.ok(!delegatedCredentialAdmits(GOLDEN["credential"].substring(3), GOLDEN["candidate_peer_id"],
    GOLDEN["founder_peer_id"], GOLDEN["group_id"], now), "no d1: prefix");
  // A credential under a key the founder never delegated: the delegation signature fails.
  const forged = delegate(Identity.generate(), GOLDEN["group_id"], secret().invitePublicKey(), notAfter, "forged");
  const forgedCredential = issueDelegated(forged, secret().inviteSeed(), GOLDEN["candidate_peer_id"]);
  assert.ok(!delegatedCredentialAdmits(forgedCredential, GOLDEN["candidate_peer_id"],
    GOLDEN["founder_peer_id"], GOLDEN["group_id"], now));
  // A credential signed by a key other than the delegated one.
  const wrongSigner = issueDelegated(GOLDEN["delegation_base64"], Identity.generate(), GOLDEN["candidate_peer_id"]);
  assert.ok(!delegatedCredentialAdmits(wrongSigner, GOLDEN["candidate_peer_id"],
    GOLDEN["founder_peer_id"], GOLDEN["group_id"], now));
});

test("the delegation record encodes as Jackson wrote it", () => {
  const bytes = Buffer.from(GOLDEN["delegation_base64"], "base64");
  assert.deepEqual(b(dumps(loads(bytes))), bytes, "decode then encode is the identity on the golden bytes");
  const credential = Buffer.from(GOLDEN["credential"].substring(3), "base64");
  assert.deepEqual(b(dumps(loads(credential))), credential);
});

test("both renderings of the key parse to the golden secret and render back exactly", () => {
  const compact = InviteKey.parse(GOLDEN["invite_key_compact"]);
  const url = InviteKey.parse(GOLDEN["invite_key_url"]);
  assert.ok(compact.secret.equals(secret()));
  assert.ok(url.secret.equals(secret()));
  assert.equal(compact.code, GOLDEN["code"]);
  assert.equal(compact.host, DEFAULT_HOST);
  assert.equal(url.host, DEFAULT_HOST);
  assert.equal(compact.delegation, null);
  assert.equal(compact.compact(), GOLDEN["invite_key_compact"]);
  assert.equal(compact.url(), GOLDEN["invite_key_url"]);
  assert.equal(url.compact(), GOLDEN["invite_key_compact"]);
  assert.equal(url.url(), GOLDEN["invite_key_url"]);
  assert.equal(InviteKey.of(secret()).compact(), GOLDEN["invite_key_compact"]);
  assert.equal(compact.documentUrl(), `https://${DEFAULT_HOST}/j/${GOLDEN["code"]}`);
});

test("the key with a host and a delegation round-trips in both renderings", () => {
  const compact = InviteKey.parse(GOLDEN["invite_key_compact_with_host_and_delegation"]);
  const url = InviteKey.parse(GOLDEN["invite_key_url_with_delegation"]);
  for (const key of [compact, url]) {
    assert.ok(key.secret.equals(secret()));
    assert.equal(key.host, "beacon.example.org");
    assert.equal(key.delegation, GOLDEN["delegation_base64"]);
    assert.equal(key.compact(), GOLDEN["invite_key_compact_with_host_and_delegation"]);
    assert.equal(key.url(), GOLDEN["invite_key_url_with_delegation"]);
    assert.equal(key.documentUrl("http"), `http://beacon.example.org/j/${GOLDEN["code"]}`);
  }
  assert.equal(InviteKey.of(secret(), GOLDEN["delegation_base64"], "beacon.example.org").compact(),
    GOLDEN["invite_key_compact_with_host_and_delegation"]);
  assert.equal(compact.withDelegation(null).compact(), GOLDEN["invite_key_compact"] + "@beacon.example.org");
  assert.equal(compact.withHost(DEFAULT_HOST).withDelegation(null).url(), GOLDEN["invite_key_url"]);
  // A port other than 443 stays with the host.
  const ported = InviteKey.parse(`https://beacon.example.org:8443/j/${GOLDEN["code"]}#${
    base32CrockfordEncode(secret().bytes())}`);
  assert.equal(ported.host, "beacon.example.org:8443");
  assert.equal(ported.compact(), GOLDEN["invite_key_compact"] + "@beacon.example.org:8443");
});

test("a key read aloud survives: case, spaces, wraps, and O/I/L for 0/1", () => {
  const lower = GOLDEN["invite_key_compact"].toLowerCase();
  assert.equal(InviteKey.parse(lower).compact(), GOLDEN["invite_key_compact"]);
  const spaced = GOLDEN["invite_key_compact"].replace("000G40R40M30E209185GR38E1W", "OOOG 40R4 OM3O E2O9\n185G R38E 1W");
  assert.equal(InviteKey.parse(spaced).compact(), GOLDEN["invite_key_compact"]);
  assert.equal(InviteKey.parse("  " + GOLDEN["invite_key_url"] + "  ").url(), GOLDEN["invite_key_url"]);
  assert.deepEqual(b(base32CrockfordDecode("oOiIlL")), b(base32CrockfordDecode("001111")));
  assert.throws(() => base32CrockfordDecode("U"), /not a Crockford/);
  assert.throws(() => InviteKey.parse("aspace-inv2-" + GOLDEN["code"]), /not an invite key/);
  assert.throws(() => InviteKey.parse(GOLDEN["invite_key_compact"].replace(GOLDEN["code"], "0000000000000000")),
    /the code does not belong to the secret/);
  assert.throws(() => InviteKey.parse(`https://${DEFAULT_HOST}/j/${GOLDEN["code"]}`), /not an invite link/);
  // A delegation segment is carried as given; whether it parses is the join's business.
  const junk = InviteKey.parse(GOLDEN["invite_key_compact"] + "-0000");
  assert.equal(junk.delegation, "AAA=");
  assert.equal(describeDelegation("AAA="), null);
  assert.throws(() => InviteKey.parse(GOLDEN["invite_key_compact"] + "-0000-0000"), /code-secret\[-delegation\]/);
});

test("Crockford base32 round-trips every length", () => {
  for (let length = 0; length <= 40; length++) {
    const bytes = new Uint8Array(length).map((_, i) => (i * 37 + length) & 0xff);
    const text = base32CrockfordEncode(bytes);
    assert.equal(text.length, Math.ceil(length * 8 / 5));
    assert.deepEqual(b(base32CrockfordDecode(text)), b(bytes));
  }
  assert.equal(base32CrockfordEncode(secret().bytes()), "000G40R40M30E209185GR38E1W");
  assert.throws(() => GroupSecret.of(new Uint8Array(15)), /16 bytes/);
  assert.ok(!GroupSecret.random().equals(GroupSecret.random()));
});
