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
 * The beacon document and the peer's bootstrap paths (SRAD DB-X-02, DB-X-03,
 * DB-X-07): a signed document served over loopback HTTP verifies, a tampered
 * one is refused, a pin is honoured; `connectAny` dials the seeds in order
 * and fails over on a lost socket; `joinInvite` with a stubbed fetch carries
 * the golden credential in the `aspace:join` hint and joins the golden group.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Server as HttpServer, createServer as createHttpServer } from "node:http";
import { Server, Socket, createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import * as beacon from "../src/beacon.js";
import { loads } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import * as social from "../src/social.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN: { [key: string]: string } = JSON.parse(readFileSync(
  join(here, "..", "..", "test", "social-golden.json"), "utf-8"));

// ------------------------------------------------------------------ helpers

/** Accepts connections and decodes every frame the peer sends, by connection. */
class FakeSeed {
  readonly server: Server;
  readonly connections: Socket[] = [];
  readonly frames: { index: number; env: Dict }[] = [];
  port = 0;

  constructor() {
    this.server = createServer((socket) => {
      const index = this.connections.length;
      this.connections.push(socket);
      let pending = Buffer.alloc(0);
      socket.on("data", (chunk) => {
        pending = Buffer.concat([pending, chunk]);
        while (pending.length >= 4) {
          const length = pending.readInt32BE(0);
          if (pending.length < 4 + length) {
            return;
          }
          const env = wire.decodeFrame(pending.subarray(4, 4 + length));
          pending = pending.subarray(4 + length);
          if (env !== null) {
            this.frames.push({ index, env });
          }
        }
      });
      socket.on("error", () => undefined);
    });
  }

  listen(port = 0): Promise<void> {
    return new Promise((resolve) => {
      this.server.listen(port, "127.0.0.1", () => {
        const address = this.server.address();
        this.port = typeof address === "object" && address !== null ? address.port : 0;
        resolve();
      });
    });
  }

  kindsOn(index: number): string[] {
    return this.frames.filter((f) => f.index === index).map((f) => String(f.env["kind"]));
  }

  close(): void {
    for (const c of this.connections) {
      c.destroy();
    }
    this.server.close();
  }
}

/** A loopback port nobody listens on: taken from a server that is closed again. */
async function deadPort(): Promise<number> {
  const seed = new FakeSeed();
  await seed.listen();
  const port = seed.port;
  await new Promise<void>((resolve) => seed.server.close(() => resolve()));
  return port;
}

async function until(condition: () => boolean, millis: number): Promise<boolean> {
  const deadline = Date.now() + millis;
  while (Date.now() < deadline) {
    if (condition()) {
      return true;
    }
    await new Promise((r) => setTimeout(r, 20));
  }
  return condition();
}

/** A loopback HTTP server with a fixed body per path. */
class Pages {
  readonly server: HttpServer;
  readonly bodies = new Map<string, Buffer>();
  readonly requests: string[] = [];
  port = 0;

  constructor() {
    this.server = createHttpServer((request, response) => {
      this.requests.push(request.url ?? "");
      const body = this.bodies.get(request.url ?? "");
      if (body === undefined) {
        response.writeHead(404);
        response.end();
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(body);
    });
  }

  listen(): Promise<void> {
    return new Promise((resolve) => {
      this.server.listen(0, "127.0.0.1", () => {
        const address = this.server.address();
        this.port = typeof address === "object" && address !== null ? address.port : 0;
        resolve();
      });
    });
  }

  url(path: string): string {
    return `http://127.0.0.1:${this.port}${path}`;
  }

  close(): void {
    this.server.closeAllConnections();
    this.server.close();
  }
}

/** The golden group as a beacon would list it, at the given tcp seeds. */
function goldenGroup(seeds: string[], invite: string | null = GOLDEN["delegation_base64"]): beacon.BeaconGroup {
  return {
    name: "weekend-hack",
    id: "aspace://" + GOLDEN["group_id"],
    founding: GOLDEN["founding_cbor_base64"],
    seeds: seeds.map((address, priority) => ({ transport: "tcp", address, priority })),
    wire: { session: 1, batch: 1 },
    parameters: { region: "eu-west-1", "a-key": "x" },
    invite,
  };
}

/** The self-advertisement a RUMOR on the peers stream carries, decoded. */
function peerAdOf(env: Dict): Dict {
  const rumor = loads(Buffer.from(env["body"] as Uint8Array)) as Dict;
  assert.equal(rumor["streamId"], "peers");
  const signed = loads(Buffer.from(rumor["payload"] as Uint8Array)) as Dict;
  return loads(Buffer.from(signed["adBytes"] as Uint8Array)) as Dict;
}

// ------------------------------------------------------------- the document

// A document Java's BeaconDocument.signed wrote for the issuer seeded 0x10..0x2f (the golden
// founder) at 2026-10-14T00:00:00Z, ttl 300: one full group (a non-ASCII, quoted,
// control-character parameter included) and one bare group. Shared with the Python suite.
const JAVA_SIGNED_DOCUMENT = '{"v":1,"issuer":"zhRv4SRobYBddjUoVn2YuPutUyi8zmqUhchSpL2uvotR","issuerKey":"d3bocLkzVPKgskwj8qNsxOgOIjIYwbl5Jv3QGDlqK5s=","issued":"2026-10-14T00:00:00Z","ttl":300,"groups":[{"name":"weekend-hack","id":"aspace://zG","founding":"AA==","seeds":[{"transport":"tls","address":"seed-a.corp.example:7500","priority":0},{"transport":"tcp","address":"127.0.0.1:7500","priority":1}],"wire":{"batch":1,"session":1},"multicast":"239.255.42.99:7787","parameters":{"a":"ü \\"q\\" \\u0001","region":"eu-west-1"},"invite":"QQ=="},{"name":"bare","seeds":[]}],"signature":"7gGY0YkDJfdrSzjbeVZTjkV+zr4o9H1MqVC8Ab7D4qoWMiuFt4qUEF99yidhtIJxzZAcvl3QbA23ST6zY02gAw=="}';
const JAVA_CANONICAL_BYTES = JAVA_SIGNED_DOCUMENT.replace(/,"signature":"[^"]*"}$/, "}");

test("a document Java signed verifies and its canonical bytes and JSON are reproduced exactly", () => {
  const document = beacon.parseBeaconDocument(JAVA_SIGNED_DOCUMENT);
  const issuer = Identity.fromSeed(new Uint8Array(Buffer.from(GOLDEN["founder_seed_hex"], "hex")));
  assert.equal(document.issuer, issuer.peerId);
  assert.equal(Buffer.from(beacon.canonicalDocumentBytes(document)).toString("utf-8"), JAVA_CANONICAL_BYTES);
  assert.equal(beacon.documentSigner(document), issuer.peerId);
  assert.equal(beacon.documentJson(document), JAVA_SIGNED_DOCUMENT);
  assert.equal(document.groups[0].parameters?.["a"], "ü \"q\" \u0001");
  // Re-signed from the founder seed, the signature is Java's byte for byte (Ed25519 is deterministic).
  const resigned = beacon.signBeaconDocument(issuer, document.groups, document.ttl,
    Date.parse(document.issued as string));
  assert.equal(resigned.signature, document.signature);
  assert.deepEqual(beacon.seedsOf(document.groups[0]), [{ host: "127.0.0.1", port: 7500 }]);
});

test("canonical bytes follow Jackson: declared order, sorted maps, nulls omitted, no whitespace", () => {
  const issuer = Identity.generate();
  const document = beacon.signBeaconDocument(issuer, [{
    name: "g", id: "aspace://zX", founding: null, seeds: [{ transport: "tls", address: "a:1", priority: 0 }],
    wire: { tree: 1, batch: 1 }, multicast: null, parameters: { zeta: "1", alpha: "q\"uote\n" }, invite: null,
  }, { name: "bare", seeds: [] }], 300, Date.UTC(2026, 9, 13, 14, 2, 11));
  const canonical = Buffer.from(beacon.canonicalDocumentBytes(document)).toString("utf-8");
  assert.equal(canonical, `{"v":1,"issuer":"${issuer.peerId}","issuerKey":"${document.issuerKey}",`
    + `"issued":"2026-10-13T14:02:11Z","ttl":300,"groups":[{"name":"g","id":"aspace://zX",`
    + `"seeds":[{"transport":"tls","address":"a:1","priority":0}],"wire":{"batch":1,"tree":1},`
    + `"parameters":{"alpha":"q\\"uote\\n","zeta":"1"}},{"name":"bare","seeds":[]}]}`);
  assert.ok(beacon.documentVerifies(document));
  assert.equal(beacon.documentSigner(document), issuer.peerId);
  // The served JSON is the canonical text plus the signature; it parses back to the same document.
  const json = beacon.documentJson(document);
  assert.ok(json.endsWith(`,"signature":"${document.signature}"}`));
  const parsed = beacon.parseBeaconDocument(json);
  assert.deepEqual(beacon.canonicalDocumentBytes(parsed), beacon.canonicalDocumentBytes(document));
  assert.equal(beacon.documentSigner(parsed), issuer.peerId);
  // Unknown fields are ignored; a forbidden parameter is refused; v < 1 is refused.
  assert.equal(beacon.parseBeaconDocument(json.slice(0, -1) + ",\"future\":true}").groups.length, 2);
  assert.throws(() => beacon.parseBeaconDocument(JSON.stringify({ v: 1, ttl: 1,
    groups: [{ name: "x", parameters: { "Content-Key": "no" } }] })), /never carries/);
  assert.throws(() => beacon.parseBeaconDocument(JSON.stringify({ v: 0, ttl: 1, groups: [] })), /v=0/);
  assert.throws(() => beacon.signBeaconDocument(issuer, [{ name: "x", seeds: [], parameters: { credential: "no" } }]),
    /never carries/);
});

test("a served document verifies, a tampered one is refused, a pin is honoured, http needs allowPlain", async () => {
  const issuer = Identity.generate();
  const document = beacon.signBeaconDocument(issuer, [goldenGroup(["seed-a:7500", "seed-b:7500"])]);
  const pages = new Pages();
  await pages.listen();
  try {
    pages.bodies.set(beacon.WELL_KNOWN, Buffer.from(beacon.documentJson(document)));
    const signature = Buffer.from(document.signature as string, "base64");
    signature[3] ^= 0x01;
    pages.bodies.set("/tampered", Buffer.from(beacon.documentJson({ ...document,
      signature: signature.toString("base64") })));
    pages.bodies.set("/forged-issuer", Buffer.from(beacon.documentJson({ ...document,
      issuer: Identity.generate().peerId })));
    pages.bodies.set("/edited", Buffer.from(beacon.documentJson({ ...document, ttl: 301 })));
    pages.bodies.set("/unsigned", Buffer.from(beacon.documentJson({ ...document, signature: null })));
    pages.bodies.set("/huge", Buffer.from("[" + "1,".repeat(40_000) + "1]"));

    const fetched = await beacon.fetchBeaconDocument(pages.url(beacon.WELL_KNOWN), { allowPlain: true });
    assert.equal(fetched.issuer, issuer.peerId);
    assert.equal(fetched.groups[0].name, "weekend-hack");
    assert.deepEqual(beacon.seedsOf(fetched.groups[0]), [{ host: "seed-a", port: 7500 }, { host: "seed-b", port: 7500 }]);
    const pinned = await beacon.fetchBeaconDocument(pages.url(beacon.WELL_KNOWN),
      { allowPlain: true, beaconPeer: issuer.peerId });
    assert.equal(pinned.ttl, 300);

    await assert.rejects(beacon.fetchBeaconDocument(pages.url("/tampered"), { allowPlain: true }), /does not verify/);
    await assert.rejects(beacon.fetchBeaconDocument(pages.url("/forged-issuer"), { allowPlain: true }), /does not verify/);
    await assert.rejects(beacon.fetchBeaconDocument(pages.url("/edited"), { allowPlain: true }), /does not verify/);
    await assert.rejects(beacon.fetchBeaconDocument(pages.url("/unsigned"), { allowPlain: true }), /does not verify/);
    await assert.rejects(beacon.fetchBeaconDocument(pages.url(beacon.WELL_KNOWN),
      { allowPlain: true, beaconPeer: Identity.generate().peerId }), /not the pinned/);
    await assert.rejects(beacon.fetchBeaconDocument(pages.url("/missing"), { allowPlain: true }), /answered 404/);
    await assert.rejects(beacon.fetchBeaconDocument(pages.url("/huge"), { allowPlain: true }), /65536/);
    const before = pages.requests.length;
    await assert.rejects(beacon.fetchBeaconDocument(pages.url(beacon.WELL_KNOWN)), /refusing to fetch .* over http/);
    assert.equal(pages.requests.length, before, "a plain URL is refused before any request");
  } finally {
    pages.close();
  }
});

test("groupFromDocument selects by id, by name, or the only group", () => {
  const document = beacon.signBeaconDocument(Identity.generate(), [
    { ...goldenGroup(["a:1"]), name: "first" }, { name: "second", id: "aspace://zSecond", seeds: [] }]);
  assert.equal(beacon.groupFromDocument(document, { groupId: GOLDEN["group_id"] }).name, "first");
  assert.equal(beacon.groupFromDocument(document, { groupId: "aspace://" + GOLDEN["group_id"] + "/x" }).name, "first");
  assert.equal(beacon.groupFromDocument(document, { groupId: "zSecond" }).name, "second");
  assert.equal(beacon.groupFromDocument(document, { name: "second" }).name, "second");
  assert.throws(() => beacon.groupFromDocument(document), /2 groups/);
  assert.throws(() => beacon.groupFromDocument(document, { groupId: "zNone" }), /no group zNone/);
  assert.throws(() => beacon.groupFromDocument(document, { name: "none" }), /no group named/);
  assert.equal(beacon.groupFromDocument({ ...document, groups: [document.groups[1]] }).name, "second");
  assert.throws(() => beacon.groupFromDocument({ ...document, groups: [] }), /no group/);
  assert.deepEqual(beacon.parseSeedAddress("[::1]:7501"), { host: "::1", port: 7501 });
  assert.deepEqual(beacon.parseSeedAddress("seed.example"), { host: "seed.example", port: 7500 });
  assert.throws(() => beacon.parseSeedAddress("seed:zero"), /not a seed address/);
});

// ------------------------------------------------------------- connectAny

test("connectAny dials the seeds in order and fails over on a lost socket (DB-X-02)", async () => {
  const dead = await deadPort();
  const a = new FakeSeed();
  const b = new FakeSeed();
  await a.listen();
  await b.listen();
  const peer = new Peer(Identity.generate(), "zTsBootstrap");
  peer.reconnectIntervalMs = 100;
  try {
    await peer.connectAny([{ host: "127.0.0.1", port: dead }, { host: "127.0.0.1", port: a.port },
      { host: "127.0.0.1", port: b.port }]);
    assert.equal(peer.currentSeed()?.port, a.port, "the first seed that answered");
    assert.ok(peer.connected());
    assert.ok(await until(() => a.kindsOn(0).length >= 2, 5000));
    assert.deepEqual(a.kindsOn(0).slice(0, 2), ["RUMOR", "DIGEST"]);
    assert.equal(b.connections.length, 0, "the next seed is not dialed while the link holds");

    // Seed A drops the link: the peer tries the next seed first, not A again.
    a.connections[0].destroy();
    assert.ok(await until(() => b.kindsOn(0).length >= 2, 5000), "failed over to B");
    assert.equal(peer.currentSeed()?.port, b.port);
    assert.equal(peer.reconnects, 1);
    assert.equal(a.connections.length, 1, "A was not re-dialed before B");

    // B goes away for good: the round continues through the dead seed back to A.
    b.close();
    assert.ok(await until(() => a.connections.length === 2 && a.kindsOn(1).length >= 2, 5000), "back to A");
    assert.equal(peer.currentSeed()?.port, a.port);
    assert.equal(peer.reconnects, 2);
  } finally {
    peer.close();
    a.close();
    b.close();
  }
});

test("connectAny rejects when no seed answers, naming them, and leaves the peer idle", async () => {
  const dead = await deadPort();
  const peer = new Peer(Identity.generate(), "zTsBootstrap");
  await assert.rejects(peer.connectAny([{ host: "127.0.0.1", port: dead }]), /no seed answered.*127\.0\.0\.1/);
  assert.ok(!peer.connected());
  await assert.rejects(peer.connectAny([]), /no seed to dial/);
  peer.close();
});

// -------------------------------------------------------------- bootstrap

test("bootstrap fetches, verifies the founding against the wanted group, and connects (DB-X-02)", async () => {
  const seed = new FakeSeed();
  await seed.listen();
  const issuer = Identity.generate();
  const pages = new Pages();
  await pages.listen();
  const peer = new Peer(Identity.generate(), "zPlaceholder");
  try {
    const document = beacon.signBeaconDocument(issuer, [
      goldenGroup([`127.0.0.1:${seed.port}`]),
      { name: "tls-only", id: "aspace://zTls", seeds: [{ transport: "tls", address: "x:1", priority: 0 }] }]);
    pages.bodies.set(beacon.WELL_KNOWN, Buffer.from(beacon.documentJson(document)));
    // The wrong group id is refused before any dial.
    await assert.rejects(peer.bootstrap(pages.url(beacon.WELL_KNOWN), { groupId: "zTls", allowPlain: true }),
      /carries no founding/);
    const stolen = { ...goldenGroup([`127.0.0.1:${seed.port}`]), id: "aspace://zTls", name: "stolen" };
    pages.bodies.set("/stolen", Buffer.from(beacon.documentJson(beacon.signBeaconDocument(issuer, [stolen]))));
    await assert.rejects(peer.bootstrap(pages.url("/stolen"), { groupId: "zTls", allowPlain: true }),
      /document says stolen is zTls/);
    await assert.rejects(peer.bootstrap(pages.url("/stolen"), { allowPlain: true }), /document says stolen is zTls/);
    assert.equal(seed.connections.length, 0);

    const group = await peer.bootstrap(pages.url(beacon.WELL_KNOWN),
      { groupId: "aspace://" + GOLDEN["group_id"], allowPlain: true, beaconPeer: issuer.peerId });
    assert.equal(group.name, "weekend-hack");
    assert.equal(peer.group, GOLDEN["group_id"]);
    assert.equal((peer.founding?.["advertisement"] as Dict)["issuer"], GOLDEN["founder_peer_id"]);
    assert.ok(await until(() => seed.kindsOn(0).length >= 2, 5000));
    assert.equal(seed.frames[0].env["group"], GOLDEN["group_id"]);
  } finally {
    peer.close();
    seed.close();
    pages.close();
  }
});

// -------------------------------------------------------------- joinInvite

test("joinInvite carries the golden credential under aspace:join and joins the delegation's group (DB-X-07)", async () => {
  const seed = new FakeSeed();
  await seed.listen();
  const candidate = Identity.fromSeed(new Uint8Array(Buffer.from(GOLDEN["candidate_seed_hex"], "hex")));
  const peer = new Peer(candidate, "zPlaceholder");
  const requested: string[] = [];
  const serve = (groups: beacon.BeaconGroup[]): typeof fetch => async (input) => {
    requested.push(String(input));
    const document = beacon.signBeaconDocument(Identity.generate(), groups);
    return new Response(beacon.documentJson(document), { status: 200, headers: { "content-type": "application/json" } });
  };
  try {
    // The compact key without a delegation: the document's invite field supplies it.
    const joined = await peer.joinInvite(GOLDEN["invite_key_compact"],
      { fetch: serve([goldenGroup([`127.0.0.1:${seed.port}`])]) });
    assert.deepEqual(requested, [`https://${social.DEFAULT_HOST}/j/${GOLDEN["code"]}`], "the server sees the code only");
    assert.equal(joined.groupId, GOLDEN["group_id"]);
    assert.deepEqual(Buffer.from(joined.contentKey), Buffer.from(GOLDEN["content_key_hex"], "hex"));
    assert.equal(joined.contentKey.length, 32);
    assert.equal(joined.delegation, GOLDEN["delegation_base64"]);
    assert.equal(joined.key.code, GOLDEN["code"]);
    const pinned = social.InviteKey.parse(joined.pinnedKey);
    assert.equal(pinned.delegation, GOLDEN["delegation_base64"], "the pinned key carries the delegation joined under");
    assert.equal(pinned.code, GOLDEN["code"]);
    assert.equal(peer.group, GOLDEN["group_id"]);
    assert.equal(peer.resourceHints[social.JOIN_HINT], GOLDEN["credential"]);
    assert.ok(await until(() => seed.kindsOn(0).length >= 2, 5000));
    const ad = peerAdOf(seed.frames[0].env);
    assert.equal((ad["resourceHints"] as Dict)[social.JOIN_HINT], GOLDEN["credential"]);
    assert.equal(ad["group"], GOLDEN["group_id"]);
    assert.ok(social.delegatedCredentialAdmits(GOLDEN["credential"], candidate.peerId,
      GOLDEN["founder_peer_id"], GOLDEN["group_id"], Date.parse(GOLDEN["founding_issued"])));
  } finally {
    peer.close();
    seed.close();
  }
});

test("joinInvite refuses a document whose founding is not the delegation's group, or without a delegation", async () => {
  const peer = new Peer(Identity.generate(), "zPlaceholder");
  const serve = (groups: beacon.BeaconGroup[]): typeof fetch => async () =>
    new Response(beacon.documentJson(beacon.signBeaconDocument(Identity.generate(), groups)), { status: 200 });
  const other = new Peer(Identity.generate(), "zOther");
  try {
    // The key names the group through its delegation; a document serving another group is refused.
    const foreign: beacon.BeaconGroup = { name: "other", id: "aspace://zOther", founding: null, seeds: [] };
    await assert.rejects(peer.joinInvite(GOLDEN["invite_key_compact_with_host_and_delegation"],
      { allowPlain: true, fetch: serve([foreign]) }), /no group/);
    // No delegation anywhere.
    await assert.rejects(peer.joinInvite(GOLDEN["invite_key_compact"],
      { fetch: serve([goldenGroup(["127.0.0.1:1"], null)]) }), /carries no delegation/);
    // A delegation signed by someone other than the founding's issuer.
    const forged = social.delegate(Identity.generate(), GOLDEN["group_id"],
      social.GroupSecret.of(new Uint8Array(Buffer.from(GOLDEN["secret_hex"], "hex"))).invitePublicKey(),
      Date.now() + 86_400_000, "forged");
    await assert.rejects(peer.joinInvite(GOLDEN["invite_key_compact"],
      { fetch: serve([goldenGroup(["127.0.0.1:1"], forged)]) }), /not signed by the group's founder/);
    assert.equal(peer.resourceHints[social.JOIN_HINT], undefined, "no hint was set");
    assert.ok(!peer.connected());
  } finally {
    peer.close();
    other.close();
  }
});

test("seeds skip the datagram schemes this client cannot dial (SRAD dtls-support DT-C-01)", () => {
  const group = {
    seeds: [
      { transport: "dtls", address: "10.0.0.5:7502", priority: 0 },
      { transport: "udp", address: "10.0.0.5:7503", priority: 1 },
      { transport: "tcp", address: "10.0.0.5:7500", priority: 2 },
    ],
  } as unknown as Parameters<typeof beacon.seedsOf>[0];
  assert.deepEqual(beacon.seedsOf(group), [{ host: "10.0.0.5", port: 7500 }]);
});
