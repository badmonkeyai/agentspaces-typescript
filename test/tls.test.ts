/*
 * Copyright 2026 Bad Monkey, Inc.
 * Licensed under the Apache License, Version 2.0; see the LICENSE file.
 */

/**
 * The tls binding (SPEC §5.5, §5.6): a channel certificate the identity key endorses, a TLS 1.3
 * dial that attests the seed from the certificate it presents and refuses one that attests
 * nobody, a listener that attests the client's certificate, the CHANNEL_HELLO announced once per
 * attested connection, and the bare frames accepted from exactly the attested seed afterwards.
 * A Node listener stands in for the Java seed; the cross-language council test covers the real one.
 */
import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import test from "node:test";
import { dumps, loads } from "../src/cbor.js";
import { Identity, multibase } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import { FrameChannel } from "../src/transport.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import {
  ED25519_SIG_OID, attestChannelCertificate, base58Decode, buildChannelCertificate, generateChannelCertificate,
  signatureAlgorithmOf,
} from "../src/node/channel-certificate.js";
import { TcpListener } from "../src/node/tcp.js";
import { TlsDialer, TlsListener, channelCredential } from "../src/node/tls.js";
import "../src/node/index.js";

const GROUP = "zTsTls";

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(predicate: () => boolean, ms = 5000): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (predicate()) {
      return;
    }
    await sleep(20);
  }
  assert.ok(predicate());
}

const portOf = (address: string | undefined): number => Number(address!.substring(address!.lastIndexOf(":") + 1));

test("a channel certificate attests its identity and parses as X.509 v3", () => {
  const identity = Identity.generate();
  const credential = generateChannelCertificate(identity);
  const parsed = new X509Certificate(credential.certificateDer);
  assert.equal(parsed.subject, `CN=${multibase(identity.publicRaw)}`);
  assert.equal(parsed.issuer, parsed.subject);
  assert.equal(signatureAlgorithmOf(credential.certificateDer), ED25519_SIG_OID);
  assert.ok(parsed.validFromDate.getTime() <= Date.now() && parsed.validToDate.getTime() > Date.now() + 300 * 86_400_000);
  assert.equal(attestChannelCertificate(credential.certificateDer), identity.peerId);
  assert.deepEqual(base58Decode(parsed.subject.substring(4)), identity.publicRaw);
  assert.ok(credential.keyPem.includes("BEGIN PRIVATE KEY") && credential.certificatePem.includes("BEGIN CERTIFICATE"));
  assert.equal(new X509Certificate(credential.certificatePem).fingerprint256, parsed.fingerprint256);
  assert.equal(channelCredential(identity), channelCredential(identity), "generated once per identity");
});

test("attestation refuses a certificate a stranger signed, a foreign CN, and garbage", () => {
  const identity = Identity.generate();
  const stranger = Identity.generate();
  const forged = buildChannelCertificate(identity.publicRaw, stranger); // names identity, signed by stranger
  assert.equal(attestChannelCertificate(forged.certificateDer), null);
  assert.equal(attestChannelCertificate(buildChannelCertificate(new Uint8Array(31), identity).certificateDer), null,
    "a CN that is not a 32-byte key");
  assert.equal(attestChannelCertificate(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])), null);
  assert.equal(attestChannelCertificate(new Uint8Array(0)), null);
  assert.throws(() => base58Decode("0OIl"));
});

test("a tls dial and a tls listener attest each other from their channel certificates", async () => {
  const host = Identity.generate();
  const client = Identity.generate();
  const accepted: FrameChannel[] = [];
  const close = await new TlsListener(host).listen("127.0.0.1:0", (channel) => accepted.push(channel));
  try {
    const channel = await new TlsDialer().dial({ host: "127.0.0.1", port: portOf(close.address), scheme: "tls" },
      { identity: client });
    try {
      assert.equal(channel.scheme, "tls");
      assert.equal(channel.attestedPeer(), host.peerId, "the dialer attested the listener");
      await waitFor(() => accepted.length === 1);
      assert.equal(accepted[0].attestedPeer(), client.peerId, "the listener attested the dialer");
      const got: Uint8Array[] = [];
      accepted[0].onFrame((frame) => got.push(frame));
      channel.send(new Uint8Array([1, 2, 3]));
      await waitFor(() => got.length === 1);
      assert.deepEqual(got[0], new Uint8Array([1, 2, 3]), "frames cross with the tcp framing");
    } finally {
      channel.close();
    }
  } finally {
    close();
  }
});

test("a seed that attests nobody is refused, and so are a plain listener and a dial without an identity", async () => {
  const stranger = Identity.generate();
  const host = Identity.generate();
  // A listener whose certificate names host but was signed by a stranger: it attests nobody.
  const { createServer } = await import("node:tls");
  const forged = buildChannelCertificate(host.publicRaw, stranger);
  const server = createServer({ key: forged.keyPem, cert: forged.certificatePem, minVersion: "TLSv1.3" });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  try {
    await assert.rejects(new TlsDialer().dial({ host: "127.0.0.1", port, scheme: "tls" }, { identity: Identity.generate() }),
      /presented no endorsed channel certificate/);
    await assert.rejects(new TlsDialer().dial({ host: "127.0.0.1", port, scheme: "tls" }), /needs the peer's identity/);
  } finally {
    server.close();
  }
  const plain = await new TcpListener().listen("127.0.0.1:0", (channel) => channel.close());
  try {
    const peer = new Peer(Identity.generate(), GROUP);
    await assert.rejects(peer.connect("127.0.0.1", portOf(plain.address), "tls"));
    assert.equal(peer.connected(), false);
  } finally {
    plain();
  }
});

/** A seed over tls that decodes the peer's frames and answers its CHANNEL_HELLO with a bare PING, as a Java node in ATTESTED mode would. */
async function tlsSeed(): Promise<{ identity: Identity; port: number; frames: { kind: string; auth: string }[];
  envelopes: Dict[]; attested: (string | null)[]; close: () => void }> {
  const identity = Identity.generate();
  const frames: { kind: string; auth: string }[] = [];
  const envelopes: Dict[] = [];
  const attested: (string | null)[] = [];
  const close = await new TlsListener(identity).listen("127.0.0.1:0", (channel) => {
    attested.push(channel.attestedPeer());
    channel.onFrame((frame) => {
      const decoded = wire.decodeFrameDetailed(frame, { attestedPeer: channel.attestedPeer(), session: null });
      if (decoded === null) {
        return;
      }
      frames.push({ kind: String(decoded.env["kind"]), auth: decoded.auth });
      envelopes.push(decoded.env);
      if (decoded.env["kind"] === "CHANNEL_HELLO") {
        assert.deepEqual({ ...(loads(decoded.env["body"] as Uint8Array) as Dict) }, { acceptsBare: true, attestedRemote: identity.peerId });
        const env = wire.envelope(GROUP, "PING", identity.peerId, wire.hlcNow(identity.peerId, Date.now()),
          wire.pingBody(41), String(decoded.env["from"]));
        // Bare: no key and no signature, each written as null since WireCodec.Signed always holds both
        // (HLC round six, 2026-11-08, P1).
        channel.send(dumps({ envelope: env, senderPublicKey: null, signature: null }));
      }
    });
  });
  return { identity, port: portOf(close.address), frames, envelopes, attested, close };
}

test("the peer announces the channel once and accepts bare frames from the attested seed", async () => {
  const seed = await tlsSeed();
  const peer = new Peer(Identity.generate(), GROUP);
  try {
    await peer.connect("127.0.0.1", seed.port, "tls");
    assert.equal(peer.currentSeed()?.scheme, "tls");
    await waitFor(() => seed.frames.length >= 3);
    assert.deepEqual(seed.frames.slice(0, 3), [{ kind: "RUMOR", auth: "SIGNED" }, { kind: "CHANNEL_HELLO", auth: "SIGNED" },
      { kind: "DIGEST", auth: "SIGNED" }], "the introduction, the announcement, the pull: every one signed");
    assert.equal(seed.attested[0], peer.identity.peerId, "the seed attested this peer");
    assert.equal(seed.envelopes.find((e) => e["kind"] === "CHANNEL_HELLO")?.["to"], seed.identity.peerId);
    await waitFor(() => peer.attestedFrames >= 1 && seed.frames.some((f) => f.kind === "ACK"));
    const ack = seed.envelopes.find((e) => e["kind"] === "ACK")!;
    assert.equal((loads(ack["body"] as Uint8Array) as Dict)["nonce"], 41, "the bare PING was accepted and answered, signed");
    assert.equal(peer.malformedFrames, 0);
    assert.ok(peer.reachable.has(seed.identity.peerId));
    peer.introduce();
    await waitFor(() => seed.frames.filter((f) => f.kind === "RUMOR").length >= 2);
    assert.equal(seed.frames.filter((f) => f.kind === "CHANNEL_HELLO").length, 1, "one announcement per connection");
  } finally {
    peer.close();
    seed.close();
  }
});

test("over tcp nothing is announced and a bare frame is malformed", async () => {
  const seedIdentity = Identity.generate();
  const frames: string[] = [];
  let link: FrameChannel | null = null;
  const close = await new TcpListener().listen("127.0.0.1:0", (channel) => {
    link = channel;
    channel.onFrame((frame) => {
      const env = wire.decodeFrame(frame);
      if (env !== null) {
        frames.push(String(env["kind"]));
      }
    });
  });
  const peer = new Peer(Identity.generate(), GROUP);
  try {
    await peer.connect("127.0.0.1", portOf(close.address));
    await waitFor(() => frames.length >= 2 && link !== null);
    assert.deepEqual(frames.slice(0, 2), ["RUMOR", "DIGEST"]);
    const env = wire.envelope(GROUP, "PING", seedIdentity.peerId, wire.hlcNow(seedIdentity.peerId, Date.now()),
      wire.pingBody(1), peer.identity.peerId);
    link!.send(dumps({ envelope: env }));
    await waitFor(() => peer.malformedFrames === 1);
    assert.equal(peer.attestedFrames, 0);
    assert.ok(!frames.includes("CHANNEL_HELLO") && !frames.includes("ACK"));
  } finally {
    peer.close();
    close();
  }
});
