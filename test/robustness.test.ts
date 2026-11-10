/**
 * ROBUSTNESS.md for the TypeScript client: replayed, stale and far-ahead frames are dropped
 * and counted; unknown kinds and malformed bodies never stop the reader; a lost socket is
 * reconnected to the seed and the peer re-introduces itself and re-pulls; the owner's close
 * is final. Mirrors agentspaces-python/tests/test_robustness.py.
 */
import assert from "node:assert/strict";
import { createServer, Server, Socket } from "node:net";
import test from "node:test";
import { concat } from "../src/bytes.js";
import { dumps } from "../src/cbor.js";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";
import * as wire from "../src/wire.js";
import type { Dict } from "../src/wire.js";
import "../src/node/index.js";

const GROUP = "zTsRobust";

type Sent = { kind: string; to: string | null };

/** A peer whose sends are captured instead of written to a socket. */
class CapturingPeer extends Peer {
  readonly sent: Sent[] = [];

  constructor() {
    super(Identity.generate(), GROUP);
  }

  protected send(kind: string, body: Buffer, to: string | null = null): void {
    void body;
    this.sent.push({ kind, to });
  }

  kinds(): string[] {
    return this.sent.map((s) => s.kind);
  }

  drive(env: Dict): void {
    (this as unknown as { handle(env: Dict): void }).handle(env);
  }

  /** One length-prefixed frame, as the tcp channel hands it on: the prefix stripped. */
  feed(chunk: Uint8Array): void {
    (this as unknown as { onFrame(frame: Uint8Array): void }).onFrame(chunk.subarray(4));
  }
}

function frame(sender: Identity, kind: string, body: Uint8Array, to: string, stamp: string): Dict {
  const env = wire.envelope(GROUP, kind, sender.peerId, stamp, body, to);
  const decoded = wire.decodeFrame(wire.encodeFrame(env, sender));
  assert.ok(decoded !== null);
  return decoded;
}

function stamp(ms: number, logical = 0, node = "other"): string {
  return `${ms}:${logical}:${node}`;
}

function lengthPrefixed(payload: Uint8Array): Buffer {
  const header = Buffer.alloc(4);
  header.writeInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

test("a replayed frame is dropped and counted (ROBUSTNESS.md §3.4)", () => {
  const peer = new CapturingPeer();
  const other = Identity.generate();
  const now = peer.now();
  const ping = frame(other, "PING", wire.pingBody(7), peer.identity.peerId, stamp(now, 1));
  peer.drive(ping);
  assert.deepEqual(peer.kinds(), ["ACK"]);
  peer.drive(ping);
  peer.drive(ping);
  assert.deepEqual(peer.kinds(), ["ACK"], "a replayed probe earns no second ACK");
  assert.equal(peer.frames.replayed, 2);
  // A fresh stamp from the same sender is a new frame.
  peer.drive(frame(other, "PING", wire.pingBody(8), peer.identity.peerId, stamp(now, 2)));
  assert.deepEqual(peer.kinds(), ["ACK", "ACK"]);
});

test("stale and far-ahead frames are dropped quietly (ROBUSTNESS.md §3.3)", () => {
  const peer = new CapturingPeer();
  const other = Identity.generate();
  const now = peer.now();
  peer.drive(frame(other, "PING", wire.pingBody(1), peer.identity.peerId,
    stamp(now - wire.MAX_FRAME_AGE_MILLIS - 1000)));
  peer.drive(frame(other, "PING", wire.pingBody(2), peer.identity.peerId,
    stamp(now + wire.MAX_HLC_SKEW_MILLIS + 60_000)));
  assert.deepEqual(peer.kinds(), []);
  assert.equal(peer.frames.stale, 1);
  assert.equal(peer.frames.framesFarFuture, 1);
  // Inside both windows the frames are live.
  peer.drive(frame(other, "PING", wire.pingBody(3), peer.identity.peerId,
    stamp(now - wire.MAX_FRAME_AGE_MILLIS / 2)));
  peer.drive(frame(other, "PING", wire.pingBody(4), peer.identity.peerId,
    stamp(now + wire.MAX_HLC_SKEW_MILLIS / 2)));
  assert.deepEqual(peer.kinds(), ["ACK", "ACK"]);
});

test("kinds this client does not speak are ignored and counted, never fatal (ROBUSTNESS.md §3.5)", () => {
  const peer = new CapturingPeer();
  const other = Identity.generate();
  const now = peer.now();
  // SESSION_HELLO is spoken since 0.4.0 (a malformed one is ignored, neither counted nor fatal).
  const kinds = ["HAVE", "GRAFT", "PRUNE", "BATCH"];
  kinds.forEach((kind, i) => {
    peer.drive(frame(other, kind, dumps({ anything: i }), peer.identity.peerId, stamp(now, i)));
  });
  assert.deepEqual(peer.kinds(), []);
  for (const kind of kinds) {
    assert.equal(peer.ignoredKinds.get(kind), 1, kind);
  }
  // HLC round six, 2026-11-08 (P2): a kind is a constant of Envelope.Kind, so a name outside the enum
  // makes the frame undecodable, as Java's decoder refuses it, and the peer counts it as malformed.
  const future = wire.encodeFrame(wire.envelope(GROUP, "FUTURE_KIND", other.peerId, stamp(now, 50), dumps({}),
    peer.identity.peerId), other);
  assert.equal(wire.decodeFrame(future), null);
  peer.feed(concat(new Uint8Array(4), future));
  assert.equal(peer.malformedFrames, 1);
  assert.equal(peer.ignoredKinds.get("FUTURE_KIND"), undefined);
  peer.drive(frame(other, "PING", wire.pingBody(9), peer.identity.peerId, stamp(now, 99)));
  assert.deepEqual(peer.kinds(), ["ACK"], "the reader is still alive");
});

test("a malformed body never stops the reader (ROBUSTNESS.md §3.5)", () => {
  const peer = new CapturingPeer();
  const other = Identity.generate();
  const now = peer.now();
  const kinds = ["PING", "RUMOR", "DIGEST", "PULL_RESP", "GROUP_AD", "PIPE_DATA"];
  kinds.forEach((kind, i) => {
    const env = wire.envelope(GROUP, kind, other.peerId, stamp(now, i),
      Buffer.from([0xff, 0x01, 0x02]), peer.identity.peerId);
    peer.feed(lengthPrefixed(wire.encodeFrame(env, other)));
  });
  // Garbage that does not decode as a frame at all.
  peer.feed(lengthPrefixed(Buffer.from([0xff, 0xff, 0xff, 0xff])));
  assert.ok(peer.malformedFrames >= 1);
  const env = wire.envelope(GROUP, "PING", other.peerId, stamp(now, 50), wire.pingBody(5),
    peer.identity.peerId);
  peer.feed(lengthPrefixed(wire.encodeFrame(env, other)));
  assert.deepEqual(peer.kinds(), ["ACK"], "a well-formed probe after the garbage is answered");
});

/** Accepts connections, decodes what the peer sends, and can close a connection on demand. */
class FakeSeed {
  readonly server: Server;
  readonly connections: Socket[] = [];
  readonly frames: { index: number; kind: string }[] = [];
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
            this.frames.push({ index, kind: String(env["kind"]) });
          }
        }
      });
      socket.on("error", () => undefined);
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

  kindsOn(index: number): string[] {
    return this.frames.filter((f) => f.index === index).map((f) => f.kind);
  }

  close(): void {
    for (const c of this.connections) {
      c.destroy();
    }
    this.server.close();
  }
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

test("a lost socket is reconnected and the peer re-introduces and re-pulls (ROBUSTNESS.md §3.6)", async () => {
  const seed = new FakeSeed();
  await seed.listen();
  const peer = new Peer(Identity.generate(), GROUP);
  peer.reconnectIntervalMs = 100;
  try {
    await peer.connect("127.0.0.1", seed.port);
    peer.pullSpace("work");
    assert.ok(await until(() => seed.kindsOn(0).length >= 3, 5000));
    assert.deepEqual(seed.kindsOn(0), ["RUMOR", "DIGEST", "DIGEST"]);
    // The seed drops the link: a network hiccup from the peer's point of view.
    seed.connections[0].destroy();
    assert.ok(await until(() => seed.kindsOn(1).length >= 3, 5000), "reconnected and re-sent");
    assert.deepEqual(seed.kindsOn(1).slice(0, 3), ["RUMOR", "DIGEST", "DIGEST"],
      "re-introduced, revocations and the space pulled again");
    assert.equal(peer.reconnects, 1);
    assert.ok(peer.connected());
  } finally {
    peer.close();
    seed.close();
  }
  assert.equal(peer.connected(), false);
});

test("a seed that is down is retried until it listens again (ROBUSTNESS.md §3.6)", async () => {
  const seed = new FakeSeed();
  await seed.listen();
  const peer = new Peer(Identity.generate(), GROUP);
  peer.reconnectIntervalMs = 100;
  const port = seed.port;
  try {
    await peer.connect("127.0.0.1", port);
    assert.ok(await until(() => seed.kindsOn(0).length >= 2, 5000));
    seed.close();
    await new Promise((r) => setTimeout(r, 300)); // several refused dials
    assert.equal(peer.reconnects, 0);
    const again = new FakeSeed();
    await new Promise<void>((resolve) => again.server.listen(port, "127.0.0.1", () => resolve()));
    try {
      assert.ok(await until(() => again.kindsOn(0).length >= 2, 5000), "the peer found the seed again");
      assert.deepEqual(again.kindsOn(0).slice(0, 2), ["RUMOR", "DIGEST"]);
      assert.equal(peer.reconnects, 1);
    } finally {
      again.close();
    }
  } finally {
    peer.close();
  }
});

test("close by the owner is final (ROBUSTNESS.md §3.6)", async () => {
  const seed = new FakeSeed();
  await seed.listen();
  const peer = new Peer(Identity.generate(), GROUP);
  peer.reconnectIntervalMs = 100;
  try {
    await peer.connect("127.0.0.1", seed.port);
    await until(() => seed.kindsOn(0).length >= 2, 5000);
    peer.close();
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(seed.connections.length, 1, "no reconnect after the owner's close");
    assert.equal(peer.reconnects, 0);
  } finally {
    seed.close();
  }
});

test("with its redial off a peer leaves a lost link to its owner's next dial (swarm retries, ROBUSTNESS.md §10.3 E5)", async () => {
  // A host whose own durable timer owns every dial, as the workers cell's alarm does, turns the core's redial off.
  const seed = new FakeSeed();
  await seed.listen();
  const peer = new Peer(Identity.generate(), GROUP);
  peer.reconnectIntervalMs = 100;
  peer.redial = false;
  try {
    await peer.connect("127.0.0.1", seed.port);
    assert.ok(await until(() => seed.kindsOn(0).length >= 2, 5000));
    seed.connections[0].destroy();
    assert.ok(await until(() => !peer.connected(), 5000), "the link is down");
    await new Promise((r) => setTimeout(r, 400)); // past every pause of a quick drop
    assert.equal(seed.connections.length, 1, "the core dialed nothing on its own");
    assert.equal(peer.reconnects, 0);
    await peer.connect("127.0.0.1", seed.port);
    assert.ok(peer.connected(), "the owner's dial brings the link back");
    assert.ok(await until(() => seed.kindsOn(1).length >= 2, 5000), "and the peer introduces itself on it");
  } finally {
    peer.close();
    seed.close();
  }
});

test("reconnect rounds back off and go on until the owner closes the peer (swarm retries, ROBUSTNESS.md §10.3 E5)", async () => {
  const peer = new Peer(Identity.generate(), GROUP);
  peer.reconnectIntervalMs = 20;
  const internals = peer as unknown as {
    running: boolean;
    dial(seed: unknown): Promise<void>;
    reconnect(rounds: number, lastTried: number): void;
  };
  const dials: number[] = [];
  internals.running = true;
  peer.seeds = [{ host: "127.0.0.1", port: 9, scheme: "tcp" } as never];
  internals.dial = () => {
    dials.push(Date.now());
    if (dials.length >= 8) {
      internals.running = false; // the owner closes the peer
    }
    return Promise.reject(new Error("refused"));
  };
  internals.reconnect(0, 0);
  assert.ok(await until(() => dials.length >= 8, 5000), `the dials went on: ${dials.length}`);
  const gaps = dials.slice(1).map((t, i) => t - dials[i]!);
  assert.ok(gaps[0]! >= 18 && gaps[2]! >= 75, `the pauses back off: ${gaps}`);
  assert.ok(gaps.every((g) => g <= 120 * 1.25 + 60), `and stop growing at six times the interval: ${gaps}`);
});

test("a seed that drops each link at once gets the backoff and no dial loop (swarm retries, ROBUSTNESS.md §10.6)", async () => {
  // A seed that accepts every dial and closes it at once, as one that refuses this peer or is still starting does:
  // a link that ends within the reconnect interval counts as a failed round of dials.
  const dials: number[] = [];
  const server = createServer((socket: Socket) => {
    dials.push(Date.now());
    socket.destroy();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  const peer = new Peer(Identity.generate(), GROUP);
  peer.reconnectIntervalMs = 100;
  try {
    await peer.connect("127.0.0.1", port);
    await new Promise((resolve) => setTimeout(resolve, 1500));
  } finally {
    peer.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  assert.ok(dials.length >= 2 && dials.length <= 8, `${dials.length} dials in 1.5 s`);
  const gaps = dials.slice(1).map((t, i) => t - dials[i]!);
  assert.ok(gaps.every((g) => g >= 90), `each dial waits its pause: ${gaps}`);
});
