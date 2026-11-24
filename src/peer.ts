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
 * A minimal wire-compatible AgentSpaces peer in TypeScript: joins a Java
 * fleet over TCP in the dial-only posture (by a literal group or by asking a
 * seed for a self-certifying founding document, SPEC §5.1/§10.1), answers
 * SWIM pings, re-leases its self-advertisement, writes signed entries, takes
 * under the LEASE_RACE claim lattice, and reads spaces back through
 * anti-entropy. The trilingual proof: the same wire the Java and Python peers
 * speak. The peer holds frame channels (srad/agentspaces-js.md §3.2) and dials
 * each seed with the dialer its scheme names; the portable core loads in
 * every JavaScript runtime and `@agentspaces/client/node` adds `tcp`.
 */

import * as beacon from "./beacon.js";
import { compare as compareBytes, equals, fromBase64, toHex, utf8 } from "./bytes.js";
import { cryptoPort } from "./crypto.js";
import { CborDouble, CborValue, canonicalMap, dumps, loads, readDocument } from "./cbor.js";
import type { Pdt } from "./pdt/index.js";
import * as pdtCids from "./pdt/cids.js";
import { AgentIdentity, Identity, deriveId, instantIso, parseDurationMillis, parseInstantMillis, spaceIdLocal, verifyAgentCertificateCovering, verifySignedGroupAd } from "./identity.js";
import * as records from "./records.js";
import * as revocation from "./revocation.js";
import * as serving from "./serving.js";
import { SESSION_HELLO_MAX_AGE_MILLIS, SESSION_HINT, Session, parseSessionHello } from "./session.js";
import * as social from "./social.js";
import * as wire from "./wire.js";
import type { Dict } from "./wire.js";
import { DIALER_PACKAGES, Dialer, FrameChannel, defaultDialers } from "./transport.js";
import "./transport/defaults.js";
import { Seed, schemeOf, seedUrl } from "./seed.js";
import { Repeating, TimerPort, systemTimers } from "./platform.js";
import { DueLoop, Watchdog, monotonicMillis, monotonicOf } from "./time.js";
import { RedialTable } from "./redial.js";
import { AuditedSets, TrackedMap } from "./audited.js";
import type { Holding } from "./audited.js";
import { BUDGET_CEILING, LATE_COPY_MILLIS, TrieAudit } from "./audit.js";
import type { AuditSignals, TreeNode } from "./audit.js";
import * as horizon from "./horizon.js";
import { entryIdOf, hasControl } from "./trie.js";
import type { HashTrie } from "./trie.js";

const wireSpaceId = (group: string, space: string): string => spaceIdLocal(`${group}/${space}`);

function sleep(millis: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, millis));
}

/**
 * The join through a beacon document waits in slices of 1 s, 2 s, 4 s, then 5 s each inside
 * its budget: the schedule of the Java join by id (ISSUE-BootstrapRobustness §9.4).
 */
const JOIN_SLICE_FIRST_MS = 1_000;
const JOIN_SLICE_MAX_MS = 5_000;

/**
 * `Peer.bootstrap` spent its `joinTimeoutMs`: the message and the fields say how many times
 * the document was fetched, how many seeds were dialed and how many of them connected, and
 * `cause` is the last error.
 */
export class BootstrapTimeoutError extends Error {
  constructor(message: string, readonly fetches: number, readonly dialed: number, readonly connected: number,
    cause: unknown) {
    super(message, { cause });
    this.name = "BootstrapTimeoutError";
  }
}

/** A join-by-GroupID in flight: the group wanted and its resolver (§10.1). */
interface PendingFounding {
  group: string;
  resolve(signed: Dict): void;
}

/** An advertisement as the cache holds it. */
export type CachedAd = { type: string; ad: Dict; stored: Dict; issuer: string; expires: number };

export type { Seed } from "./seed.js";

/** Lets a repeating timer stop holding a Node process open; other runtimes have no unref. */
function unref(timer: unknown): void {
  const t = timer as { unref?: () => void };
  if (typeof t?.unref === "function") {
    t.unref();
  }
}

/** What {@link Peer.joinInvite} yields: the group joined and the content key the secret derives. */
export type InviteJoined = {
  groupId: string;
  /** The group's content key, epoch 0, 32 bytes (SRAD §3.8). */
  contentKey: Uint8Array;
  /** The delegation the credential was issued under (base64 CBOR), from the key or the document. */
  delegation: string;
  key: social.InviteKey;
  /**
   * The key pinned to that delegation, compact form. Persist it and join with it next time:
   * the members that admitted this peer re-admit it after the key's window only under the
   * same credential (SPEC §5.1, v0.1.20), and the beacon document may carry a newer
   * delegation by then. Ed25519 is deterministic, so the same pinned key gives the same credential.
   */
  pinnedKey: string;
};

/**
 * One accepted connection of a peer that listens (JS-R-04): its channel, the
 * session established on it (one per connection, SPEC §5.6), and the members
 * heard on it, which addressed frames to them follow.
 */
export type Link = { channel: FrameChannel; session: Session | null; readonly peers: Set<string> };

/**
 * The content swarm's seam on a peer (SPEC §7.1 group E): a payload above `escalateAbove` is
 * published as an artifact and the record carries its root; a read resolves the root here.
 */
export interface BulkPayloads {
  readonly escalateAbove: number;
  publishOpaque(payload: Uint8Array, leaseMillis: number): string;
  local(root: string): Uint8Array | null;
  ensure(root: string): void;
  /** Releases a root no held entry references any more, once its entry is collected (LB-E-04). */
  unpin(root: string): void;
}

/**
 * The wire hint this client advertises (SPEC v0.1.17 §9, srad/agentspaces-pdt.md §3.9, PD-L-04): a
 * renew, cancel, or complete may reach it as an EntryStateDto without its record (PD-L-01); it merges
 * the state over the record it holds or keeps it pending, without an event, until the record arrives.
 */
export const RECORDLESS_HINT = "wire.recordless";

/** The most recordless states kept pending for records that have not arrived (PD-L-02). */
export const MAX_PENDING_RECORDLESS = 1024;

/**
 * The hint of the hashed anti-entropy round (SPEC v0.1.17 §5.3): a round toward a member that carries it opens with a
 * hash per stream and sends the full text only for the streams that differ.
 */
export const HASHES_HINT = "wire.hashes";
/**
 * The hint of replication by entry (SPEC annex I.6, v0.1.35; srad/replication-by-entry.md RE-T-02): `wire.ae=2`, a value
 * in the hints map. Between two members that carry it a round audits each space by its fingerprinted trie and fetches
 * the entries that differ by id, under a budget.
 */
export const AE_HINT = "wire.ae";
/** The value of {@link AE_HINT} this build implements; a later form would be a new value. */
export const AE_LEVEL = "2";
/**
 * The hint of the per-entry horizon (SPEC §7.3, v0.1.35; RE-H-04): `wire.horizon=1` promises that every writer behind
 * this member renews by §7.2 (issuer only, present and unexpired, never shorter) and from one node per identity.
 */
export const HORIZON_HINT = "wire.horizon";
/** The value of {@link HORIZON_HINT} this build implements. */
export const HORIZON_LEVEL = "1";
/** Streams a probe carries per-stream hashes for at most; above it the probe carries their root (SPEC §5.2, RE-T-07). */
export const PROBE_HASH_STREAMS = 32;
/** Rounds this peer's own anti-entropy must have been quiet before a probe's differing hashes open one (SPEC §5.2). */
export const PROBE_QUIET_ROUNDS = 4;
/** Budgeted text pulls continued at once per partner per round, at most: the session bound of annex I.6. */
export const PULL_CONTINUATIONS_MAX = 64;
/** How long the acknowledgement of a re-offered collected tombstone is held after its last refusal (RE-H-03). */
export const COLLECTED_ACK_HOLD_MILLIS = horizon.LAPSED_GRACE_MILLIS;
/** The anti-entropy form a round toward a member takes, read from its current card. */
export type Form = "ae" | "hashes" | "text";
/**
 * The replication settings a host reads from its options (srad/replication-by-entry.md §7.2): `audit` advertises
 * `wire.ae=2` and uses the audit toward members that carry it (on by default), `auditBudget` is the bytes this member
 * asks an answer to stay within (1 MiB by default, 4 KiB to 4 MiB), and `horizon` is `per-entry` (the default) or
 * `legacy`. Each is refused when it is out of bounds or misspelt.
 */
/**
 * A host's replication settings (srad/replication-by-entry.md §7.2), each absent for the default: `audit` (true,
 * Java's `agentspaces.gossip.audit`), `auditBudget` in bytes (1 MiB, `audit-budget`), `auditSessions` per asker (4,
 * `audit-sessions`) and `horizon` (`per-entry`, `agentspaces.space.horizon`).
 */
export type ReplicationOptions = {
  audit?: boolean; auditBudget?: number; auditSessions?: number; horizon?: "per-entry" | "legacy";
};

/**
 * The hint a peer advertises once every decoder it runs reads the v0.1.32 schemas of the AppCard and the AgentCard
 * (`wire.appcard=2`; SPEC §6.1a.2, §9; AppCard origin and formats, 2026-11-09): canonical decimal text, read as
 * level N or above. An issuer writes a card's origin, formats, an `idp` host, and a spill reference only while every
 * member it knows is at level 2.
 */
export const APPCARD_HINT = "wire.appcard";
/** The AppCard level this build reads and, by default, advertises. */
export const APPCARD_LEVEL = 2;

/**
 * The AppCard level a hint's text states, as Java's `PeerNode.appCardLevelOf` reads it: 1 for no hint, any text
 * that is not canonical decimal (a leading zero, a sign, a space), or a value below 1; a value past nine digits reads
 * as the largest int.
 */
export function appCardLevelOf(text: unknown): number {
  if (typeof text !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(text)) {
    return 1;
  }
  return text.length > 9 ? 2_147_483_647 : Math.max(1, Number(text));
}

/** The advertisement cache's default entry bound (ASF-019) and byte budget (SPEC §6.3, v0.1.32), as Java's AdCache. */
export const AD_CACHE_MAX_ENTRIES = 8_192;
export const AD_CACHE_MAX_BYTES = 33_554_432;

/** How often a peer that holds parts documents for its stubs checks whether one may lapse. */
const SPILL_SWEEP_MILLIS = 5_000;

/**
 * Where a publisher puts a stub card's parts document and a reader fetches it (SPEC §6.1a.5, v0.1.32;
 * ISSUE-AppCardOriginFormats §9.8; AppCard origin and formats, 2026-11-09): the group's content swarm, whose
 * `ContentSpillStore` (`capabilities/content`) installs itself on the peer it attaches to. With none installed a
 * publisher never spills and {@link Peer.resolve} fails a stub.
 */
export interface SpillStore {
  /**
   * Publishes a parts document as a content-swarm artifact in 65,536-byte pieces, manifest `name`, media type
   * `application/cbor`, sealing `none`, and keeps it served until {@link release}; returns its root. The same bytes
   * give the same root. Throws when the swarm does not take the document.
   */
  put(name: string, document: Uint8Array): string;
  /**
   * Fetches a parts document, every piece verified against the root. Rejects with a {@link SpillRefusedError} when
   * the artifact's length is not `size`, found from its manifest before a piece is fetched, and with another error
   * when no holder serves it within the store's deadline.
   */
  get(root: string, size: number): Promise<Uint8Array>;
  /** Stops keeping a root served on behalf of the cards that named it, so the artifact lapses. */
  release(root: string): void;
}

/** A parts document that does not complete its stub (SPEC §6.1a.5, FR-15): counted in `spillsRefused`. */
export class SpillRefusedError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "SpillRefusedError";
  }
}

/**
 * A card this peer issues under the AppCard level: the full card, its type, the last issue instant signed, and the
 * gate it was last issued under (null before its first issue), so a change of the members' level reissues exactly the
 * cards that went out under the other gate (AppCard origin and formats, 2026-11-09, adversary pass).
 */
interface IssuedCard { adType: "AppCard" | "AgentCard"; full: Dict; issued: number; open: boolean | null }

/**
 * How many distinct refused states and claims a replica remembers so a re-offer counts no second
 * refusal, as Java's ReplicatedSpace REJECTED_OFFERS_CAP (HLC canonical stamps, 2026-11-08); the
 * same cap bounds the deferred offers (HLC round four, 2026-11-08). Past the cap each memory forgets
 * its least recently offered key, as Java's access-ordered maps do (HLC round five, 2026-11-08, E14).
 */
const MAX_REFUSED_STAMPS = 4096;

/**
 * How many refused-and-acknowledged digest lines a replica keeps, Java's ReplicatedSpace
 * REFUSED_ACK_CAP (HLC round six, 2026-11-08, R7), the least recently refused forgotten first.
 */
export const MAX_REFUSED_ACK = 8192;

/**
 * How long an entry whose write lease lapsed stays held past its expiry, at most (SPEC §7.3, Java's
 * SpaceStateCrdt.LAPSED_GRACE_MILLIS). HLC round five, 2026-11-08: a lapse needs no long tombstone,
 * since every replica judges the same lease stamp lapsed; a completion or a withdrawal keeps twice
 * the longest lease, so every replica that could still learn of it has two full leases to do so.
 */
export const LAPSED_GRACE_MILLIS = 5 * 60_000;

/**
 * The ceiling on the lease that feeds the collection horizon (SPEC §7.3, Java's
 * MAX_TRACKED_LEASE_MILLIS, HLC round five, 2026-11-08): one member's century-long lease cannot stop
 * collection fleet-wide.
 */
export const MAX_TRACKED_LEASE_MILLIS = 24 * 60 * 60_000;

/** How often a replica collects its tombstones (SPEC §7.3). */
const COLLECT_PERIOD_MILLIS = 1000;
/** The tombstone collection's name on the peer's loop. */
const COLLECT_TASK = "collect";

/**
 * A forward wall step longer than this is a resume (SPEC v0.1.36 §9.5): the 30 s member TTL a 0.6.0 Java member judges
 * this peer by, the keepalive bound every Java member keeps; a peer silent that long may have left other members' views.
 */
export const RESUME_STEP_MILLIS = 30_000;
/**
 * The dead-seed rule for a dial-only link (owner decision 1 of 2026-11-23): a dialed channel this peer has read nothing
 * from for this long is asked with a PING to the seed, which answers every PING at once (SPEC §5.2). 1.5 times the
 * 30 s keepalive bound a member keeps, so a live seed in a quiet group is asked rarely, and a seed whose own probes or
 * relayed PINGs keep the link busy is never asked.
 */
export const LINK_QUIET_MILLIS = 45_000;
/**
 * A link asked and still silent this long after the PING is dead: a seed that left without a FIN (power loss, a
 * partition, a laptop moved to another network) is otherwise read from until TCP gives up, minutes later, so this peer
 * would not fail over and its relay.via would go on naming a holder that is gone. The channel is closed and the close
 * signal fails over to another seed (the silent one is dialled last). This is the ping timeout,
 * 2 s, the one a prober gives each PING (SPEC §9.4, the core's `GroupMembership`), as the decision names it and as
 * Python's `LINK_ANSWER_S` keeps it.
 */
export const LINK_ANSWER_MILLIS = 2_000;
/**
 * How long a wake holds off judging the members whose advertisement lapsed while this peer did not run (owner decision
 * 3 of 2026-11-23): each is PINGed first, and dropped only if it stays silent this long. 1.5 times the 2 s ping timeout
 * ({@link LINK_ANSWER_MILLIS}), since the PING and its answer may each cross the seed.
 */
export const WAKE_PROBE_MILLIS = 3_000;
/**
 * The bucket a dial-only peer answers each asker's relayed or non-seed DIGESTs from (owner decision 1 of 2026-11-23):
 * at most this many at once, refilled at {@link RELAYED_ANSWER_PER_SECOND}, one bucket per asker (the cross-client
 * check of 2026-11-23: a shared bucket let one member flooding relayed DIGESTs starve every winner's targeted round).
 * The Rust figures; the same in every client.
 */
export const RELAYED_ANSWER_BURST = 16;
export const RELAYED_ANSWER_PER_SECOND = 4;
/** At most this many askers' buckets are kept; the one asked least recently goes first. */
export const RELAYED_ANSWER_ASKERS = 1_024;
/**
 * How long a member that answered a wake's probe is kept with a lapsed advertisement, waiting for a fresh one (the
 * wake's view pull, or the member's own refresh): 1.5 times the 60 s refresh a dial-only member keeps
 * ({@link SELF_AD_REFRESH_MILLIS}). It is judged by its advertisement again after that.
 */
export const WAKE_KEEP_MILLIS = 90_000;
/**
 * The connection attempt delay between the starts of two seed dials (owner decision 2 of 2026-11-23, RFC 8305 Happy
 * Eyeballs): the seeds are dialled in list order, one start every 250 ms, and a dial that fails starts the next at once.
 */
export const SEED_STAGGER_MILLIS = 250;
/** The most seed dials of one round in flight at once (a seed name may expand to many addresses), as Rust, Python and Ruby. */
export const SEED_DIALS_IN_FLIGHT_MAX = 16;
/** The due-work task that judges the dialed link by the dead-seed rule. */
const SEED_LINK_TASK = "seed-link";
/** The task that re-leases this peer's self-advertisement while a dialed link holds (see {@link SELF_AD_REFRESH_MILLIS}). */
const SELF_AD_TASK = "self-ad";
/**
 * How often a dial-only peer re-issues its self-advertisement on its link (SPEC §5.2: every member periodically
 * republishes it). A member that dropped this peer for silence (a sleep, a lost relay) admits it again only on an
 * advertisement issued after the drop, and a peer that re-issued nothing while its link held stayed out of that view
 * for good (the mixed idle run of 2026-11-23: a Java member slept 60 s never held the TypeScript members again).
 * The rumor is flooded by the seed, so card readers of other dial-only members hold a live card too.
 */
export const SELF_AD_REFRESH_MILLIS = 60_000;

/**
 * How long a relayed probe waits for the target's ACK before it is forgotten. A prober waits one ping timeout for the
 * relay's answer (about a second in the reference implementation); 10 s is generous, and only bounds memory.
 */
export const RELAY_HOLD_MILLIS = 10_000;
/** The most PING_REQ relays held at once; past it the eldest is forgotten. */
export const MAX_RELAYS = 4_096;

/** At most this many displaced claims, or unproven completions, per entry (SPEC §7.4; Java DISPLACED_PER_ENTRY). */
export const DISPLACED_PER_ENTRY = 4;
/** At most this many offers of one displaced claim (Java REOFFER_MAX). */
export const REOFFER_MAX = 6;
/** The first backoff between offers of a displaced claim; it doubles after each (Java REOFFER_BACKOFF_MILLIS). */
export const REOFFER_BACKOFF_MILLIS = 1_000;
/** At most this many entries per settle map; past it the eldest goes (Java OUTBID_COMPLETIONS_CAP). */
export const SETTLE_LINES_CAP = 1_024;
/**
 * At most this many targeted anti-entropy rounds toward the holders one entry's winning claim displaced (Java
 * DISPLACED_PULL_MAX, owner decision 4 of 2026-11-23): at once, then after 1, 2, 4, 8 and 16 s.
 */
export const DISPLACED_PULL_MAX = 6;
/** The due-work task that opens the targeted rounds toward displaced holders. */
const DISPLACED_PULL_TASK = "displaced-pull";

/** Forgets the eldest lines of an insertion-ordered map past SETTLE_LINES_CAP. */
function capLines(map: Map<string, unknown>): void {
  while (map.size > SETTLE_LINES_CAP) {
    map.delete(map.keys().next().value as string);
  }
}

/** The peer part of a claim's holder (`<peer>/<agent>`). */
function holderPeer(claim: Dict): string {
  const holder = String(claim["holder"] ?? "");
  const slash = holder.indexOf("/");
  return slash < 0 ? holder : holder.substring(0, slash);
}

/** Whether two claims are the same claim (every field). */
function sameClaim(a: Dict, b: Dict): boolean {
  return equals(dumps(a), dumps(b));
}

/** One watchdog per timer port: the runtime's timers share one per process, a test's virtual time has its own. */
const watchdogs = new WeakMap<object, Watchdog>();

/** The shared watchdog of a timer port. */
export function watchdogFor(timers: TimerPort): Watchdog {
  let dog = watchdogs.get(timers);
  if (dog === undefined) {
    dog = new Watchdog(timers);
    watchdogs.set(timers, dog);
  }
  return dog;
}

/**
 * After its settle window a take pulls the space once more and waits up to this long for the answer to fold,
 * so a rival claim that push gossip dropped still reaches the judgement. Java has no such wait.
 */
const TAKE_FOLLOW_UP_MAX_MILLIS = 300;

/** The take's follow-up wait after a settle window of `settleMillis`. */
function takeFollowUpMillis(settleMillis: number): number {
  return Math.min(Math.max(0, settleMillis), TAKE_FOLLOW_UP_MAX_MILLIS);
}

/**
 * How long after its claim goes out a take may be judged in a quiet space: the whole settle window, then
 * the follow-up wait, which ends early only when something folds. A take lease must be longer than this,
 * since only a live claim wins. For the default window of 600 ms the bound is 900 ms.
 */
export function takeJudgedWithinMillis(settleMillis: number): number {
  return Math.max(0, settleMillis) + takeFollowUpMillis(settleMillis);
}

/** Whether a `b` reference names a persistent tree (dag-cbor) rather than a piece artifact. */
function isTreeRoot(ref: string): boolean {
  try {
    return pdtCids.parse(ref).codec === pdtCids.DAG_CBOR;
  } catch {
    return false;
  }
}

export class Peer {
  /**
   * Moves on every change to the states, the claims and the acknowledged lines, which are all a space's text digest
   * reads, so the digest is built once per change rather than once per probe (adversarial review of 2026-11-15).
   */
  private replicaVersion = 0;
  // Every change to these maps names its entry to the audited sets (annex I.6), wherever it is made.
  readonly states: Map<string, Dict> = new TrackedMap<string, Dict>().track((id, before, after) => {
    this.replicaVersion += 1;
    this.audited.touched(id);
    if (after === undefined || !this.joinedStates.has(after)) {
      this.signedStates.delete(id); // a state stored as signed is its own signed copy
    }
  });
  readonly claims: Map<string, Dict> = new TrackedMap<string, Dict>().track((id) => {
    this.replicaVersion += 1;
    this.audited.touched(id);
  });
  /** Recordless states for entries whose record has not arrived yet, by entry id (PD-L-02). */
  readonly pendingStates = new Map<string, Dict>();
  /** The founding advertisement this peer joined with, when it joined by GroupID. */
  founding: Dict | null = null;
  private channel: FrameChannel | null = null;
  /**
   * The channel authentication mode (PeerNode.ChannelAuth): `session` (the default, and the
   * dev-local profile's) advertises `wire.session=1` and, on a channel the transport cannot
   * attest, establishes a session with a member that advertises the same, after which frames
   * to it carry a tag in place of a signature (SPEC §5.6, v0.1.17); `signed` signs every frame.
   */
  channelAuth: "signed" | "session" = "session";
  /** The members whose advertisement carries the session hint. */
  readonly sessionPeers = new Set<string>();
  private session: Session | null = null;
  /**
   * The connections a listener handed this peer (a service host), each with its own session and
   * the members heard on it; the dialed channel above stays the route for everyone else.
   */
  readonly inbound = new Map<FrameChannel, Link>();
  /** The endpoints this peer's advertisement names (a host's listeners); empty is the dial-only posture. */
  readonly endpoints: Dict[] = [];
  /** How many hops a rumor this peer originates may travel (GossipBus defaultHops). */
  rumorHops = 6;
  /** Rumors forwarded to other links (a host relays what one connection brings to the others). */
  rumorsForwarded = 0;
  /** DIGESTs answered with a PULL_RESP, and PING_REQs relayed. */
  pullsAnswered = 0;
  pingsRelayed = 0;
  /** How many rumor keys stay remembered for duplicate suppression: a cache size, not a cap on anything. */
  rumorMemory = 65_536;
  private readonly rumorsSeen = new Set<string>();
  /**
   * PING_REQ relays in flight: the relay nonce to who asked, their nonce, the target vouched for, and when the relay's
   * PING went out on the monotonic clock. Bounded by time ({@link RELAY_HOLD_MILLIS}) and size ({@link MAX_RELAYS}):
   * under the targeted relay (SPEC v0.1.36 §5.2) a member named in `relay.via` receives about one PING_REQ per prober
   * per quiet cycle for each dial-only peer it holds, and a target that never answers must not grow the table.
   */
  private readonly relays = new Map<string, { origin: string; originNonce: number | bigint; target: string; at: number }>();
  /** PING_REQs dropped because this peer holds no route to the target (no link, no dialed channel). */
  pingReqsUnroutable = 0;
  /** Relays forgotten unanswered past their hold, or evicted by the size bound. */
  relaysExpired = 0;
  /** Frames sent under a session key rather than a signature. */
  sessionFramesSent = 0;
  /** Session hellos ignored as older than the hello age window (never a strike). */
  framesStale = 0;
  /**
   * States and claims this replica refused because a stamp they carry (a record's `issued`, a
   * state's `leaseStamp` or `signedAt`, a claim's `stamp`) decodes with a logical counter above
   * wire.LOGICAL_LIMIT (HLC logical counter, 2026-11-08, Rust team report). Rumors, anti-entropy,
   * snapshots and committed claims all fold through the same check. This peer keeps no strikes, so
   * the count records each refusal: after the signatures verify, since an unverified carrier names
   * no signer, and once per distinct offer, keyed on signed content alone, since a re-offer is no
   * new refusal. The name is Java's ReplicatedSpace counter (HLC round four, 2026-11-08, D5).
   */
  stampsLogicalRefused = 0;
  /**
   * States and gossiped claims this replica refused as hostile because a stamp they carry lies more
   * than wire.FAR_FUTURE_HOSTILE_MILLIS past its wall + MAX_HLC_SKEW_MILLIS +
   * FAR_FUTURE_MARGIN_MILLIS, counted as stampsLogicalRefused is (HLC round four, 2026-11-08, D4).
   */
  stampsFarFutureRefused = 0;
  /**
   * Distinct states and gossiped claims this replica deferred because a stamp lies past that
   * margin by at most wire.FAR_FUTURE_HOSTILE_MILLIS: neither merged, acknowledged, nor taken for
   * misbehaviour, each merges when anti-entropy offers it after this replica's wall catches up (HLC
   * round four, 2026-11-08, D4). The names are Java's ReplicatedSpace counters.
   */
  stampsFarFutureDeferred = 0;
  /** The distinct deferred states and claims counted above, the eldest forgotten past the cap. */
  private readonly deferredStamps = new Set<string>();
  /**
   * Space deltas, by rumor or by anti-entropy, and snapshot entries this replica dropped because
   * they did not decode: bytes that are no delta, or a delta holding a stamp that is no canonical
   * CBOR text (HLC round four, 2026-11-08, D3). Such a carrier names no verified signer. The name
   * is Java's ReplicatedSpace counter.
   */
  deltasUndecodable = 0;
  /** The distinct refused states and claims counted above, the eldest forgotten past the cap. */
  private readonly refusedStamps = new Set<string>();
  /**
   * The digest lines (`e:<entry>=<state hash>`) of verified states this replica refused for their
   * stamps, by line with the state's SpaceId, the eldest forgotten past the cap. Each digest names
   * them as `a:<line>`, as Java's acknowledges them, so partners stop re-offering them (HLC round
   * four, 2026-11-08, D5).
   */
  private readonly refusedAck: Map<string, string> = new TrackedMap<string, string>()
    .track((line, before, after) => {
      this.replicaVersion += 1;
      this.ackChanged(line, before, after);
    });
  /** The dialers this peer dials with, by scheme; the registered defaults at construction. */
  readonly dialers = new Map<string, Dialer>();
  private pendingFounding: PendingFounding | null = null;

  /**
   * @param group the GroupID this peer belongs to (a literal-founding id, or
   *              the self-certifying id {@link joinByGroupId} will verify)
   */
  /**
   * @param now epoch milliseconds; a test pins it to verify time-bound material
   *            (agent certificates) against a fixed instant, as Java's TestClock does
   */
  /**
   * The group's revocations (SPEC §5.6, v0.1.13), verified founder-rooted
   * (when the founder is known, from `founder` or the verified founding
   * document) or, for an agent and its keys, by the agent's own peer.
   */
  revocations: revocation.Registry;

  constructor(readonly identity: Identity, public group: string,
              readonly now: () => number = Date.now, private readonly founder: string | null = null) {
    this.revocations = new revocation.Registry(() => this.founderId(), () => this.group);
    for (const dialer of defaultDialers()) {
      this.dialers.set(dialer.scheme.toLowerCase(), dialer);
    }
  }

  /** The timers this peer schedules on (JS-P-10); a test installs a fake before using the peer. */
  timers: TimerPort = systemTimers;
  private readonly repeating: Repeating[] = [];

  /** This peer's monotonic clock, for local periods (SPEC v0.1.36 §9.5): its timers' `now()`, else the runtime's. */
  monotonic(): number {
    return monotonicOf(this.timers)();
  }

  private dueLoop: DueLoop | null = null;
  private unwatchLoop: (() => void) | null = null;

  /**
   * This peer's due work (srad/agentspaces-event-loop.md §3.2, parity for this client): one sequential loop on this
   * peer's timers that runs each task when its deadline falls due or when a fold wakes it, in place of fixed-rate
   * tickers. Made on first use, on the timers installed then (a test installs {@link VirtualTime} first), watched by
   * the {@link watchdog}, and stopped by {@link close}. Hosts add their own tasks to it.
   */
  get loop(): DueLoop {
    if (this.dueLoop === null) {
      const loop = new DueLoop(this.timers, {
        wall: () => this.now(),
        name: `peer ${this.identity.peerId.slice(0, 12)}`,
        log: (line) => this.onLoopLog?.(line),
        onWallStep: (step) => this.onWallStep(step),
        onLateWake: (late) => this.onLateWake(late),
      });
      this.dueLoop = loop;
      this.unwatchLoop = (this.watchdog ?? watchdogFor(this.timers)).watch(loop);
    }
    return this.dueLoop;
  }

  /** Re-arms the loop {@link close} paused (a peer that dials again keeps its tasks), or makes it. */
  private openLoop(): void {
    const loop = this.loop;
    if (loop.isPaused) {
      loop.resume();
      this.unwatchLoop = (this.watchdog ?? watchdogFor(this.timers)).watch(loop);
    }
  }

  /** The watchdog this peer's loop registers with; the per-timers shared one when null (one per process for real time). */
  watchdog: Watchdog | null = null;
  /** Where the loop reports a failed task or a re-arm; nowhere by default. */
  onLoopLog: ((line: string) => void) | null = null;
  /** Wall steps longer than {@link RESUME_STEP_MILLIS} forward this peer answered with a resume (SPEC §9.5). */
  resumes = 0;

  /**
   * A wall step the loop saw (an NTP step, or a suspend that the monotonic clock did not count). Every deadline the
   * loop holds is asked again by the loop itself. A forward step longer than the member TTL other members judge this
   * peer by is a resume (SPEC §9.5, EL-C-14): this peer re-introduces itself on every link at once and pulls the view,
   * so it rejoins without waiting for a probe cycle, and PINGs its seed under the dead-seed rule ({@link resume}).
   */
  protected onWallStep(stepMillis: number): void {
    this.onWallStepListeners.forEach((listener) => listener(stepMillis));
    if (stepMillis > RESUME_STEP_MILLIS) {
      this.resume();
    }
  }

  /**
   * The watchdog's tick came back `lateMillis` past its period with no wall step: a runtime whose monotonic clock
   * counts a suspend (some browsers' `performance.now()`), or a process frozen that long. The members have judged this
   * peer silent just the same, so it is a resume too.
   */
  protected onLateWake(lateMillis: number): void {
    this.onLateWakeListeners.forEach((listener) => listener(lateMillis));
    if (lateMillis >= RESUME_STEP_MILLIS) {
      this.lateWakeResumes += 1;
      this.resume();
    }
  }

  /** Resumes started by a late watchdog tick rather than a wall step. */
  lateWakeResumes = 0;

  /**
   * Re-introduces this peer after a suspend (SPEC §9.5, EL-C-14) and checks its seed (owner decision 3 of 2026-11-23).
   * With the link up, the seed is PINGed and the dead-seed rule applies: no frame within the ping timeout
   * ({@link LINK_ANSWER_MILLIS}) closes the link and fails over at once. With no link, the seeds are dialled at once.
   * Either way the redial table starts again from its first wait.
   */
  private resume(): void {
    if (this.running) {
      this.resumes += 1;
      this.redialTable.reset(); // a wake redials at once, and any later wait starts from the table's first
      if (this.channel !== null) {
        // The socket may be dead without knowing it, and the seed may have dropped this peer while it slept. A PING
        // costs one frame where a redial costs a handshake, and the same rule judges the link as everywhere else.
        // A PING already waiting is not sent again (as every client): it becomes the wake's ask.
        if (this.seedAskedAt === null) {
          this.wakePings += 1;
          this.askSeed(this.monotonic());
          this.seedVerdictFor = null;
        }
        this.wakeAsked = this.seedAskedAt;
        this.loop.reschedule(SEED_LINK_TASK, this.seedAskedAt! + LINK_ANSWER_MILLIS);
      } else if (this.reconnectTimer !== null) {
        // Asleep while backing off between dials: the pause was judged on a clock that did not count the suspend, so
        // the rest of it would still be waited out after the wake. The resume dials at once instead.
        this.resumeRedials += 1;
        this.timers.clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
        this.reconnect();
      }
      if (this.channel !== null || this.inbound.size > 0) {
        this.introduce();
        this.pullView();
      }
      this.probeLapsedMembers();
    }
  }

  /** Members a wake PINGed before judging them, and those that answered (monotonic instant of the answer). */
  private readonly wakeSuspects = new Set<string>();
  private readonly wakeAnswered = new Map<string, number>();
  /** When the wake's probes are judged (monotonic), or null with none out. */
  private wakeJudgeAt: number | null = null;
  /** Members a wake PINGed because their advertisement lapsed while this peer did not run, and those that answered. */
  wakeMemberProbes = 0;
  wakeProbesAnswered = 0;
  /** Drops {@link expireMembers} held back for a wake's probe, or for a member that answered one. */
  wakeDropsDeferred = 0;

  /**
   * Owner decision 3 of 2026-11-23: before judging members by elapsed time after a wake, re-probe them. Each member
   * heard on no link of this peer's whose advertisement lapsed is PINGed (through the seed when it is not on a link
   * of this peer's own), and {@link expireMembers} holds its drop for {@link WAKE_PROBE_MILLIS}: a member whose age
   * is past its TTL only because this peer was frozen or asleep gets a probe, not a drop.
   */
  private probeLapsedMembers(): void {
    const now = this.now();
    const linked = new Set(this.linkedMembers());
    let probed = false;
    for (const [peer, ad] of this.members) {
      if (linked.has(peer) || peer === this.identity.peerId || !this.adLapsed(ad, now)) {
        continue;
      }
      this.wakeSuspects.add(peer);
      this.wakeMemberProbes += 1;
      probed = true;
      this.sendAddressed("PING", wire.pingBody(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)), peer);
    }
    if (probed) {
      this.wakeJudgeAt = this.monotonic() + WAKE_PROBE_MILLIS;
    }
  }

  /** Whether an advertisement's lease has passed at `now` (wall); an unreadable or issue-less one never lapses here. */
  private adLapsed(ad: Dict, now: number): boolean {
    if (ad["issued"] === undefined) {
      return false;
    }
    try {
      return parseInstantMillis(ad["issued"]) + parseDurationMillis(ad["ttl"]) <= now;
    } catch {
      return false;
    }
  }

  /** A member a wake probed was heard: it is kept for {@link WAKE_KEEP_MILLIS} while its fresh advertisement comes. */
  private heardSuspect(peer: string): void {
    if (this.wakeSuspects.delete(peer)) {
      this.wakeProbesAnswered += 1;
      this.wakeAnswered.set(peer, this.monotonic());
    }
  }

  /**
   * Whether {@link expireMembers} holds a lapsed member's drop after a wake: its probe still waits, or it answered one
   * within {@link WAKE_KEEP_MILLIS}. Ends the wake's window once it has passed.
   */
  private wakeHolds(peer: string, mono: number): boolean {
    if (this.wakeJudgeAt !== null && mono >= this.wakeJudgeAt) {
      this.wakeSuspects.clear();
      this.wakeJudgeAt = null;
    }
    if (this.wakeSuspects.has(peer)) {
      return true;
    }
    const answered = this.wakeAnswered.get(peer);
    if (answered !== undefined && mono - answered < WAKE_KEEP_MILLIS) {
      return true;
    }
    this.wakeAnswered.delete(peer);
    return false;
  }

  /** Reconnect pauses a resume cut short to dial at once. */
  resumeRedials = 0;
  /** PINGs to the seed a resume sent with the link up (the dead-seed rule then judges the link). */
  wakePings = 0;
  /** The ask a resume made; its verdict fails over at once, however young the link (see {@link failoverClosed}). */
  private wakeAsked: number | null = null;
  /** The dialed channel the dead-seed verdict after a wake closed: its close fails over at once, no quick drop. */
  private failoverClosed: FrameChannel | null = null;
  /** The seed whose link last ended while this peer ran; every round dials it last (owner decision 2 of 2026-11-23). */
  private lostSeedUrl: string | null = null;
  /** Seed dials started, and channels that opened after another seed had won and were closed. */
  seedDials = 0;
  lateSeedChannels = 0;
  /** The pause before the next round of reconnect dials, on this peer's timers. */
  private reconnectTimer: unknown = null;

  private readonly onWallStepListeners: Array<(stepMillis: number) => void> = [];

  /** Hears every wall step this peer's loop sees (a host re-dials its seed on a resume). */
  onWallStepped(listener: (stepMillis: number) => void): () => void {
    this.onWallStepListeners.push(listener);
    return () => {
      const i = this.onWallStepListeners.indexOf(listener);
      if (i >= 0) {
        this.onWallStepListeners.splice(i, 1);
      }
    };
  }

  private readonly onLateWakeListeners: Array<(lateMillis: number) => void> = [];

  /**
   * Hears every late wake this peer's loop sees: a watchdog tick that came back long past its period with no wall step,
   * a suspend the monotonic clock counted (the other half of a wake, beside {@link onWallStepped}).
   */
  onLateWoke(listener: (lateMillis: number) => void): () => void {
    this.onLateWakeListeners.push(listener);
    return () => {
      const i = this.onLateWakeListeners.indexOf(listener);
      if (i >= 0) {
        this.onLateWakeListeners.splice(i, 1);
      }
    };
  }

  /** Runs `fn` every `periodMillis` on this peer's timers until {@link close}; never holds a Node process open. */
  every(periodMillis: number, fn: () => void): Repeating {
    const handle = this.timers.every(periodMillis, fn);
    this.repeating.push(handle);
    return handle;
  }

  /** Adds (or replaces) the dialer for its scheme. */
  registerDialer(dialer: Dialer): this {
    this.dialers.set(dialer.scheme.toLowerCase(), dialer);
    return this;
  }

  /** The schemes this peer can dial. */
  dialableSchemes(): string[] {
    return [...this.dialers.keys()];
  }

  /** The channel the peer's link is on, if any. */
  currentChannel(): FrameChannel | null {
    return this.channel;
  }

  // ROBUSTNESS.md: late, replayed and unknown frames are the normal case; count, never fail.
  readonly frames = new wire.FrameFilter();
  readonly ignoredKinds = new Map<string, number>();
  /** Frames accepted bare under the dialed channel's attestation (SPEC §5.6), after this peer's CHANNEL_HELLO. */
  attestedFrames = 0;
  /** The dialed channel a CHANNEL_HELLO went out on, so one announcement serves one connection. */
  private helloSentOn: FrameChannel | null = null;
  malformedFrames = 0;
  // A lost socket is reconnected to the seeds, dialled in list order 250 ms apart with the first to open winning and
  // the lost seed last, a wait from the redial table after every round in which none opened, and the peer
  // re-introduced and re-pulled, until a close() by the owner, which is final (swarm retries; owner decisions 1 and 2
  // of 2026-11-23).
  reconnects = 0;
  /**
   * The first wait of the redial table (5 s): the table's waits are 1, 2, 4 and 6 times it, then wrap. It is also the
   * quick-drop window: a link that ends sooner after its dial counts as a failed round.
   */
  reconnectIntervalMs = 5000;
  /** This peer's position in the redial table (owner decision 1 of 2026-11-23); a test installs one with a fixed spread. */
  redialTable = new RedialTable();
  /**
   * Whether a lost link re-dials the seeds on its own. A host whose own durable timer owns every dial, as the
   * workers cell's alarm does, turns it off and dials again with `connectAny` (swarm retries, ROBUSTNESS.md §10.3 E5).
   */
  redial = true;
  /** The seeds this peer dials, in order; `seeds[seedIndex]` is the one in use or tried last. */
  seeds: Seed[] = [];
  seedIndex = 0;
  /**
   * Resolve a seed hostname to every address and dial each (DB-X-03); off, the runtime's
   * resolver picks one address per dial.
   */
  resolveSeeds = true;
  /**
   * The free-form resource hints this peer's self-advertisement carries (SPEC §5.2); a join
   * credential rides under `aspace:join`. Set before `connect`, or call `introduce()` again.
   */
  readonly resourceHints: { [key: string]: string } = {};
  /**
   * SPEC v0.1.23 §5.4 (srad/large-networks-bulk-data.md): the seed's PeerID, learned from the
   * first frame it addresses to this peer on the dialed channel. A dial-only peer reaches the
   * seed directly and every other member through it (a `RELAY_FRAME` the seed forwards), and
   * declares the seed as its relay in the `relay.via` hint so members reach it the same way back.
   */
  seedPeer: string | null = null;
  /** The seed (its URL) {@link seedPeer} was learned on, and the seed the dialed channel is on now. */
  private seedPeerOn: string | null = null;
  private dialedSeed: string | null = null;
  /** Times a failover to another seed withdrew a `relay.via` that named the old one. */
  relayViaCleared = 0;

  /** Declares `peer`, the member on the other end of the dialed channel, as this peer's relay (SPEC §5.4). */
  private adoptSeedPeer(peer: string): void {
    this.seedPeer = peer;
    this.seedPeerOn = this.dialedSeed;
    this.resourceHints["relay.via"] = peer;
  }
  /** The longest path a relayed frame of this peer's names (LB-R-03). */
  maxPathHops = 4;
  /** Frames this peer sent through its seed. */
  relayedFrames = 0;
  /** The last unreachable signals relays sent back (`aspace:cap/relay-signal`). */
  readonly relaySignals: Dict[] = [];
  /** Block-stored payloads (SPEC §7.1, `z` references): put here or fetched, by id. */
  readonly blocks = new Map<string, Uint8Array>();
  private readonly blockAsked = new Map<string, number>();
  /** The content swarm attached to this peer (`capabilities/content`): resolves `b` references and takes payloads above its bound. */
  content: BulkPayloads | null = null;
  /**
   * Where a stub card's parts document goes and comes from (SPEC §6.1a.5, v0.1.32): a content swarm installs its
   * `ContentSpillStore` when it attaches; null, and this peer never spills and fails to resolve a stub.
   */
  spillStore: SpillStore | null = null;
  /** The largest parts document {@link resolve} fetches (16 MiB by default). */
  spillMaxFetchBytes = wire.CARD_SPILL_MAX_FETCH_BYTES;
  /** AppCards issued without a gated field because a member is below the AppCard level (SPEC §6.1a.2). */
  appCardsDowngraded = 0;
  /** Cards issued as stubs (SPEC §6.1a.5). */
  cardsSpilled = 0;
  /** Cards above the spill threshold issued inline: a closed gate, no spill store, a refused document, or nothing to move. */
  cardsOversizeInline = 0;
  /** Resolutions that failed a check of the parts document. */
  spillsRefused = 0;
  /** Resolutions refused because the stub's `size` passed {@link spillMaxFetchBytes}. */
  spillsOverLimit = 0;
  /** Where this peer's warnings go: the soft warning of a card near the spill threshold (FR-13), and a refused spill. */
  onWarning: (message: string) => void = (message) => console.warn(message);
  private level = APPCARD_LEVEL;
  /** The cards this peer issues under the AppCard level, by id, so a change of the members' level reissues them. */
  private readonly issuedCards = new Map<string, IssuedCard>();
  /** The size each card id last warned at, so a refresh at the same size stays quiet. */
  private readonly warnedSizes = new Map<string, number>();
  /** Each parts-document root this peer named, to the moment the last card that named it expires. */
  private readonly spillHolds = new Map<string, number>();
  private spillSweep: Repeating | null = null;

  /**
   * The AppCard level this peer advertises (`wire.appcard`), 1 or 2; 1 advertises no hint, so a test builds a mixed
   * fleet. Advertise a change with {@link introduce}.
   */
  get appCardLevel(): number {
    return this.level;
  }

  set appCardLevel(level: number) {
    if (level !== 1 && level !== APPCARD_LEVEL) {
      throw new RangeError(`this build reads AppCard levels 1 to ${APPCARD_LEVEL}: ${level}`);
    }
    this.level = level;
    this.appCardLevelChanged();
  }
  /** The persistent data structures attached to this peer (`pdt`): refs, values, and the tree exchange (PD-C-05). */
  pdt: Pdt | null = null;
  private running = false;
  private readonly pulledSpaces = new Set<string>();
  /**
   * The spaces this peer joined: pulled, written to, or opened as a Space. HLC round five,
   * 2026-11-08: this peer relays a rumor of any other space without decoding or folding it, as
   * Java's GossipBus relays a stream it holds no handler for.
   */
  private readonly joinedSpaces = new Set<string>();
  /** The longest lease observed per space id, capped at MAX_TRACKED_LEASE_MILLIS, for the collection horizon (SPEC §7.3, HLC round five, 2026-11-08). */
  private readonly longestLease = new Map<string, number>();
  /** Whether the tombstone collection runs as due work on this peer's loop (from the first state or claim stored). */
  private collector = false;
  private pulledAds = false;

  private founderId(): string | null {
    if (this.founder !== null) {
      return this.founder;
    }
    const ad = this.founding?.["advertisement"] as Dict | undefined;
    return typeof ad?.["issuer"] === "string" ? ad["issuer"] : null;
  }

  /** Dials the seed (`tcp` unless `scheme` says otherwise, `tls` for instance) and introduces this peer to the group. */
  async connect(host: string, port: number, scheme?: string): Promise<void> {
    await this.connectAny([scheme === undefined ? { host, port } : { host, port, scheme }]);
  }

  /**
   * Dials the seeds in list order, one start every 250 ms, with the first
   * to answer winning (owner decision 2 of 2026-11-23, RFC 8305), then introduces this peer to the group
   * (DB-X-02). A lost socket later fails over to another seed inside the
   * reconnect window (ROBUSTNESS.md §6a). Rejects when no seed answers,
   * with the last dial's error.
   */
  /**
   * Takes a connection a listener accepted (JS-R-04): frames on it are handled like those on
   * the dialed channel, with a session of its own; a member heard on it is reachable until the
   * connection ends. The host introduces itself on the new link so the other end learns this
   * peer, and the rumor it brings travels on to the other links.
   */
  acceptChannel(channel: FrameChannel): Link {
    const link: Link = { channel, session: null, peers: new Set() };
    this.inbound.set(channel, link);
    this.running = true;
    this.openLoop(); // the loop sees a wall step (a resume) even when no task is due
    channel.onFrame((frame) => this.onFrame(frame, link));
    channel.onClose(() => this.onInboundClosed(link));
    this.sendOn(link, "RUMOR", this.selfAdRumor(), null);
    return link;
  }

  private onInboundClosed(link: Link): void {
    if (this.inbound.get(link.channel) !== link) {
      return;
    }
    this.inbound.delete(link.channel);
    for (const peer of link.peers) {
      if (!this.linkedElsewhere(peer, link)) {
        this.reachable.delete(peer);
      }
    }
  }

  /** Whether a member is heard on some link other than `except` (null: other than the dialed channel). */
  private linkedElsewhere(peer: string, except: Link | null): boolean {
    if (except !== null && this.dialPeers.has(peer)) {
      return true;
    }
    for (const other of this.inbound.values()) {
      if (other !== except && other.peers.has(peer)) {
        return true;
      }
    }
    return false;
  }

  /** The members heard on the dialed channel. */
  private readonly dialPeers = new Set<string>();

  /** The link a member was heard on, or null for the dialed channel (the route for everyone else). */
  private linkFor(peer: string): Link | null {
    if (this.dialPeers.has(peer) && this.channel !== null) {
      return null;
    }
    for (const link of this.inbound.values()) {
      if (link.peers.has(peer)) {
        return link;
      }
    }
    return null;
  }

  /** The members this peer has a connection to, in no particular order. */
  linkedMembers(): string[] {
    const out = new Set<string>(this.dialPeers);
    for (const link of this.inbound.values()) {
      for (const peer of link.peers) {
        out.add(peer);
      }
    }
    out.delete(this.identity.peerId);
    return [...out];
  }

  async connectAny(seeds: Seed[]): Promise<void> {
    await this.dialAny(seeds);
    this.introduce();
    this.pullRevocations();
  }

  /** The seed the link is on (or was tried last), if any. */
  currentSeed(): Seed | null {
    return this.seeds[this.seedIndex] ?? null;
  }

  private async dialAny(seeds: Seed[]): Promise<void> {
    const dialable = seeds.filter((s) => this.dialers.has(schemeOf(s)));
    if (dialable.length === 0 && seeds.length > 0) {
      // JS-Q-AVL-03: name what was seen and what dials it.
      const schemes = [...new Set(seeds.map(schemeOf))];
      throw new Error(`no dialer for the seeds' schemes (${schemes.join(", ")}); this peer dials `
        + `${this.dialableSchemes().join(", ") || "nothing"}; add `
        + schemes.map((s) => DIALER_PACKAGES[s] ?? `a ${s} dialer`).join(" or "));
    }
    const expanded = await this.expandSeeds(dialable);
    if (expanded.length === 0) {
      throw new Error("no seed to dial");
    }
    this.seeds = expanded;
    this.seedIndex = 0;
    this.running = true;
    this.openLoop(); // the loop sees a wall step (a resume) even when no task is due
    try {
      await this.dialSeeds();
    } catch (lastError) {
      this.running = false;
      throw new Error(`no seed answered (${this.seeds.map((s) => schemeOf(s) === "tcp" && s.scheme === undefined
        ? `${s.host}:${s.port}` : seedUrl(s)).join(", ")}): `
        + (lastError instanceof Error ? lastError.message : String(lastError)));
    }
  }

  /**
   * Dials the seeds in list order, one start every {@link SEED_STAGGER_MILLIS} (owner decision 2 of 2026-11-23, RFC 8305
   * Happy Eyeballs): a dial that fails starts the next at once, the first channel to open becomes the link, the seeds
   * not yet started are never dialled, and a channel that opens after the winner is closed with nothing sent on it. At
   * most {@link SEED_DIALS_IN_FLIGHT_MAX} dials are in flight at once; with every slot taken, a failure starts the next. So
   * a dead or blackholed first seed costs 250 ms, not its connect timeout, and with every seed up the first listed
   * wins. The seed whose link last ended ({@link lostSeedUrl}) is dialled last, so a seed that accepts dials and then
   * goes silent or drops them is not picked again ahead of a live one. Rejects with the last error when no seed opens.
   */
  private dialSeeds(): Promise<void> {
    const seeds = this.seeds;
    const lost = seeds.findIndex((s) => seedUrl(s) === this.lostSeedUrl);
    const order = seeds.map((_, i) => i).filter((i) => i !== lost);
    if (lost >= 0) {
      order.push(lost);
    }
    return new Promise<void>((resolve, reject) => {
      if (order.length === 0) {
        reject(new Error("no seed to dial"));
        return;
      }
      let next = 0;
      let inFlight = 0;
      let settled = false;
      let lastError: unknown = new Error("the peer was closed while dialing");
      let stagger: unknown = null;
      const stopStagger = (): void => {
        if (stagger !== null) {
          this.timers.clearTimeout(stagger);
          stagger = null;
        }
      };
      const giveUpIfDone = (): void => {
        if (!settled && inFlight === 0 && (next >= order.length || !this.running)) {
          settled = true;
          stopStagger();
          reject(lastError);
        }
      };
      const start = (): void => {
        stopStagger();
        if (settled || next >= order.length || !this.running) {
          giveUpIfDone();
          return;
        }
        if (inFlight >= SEED_DIALS_IN_FLIGHT_MAX) {
          return; // every slot is taken: the next dial starts when one fails
        }
        const i = order[next++]!;
        inFlight += 1;
        if (next < order.length) {
          stagger = this.timers.setTimeout(() => { stagger = null; start(); }, SEED_STAGGER_MILLIS);
          unref(stagger);
        }
        this.seedDials += 1;
        this.openSeed(seeds[i]!).then((channel) => {
          inFlight -= 1;
          if (settled) {
            this.lateSeedChannels += 1;
            channel.close(); // another seed answered first
            return;
          }
          settled = true;
          stopStagger(); // the seeds not yet started are never dialled
          if (this.running) {
            this.seedIndex = i;
            this.adopt(channel, seeds[i]!);
          } else {
            channel.close(); // closed while dialing
          }
          resolve();
        }, (e: unknown) => {
          inFlight -= 1;
          lastError = e;
          if (!settled) {
            start(); // a refused dial starts the next at once
          }
        });
      };
      start();
    });
  }

  /** DB-X-03: each dialer may expand a seed (a hostname into one seed per address, for tcp). */
  private async expandSeeds(seeds: Seed[]): Promise<Seed[]> {
    const out: Seed[] = [];
    for (const seed of seeds) {
      const dialer = this.dialers.get(schemeOf(seed));
      if (dialer?.expand === undefined) {
        out.push(seed);
        continue;
      }
      try {
        out.push(...await dialer.expand(seed, this.resolveSeeds));
      } catch {
        out.push(seed); // let the dial report the resolver's verdict
      }
    }
    return out;
  }

  /**
   * DB-X-02: fetches a beacon document (signature verified, the pinned
   * signer honoured), selects the group (`groupId`, else `name`, else the
   * document's only group), verifies its founding advertisement with the
   * four checks `joinByGroupId` applies and, when `groupId` is given, that
   * it is exactly that group, then dials the document's seeds of every scheme
   * this peer dials, in the JS-P-07 priority order one start every 250 ms,
   * with the first to answer winning (owner decision 2 of 2026-11-23,
   * RFC 8305). Returns the group selected.
   *
   * `timeoutMs` (3 000 by default) bounds one fetch of the document and
   * `joinTimeoutMs` (10 000) bounds the whole call. A first attempt that
   * succeeds fetches once and dials once. Otherwise the call keeps asking
   * inside the budget, in slices of 1 s, 2 s, 4 s, then 5 s each, the shape
   * of the Java join by id (ISSUE-BootstrapRobustness FR-4): at the start of
   * each slice it fetches the document again when the previous fetch left the
   * beacon unavailable ({@link beacon.BeaconUnavailableError}) or the document
   * named no seed this peer dials, and dials again, once per slice, every seed
   * that refused. A beacon or a seed that starts a few seconds after this peer
   * is reached on a later slice. A refusal (the scheme policy, a document or a
   * founding that does not verify, a founding for another id, a group the
   * document does not carry) rejects at once, as before. When the budget runs
   * out the call rejects with {@link BootstrapTimeoutError}, whose message
   * carries the number of fetches, the seeds dialed, how many connected, and
   * the last error.
   */
  async bootstrap(url: string, options: {
    groupId?: string | null; name?: string | null; allowPlain?: boolean;
    beaconPeer?: string | null; timeoutMs?: number; joinTimeoutMs?: number; fetch?: typeof fetch;
  } = {}): Promise<beacon.BeaconGroup> {
    const joinTimeoutMs = options.joinTimeoutMs ?? 10_000;
    const attemptMs = options.timeoutMs ?? 3_000;
    const deadline = monotonicMillis() + joinTimeoutMs;
    let fetches = 0;
    const dialed = new Set<string>();
    let lastError: unknown = null;
    let group: beacon.BeaconGroup | null = null;
    let seeds: Seed[] = [];
    let slice = JOIN_SLICE_FIRST_MS;
    for (;;) {
      const started = monotonicMillis();
      if (seeds.length === 0) {
        fetches += 1;
        try {
          const document = await beacon.fetchBeaconDocument(url,
            { ...options, timeoutMs: Math.min(attemptMs, Math.max(deadline - started, 1)) });
          const selected = beacon.groupFromDocument(document, { groupId: options.groupId, name: options.name });
          const wanted = beacon.bareGroupId(options.groupId) ?? beacon.bareGroupId(selected.id);
          const founding = this.verifyFounding(selected, wanted);
          this.group = founding.group;
          this.founding = founding.signed;
          group = selected;
          seeds = this.seedsOfGroup(selected);
          if (seeds.length === 0) {
            lastError = new Error(`the beacon document lists no ${this.dialableSchemes().join(" or ")} seed for ${selected.name}`);
          }
        } catch (e) {
          if (!(e instanceof beacon.BeaconUnavailableError)) {
            throw e; // a refusal: asking again would not change it
          }
          lastError = e; // the beacon is unreachable or answered an error: ask again
        }
      }
      if (seeds.length > 0 && monotonicMillis() < deadline) {
        try {
          await this.dialAny(seeds); // the seeds in list order, 250 ms apart
          this.introduce();
          this.pullRevocations();
          return group as beacon.BeaconGroup;
        } catch (e) {
          lastError = e;
        } finally {
          for (const seed of this.seeds) {
            dialed.add(seedUrl(seed));
          }
        }
      }
      const now = monotonicMillis();
      const wait = Math.min(slice - (now - started), deadline - now);
      if (wait > 0) {
        await sleep(wait);
      }
      // A wait that ran to the deadline ends the call even when the timer fired a fraction of a millisecond early
      // (Node runs timers on whole milliseconds of its own clock), so the budget never buys one more attempt.
      if (wait >= deadline - now || monotonicMillis() >= deadline) {
        const last = lastError instanceof Error ? lastError.message : String(lastError);
        throw new BootstrapTimeoutError(`no join through ${url} within ${joinTimeoutMs} ms: ${fetches} fetch(es), `
          + `0 of ${dialed.size} seed(s) connected; last error: ${last}`, fetches, dialed.size, 0, lastError);
      }
      slice = Math.min(slice * 2, JOIN_SLICE_MAX_MS);
    }
  }

  /**
   * DB-X-07: joins a group for friends with an invite key. Parses the key,
   * fetches the beacon document under its code, takes the delegation from
   * the key or the document's `invite`, derives the credential for this
   * peer under the invite signing key and carries it in the self-ad's
   * `aspace:join` hint, verifies the founding against the delegation's
   * group, and dials the seeds. The returned content key is the group's
   * (epoch 0); the beacon never sees it.
   */
  async joinInvite(keyText: string, options: {
    allowPlain?: boolean; timeoutMs?: number; fetch?: typeof fetch;
  } = {}): Promise<InviteJoined> {
    const key = social.InviteKey.parse(keyText);
    const scheme = options.allowPlain ? "http" : "https";
    const document = await beacon.fetchBeaconDocument(key.documentUrl(scheme), options);
    const claimed = key.delegation === null ? null : social.delegationGroup(key.delegation);
    const group = beacon.groupFromDocument(document, { groupId: claimed });
    const delegation = key.delegation ?? group.invite ?? null;
    if (delegation === null) {
      throw new Error("the invite key carries no delegation and the beacon document has none");
    }
    const groupId = social.delegationGroup(delegation);
    const founding = this.verifyFounding(group, groupId);
    const issuer = (founding.signed["advertisement"] as Dict)["issuer"];
    if (typeof issuer !== "string" || issuer !== social.describeDelegation(delegation)?.founder) {
      throw new Error("the delegation was not signed by the group's founder");
    }
    this.resourceHints[social.JOIN_HINT] = social.issueDelegated(delegation, key.secret.inviteSeed(),
      this.identity.peerId);
    this.group = groupId;
    this.founding = founding.signed;
    const seeds = this.seedsOfGroup(group);
    if (seeds.length === 0) {
      throw new Error(`the beacon lists no ${this.dialableSchemes().join(" or ")} seed under ${key.code}`);
    }
    await this.connectAny(seeds);
    return { groupId, contentKey: key.secret.contentKey(), delegation, key,
      pinnedKey: key.withDelegation(delegation).compact() };
  }

  /**
   * A beacon group's seeds this peer can dial; a `tcp` seed keeps the bare
   * `{host, port}` form the earlier clients used.
   */
  private seedsOfGroup(group: beacon.BeaconGroup): Seed[] {
    return beacon.seedsFor(group, this.dialableSchemes()).map((s) => {
      if (s.scheme === "tcp") {
        const { scheme: _scheme, ...rest } = s;
        return rest;
      }
      return s;
    });
  }

  /**
   * The founding a document carries, verified as `joinByGroupId` verifies a
   * GROUP_AD (the four checks of GroupFounding.verify) and, when `wanted`
   * is given, required to be exactly that group.
   */
  private verifyFounding(group: beacon.BeaconGroup, wanted: string | null): { group: string; signed: Dict } {
    if (!group.founding) {
      throw new Error(`the beacon document carries no founding for ${group.name}`);
    }
    let bytes: Uint8Array;
    try {
      bytes = fromBase64(group.founding);
    } catch {
      throw new Error(`the founding of ${group.name} is not base64`);
    }
    const signed = records.readRecord(bytes, records.SIGNED_GROUP_ADVERTISEMENT);
    if (signed === null) {
      throw new Error(`the founding of ${group.name} is no SignedGroupAdvertisement in the wire encoding`);
    }
    const verified = verifySignedGroupAd(signed);
    if (verified === null) {
      throw new Error(`the founding of ${group.name} does not verify`);
    }
    const id = beacon.bareGroupId(group.id);
    if (id !== null && id !== verified) {
      throw new Error(`the document says ${group.name} is ${id} but its founding is ${verified}`);
    }
    if (wanted !== null && verified !== wanted) {
      throw new Error(`the founding of ${group.name} is ${verified}, not ${wanted}`);
    }
    return { group: verified, signed };
  }

  /** Whether the seed connection is up (a reconnect may be in progress while it is not). */
  connected(): boolean {
    return this.running && this.channel !== null;
  }

  /**
   * After a lost socket: dials the seeds again, then introduces this peer again and pulls what it
   * had pulled before, so a network hiccup costs a few seconds rather than the membership
   * (ROBUSTNESS.md §3.6). Each round dials the seeds in list order 250 ms apart, the lost seed last, and
   * the waits between rounds follow the redial table, 5, 10, 20, 30 s and then 5 s again, each with a
   * spread of +/-10%, so the clients of a seed that restarts do not all dial it at once (owner decisions 1
   * and 2 of 2026-11-23). The dials go
   * on until the owner closes the peer (swarm retries, ROBUSTNESS.md §10.3 E5).
   */
  private reconnecting = false;

  private reconnect(): void {
    if (!this.running || this.seeds.length === 0) {
      this.reconnecting = false;
      return;
    }
    this.reconnecting = true;
    this.dialSeeds().then(() => {
      if (!this.running) {
        this.reconnecting = false;
        return; // closed by the owner while dialing: the channel is closed and nothing goes out
      }
      if (this.channel === null) {
        // The seed accepted and dropped the link before this turn: its close signal came while this round was still
        // reconnecting and left the next dial to it. A quick drop, so the round waits the table's next wait, and the
        // seed that dropped it is now the lost seed, dialled last, so a seed that accepts and drops every dial cannot
        // keep winning the race against a live one.
        this.pauseThenReconnect(this.redialTable.next(this.reconnectIntervalMs));
        return;
      }
      this.reconnecting = false;
      this.reconnects += 1;
      this.introduce();
      this.pullRevocations();
      if (this.pulledAds) {
        this.pullAds();
      }
      for (const space of this.pulledSpaces) {
        this.pullSpace(space);
      }
    }).catch(() => {
      if (!this.running) {
        this.reconnecting = false;
        return;
      }
      // Never a tight loop: every round in which no seed opened waits the redial table's next wait.
      this.pauseThenReconnect(this.redialTable.next(this.reconnectIntervalMs));
    });
  }

  /**
   * Waits `pause` on this peer's timers (a virtual clock in a test), then dials the seeds again. A resume cuts the
   * wait short ({@link onWallStep}).
   */
  private pauseThenReconnect(pause: number): void {
    const timer = this.timers.setTimeout(() => {
      if (this.reconnectTimer === timer) {
        this.reconnectTimer = null;
        this.reconnect();
      }
    }, pause);
    this.reconnectTimer = timer;
    unref(timer);
  }

  /** When the current link was dialed (the quick-drop window is judged from it). */
  private linkSince = 0;

  private onChannelClosed(channel: FrameChannel): void {
    if (this.channel !== channel) {
      return; // an old link, already replaced
    }
    this.channel = null;
    this.lostSeedUrl = this.dialedSeed; // dialled last in the rounds that follow (owner decision 2 of 2026-11-23)
    this.session = null; // a session ends with its connection
    this.dialPeers.clear();
    for (const peer of [...this.reachable]) {
      if (!this.linkedElsewhere(peer, null)) {
        this.reachable.delete(peer);
      }
    }
    if (this.running && this.redial && this.seeds.length > 0 && !this.reconnecting) {
      // Owner decision 1 of 2026-11-23: a link that ended within the reconnect interval (5 s) counts as a failed round
      // of dials and waits the redial table's next step without resetting it, so a seed that accepts each dial and
      // drops it at once climbs the table and gets no dial loop (swarm retries, ROBUSTNESS.md §10.6). A link that held
      // at least that long succeeded: the table goes back to its first wait and the seeds are dialled at once. A link
      // this peer closed on the dead-seed verdict after a wake fails over at once, however young.
      const quick = channel !== this.failoverClosed && this.monotonic() - this.linkSince < this.reconnectIntervalMs;
      this.failoverClosed = null;
      if (quick) {
        this.reconnecting = true;
        this.pauseThenReconnect(this.redialTable.next(this.reconnectIntervalMs));
      } else {
        this.redialTable.reset();
        this.reconnect();
      }
    }
  }

  /**
   * Joins a self-certifying group knowing only its GroupID and a seed (SPEC
   * §5.1, §10.1 `join: "aspace://<groupID>"`): dials the seed, sends an
   * unaddressed GROUP_AD_WANT naming the group, waits for the first GROUP_AD
   * whose body verifies as the founding document of exactly that GroupID
   * (the four checks of GroupFounding.verify), and only then introduces this
   * peer. Answers that fail verification are ignored, so a hostile seed can
   * delay the join but never substitute a policy. Rejects with a timeout
   * error when no verified document arrives in time.
   *
   * `groupId` is the bare id or the join URI `aspace://<id>[/<space>]`, read
   * as Java's `GroupId.ofUri` reads it. `scheme` names the seed's transport
   * (`tcp` by default, `tls`, `ws`, or any scheme a registered dialer serves).
   * The want goes out again while the join waits, in slices of 1 s, 2 s, 4 s,
   * then 5 s, as Java's join does (ISSUE-BootstrapRobustness FR-4), so a seed
   * that missed the first want or had not yet founded the group still answers.
   */
  async joinByGroupId(host: string, port: number, groupId: string,
                      timeoutMillis = 10_000, scheme = "tcp"): Promise<Dict> {
    const id = beacon.bareGroupId(groupId);
    if (id === null) {
      throw new Error(`no GroupId in '${groupId}'`);
    }
    this.group = id;
    await this.dialAny([scheme.toLowerCase() === "tcp" ? { host, port } : { host, port, scheme }]);
    const founding = this.awaitFounding(id, timeoutMillis);
    // Unaddressed: the seed's PeerID is unknown until it answers (§9).
    const want = (): void => this.sendEnvelope(wire.groupAdWantEnvelope(id, this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now())));
    want();
    let resend: unknown = null;
    let slice = 1_000;
    const again = (): void => {
      resend = this.timers.setTimeout(() => {
        want();
        slice = Math.min(slice * 2, 5_000);
        again();
      }, slice);
    };
    again();
    try {
      this.founding = await founding;
    } catch (e) {
      this.close();
      throw e;
    } finally {
      this.timers.clearTimeout(resend);
    }
    this.introduce();
    this.pullRevocations();
    return this.founding;
  }

  /**
   * The waiting half of {@link joinByGroupId}, exposed so the verification
   * path can be driven without a socket: resolves with the first verified
   * founding advertisement {@link offerGroupAd} receives for `groupId`.
   */
  awaitFounding(groupId: string, timeoutMillis: number): Promise<Dict> {
    if (this.pendingFounding !== null) {
      return Promise.reject(new Error(`a join of ${this.pendingFounding.group} is already in progress`));
    }
    return new Promise<Dict>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingFounding = null;
        reject(new Error(`timed out after ${timeoutMillis} ms waiting for a verified`
          + ` GROUP_AD for ${groupId}`));
      }, timeoutMillis);
      this.pendingFounding = {
        group: groupId,
        resolve: (signed) => {
          clearTimeout(timer);
          this.pendingFounding = null;
          resolve(signed);
        },
      };
    });
  }

  /**
   * Offers a decoded GROUP_AD envelope to the join in progress. Returns true
   * only when the body verified as the founding document of exactly the
   * wanted group and resolved the join; every other answer is ignored. The
   * reader calls this for GROUP_AD frames; tests call it directly.
   */
  offerGroupAd(env: Dict): boolean {
    const pending = this.pendingFounding;
    if (pending === null || env["kind"] !== "GROUP_AD" || env["group"] !== pending.group) {
      return false;
    }
    const signed = records.readRecord(env["body"], records.SIGNED_GROUP_ADVERTISEMENT);
    if (signed === null || verifySignedGroupAd(signed) !== pending.group) {
      return false; // not the self-certifying founding document of this group
    }
    pending.resolve(signed);
    return true;
  }

  close(): void {
    this.running = false;
    if (this.reconnectTimer !== null) {
      this.timers.clearTimeout(this.reconnectTimer); // a closed peer dials nothing more
      this.reconnectTimer = null;
      this.reconnecting = false; // as the cleared pause would have found it: a peer that connects again re-dials
    }
    for (const handle of this.repeating.splice(0)) {
      handle.stop();
    }
    this.dueLoop?.pause(); // its tasks and deadlines stay for a peer that dials again (a resident host's resume)
    this.unwatchLoop?.();
    this.unwatchLoop = null;
    const channel = this.channel;
    this.channel = null;
    channel?.close();
    for (const link of [...this.inbound.values()]) {
      this.inbound.delete(link.channel);
      link.channel.close();
    }
  }

  /** Publishes this peer's leased self-advertisement (spec §5.2) on every link. */
  introduce(): void {
    this.send("RUMOR", this.selfAdRumor());
    this.maybeAnnounceChannel();
  }

  /**
   * On a dialed channel the transport attested (`tls`), announces once that this peer accepts
   * channel-attested frames there (CHANNEL_HELLO, SPEC §5.6; PeerNode.maybeAnnounceChannel), so
   * a Java node in ATTESTED or SESSION mode stops signing every frame toward it. The announcement
   * travels signed, and this peer keeps signing what it sends. Nothing is announced in `signed` mode.
   */
  private maybeAnnounceChannel(): void {
    const channel = this.channel;
    const attested = channel?.attestedPeer() ?? null;
    if (channel === null || attested === null || this.channelAuth === "signed" || this.helloSentOn === channel) {
      return;
    }
    this.helloSentOn = channel;
    const env = wire.envelope(this.group, "CHANNEL_HELLO", this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now()), wire.channelHelloBody(true, attested), attested);
    channel.send(wire.encodeFrame(env, this.identity));
  }

  /** The millisecond the last self-advertisement rumor was named for. */
  private lastSelfAdItemMillis = Number.NEGATIVE_INFINITY;

  /** This peer's advertisement as of now: its endpoints, hints, and lease (whole seconds, as always stamped). */
  private selfAd(): Dict {
    const now = this.now();
    const hints: { [key: string]: string } = { ...this.resourceHints, [RECORDLESS_HINT]: "1" };
    if (this.channelAuth === "session") {
      hints[SESSION_HINT] = "1";
    }
    if (this.level > 1) {
      hints[APPCARD_HINT] = String(this.level); // AppCard origin and formats, 2026-11-09
    }
    if (this.auditOn) {
      // Replication by entry (annex I.6): the hashed round of v0.1.17 and the audit; off, this peer is a 0.6.0 member.
      hints[HASHES_HINT] = "1";
      hints[AE_HINT] = AE_LEVEL;
    }
    if (this.horizonOn) {
      hints[HORIZON_HINT] = HORIZON_LEVEL; // every renewal here keeps §7.2's rule (RE-H-02, RE-H-04)
    }
    const ad = wire.peerAdvertisement(this.group, this.identity, instantIso(now - (now % 1000)),
      "PT10M", hints);
    ad["endpoints"] = this.endpoints.map((e) => ({ ...e }));
    return ad;
  }

  /** The `peers` rumor carrying this peer's signed advertisement. */
  private selfAdRumor(): Uint8Array {
    const payload = wire.signedPeerAd(this.selfAd(), this.identity);
    // Issued at least a millisecond after the last one (SPEC v0.1.36, srad/agentspaces-event-loop.md §10.16): a changed
    // advertisement in the millisecond of the last shared its gossip item id, and every member dropped it as a duplicate.
    const at = Math.max(Math.trunc(this.now()), this.lastSelfAdItemMillis + 1);
    this.lastSelfAdItemMillis = at;
    const itemId = `peer:${this.identity.peerId}:${at}`;
    return wire.rumorBody("peers", itemId, this.rumorHops, payload);
  }

  /**
   * Writes one signed entry into a replicated space; returns its id. With
   * `agent` (v0.1.13) the entry is the agent's own: agent-signed record and
   * state, stored AGENT_ATTESTED everywhere.
   */
  writeEntry(space: string, typeName: string, value: Dict,
             agentName = "typescript", leaseMillis = 600_000,
             agent: AgentIdentity | null = null, tags: Dict = {}): string {
    if (agent !== null && this.revocations.refuses(agent.agentId, agent.publicRaw, null)) {
      throw new Error(`${agent.agentId} is revoked in this group`);
    }
    let payload: Uint8Array | null = dumps(value);
    let payloadRef: string | null = null;
    if (this.content !== null && this.content.escalateAbove > 0 && payload.length > this.content.escalateAbove) {
      // SPEC §7.1 group E: above the bound the payload becomes an artifact of the content swarm
      // and the record carries its root.
      payloadRef = this.content.publishOpaque(payload, leaseMillis);
      payload = null;
    } else if (payload.length > wire.INLINE_PAYLOAD_LIMIT) {
      payloadRef = this.putBlock(payload);
      payload = null;
    }
    this.joinSpace(space);
    const { entryId, body } = wire.entryDelta(space, this.group, typeName,
      payload, this.identity, agentName, leaseMillis, agent, this.now(), tags, payloadRef);
    // The writer holds its own entry too, folded into the verified local
    // replica before transport, so a local read sees it at once.
    // HLC round six, 2026-11-08 (F3): read strictly, as a receiver reads it, so a write this client
    // could not deliver to a strict receiver fails here, loudly.
    this.foldDelta(records.decodeRecord((loads(body) as Dict)["payload"] as Uint8Array, records.SPACE_DELTA) as Dict);
    this.send("RUMOR", body);
    return entryId;
  }

  /**
   * Publishes an advertisement this peer issued (an AgentCard, an AssetCard)
   * on the `ads` stream as DiscoveryService.publish does: the stored form,
   * under the advertisement's id and issue time. An AppCard or an AgentCard is
   * issued under the AppCard level and the card spill (SPEC §6.1a.2, §6.1a.5,
   * v0.1.32; AppCard origin and formats, 2026-11-09): pass the full card, and
   * the peer strips the gated fields while a member it knows is below level 2,
   * sends a card above 65,536 bytes as a stub behind an open gate, and reissues
   * the card at once when the members' level changes.
   */
  publishAd(adType: string, ad: Dict): void {
    if (adType === "AppCard" || adType === "AgentCard") {
      if (ad["spill"] !== undefined) {
        throw new Error("publish the full card: the peer decides whether it travels as a stub");
      }
      // read as the record before it is kept, so a card that fails its schema throws here and never reaches a
      // reissue (AppCard origin and formats, 2026-11-09, adversary pass)
      records.conform(ad, adType === "AppCard" ? records.APP_CARD : records.AGENT_CARD);
      const id = String(ad["id"]);
      this.pruneIssuedCards();
      const previous = this.issuedCards.get(id);
      this.issuedCards.set(id, { adType, full: ad, issued: previous?.issued ?? Number.NEGATIVE_INFINITY,
        open: previous?.open ?? null });
      this.issueCard(id);
      return;
    }
    this.sendAd(adType, ad);
  }

  /**
   * Stops reissuing a card published with {@link publishAd} (AppCardPublisher.withdraw; AppCard origin and formats,
   * 2026-11-09, adversary pass): the last card signed lapses at its ttl, and a parts document it named is released
   * once that card expires.
   */
  withdrawAd(id: string): void {
    this.issuedCards.delete(id);
    this.warnedSizes.delete(id);
  }

  /** Signs an advertisement, holds it in this peer's own cache, and sends it on the `ads` stream. */
  private sendAd(adType: string, ad: Dict): void {
    const stored = wire.storedAd(adType, ad, this.identity);
    this.acceptAd(stored); // our own cache holds it too, as DiscoveryService.publish does
    const itemId = `${String(ad["id"])}:${parseInstantMillis(ad["issued"])}`;
    this.send("RUMOR", wire.rumorBody("ads", itemId, 6, dumps(stored)));
  }

  /** Layer 4 (SPEC §6, §8): the members heard from (peer id to its advertisement, `{}` when only heard). */
  readonly members: Map<string, Dict> = new TrackedMap<string, Dict>()
    .track(() => {
      this.hinted.at = Number.NaN; // a member that comes or goes is judged afresh by the horizon
      this.wakeCollector();
      for (const listener of this.membersListeners) {
        listener(); // due work that judges the view (a host's member expiry, the collection's horizon) is asked again
      }
    });
  private readonly membersListeners: Array<() => void> = [];

  /** Hears every change of the member view (a member admitted, updated, or gone). */
  onMembersChanged(listener: () => void): () => void {
    this.membersListeners.push(listener);
    return () => {
      const i = this.membersListeners.indexOf(listener);
      if (i >= 0) {
        this.membersListeners.splice(i, 1);
      }
    };
  }

  /** The earliest wall instant a member's advertisement lapses ({@link expireMembers}'s next due), or null. */
  nextMemberExpiry(): number | null {
    let next: number | null = null;
    const linked = new Set(this.linkedMembers());
    for (const [peer, ad] of this.members) {
      if (linked.has(peer) || ad["issued"] === undefined) {
        continue; // a member heard on a link is kept while the link lasts
      }
      try {
        let at = parseInstantMillis(ad["issued"]) + parseDurationMillis(ad["ttl"]);
        const held = this.wakeHeldUntil(peer);
        if (held !== null && held > at) {
          at = held; // a lapsed member a wake probed is judged when its hold ends, not before
        }
        next = next === null ? at : Math.min(next, at);
      } catch {
        // an unreadable advertisement never lapses here, as expireMembers keeps it
      }
    }
    return next;
  }

  /** The wall instant a wake's hold on a member's drop ends ({@link wakeHolds}), or null with none. */
  private wakeHeldUntil(peer: string): number | null {
    const mono = this.monotonic();
    let until: number | null = null;
    if (this.wakeSuspects.has(peer) && this.wakeJudgeAt !== null) {
      until = this.wakeJudgeAt;
    }
    const answered = this.wakeAnswered.get(peer);
    if (answered !== undefined) {
      until = Math.max(until ?? 0, answered + WAKE_KEEP_MILLIS);
    }
    return until === null ? null : this.now() + Math.max(0, until - mono);
  }
  /** The signed `peers` payloads held per member, served on the `view` stream (SPEC §5.2, v0.1.17). */
  private readonly heldPeerAds = new Map<string, Uint8Array>();
  /**
   * The members a frame of ours can reach: those that signed a frame that
   * arrived on our connection. A dial-only peer has one socket, so a member
   * learned only from the peers stream (another dial-only peer behind the
   * same seed) is not among them; the seed drops, not relays, a frame to it.
   */
  readonly reachable = new Set<string>();
  /**
   * The advertisements the `ads` stream carried, by id, bounded by {@link adCacheMaxEntries} and by
   * {@link adCacheMaxBytes} of encoded advertisements (SPEC §6.3, v0.1.32).
   */
  readonly ads = new Map<string, CachedAd>();
  /** The most advertisements the cache holds (8,192 by default). */
  adCacheMaxEntries = AD_CACHE_MAX_ENTRIES;
  /** The most bytes of advertisement encodings the cache holds (32 MiB by default). */
  adCacheMaxBytes = AD_CACHE_MAX_BYTES;
  /** Advertisements the cache refused under its entry bound or its byte budget. */
  adsRefusedCacheFull = 0;
  private cachedBytes = 0;

  /** The sum of the cached advertisements' encodings, expired ones included until a refusal evicts them. */
  get adCacheBytes(): number {
    return this.cachedBytes;
  }
  /** Capability frame handlers by capability type: `(fromPeerId, payload)`. */
  readonly pipeHandlers = new Map<string, (from: string, payload: Uint8Array) => void>();
  /**
   * Handlers of gossip streams by stream id (PDT 2 phase 7, P2-P-02): a push follower takes the bundles of a ref's
   * stream `pdt:<space>:<name>`, and the handler's answer says whether this peer forwards the rumour, so a follower
   * forwards only what it took. A stream without a handler is relayed unread (rule 16).
   */
  readonly streamHandlers = new Map<string, (from: string, payload: Uint8Array) => boolean>();

  /** Anti-entropy pull of the `ads` stream (SPEC §6.2): the cards and capability advertisements the group holds. */
  pullAds(): void {
    this.pulledAds = true;
    this.send("DIGEST", wire.digestBody({ ads: new Uint8Array() }), null, "dial");
  }

  /**
   * Admits a StoredAd as AdCache.accept does: an advertisement type Java registers, the advertisement
   * read strictly as that type (HLC round six, 2026-11-08, F3), the signature over its bytes under
   * the carried key, the issuer derived from that key, and the TTL not yet passed. Returns the
   * cached entry, or null.
   */
  acceptAd(stored: unknown): CachedAd | null {
    const s = records.conformed(stored, records.STORED_AD);
    const schema = s === null ? undefined : records.AD_TYPES.get(String(s["adType"]));
    if (s === null || schema === undefined) {
      return null;
    }
    const adBytes = s["adBytes"] as Uint8Array;
    const key = s["publicKey"] as Uint8Array;
    if (key.length !== 32 || !Identity.verify(key, adBytes, s["signature"] as Uint8Array)) {
      return null;
    }
    const ad = records.readRecord(adBytes, schema);
    if (ad === null || ad["issuer"] !== deriveId(key)) {
      return null;
    }
    let expires: number;
    try {
      expires = parseInstantMillis(ad["issued"]) + parseDurationMillis(ad["ttl"]);
    } catch {
      return null;
    }
    if (expires <= this.now()) {
      return null;
    }
    const entry: CachedAd = { type: String(s["adType"]), ad, stored: s, issuer: String(ad["issuer"]), expires };
    const id = String(ad["id"]);
    const previous = this.ads.get(id);
    if (previous !== undefined && parseInstantMillis(previous.ad["issued"]) > parseInstantMillis(ad["issued"])) {
      return previous; // an older version leaves the held one in place
    }
    // SPEC §6.3 (v0.1.32; AppCard origin and formats, 2026-11-09): a new id that would pass either bound, or a version
    // that would pass the byte budget, is refused once the expired entries leave; nothing live is evicted for it
    if (!this.fitsCache(id, adBytes.length)) {
      this.evictExpiredAds();
      if (!this.fitsCache(id, adBytes.length)) {
        this.adsRefusedCacheFull += 1;
        return null;
      }
    }
    this.cachedBytes += adBytes.length - (this.ads.get(id)?.stored["adBytes"] as Uint8Array | undefined ?? new Uint8Array()).length;
    this.ads.set(id, entry);
    return entry;
  }

  /** Whether an advertisement of `length` bytes fits both bounds, given what the cache holds for its id. */
  private fitsCache(id: string, length: number): boolean {
    const held = this.ads.get(id);
    if (held === undefined) {
      return this.ads.size < this.adCacheMaxEntries && this.cachedBytes + length <= this.adCacheMaxBytes;
    }
    return this.cachedBytes - (held.stored["adBytes"] as Uint8Array).length + length <= this.adCacheMaxBytes;
  }

  /** Drops the cached advertisements whose TTL has passed. */
  private evictExpiredAds(): void {
    const now = this.now();
    for (const [id, entry] of this.ads) {
      if (entry.expires <= now) {
        this.ads.delete(id);
        this.cachedBytes -= (entry.stored["adBytes"] as Uint8Array).length;
      }
    }
  }

  /**
   * Whether this peer and every member it knows read the AppCard level (SPEC §6.1a.2, FR-6): the gate under which
   * it writes a card's origin, formats, an `idp` host, and a spill reference. A member heard before its
   * advertisement arrives counts as level 1.
   */
  appCardGateOpen(): boolean {
    if (this.level < APPCARD_LEVEL) {
      return false;
    }
    for (const ad of this.members.values()) {
      if (appCardLevelOf((ad["resourceHints"] as Dict | undefined)?.[APPCARD_HINT]) < APPCARD_LEVEL) {
        return false;
      }
    }
    return true;
  }

  /**
   * The full card of a stub (SPEC §6.1a.5, FR-15): a card without `spill` as it is, and otherwise the stub with its
   * parts document's values in place, read strictly as the card's record. A `size` above {@link spillMaxFetchBytes}
   * fails before any fetch (`spillsOverLimit`); a document of the wrong length, one that does not read as the kind's
   * parts record, or one whose non-empty fields are not exactly `spill.parts` fails (`spillsRefused`, a
   * {@link SpillRefusedError}). A document nobody serves in time fails uncounted. Nothing is struck, and a cached
   * stub stays cached.
   */
  async resolve(card: Dict): Promise<Dict> {
    const spill = card["spill"] as Dict | undefined;
    if (spill === undefined) {
      return card;
    }
    const kind = wire.spillKindOf(card);
    const id = String(card["id"]);
    const size = Number(spill["size"]);
    if (size > this.spillMaxFetchBytes) {
      this.spillsOverLimit += 1;
      throw new Error(`the parts document of ${id} is ${size} bytes, above the fetch bound of ${this.spillMaxFetchBytes}`);
    }
    const store = this.spillStore;
    if (store === null) {
      throw new Error(`no content swarm serves this group, so the stub ${id} stays a stub`);
    }
    let document: Uint8Array;
    try {
      document = await store.get(String(spill["root"]), size);
    } catch (e) {
      if (e instanceof SpillRefusedError) {
        this.spillsRefused += 1;
      }
      throw e;
    }
    try {
      if (document.length !== size) {
        throw new SpillRefusedError(`the parts document of ${id} is ${document.length} bytes; the stub states ${size}`);
      }
      const parts = records.decodeRecord(document, kind === "AppCard" ? records.APP_CARD_PARTS : records.AGENT_CARD_PARTS);
      return records.conform(wire.cardComplete(card, parts as Dict), kind === "AppCard" ? records.APP_CARD : records.AGENT_CARD) as Dict;
    } catch (e) {
      this.spillsRefused += 1;
      throw e instanceof SpillRefusedError ? e
        : new SpillRefusedError(`the parts document of ${id} does not complete its stub`, { cause: e });
    }
  }

  /**
   * Issues one kept card (FR-7, FR-12, FR-13): under a strictly newer `issued` than the last one signed, without the
   * gated fields when the gate is closed, and as a stub when it passes the spill threshold behind an open gate with
   * a spill store that takes its parts document; otherwise inline in full.
   */
  private issueCard(id: string): void {
    const kept = this.issuedCards.get(id)!;
    const open = this.appCardGateOpen();
    kept.open = open;
    const issued = Math.max(parseInstantMillis(kept.full["issued"]), kept.issued + 1);
    kept.issued = issued;
    const current: Dict = { ...kept.full, issued: instantIso(issued) };
    const card = kept.adType === "AppCard" ? wire.appCardForView(current, open) : current;
    if (Object.keys(card).length !== Object.keys(current).length) {
      this.appCardsDowngraded += 1;
    }
    const schema = kept.adType === "AppCard" ? records.APP_CARD : records.AGENT_CARD;
    const size = dumps(records.conform(card, schema)).length;
    const parts = size > wire.CARD_SPILL_THRESHOLD_BYTES ? wire.cardSpillParts(card) : [];
    const store = this.spillStore;
    // a card whose size sits outside the spill set (a long name or description) has nothing to move
    const spills = parts.length > 0 && open && store !== null;
    this.warnCard(kept.adType, card, size, spills);
    let signed = card;
    if (size > wire.CARD_SPILL_THRESHOLD_BYTES) {
      signed = spills ? this.spill(kept.adType, card, parts, store!) : card;
      if (signed === card) {
        this.cardsOversizeInline += 1;
      }
    }
    this.sendAd(kept.adType, signed);
  }

  /** The stub of a full card once its parts document is on the swarm, or the card itself when the swarm refuses it. */
  private spill(adType: "AppCard" | "AgentCard", card: Dict, parts: string[], store: SpillStore): Dict {
    const partsSchema = adType === "AppCard" ? records.APP_CARD_PARTS : records.AGENT_CARD_PARTS;
    const document = dumps(records.conform(wire.cardParts(card), partsSchema));
    let root: string;
    try {
      root = store.put(String(card["id"]), document);
    } catch (e) {
      this.onWarning(`the content swarm refused the parts document of ${String(card["id"])}; the card travels inline: ${String(e)}`);
      return card;
    }
    this.holdSpill(root, parseInstantMillis(card["issued"]) + parseDurationMillis(card["ttl"]));
    this.cardsSpilled += 1;
    return wire.cardStub(card, { root, size: document.length, parts });
  }

  /** FR-13: one warning per card id and encoded size past 57,344 bytes, naming the card and saying what happens. */
  private warnCard(adType: string, card: Dict, size: number, spills: boolean): void {
    const id = String(card["id"]);
    if (size <= wire.CARD_SPILL_WARN_BYTES || this.warnedSizes.get(id) === size) {
      return;
    }
    this.warnedSizes.set(id, size);
    const kind = adType === "AppCard" ? `AppCard (kind ${String(card["kind"])})` : adType;
    const fate = size <= wire.CARD_SPILL_THRESHOLD_BYTES ? "it travels inline until it passes the threshold"
      : spills ? "it spills its large parts to the content swarm"
        : "it travels inline, since a member is below the AppCard level, no content swarm serves the group,"
          + " or no field of its spill set holds anything";
    this.onWarning(`${kind} ${id} encodes to ${size} bytes, past the ${wire.CARD_SPILL_WARN_BYTES}-byte warning`
      + ` and ${size <= wire.CARD_SPILL_THRESHOLD_BYTES ? "within" : "past"} the ${wire.CARD_SPILL_THRESHOLD_BYTES}-byte`
      + ` spill threshold; ${fate}`);
  }

  /** Keeps a parts document served until the last card that names it expires. */
  private holdSpill(root: string, until: number): void {
    this.spillHolds.set(root, Math.max(this.spillHolds.get(root) ?? 0, until));
    this.spillSweep ??= this.every(SPILL_SWEEP_MILLIS, () => this.sweepSpills());
  }

  /** Releases every parts document whose last naming card has expired. */
  private sweepSpills(): void {
    const now = this.now();
    for (const [root, until] of [...this.spillHolds]) {
      if (now >= until) {
        this.spillHolds.delete(root);
        this.spillStore?.release(root);
      }
    }
    if (this.spillHolds.size === 0) {
      this.spillSweep?.stop();
      this.spillSweep = null;
    }
  }

  /** Forgets the kept cards whose last issue has expired: this peer issues them no more. */
  private pruneIssuedCards(): void {
    const now = this.now();
    for (const [id, kept] of [...this.issuedCards]) {
      if (kept.issued + parseDurationMillis(kept.full["ttl"]) <= now) {
        this.issuedCards.delete(id);
        this.warnedSizes.delete(id);
      }
    }
  }

  /**
   * A member's AppCard level may have changed (its advertisement arrived or changed, it left, or this peer's own
   * level changed): every kept card last issued under the other gate whose form depends on the gate goes out again at
   * once. A card issued while a member heard only by its frames held the gate closed thus follows when that member's
   * advertisement arrives, whatever the gate of the cards issued since.
   */
  private appCardLevelChanged(): void {
    if (this.issuedCards.size === 0) {
      return;
    }
    const open = this.appCardGateOpen();
    this.pruneIssuedCards();
    for (const [id, kept] of this.issuedCards) {
      if (kept.open === open) {
        continue;
      }
      const schema = kept.adType === "AppCard" ? records.APP_CARD : records.AGENT_CARD;
      const gated = kept.adType === "AppCard"
        && Object.keys(wire.appCardForView(kept.full, false)).length !== Object.keys(kept.full).length;
      if (gated || dumps(records.conform(kept.full, schema)).length > wire.CARD_SPILL_THRESHOLD_BYTES) {
        this.issueCard(id);
      } else {
        kept.open = open; // its form is the same under either gate
      }
    }
  }

  /** The live AgentCards the ads stream carried. */
  cards(): Dict[] {
    const now = this.now();
    return [...this.ads.values()].filter((e) => e.type === "AgentCard" && e.expires > now).map((e) => e.ad);
  }

  /**
   * One capability frame to a member (CapabilityPipes.send): a PIPE_DATA envelope addressed to
   * it. A dial-only peer's seed carries it when `to` is any other member (SPEC §5.4); `via` (the
   * relays the member declared) extends the path past the seed.
   */
  sendPipe(to: string, capability: string, payload: Uint8Array, via: string[] | null = null): void {
    this.sendAddressed("PIPE_DATA", dumps({ capability, payload }), to, via);
  }

  /**
   * The relay an addressed frame to `to` goes through, or null for a direct send: for a peer
   * that only dialed (no accepted links), the seed for everyone but the seed itself.
   */
  relayFor(to: string): string | null {
    if (this.channel === null || this.inbound.size > 0 || this.seedPeer === null || to === this.seedPeer) {
      return null;
    }
    return this.seedPeer;
  }

  /**
   * Sends an addressed frame directly or, when the seed must carry it, wrapped in a
   * `RELAY_FRAME` to the seed (the one-hop form), extended to a path `[seed, via...]` when
   * `via` names other relays (v0.1.23).
   */
  sendAddressed(kind: string, body: Uint8Array, to: string, via: string[] | null = null): void {
    const relay = this.relayFor(to);
    if (relay === null) {
      this.send(kind, body, to);
      return;
    }
    const inner = wire.encodeFrame(wire.envelope(this.group, kind, this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now()), body, to), this.identity);
    const path = [relay, ...(via ?? []).filter((v) => v !== relay && v !== to)].slice(0, Math.max(1, this.maxPathHops));
    this.relayedFrames += 1;
    this.send("RELAY_FRAME", path.length > 1 ? wire.relayFrameBody(to, inner, path, 0)
      : wire.relayFrameBody(to, inner), relay);
    this.noteRelayed(to);
  }

  /**
   * The payload bytes of an entry's record: inline, or resolved from a block (`z`) or a content
   * root (`b`) held here. A reference not yet held starts its transfer and returns null; reads
   * never block on the network (SPEC §7.2). A null payload with no reference is the CBOR null.
   */
  payloadOf(dto: Dict): Uint8Array | null {
    const record = (dto["record"] as Dict | undefined) ?? {};
    const payload = record["payload"];
    if (payload instanceof Uint8Array) {
      return payload;
    }
    const ref = record["payloadRef"];
    if (typeof ref !== "string" || ref.length === 0) {
      return new Uint8Array([0xf6]);
    }
    if (ref.startsWith("b")) {
      // SPEC §7.1 tree roots: the codec alone tells a persistent tree (dag-cbor, 0x71) from a piece
      // artifact (raw, 0x55); each goes to the seam that can carry it, never the other
      // (srad/agentspaces-pdt.md PD-E-01). Without a facade a tree root stays invisible here.
      if (isTreeRoot(ref)) {
        return this.pdt === null ? null : this.pdt.payload(ref);
      }
      if (this.content === null) {
        return null;
      }
      const data = this.content.local(ref);
      if (data === null) {
        this.content.ensure(ref);
      }
      return data;
    }
    const block = this.blocks.get(ref);
    if (block === undefined) {
      this.wantBlock(ref, dto);
    }
    return block ?? null;
  }

  /** Asks the entry's issuing peer (and the seed) for a block, at most once a second. */
  wantBlock(cid: string, dto: Dict | null = null): void {
    const now = this.monotonic();
    if (now - (this.blockAsked.get(cid) ?? Number.NEGATIVE_INFINITY) < 1000) {
      return;
    }
    this.blockAsked.set(cid, now);
    const targets: string[] = [];
    const key = dto?.["issuerPublicKey"];
    if (key instanceof Uint8Array) {
      targets.push(deriveId(key));
    }
    if (this.seedPeer !== null && !targets.includes(this.seedPeer)) {
      targets.push(this.seedPeer);
    }
    for (const target of targets) {
      if (target !== this.identity.peerId) {
        this.sendAddressed("BLOCK_WANT", wire.blockWantBody(cid), target);
      }
    }
  }

  /** Stores a block here and returns its id; served to any member that asks. */
  putBlock(data: Uint8Array): string {
    const cid = wire.contentId(data);
    this.blocks.set(cid, data);
    return cid;
  }

  /** The members whose advertisement declares the RELAY role (SPEC §5.4). */
  relayMembers(): string[] {
    const out: string[] = [];
    for (const [id, ad] of this.members) {
      const roles = ad["roles"];
      if (Array.isArray(roles) && roles.some((r) => String(r) === "RELAY") && id !== this.identity.peerId) {
        out.push(id);
      }
    }
    return out;
  }

  /**
   * A capability frame to a member (SRAD srad/agentspaces-js.md JS-W-03): sent directly when the
   * target is reachable, otherwise inside a `RELAY_FRAME` through a reachable RELAY-role member.
   * The inner frame is this peer's fully signed `PIPE_DATA` to the target, so the relay forwards
   * it verbatim and the target verifies the origin. Returns whether a route was found.
   */
  sendPipeOrRelay(to: string, capability: string, payload: Uint8Array): boolean {
    if (this.reachable.has(to) || this.relayFor(to) !== null) {
      this.sendPipe(to, capability, payload);
      return true;
    }
    const relay = this.relayMembers().find((m) => this.reachable.has(m));
    if (relay === undefined) {
      return false;
    }
    const inner = wire.encodeFrame(wire.envelope(this.group, "PIPE_DATA", this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now()), dumps({ capability, payload }), to), this.identity);
    this.send("RELAY_FRAME", wire.relayFrameBody(to, inner), relay);
    this.noteRelayed(to); // JS-W-11: a frame the relay carried for this pair
    return true;
  }

  /**
   * The relay offload's observation (SRAD srad/agentspaces-js.md JS-W-11, PeerNode.noteRelayed):
   * per member, the clock stamps of the frames relayed between this peer and it in the last
   * minute, sent through a relay or unwrapped from a `RELAY_FRAME` addressed here. The core only
   * counts and tells; a binding that can open a direct connection (`@agentspaces/webrtc`)
   * subscribes and decides, with its own threshold and backoff. Bounded as a cache, not a cap.
   */
  private readonly relayedWith = new Map<string, number[]>();
  private readonly relayedListeners: ((member: string, framesInLastMinute: number) => void)[] = [];
  /** How many members' relay windows stay remembered; the least recently relayed-with is dropped past it. */
  relayedMemory = 4096;

  /** Registers an observer told, on every frame relayed to or from a member, how many were in the sliding minute. */
  onRelayed(listener: (member: string, framesInLastMinute: number) => void): this {
    this.relayedListeners.push(listener);
    return this;
  }

  /** The frames relayed between this peer and a member in the last minute, as the offload counts them. */
  relayedWithInLastMinute(member: string): number {
    const times = this.relayedWith.get(member);
    return times === undefined ? 0 : pruneMinute(times, this.now());
  }

  private noteRelayed(member: string): void {
    const now = this.now();
    let times = this.relayedWith.get(member);
    if (times === undefined) {
      times = [];
    } else {
      this.relayedWith.delete(member); // re-inserted last: the map's order is the recency order
    }
    this.relayedWith.set(member, times);
    pruneMinute(times, now);
    times.push(now);
    while (this.relayedWith.size > this.relayedMemory) {
      const eldest = this.relayedWith.keys().next().value;
      if (eldest === undefined) {
        break;
      }
      this.relayedWith.delete(eldest);
    }
    const count = times.length;
    for (const listener of this.relayedListeners) {
      try {
        listener(member, count);
      } catch {
        // an observer's failure never stops the frame
      }
    }
  }

  /**
   * A `peers` stream item (PeerNode.SignedPeerAd): kept under its issuer when it and its
   * PeerAdvertisement read strictly (HLC round six, 2026-11-08, F3) and its signature verifies.
   */
  private acceptPeerAd(payload: Uint8Array): void {
    try {
      const signed = records.readRecord(payload, records.SIGNED_PEER_AD);
      if (signed === null) {
        return;
      }
      const adBytes = signed["adBytes"] as Uint8Array;
      const key = signed["publicKey"] as Uint8Array;
      if (key.length !== 32 || !Identity.verify(key, adBytes, signed["signature"] as Uint8Array)) {
        return;
      }
      const ad = records.readRecord(adBytes, records.PEER_ADVERTISEMENT);
      if (ad !== null && ad["issuer"] === deriveId(key)
          && ad["issuer"] !== this.identity.peerId) {
        const issuer = String(ad["issuer"]);
        const previous = this.members.get(issuer);
        if (previous !== undefined && previous["issued"] !== undefined
            && parseInstantMillis(previous["issued"]) > parseInstantMillis(ad["issued"])) {
          return; // an older issue of an advertisement already held
        }
        this.members.set(issuer, ad);
        this.heldPeerAds.set(issuer, payload);
        this.appCardLevelChanged();
        const hints = (ad["resourceHints"] ?? {}) as Dict;
        if (this.channelAuth === "session" && hints[SESSION_HINT] === "1") {
          this.sessionPeers.add(String(ad["issuer"]));
        } else {
          this.sessionPeers.delete(String(ad["issuer"]));
        }
        this.noteReplicationHints(issuer, hints);
      }
    } catch {
      // not a peer advertisement
    }
  }

  /**
   * Called after a state folds, for spaces and watches: the merged state, and the state this replica held
   * before, when it held one (core cancel events, 2026-11-09: a space raises EXPIRED for a withdrawal of an
   * entry that was present).
   */
  onState: ((dto: Dict, previous?: Dict) => void) | null = null;
  /** Takes waiting for the next fold (JS-V-02): woken by a state or a claim, or by their own deadline. */
  private readonly foldWaiters = new Set<() => void>();
  /** When the last anti-entropy pull of each space went out, so a waiting take pulls at most once per settle window. */
  private readonly lastPullMillis = new Map<string, number>();

  /** Resolves on the next fold (a state or a claim) or after `maxMillis`, whichever comes first. */
  awaitFold(maxMillis: number): Promise<void> {
    return this.foldOrTimeout(maxMillis);
  }

  /**
   * Resolves after exactly `millis` on this peer's timers, whatever folds meanwhile: the take's settle
   * window, which a fold must never shorten.
   */
  private settle(millis: number): Promise<void> {
    return new Promise<void>((resolve) => {
      this.timers.setTimeout(resolve, Math.max(0, millis));
    });
  }

  /** Resolves on the next fold or after `maxMillis`, whichever comes first. */
  private foldOrTimeout(maxMillis: number): Promise<void> {
    return new Promise<void>((resolve) => {
      const timer = this.timers.setTimeout(() => {
        this.foldWaiters.delete(wake);
        resolve();
      }, Math.max(0, maxMillis));
      const wake = (): void => {
        this.timers.clearTimeout(timer);
        this.foldWaiters.delete(wake);
        resolve();
      };
      this.foldWaiters.add(wake);
    });
  }

  private wakeFoldWaiters(): void {
    for (const wake of [...this.foldWaiters]) {
      wake();
    }
  }

  /** Pulls a space unless it was pulled within `settleMillis` (JS-Q-PRF-01: one DIGEST per settle window). */
  private pullSpacePaced(space: string, settleMillis: number): void {
    const now = this.monotonic();
    if (now - (this.lastPullMillis.get(space) ?? -Infinity) >= settleMillis) {
      this.lastPullMillis.set(space, now);
      this.pullSpace(space);
    }
  }
  /** Called after a claim folds (the merged signed claim). */
  onClaim: ((entryId: string, signed: Dict) => void) | null = null;
  /** Called with the entry ids a tombstone collection dropped, so spaces forget what they judged of them. */
  onCollected: ((entryIds: string[]) => void) | null = null;

  /**
   * Installs a claim the ordered log committed (OrderedTakes.onCommand, SPEC §7.4 ORDERED):
   * exactly as the holder signed it, through the same verification gossip gets, and then
   * gossips it on the space's stream so members outside the log learn it. Returns whether the
   * claim is now the one held for the entry.
   */
  applyCommittedClaim(space: string, entryId: string, signed: Dict): boolean {
    this.foldClaim(entryId, signed, true);
    const held = this.claims.get(entryId);
    if (held === undefined || !equals(dumps((held["claim"] as Dict) ?? {}), dumps((signed["claim"] as Dict) ?? {}))) {
      return false;
    }
    this.send("RUMOR", wire.rumorBody(`space:${space}`, `c:${entryId}:${this.now()}`, this.rumorHops,
      wire.claimDelta(entryId, held)));
    return true;
  }

  /**
   * Joins a space by name: its rumors and anti-entropy answers fold here from now on. Pulling,
   * writing, and opening a Space join it; this peer relays a rumor of a space it has not joined
   * without decoding it (HLC round five, 2026-11-08).
   */
  joinSpace(space: string): void {
    this.joinedSpaces.add(space);
  }

  /**
   * Collects tombstones (SPEC §7.3, ReplicatedSpace's sweep): drops every entry past its collection
   * horizon, with its claim and any block or bulk payload no remaining entry names, and tells
   * `onCollected`. HLC round five, 2026-11-08: without it the replica held every entry ever written,
   * and each sweep, digest, and read grew with them. HLC round six, 2026-11-08: a collected entry's
   * bulk payload is released through the content seam (R9, Java's LB-E-04), and a claim on an entry
   * this replica collected or never held goes once its expiry passes, so the claim map stays bounded
   * (R10). Returns the collected entry ids.
   */
  collectTombstones(): string[] {
    const now = this.now();
    for (const [entryId, signed] of this.claims) {
      if (!this.states.has(entryId) && Number((signed["claim"] as Dict)["expiresAtMillis"]) <= now) {
        this.claims.delete(entryId);
      }
    }
    this.forgetAcknowledgements(now);
    this.judgeHorizons(now);
    const collected: string[] = [];
    for (const [entryId, dto] of this.states) {
      if (this.collectableHere(dto, now)) {
        collected.push(entryId);
      }
    }
    if (collected.length === 0) {
      return collected;
    }
    const released = new Set<string>();
    for (const entryId of collected) {
      const ref = (this.states.get(entryId)!["record"] as Dict | undefined)?.["payloadRef"];
      if (typeof ref === "string" && (this.blocks.has(ref) || this.isBulk(ref))) {
        released.add(ref);
      }
      this.states.delete(entryId);
      this.claims.delete(entryId);
      this.forgetSettleLines(entryId);
    }
    if (released.size > 0) {
      for (const dto of this.states.values()) {
        released.delete(String((dto["record"] as Dict | undefined)?.["payloadRef"]));
      }
      for (const ref of released) {
        if (this.isBulk(ref)) {
          this.content!.unpin(ref);
        } else {
          this.blocks.delete(ref);
          this.blockAsked.delete(ref);
        }
      }
    }
    this.onCollected?.(collected);
    return collected;
  }

  /**
   * Brings the tombstone collection forward to the wall instant `wallMillis` (SPEC v0.1.36 §9.5: the space sweep runs
   * when the earliest lapse falls due, not on a fixed 1 s ticker as before), registering it on the loop the first time.
   */
  private collectBy(wallMillis: number): void {
    if (!Number.isFinite(wallMillis)) {
      wallMillis = this.now();
    }
    const loop = this.loop;
    if (!this.collector) {
      this.collector = true;
      loop.add(COLLECT_TASK, (nowMono) => {
        this.collectTombstones();
        const next = this.nextCollection();
        return next === null ? null : nowMono + Math.max(0, next - this.now());
      }, null);
    }
    const at = loop.now() + Math.max(0, wallMillis - this.now());
    const current = loop.dueOf(COLLECT_TASK);
    if (current === null || at < current) {
      loop.reschedule(COLLECT_TASK, at);
    }
  }

  /** Asks the collection to judge again soon (the view or its hints changed), when it runs at all. */
  private wakeCollector(): void {
    if (this.collector && this.dueLoop !== null && !this.dueLoop.isStopped) {
      this.collectBy(this.now() + COLLECT_PERIOD_MILLIS);
    }
  }

  /** The earliest wall instant the collection has anything to do: a horizon, a claim's lapse, a forgotten line. */
  private nextCollection(): number | null {
    const now = this.now();
    let next = Number.POSITIVE_INFINITY;
    // An instant already past whose work did not happen (a withdrawal no member vouches for keeps the later horizon)
    // is judged again a collection period on, so a past deadline never spins the loop.
    const due = (at: number): void => {
      next = Math.min(next, at > now ? at : now + COLLECT_PERIOD_MILLIS);
    };
    for (const [entryId, signed] of this.claims) {
      if (!this.states.has(entryId)) {
        due(wire.claimNumber((signed["claim"] as Dict)["expiresAtMillis"]));
      }
    }
    for (const at of this.ackForgetAt.values()) {
      due(at);
    }
    for (const dto of this.states.values()) {
      for (const at of this.horizonsOf(dto)) {
        due(at);
      }
    }
    for (const space of this.joinedSpaces) {
      const spaceId = wireSpaceId(this.group, space);
      const at = this.horizonModes.get(spaceId)?.nextJudgement(now, this.viewHinted(now), this.roundMillis(),
        this.longestLease.get(spaceId) ?? 0);
      if (at !== undefined && at !== null) {
        due(at);
      }
    }
    return Number.isFinite(next) ? next : null;
  }

  /**
   * The instants a state could become collectable, under each rule (the rule in force moves with the view; running
   * early is safe, the run judges again). A present entry never before its own lapse.
   */
  private horizonsOf(dto: Dict): number[] {
    const kind = horizonKindOf(dto);
    const expiry = leaseExpiryOf(dto);
    const maxLease = this.longestLeaseOf(dto);
    const legacy = horizon.collectionHorizon(kind, expiry, maxLease, "legacy");
    if (kind === "present") {
      return [Math.max(legacy, expiry)];
    }
    if (kind !== "withdrawn") {
      return [legacy]; // only a bare withdrawal's horizon depends on the rule (keepMillis)
    }
    // A withdrawal takes the per-entry horizon only while its space's mode is engaged and this replica vouches for
    // every writer (collectableHere): the vouch comes one longest lease plus the grace into each writer's hinted stay.
    const spaceId = String((dto["record"] as Dict | undefined)?.["spaceId"]);
    if (this.horizonModes.get(spaceId)?.mode !== "PER_ENTRY") {
      return [legacy];
    }
    const adds = (dto["adds"] as Dict[] | undefined) ?? [];
    if (adds.length === 0) {
      return [legacy]; // nobody to vouch for: the legacy horizon (vouchesFor)
    }
    let vouchAt = Number.NEGATIVE_INFINITY;
    for (const dot of adds) {
      const writer = String(dot["replica"] ?? "");
      if (writer === this.identity.peerId) {
        continue;
      }
      const since = this.hintedSince.get(writer);
      vouchAt = Math.max(vouchAt, since === undefined || !this.members.has(writer) ? Number.POSITIVE_INFINITY
        : since + Math.max(0, maxLease) + horizon.LAPSED_GRACE_MILLIS);
    }
    const perEntry = horizon.collectionHorizon(kind, expiry, maxLease, "per-entry");
    return [Math.min(legacy, Math.max(perEntry, vouchAt))];
  }

  /** The earliest of {@link horizonsOf}. */
  private horizonOf(dto: Dict): number {
    return Math.min(...this.horizonsOf(dto));
  }

  /** Whether `ref` names a payload the content seam holds: a `b` root that is no persistent tree. */
  private isBulk(ref: string): boolean {
    return this.content !== null && ref.startsWith("b") && !isTreeRoot(ref);
  }

  /** The longest lease observed in the space of `dto`, the horizon's measure (SPEC §7.3). */
  private longestLeaseOf(dto: Dict): number {
    return this.longestLease.get(String((dto["record"] as Dict | undefined)?.["spaceId"])) ?? 0;
  }

  /**
   * Records the lease `dto` grants, from its lease stamp to its expiry, as the longest of its space
   * when it is (SPEC §7.3, HLC round five, 2026-11-08), capped at MAX_TRACKED_LEASE_MILLIS; a
   * non-positive lease records nothing.
   */
  private observeLease(dto: Dict): void {
    this.observeGrant(String((dto["record"] as Dict)["spaceId"]), leaseExpiryOf(dto) - wire.hlcPhysical(dto["leaseStamp"]));
  }

  /**
   * Records the hold a claim this replica merges grants, from its stamp to its expiry, as Java's
   * ReplicatedSpace observes every claim it merges and every take it makes (SPEC §7.3, HLC round
   * five, 2026-11-08): a space of short writes and long holds keeps its tombstones two holds.
   */
  private observeClaimLease(signed: Dict): void {
    const claim = signed["claim"] as Dict;
    this.observeGrant(String(claim["spaceId"]), Number(claim["expiresAtMillis"]) - wire.hlcPhysical(claim["stamp"]));
  }

  /** Raises the longest lease of `spaceId` to `grantedMillis`, capped at MAX_TRACKED_LEASE_MILLIS. */
  private observeGrant(spaceId: string, grantedMillis: number): void {
    const granted = Math.min(grantedMillis, MAX_TRACKED_LEASE_MILLIS);
    if (granted > (this.longestLease.get(spaceId) ?? 0)) {
      this.longestLease.set(spaceId, granted);
    }
  }

  /**
   * Anti-entropy pull (spec §5.3): offer an empty digest. The revocation
   * streams ride along: a partner answers only the streams a digest names, so
   * a late joiner learns the group's revocations here.
   */
  pullSpace(space: string): void {
    this.joinSpace(space);
    this.pulledSpaces.add(space);
    // HLC round four, 2026-11-08 (D5): the digest names no entry, so the partner answers with every
    // state but those this replica refused and acknowledges.
    const digests = { [`space:${space}`]: utf8(this.acknowledgedLines(space)), ...revocationDigests() };
    // Toward a seed on wire.ae=2 the whole-space answer comes under this peer's budget, newest first, and the
    // remainder continues as an audit, so a late joiner's pull never needs one frame of the whole space (RE-I-04).
    const seed = this.seedPeer;
    if (seed !== null && this.audits(seed)) {
      this.expectPull(seed);
      this.awaitBudgetedPull(seed);
      this.send("DIGEST", wire.digestRecord({ digests, budget: this.trieAudit.budget }), null, "dial");
      return;
    }
    this.send("DIGEST", wire.digestBody(digests), null, "dial");
  }

  /**
   * Anti-entropy pull of the membership view (SPEC §5.2, v0.1.17: the view is reconcilable
   * state, the `view` stream): the digest names the members this peer holds, and the partner
   * answers with the signed advertisements it lacks, so a late joiner behind a seed learns the
   * members whose introductions it never saw.
   */
  pullView(): void {
    this.pulledView = true;
    this.send("DIGEST", wire.digestBody({ view: this.viewDigest() }), null, "dial");
  }

  private pulledView = false;

  /** `PeerNode.ViewState.digest`: one line per member held, this peer included. */
  viewDigest(): Uint8Array {
    const ids = [...this.heldPeerAds.keys(), this.identity.peerId].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return utf8(ids.map((id) => `${id}\n`).join(""));
  }

  /** `PeerNode.ViewState.deltaFor`: the signed advertisements the remote digest does not name, this peer's own included. */
  viewDeltaFor(remoteDigest: Uint8Array): Uint8Array {
    const remote = serving.parseDigestLines(remoteDigest);
    const missing: Uint8Array[] = [];
    for (const [id, payload] of this.heldPeerAds) {
      if (!remote.has(id)) {
        missing.push(payload);
      }
    }
    if (!remote.has(this.identity.peerId)) {
      missing.push(wire.signedPeerAd(this.selfAd(), this.identity));
    }
    return missing.length === 0 ? new Uint8Array() : dumps(missing);
  }

  /**
   * Anti-entropy pull of the revocation streams alone (SPEC §5.6): sent once
   * on joining, so revocations issued before this peer arrived apply from its
   * first merge.
   */
  pullRevocations(): void {
    // The membership view rides along (SPEC §5.2, v0.1.17): a late joiner behind a seed learns the
    // members whose introductions it never saw, from the same answer.
    this.pulledView = true;
    this.send("DIGEST", wire.digestBody({ ...revocationDigests(), view: this.viewDigest() }), null, "dial");
  }

  /** Returns decoded values of known live entries of one schema type. */
  find(typeName: string): Dict[] {
    const results: Dict[] = [];
    for (const dto of this.states.values()) {
      const record = dto["record"] as Dict | undefined;
      if (record && record["type"] === typeName && present(dto)) {
        const read = applicationValue(this.payloadOf(dto));
        if (read !== null) {
          results.push(read.value);
        }
      }
    }
    return results;
  }

  /**
   * Takes one entry under LEASE_RACE (spec §7.4): publish a signed claim,
   * wait one settle window, and win when the lattice still says so.
   *
   * The claim must still be live when the take is judged, which in a quiet
   * space is after the whole settle window and a follow-up wait of up to
   * min(settleMillis, 300) ms, so `leaseMillis` must exceed
   * `takeJudgedWithinMillis(settleMillis)` (900 ms for the default 600 ms
   * window). A take whose lease cannot outlast that throws a RangeError
   * rather than racing for nothing until its timeout. Leave a margin above
   * the bound: a busy event loop fires the timers late.
   */
  async takeEntry(space: string, typeName: string, agentName = "ts-worker",
                  leaseMillis = 60_000, settleMillis = 600,
                  timeoutMillis = 15_000, agent: AgentIdentity | null = null,
                  exactEntryId: string | null = null,
                  matches: ((payload: Dict, tags: Dict) => boolean) | null = null,
                  bid: number | ((payload: Dict) => number) = 0.0): Promise<string | null> {
    // Only a live claim wins, as in Java's tryTakeOnce, and in a quiet space the claim is judged after the
    // settle window and the follow-up wait. A lease no longer than both has always lapsed by then, so such
    // a take could only publish doomed claims, each blocking other takers for its lease, and return null
    // after its timeout as if it had lost a race (2026-11-15: the browser host took a 600 ms lease with a
    // 600 ms window and never won; leases up to 900 ms failed the same way). Java judges right after its
    // window, so its bound is the window alone.
    const judgedWithin = takeJudgedWithinMillis(settleMillis);
    if (!(leaseMillis > judgedWithin)) {
      throw new RangeError(`a take lease of ${leaseMillis} ms cannot outlast its settle window of `
        + `${settleMillis} ms and follow-up wait of ${takeFollowUpMillis(settleMillis)} ms: the claim `
        + `would lapse before the take is judged (the lease must exceed ${judgedWithin} ms)`);
    }
    const holder = agent !== null ? agent.agentId : this.identity.agent(agentName);
    if (this.revocations.refuses(holder, agent?.publicRaw ?? null, null)) {
      return null; // a revoked agent takes nothing, even locally
    }
    const deadline = this.monotonic() + timeoutMillis;
    while (this.monotonic() < deadline) {
      // Fold-driven (JS-V-02): one pull per settle window at most, then wait for a fold rather
      // than a fixed sleep, so an entry that arrives wakes the take at once.
      this.pullSpacePaced(space, settleMillis);
      await this.foldOrTimeout(Math.min(settleMillis, deadline - this.monotonic()));
      const now = this.now();
      for (const [entryId, dto] of this.states) {
        const record = dto["record"] as Dict | undefined;
        if (!record || record["type"] !== typeName || !present(dto)
            || (record["group"] !== undefined && record["group"] !== this.group)
            || record["spaceId"] !== wireSpaceId(this.group, space)
            || (exactEntryId !== null && entryId !== exactEntryId)) {
          continue;
        }
        if (leaseExpiryOf(dto) <= now) {
          continue;
        }
        const current = this.claims.get(entryId)?.["claim"] as Dict | undefined;
        if (current && Number(current["expiresAtMillis"]) > now) {
          continue;
        }
        // A template narrows the candidates; a bid function prices the claim (AUCTION).
        const read = applicationValue(this.payloadOf(dto));
        if (read === null) {
          continue; // its block or artifact is still on its way, or its value is unreadable
        }
        const payload = read.value;
        if (matches !== null && !matches(payload ?? {}, (record["tags"] as Dict) ?? {})) {
          continue;
        }
        const price = typeof bid === "function" ? bid(payload ?? {}) : bid;
        const epoch = current ? Number(current["epoch"]) + 1 : 1;
        const claim = wire.takeClaim(entryId, String(record["spaceId"]), epoch,
          wire.hlcNow(holder, now), holder, price, now + leaseMillis);
        const signed = wire.signedClaim(claim, this.identity, agent);
        this.observeClaimLease(signed);
        this.mergeHeldClaim(entryId, signed);
        this.send("RUMOR", wire.rumorBody(`space:${space}`,
          `c:${entryId}:${claim["stamp"]}`, 6, wire.claimDelta(entryId, signed)));
        // The settle window is waited in full, as the Python and Java takes wait it: a competing
        // claim folds within it. Waking at the first fold of any entry ended the window early in a
        // busy space, so this peer judged the race before the rival claim arrived, kept a claim it
        // had lost, and two takers ran one task (2026-11-11, exactly-once over TLS).
        await this.settle(settleMillis);
        this.pullSpacePaced(space, settleMillis);
        await this.foldOrTimeout(takeFollowUpMillis(settleMillis));
        const winner = this.claims.get(entryId)?.["claim"] as Dict | undefined;
        if (winner && winner["holder"] === holder
            && Number(winner["epoch"]) === epoch
            && Number(winner["expiresAtMillis"]) > this.now()
            // core cancel events, 2026-11-09: an entry completed or withdrawn during the settle window is nobody's
            && present(this.states.get(entryId) ?? {})
            && !this.revocations.refuses(holder, agent?.publicRaw ?? null, null)) {
          if (this.outbidCompletions.get(entryId) === epoch) {
            // The holder this claim displaced completed the entry during the window (SPEC §7.4, rule two): the work
            // is done, so this take acknowledges that completion instead of doing it again, and comes back empty here.
            try {
              this.acknowledgeDisplacedCompletion(space, entryId, agent);
            } catch {
              // the claim lapsed or a better one arrived meanwhile: whoever holds it completes it
            }
            continue;
          }
          this.outbidCompletions.delete(entryId);
          // As Java's take fires TAKEN for the claim it won (HLC round six, 2026-11-08, R9).
          this.onClaim?.(entryId, this.claims.get(entryId)!);
          return entryId;
        }
      }
    }
    return null;
  }

  /**
   * Completes a held entry: publish its state with completed set (monotone),
   * re-signed with our (holder) key and carrying our winning claim, so honest
   * replicas can authenticate the completion (SPEC §11a).
   */
  completeEntry(space: string, entryId: string, agent: AgentIdentity | null = null): void {
    this.requireHeld(space, entryId, agent);
    const heldEpoch = wire.claimNumber((this.claims.get(entryId)!["claim"] as Dict)["epoch"]);
    if (this.outbidCompletions.get(entryId) === heldEpoch) {
      this.outbidCompletions.delete(entryId);
      this.displacedAcknowledged += 1; // the acknowledgement of a displaced holder's completion (SPEC §7.4)
    } else {
      // This holder does the work, so a displaced holder's completion that arrives later is a duplicate.
      this.completedHere.set(entryId, { epoch: heldEpoch, space });
      capLines(this.completedHere);
    }
    // A claim taken as an agent must be completed as that agent (A6, v0.1.13).
    const previous = this.states.get(entryId)!;
    const dto = wire.signState({ ...previous, completed: true }, this.identity, agent, this.now());
    this.states.set(entryId, dto);
    this.onState?.(dto, previous);
    const proof = this.claims.get(entryId) ?? null;
    this.send("RUMOR", wire.rumorBody(`space:${space}`, `d:${entryId}`, 6,
      dumps({ state: dto, claimEntry: proof ? entryId : null, claim: proof })));
  }

  /** Checks the exact current live claim before an application emits a result. */
  requireHeld(space: string, entryId: string, agent: AgentIdentity | null = null): void {
    const state = this.states.get(entryId), record = state?.["record"] as Dict | undefined;
    const claim = this.claims.get(entryId)?.["claim"] as Dict | undefined;
    const holder = agent?.agentId ?? claim?.["holder"];
    const signed = this.claims.get(entryId);
    const localPeerHolder = agent !== null || (typeof holder === "string"
      && holder.startsWith(this.identity.peerId + "/") && signed?.["holderCertificate"] == null
      && signed?.["holderKey"] instanceof Uint8Array
      && equals(signed["holderKey"] as Uint8Array, this.identity.publicRaw));
    if (!record || (record["group"] !== undefined && record["group"] !== this.group) || record["spaceId"] !== wireSpaceId(this.group, space)
        // core cancel events, 2026-11-09: a completed or withdrawn entry is held by nobody, as in Java
        || !localPeerHolder || !present(state ?? {}) || !claim || claim["entryId"] !== entryId
        || claim["spaceId"] !== record["spaceId"] || claim["holder"] !== holder
        || !Number.isFinite(Number(claim["expiresAtMillis"])) || Number(claim["expiresAtMillis"]) <= this.now()
        || Number(((state?.["leaseValue"] ?? record["lease"]) as Dict)?.["expiresAtMillis"]) <= this.now()
        || this.revocations.refuses(holder, agent?.publicRaw ?? null, null)) {
      throw new Error("Current exact live claim required");
    }
  }

  /**
   * Extends a held claim to at least `leaseMillis` from now, never shorter (SPEC §7.2 renewal, v0.1.35).
   * The renewal is the same take, so it keeps the claim's epoch, stamp and bid and moves only the expiry,
   * as Java's TakenEntry.renew does; the lattice prefers the later expiry of two otherwise equal claims.
   */
  renewClaim(space: string, entryId: string, leaseMillis: number, agent: AgentIdentity | null = null): void {
    if (!Number.isFinite(leaseMillis) || leaseMillis <= 0) throw new Error("Positive lease required");
    this.requireHeld(space, entryId, agent);
    const previous = this.claims.get(entryId)!["claim"] as Dict;
    // A take made without an agent is held by one of this peer's agent names and signed by the peer, so its renewal is.
    const holder = agent?.agentId ?? String(previous["holder"]);
    const now = this.now();
    const current = Number(previous["expiresAtMillis"]);
    const expiry = Math.max(current, now + leaseMillis);
    if (expiry === current) {
      return; // the hold already runs that long, so nothing changes and nothing goes out (as Java, RE-H-02)
    }
    // A fresh epoch here made the renewal a new take: it outranked the held claim whatever its expiry, so
    // a shorter renewal shortened the hold, and every replica, Java's included, announced TAKEN again for
    // the new epoch. A fresh stamp broke SPEC §6.1, under which a renewal keeps the original stamp.
    const claim = wire.takeClaim(entryId, String(previous["spaceId"]), wire.claimNumber(previous["epoch"]),
      String(previous["stamp"]), holder, wire.claimNumber(previous["bid"]), expiry);
    const signed = wire.signedClaim(claim, this.identity, agent);
    this.observeClaimLease(signed);
    this.claims.set(entryId, wire.mergeClaims(this.claims.get(entryId), signed));
    // The stamp no longer names the renewal, so its rumor id says renew and when, as Java's does; the
    // original claim's id would be taken for the claim already heard.
    this.send("RUMOR", wire.rumorBody(`space:${space}`, `c:${entryId}:renew:${now}`, 6,
      wire.claimDelta(entryId, signed)));
  }

  /** Snapshot contains signed public material only. Restore re-verifies every entry. */
  exportSnapshot(): Dict {
    return { group: this.group, states: [...this.states].map(([id, dto]) => this.signedStateOf(id, dto)), claims: Object.fromEntries(this.claims), revocations: this.revocations.exportSigned() };
  }
  restoreSnapshot(snapshot: Dict): void {
    if (snapshot["group"] !== this.group) throw new Error("Snapshot group mismatch");
    this.revocations.restoreSigned((snapshot["revocations"] ?? {}) as Dict, this.now());
    // HLC round six, 2026-11-08 (F1): a claim or state that is no conformed SignedClaim or
    // EntryStateDto counts as an undecodable carrier, as a delta bringing it would.
    for (const [id, held] of Object.entries((snapshot["claims"] ?? {}) as Dict)) {
      const claim = records.conformed(held, records.SIGNED_CLAIM);
      if (claim === null) {
        this.deltasUndecodable += 1;
        continue;
      }
      this.foldClaim(id, claim);
    }
    for (const held of (snapshot["states"] ?? []) as Dict[]) {
      const dto = records.conformed(held, records.ENTRY_STATE);
      if (dto === null) {
        this.deltasUndecodable += 1;
        continue;
      }
      if (dto["record"] !== undefined) this.fold(dto);
    }
  }

  /**
   * Cancels an entry this peer (or `agent`) wrote, as `EntryHandle.cancel` does in Java: a state whose
   * `removes` cover its `adds`, signed by the issuer, so every replica drops the entry. Reads, finds,
   * takes, and watches here skip it at once, and the replica keeps its tombstone until the collection
   * horizon (SPEC §7.3, HLC round five, 2026-11-08). Watches here hear EXPIRED at once, and every other
   * member's when the withdrawal folds there (core cancel events, 2026-11-09). An entry this replica holds
   * completed or withdrawn stays as it is and nothing goes out, as Java's `EntryHandle.cancel` leaves it: an
   * issuer's signature over a completed state verifies nowhere (SPEC §11a.4).
   */
  cancelEntry(space: string, entryId: string, agent: AgentIdentity | null = null): void {
    const previous = this.states.get(entryId);
    if (previous === undefined) {
      throw new Error(`${entryId} is not held here`);
    }
    const record = previous["record"] as Dict;
    const issuer = String(record["issuer"]);
    if (agent !== null && agent.agentId !== issuer) {
      throw new Error(`${entryId} was written by ${issuer}, not ${agent.agentId}`);
    }
    if (agent === null && !issuer.startsWith(this.identity.peerId + "/")) {
      throw new Error(`${entryId} was written by ${issuer}, not by this peer`);
    }
    if (!present(previous)) {
      return;
    }
    const now = this.now();
    const dto = wire.signState({ ...previous, removes: unionDots(previous["removes"], previous["adds"]) },
      this.identity, agent, now);
    this.states.set(entryId, dto);
    this.onState?.(dto, previous);
    this.send("RUMOR", wire.rumorBody(`space:${space}`, `x:${entryId}:${now}`, 6,
      dumps({ state: dto, claimEntry: null, claim: null })));
  }

  /**
   * Renews this peer's write of an entry (SPEC §7.2, v0.1.35, normative): the write lease runs to at least
   * `leaseMillis` from now and never shortens, `expiry = max(current, now + leaseMillis)`, so the issuer's last lease
   * is the largest any copy carries, which the collection horizons of §7.3 rely on. Three conditions guard it, each
   * refused here with nothing sent: only the issuer renews (`agent` must be the record's issuer, and without one the
   * issuer must be one of this peer's agent names), the entry is held present (neither completed nor withdrawn), and
   * its write lease has not lapsed here. A renewal the rule leaves unchanged sends nothing. A caller that wants an entry
   * gone sooner cancels it; one that wants a shorter lease cancels and writes again.
   */
  renewEntry(space: string, entryId: string, leaseMillis = 600_000,
             agent: AgentIdentity | null = null): void {
    const previous = this.states.get(entryId);
    if (previous === undefined) {
      throw new Error(`${entryId} is not held here`);
    }
    const record = previous["record"] as Dict;
    const issuer = String(record["issuer"]);
    if (agent !== null && agent.agentId !== issuer) {
      throw new Error(`${entryId} was written by ${issuer}, not ${agent.agentId}`);
    }
    if (agent === null && !issuer.startsWith(this.identity.peerId + "/")) {
      throw new Error(`${entryId} was written by ${issuer}, not by this peer`);
    }
    if (!Number.isFinite(leaseMillis) || leaseMillis < 0) {
      throw new RangeError(`a renewal extends by a non-negative lease, not ${leaseMillis}`);
    }
    const now = this.now();
    if (!present(previous)) {
      throw new Error(`${entryId} is no longer present here (completed or withdrawn), so it cannot be renewed`);
    }
    const current = leaseExpiryOf(previous);
    if (current <= now) {
      throw new Error(`the write lease of ${entryId} lapsed, so it cannot be renewed`);
    }
    if (now + leaseMillis < current) {
      this.renewShortenings += 1; // RE-H-01: a call that would have shortened the lease before v0.1.35
    }
    const expiry = Math.max(current, now + leaseMillis);
    if (expiry === current) {
      return; // the lease already runs that long: nothing changes and nothing goes out
    }
    const dto = wire.signState({ ...previous, leaseStamp: wire.hlcNow(issuer, now),
      leaseValue: { holder: issuer, expiresAtMillis: expiry, kind: "WRITE" } },
    this.identity, agent, now);
    this.observeLease(dto);
    this.states.set(entryId, dto);
    this.send("RUMOR", wire.rumorBody(`space:${space}`, `r:${entryId}:${now}`, 6,
      dumps({ state: dto, claimEntry: null, claim: null })));
  }

  // ------------------------------------------------------------------ internals

  /**
   * Opens a channel to one seed. The channel becomes this peer's link only once {@link adopt}ed: a refused dial ends
   * too, and that end must not start a second reconnect chain.
   */
  private async openSeed(seed: Seed): Promise<FrameChannel> {
    const dialer = this.dialers.get(schemeOf(seed));
    if (dialer === undefined) {
      throw new Error(`no dialer for ${schemeOf(seed)}`);
    }
    return dialer.dial(seed, { identity: this.identity });
  }

  /** Makes an opened channel to `seed` this peer's dialed link. */
  private adopt(channel: FrameChannel, seed: Seed): void {
    this.channel = channel;
    this.session = null;
    this.linkSince = this.monotonic();
    this.dialedSeed = seedUrl(seed);
    const attested = channel.attestedPeer();
    if (attested !== null && attested !== this.identity.peerId) {
      this.adoptSeedPeer(attested); // the transport proved who the seed is: it is the member this peer dialled
    } else if (this.seedPeer !== null && this.seedPeerOn !== this.dialedSeed) {
      // A failover to another seed: the one relay.via named no longer holds this peer's link, and a Java member's
      // targeted relay (SPEC v0.1.36 §5.2) would probe it through that member. The hint goes until the new seed's
      // first addressed frame names it.
      this.seedPeer = null;
      this.seedPeerOn = null;
      delete this.resourceHints["relay.via"];
      this.relayViaCleared += 1;
    }
    this.seedHeardAt = this.linkSince;
    this.seedAskedAt = null;
    this.seedVerdictFor = null;
    this.wakeAsked = null;
    channel.onFrame((frame) => {
      if (this.channel === channel) {
        this.seedHeard(); // any frame read off the link shows the seed still writes to it
      }
      this.onFrame(frame, null);
    });
    channel.onProgress?.(() => {
      if (this.channel === channel) {
        // Owner decision 4 of 2026-11-23 (SPEC v0.1.37's dead-seed row): bytes of a frame still arriving answer the
        // seed's PING too, so a large frame trickling over a slow link is no dead seed. Local only; no wire change.
        this.seedProgress += 1;
        this.seedHeard();
      }
    });
    channel.onClose(() => this.onChannelClosed(channel));
    this.loop.add(SEED_LINK_TASK, (now) => this.judgeSeedLink(now), this.seedHeardAt + LINK_QUIET_MILLIS);
    this.loop.add(SELF_AD_TASK, (now) => this.reLeaseSelfAd(now), this.linkSince + SELF_AD_REFRESH_MILLIS);
  }

  /** Self-advertisements re-issued by {@link SELF_AD_TASK}. */
  selfAdRefreshes = 0;

  /** Re-issues the self-advertisement every {@link SELF_AD_REFRESH_MILLIS} while a dialed link holds. */
  private reLeaseSelfAd(now: number): number | null {
    if (this.channel === null || !this.running) {
      return null; // the next dial arms it again
    }
    this.selfAdRefreshes += 1;
    this.introduce();
    return now + SELF_AD_REFRESH_MILLIS;
  }

  /** When a frame was last read off the dialed channel, and when this peer asked a silent one (monotonic; null: not asked). */
  private seedHeardAt = 0;
  private seedAskedAt: number | null = null;
  /** PINGs sent to a silent seed, and dialed links closed because the seed answered none (the dead-seed rule). */
  seedPings = 0;
  linksSilent = 0;

  /**
   * The dead-seed rule (owner decision 1 of 2026-11-23), a task on this peer's loop: a dialed channel silent for
   * {@link LINK_QUIET_MILLIS} is asked with a PING to the seed; one still silent {@link LINK_ANSWER_MILLIS} after the
   * PING is closed, and the close signal fails over to another seed. A run that comes late by more than the answer
   * window (a stalled runtime, whose frames may still wait unread) asks again rather than judge the seed by this
   * peer's own stall. Returns the next deadline; with no dialed channel it waits for the next dial.
   */
  private judgeSeedLink(now: number): number | null {
    const channel = this.channel;
    if (channel === null || !this.running) {
      return null;
    }
    const asked = this.seedAskedAt;
    if (asked === null) {
      const due = this.seedHeardAt + LINK_QUIET_MILLIS;
      if (now < due) {
        return due;
      }
      this.askSeed(now);
      return now + LINK_ANSWER_MILLIS;
    }
    const due = asked + LINK_ANSWER_MILLIS;
    if (now < due) {
      return due;
    }
    if (now - due > LINK_ANSWER_MILLIS) {
      this.askSeed(now); // this peer did not run for the whole window: the silence may be its own
      return now + LINK_ANSWER_MILLIS;
    }
    if (this.seedVerdictFor !== asked) {
      // The verdict waits one more turn of the runtime: a frame the seed sent in time may still sit unread behind
      // this timer (Node runs its due timers before it polls its sockets), and any frame read meanwhile clears the
      // ask. A timer set from a timer runs on the next turn, after that poll.
      this.seedVerdictFor = asked;
      return now + 1;
    }
    this.seedVerdictFor = null;
    this.linksSilent += 1;
    if (asked === this.wakeAsked) {
      this.failoverClosed = channel; // the wake's ask: a link young in monotonic time still fails over at once
    }
    this.wakeAsked = null;
    this.seedAskedAt = null;
    channel.close(); // the close signal fails over (onChannelClosed); a link this old is no quick drop
    return null;
  }

  /** Reads off the dialed link that brought part of a frame and no whole one, each counted as the seed heard. */
  seedProgress = 0;

  /** The seed wrote to the dialed link (a whole frame, or bytes of one still arriving): any ask is answered. */
  private seedHeard(): void {
    this.seedHeardAt = this.monotonic();
    this.seedAskedAt = null;
    this.wakeAsked = null;
  }

  /** The ask whose verdict waits one turn for frames already arrived (see {@link judgeSeedLink}). */
  private seedVerdictFor: number | null = null;

  /** A PING to the seed on the dialed channel (addressed once the seed is known), which every member answers at once. */
  private askSeed(now: number): void {
    this.seedAskedAt = now;
    this.seedPings += 1;
    this.sendOn(null, "PING", wire.pingBody(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)),
      this.seedPeer ?? (this.session?.confirmed ? this.session.remote : null));
  }

  /**
   * Sends a frame: addressed, on the link its recipient was heard on (the dialed channel for
   * anyone else); unaddressed, on the dialed channel and, with scope `all`, on every accepted
   * link too, so a host's own rumors reach each connection. An unaddressed frame under a
   * confirmed session is addressed to the session's peer, so it can travel tagged (the Java
   * node addresses its frames too).
   */
  protected send(kind: string, body: Uint8Array, to: string | null = null, scope: "all" | "dial" = "all"): void {
    if (kind === "RUMOR") {
      this.rememberRumor(body); // an echo of our own item is never forwarded again
    }
    if (to !== null) {
      const link = this.linkFor(to);
      if (link !== null || this.channel !== null) {
        this.sendOn(link, kind, body, to);
      } else {
        for (const other of this.inbound.values()) {
          this.sendOn(other, kind, body, to); // an unknown recipient with no dialed channel: every link
        }
      }
      return;
    }
    if (this.channel !== null) {
      this.sendOn(null, kind, body, this.session?.confirmed ? this.session.remote : null);
    }
    if (scope === "all" || this.channel === null) {
      for (const link of this.inbound.values()) {
        this.sendOn(link, kind, body, link.session?.confirmed ? link.session.remote : null);
      }
    }
  }

  /** One frame on one link (null: the dialed channel), under that link's session when it has one. */
  private sendOn(link: Link | null, kind: string, body: Uint8Array, to: string | null): void {
    this.sendEnvelopeOn(link, wire.envelope(this.group, kind, this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now()), body, to));
  }

  private sendEnvelope(env: Dict): void {
    this.sendEnvelopeOn(null, env);
  }

  private sendEnvelopeOn(link: Link | null, env: Dict): void {
    const session = link === null ? this.session : link.session;
    const channel = link === null ? this.channel : link.channel;
    const key = session?.keyFor(env["to"] as string | null, String(env["kind"])) ?? null;
    if (key !== null) {
      this.sessionFramesSent += 1;
    }
    const frame = session !== null
      ? session.encode(env, (e) => wire.encodeFrame(e, this.identity))
      : wire.encodeFrame(env, this.identity);
    channel?.send(frame);
  }

  /**
   * Opens this peer's half of a session (PeerNode.maybeSessionHello): once per connection, in
   * session mode, toward a member whose advertisement carries the hint, on a channel the
   * transport could not attest. The hello travels fully signed.
   */
  private maybeSessionHello(peer: string, link: Link | null): void {
    const channel = link === null ? this.channel : link.channel;
    if (this.channelAuth !== "session" || channel === null || !this.sessionPeers.has(peer)
        || peer === this.identity.peerId || channel.attestedPeer() !== null) {
      return;
    }
    const session = this.sessionOf(link);
    if (session.mayOpen(this.now())) {
      this.sendSessionHello(session, peer, null, link);
    }
  }

  /** The session slot of a link (the dialed channel's for null), created on first use. */
  private sessionOf(link: Link | null): Session {
    if (link === null) {
      this.session ??= new Session(this.identity.peerId);
      return this.session;
    }
    link.session ??= new Session(this.identity.peerId);
    return link.session;
  }

  /** Sends this peer's half (opening when `echo` is null, answering otherwise), fully signed. */
  private sendSessionHello(session: Session, peer: string, echo: Uint8Array | null, link: Link | null): void {
    session.sent(this.now(), echo !== null);
    const env = wire.envelope(this.group, "SESSION_HELLO", this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now()), session.hello(peer, echo), peer);
    (link === null ? this.channel : link.channel)?.send(wire.encodeFrame(env, this.identity));
  }

  /**
   * Handles a SESSION_HELLO (PeerNode.onSessionHello): the decoder admits it only fully signed;
   * it counts only when it names this peer; a hello older than the age window is ignored and
   * counted; an opening hello is answered with this peer's half echoing the opener's nonce.
   */
  private onSessionHello(env: Dict, link: Link | null): void {
    const channel = link === null ? this.channel : link.channel;
    if (this.channelAuth !== "session" || channel === null || channel.attestedPeer() !== null) {
      return;
    }
    const hello = parseSessionHello((env["body"] as Uint8Array) ?? new Uint8Array());
    if (hello === null || hello.remote !== this.identity.peerId) {
      return;
    }
    let physical: number;
    try {
      physical = wire.hlcPhysical(env["stamp"]);
    } catch {
      return;
    }
    if (this.now() - physical > SESSION_HELLO_MAX_AGE_MILLIS) {
      this.framesStale += 1; // a captured hello replayed on a fresh link, never a strike
      return;
    }
    const session = this.sessionOf(link);
    const verdict = session.accept(String(env["from"]), hello);
    if (verdict === "answer") {
      this.sendSessionHello(session, String(env["from"]), hello.nonce, link);
    }
  }

  /** One whole frame from a link (the channel did the framing, ASF-014/016); null is the dialed channel. */
  private onFrame(frame: Uint8Array, link: Link | null = null): void {
    const channel = link === null ? this.channel : link.channel;
    const session = link === null ? this.session : link.session;
    const decoded = wire.decodeFrameDetailed(frame, {
      attestedPeer: channel?.attestedPeer() ?? null,
      session: session?.established() ?? null,
    });
    const env = decoded?.env ?? null;
    if (env === null) {
      this.malformedFrames += 1;
    } else if (decoded!.auth === "SESSION" && session !== null) {
      session.confirmed = true; // the other end holds the key: key confirmation (SPEC §5.6)
    } else if (decoded!.auth === "ATTESTED") {
      this.attestedFrames += 1;
    }
    if (this.accepts(env)) {
      try {
        this.handle(env, link, false, decoded!.body);
      } catch {
        // One undecodable frame never stops the peer.
      }
    }
  }

  /**
   * The reader filter: a verified envelope for our group that is either
   * unaddressed (the bootstrap exception) or addressed to us. An addressed
   * frame is honored only by its intended recipient (ASF-010); a frame for a
   * group we never joined is dropped (SPEC section 9).
   */
  accepts(env: Dict | null): env is Dict {
    return env !== null && env["group"] === this.group
      && (env["to"] == null || env["to"] === this.identity.peerId);
  }

  /**
   * A verified frame for this peer; `decoded` is its body read strictly as its kind's record, and a
   * body that does not read makes the frame undecodable (HLC round six, 2026-11-08, F3).
   */
  private handle(env: Dict, link: Link | null = null, relayedFrame = false,
                 decoded: Dict | null = wire.decodeBody(env)): void {
    if (decoded === null) {
      this.malformedFrames += 1;
      return;
    }
    if (!this.frames.admit(env, this.now())) {
      return; // stale, far ahead, or a replay: dropped and counted, nothing more
    }
    let reintroduce = false;
    wire.hlcObserve(this.identity.peerId, env["stamp"], this.now());
    const kind = env["kind"];
    const sender = env["from"];
    // How a probe's answer goes back (SPEC v0.1.36 §5.2): set below for a frame heard through another member.
    let heardRelayed = relayedFrame;
    let carrier: string | null = null;
    if (typeof sender === "string" && sender !== this.identity.peerId) {
      if (!this.members.has(sender)) {
        this.members.set(sender, {}); // a verified frame is a member heard from
      }
      if (this.wakeSuspects.size > 0) {
        this.heardSuspect(sender); // any verified frame answers a wake's probe, relayed or not
      }
      // A relayed inner frame arrives on a link whose other end is someone else (the session's or
      // the attestation's peer): its signer is heard, not reachable, so an answer to it goes back
      // through a relay rather than onto a link that would drop a frame addressed elsewhere.
      const channel = link === null ? this.channel : link.channel;
      const session = link === null ? this.session : link.session;
      const linkPeer = channel?.attestedPeer() ?? (session?.established() !== null && session?.established() !== undefined ? session.remote : null);
      const relayed = relayedFrame || (linkPeer !== null && linkPeer !== undefined && linkPeer !== sender);
      heardRelayed = relayed;
      carrier = linkPeer ?? null;
      if (!relayed) {
        this.reachable.add(sender);
        (link === null ? this.dialPeers : link.peers).add(sender);
        if (link === null && this.channel !== null && env["to"] === this.identity.peerId
            && this.seedPeer !== sender) {
          // On the dialed channel an addressed frame is the seed's own; it is the relay this peer
          // declares, so members behind other seeds reach it through the seed (SPEC §5.4).
          this.adoptSeedPeer(sender);
          reintroduce = true; // after this frame's own answer, so a probe's ACK stays first
        }
      }
      if (kind !== "RUMOR" && kind !== "SESSION_HELLO" && kind !== "CHANNEL_HELLO" && !relayed) {
        this.maybeSessionHello(sender, link); // a frame past the introduction proves the member admitted us
      }
    }
    if (kind === "SESSION_HELLO") {
      this.onSessionHello(env, link);
    } else if (kind === "RELAY_FRAME") {
      this.onRelayFrame(decoded, link);
    } else if (kind === "DIGEST") {
      this.onDigest(String(sender), decoded, heardRelayed, link);
    } else if (kind === "PING_REQ") {
      this.onPingReq(String(sender), decoded);
    } else if (kind === "ACK") {
      this.onAck(String(sender), decoded);
    } else if (kind === "PIPE_DATA") {
      if (decoded["capability"] === wire.RELAY_SIGNAL_CAPABILITY) {
        const signal = records.readRecord(decoded["payload"], records.RELAY_SIGNAL);
        if (signal !== null) {
          this.relaySignals.push(signal);
          this.relaySignals.splice(0, Math.max(0, this.relaySignals.length - 64));
        }
        return;
      }
      const handler = this.pipeHandlers.get(String(decoded["capability"]));
      if (handler !== undefined) {
        handler(String(sender), decoded["payload"] as Uint8Array);
      }
    } else if (kind === "PING") {
      // Java's probe nonces are random 64-bit longs: echo the decoded integer
      // as is (a bigint beyond 2^53), since a Number would lose it and the
      // encoder would refuse it, leaving the probe unanswered and this peer evicted.
      // The ACK goes to the prober, as Java answers send(group, from, ACK): addressed, on the link the PING came in
      // on, or back through the member that relayed it (a prober with a relay path to this peer). Unaddressed, it went
      // to the seed, which never asked and reads it as an answer to a probe of its own, and to every other link.
      const answer = typeof sender === "string"
        ? (body: Uint8Array): void => this.answerProbe(body, sender, link, heardRelayed, carrier)
        : (body: Uint8Array): void => this.send("ACK", body);
      if (this.auditOn && typeof sender === "string" && (decoded["hashes"] !== undefined || decoded["root"] !== undefined)) {
        this.onProbeHashes(sender, decoded, answer); // SPEC §5.2: hashes are answered with hashes, of the kind the pinger reads
      } else {
        answer(wire.ackBody(decoded["nonce"] as number | bigint));
      }
    } else if (kind === "GROUP_AD") {
      this.offerGroupAd(env); // only a join in progress cares (§10.1)
    } else if (kind === "RUMOR") {
      const rumor = decoded;
      let forward = true;
      if (revocation.STREAMS.includes(String(rumor["streamId"]))) {
        this.revocations.accept(String(rumor["streamId"]), rumor["payload"], this.now());
      } else if (rumor["streamId"] === "peers") {
        this.acceptPeerAd(rumor["payload"] as Uint8Array);
      } else if (rumor["streamId"] === "ads") {
        this.acceptAd(records.readRecord(rumor["payload"], records.STORED_AD));
      } else if (this.streamHandlers.has(String(rumor["streamId"])) && rumor["payload"] instanceof Uint8Array) {
        forward = this.streamHandlers.get(String(rumor["streamId"]))!(String(sender), rumor["payload"]);
      } else if (String(rumor["streamId"] ?? "").startsWith("space:")
          && this.joinedSpaces.has(String(rumor["streamId"]).substring("space:".length))) {
        // a rumor of a space not joined is relayed undecoded (HLC round five, 2026-11-08); a PDT
        // facade joins its ref spaces itself (HLC round six, 2026-11-08, R11)
        const delta = this.decodeDelta(rumor["payload"], records.SPACE_DELTA);
        if (delta === null) {
          forward = false; // counted, and carried no further from here
        } else {
          if (isDict(delta["state"])) {
            nameRecordless(delta["state"] as Dict, rumor["itemId"]);
          }
          this.foldDelta(delta);
        }
      }
      if (forward) {
        this.forwardRumor(rumor, link);
      }
    } else if (kind === "BLOCK_WANT") {
      const data = this.blocks.get(String(decoded["cid"]));
      if (data !== undefined) {
        this.sendAddressed("BLOCK", wire.blockBody(String(decoded["cid"]), data), String(sender));
      }
    } else if (kind === "BLOCK") {
      const bytes = decoded["bytes"] as Uint8Array;
      if (this.blockAsked.has(String(decoded["cid"])) && wire.contentId(bytes) === decoded["cid"]) {
        this.blocks.set(String(decoded["cid"]), bytes);
        this.wakeFoldWaiters();
      }
    } else if (kind === "PULL_RESP") {
      const deltas = decoded["deltas"] as { [stream: string]: Uint8Array };
      // A fetch's answer is booked against the body it answers, and a budgeted pull's remainder continues (annex I.6).
      const fetchStream = this.pullRespArrived(String(sender), decoded);
      // A fetch's answer leaves a budgeted text pull to the same member waiting for its own answer.
      const awaited = fetchStream === null && this.budgetedPullAnswered(String(sender));
      const received = new Set<string>();
      for (const [stream, deltaBytes] of Object.entries(deltas)) {
        if (revocation.STREAMS.includes(stream) && deltaBytes.length > 0) {
          for (const signed of (records.readList(deltaBytes, records.SIGNED_REVOCATION) ?? [])) {
            this.revocations.acceptSigned(stream, signed, this.now());
          }
          continue;
        }
        if (stream === "view" && deltaBytes.length > 0) {
          for (const payload of (records.readList(deltaBytes, "bytes") ?? []) as Uint8Array[]) {
            this.acceptPeerAd(payload);
          }
          continue;
        }
        if (stream === "ads" && deltaBytes.length > 0) {
          for (const stored of ((records.readRecord(deltaBytes, records.AD_CACHE_DELTA)?.["ads"] as Dict[]) ?? [])) {
            this.acceptAd(stored);
          }
          continue;
        }
        if (!stream.startsWith("space:") || !this.joinedSpaces.has(stream.substring("space:".length))
            || deltaBytes.length === 0) {
          continue; // HLC round five, 2026-11-08: an answer for a space not joined folds nothing
        }
        const sync = this.decodeDelta(deltaBytes, records.SYNC_DELTA);
        if (sync === null) {
          continue; // counted: as in Java, one undecodable state or claim drops the whole sync delta
        }
        // Claims before states: a completion authenticates against the holder's
        // claim, which must be folded first.
        const claims = (sync["claims"] as Dict) ?? {};
        for (const [entryId, signed] of Object.entries(claims)) {
          this.foldClaim(entryId, signed as Dict);
        }
        for (const dto of (sync["states"] as CborValue[]) ?? []) {
          this.fold(dto as Dict);
        }
        if (stream === fetchStream) {
          for (const entryId of Object.keys(claims)) {
            received.add(entryId);
          }
          for (const dto of (sync["states"] as Dict[]) ?? []) {
            const id = (dto["record"] as Dict | null | undefined)?.["entryId"] ?? dto["entryId"];
            if (typeof id === "string") {
              received.add(id);
            }
          }
        }
      }
      this.pullRespSettled(String(sender), decoded, fetchStream, received, awaited);
    } else {
      // A kind this client does not speak (the hint-gated kinds of SPEC v0.1.17 are never
      // sent to it, but a misconfigured peer could): ignored, counted, never fatal.
      this.ignoredKinds.set(String(kind), (this.ignoredKinds.get(String(kind)) ?? 0) + 1);
    }
    if (reintroduce) {
      this.introduce();
    }
  }

  // ------------------------------------------------- the serving half (JS-R-04)

  /** The key a rumor is remembered under: its stream and the hash of its payload, as GossipBus keys it. */
  private rumorKey(stream: string, payload: Uint8Array): string {
    const hash = cryptoPort().sha256(payload);
    return `${stream}\u0000${[...hash.subarray(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  }

  /** Remembers a rumor this peer sends, so its echo is not forwarded; the memory is a bounded ring. */
  private rememberRumor(body: Uint8Array): boolean {
    let rumor: Dict;
    try {
      rumor = loads(body) as Dict;
    } catch {
      return false;
    }
    const payload = rumor["payload"];
    if (!(payload instanceof Uint8Array)) {
      return false;
    }
    return this.remember(this.rumorKey(String(rumor["streamId"] ?? ""), payload));
  }

  /** Adds a key to the rumor memory; false when it was there already. */
  private remember(key: string): boolean {
    if (this.rumorsSeen.has(key)) {
      return false;
    }
    this.rumorsSeen.add(key);
    if (this.rumorsSeen.size > this.rumorMemory) {
      this.rumorsSeen.delete(this.rumorsSeen.values().next().value as string); // the oldest
    }
    return true;
  }

  /**
   * Forwards a rumor that arrived on one link to every other link, one hop fewer, the first
   * time it is seen (GossipBus.onRumor with the hop budget clamped to this peer's own, ASF-012).
   * A dial-only peer has one link and forwards nothing.
   */
  private forwardRumor(rumor: Dict, from: Link | null): void {
    const payload = rumor["payload"];
    if (!(payload instanceof Uint8Array)) {
      return;
    }
    const first = this.remember(this.rumorKey(String(rumor["streamId"] ?? ""), payload));
    const hops = Math.min(this.rumorHops, Number(rumor["hopsRemaining"] ?? 0));
    if (!first || hops <= 1 || (this.inbound.size === 0) || (this.inbound.size === 1 && from !== null && this.channel === null)) {
      return;
    }
    const body = wire.rumorBody(String(rumor["streamId"]), String(rumor["itemId"] ?? ""), hops - 1, payload);
    if (from !== null && this.channel !== null) {
      this.sendOn(null, "RUMOR", body, this.session?.confirmed ? this.session.remote : null);
    }
    for (const link of this.inbound.values()) {
      if (link !== from) {
        this.sendOn(link, "RUMOR", body, link.session?.confirmed ? link.session.remote : null);
      }
    }
    this.rumorsForwarded += 1;
  }

  /** The streams this peer serves: the spaces it pulled or wrote, the ads, and the revocations. */
  /**
   * Whether this peer answers a digest of the stream. A space is served once joined (pulled, written, or opened), not
   * only once pulled (owner decision 2 of 2026-11-23): a dial-only peer that wrote to a space it never pulled answers
   * its seed's DIGEST with its own states, so a rumor of its own lost on its only link is repaired by the seed's round.
   * Only the rounds this peer opens ({@link fullDigests}, {@link heldStreams}) stay on the pulled spaces.
   */
  private servesStream(stream: string): boolean {
    return stream === "ads" || stream === "view" || revocation.STREAMS.includes(stream)
      || (stream.startsWith("space:") && this.joinedSpaces.has(stream.substring("space:".length)));
  }

  /** The entry states of one space (by its SpaceId), as held. */
  private statesOf(space: string): Map<string, Dict> {
    const spaceId = spaceIdLocal(`${this.group}/${space}`);
    const out = new Map<string, Dict>();
    for (const [entryId, dto] of this.states) {
      if ((dto["record"] as Dict | undefined)?.["spaceId"] === spaceId) {
        out.set(entryId, dto);
      }
    }
    return out;
  }

  /**
   * `ReplicatedSpace.digest` for one space: `e:`/`c:` lines in key order. It reads only the states, the claims and
   * the acknowledged lines, so it is kept until one of them changes: a probe whose hash differs compares the text
   * kind too, and building it afresh cost each such probe about 21 ms at 20,000 entries, linear in the space, which
   * any member could ask every second (adversarial review of 2026-11-15).
   */
  spaceDigest(space: string): Uint8Array {
    return this.textOfSpace(space).bytes;
  }

  /** A space's text digest and, once asked, its SHA-256, as of the replica's current version. */
  private textOfSpace(space: string): { bytes: Uint8Array; hash: Uint8Array | null } {
    const held = this.spaceTexts.get(space);
    if (held !== undefined && held.version === this.replicaVersion) {
      return held;
    }
    const summary = new Map<string, string>();
    const states = this.statesOf(space);
    for (const [entryId, dto] of states) {
      summary.set(`e:${entryId}`, this.stateHashOf(dto));
    }
    for (const [entryId, signed] of this.claims) {
      if (states.has(entryId)) {
        summary.set(`c:${entryId}`, serving.claimHash((signed["claim"] as Dict) ?? {}));
      }
    }
    const text = { version: this.replicaVersion, bytes: utf8(serving.digestLines(summary) + this.acknowledgedLines(space)),
      hash: null as Uint8Array | null };
    this.spaceTexts.set(space, text);
    return text;
  }

  /** Each space's text digest as last built, with the version it was built at. */
  private readonly spaceTexts = new Map<string, { version: number; bytes: Uint8Array; hash: Uint8Array | null }>();

  /** `ReplicatedSpace.deltaFor`: the states and claims the remote digest does not name, as a SyncDelta. */
  spaceDeltaFor(space: string, remoteDigest: Uint8Array, only: Map<string, Dict> | null = null): Uint8Array {
    const remote = serving.parseDigestLines(remoteDigest);
    const states: Dict[] = [];
    const claims: Dict = {};
    const held = this.statesOf(space);
    if (only !== null) {
      for (const entryId of [...held.keys()]) {
        if (!only.has(entryId)) {
          held.delete(entryId); // a dial-only peer's answer to a relayed DIGEST: its displaced entries alone
        }
      }
    }
    for (const [entryId, dto] of held) {
      const key = `e:${entryId}=${serving.stateHash(dto)}`;
      if (!remote.has(key) && !remote.has(`a:${key}`)) {
        states.push(this.signedStateOf(entryId, dto)); // a join nobody signed travels as its most advanced signed input
      }
    }
    // A dial-only peer's answer to a relayed DIGEST carries its own displaced claim, not the one its lattice kept.
    const claimsOf: Iterable<[string, Dict]> = only ?? this.claims;
    for (const [entryId, signed] of claimsOf) {
      if (!held.has(entryId)) {
        continue;
      }
      const key = `c:${entryId}=${serving.claimHash((signed["claim"] as Dict) ?? {})}`;
      if (!remote.has(key) && !remote.has(`a:${key}`)) {
        claims[entryId] = signed;
      }
    }
    if (states.length === 0 && Object.keys(claims).length === 0) {
      return new Uint8Array();
    }
    // HLC round six, 2026-11-08 (P2): `claims` is a protocol map field, written in the RFC 8949 order.
    return dumps({ states, claims: canonicalMap(claims) });
  }

  /** `AdCache.digest`: the live advertisements by id and issue instant. */
  adsDigest(): Uint8Array {
    const keys = new Map<string, string>();
    const now = this.now();
    for (const [id, entry] of this.ads) {
      if (entry.expires > now) {
        keys.set(id, String(parseInstantMillis(entry.ad["issued"])));
      }
    }
    return serving.adDigest(keys);
  }

  /** `AdCache.deltaFor`: the stored advertisements the remote digest does not name. */
  adsDeltaFor(remoteDigest: Uint8Array): Uint8Array {
    const remote = serving.parseAdDigestKeys(remoteDigest);
    const now = this.now();
    const missing: Dict[] = [];
    for (const [id, entry] of this.ads) {
      if (entry.expires > now && !remote.has(`${id}=${parseInstantMillis(entry.ad["issued"])}`)) {
        missing.push(entry.stored);
      }
    }
    return missing.length === 0 ? new Uint8Array() : dumps({ ads: missing });
  }

  /**
   * `RevocationRegistry.deltaFor` and `CredentialRevocationRegistry.deltaFor`: the signed
   * revocations of a stream the remote digest does not name, keyed `r:<revoked peer>` and
   * `c:<kind>:<canonical target>` with the SHA-256 of the signed bytes, as Java lines them.
   */
  revocationDeltaFor(stream: string, remoteDigest: Uint8Array): Uint8Array {
    const remote = serving.parseDigestLines(remoteDigest);
    const held = (this.revocations.exportSigned()[stream] ?? []) as Dict[];
    const missing: Dict[] = [];
    for (const signed of held) {
      const adBytes = signed["adBytes"];
      if (!(adBytes instanceof Uint8Array)) {
        continue;
      }
      let key: string;
      try {
        const ad = loads(adBytes) as Dict;
        key = stream === revocation.PEER_STREAM ? `r:${String(ad["revoked"])}`
          : `c:${String((ad["target"] as Dict)["kind"])}:${revocation.canonicalTarget(ad["target"] as Dict)}`;
      } catch {
        continue;
      }
      if (!remote.has(serving.revocationLine(key, adBytes))) {
        missing.push(signed);
      }
    }
    return missing.length === 0 ? new Uint8Array() : dumps(missing);
  }

  /** The full digests of every stream this peer serves, the opening of an anti-entropy round. */
  fullDigests(): Dict {
    const digests: Dict = { ads: this.adsDigest(), view: this.viewDigest() };
    for (const space of this.pulledSpaces) {
      digests[`space:${space}`] = this.spaceDigest(space);
    }
    for (const stream of revocation.STREAMS) {
      digests[stream] = new Uint8Array(); // asked in full: this peer serves them but keeps no digest of its own
    }
    return digests;
  }

  /**
   * One anti-entropy round (GossipBus.antiEntropy): this peer's full digests to one member it
   * has a connection to, chosen at random, which answers with what this peer lacks. A host's
   * tick calls it; a dial-only peer pulls on demand instead.
   */
  antiEntropyRound(): string | null {
    const partners = this.linkedMembers();
    if (partners.length === 0) {
      return null;
    }
    const partner = partners[Math.floor(Math.random() * partners.length)];
    this.expectedPulls.clear(); // as Java's round: only this round's partner may answer it with a want
    this.digestTo(partner);
    if (this.auditOn) {
      // The fetch queue's turn (RE-I-03): ids a partner left out go to the next member once their backoff passes.
      this.trieAudit.retry(this.linkedMembers());
    }
    return partner;
  }

  /**
   * Answers a DIGEST (GossipBus.onDigest): for each stream the asker names and this peer serves,
   * the delta its digest shows it lacks, in one PULL_RESP; nothing when nothing is missing. A
   * hashed opening (`hashes`) or a `want` list belongs to the hashed round this peer never
   * advertises, and is ignored.
   */
  private onDigest(from: string, digest: Dict, relayed = false, link: Link | null = null): void {
    if (this.dialsOnly() && !this.fromOwnSeed(from, relayed, link)) {
      this.answerDisplacedPull(from, digest);
      return;
    }
    if (this.onDigestFields(from, digest)) {
      return;
    }
    this.answerTextPull(from, digest);
  }

  /** Whether this peer only dials: it names no endpoint of its own and holds no accepted link (SPEC §9.4's row). */
  private dialsOnly(): boolean {
    return this.endpoints.length === 0 && this.inbound.size === 0;
  }

  /**
   * Whether a frame is its own seed's: read directly off the dialed link (not relayed, not a forwarded copy) from the
   * seed's PeerID, or, before the seed's first addressed frame names it, from the link's other end.
   */
  private fromOwnSeed(from: string, relayed: boolean, link: Link | null): boolean {
    return link === null && !relayed && (this.seedPeer === null || from === this.seedPeer);
  }

  /** DIGESTs a dial-only peer left unanswered: relayed or from a member other than its seed, naming nothing it holds displaced. */
  digestsIgnored = 0;
  /** Relayed or non-seed DIGESTs a dial-only peer answered with its displaced entries alone (owner decision 1). */
  displacedDigestAnswers = 0;
  /** Such DIGESTs left unanswered because the asker's answer bucket was empty. */
  relayedAnswersPaced = 0;
  /** The relayed answers' buckets, per asker: tokens left, and when each was last refilled (monotonic). */
  private readonly answerBuckets = new Map<string, { tokens: number; at: number }>();

  /**
   * Owner decision 1 of 2026-11-23 (SPEC §9.4's dial-only DIGEST row, §14's open question settled): a dial-only peer
   * answers a DIGEST that reached it relayed, or from any member but its seed, only for the spaces where it holds a
   * claim made here that a better claim displaced, with or without its completion ({@link displacedHeld}, as the
   * core), and sends only those entries: the displaced claim, and the entry's state (its completion, if any), each only
   * where the asker's digest lacks it. So a winner's targeted round (§7.4) reaches the
   * holder its claim displaced, while no member can draw the rest of this peer's state through the seed (upload
   * amplification). The fields read are the core's: `hashes` (an opening, answered with `want` for the spaces holding
   * a displaced claim whose text form differs), `digests` (the text pull), and `want` for a round this peer opened;
   * every other field (an audit's `tree`, `ids`) and every stream but a space's is left out. Each asker's answers take its own bucket, {@link RELAYED_ANSWER_BURST}
   * refilled at {@link RELAYED_ANSWER_PER_SECOND} on the monotonic clock (as in every client), so one member flooding
   * relayed DIGESTs cannot starve another winner's round; the seed's own round stays outside them. The answer goes back through the seed ({@link sendAddressed}).
   */
  private answerDisplacedPull(from: string, digest: Dict): void {
    let answered = false;
    const asked = digest["want"] as string[] | undefined;
    if (Array.isArray(asked) && asked.length > 0 && this.expectedPulls.has(from)) {
      // A round this peer opened: answered as ever (the core's onDigestDisplacedOnly).
      this.pacing.wantsReceived += 1;
      const digests = this.textDigests(asked);
      if (Object.keys(digests).length > 0) {
        this.sendAddressed("DIGEST", this.textPull(from, digests), from);
        answered = true;
      }
    }
    // An opening of hashes: the spaces holding a displaced claim whose text form differs, named in want, so the
    // winner sends its text digests (by the text form even toward an auditing member, as the core).
    const want: string[] = [];
    const hashes = digest["hashes"];
    if (hashes !== null && typeof hashes === "object" && !Array.isArray(hashes)) {
      for (const stream of Object.keys(hashes as Dict).sort()) {
        const hash = (hashes as Dict)[stream];
        if (!(hash instanceof Uint8Array) || !stream.startsWith("space:") || !this.servesStream(stream)) {
          continue;
        }
        if (this.displacedAnswerable(stream.substring("space:".length)).size > 0
            && !equals(this.streamHashOf(stream, false), hash)) {
          want.push(stream);
        }
      }
    }
    const digests = digest["digests"];
    const deltas: Dict = {};
    if (digests !== null && typeof digests === "object" && !Array.isArray(digests)) {
      for (const [stream, remote] of Object.entries(digests as Dict)) {
        if (!(remote instanceof Uint8Array) || !stream.startsWith("space:") || !this.servesStream(stream)) {
          continue;
        }
        const space = stream.substring("space:".length);
        const only = this.displacedAnswerable(space);
        if (only.size === 0) {
          continue;
        }
        const delta = this.spaceDeltaFor(space, remote, only);
        if (delta.length > 0) {
          deltas[stream] = delta;
        }
      }
    }
    if (want.length === 0 && Object.keys(deltas).length === 0) {
      if (!answered) {
        this.digestsIgnored += 1;
      }
      return;
    }
    if (!this.takeAnswerToken(from)) {
      this.relayedAnswersPaced += 1;
      return; // the asker's next round finds a token
    }
    if (want.length > 0) {
      this.pacing.wantsSent += 1;
      this.displacedDigestAnswers += 1;
      this.sendAddressed("DIGEST", wire.digestRecord({ want }), from);
    }
    if (Object.keys(deltas).length > 0) {
      this.pullsAnswered += 1;
      this.displacedDigestAnswers += 1;
      this.sendAddressed("PULL_RESP", dumps({ deltas: canonicalMap(deltas) }), from);
    }
  }

  /** Takes one token of `asker`'s answer bucket, refilled on the monotonic clock; false when it is empty. */
  private takeAnswerToken(asker: string): boolean {
    const mono = this.monotonic();
    const held = this.answerBuckets.get(asker);
    this.answerBuckets.delete(asker); // re-inserted last: the least recently asked goes first past the cap
    const tokens = held === undefined ? RELAYED_ANSWER_BURST
      : Math.min(RELAYED_ANSWER_BURST, held.tokens + (mono - held.at) * RELAYED_ANSWER_PER_SECOND / 1000);
    const spent = tokens >= 1;
    this.answerBuckets.set(asker, { tokens: spent ? tokens - 1 : tokens, at: mono });
    while (this.answerBuckets.size > RELAYED_ANSWER_ASKERS) {
      this.answerBuckets.delete(this.answerBuckets.keys().next().value as string);
    }
    return spent;
  }

  /**
   * The entries of one space for which this peer holds a claim made here that a better claim displaced, with or
   * without a completion under it ({@link displacedHeld}, then each claim still offered again), each with that claim,
   * as the core's displacedFor; a line whose claim lapsed, whose stamp is half the drift ceiling old, or whose entry is
   * gone is dropped here. Read from this peer's own lattice alone, never from the asker's digest, so an asker cannot
   * widen it.
   */
  private displacedAnswerable(space: string): Map<string, Dict> {
    const out = new Map<string, Dict>();
    const now = this.now();
    const spaceId = wireSpaceId(this.group, space);
    for (const [entryId, signed] of [...this.displacedHeld]) {
      const claim = signed["claim"] as Dict;
      if (wire.claimNumber(claim["expiresAtMillis"]) <= now
          || now - wire.hlcPhysical(claim["stamp"]) > wire.MAX_HLC_SKEW_MILLIS / 2 || !this.states.has(entryId)) {
        this.displacedHeld.delete(entryId);
      } else if (claim["spaceId"] === spaceId) {
        out.set(entryId, signed);
      }
    }
    for (const [entryId, line] of this.displacedOwn) {
      if (line.space === space && !out.has(entryId) && this.states.has(entryId)) {
        out.set(entryId, line.signed);
      }
    }
    return out;
  }

  /** The text pull of a body without a budget or ids, answered exactly as a 0.6.0 member answers it. */
  private answerTextPull(from: string, digest: Dict): void {
    const digests = digest["digests"];
    if (digests === null || typeof digests !== "object" || Array.isArray(digests)) {
      return;
    }
    const deltas: Dict = {};
    for (const [stream, remote] of Object.entries(digests as Dict)) {
      if (!(remote instanceof Uint8Array) || !this.servesStream(stream)) {
        continue;
      }
      const delta = stream === "ads" ? this.adsDeltaFor(remote)
        : stream === "view" ? this.viewDeltaFor(remote)
        : revocation.STREAMS.includes(stream) ? this.revocationDeltaFor(stream, remote)
          : this.spaceDeltaFor(stream.substring("space:".length), remote);
      if (delta.length > 0) {
        deltas[stream] = delta;
      }
    }
    if (Object.keys(deltas).length > 0) {
      this.pullsAnswered += 1;
      // Through the seed when the asker is not on a link of this peer's own: a dial-only peer's addressed frame on its
      // dialed channel is dropped by a seed that is not its recipient, so a member's (a winner's targeted) DIGEST that
      // reached it in a RELAY_FRAME was never answered (owner decision 4 of 2026-11-23).
      this.sendAddressed("PULL_RESP", dumps({ deltas: canonicalMap(deltas) }), from); // P2, HLC round six, 2026-11-08
    }
  }

  /** Relayed frames unwrapped for this peer, and forwarded on toward a linked target. */
  relayedIn = 0;
  relayedForwarded = 0;
  /** Path frames refused as malformed and frames no hop could deliver (SPEC v0.1.23 §5.4). */
  relayedDroppedBadPath = 0;
  relayedDroppedUnreachable = 0;

  /**
   * A `RELAY_FRAME` (SPEC §5.4; PeerNode.onRelayFrame): addressed to this peer, the inner frame is
   * decoded fully signed (never a nested relay) and handled as its origin's, marked relayed so the
   * origin is heard but not reachable; addressed to a member on one of this peer's links, it is
   * forwarded verbatim there, which is what a service host that advertises the RELAY role does
   * for the browsers behind it. Anyone else's is dropped.
   */
  private onRelayFrame(body: Dict, link: Link | null): void {
    const target = body["target"] as string;
    const frame = body["frame"] as Uint8Array;
    if (target === this.identity.peerId) {
      const decoded = wire.decodeFrameDetailed(frame, {}); // fully signed, whatever the link's session
      const inner = decoded?.env ?? null;
      if (inner === null || inner["kind"] === "RELAY_FRAME" || !this.accepts(inner)) {
        return;
      }
      this.relayedIn += 1;
      if (typeof inner["from"] === "string") {
        this.noteRelayed(inner["from"]); // JS-W-11: the other direction of the pair
      }
      try {
        this.handle(inner, link, true, decoded!.body);
      } catch {
        // one bad inner frame never stops the peer
      }
      return;
    }
    const path = Array.isArray(body["path"]) ? (body["path"] as unknown[]).map(String) : null;
    const hop = typeof body["hop"] === "number" ? body["hop"] : -1;
    if (path !== null && (hop < 0 || hop >= path.length || path[hop] !== this.identity.peerId
        || path.length > this.maxPathHops || path.includes(target))) {
      this.relayedDroppedBadPath += 1;
      return; // a path frame names this relay at its hop (LB-R-03); anything else is malformed
    }
    const route = this.linkFor(target);
    if (route !== null || this.dialPeers.has(target)) {
      this.relayedForwarded += 1;
      this.sendOn(route, "RELAY_FRAME", path === null ? dumps({ target, frame })
        : wire.relayFrameBody(target, frame, path, hop), target);
      return;
    }
    // Not deliverable from here: the next relay on the path carries it, once (LB-R-08).
    if (path !== null && hop + 1 < path.length) {
      const next = path[hop + 1];
      const link = this.linkFor(next);
      if (link !== null || this.dialPeers.has(next)) {
        this.relayedForwarded += 1;
        this.sendOn(link, "RELAY_FRAME", wire.relayFrameBody(target, frame, path, hop + 1), next);
        return;
      }
      const origin = wire.decodeFrame(frame)?.["from"];
      if (typeof origin === "string") {
        this.sendAddressed("PIPE_DATA", wire.relaySignalBody(target, next), origin);
      }
    }
    this.relayedDroppedUnreachable += 1;
  }

  /**
   * Relays a probe (PeerNode PING_REQ, SWIM indirect ping): pings the target under a nonce of
   * this peer's own and, when the target itself answers, vouches for it to the asker with an
   * ACK carrying the asker's nonce and `onBehalf` (ASF-011).
   */
  private onPingReq(from: string, request: Dict): void {
    const target = request["target"];
    if (typeof target !== "string" || target === this.identity.peerId) {
      return;
    }
    // A holder probes the target over its own link (SPEC v0.1.36 §5.2, the targeted relay); with no link to it and no
    // dialed channel to route through, the PING would go to every link this peer holds, so it goes nowhere.
    if (this.linkFor(target) === null && this.channel === null) {
      this.pingReqsUnroutable += 1;
      return;
    }
    const now = this.monotonic();
    this.forgetRelays(now);
    const nonce = BigInt.asIntN(64, (BigInt(Math.floor(Math.random() * 2 ** 32)) << 32n)
      | BigInt(Math.floor(Math.random() * 2 ** 32)));
    this.relays.set(String(nonce), { origin: from, originNonce: (request["nonce"] as number | bigint | undefined) ?? 0,
      target, at: now });
    this.pingsRelayed += 1;
    if (this.linkFor(target) !== null) {
      this.send("PING", wire.pingBody(nonce), target);
    } else {
      // Over the dialed channel: a dial-only peer asked as one of a Java prober's random members (the escalated round
      // of SPEC v0.1.36 §5.2) reaches any member but its seed inside a RELAY_FRAME the seed carries; addressed and
      // bare, the seed would drop it.
      this.sendAddressed("PING", wire.pingBody(nonce), target);
    }
  }

  /** Forgets relays past their hold, and the eldest beyond the size bound. */
  private forgetRelays(now: number): void {
    for (const [nonce, relay] of this.relays) {
      if (now - relay.at <= RELAY_HOLD_MILLIS && this.relays.size < MAX_RELAYS) {
        break; // insertion order is time order: the rest are younger
      }
      this.relays.delete(nonce);
      this.relaysExpired += 1;
    }
  }

  /**
   * Answers a probe to its prober (SPEC v0.1.36 §5.2): addressed, on the link it was heard on; a PING heard through
   * another member (inside a `RELAY_FRAME`, or forwarded on a link whose other end is not its signer) goes back the
   * same way, wrapped in a `RELAY_FRAME` to the member that carried it, so the prober's own nonce reaches the prober.
   */
  private answerProbe(body: Uint8Array, to: string, link: Link | null, relayed: boolean, carrier: string | null): void {
    if (!relayed) {
      this.send("ACK", body, to);
      return;
    }
    const inner = wire.encodeFrame(wire.envelope(this.group, "ACK", this.identity.peerId,
      wire.hlcNow(this.identity.peerId, this.now()), body, to), this.identity);
    this.relayedFrames += 1;
    this.probesAnsweredRelayed += 1;
    this.sendOn(link, "RELAY_FRAME", wire.relayFrameBody(to, inner), carrier ?? (link === null ? this.seedPeer : null));
    this.noteRelayed(to);
  }

  /** PINGs heard through another member and answered back through it. */
  probesAnsweredRelayed = 0;

  /** PING_REQ relays awaiting the target's ACK (bounded; for tests and operators). */
  get relaysInFlight(): number {
    return this.relays.size;
  }

  private onAck(from: string, ack: Dict): void {
    const relay = this.relays.get(String(ack["nonce"] ?? ""));
    if (relay !== undefined && from === relay.target) {
      this.relays.delete(String(ack["nonce"]));
      this.send("ACK", dumps({ nonce: relay.originNonce, onBehalf: relay.target }), relay.origin);
    }
  }

  /**
   * Forgets members whose advertisement lease has lapsed and who are heard on no link (a host
   * has no SWIM prober; a member that left or died ages out with its advertisement).
   */
  expireMembers(): string[] {
    if (this.dueLoop !== null) {
      // A frozen process whose watchdog has not run yet: the wake is seen (and its probes sent) before any judgement.
      (this.watchdog ?? watchdogFor(this.timers)).catchUp();
    }
    const now = this.now();
    const mono = this.monotonic();
    const gone: string[] = [];
    const linked = new Set(this.linkedMembers());
    for (const [peer, ad] of this.members) {
      if (linked.has(peer) || !this.adLapsed(ad, now)) {
        continue;
      }
      if (this.wakeHolds(peer, mono)) {
        this.wakeDropsDeferred += 1; // a probe, not a drop (owner decision 3 of 2026-11-23)
        continue;
      }
      gone.push(peer);
    }
    for (const peer of gone) {
      this.members.delete(peer);
      this.wakeAnswered.delete(peer);
      this.heldPeerAds.delete(peer);
      this.reachable.delete(peer);
      this.sessionPeers.delete(peer);
      this.forgetReplicationHints(peer);
    }
    if (gone.length > 0) {
      this.appCardLevelChanged();
    }
    return gone;
  }

  private foldDelta(delta: Dict): void {
    // Claim before state: a completion authenticates against the holder's claim.
    if (delta["claimEntry"] && typeof delta["claim"] === "object"
        && delta["claim"] !== null) {
      this.foldClaim(String(delta["claimEntry"]), delta["claim"] as Dict);
    }
    if (delta["state"] !== null && typeof delta["state"] === "object") {
      this.fold(delta["state"] as Dict);
      this.staleOffered(delta["state"] as Dict);
    }
    this.offerDisplaced();
  }

  private fold(dto: Dict): void {
    // HLC round five, 2026-11-08 (E7): a state without its lease stamp or its lease value decodes,
    // but a lease register holds nothing without both, so the replica drops it before it judges
    // anything, as Java's mergeState does: it merges nothing, waits for nothing, no digest
    // acknowledges it, and it counts in no counter.
    if (dto["leaseStamp"] === null || dto["leaseStamp"] === undefined
        || dto["leaseValue"] === null || dto["leaseValue"] === undefined) {
      return;
    }
    if (dto["record"] === null || dto["record"] === undefined) {
      this.foldRecordless(dto);
      return;
    }
    const record = dto["record"] as Dict;
    const entryId = record["entryId"];
    // ASF-025, as Java's ReplicatedSpace.dotsBoundToIssuer and before the signatures (HLC round six,
    // 2026-11-08, reference rule): only an entry's writer mints its dots, so a dot naming another
    // replica is fabricated provenance and the state is dropped, counted nowhere.
    if (typeof entryId !== "string" || !dotsBoundToIssuer(dto, record)) {
      return; // fabricated provenance: drop it
    }
    if (!this.verifyState(dto, record)) {
      if (dto["completed"] && this.rememberUnproven(entryId, dto)) {
        this.judgeDisplaced(entryId); // a displaced holder's completion whose claim came in another frame (§7.4)
      }
      return; // unauthenticated record or forged mutable state: drop it
    }
    if (this.auditOn && hasControl(entryId)) {
      return; // annex I.6: under wire.ae=2 an id holding a control character is dropped uncounted, as R8 drops a state
    }
    // HLC logical counter, 2026-11-08 (Rust team report): every implementation refuses a state
    // whose issue or lease stamp fails the strict parse, so the replicas converge and no such
    // stamp reaches the lease's last-writer-wins join. HLC round four, 2026-11-08: an agent-signed
    // state's signedAt is a stamp like any other (D1), and a stamp that does not decode was counted
    // with the carrier that brought it (D3), so it is dropped here uncounted. The check follows the
    // signatures, and a re-offered state counts once.
    // A peer-signed state carries no signedAt, so only the stamps the state names are judged.
    const stamps = [record["issued"], dto["leaseStamp"], dto["signedAt"]]
      .filter((stamp) => stamp !== null && stamp !== undefined);
    if (stamps.some((stamp) => wire.decodeHlc(stamp) === null)) {
      return;
    }
    // HLC round five, 2026-11-08 (E6): revocation comes before the stamp checks, so a revoked actor's
    // state counts in no stamp counter, whatever its stamps.
    const pending = this.pendingStates.get(entryId);
    if (this.refusedForRevocation(dto, record)) {
      // Authentic, but its actor is revoked here (SPEC §5.6): what is already
      // held stays as held, and this state is not merged.
      this.pendingStates.delete(entryId);
      return;
    }
    if (stamps.some((stamp) => wire.parseHlc(stamp) === null)) {
      this.refuseState(dto, record, false);
      return;
    }
    // HLC round four, 2026-11-08 (D4), as Java's ReplicatedSpace: a record or lease stamp past the
    // far-future margin waits for this replica's wall, unmerged and unacknowledged, and counts only
    // as deferred, unless it lies so far ahead that no honest clock reaches it. HLC round six,
    // 2026-11-08 (F4): an agent-signed state's signedAt is judged the same way.
    const ahead = this.farFuture(record["issued"], dto["leaseStamp"], dto["signedAt"]);
    if (ahead === "hostile") {
      this.refuseState(dto, record, true);
      return;
    }
    if (ahead === "deferred") {
      this.countOnce(this.deferredStamps, stateOfferKey(dto, record), () => this.stampsFarFutureDeferred++);
      return;
    }
    // SPEC §7.3, as Java's ReplicatedSpace (HLC round five, 2026-11-08): this replica refuses at the
    // door a state past the collection horizon that a lagging replica re-offers, so a collected
    // tombstone never returns.
    this.observeLease(dto);
    if (this.collectableHere(dto, this.now())) {
      // Acknowledged when this replica holds no state of the entry, so a member that keeps the tombstone longer
      // stops re-offering it every round (SPEC §7.3, RE-H-03).
      this.acknowledgeCollected(dto, record);
      return;
    }
    this.pendingStates.delete(entryId);
    // ASF-017: states JOIN, mirroring the Java CRDT — dot sets union, the
    // lease is last-writer-wins by HLC stamp, and completed is monotone. A
    // replayed early state (validly signed by its author) can therefore never
    // shrink the sets, roll back the lease, or undo a completion.
    const previous = this.states.get(entryId);
    this.storeJoined(entryId, previous, dto);
    this.collectBy(this.horizonOf(this.states.get(entryId)!));
    this.onState?.(this.states.get(entryId)!, previous);
    this.wakeFoldWaiters();
    if (pending !== undefined) {
      this.foldRecordless(pending);
    }
  }

  /**
   * A renew, cancel, or complete without its record (srad/agentspaces-pdt.md §3.9, PD-L-01, PD-L-02,
   * PD-L-04): the state is merged over the record this replica holds, through every check a full
   * state passes, or kept pending with no event until anti-entropy ships the whole DTO. The entry
   * id comes from the DTO's `entryId` or from the rumor item that carried it.
   */
  private foldRecordless(dto: Dict): void {
    const entryId = dto["entryId"];
    if (typeof entryId !== "string" || entryId.length === 0) {
      return;
    }
    // HLC canonical stamps, 2026-11-08: a lease stamp is judged once the record arrives, since
    // only the record's signer verifies the renewal; fold refuses it then and counts it once.
    const previous = this.states.get(entryId);
    if (previous === undefined) {
      if (this.pendingStates.size >= MAX_PENDING_RECORDLESS && !this.pendingStates.has(entryId)) {
        const oldest = this.pendingStates.keys().next().value;
        if (oldest !== undefined) {
          this.pendingStates.delete(oldest);
        }
      }
      this.pendingStates.set(entryId, dto);
      return;
    }
    const full: Dict = { ...dto, record: previous["record"] };
    for (const carried of ["issuerPublicKey", "agentCertificate"]) {
      if ((full[carried] === null || full[carried] === undefined) && previous[carried] !== undefined && previous[carried] !== null) {
        full[carried] = previous[carried];
      }
    }
    delete full["entryId"];
    this.fold(full);
  }

  /**
   * Authenticates a received state DTO: the record signature (the writer's
   * identity) and the state signature (the transition). The party authorized
   * for the transition is the take-claim holder for a completion and the
   * issuer otherwise. Mirrors ReplicatedSpace.verifyState (SPEC §11a.4): an
   * agent-signed state must name that party, carry a certificate the party's
   * peer key verifies at `signedAt`, and verify under its agent key; and an
   * agent-attested party's transitions must be agent-signed (A6, v0.1.13).
   */
  private verifyState(dto: Dict, record: Dict, proof: Dict | null = null): boolean {
    const issuerKey = dto["issuerPublicKey"];
    if (!(issuerKey instanceof Uint8Array) || issuerKey.length !== 32) {
      return false;
    }
    // The record: peer-signed, or agent-signed under a peer certificate
    // (TECH-SPEC §7.2's two-key rule, QA4 A4-7), judged at its issue stamp.
    if (!wire.verifyRecord(record, issuerKey, dto["agentCertificate"])) {
      return false;
    }
    const stateSig = dto["stateSig"];
    if (!(stateSig instanceof Uint8Array)) {
      return false;
    }
    let signerKey: unknown;
    let party: unknown;
    let partyAttested: boolean;
    if (dto["completed"]) {
      const signed = proof ?? this.claims.get(String(record["entryId"]));
      if (!signed) {
        return false; // no authenticated holder to attribute the completion to
      }
      // The claim authenticating this completion must be bound to exactly this
      // entry and space by its own signed fields (ASF-002/041).
      const claim = signed["claim"] as Dict;
      if (claim["entryId"] !== record["entryId"]
          || claim["spaceId"] !== record["spaceId"]
          || !wire.verifyClaimProof(signed)) {
        return false;
      }
      signerKey = signed["holderKey"];
      party = claim["holder"];
      partyAttested = signed["holderCertificate"] != null;
    } else {
      signerKey = issuerKey;
      party = record["issuer"];
      partyAttested = dto["agentCertificate"] != null;
    }
    if (!(signerKey instanceof Uint8Array) || signerKey.length !== 32) {
      return false;
    }
    const signer = dto["signer"] ?? null;
    const view = dumps(stateViewOf(dto, record));
    if (signer !== null) {
      const certificate = dto["stateCertificate"];
      // HLC round four, 2026-11-08 (D1): judged at a signedAt that decodes, so one above the limit
      // verifies and fold then refuses and counts it. HLC round six, 2026-11-08 (F4): the certificate
      // no longer drops a signedAt past the drift ceiling in silence; fold judges it by D4's rule.
      const signedMillis = wire.decodedPhysical(dto["signedAt"]);
      if (signedMillis === null) {
        return false;
      }
      return signer === party && typeof certificate === "object" && certificate !== null
        && verifyAgentCertificateCovering(certificate, signerKey, String(party), signedMillis)
        && Identity.verify((certificate as Dict)["agentPublicKey"] as Uint8Array, view, stateSig);
    }
    if (partyAttested) {
      return false; // A6: an attested party's transitions must be agent-signed
    }
    return Identity.verify(signerKey, view, stateSig);
  }

  /**
   * SPEC §5.6's freeze rule at merge, for every incoming state: the actor of
   * the transition (the claim holder for a completion, the issuer otherwise)
   * must not be revoked; an agent is judged at the state's `signedAt` with
   * the keys it signed with. A peer-signed state (no `signedAt`) is judged at
   * its `leaseStamp`, the stamp of the last write or renewal (the record's
   * issue stamp for an unrenewed write), so a renewal after the effective
   * instant is refused while the original history still folds. A refused state's digest line is
   * acknowledged, as Java's ReplicatedSpace acknowledges it, so partners stop re-offering it (HLC
   * round five, 2026-11-08, E12). The times are those of stamps that decode, a counter above the
   * limit included, since this judgement comes before the stamp checks (E6).
   */
  private refusedForRevocation(dto: Dict, record: Dict): boolean {
    // An unreadable time is an unknown one: refused under any revocation.
    const signedAt = dto["signedAt"] != null ? wire.decodedPhysical(dto["signedAt"]) : null;
    let refused: boolean;
    if (dto["completed"]) {
      const signed = this.claims.get(String(record["entryId"]));
      const claim = (signed?.["claim"] ?? {}) as Dict;
      const certificate = (signed?.["holderCertificate"] ?? {}) as Dict;
      refused = claim["holder"] != null
        && this.revocations.refuses(claim["holder"], certificate["agentPublicKey"], signedAt);
    } else {
      const certificate = (dto["agentCertificate"] ?? {}) as Dict;
      const stateCertificate = (dto["stateCertificate"] ?? {}) as Dict;
      refused = this.revocations.refuses(record["issuer"], certificate["agentPublicKey"],
        signedAt ?? wire.decodedPhysical(dto["leaseStamp"]))
        || (dto["signer"] != null
          && this.revocations.refuses(record["issuer"], stateCertificate["agentPublicKey"], signedAt));
    }
    if (refused) {
      this.acknowledge(dto, record);
    }
    return refused;
  }

  /**
   * Whether a claim's stamp is one the replica refuses: a stamp item that does not decode (E1, D3)
   * or one wire.parseHlc refuses. The replica counts a refusal in stampsLogicalRefused, once per
   * distinct claim on the entry (HLC canonical stamps, 2026-11-08), only when the stamp decodes, the
   * claim's proof verifies, and its holder is not revoked: signatures, then revocation, then the
   * stamp (HLC round five, 2026-11-08, E6). A stamp that does not decode names no verified signer
   * and counts where its carrier was decoded: as a space delta, or as the ordered-log host's dropped
   * command (HLC round four, 2026-11-08, D3). The ordered-log host asks this of every committed
   * claim before it installs or announces one.
   */
  refusesClaimStamp(entryId: string, signed: Dict): boolean {
    const claim = (signed["claim"] ?? {}) as Dict;
    if (wire.decodeHlc(claim["stamp"]) === null) {
      return true;
    }
    if (wire.parseHlc(claim["stamp"]) !== null) {
      return false;
    }
    if (wire.verifyClaimProof(signed) && !this.holderRevoked(signed)) {
      this.countRefusal(claimOfferKey(entryId, claim), false);
    }
    return true;
  }

  /**
   * SPEC §5.6 v0.1.13 (review M-1): a revoked holder takes nothing, whatever the claim's stamp,
   * since a renewal keeps it.
   */
  private holderRevoked(signed: Dict): boolean {
    const claim = (signed["claim"] ?? {}) as Dict;
    const certificate = (signed["holderCertificate"] ?? {}) as Dict;
    return this.revocations.refuses(claim["holder"], certificate["agentPublicKey"], null);
  }

  /**
   * Refuses a verified state for its stamps: counts it once per distinct state, keyed on its entry
   * id, issue stamp and signed state view alone, so no unsigned field a relay changes makes a second
   * refusal, and acknowledges its digest line so partners stop re-offering it (HLC round four,
   * 2026-11-08, D5).
   */
  private refuseState(dto: Dict, record: Dict, farFuture: boolean): void {
    this.countRefusal(stateOfferKey(dto, record), farFuture);
    this.acknowledge(dto, record);
  }

  /** Names a verified, refused state's digest line as acknowledged. */
  private acknowledge(dto: Dict, record: Dict): void {
    const line = `e:${String(record["entryId"])}=${serving.stateHash(dto)}`;
    this.acknowledgeLine(line, String(record["spaceId"]));
    // Annex I.6: forgotten once a holder would have collected what was refused, so the line cannot hold this
    // replica's audited set apart from its partners' for good; a member that still holds it earns it again.
    this.forgetRefusedAfter(line, horizon.collectionHorizon(horizonKindOf(dto), leaseExpiryOf(dto),
      this.longestLeaseOf(dto), "legacy"));
  }

  /**
   * Names a digest line of the space `spaceId` as refused and acknowledged, the newest past
   * MAX_REFUSED_ACK, as Java's access-ordered refusedAck keeps them.
   */
  private acknowledgeLine(line: string, spaceId: string): void {
    this.refusedAck.delete(line); // re-offered: kept as the newest
    this.refusedAck.set(line, spaceId);
    // The sweep forgets acknowledgements whose time has come, so it runs once there is one to forget (the forget
    // times below bring it forward).
    this.collectBy(this.now() + COLLECTED_ACK_HOLD_MILLIS);
    // R7's bound is per space, as Java's refusedAck is (srad/replication-by-entry.md §10.1): one busy space's refusals
    // never push another space's acknowledgements out.
    if ((this.ackCounts.get(spaceId) ?? 0) > MAX_REFUSED_ACK) {
      for (const [held, id] of this.refusedAck) {
        if (id === spaceId) {
          this.refusedAck.delete(held);
          break;
        }
      }
    }
  }

  /** Counts a verified refusal once per distinct offer `key`, as far-future or as a logical refusal. */
  private countRefusal(key: string, farFuture: boolean): void {
    this.countOnce(this.refusedStamps, key, farFuture
      ? () => this.stampsFarFutureRefused++ : () => this.stampsLogicalRefused++);
  }

  /**
   * Runs `count` the first time `seen` meets `key`. A key met again becomes the most recent, and
   * `seen` forgets its least recently met key past the cap (HLC round five, 2026-11-08, E14).
   */
  private countOnce(seen: Set<string>, key: string, count: () => void): void {
    if (seen.delete(key)) {
      seen.add(key);
      return;
    }
    seen.add(key);
    if (seen.size > MAX_REFUSED_STAMPS) {
      seen.delete(seen.values().next().value!);
    }
    count();
  }

  /**
   * Where the latest of `stamps` lies against this replica's wall (HLC round four, 2026-11-08, D4):
   * `inside` up to wall + MAX_HLC_SKEW_MILLIS + FAR_FUTURE_MARGIN_MILLIS, `deferred` up to
   * FAR_FUTURE_HOSTILE_MILLIS past that, and `hostile` beyond. The stamps are acceptable ones.
   */
  private farFuture(...stamps: CborValue[]): "inside" | "deferred" | "hostile" {
    const ceiling = BigInt(Math.trunc(this.now()) + wire.MAX_HLC_SKEW_MILLIS + wire.FAR_FUTURE_MARGIN_MILLIS);
    let lead = 0n;
    for (const stamp of stamps) {
      const parsed = wire.parseHlc(stamp);
      if (parsed !== null && parsed.physical - ceiling > lead) {
        lead = parsed.physical - ceiling;
      }
    }
    return lead === 0n ? "inside" : lead <= BigInt(wire.FAR_FUTURE_HOSTILE_MILLIS) ? "deferred" : "hostile";
  }

  /** The `a:` lines of one space's digest: its refused states, acknowledged in Java's order. */
  private acknowledgedLines(space: string): string {
    const spaceId = spaceIdLocal(`${this.group}/${space}`);
    const lines = [...this.refusedAck].filter(([, id]) => id === spaceId).map(([line]) => line);
    return lines.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).map((line) => `a:${line}\n`).join("");
  }

  /**
   * The space delta in `bytes` read strictly as `schema`, or null once it is counted in
   * deltasUndecodable (HLC round six, 2026-11-08, F1 and F3): bytes that are no document in the wire
   * encoding, a record with a field the schema does not name, absent, out of order or of the wrong
   * kind, or any form other than the one its value encodes to. Such a delta names no verified signer.
   */
  private decodeDelta(bytes: CborValue | undefined, schema: records.Schema): Dict | null {
    const delta = records.readRecord(bytes, schema);
    if (delta === null) {
      this.deltasUndecodable += 1;
    }
    return delta;
  }

  /**
   * Whether a gossiped claim breaks Java's time bounds on a claim (HLC round six, 2026-11-08, R6): its
   * stamp lies more than MAX_CLAIM_PREDATES_ISSUE_MILLIS before the held entry's issue stamp, or it
   * contests `current`, another holder's claim, with a stamp before now - MAX_HLC_SKEW_MILLIS -
   * CLAIM_SETTLE_WINDOW_MILLIS. The claim's stamp parses, as foldClaim refused it otherwise.
   */
  private claimOutOfTime(entryId: string, claim: Dict, current: Dict | undefined): boolean {
    const physical = wire.parseHlc(claim["stamp"])!.physical;
    const issued = wire.parseHlc((this.states.get(entryId)?.["record"] as Dict | undefined)?.["issued"]);
    if (issued !== null && physical < issued.physical - BigInt(wire.MAX_CLAIM_PREDATES_ISSUE_MILLIS)) {
      return true;
    }
    return current !== undefined && current["holder"] !== claim["holder"]
      && physical < BigInt(Math.trunc(this.now()) - wire.MAX_HLC_SKEW_MILLIS - wire.CLAIM_SETTLE_WINDOW_MILLIS);
  }

  private foldClaim(entryId: string, signed: Dict, committed = false): void {
    // The claim is a conformed TakeClaim before the lattice sees it, so a NaN or infinite bid and a
    // non-positive epoch never reach it (ASF-033; HLC round six, 2026-11-08, F1), and a claim
    // transplanted under a foreign map key is dropped (ASF-002).
    const claim = wire.canonicalClaim(signed["claim"]);
    if (claim === null || claim["entryId"] !== entryId) {
      return;
    }
    if (this.auditOn && hasControl(entryId)) {
      return; // annex I.6: dropped uncounted under wire.ae=2, so no line of the audited set names two sets
    }
    const epoch = wire.claimNumber(claim["epoch"]);
    const expires = wire.claimNumber(claim["expiresAtMillis"]);
    // The proof: peer-signed, or agent-signed under a peer certificate
    // (TECH-SPEC §7.6's two-key rule, QA4 A4-7 phase 3).
    if (!wire.verifyClaimProof(signed)) {
      return;
    }
    // ASF-047, as Java's mergeClaim: a revoked holder takes nothing, whatever the claim's stamp, and
    // the refusal is acknowledged in the digest so partners stop re-offering it (HLC round six,
    // 2026-11-08, R7).
    if (this.holderRevoked(signed)) {
      const line = `c:${entryId}=${serving.claimHash(claim)}`;
      this.acknowledgeLine(line, String(claim["spaceId"]));
      this.forgetRefusedAfter(line, expires + horizon.LAPSED_GRACE_MILLIS); // a claim's holders drop it past its lapse
      return;
    }
    // HLC logical counter, 2026-11-08 (Rust team report): every implementation refuses a claim
    // whose stamp fails the strict parse, so the lattice decides alike everywhere and
    // wire.compareClaims never sees an unparsed stamp. The refusal counts only after the proof
    // and the revocation check (HLC round five, 2026-11-08, E6).
    if (this.refusesClaimStamp(entryId, signed)) {
      return;
    }
    // HLC round four, 2026-11-08 (D4), in Java's order: a gossiped claim stamped far beyond the
    // far-future margin is refused and counted before the bounds below, and one past the margin
    // that meets them waits for this replica's wall. A claim the ordered log committed skips this
    // wall-dependent rule, so every member installs it alike.
    const ahead = committed ? "inside" : this.farFuture(claim["stamp"]);
    if (ahead === "hostile") {
      this.countRefusal(claimOfferKey(entryId, claim), true);
      return;
    }
    // ASF-004, mirroring ReplicatedSpace: bound what a remote claim may assert
    // before the lattice (where higher epochs win by design) sees it.
    const current = this.claims.get(entryId)?.["claim"] as Dict | undefined;
    const observed = current ? wire.claimNumber(current["epoch"]) : 0;
    if (epoch > observed + wire.MAX_CLAIM_EPOCH_JUMP
        || expires > this.now() + wire.MAX_CLAIM_HOLD_MILLIS) {
      return;
    }
    // HLC round six, 2026-11-08 (R6), Java's two checks in mergeClaim's order, on gossip alone as Java's
    // log path skips them: a claim cannot predate the entry it answers by more than the drift ceiling,
    // and a claim contesting another holder's claim with a stamp older than the ceiling plus one settle
    // window is a queue-jump, since LEASE_RACE picks the lowest stamp. Each drop counts nothing.
    if (!committed && this.claimOutOfTime(entryId, claim, current)) {
      return;
    }
    if (ahead === "deferred") {
      this.countOnce(this.deferredStamps, claimOfferKey(entryId, claim), () => this.stampsFarFutureDeferred++);
      return;
    }
    this.observeClaimLease(signed);
    if (committed) {
      this.logDecidedEpochs.set(entryId, Math.max(this.logDecidedEpochs.get(entryId) ?? 0, epoch));
      capLines(this.logDecidedEpochs);
    }
    this.mergeHeldClaim(entryId, signed);
    this.collectBy(wire.claimNumber(signed["claim"] && (signed["claim"] as Dict)["expiresAtMillis"])); // R10: claims expire too
    this.onClaim?.(entryId, this.claims.get(entryId)!);
    this.wakeFoldWaiters();
    this.judgeDisplaced(entryId);
    this.offerDisplaced();
  }

  // ------------------------------------------------- the settle guarantee's second rule, paired (SPEC §7.4, v0.1.36)
  // As Java's ReplicatedSpace (the store race of 2026-11-22): the winner remembers, per entry and bounded, the claims
  // its own claim displaced and the completions it dropped for want of their claim, and judges each pair when its
  // second half arrives, from any frame; a displaced holder that completed offers its claim again with a doubling
  // backoff. No frame, field or vector changes.

  /** The entries whose displaced holder's authentic completion this peer's take acknowledges, by the held epoch. */
  private readonly outbidCompletions = new Map<string, number>();
  /** The entries an agent of this peer completed with its own work, by epoch and space name. */
  private readonly completedHere = new Map<string, { epoch: number; space: string }>();
  /** Verified claims this peer's held claim displaced, at most DISPLACED_PER_ENTRY per entry. */
  private readonly displacedClaims = new Map<string, Dict[]>();
  /** Completions dropped while this peer's claim held the entry, at most DISPLACED_PER_ENTRY per entry. */
  private readonly unprovenCompletions = new Map<string, Dict[]>();
  /**
   * The claims made here that a better claim of another peer displaced, the first one lost per entry, with or without
   * a completion under it (Java's displacedHere), kept while the claim lives (until it lapses, its stamp is half the
   * drift ceiling old, or the entry is gone), after any re-offers are spent too: a winner's targeted rounds may start
   * late, and this peer is the only source of its completion (owner decision 1 of 2026-11-23, as the core). The
   * entries a relayed or non-seed DIGEST is answered with on a dial-only peer.
   */
  private readonly displacedHeld = new Map<string, Dict>();
  /** This peer's completions whose claim a better claim displaced, offered again (the losing side of rule two). */
  private readonly displacedOwn = new Map<string, { signed: Dict; space: string; offers: number; next: number }>();
  /** The highest epoch the ordered log decided per entry: there the log alone names the holder. */
  private readonly logDecidedEpochs = new Map<string, number>();
  /** Completions counted twice: this peer did the work and a displaced holder's authentic completion arrived after. */
  duplicateCompletions = 0;
  /** Displaced holders' completions this peer's takes acknowledged instead of doing the work again. */
  displacedAcknowledged = 0;
  /** Offers of this peer's displaced claims, made again. */
  displacedReoffers = 0;

  /**
   * Whether this peer's take of the entry is to acknowledge a displaced holder's authentic completion rather than do
   * the work again (rule two of SPEC §7.4): its take comes back empty, or its complete writes no result.
   */
  knowsDisplacedCompletion(entryId: string): boolean {
    const held = this.claims.get(entryId)?.["claim"] as Dict | undefined;
    return held !== undefined && this.outbidCompletions.get(entryId) === wire.claimNumber(held["epoch"]);
  }

  /** Merges a claim into the lattice and notes which claim the merge displaced. */
  private mergeHeldClaim(entryId: string, signed: Dict): Dict {
    const held = this.claims.get(entryId);
    const kept = wire.mergeClaims(held, signed);
    if (kept !== held) {
      this.claims.set(entryId, kept);
    }
    if (held !== undefined) {
      this.noteDisplaced(entryId, kept, kept === held ? signed : held);
    }
    return kept;
  }

  private noteDisplaced(entryId: string, kept: Dict, lost: Dict): void {
    const keptClaim = kept["claim"] as Dict, lostClaim = lost["claim"] as Dict;
    if (kept === lost || keptClaim["holder"] === lostClaim["holder"]) {
      return; // the same holder's renewal or attestation upgrade displaces nobody
    }
    const self = this.identity.peerId;
    if (holderPeer(keptClaim) === self) {
      const lines = this.displacedClaims.get(entryId) ?? [];
      if (!lines.some((c) => sameClaim(c["claim"] as Dict, lostClaim))) {
        lines.push(lost);
        lines.splice(0, Math.max(0, lines.length - DISPLACED_PER_ENTRY));
      }
      this.displacedClaims.set(entryId, lines);
      capLines(this.displacedClaims);
      const displacedPeer = holderPeer(lostClaim);
      if (displacedPeer !== self) {
        this.fileDisplacedPull(entryId, displacedPeer);
      }
    } else if (holderPeer(lostClaim) === self) {
      if (!this.displacedHeld.has(entryId)) {
        // The claim made here this peer first lost on the entry, with or without a completion under it (Java's
        // displacedHere): kept past the re-offers too, while the claim lives, for a relayed DIGEST (decision 1).
        this.displacedHeld.set(entryId, lost);
        capLines(this.displacedHeld);
      }
      const done = this.completedHere.get(entryId);
      if (done !== undefined && done.epoch === wire.claimNumber(lostClaim["epoch"])) {
        if (!this.displacedOwn.has(entryId)) {
          this.displacedOwn.set(entryId, { signed: lost, space: done.space, offers: 0, next: this.monotonic() });
          capLines(this.displacedOwn);
        }
      }
    }
  }

  /** Keeps a completion dropped while this peer's claim holds the entry; returns whether a displaced claim is known. */
  private rememberUnproven(entryId: string, dto: Dict): boolean {
    const held = this.claims.get(entryId)?.["claim"] as Dict | undefined;
    if (held === undefined || holderPeer(held) !== this.identity.peerId || !(dto["stateSig"] instanceof Uint8Array)
        || (dto["signer"] != null && dto["signer"] === held["holder"])) {
      return false; // not this peer's claim, or the held claim's own completion coming back
    }
    const lines = this.unprovenCompletions.get(entryId) ?? [];
    if (!lines.some((d) => equals(d["stateSig"] as Uint8Array, dto["stateSig"] as Uint8Array))) {
      lines.push(dto);
      lines.splice(0, Math.max(0, lines.length - DISPLACED_PER_ENTRY));
    }
    this.unprovenCompletions.set(entryId, lines);
    capLines(this.unprovenCompletions);
    return this.displacedClaims.has(entryId);
  }

  /** Judges each completion dropped here for an entry against each claim this peer's claim displaced for it. */
  private judgeDisplaced(entryId: string): void {
    const claims = this.displacedClaims.get(entryId);
    const states = this.unprovenCompletions.get(entryId);
    if (claims === undefined || states === undefined) {
      return;
    }
    for (const dto of [...states]) {
      for (const claim of [...claims]) {
        const holder = (claim["claim"] as Dict)["holder"];
        if (dto["signer"] == null || dto["signer"] === holder) {
          this.noteOutbidCompletion(entryId, claim, dto);
        }
      }
    }
  }

  /**
   * Judges a completion this replica dropped because this peer's held claim displaces the claim it was made under
   * (rule two of SPEC §7.4). While the entry is present here, a live displaced holder's authentic completion makes
   * this peer's take acknowledge it instead of doing the work again; when this peer already completed it with its
   * own work, both did the work, and it is counted once as a duplicate. A revoked holder's completion is no evidence,
   * nor is one at an epoch the ordered log decided.
   */
  private noteOutbidCompletion(entryId: string, proof: Dict, received: Dict): void {
    if (!received["completed"]) {
      return;
    }
    const displaced = proof["claim"] as Dict;
    const held = this.claims.get(entryId)?.["claim"] as Dict | undefined;
    const state = this.states.get(entryId);
    if (displaced["entryId"] !== entryId || held === undefined || state === undefined
        || holderPeer(held) !== this.identity.peerId || held["holder"] === displaced["holder"]
        || wire.claimNumber(displaced["epoch"]) > wire.claimNumber(held["epoch"])
        || wire.mergeClaims(this.claims.get(entryId), proof) !== this.claims.get(entryId)) {
      return;
    }
    const decided = this.logDecidedEpochs.get(entryId);
    if (decided !== undefined && wire.claimNumber(displaced["epoch"]) <= decided) {
      return;
    }
    const now = this.now();
    const heldEpoch = wire.claimNumber(held["epoch"]);
    let duplicate: boolean;
    if (present(state)) {
      if (wire.claimNumber(held["expiresAtMillis"]) <= now || wire.claimNumber(displaced["expiresAtMillis"]) <= now
          || this.outbidCompletions.get(entryId) === heldEpoch) {
        return;
      }
      duplicate = false;
    } else if (state["completed"] && this.completedHere.get(entryId)?.epoch === heldEpoch) {
      duplicate = true;
    } else {
      return;
    }
    const record = (received["record"] as Dict | null | undefined) ?? (state["record"] as Dict | undefined);
    if (record === undefined || record === null || record["spaceId"] !== (state["record"] as Dict)["spaceId"]
        || this.holderRevoked(proof)
        || !this.verifyState(received["record"] == null ? { ...received, record } : received, record, proof)) {
      return;
    }
    if (duplicate) {
      this.completedHere.delete(entryId);
      this.duplicateCompletions += 1;
    } else {
      this.outbidCompletions.set(entryId, heldEpoch);
      capLines(this.outbidCompletions);
    }
  }

  /** A state showing the entry present while one of this peer's completions of it waits to be offered: due again. */
  private staleOffered(dto: Dict): void {
    if (this.displacedOwn.size === 0 || dto["completed"] || !present(dto)) {
      return;
    }
    const entryId = (dto["record"] as Dict | undefined)?.["entryId"] ?? dto["entryId"];
    const line = typeof entryId === "string" ? this.displacedOwn.get(entryId) : undefined;
    if (line !== undefined && this.monotonic() >= line.next) {
      this.reofferDue = true;
    }
  }

  private reofferDue = false;

  /**
   * Offers again each displaced claim of this peer's that is due, as the claim delta it first travelled in, and moves
   * its next offer back (at once, then no sooner than 1 s, 2 s, 4 s ... after the previous one, at most six offers,
   * while the claim is live and younger than half the drift ceiling); drops a line that is spent.
   */
  private offerDisplaced(): void {
    if (this.displacedOwn.size === 0) {
      return;
    }
    const mono = this.monotonic();
    const now = this.now();
    for (const [entryId, line] of [...this.displacedOwn]) {
      const claim = line.signed["claim"] as Dict;
      const decided = this.logDecidedEpochs.get(entryId);
      if (line.offers >= REOFFER_MAX || wire.claimNumber(claim["expiresAtMillis"]) <= now
          || now - wire.hlcPhysical(claim["stamp"]) > wire.MAX_HLC_SKEW_MILLIS / 2
          || !this.states.has(entryId)
          || (decided !== undefined && wire.claimNumber(claim["epoch"]) <= decided)) {
        this.displacedOwn.delete(entryId);
        continue;
      }
      if (line.offers === 0 || (this.reofferDue && mono >= line.next)) {
        line.next = mono + REOFFER_BACKOFF_MILLIS * 2 ** line.offers;
        line.offers += 1;
        this.displacedReoffers += 1;
        this.send("RUMOR", wire.rumorBody(`space:${line.space}`, `c:${entryId}:${String(claim["stamp"])}`, 6,
          wire.claimDelta(entryId, line.signed)));
      }
    }
    this.reofferDue = false;
  }

  // ------------------------------------------------- targeted rounds toward displaced holders (owner decision 4)
  // As Java's ReplicatedSpace.displacedPulls (srad/agentspaces-event-loop.md §10.29, phase 6, owner decision 4 of
  // 2026-11-23): a displaced holder's completion may have one source only, the holder itself, since a replica holding
  // the better claim drops it (SPEC §11a.4), and anti-entropy repairs only a round's opener. So while this peer's take
  // of the entry is open, it opens rounds with each holder its claim displaced rather than wait for a random partner
  // pick (or, on a dial-only peer, for a pull through its seed, which drops the completion): at once, then after 1, 2,
  // 4, 8 and 16 s on the monotonic clock, at most DISPLACED_PULL_MAX rounds, ending when it learns the completion,
  // completes the entry itself, or no longer holds the claim. No wire change: a round is the usual DIGEST, sent through
  // the seed in a RELAY_FRAME when the holder is not on a link of this peer's own.

  /** Per entry this peer's claim won: the holders it displaced and the targeted rounds so far. Bounded. */
  private readonly displacedPulls = new Map<string, { holders: Set<string>; rounds: number; next: number }>();
  /** Targeted anti-entropy rounds opened toward holders this peer's claim displaced (Java displacedPullRounds). */
  displacedPullRounds = 0;

  /** Files a displaced holder for the targeted rounds and brings the task forward to its next round. */
  private fileDisplacedPull(entryId: string, holder: string): void {
    const now = this.monotonic();
    let pull = this.displacedPulls.get(entryId);
    if (pull === undefined) {
      pull = { holders: new Set(), rounds: 0, next: now };
      this.displacedPulls.set(entryId, pull);
      capLines(this.displacedPulls);
    }
    if (!pull.holders.has(holder)) {
      pull.holders.add(holder);
      if (pull.rounds > 0) {
        pull.next = Math.min(pull.next, now); // a newly displaced holder is asked at once
      }
    }
    const loop = this.loop;
    if (!loop.has(DISPLACED_PULL_TASK)) {
      loop.add(DISPLACED_PULL_TASK, (nowMono) => this.pullDisplacedHolders(nowMono), null);
    }
    const due = loop.dueOf(DISPLACED_PULL_TASK);
    if (due === null || pull.next < due) {
      loop.reschedule(DISPLACED_PULL_TASK, pull.next);
    }
  }

  /**
   * Opens the targeted rounds that are due and drops the lines whose take is no longer open here: this peer no longer
   * holds the claim, it has lapsed, the entry is no longer present, the displaced completion is already known, or the
   * rounds are spent. Returns the next round's deadline on the monotonic clock, or null for none.
   */
  private pullDisplacedHolders(nowMono: number): number | null {
    const self = this.identity.peerId;
    const wall = this.now();
    const partners = new Map<string, Set<string>>(); // holder -> the entries it is asked for (one round names all)
    let next = Number.POSITIVE_INFINITY;
    for (const [entryId, pull] of [...this.displacedPulls]) {
      const held = this.claims.get(entryId)?.["claim"] as Dict | undefined;
      const state = this.states.get(entryId);
      const open = held !== undefined && holderPeer(held) === self && state !== undefined && present(state)
        && wire.claimNumber(held["expiresAtMillis"]) > wall
        && this.outbidCompletions.get(entryId) !== wire.claimNumber(held["epoch"]);
      if (!open || pull.rounds >= DISPLACED_PULL_MAX) {
        this.displacedPulls.delete(entryId);
        continue;
      }
      if (nowMono >= pull.next) {
        for (const holder of pull.holders) {
          let asked = partners.get(holder);
          if (asked === undefined) {
            asked = new Set();
            partners.set(holder, asked);
          }
          asked.add(entryId);
        }
        pull.next = nowMono + REOFFER_BACKOFF_MILLIS * 2 ** pull.rounds;
        pull.rounds += 1;
      }
      next = Math.min(next, pull.next);
    }
    for (const [holder, entryIds] of partners) {
      this.displacedPullRounds += 1;
      try {
        this.targetedRound(holder, entryIds);
      } catch {
        // the next round is due on its backoff
      }
    }
    return Number.isFinite(next) ? next : null;
  }

  /**
   * One anti-entropy round with a named member (Java GossipBus.antiEntropyWith): a text DIGEST of the asked entries' spaces,
   * the form every member answers (a 0.6.0 one, and one under `wire.ae=2` answers it as a 0.6.0 member would), with a
   * PULL_RESP of what this peer lacks. It names the space whether this peer pulls it or only joined it, as a dial-only
   * peer does. Directly on a link of this peer's own; through the seed, which drops a frame addressed to anyone else,
   * in a RELAY_FRAME, and the holder's PULL_RESP comes back the same way.
   */
  private targetedRound(holder: string, entryIds: Set<string>): void {
    // One round names the space of every entry the holder is asked for (Java's antiEntropyWith digests every stream):
    // a holder displaced in two spaces is asked for both at once.
    const digests: Dict = {};
    for (const entryId of entryIds) {
      const space = this.spaceNameOf(entryId);
      if (space !== null) {
        digests[`space:${space}`] = this.spaceDigest(space);
      } else {
        Object.assign(digests, this.fullDigests());
      }
    }
    this.sendAddressed("DIGEST", wire.digestBody(digests), holder);
  }

  /** The name of the joined space an entry belongs to, or null when no joined space holds it. */
  private spaceNameOf(entryId: string): string | null {
    const spaceId = (this.states.get(entryId)?.["record"] as Dict | undefined)?.["spaceId"];
    for (const space of this.joinedSpaces) {
      if (wireSpaceId(this.group, space) === spaceId) {
        return space;
      }
    }
    return null;
  }

  /** Forgets the settle lines of collected entries. */
  private forgetSettleLines(entryId: string): void {
    this.outbidCompletions.delete(entryId);
    this.completedHere.delete(entryId);
    this.displacedClaims.delete(entryId);
    this.unprovenCompletions.delete(entryId);
    this.displacedOwn.delete(entryId);
    this.displacedHeld.delete(entryId);
    this.displacedPulls.delete(entryId);
    this.logDecidedEpochs.delete(entryId);
  }

  /**
   * Completes an entry this peer's claim holds, with no result, when the holder that claim displaced already completed
   * it (rule two of SPEC §7.4): every replica converges on one completion and the displaced holder's result stays the
   * only one. Returns whether it did; the caller then writes no result.
   */
  acknowledgeDisplacedCompletion(space: string, entryId: string, agent: AgentIdentity | null = null): boolean {
    if (!this.knowsDisplacedCompletion(entryId)) {
      return false;
    }
    this.requireHeld(space, entryId, agent);
    this.completeEntry(space, entryId, agent);
    return true;
  }
  // ------------------------------------------------- replication by entry (SPEC annex I.6, §5.2, §7.2, §7.3, v0.1.35)
  // srad/replication-by-entry.md RE-L-01: the form per partner from its current card (the audit, the hashed round of
  // v0.1.17, or the full text), the audit and the fetch by id under a budget, the probe hashes split by partner kind,
  // the per-entry horizon with the view's and the writer's halves, and the acknowledgement of a collected tombstone.

  private auditOn = true;
  private horizonOn = true;
  /** The members whose current card carries `wire.ae=2`, `wire.hashes=1`, and `wire.horizon=1`. */
  readonly aePeers = new Set<string>();
  readonly hashPeers = new Set<string>();
  readonly horizonPeers = new Set<string>();
  /** When each member's current stay with the horizon hint began, on this peer's clock (the writer's half, RE-H-04). */
  private readonly hintedSince = new Map<string, number>();
  /** The annex I.6 audit, both halves, and its fetch queue. */
  readonly trieAudit: TrieAudit = new TrieAudit({
    trieFor: (stream) => this.trieForStream(stream),
    sendDigest: (to, fields) => this.send("DIGEST", wire.digestRecord(fields), to),
    audits: (member) => this.audits(member),
    now: () => this.now(),
    random: () => Math.random(),
    log: (message) => this.onReplicationLog?.(message),
  });
  private readonly audited: AuditedSets = new AuditedSets({
    holding: (id, now) => this.holdingOf(id, now),
    idsOf: (spaceId) => this.idsOfSpace(spaceId),
    now: () => this.now(),
  });
  /** The acknowledged lines by entry id, and how many each space holds (R7's bound is per space). */
  private readonly ackIndex = new Map<string, Set<string>>();
  private readonly ackCounts = new Map<string, number>();
  /** When each acknowledged line is forgotten: a collected tombstone's after its hold, a refusal's past its horizon. */
  private readonly ackForgetAt = new Map<string, number>();
  private readonly horizonModes = new Map<string, horizon.HorizonMode>();
  private readonly stateHashes = new WeakMap<Dict, string>();
  /** The partners whose answer to a round this peer opened is awaited, so only they draw a `want`'s text. */
  private readonly expectedPulls = new Set<string>();
  /**
   * The partners a budgeted text pull went to whose answer has not come, and when it went: only such an answer's
   * remainder continues the pull. Kept apart from `expectedPulls`, which each round clears, so a pull's chain is not
   * cut by a round that starts while its answer is on the way.
   */
  private readonly budgetedPulls = new Map<string, number>();
  private readonly continuations = new Map<string, number>();
  private readonly lastForm = new Map<string, Form>();
  private readonly probePulls = new Map<string, number>();
  private hinted: { at: number; value: boolean } = { at: Number.NaN, value: false };
  /** Since when this peer has opened no round, as first seen by a probe: its rounds have backed off past four. */
  private quietSince: number | null = null;
  /**
   * One round of the group, the unit of the horizon's hysteresis and of the probe's pacing: the founding's gossip
   * period when this peer knows it, else one second, Java's default.
   */
  gossipPeriodMillis = 1000;
  /** How many times a round toward a member took another form than the round before it (RE-Q-REL-09). */
  formChanges = 0;
  /** Renewals that would have shortened a lease before v0.1.35 (RE-H-01); the rule kept the longer lease. */
  renewShortenings = 0;
  /** Re-offers of collected tombstones this replica acknowledged at its door (RE-H-03). */
  collectedReoffersAcknowledged = 0;
  /** What anti-entropy cost, counters that only grow (RE-F-03). */
  readonly pacing = {
    hashedOpeningsSent: 0, hashedOpeningsReceived: 0, wantsSent: 0, wantsReceived: 0, digestTextBytesSent: 0,
    pullRespSent: 0, budgetedAnswers: 0, remainderSent: 0, remainderReceived: 0, pullContinued: 0, probeRounds: 0,
    remainderUnsolicited: 0,
  };
  /** Where the audit logs a refusal, once per member and reason. */
  onReplicationLog: ((message: string) => void) | null = null;

  /**
   * Whether this peer advertises `wire.hashes=1` and `wire.ae=2` and audits toward members that do (on by default).
   * Off, it is a 0.6.0 member: it opens every round with the full text, ignores a hashed opening, and drops a body
   * carrying a field of annex I.6. Advertise a change with {@link introduce}.
   */
  get audit(): boolean {
    return this.auditOn;
  }

  set audit(on: boolean) {
    this.auditOn = on;
  }

  /** The budget this peer puts on its requests, in bytes (annex I.6; 4 KiB to 4 MiB, 1 MiB by default). */
  get auditBudget(): number {
    return this.trieAudit.budget;
  }

  set auditBudget(bytes: number) {
    this.trieAudit.budget = bytes;
  }

  /** The audit sessions this peer keeps open per asker (1 to 4). */
  get auditSessions(): number {
    return this.trieAudit.sessionsMax;
  }

  set auditSessions(sessions: number) {
    this.trieAudit.sessionsMax = sessions;
  }

  /**
   * `per-entry` (the default) advertises `wire.horizon=1` and lets a withdrawal be collected by its own lease once
   * every member in view advertises it too; `legacy` keeps two maximum leases. Any other value is refused, so a
   * misspelt setting never passes for the default. Advertise a change with {@link introduce}.
   */
  get horizon(): "per-entry" | "legacy" {
    return this.horizonOn ? "per-entry" : "legacy";
  }

  set horizon(mode: "per-entry" | "legacy") {
    if (mode !== "per-entry" && mode !== "legacy") {
      throw new RangeError(`the horizon is "per-entry" or "legacy", not ${JSON.stringify(mode)}`);
    }
    this.horizonOn = mode === "per-entry";
  }

  /** Applies a host's replication settings; advertise a change of the hints with {@link introduce}. */
  configureReplication(options: ReplicationOptions): void {
    if (options.audit !== undefined) {
      if (typeof options.audit !== "boolean") {
        throw new TypeError(`audit is true or false, not ${JSON.stringify(options.audit)}`);
      }
      this.audit = options.audit;
    }
    if (options.auditBudget !== undefined) {
      this.auditBudget = options.auditBudget;
    }
    if (options.auditSessions !== undefined) {
      this.auditSessions = options.auditSessions;
    }
    if (options.horizon !== undefined) {
      this.horizon = options.horizon;
    }
  }

  /** Whether this peer audits with a member: both carry `wire.ae=2` (the member by its current card). */
  audits(member: string): boolean {
    return this.auditOn && this.aePeers.has(member);
  }

  /** The form a round toward a member takes now, read from its current card; it changes only when the card does. */
  formToward(member: string): Form {
    if (!this.auditOn) {
      return "text";
    }
    return this.aePeers.has(member) ? "ae" : this.hashPeers.has(member) ? "hashes" : "text";
  }

  /** The form of the last round this peer opened with a member, or undefined before the first. */
  lastFormToward(member: string): Form | undefined {
    return this.lastForm.get(member);
  }

  /** The per-entry horizon's mode in one space (RE-H-04), as last judged. */
  horizonModeOf(space: string): horizon.HorizonModeName {
    return this.horizonModes.get(wireSpaceId(this.group, space))?.mode ?? "LEGACY";
  }

  /** The figures of replication by entry, for a status page (RE-F-03, RE-Q-MNT-02). */
  replicationStatus(): {
    forms: { [form in Form]: number }; formChanges: number; audit: AuditSignals; pacing: Peer["pacing"];
    horizon: { [spaceId: string]: { mode: horizon.HorizonModeName; engagements: number; settlements: number;
      disengagements: number } };
    renewShortenings: number; collectedReoffersAcknowledged: number; acknowledged: number;
  } {
    const forms = { ae: 0, hashes: 0, text: 0 };
    for (const member of this.members.keys()) {
      forms[this.formToward(member)] += 1;
    }
    const modes: { [spaceId: string]: { mode: horizon.HorizonModeName; engagements: number; settlements: number;
      disengagements: number } } = {};
    for (const [spaceId, mode] of this.horizonModes) {
      modes[spaceId] = { mode: mode.mode, engagements: mode.engagements, settlements: mode.settlements,
        disengagements: mode.disengagements };
    }
    return { forms, formChanges: this.formChanges, audit: this.trieAudit.signals(), pacing: { ...this.pacing },
      horizon: modes, renewShortenings: this.renewShortenings,
      collectedReoffersAcknowledged: this.collectedReoffersAcknowledged, acknowledged: this.refusedAck.size };
  }

  /** The trie of a space (by name) as the audit reads it; built on its first read. */
  spaceTrie(space: string): HashTrie {
    return this.audited.trieFor(wireSpaceId(this.group, space));
  }

  // ---- the hints of the members' cards

  private noteReplicationHints(issuer: string, hints: Dict): void {
    this.hinted.at = Number.NaN;
    this.wakeCollector(); // a hint that comes or goes moves the horizon's streak, judged once per round
    const toggle = (set: Set<string>, on: boolean): void => {
      if (on) {
        set.add(issuer);
      } else {
        set.delete(issuer);
      }
    };
    // RE-T-03: the form toward a member follows its current card alone, so a card that drops a hint moves the member
    // back at the next round, and nothing else moves it (RE-Q-REL-09).
    toggle(this.hashPeers, hints[HASHES_HINT] === "1");
    toggle(this.aePeers, hints[AE_HINT] === AE_LEVEL);
    const horizonHinted = hints[HORIZON_HINT] === HORIZON_LEVEL;
    toggle(this.horizonPeers, horizonHinted);
    if (!horizonHinted) {
      this.hintedSince.delete(issuer);
    } else if (!this.hintedSince.has(issuer)) {
      this.hintedSince.set(issuer, this.now());
    }
  }

  private forgetReplicationHints(peer: string): void {
    this.aePeers.delete(peer);
    this.hashPeers.delete(peer);
    this.horizonPeers.delete(peer);
    this.hintedSince.delete(peer);
    this.lastForm.delete(peer);
    this.probePulls.delete(peer);
    this.continuations.delete(peer);
    this.expectedPulls.delete(peer);
    this.budgetedPulls.delete(peer);
    this.trieAudit.memberLeft(peer);
  }

  // ---- the streams and their hashes

  private heldStreams(): string[] {
    return ["ads", "view", ...revocation.STREAMS, ...[...this.pulledSpaces].map((space) => `space:${space}`)];
  }

  private trieForStream(stream: string): HashTrie | null | undefined {
    if (!this.servesStream(stream)) {
      return undefined;
    }
    if (!this.auditOn || !stream.startsWith("space:")) {
      return null; // held, with the text digest alone
    }
    return this.audited.trieFor(wireSpaceId(this.group, stream.substring("space:".length)));
  }

  /** `RevocationRegistry.digest` and `CredentialRevocationRegistry.digest`: one line per revocation, by key. */
  private revocationDigest(stream: string): Uint8Array {
    const lines: [string, string][] = [];
    for (const signed of (this.revocations.exportSigned()[stream] ?? []) as Dict[]) {
      const adBytes = signed["adBytes"];
      if (!(adBytes instanceof Uint8Array)) {
        continue;
      }
      try {
        const ad = loads(adBytes) as Dict;
        const key = stream === revocation.PEER_STREAM ? `r:${String(ad["revoked"])}`
          : `c:${String((ad["target"] as Dict)["kind"])}:${revocation.canonicalTarget(ad["target"] as Dict)}`;
        lines.push([key, serving.revocationLine(key, adBytes)]);
      } catch {
        // not a revocation this replica can name
      }
    }
    lines.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return utf8(lines.map(([, line]) => `${line}\n`).join(""));
  }

  /** A held stream's text digest, the form every member without `wire.ae=2` compares. */
  private textDigestOf(stream: string): Uint8Array {
    if (stream === "ads") {
      return this.adsDigest();
    }
    if (stream === "view") {
      return this.viewDigest();
    }
    if (revocation.STREAMS.includes(stream)) {
      return this.revocationDigest(stream);
    }
    return this.spaceDigest(stream.substring("space:".length));
  }

  private textDigests(streams: Iterable<string>): Dict {
    const digests: Dict = {};
    for (const stream of streams) {
      if (this.servesStream(stream)) {
        digests[stream] = this.textDigestOf(stream);
      }
    }
    return digests;
  }

  /** A stream's hash toward a partner of one kind: its trie's stream hash toward `wire.ae=2`, else its text's. */
  private streamHashOf(stream: string, trie: boolean): Uint8Array {
    if (trie) {
      const audited = this.trieForStream(stream);
      if (audited) {
        return audited.streamHash();
      }
    }
    if (stream.startsWith("space:")) {
      const text = this.textOfSpace(stream.substring("space:".length));
      text.hash ??= cryptoPort().sha256(text.bytes);
      return text.hash;
    }
    return cryptoPort().sha256(this.textDigestOf(stream));
  }

  /**
   * Whether a hash a member sent names this peer's own set of a stream, compared first in the kind expected from it
   * and then in the other, since the sender chose the kind by its view of this peer's card and the two views differ
   * until the cards spread. Equal hashes of either kind mean equal sets (annex I.6), so this is never a false match.
   */
  private sameStream(stream: string, trie: boolean, theirs: Uint8Array): boolean {
    if (equals(this.streamHashOf(stream, trie), theirs)) {
      return true;
    }
    if (trie) {
      return equals(this.streamHashOf(stream, false), theirs);
    }
    const audited = this.auditOn ? this.trieForStream(stream) : null;
    return audited !== null && audited !== undefined && equals(audited.streamHash(), theirs);
  }

  // ---- the round

  private expectPull(partner: string): void {
    this.expectedPulls.delete(partner);
    this.expectedPulls.add(partner);
    while (this.expectedPulls.size > 64) {
      this.expectedPulls.delete(this.expectedPulls.values().next().value!);
    }
  }

  /**
   * Opens a round with a member in the form its current card names (RE-T-03): the full text toward a member with
   * neither hint, as every round went before; a hash per stream toward `wire.hashes=1`; and toward `wire.ae=2` the
   * trie's stream hash for each space and the text's for every other stream (annex I.6).
   */
  private digestTo(partner: string): void {
    this.quietSince = this.now();
    this.continuations.delete(partner);
    const form = this.formToward(partner);
    const before = this.lastForm.get(partner);
    if (before !== undefined && before !== form) {
      this.formChanges += 1;
    }
    this.lastForm.set(partner, form);
    if (form === "text") {
      this.send("DIGEST", wire.digestBody(this.fullDigests()), partner);
      return;
    }
    this.expectPull(partner);
    const hashes: Dict = {};
    for (const stream of this.heldStreams()) {
      hashes[stream] = this.streamHashOf(stream, form === "ae");
    }
    if (form === "ae") {
      this.trieAudit.opening(partner);
    }
    this.pacing.hashedOpeningsSent += 1;
    this.send("DIGEST", wire.digestRecord({ hashes }), partner);
  }

  /** A body asking for full text digests: under this peer's budget toward `wire.ae=2`, as since v0.1.17 otherwise. */
  private textPull(to: string, digests: Dict): Uint8Array {
    for (const digest of Object.values(digests)) {
      this.pacing.digestTextBytesSent += (digest as Uint8Array).length;
    }
    if (!this.audits(to)) {
      return wire.digestBody(digests);
    }
    this.awaitBudgetedPull(to); // every caller sends the body at once
    return wire.digestRecord({ digests, budget: this.trieAudit.budget });
  }

  /** Notes a budgeted text pull sent to a partner, whose answer's remainder may continue it. */
  private awaitBudgetedPull(partner: string): void {
    this.budgetedPulls.delete(partner);
    this.budgetedPulls.set(partner, this.now());
    while (this.budgetedPulls.size > 64) {
      this.budgetedPulls.delete(this.budgetedPulls.keys().next().value!);
    }
  }

  /**
   * Whether a PULL_RESP from a partner answers a budgeted text pull this peer sent it, within the time a late copy is
   * taken, and forgets the pull: an answer continues the pull it answers, once.
   */
  private budgetedPullAnswered(from: string): boolean {
    const at = this.budgetedPulls.get(from);
    if (at === undefined) {
      return false;
    }
    this.budgetedPulls.delete(from);
    return this.now() - at <= LATE_COPY_MILLIS;
  }

  /**
   * The fields of a DIGEST beside a plain text pull, each handled on its own (annex I.6): `hashes` opens a round,
   * `want` asks this peer, which opened the round, for full text, `tree` carries an audit, and a budgeted text pull or
   * `ids` draw one bounded PULL_RESP. Returns true when the body is fully handled, false when its text digests are
   * answered as a 0.6.0 member answers them. A body carrying a field of annex I.6 reaches a peer with the audit off
   * only from a sender that read a stale card; it is dropped and counted, as a member without the hint drops it.
   */
  private onDigestFields(from: string, digest: Dict): boolean {
    const carriesAudit = ["tree", "ids", "budget", "sketch"].some((field) => digest[field] !== undefined);
    if (carriesAudit && !this.auditOn) {
      this.trieAudit.refuse(from, null, "lacks-hint");
      return true;
    }
    if (!this.auditOn) {
      return false; // a hashed opening or a want reaches a 0.6.0 member only from a stale read, and is ignored
    }
    // Taken before want is answered, since an in-process transport delivers that answer before this body's tree.
    const textRound = !this.audits(from) && this.expectedPulls.has(from);
    if (digest["hashes"] !== undefined) {
      this.onOpening(from, digest["hashes"] as Dict);
    }
    const want = digest["want"] as string[] | undefined;
    if (want !== undefined && want.length > 0 && this.expectedPulls.has(from)) {
      // Only the partner this peer opened a round with is answered, so a stranger cannot make it send its digests.
      this.pacing.wantsReceived += 1;
      const digests = this.textDigests(want);
      if (Object.keys(digests).length > 0) {
        this.send("DIGEST", this.textPull(from, digests), from);
      }
    }
    const tree = digest["tree"] as { [stream: string]: Dict[] } | undefined;
    if (tree !== undefined && Object.keys(tree).length > 0) {
      const budget = digest["budget"] === undefined ? null : Number(digest["budget"]);
      const fallback = this.trieAudit.onTree(from, tree as unknown as { [stream: string]: TreeNode[] }, budget,
        textRound);
      if (fallback.length > 0) {
        // A stream this peer keeps no trie for came back as a root: pulled by the text form, as a want would.
        const digests = this.textDigests(fallback);
        if (Object.keys(digests).length > 0) {
          this.expectPull(from);
          this.send("DIGEST", this.textPull(from, digests), from);
        }
      }
    }
    // sketch is reserved (annex I.6, RE-F-01): never sent, and ignored when received.
    if (digest["digests"] === null && digest["ids"] === undefined) {
      return true;
    }
    if (digest["budget"] === undefined && digest["ids"] === undefined) {
      return false;
    }
    this.answerPull(from, digest);
    return true;
  }

  /**
   * The opening of a hashed round, as the partner: the streams both hold whose hashes differ. A space this peer audits
   * with the asker is compared by its trie and answered with its root, a session permitting; any other stream by its
   * text digest and named in `want`. Both go in one body; nothing goes when nothing differs.
   */
  private onOpening(from: string, theirs: Dict): void {
    this.pacing.hashedOpeningsReceived += 1;
    const trie = this.audits(from);
    const want: string[] = [];
    const differs: string[] = [];
    const equal: string[] = [];
    for (const stream of Object.keys(theirs).sort()) {
      const hash = theirs[stream];
      if (!(hash instanceof Uint8Array) || !this.servesStream(stream)) {
        continue;
      }
      const audited = trie && stream.startsWith("space:");
      if (!this.sameStream(stream, audited, hash)) {
        (audited ? differs : want).push(stream);
      } else if (audited) {
        equal.push(stream);
      }
    }
    const roots = differs.length === 0 && equal.length === 0 ? {} : this.trieAudit.roots(from, differs, equal);
    const rooted = Object.keys(roots).length > 0;
    if (want.length === 0 && !rooted) {
      return;
    }
    if (want.length > 0) {
      this.pacing.wantsSent += 1;
    }
    this.sendAddressed("DIGEST", wire.digestRecord({ want: want.length > 0 ? want : null,
      tree: rooted ? roots as unknown as { [stream: string]: Dict[] } : null }), from);
  }

  /**
   * The PULL_RESP a body's text digests and `ids` draw, in one answer (annex I.6). Without a budget every delta goes
   * whole; with one the answer is cut to the smaller of the asker's budget and this peer's cap, the streams in the
   * order a Java member registers them (the revocations before the spaces whose records they judge), each space's
   * states in the annex's order, the first item always carried, and `remainder` counting per stream what was held and
   * left out. A budgeted fetch is always answered, even with nothing held, so the asker learns at once to ask another.
   */
  private answerPull(from: string, digest: Dict): void {
    const asked = digest["budget"] === undefined ? null : Number(digest["budget"]);
    const cap = asked === null ? Number.POSITIVE_INFINITY : Math.min(asked, BUDGET_CEILING);
    const texts = (digest["digests"] ?? {}) as { [stream: string]: Uint8Array };
    const ids = (digest["ids"] ?? {}) as { [stream: string]: string[] };
    const deltas: Dict = {};
    const remainder: { [stream: string]: number } | null = asked === null ? null : {};
    let used = 32;
    const named = new Set([...Object.keys(texts), ...Object.keys(ids)]);
    const order = [...revocation.STREAMS, "view", "ads"].filter((stream) => named.has(stream));
    order.push(...[...named].filter((stream) => !order.includes(stream)).sort());
    for (const stream of order) {
      const text = texts[stream];
      const wanted = ids[stream];
      const space = stream.startsWith("space:") ? stream.substring("space:".length) : null;
      const fetch = wanted !== undefined && wanted.length > 0 && space !== null && this.servesStream(stream);
      if (!this.servesStream(stream) || (text === undefined && !fetch)) {
        if (remainder !== null && wanted !== undefined) {
          remainder[stream] = 0; // nothing of it held here: the asker asks the next member at once
        }
        continue;
      }
      const overhead = 2 * (utf8(stream).length + 9) + 9;
      let delta: Uint8Array;
      let left = 0;
      if (space === null) {
        delta = stream === "ads" ? this.adsDeltaFor(text!) : stream === "view" ? this.viewDeltaFor(text!)
          : this.revocationDeltaFor(stream, text!);
      } else {
        const answer = this.boundedSpaceDelta(space, text ?? null, text === undefined ? wanted! : null,
          cap - used - overhead, Object.keys(deltas).length === 0);
        delta = answer.delta;
        left = answer.left;
      }
      if (remainder !== null) {
        remainder[stream] = left;
        this.pacing.remainderSent += left;
      }
      if (delta.length > 0) {
        deltas[stream] = delta;
        used += delta.length + overhead;
      }
      if (text === undefined) {
        this.trieAudit.fetchAnswered();
      }
    }
    if (Object.keys(deltas).length === 0 && !(Object.keys(ids).length > 0 && asked !== null)) {
      return;
    }
    this.pullsAnswered += 1;
    this.pacing.pullRespSent += 1;
    if (asked !== null) {
      this.pacing.budgetedAnswers += 1;
    }
    this.sendAddressed("PULL_RESP", wire.pullRespBody(deltas, remainder), from); // through the seed, as answerTextPull
  }

  /**
   * One space's answer under a budget (annex I.6, *The fetch* and *The budget*; RE-I-06): for a text digest, every
   * state and claim it does not name; for ids, the state and claim of each named entry held. A state and its claim are
   * one item; present states go before tombstones, and claims alone last, so a budget that splits a replacement sends
   * the new revision first; within each group newest first by lease stamp, ties by id. The first item always goes.
   */
  private boundedSpaceDelta(space: string, text: Uint8Array | null, ids: string[] | null, budget: number,
                            first: boolean): { delta: Uint8Array; left: number } {
    const spaceId = wireSpaceId(this.group, space);
    const remote = text === null ? null : serving.parseDigestLines(text);
    type Offer = { id: string; state: Dict | null; claim: Dict | null; rank: number; stamp: CborValue | null };
    const offers: Offer[] = [];
    const consider = (id: string): void => {
      const dto = this.states.get(id);
      const state = dto !== undefined && (dto["record"] as Dict | undefined)?.["spaceId"] === spaceId ? dto : undefined;
      const held = this.claims.get(id);
      const claim = held !== undefined && (held["claim"] as Dict)["spaceId"] === spaceId ? held : undefined;
      let sendState = state;
      let sendClaim = claim;
      if (remote !== null) {
        const stateLine = state === undefined ? null : `e:${id}=${this.stateHashOf(state)}`;
        if (stateLine !== null && (remote.has(stateLine) || remote.has(`a:${stateLine}`))) {
          sendState = undefined;
        }
        const claimLine = claim === undefined ? null : `c:${id}=${serving.claimHash(claim["claim"] as Dict)}`;
        if (claimLine !== null && (remote.has(claimLine) || remote.has(`a:${claimLine}`))) {
          sendClaim = undefined;
        }
      }
      if (sendState === undefined && sendClaim === undefined) {
        return;
      }
      offers.push({ id, state: sendState === undefined ? null : this.signedStateOf(id, sendState), claim: sendClaim ?? null,
        rank: sendState === undefined ? 2 : present(sendState) ? 0 : 1,
        stamp: sendState !== undefined ? sendState["leaseStamp"] : (sendClaim!["claim"] as Dict)["stamp"] });
    };
    if (ids !== null) {
      for (const id of ids) {
        consider(id);
      }
    } else {
      for (const id of this.idsOfSpace(spaceId)) {
        consider(id);
      }
    }
    offers.sort((a, b) => a.rank - b.rank || wire.compareHlc(b.stamp, a.stamp)
      || compareBytes(utf8(a.id), utf8(b.id)));
    const states: Dict[] = [];
    const claims: Dict = {};
    let used = 32;
    let taken = 0;
    for (const offer of offers) {
      let size = offer.state === null ? 0 : dumps(offer.state).length;
      if (offer.claim !== null) {
        size += dumps(offer.claim).length + utf8(offer.id).length + 9;
      }
      if (used + size > budget && !(first && taken === 0)) {
        break;
      }
      used += size;
      taken += 1;
      if (offer.state !== null) {
        states.push(offer.state);
      }
      if (offer.claim !== null) {
        claims[offer.id] = offer.claim;
      }
    }
    const left = offers.length - taken;
    if (taken === 0) {
      return { delta: new Uint8Array(), left };
    }
    return { delta: dumps({ states, claims: canonicalMap(claims) }), left };
  }

  /** The stream of a fetch a PULL_RESP answers, if any; the partner's round is answered either way. */
  private pullRespArrived(from: string, resp: Dict): string | null {
    const named = new Set([...Object.keys((resp["deltas"] ?? {}) as Dict), ...Object.keys((resp["remainder"] ?? {}) as Dict)]);
    const fetchStream = this.auditOn ? this.trieAudit.fetchAnswer(from, named) : null;
    this.expectedPulls.delete(from);
    for (const left of Object.values((resp["remainder"] ?? {}) as Dict)) {
      this.pacing.remainderReceived += Number(left);
    }
    return fetchStream;
  }

  /**
   * After a PULL_RESP folded: a fetch's answer settles the body it answers, by what it carried, and asks again for
   * what it left out; a budgeted text pull that came back with a remainder continues at once.
   */
  private pullRespSettled(from: string, resp: Dict, fetchStream: string | null, received: Set<string>,
                          awaited: boolean): void {
    if (fetchStream !== null) {
      const batch = this.trieAudit.settle(from, fetchStream, received);
      if (batch !== null) {
        const left = ((resp["remainder"] ?? {}) as Dict)[fetchStream];
        this.trieAudit.fetched(from, batch, received, left === undefined ? 0 : Number(left));
      }
    } else if (resp["remainder"] !== undefined) {
      if (!awaited) {
        // A remainder answers a budgeted pull, and this peer sent none to the member: without this check any member
        // could send a few bytes naming a remainder and draw this peer's full text digests, up to 64 times per round
        // (adversarial review of 2026-11-15). Java drops an unsolicited PULL_RESP whole (ASF-003).
        this.pacing.remainderUnsolicited += 1;
        return;
      }
      this.continuePull(from, resp["remainder"] as Dict);
    }
  }

  /**
   * A budgeted text pull came back with a remainder: continue it now rather than a round later (RE-Q-PRF-03), with
   * this peer's own text digest under the same budget, which now names what the answer brought; a space this peer
   * audits with the partner continues by an audit instead, whose fetch is bounded per body. At most
   * {@link PULL_CONTINUATIONS_MAX} per partner per round; the next round carries on.
   */
  private continuePull(from: string, remainder: Dict): void {
    const text: string[] = [];
    let reopen = false;
    for (const [stream, left] of Object.entries(remainder)) {
      if (!this.servesStream(stream) || Number(left) <= 0) {
        continue;
      }
      if (this.audits(from) && stream.startsWith("space:")) {
        reopen = true;
      } else {
        text.push(stream);
      }
    }
    if (text.length === 0 && !reopen) {
      return;
    }
    const sofar = (this.continuations.get(from) ?? 0) + 1;
    this.continuations.set(from, sofar);
    if (sofar > PULL_CONTINUATIONS_MAX) {
      return;
    }
    this.pacing.pullContinued += 1;
    if (text.length > 0) {
      this.expectPull(from);
      this.send("DIGEST", this.textPull(from, this.textDigests(text)), from);
    }
    if (reopen) {
      this.digestTo(from); // an audit opening, which resets the count, so it is kept
      this.continuations.set(from, sofar);
    }
  }

  // ---- probes (SPEC §5.2)

  /** The hashes a probe's answer carries toward a member of one kind: one per stream, or their root past the bound. */
  private probeDigests(trie: boolean): { root: Uint8Array | null; hashes: Dict | null } {
    const streams = this.heldStreams();
    if (streams.length > PROBE_HASH_STREAMS) {
      return { root: this.rootDigest(trie), hashes: null };
    }
    const hashes: Dict = {};
    for (const stream of streams) {
      hashes[stream] = this.streamHashOf(stream, trie);
    }
    return { root: null, hashes };
  }

  /** SHA-256 over each stream id in Java's String order, a zero byte, its hash, and a zero byte (annex I.6). */
  private rootDigest(trie: boolean): Uint8Array {
    const parts: Uint8Array[] = [];
    for (const stream of this.heldStreams().sort()) {
      parts.push(utf8(stream), new Uint8Array(1), this.streamHashOf(stream, trie), new Uint8Array(1));
    }
    let size = 0;
    for (const part of parts) {
      size += part.length;
    }
    const all = new Uint8Array(size);
    let at = 0;
    for (const part of parts) {
      all.set(part, at);
      at += part.length;
    }
    return cryptoPort().sha256(all);
  }

  /**
   * A probe that carried hashes or a root (SPEC §5.2): answered with hashes of the kind the pinger reads, and when they
   * differ from this peer's on a stream both hold, a targeted round with the pinger, at most once per round per member,
   * so a persistent difference costs one round per period and no more. An absent value is no information.
   */
  private onProbeHashes(from: string, ping: Dict,
                        answer: (body: Uint8Array) => void = (body) => this.send("ACK", body, from)): void {
    const trie = this.audits(from);
    const hashes = ping["hashes"] as Dict | undefined;
    let mismatch = false;
    if (hashes !== undefined) {
      for (const [stream, hash] of Object.entries(hashes)) {
        if (hash instanceof Uint8Array && this.servesStream(stream) && !this.sameStream(stream, trie, hash)) {
          mismatch = true;
          break;
        }
      }
    } else if (ping["root"] instanceof Uint8Array) {
      const root = ping["root"];
      mismatch = !equals(this.rootDigest(trie), root) && !equals(this.rootDigest(!trie), root);
    }
    const probe = this.probeDigests(trie);
    answer(wire.probeBody("ACK", ping["nonce"] as number | bigint, probe.root, probe.hashes));
    const now = this.now();
    // As Java's node, a probe opens a round only while this peer's own rounds have backed off: a peer that reconciles
    // at its usual pace repairs the difference there, and a probe's round would only double it (SPEC §5.2).
    if (this.quietSince === null) {
      this.quietSince = now;
    }
    if (!mismatch || now - this.quietSince < PROBE_QUIET_ROUNDS * this.roundMillis()) {
      return;
    }
    const last = this.probePulls.get(from);
    if (last !== undefined && now - last < this.roundMillis()) {
      return;
    }
    this.probePulls.set(from, now);
    this.pacing.probeRounds += 1;
    this.digestTo(from);
  }

  // ---- the audited sets

  private stateHashOf(dto: Dict): string {
    let hash = this.stateHashes.get(dto);
    if (hash === undefined) {
      hash = serving.stateHash(dto);
      this.stateHashes.set(dto, hash);
    }
    return hash;
  }

  /** What one entry id holds now: its state and claim lines unless its lease lapsed, and its acknowledged lines. */
  private holdingOf(id: string, now: number): Holding {
    const state = this.states.get(id);
    const signed = this.claims.get(id);
    const claim = signed?.["claim"] as Dict | undefined;
    const acks = this.ackIndex.get(id);
    let spaceId: string | null = null;
    const recordSpace = (state?.["record"] as Dict | undefined)?.["spaceId"];
    if (typeof recordSpace === "string") {
      spaceId = recordSpace;
    } else if (typeof claim?.["spaceId"] === "string") {
      spaceId = claim["spaceId"] as string;
    } else if (acks !== undefined && acks.size > 0) {
      spaceId = this.refusedAck.get(acks.values().next().value!) ?? null;
    }
    const live = state !== undefined && present(state);
    const expiry = state === undefined ? 0 : leaseExpiryOf(state);
    const lapsed = live && expiry <= now;
    return {
      spaceId,
      state: state === undefined ? null : this.stateHashOf(state),
      claim: claim === undefined ? null : serving.claimHash(claim),
      lapsed,
      acks: acks ?? [],
      liveUntil: live && !lapsed ? expiry : null,
    };
  }

  /** Every id with a state, a claim or an acknowledged line in a space. */
  private idsOfSpace(spaceId: string): Set<string> {
    const ids = new Set<string>();
    for (const [id, dto] of this.states) {
      if ((dto["record"] as Dict | undefined)?.["spaceId"] === spaceId) {
        ids.add(id);
      }
    }
    for (const [id, signed] of this.claims) {
      if ((signed["claim"] as Dict | undefined)?.["spaceId"] === spaceId) {
        ids.add(id);
      }
    }
    for (const [line, lineSpace] of this.refusedAck) {
      const id = entryIdOf(line);
      if (lineSpace === spaceId && id !== null) {
        ids.add(id);
      }
    }
    return ids;
  }

  // ---- acknowledgements (annex I.6, *The audited set*; SPEC §7.3, RE-H-03)

  private ackChanged(line: string, before: string | undefined, after: string | undefined): void {
    const id = entryIdOf(line);
    if (before !== undefined) {
      this.ackCounts.set(before, (this.ackCounts.get(before) ?? 1) - 1);
      if (id !== null) {
        const lines = this.ackIndex.get(id);
        lines?.delete(line);
        if (lines?.size === 0) {
          this.ackIndex.delete(id);
        }
      }
    }
    if (after !== undefined) {
      this.ackCounts.set(after, (this.ackCounts.get(after) ?? 0) + 1);
      if (id !== null) {
        let lines = this.ackIndex.get(id);
        if (lines === undefined) {
          lines = new Set();
          this.ackIndex.set(id, lines);
        }
        lines.add(line);
      }
    } else {
      this.ackForgetAt.delete(line);
    }
    if (id !== null) {
      this.audited.touched(id);
    }
  }

  /**
   * Acknowledges a re-offered state the door refused as past its collection horizon, when this replica holds no state
   * of the entry: without it a member that keeps tombstones longer offers the state every round until it collects it
   * too. The line shares R7's bound and is forgotten five minutes after the last refusal, so it cannot keep this
   * replica's digest apart once the offerer collects; a member still holding the state earns it again. Only a state
   * whose signatures verified reaches here.
   */
  private acknowledgeCollected(dto: Dict, record: Dict): void {
    const entryId = String(record["entryId"]);
    if (this.states.has(entryId)) {
      return; // still held: its own sweep collects it
    }
    const line = `e:${entryId}=${this.stateHashOf(dto)}`;
    const added = !this.refusedAck.has(line);
    this.acknowledgeLine(line, String(record["spaceId"]));
    this.ackForgetAt.set(line, this.now() + COLLECTED_ACK_HOLD_MILLIS);
    this.collectBy(this.ackForgetAt.get(line)!);
    if (added) {
      this.collectedReoffersAcknowledged += 1;
    }
  }

  /** Schedules an acknowledgement to be forgotten at `at`, and never sooner than the hold from now. */
  private forgetRefusedAfter(line: string, at: number): void {
    if (this.refusedAck.has(line)) {
      this.ackForgetAt.set(line, Math.max(at, this.now() + COLLECTED_ACK_HOLD_MILLIS));

      this.collectBy(this.ackForgetAt.get(line)!);
    }
  }

  private forgetAcknowledgements(now: number): void {
    for (const [line, at] of [...this.ackForgetAt]) {
      if (at <= now) {
        this.refusedAck.delete(line);
      }
    }
  }

  // ---- the per-entry horizon (SPEC §7.3, RE-H-04)

  /** One round of the group: the verified founding's gossip period when this peer joined by one, else the setting. */
  private roundMillis(): number {
    const period = ((this.founding?.["advertisement"] as Dict | undefined)?.["gossip"] as Dict | undefined)?.["period"];
    if (typeof period === "string") {
      try {
        return Math.max(1, parseDurationMillis(period));
      } catch {
        // an unreadable period: the setting stands
      }
    }
    return this.gossipPeriodMillis;
  }

  /** Whether this peer advertises the horizon hint and every member of its view does too. */
  private viewHinted(now: number): boolean {
    if (this.hinted.at === now) {
      return this.hinted.value;
    }
    let value = this.horizonOn;
    if (value) {
      for (const member of this.members.keys()) {
        if (!this.horizonPeers.has(member)) {
          value = false; // a member whose card this peer has not received counts as lacking the hint
          break;
        }
      }
    }
    this.hinted = { at: now, value };
    return value;
  }

  /** The rule the view allows in a space now, moving its mode (the view's half). */
  private horizonRule(spaceId: string, now: number, maxLeaseMillis: number): horizon.Rule {
    let mode = this.horizonModes.get(spaceId);
    if (mode === undefined) {
      mode = new horizon.HorizonMode();
      this.horizonModes.set(spaceId, mode);
    }
    return mode.judge(now, this.viewHinted(now), this.roundMillis(), maxLeaseMillis);
  }

  /** Judges the mode of every space this peer joined, once per sweep, so the hysteresis counts rounds as they pass. */
  private judgeHorizons(now: number): void {
    for (const space of this.joinedSpaces) {
      const spaceId = wireSpaceId(this.group, space);
      this.horizonRule(spaceId, now, this.longestLease.get(spaceId) ?? 0);
    }
  }

  /**
   * The writer's half: this replica vouches for a withdrawal only when every node that wrote it (each add dot's
   * replica) is this one, or a member of the view whose current card carries the hint and whose stay has lasted one
   * maximum lease plus the grace, so whatever it renewed out of sight before has lapsed and passed its lapse horizon.
   */
  private vouchesFor(dto: Dict, now: number, maxLeaseMillis: number): boolean {
    const adds = (dto["adds"] as Dict[] | undefined) ?? [];
    if (adds.length === 0) {
      return false;
    }
    const settle = Math.max(0, maxLeaseMillis) + horizon.LAPSED_GRACE_MILLIS;
    for (const dot of adds) {
      const writer = String(dot["replica"] ?? "");
      if (writer === this.identity.peerId) {
        continue;
      }
      const since = this.hintedSince.get(writer);
      if (since === undefined || !this.members.has(writer) || since + settle > now) {
        return false;
      }
    }
    return true;
  }

  /**
   * Whether this replica collects a state now: by its kind's horizon under the rule the view allows, except that a
   * withdrawal this replica cannot vouch for keeps the later of the legacy horizon and the per-entry one, so a writer
   * leaving the view never brings a horizon closer. The sweep and the door both read this.
   */
  private collectableHere(dto: Dict, now: number): boolean {
    const kind = horizonKindOf(dto);
    const expiry = leaseExpiryOf(dto);
    const maxLease = this.longestLeaseOf(dto);
    if (kind !== "withdrawn") {
      return horizon.collectableAt(kind, expiry, now, maxLease, "legacy"); // the same under both rules
    }
    const spaceId = String((dto["record"] as Dict | undefined)?.["spaceId"]);
    const mode = this.horizonRule(spaceId, now, maxLease);
    const rule = mode === "per-entry" && !this.vouchesFor(dto, now, maxLease) ? "legacy" : mode;
    const byRule = horizon.collectableAt(kind, expiry, now, maxLease, rule);
    if (mode === "per-entry" && rule === "legacy") {
      return byRule && horizon.collectableAt(kind, expiry, now, maxLease, "per-entry");
    }
    return byRule;
  }

  // ---- the signed copy of a joined state

  /** States this replica joined from two signed inputs, neither of which equals the join. */
  private readonly joinedStates = new WeakSet<Dict>();
  /** For such a join, the most advanced signed input, which anti-entropy forwards verbatim as Java's signedStates. */
  private readonly signedStates = new Map<string, Dict>();

  /**
   * Stores the join of a held state and an incoming one (ASF-017). A join equal to one input is stored as that input,
   * whose signature covers it; one equal to neither (a renewal and a completion that crossed) is stored for this
   * replica's judgements and digest, and the most advanced signed input is kept beside it to be forwarded, since the
   * join's own fields carry no signature anyone made. Before this, the join kept the held state's signature over the
   * incoming state's removes, and every member it was forwarded to refused it.
   */
  private storeJoined(entryId: string, previous: Dict | undefined, dto: Dict): void {
    if (previous === undefined) {
      this.states.set(entryId, dto);
      return;
    }
    const merged = joinStates(previous, dto);
    if (sameStateContent(merged, dto)) {
      this.states.set(entryId, dto);
      return;
    }
    if (sameStateContent(merged, previous)) {
      return; // nothing new: the held state already covers the incoming one
    }
    const held = this.signedStateOf(entryId, previous);
    this.joinedStates.add(merged);
    this.states.set(entryId, merged);
    this.signedStates.set(entryId, advancesState(dto, held) ? dto : held);
  }

  /** The signed state to forward for an entry: the held state itself, or a join's most advanced signed input. */
  private signedStateOf(entryId: string, dto: Dict): Dict {
    return this.joinedStates.has(dto) ? (this.signedStates.get(entryId) ?? dto) : dto;
  }
}

/** An empty digest for each revocation stream (SPEC §5.6). */
function revocationDigests(): Dict {
  return Object.fromEntries(revocation.STREAMS.map((stream) => [stream, new Uint8Array()]));
}

/** The value of an entry's payload, or null when it is not here yet or unreadable ({@link readDocument}). */
function applicationValue(raw: Uint8Array | null): { value: Dict } | null {
  return raw === null ? null : readDocument(raw) as { value: Dict } | null;
}

/** Whether a decoded item is a map, the shape of a delta, a state, and a claim. */
function isDict(value: unknown): value is Dict {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && !(value instanceof Uint8Array) && !(value instanceof CborDouble);
}

/**
 * The state view a state signature covers (SPEC §11a.4): the one verifyState checks, and the signed
 * content a refusal is keyed on (HLC round four, 2026-11-08, D5).
 */
function stateViewOf(dto: Dict, record: Dict): Dict {
  const signer = dto["signer"] ?? null;
  const signedAt = dto["signedAt"] ?? null;
  return wire.stateSignView(String(record["spaceId"]), String(record["entryId"]), (dto["adds"] as Dict[]) ?? [],
    (dto["removes"] as Dict[]) ?? [], wire.leaseStampOf(dto), dto["leaseValue"] as Dict,
    Boolean(dto["completed"]), signer === null ? null : String(signer), signedAt === null ? null : String(signedAt));
}

/**
 * The key a state offer is judged under, its signed content alone (HLC round four, 2026-11-08, D5),
 * as Java's: the entry, the issue stamp, and the SHA-256 of the signed state view.
 */
function stateOfferKey(dto: Dict, record: Dict): string {
  return `state:${String(record["entryId"])}=${String(record["issued"])}/${toHex(cryptoPort().sha256(dumps(stateViewOf(dto, record))))}`;
}

/**
 * The key a claim offer is judged under, as Java's: the SHA-256 of its canonical TakeClaim encoding,
 * the bytes its signature covers whatever order the map arrived in (HLC round five, 2026-11-08,
 * E13), and its entry.
 */
function claimOfferKey(entryId: string, claim: Dict): string {
  return `claim:${toHex(cryptoPort().sha256(dumps(wire.canonicalClaim(claim) ?? claim)))}@${entryId}`;
}

/** The state join (ASF-017), exported so the conformance suite can prove it. */
/**
 * Fills `entryId` of a recordless state from the rumor item id (`r:<id>:<stamp>`, `d:<id>`,
 * `x:<id>:<stamp>`, `c:<id>:<stamp>`) when the DTO does not carry one (PD-L-02).
 */
export function nameRecordless(state: Dict, itemId: unknown): void {
  if ((state["record"] !== null && state["record"] !== undefined) || state["entryId"] || typeof itemId !== "string") {
    return;
  }
  const parts = itemId.split(":");
  if (parts.length >= 2 && ["r", "d", "x", "c"].includes(parts[0]) && parts[1].length > 0) {
    state["entryId"] = parts[1];
  }
}

/**
 * When the entry of `dto` lapses: its lease register, which a renewal moves, else its record's first
 * lease (HLC round five, 2026-11-08: every read, take, and sweep judges the renewed lease).
 */
export function leaseExpiryOf(dto: Dict): number {
  const lease = (dto["leaseValue"] ?? (dto["record"] as Dict | undefined)?.["lease"]) as Dict | undefined;
  return Number(lease?.["expiresAtMillis"] ?? 0);
}

/**
 * Whether the entry of `dto` is present (Java's EntryState.present, HLC round five, 2026-11-08):
 * uncompleted, with an add dot no remove covers.
 */
export function present(dto: Dict): boolean {
  if (dto["completed"]) {
    return false;
  }
  const adds = (dto["adds"] as Dict[] | undefined) ?? [];
  const removes = (dto["removes"] as Dict[] | undefined) ?? [];
  if (removes.length === 0) {
    return adds.length > 0; // the common case, judged on every sweep without a set
  }
  const removed = new Set(removes.map(dotKey));
  return adds.some((dot) => !removed.has(dotKey(dot)));
}

/**
 * Whether `dto` lies past its collection horizon (SPEC §7.3, Java's SpaceStateCrdt.collectable, HLC
 * round five, 2026-11-08): the entry is no longer live, and its lease expired LAPSED_GRACE_MILLIS ago
 * (at most twice the longest lease) for a lapse, or twice the longest lease ago for a completion or a
 * withdrawal.
 */
export function collectable(dto: Dict, nowMillis: number, longestLeaseMillis: number,
                            rule: horizon.Rule = "legacy"): boolean {
  // SPEC §7.3 (v0.1.35): a withdrawn entry keeps the drift floor under either rule (decision 22), and under the
  // per-entry rule of wire.horizon=1 its own five minutes past its expiry rather than two maximum leases.
  return horizon.collectableAt(horizonKindOf(dto), leaseExpiryOf(dto), nowMillis, longestLeaseMillis, rule);
}

/**
 * What an entry is for its horizon (SPEC §7.3): present (live or lapsed), completed, withdrawn, or both withdrawn and
 * completed, which keeps the drift floor as a withdrawal does.
 */
export function horizonKindOf(dto: Dict): horizon.HorizonKind {
  if (dto["completed"]) {
    const adds = (dto["adds"] as Dict[] | undefined) ?? [];
    const removed = new Set(((dto["removes"] as Dict[] | undefined) ?? []).map(dotKey));
    return adds.every((dot) => removed.has(dotKey(dot))) ? "withdrawn_completed" : "completed";
  }
  return present(dto) ? "present" : "withdrawn";
}

/**
 * Whether every dot in a state's adds and removes names the record issuer's peer as its replica (ASF-025,
 * Java's ReplicatedSpace.dotsBoundToIssuer). The issuer is an AgentId, `<peerId>/<localName>` (R5).
 */
function dotsBoundToIssuer(dto: Dict, record: Dict): boolean {
  const issuer = String(record["issuer"]);
  const peer = issuer.substring(0, issuer.indexOf("/"));
  const dots = [...((dto["adds"] as Dict[] | undefined) ?? []), ...((dto["removes"] as Dict[] | undefined) ?? [])];
  return dots.every((dot) => dot["replica"] === peer);
}

/** The identity of a dot, its replica and counter, as unionDots keys it. */
function dotKey(dot: unknown): string {
  const d = (dot ?? {}) as Dict;
  return `${String(d["replica"] ?? "")}\u0000${Number(d["counter"] ?? 0)}`;
}

export function joinStates(previous: Dict, incoming: Dict): Dict {
  const merged: Dict = { ...previous };
  merged["adds"] = unionDots(previous["adds"], incoming["adds"]);
  merged["removes"] = unionDots(previous["removes"], incoming["removes"]);
  // compareHlc sorts a refused or missing stamp first; the folds hand this join parsed stamps only.
  if (wire.compareHlc(incoming["leaseStamp"], previous["leaseStamp"]) > 0) {
    merged["leaseStamp"] = incoming["leaseStamp"];
    merged["leaseValue"] = incoming["leaseValue"];
  }
  merged["completed"] = Boolean(previous["completed"]) || Boolean(incoming["completed"]);
  return merged;
}

/** Whether two states carry the same CRDT fields: dot sets, lease register, and completion. */
function sameStateContent(a: Dict, b: Dict): boolean {
  const dots = (x: unknown): string => (Array.isArray(x) ? x.map(dotKey).sort().join("|") : "");
  return dots(a["adds"]) === dots(b["adds"]) && dots(a["removes"]) === dots(b["removes"])
    && String(a["leaseStamp"]) === String(b["leaseStamp"]) && Boolean(a["completed"]) === Boolean(b["completed"]);
}

/** Java's ReplicatedSpace.advances: completion dominates, then more removes, a newer lease stamp, more adds. */
function advancesState(a: Dict, b: Dict): boolean {
  if (Boolean(a["completed"]) !== Boolean(b["completed"])) {
    return Boolean(a["completed"]);
  }
  const removes = (x: Dict): number => ((x["removes"] as unknown[] | undefined) ?? []).length;
  if (removes(a) !== removes(b)) {
    return removes(a) > removes(b);
  }
  const stamp = wire.compareHlc(a["leaseStamp"], b["leaseStamp"]);
  if (stamp !== 0) {
    return stamp > 0;
  }
  return ((a["adds"] as unknown[] | undefined) ?? []).length >= ((b["adds"] as unknown[] | undefined) ?? []).length;
}

/** The union of two dot lists, deduplicated by (replica, counter) and
 * deterministically ordered like the Java side's sorted dots. */
function unionDots(a: unknown, b: unknown): Dict[] {
  const seen = new Map<string, Dict>();
  for (const dot of [...(Array.isArray(a) ? a : []), ...(Array.isArray(b) ? b : [])]) {
    if (dot !== null && typeof dot === "object") {
      const d = dot as Dict;
      seen.set(dotKey(d), d);
    }
  }
  return [...seen.entries()]
      .sort(([ka], [kb]) => (ka < kb ? -1 : ka > kb ? 1 : 0))
      .map(([, dot]) => dot);
}

/** Drops stamps older than a minute from a window and returns what remains. */
function pruneMinute(times: number[], now: number): number {
  let drop = 0;
  while (drop < times.length && now - times[drop] >= 60_000) {
    drop += 1;
  }
  if (drop > 0) {
    times.splice(0, drop);
  }
  return times.length;
}
