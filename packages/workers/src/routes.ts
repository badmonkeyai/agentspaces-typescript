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
 * Route helpers for a Worker that the Java celld connector serves from beside
 * the deployment (srad/celld-phase2.md group W): a ranged object route over
 * R2, a change log in a Durable Object's SQLite with its cursor route and its
 * Server-Sent Events stream, and routes that receive an artifact the
 * connector sends, whole or piece by piece. Each helper speaks plain HTTP
 * (RFC 9110 ranges and conditions, the WHATWG event-stream format) and runs
 * the same on celld, workerd, and Cloudflare.
 */

import type { SqlStorageLike, SqlValue } from "./workers-types.js";

/** The header carrying the invocation id. */
export const INVOCATION_HEADER = "Aspace-Invocation-Id";
/** The header carrying an artifact body's content root. */
export const ROOT_HEADER = "Aspace-Content-Root";
/** The header naming a chunked upload's step: `piece` or `finish`. */
export const UPLOAD_HEADER = "Aspace-Upload";
/** The header carrying a chunked upload's piece index. */
export const PIECE_INDEX_HEADER = "Aspace-Piece-Index";
/** The header carrying a chunked upload's piece count. */
export const PIECE_COUNT_HEADER = "Aspace-Piece-Count";

/** The R2 object fields the range route reads. */
export interface RangeObject {
  readonly size: number;
  readonly httpEtag: string;
  readonly body?: ReadableStream<Uint8Array> | null;
  writeHttpMetadata?(headers: Headers): void;
}

/** The R2 bucket calls the range route makes. */
export interface RangeBucket {
  head(key: string): Promise<RangeObject | null>;
  get(key: string, options?: { range?: { offset: number; length: number }; onlyIf?: { etagMatches?: string } }):
    Promise<RangeObject | null>;
}

const RANGE = /^bytes=(\d+)-(\d+)?$/;

/**
 * Answers a ranged read of one object (CC-W-01): 206 with `Content-Range` and
 * `ETag` for `Range: bytes=a-b`, 412 when `If-Match` names another version,
 * 416 for a range past the end, 404 for an absent key, 200 with the whole
 * body when the request names no range.
 */
export async function serveRange(bucket: RangeBucket, request: Request, key: string): Promise<Response> {
  const ifMatch = request.headers.get("If-Match") ?? undefined;
  // R2's etagMatches takes the bare ETag; the header carries the quoted httpEtag.
  const bare = ifMatch?.replace(/^W\//, "").replace(/^"(.*)"$/, "$1");
  const range = request.headers.get("Range");
  const head = await bucket.head(key);
  if (head === null) {
    return new Response("not found", { status: 404 });
  }
  if (ifMatch !== undefined && ifMatch !== head.httpEtag) {
    return new Response(null, { status: 412, headers: { "ETag": head.httpEtag } });
  }
  const headers = new Headers({ "ETag": head.httpEtag, "Accept-Ranges": "bytes" });
  if (range === null) {
    const whole = await bucket.get(key, bare ? { onlyIf: { etagMatches: bare } } : undefined);
    if (whole === null || !whole.body) {
      return new Response(null, { status: 412 });
    }
    whole.writeHttpMetadata?.(headers);
    return new Response(whole.body, { status: 200, headers });
  }
  const m = RANGE.exec(range.trim());
  if (!m) {
    return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${head.size}` } });
  }
  const offset = Number(m[1]);
  const last = m[2] === undefined ? head.size - 1 : Math.min(Number(m[2]), head.size - 1);
  if (offset >= head.size || last < offset) {
    return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${head.size}` } });
  }
  const part = await bucket.get(key, {
    range: { offset, length: last - offset + 1 },
    ...(bare ? { onlyIf: { etagMatches: bare } } : {}),
  });
  if (part === null || !part.body) {
    return new Response(null, { status: 412 }); // the object changed between the head and the get
  }
  part.writeHttpMetadata?.(headers);
  headers.set("Content-Range", `bytes ${offset}-${last}/${head.size}`);
  return new Response(part.body, { status: 206, headers });
}

/** One change, as the connector's change route reads it. */
export type Change =
  | { kind: "upsert" | "delete"; route: string; key: string; row?: Record<string, string> }
  | { kind: "object"; object: string; key: string };

/** One answer of the change route. */
export type ChangePage = { cursor: string; changes: Change[] };

/**
 * A change log in a Durable Object's SQLite (CC-W-02): `record` appends a
 * change in the same storage the write it describes used, and `after`
 * answers the change route: the changes after a cursor, in order, and the
 * cursor after the last one. The cursor is the log's sequence number as text.
 */
export class ChangeLog {
  private prepared = false;

  constructor(private readonly sql: SqlStorageLike, private readonly table = "aspace_changes") {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) {
      throw new Error(`table name ${table} is not a SQL identifier`);
    }
  }

  private prepare(): void {
    if (!this.prepared) {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS ${this.table} (seq INTEGER PRIMARY KEY AUTOINCREMENT,`
        + " kind TEXT NOT NULL, name TEXT NOT NULL, key TEXT NOT NULL, row TEXT)");
      this.prepared = true;
    }
  }

  /** Appends one change. */
  record(change: Change): void {
    this.prepare();
    const name = change.kind === "object" ? change.object : change.route;
    const row = change.kind !== "object" && change.row ? JSON.stringify(change.row) : null;
    this.sql.exec(`INSERT INTO ${this.table} (kind, name, key, row) VALUES (?, ?, ?, ?)`, change.kind, name,
      change.key, row);
  }

  /** The changes after `cursor` (none: the log's end, so a first caller starts at now), at most `limit`. */
  after(cursor: string | null | undefined, limit = 1000): ChangePage {
    this.prepare();
    const bound = Math.max(1, Math.min(limit, 100_000));
    if (cursor === null || cursor === undefined || cursor === "") {
      const end = this.sql.exec<{ seq: SqlValue }>(`SELECT COALESCE(MAX(seq), 0) AS seq FROM ${this.table}`).one();
      return { cursor: String(end.seq), changes: [] };
    }
    const rows = this.sql.exec<{ seq: SqlValue; kind: SqlValue; name: SqlValue; key: SqlValue; row: SqlValue }>(
      `SELECT seq, kind, name, key, row FROM ${this.table} WHERE seq > ? ORDER BY seq LIMIT ?`,
      Number(cursor), bound).toArray();
    const changes: Change[] = rows.map((r) => r.kind === "object"
      ? { kind: "object", object: String(r.name), key: String(r.key) }
      : { kind: r.kind as "upsert" | "delete", route: String(r.name), key: String(r.key),
          ...(r.row ? { row: JSON.parse(String(r.row)) as Record<string, string> } : {}) });
    return { cursor: rows.length ? String(rows[rows.length - 1]!.seq) : String(cursor), changes };
  }

  /** The change route's answer for a request: `?after=<cursor>&limit=<n>`. */
  respond(request: Request): Response {
    const url = new URL(request.url);
    return Response.json(this.after(url.searchParams.get("after"), Number(url.searchParams.get("limit") ?? 1000)));
  }
}

/**
 * The change log as Server-Sent Events (CC-W-04): every change after
 * `Last-Event-ID`, each event's `id` the cursor after it, then new changes
 * as they land, with a keep-alive comment every `keepAliveMillis` (30 s) so
 * celld never sees the stream idle. The stream ends after `maxMillis`
 * (5 min); the connector reconnects after the last id.
 */
export function serveChangeStream(log: ChangeLog, request: Request,
                                  options: { keepAliveMillis?: number; pollMillis?: number; maxMillis?: number } = {}): Response {
  const keepAlive = options.keepAliveMillis ?? 30_000;
  const poll = options.pollMillis ?? 1_000;
  const max = options.maxMillis ?? 300_000;
  let cursor = request.headers.get("Last-Event-ID") ?? log.after(null).cursor;
  const encoder = new TextEncoder();
  let timer: ReturnType<typeof setInterval> | undefined;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const started = Date.now();
      let lastWrite = Date.now();
      const flush = () => {
        const page = log.after(cursor);
        let seq = Number(cursor);
        for (const change of page.changes) {
          seq += 1;
          controller.enqueue(encoder.encode(`id: ${seq}\ndata: ${JSON.stringify(change)}\n\n`));
          lastWrite = Date.now();
        }
        cursor = page.cursor;
      };
      controller.enqueue(encoder.encode(": keep-alive\n\n"));
      flush();
      timer = setInterval(() => {
        try {
          flush();
          if (Date.now() - lastWrite >= keepAlive) {
            controller.enqueue(encoder.encode(": keep-alive\n\n"));
            lastWrite = Date.now();
          }
          if (Date.now() - started >= max) {
            clearInterval(timer);
            controller.close();
          }
        } catch (e) {
          clearInterval(timer);
          controller.error(e);
        }
      }, poll);
    },
    cancel() {
      clearInterval(timer);
    },
  });
  return new Response(stream, { headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-store" } });
}

/** The R2 call the receiving routes make. */
export interface PutBucket {
  put(key: string, value: ReadableStream<Uint8Array> | ArrayBuffer | Uint8Array | string): Promise<unknown>;
}

/** What a receiving route learned from the connector's request. */
export type Received = { invocationId: string; root: string; key: string; bytes: number };

/**
 * Receives an artifact the connector sends whole (CC-W-03): streams the body
 * into `bucket` under `key` and returns what it stored. Wrap the call in the
 * cell's `once(invocationId, ...)` so a retry stores nothing twice; the
 * connector sends `Content-Length`, which R2 needs for a streamed put.
 */
export async function receiveArtifact(request: Request, bucket: PutBucket, key: string): Promise<Received> {
  const invocationId = required(request, INVOCATION_HEADER);
  const root = required(request, ROOT_HEADER);
  const length = Number(request.headers.get("Content-Length") ?? -1);
  if (!request.body) {
    throw new Error("the request has no body");
  }
  await bucket.put(key, request.body);
  return { invocationId, root, key, bytes: length };
}

/**
 * Receives one step of an artifact the connector sends piece by piece
 * (CC-W-03): a `piece` step stores the piece as `<key>/pieces/<index>`; the
 * `finish` step checks every piece landed and writes `<key>/pieces.json`
 * listing them in order. An R2 multipart upload needs parts of 5 MiB or
 * more, so the pieces stay separate objects the application reads in order.
 * The `finish` step returns the received artifact; a `piece` step returns
 * `null`.
 */
export async function receivePiece(request: Request, bucket: PutBucket & { head(key: string): Promise<unknown | null> },
                                   key: string): Promise<Received | null> {
  const invocationId = required(request, INVOCATION_HEADER);
  const root = required(request, ROOT_HEADER);
  const count = Number(required(request, PIECE_COUNT_HEADER));
  const step = required(request, UPLOAD_HEADER);
  if (step === "piece") {
    const index = Number(required(request, PIECE_INDEX_HEADER));
    if (!Number.isInteger(index) || index < 0 || index >= count) {
      throw new Error(`piece index ${index} is outside 0..${count - 1}`);
    }
    const bytes = new Uint8Array(await request.arrayBuffer());
    await bucket.put(`${key}/pieces/${index}`, bytes);
    return null;
  }
  if (step !== "finish") {
    throw new Error(`unknown upload step ${step}`);
  }
  const names: string[] = [];
  for (let i = 0; i < count; i++) {
    const name = `${key}/pieces/${i}`;
    if ((await bucket.head(name)) === null) {
      throw new Error(`piece ${i} of ${count} never arrived`);
    }
    names.push(name);
  }
  await bucket.put(`${key}/pieces.json`, JSON.stringify({ root, pieces: names }));
  return { invocationId, root, key, bytes: -1 };
}

function required(request: Request, header: string): string {
  const value = request.headers.get(header);
  if (value === null || value === "") {
    throw new Error(`the request has no ${header} header`);
  }
  return value;
}
