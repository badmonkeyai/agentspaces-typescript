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
 * The Worker route helpers the Java celld connector reads (srad/celld-phase2.md group W): ranged
 * reads with ETag conditions over an R2-shaped bucket, the change log and its cursor route over a
 * real SQLite, the Server-Sent Events stream, and the receiving routes for whole and chunked artifacts.
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  ChangeLog, INVOCATION_HEADER, PIECE_COUNT_HEADER, PIECE_INDEX_HEADER, ROOT_HEADER, UPLOAD_HEADER,
  receiveArtifact, receivePiece, serveChangeStream, serveRange,
} from "../src/routes.js";
import type { RangeBucket, RangeObject } from "../src/routes.js";
import { NodeSqlStorage } from "./sqlite.js";

/** An in-memory bucket with R2's head, ranged get, conditional get, and put. */
class MemoryBucket implements RangeBucket {
  readonly objects = new Map<string, { bytes: Uint8Array; etag: string }>();

  async head(key: string): Promise<RangeObject | null> {
    const o = this.objects.get(key);
    return o ? { size: o.bytes.length, httpEtag: o.etag } : null;
  }

  async get(key: string, options?: { range?: { offset: number; length: number }; onlyIf?: { etagMatches?: string } }) {
    const o = this.objects.get(key);
    if (!o) {
      return null;
    }
    if (options?.onlyIf?.etagMatches && `"${options.onlyIf.etagMatches}"` !== o.etag) { // R2 compares the bare etag
      return { size: o.bytes.length, httpEtag: o.etag };
    }
    const bytes = options?.range
      ? o.bytes.slice(options.range.offset, options.range.offset + options.range.length) : o.bytes;
    return { size: o.bytes.length, httpEtag: o.etag, body: new Blob([bytes as Uint8Array<ArrayBuffer>]).stream() };
  }

  async put(key: string, value: ReadableStream<Uint8Array> | ArrayBuffer | Uint8Array | string) {
    const bytes = typeof value === "string" ? new TextEncoder().encode(value)
      : value instanceof Uint8Array ? value
      : value instanceof ArrayBuffer ? new Uint8Array(value)
      : new Uint8Array(await new Response(value).arrayBuffer());
    this.objects.set(key, { bytes, etag: `"${bytes.length}-${key}"` });
  }
}

function request(headers: Record<string, string>, body?: BodyInit, url = "https://cell/api/x"): Request {
  return new Request(url, { method: body === undefined ? "GET" : "POST", headers, body,
    ...(body instanceof ReadableStream ? { duplex: "half" } : {}) } as RequestInit);
}

test("serveRange answers 206 with Content-Range, 412 on another version, 416 past the end, 200 whole (CC-W-01)", async () => {
  const bucket = new MemoryBucket();
  const bytes = new Uint8Array(1000).map((_, i) => i % 251);
  bucket.objects.set("ckpt", { bytes, etag: "\"v1\"" });
  const part = await serveRange(bucket, request({ Range: "bytes=100-199", "If-Match": "\"v1\"" }), "ckpt");
  assert.equal(part.status, 206);
  assert.equal(part.headers.get("Content-Range"), "bytes 100-199/1000");
  assert.equal(part.headers.get("ETag"), "\"v1\"");
  assert.deepEqual(new Uint8Array(await part.arrayBuffer()), bytes.slice(100, 200));
  assert.equal((await serveRange(bucket, request({ Range: "bytes=0-9", "If-Match": "\"v0\"" }), "ckpt")).status, 412);
  const past = await serveRange(bucket, request({ Range: "bytes=1000-1009" }), "ckpt");
  assert.equal(past.status, 416);
  assert.equal(past.headers.get("Content-Range"), "bytes */1000");
  const tail = await serveRange(bucket, request({ Range: "bytes=990-1999" }), "ckpt");
  assert.equal(tail.headers.get("Content-Range"), "bytes 990-999/1000");
  const whole = await serveRange(bucket, request({}), "ckpt");
  assert.equal(whole.status, 200);
  assert.equal((await whole.arrayBuffer()).byteLength, 1000);
  assert.equal((await serveRange(bucket, request({}), "absent")).status, 404);
});

test("the change log answers after a cursor, and a first caller starts at the end (CC-W-02)", () => {
  const log = new ChangeLog(new NodeSqlStorage());
  log.record({ kind: "upsert", route: "stock", key: "A-1", row: { sku: "A-1", qty: "40" } });
  const start = log.after(null);
  assert.deepEqual(start, { cursor: "1", changes: [] });
  log.record({ kind: "delete", route: "stock", key: "B-9" });
  log.record({ kind: "object", object: "models", key: "ckpt-7" });
  const page = log.after("1");
  assert.equal(page.cursor, "3");
  assert.deepEqual(page.changes, [
    { kind: "delete", route: "stock", key: "B-9" },
    { kind: "object", object: "models", key: "ckpt-7" },
  ]);
  assert.deepEqual(log.after("3"), { cursor: "3", changes: [] });
  assert.equal(log.after("0", 1).changes.length, 1);
  assert.throws(() => new ChangeLog(new NodeSqlStorage(), "x; DROP TABLE y"));
});

test("the change stream sends every change after Last-Event-ID with its cursor as the id (CC-W-04)", async () => {
  const log = new ChangeLog(new NodeSqlStorage());
  log.record({ kind: "upsert", route: "stock", key: "A-1", row: { qty: "1" } });
  log.record({ kind: "upsert", route: "stock", key: "A-1", row: { qty: "2" } });
  const response = serveChangeStream(log, request({ "Last-Event-ID": "1" }), { pollMillis: 20, maxMillis: 120 });
  assert.equal(response.headers.get("Content-Type"), "text/event-stream");
  const text = await response.text();
  assert.match(text, /^: keep-alive\n\n/);
  assert.match(text, /id: 2\ndata: \{"kind":"upsert","route":"stock","key":"A-1","row":\{"qty":"2"\}\}\n\n/);
  assert.doesNotMatch(text, /"qty":"1"/);
});

test("receiveArtifact stores the body and receivePiece reassembles a chunked one in order (CC-W-03)", async () => {
  const bucket = new MemoryBucket();
  const headers = { [INVOCATION_HEADER]: "inv-1", [ROOT_HEADER]: "bafkroot", "Content-Length": "5" };
  const received = await receiveArtifact(request(headers, "hello"), bucket, "ingest/bafkroot");
  assert.deepEqual(received, { invocationId: "inv-1", root: "bafkroot", key: "ingest/bafkroot", bytes: 5 });
  assert.equal(new TextDecoder().decode(bucket.objects.get("ingest/bafkroot")!.bytes), "hello");

  const chunk = (step: string, extra: Record<string, string>, body?: string) => request({
    [INVOCATION_HEADER]: "inv-2", [ROOT_HEADER]: "bafkroot2", [PIECE_COUNT_HEADER]: "2", [UPLOAD_HEADER]: step, ...extra,
  }, body ?? "");
  assert.equal(await receivePiece(chunk("piece", { [PIECE_INDEX_HEADER]: "1" }, "world"), bucket, "c"), null);
  await assert.rejects(receivePiece(chunk("finish", {}), bucket, "c"), /piece 0 of 2 never arrived/);
  await receivePiece(chunk("piece", { [PIECE_INDEX_HEADER]: "0" }, "hello "), bucket, "c");
  const done = await receivePiece(chunk("finish", {}), bucket, "c");
  assert.equal(done?.root, "bafkroot2");
  assert.deepEqual(JSON.parse(new TextDecoder().decode(bucket.objects.get("c/pieces.json")!.bytes)),
    { root: "bafkroot2", pieces: ["c/pieces/0", "c/pieces/1"] });
  await assert.rejects(receivePiece(chunk("piece", { [PIECE_INDEX_HEADER]: "2" }, "x"), bucket, "c"), /outside 0..1/);
  await assert.rejects(receiveArtifact(request({ [ROOT_HEADER]: "r" }, "x"), bucket, "k"), /no Aspace-Invocation-Id/);
});
