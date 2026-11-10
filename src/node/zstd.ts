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
 * The zstd of Node's `zlib` (PDT 2 phase 7, P2-Z-04; srad/agentspaces-pdt2.md §3.8): the decoder of intra-chunk
 * delta frames, which loads a base that does not start with the zstd dictionary magic as raw content, as
 * `zstd --patch-from` writes it. Node 23.8 and later carry it; on an older Node the port is absent and every frame
 * is refused by name, so its chunk travels whole.
 */

import zlib from "node:zlib";

import type { ZstdPort } from "../pdt/dcz.js";

export const nodeZstd: ZstdPort | null = typeof zlib.zstdDecompressSync === "function" ? {
  decompress: (frame, dictionary, size) => new Uint8Array(zlib.zstdDecompressSync(frame,
    { dictionary, maxOutputLength: Math.max(1, size) } as zlib.ZstdOptions)),
} : null;
