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
 * Verified windows of a blob (PDT 2 phase 7, P2-C-01, P2-B-03; srad/agentspaces-pdt2.md §3.5), a port of Java's
 * `VerifiedWindow`: the bytes `[offset, offset + length)` of a blob, each 16 KiB chunk group delivered only after its
 * chaining value verifies up to the blob's BLAKE3 identity through the `bo` nodes of its Bao outboard. A group verifies
 * alone, so a window from the middle of a large blob needs its chunks, the path of `b` nodes to them, and the `bo`
 * nodes on the paths of its groups. The identity and the outboard root come from a head's advisory attributes
 * `pdt.blake3` and `pdt.bao`; a reader reaches `bo` nodes through `pdt.bao` alone (§6.10.3 rule 5).
 */

import { equals } from "../bytes.js";
import { BlobTree } from "./blob.js";
import * as blake3 from "./blake3.js";
import * as cids from "./cids.js";
import { BoNode } from "./kinds.js";
import { Link, NodeFormatError, decode } from "./nodes.js";
import { NodeStore } from "./store.js";

const CHUNKS_PER_GROUP = 2 ** BoNode.GROUP_LOG;

/** The 32-byte digest an identity CID names: CIDv1 `raw` over multihash 0x1e. */
function identityDigest(identity: string): Uint8Array {
  let binary: Uint8Array;
  try {
    binary = identity.startsWith("b") ? cids.base32Decode(identity.slice(1)) : new Uint8Array(0);
  } catch {
    binary = new Uint8Array(0);
  }
  if (binary.length !== 36 || binary[0] !== 0x01 || binary[1] !== cids.RAW || binary[2] !== blake3.MULTIHASH || binary[3] !== 32
      || blake3.identity(binary.subarray(4)) !== identity) {
    throw new NodeFormatError(`'${identity}' is no BLAKE3 identity`, null);
  }
  return binary.subarray(4);
}

/** The largest power of two strictly below `n`, for n >= 2: BLAKE3's left subtree over n leaves. */
function leftOf(n: number): number {
  let bit = 1;
  while (bit * 2 < n) {
    bit *= 2;
  }
  return bit;
}

function loadBo(store: NodeStore, cid: string, size: number): BoNode {
  const node = BoNode.decode(store.load(cid), cid);
  if (node.size !== size) {
    throw new NodeFormatError(`an outboard of ${node.size} bytes where its parent counts ${size}`, cid);
  }
  return node;
}

/**
 * The chaining value a group must have, found by descending the outboard from its root and checking every parent pair
 * on the way against the value above it, the root's pair against the identity; null for a blob of one group, which is
 * hashed as the root itself.
 */
function expectedCv(store: NodeStore, bao: string, size: number, digest: Uint8Array, group: number): Uint8Array | null {
  let node = loadBo(store, bao, size);
  if (BoNode.groups(size) === 1) {
    return null;
  }
  let expected = digest;
  let root = true;
  let first = 0; // the first group of this node
  for (;;) {
    const blocks = BoNode.childSizes(node.size);
    const leaves = blocks.length === 0 ? BoNode.groups(node.size) : blocks.length;
    const blockGroups = blocks.length === 0 ? 1 : BoNode.groups(blocks[0]!);
    const target = Math.floor((group - first) / blockGroups);
    // descend the pre-order parents over this node's leaves to the leaf that holds the group
    let from = 0, to = leaves, at = 0;
    while (to - from > 1) {
      const pair = node.parents.subarray(at * BoNode.PARENT_BYTES, (at + 1) * BoNode.PARENT_BYTES);
      const left = pair.subarray(0, blake3.DIGEST_BYTES), right = pair.subarray(blake3.DIGEST_BYTES);
      if (!equals(blake3.parent(left, right, root), expected)) {
        throw new NodeFormatError(`group ${group} does not verify: a parent of the outboard does not chain to the value above it`,
          null);
      }
      root = false;
      const mid = from + leftOf(to - from);
      if (target < mid) {
        expected = left.slice();
        to = mid;
        at += 1;
      } else {
        expected = right.slice();
        at += mid - from; // past the parents of the left subtree
        from = mid;
      }
    }
    if (blocks.length === 0) {
      return expected;
    }
    first += target * blockGroups;
    node = loadBo(store, node.children[target]!.cid, blocks[target]!);
  }
}

/**
 * The verified bytes `[offset, offset + length)` of the blob under `root`, whose identity and outboard root a head
 * names. Throws NodeFormatError naming the first group that does not verify, and NodeUnavailableError naming a node the
 * store lacks; it delivers no byte of a group before that group verifies.
 */
export function readVerified(store: NodeStore, root: string, identity: string, bao: string, offset: number, length: number): Uint8Array {
  const digest = identityDigest(identity);
  const tree = BlobTree.open(store, root);
  if (offset < 0 || length < 0 || offset + length > tree.size) {
    throw new RangeError(`window ${offset}+${length} outside a blob of ${tree.size} bytes`);
  }
  const out = new Uint8Array(length);
  if (length === 0) {
    return out;
  }
  const firstGroup = Math.floor(offset / BoNode.GROUP_BYTES);
  const lastGroup = Math.floor((offset + length - 1) / BoNode.GROUP_BYTES);
  for (let g = firstGroup; g <= lastGroup; g++) {
    const start = g * BoNode.GROUP_BYTES;
    const bytes = groupBytes(tree, start, Math.min(BoNode.GROUP_BYTES, tree.size - start));
    const expected = expectedCv(store, bao, tree.size, digest, g);
    const actual = expected === null ? blake3.digest(bytes) : blake3.groupCv(bytes, g * CHUNKS_PER_GROUP);
    if (!equals(actual, expected ?? digest)) {
      throw new NodeFormatError(`group ${g} does not verify against the identity ${identity}`, null);
    }
    const from = Math.max(offset, start), to = Math.min(offset + length, start + bytes.length);
    out.set(bytes.subarray(from - start, to - start), from - offset);
  }
  return out;
}

/** The bytes of a group from the chunks that cover it. */
function groupBytes(tree: BlobTree, start: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let at = 0; at < length;) {
    const located = tree.seek(start + at);
    const chunk = tree.chunk({ cid: located.cid, length: located.length });
    const from = start + at - located.start;
    const take = Math.min(length - at, chunk.length - from);
    out.set(chunk.subarray(from, from + take), at);
    at += take;
  }
  return out;
}

/**
 * The nodes a window needs that the store lacks, as far as the nodes it holds reach (PDT 2 phase 7, P2-B-03): the `b`
 * nodes and chunks that cover the window, then the `bo` nodes on its groups' paths. A reader fetches them in one batch
 * per round, a round per level it has not reached yet. Empty when the window reads.
 */
export function missingFor(store: NodeStore, root: string, bao: string, offset: number, length: number): string[] {
  const missing: string[] = [];
  const end = offset + length;
  const blob = (cid: string, start: number): void => {
    if (!store.has(cid)) {
      missing.push(cid);
      return;
    }
    if (cids.parse(cid).codec === cids.RAW) {
      return;
    }
    const node = decode(store.get(cid)!, cid);
    const children = (node["c"] as Link[] | undefined) ?? [];
    const sizes = (node["z"] as number[] | undefined) ?? [];
    let at = start;
    children.forEach((child, i) => {
      if (at < end && at + sizes[i]! > offset) {
        blob(child.cid, at);
      }
      at += sizes[i]!;
    });
  };
  blob(root, 0);
  if (missing.length > 0 || length === 0) {
    return missing;
  }
  const outboard = (cid: string, start: number): void => {
    if (!store.has(cid)) {
      missing.push(cid);
      return;
    }
    const node = BoNode.decode(store.get(cid)!, cid);
    const blocks = BoNode.childSizes(node.size);
    let at = start;
    blocks.forEach((size, i) => {
      if (at < end && at + size > offset) {
        outboard(node.children[i]!.cid, at);
      }
      at += size;
    });
  };
  outboard(bao, 0);
  return missing;
}
