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
 * The page of the swarm demo (srad/large-networks-bulk-data.md LB-C-06, scenario 5): it connects
 * to the resident host with the content swarm on, fetches the artifact the demo fleet holds, and
 * draws the bytes arriving from each holder as the worker pushes progress. `?auto` fetches at
 * once; `window.result` carries the outcome for the demo's headless check.
 */

import { connect } from "../src/index.js";
import type { WireProgress } from "../src/index.js";

type Fleet = { group: string; seeds: string[]; root: string; size: number; pieceSize: number; names: { [peerId: string]: string } };

const $ = (id: string): HTMLElement => document.getElementById(id)!;

function bar(label: string, value: number, total: number): string {
  const pct = total === 0 ? 0 : Math.round((value / total) * 100);
  return `<div class="row"><span class="who">${label}</span><span class="track"><span class="fill" style="width:${pct}%"></span></span>`
    + `<span class="num">${(value / 1024 / 1024).toFixed(1)} MiB</span></div>`;
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(data)));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function main(): Promise<void> {
  const fleet = await (await fetch("/fleet.json")).json() as Fleet;
  $("artifact").textContent = `${fleet.root.slice(0, 20)}... ${(fleet.size / 1024 / 1024).toFixed(1)} MiB in `
    + `${fleet.size === 0 ? 0 : Math.ceil(fleet.size / fleet.pieceSize)} pieces`;
  const host = await connect({ group: fleet.group, seeds: fleet.seeds, worker: "/worker.js",
    content: { pieceSize: fleet.pieceSize } });
  const state = await host.status();
  $("status").textContent = `peer ${state.peerId.slice(0, 12)}... in a ${state.shared ? "shared" : "dedicated"} worker, `
    + `pieces stored on ${state.contentStore ?? "nothing"}`;
  const draw = (p: WireProgress): void => {
    $("overall").innerHTML = bar("all holders", p.bytesReceived, fleet.size);
    $("sources").innerHTML = Object.entries(p.bySource)
      .map(([peer, bytes]) => bar(fleet.names[peer] ?? peer.slice(0, 10), bytes, fleet.size)).join("");
    $("pieces").textContent = `${p.piecesVerified} of ${p.pieces} pieces verified`;
  };
  const run = async (): Promise<void> => {
    ($("go") as HTMLButtonElement).disabled = true;
    const started = performance.now();
    try {
      const final = await host.content.fetch(fleet.root, draw);
      draw(final);
      const bytes = await host.content.read(fleet.root);
      const millis = Math.round(performance.now() - started);
      const sha = await sha256Hex(bytes);
      $("done").textContent = `complete in ${millis} ms, sha-256 ${sha.slice(0, 16)}...`;
      (globalThis as { result?: unknown }).result = { ok: true, size: bytes.length, sha256: sha, millis,
        sources: Object.fromEntries(Object.entries(final.bySource).map(([p, b]) => [fleet.names[p] ?? p, b])),
        store: state.contentStore };
    } catch (e) {
      $("done").textContent = `failed: ${e instanceof Error ? e.message : String(e)}`;
      (globalThis as { result?: unknown }).result = { ok: false, error: String(e) };
    }
  };
  $("go").addEventListener("click", () => { void run(); });
  if (new URLSearchParams(location.search).has("auto")) {
    await run();
  }
}

main().catch((e: unknown) => {
  $("status").textContent = `could not start: ${e instanceof Error ? e.message : String(e)}`;
  (globalThis as { result?: unknown }).result = { ok: false, error: String(e) };
});
