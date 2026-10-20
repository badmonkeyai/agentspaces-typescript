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
 * The worker entry of the resident host (srad/agentspaces-js.md JS-R-02):
 * the script a page names in `connect({ worker })`. Loaded as a
 * SharedWorker it serves every page that connects on its own port; loaded
 * as a dedicated Worker it serves the one page over the worker's own
 * scope, and closes the worker once that page detaches. One
 * `ResidentHost` lives per worker; the first page's hello configures it.
 * Importing this module starts the service, so a custom worker script that
 * wants its own wiring imports `./host.js` instead and calls
 * {@link startResidentHost}. Nothing here imports a Node module (the core's
 * portable rule, checked by `test/portable.test.ts`).
 */

import { ResidentHost, ResidentHostOptions } from "./host.js";
import type { PortLike } from "./protocol.js";

interface SharedScope { onconnect: ((event: { ports: PortLike[] }) => void) | null }
interface DedicatedScope extends PortLike { close(): void }

/** Whether this global is a SharedWorker's scope. */
export function isSharedWorkerScope(scope: object = globalThis): boolean {
  return "onconnect" in scope && typeof (globalThis as { SharedWorkerGlobalScope?: unknown }).SharedWorkerGlobalScope === "function";
}

/** Whether this global is a dedicated Worker's scope. */
export function isDedicatedWorkerScope(scope: object = globalThis): boolean {
  return typeof (globalThis as { DedicatedWorkerGlobalScope?: unknown }).DedicatedWorkerGlobalScope === "function"
    && scope instanceof (globalThis as unknown as { DedicatedWorkerGlobalScope: abstract new () => object }).DedicatedWorkerGlobalScope;
}

/**
 * Starts the host for the scope this runs in and wires the ports to it; returns the host so a
 * custom worker script can bind worker-side agents through `host.bind`. Outside a worker it
 * returns a host that serves whatever ports `attach` is given (tests drive it so).
 */
export function startResidentHost(options: Partial<ResidentHostOptions> = {}): ResidentHost {
  const scope = globalThis as unknown as SharedScope & DedicatedScope;
  const shared = isSharedWorkerScope(scope);
  const host = new ResidentHost({ ...options, shared: options.shared ?? shared });
  if (shared) {
    scope.onconnect = (event) => {
      for (const port of event.ports) {
        host.attach(port);
      }
    };
  } else if (isDedicatedWorkerScope(scope)) {
    // The page's port is the worker's own scope; detaching ends the worker after the clean
    // close had a moment to leave.
    const port: PortLike = {
      postMessage: (message) => scope.postMessage(message),
      get onmessage() { return scope.onmessage; },
      set onmessage(handler) { scope.onmessage = handler; },
      close: () => {
        void host.stop().finally(() => { globalThis.setTimeout(() => scope.close(), 250); });
      },
    };
    host.attach(port);
  }
  return host;
}

/** The host this worker runs. */
export const host: ResidentHost = startResidentHost();
