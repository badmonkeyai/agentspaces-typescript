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
 * `@agentspaces/client/node`: the Node adapters of the portable core. Importing
 * it registers the `tcp` dialer for every `Peer` built afterwards and makes the
 * binder's current take an `AsyncLocalStorage`, so it survives awaits. It also
 * exports the file keystore and the `node:crypto` port. `@agentspaces/node`
 * re-exports this entry and adds the service host.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { ContextStore, installContextStores } from "../emitter.js";
import { registerDefaultDialer } from "../transport.js";
import { TcpDialer } from "./tcp.js";

registerDefaultDialer(new TcpDialer());
installContextStores(<T>(): ContextStore<T> => {
  const storage = new AsyncLocalStorage<T>();
  return { get: () => storage.getStore(), run: (value, fn) => storage.run(value, fn) };
});

export { TcpChannel, TcpDialer, TcpListener } from "./tcp.js";
export { FileKeyStore, agentKeys, loadOrCreateIdentity, savePkcs8, writeKeyFile } from "./keystore.js";
export { nodeCrypto } from "./crypto.js";
