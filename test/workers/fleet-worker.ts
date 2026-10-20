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
 * The Node worker of the Java cross-language test (agentspaces-transport-http
 * TypeScriptClientTest): runs {@link runFleetWorker} on Node and prints one
 * JSON line. Exit 0 when the Done went out.
 *
 *   node build/test/workers/fleet-worker.js <scheme> <host> <port> <founding> <jobType> <doneType> [maxSeconds]
 */

import { runFleetWorker } from "./fleet-run.js";
import "../../src/node/index.js";

const [scheme, host, port, founding, jobType, doneType, maxSeconds] = process.argv.slice(2);
runFleetWorker({ scheme, host, port: Number(port), founding, jobType, doneType, maxSeconds: Number(maxSeconds ?? 60) })
  .then((result) => {
    console.log(JSON.stringify(result));
    process.exit(result.ok ? 0 : 2);
  }, (e) => {
    console.log(JSON.stringify({ ok: false, reason: String(e instanceof Error ? e.message : e) }));
    process.exit(1);
  });
