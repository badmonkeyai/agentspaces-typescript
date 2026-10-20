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
 * The page side of the browser fleet test: reads the worker arguments from
 * the page URL, runs {@link runFleetWorker} in the browser over the portable
 * core, and publishes the result on `window.fleetResult` for the driver.
 */

import { runFleetWorker } from "./fleet-run.js";

const params = new URLSearchParams(location.search);
runFleetWorker({
  scheme: params.get("scheme") ?? "ws",
  host: params.get("host") ?? "127.0.0.1",
  port: Number(params.get("port")),
  founding: params.get("founding") ?? "",
  jobType: params.get("jobType") ?? "",
  doneType: params.get("doneType") ?? "",
  maxSeconds: Number(params.get("maxSeconds") ?? 60),
}).then((result) => {
  (globalThis as { fleetResult?: unknown }).fleetResult = result;
}, (e) => {
  (globalThis as { fleetResult?: unknown }).fleetResult = { ok: false, reason: String(e) };
});
