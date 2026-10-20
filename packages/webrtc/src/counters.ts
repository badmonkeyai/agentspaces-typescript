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
 * The binding's counters (SRAD srad/agentspaces-js.md JS-W-14): sessions offered, answered, opened,
 * failed by reason; signals dropped by reason; chunks and bytes each way; the selected candidate
 * type of each opened connection. The twin of the Java `WebRtcCounters`.
 */
export class WebRtcCounters {
  sessionsOffered = 0;
  sessionsAnswered = 0;
  sessionsOpened = 0;
  chunksSent = 0;
  chunksReceived = 0;
  bytesSent = 0;
  bytesReceived = 0;
  /** The relay offload (JS-W-11): dials started past the threshold, opened, and failed into the backoff. */
  offloadAttempts = 0;
  offloadOpened = 0;
  offloadFailed = 0;
  readonly failed: { [reason: string]: number } = {};
  readonly signalsDropped: { [reason: string]: number } = {};
  readonly selectedCandidates: { [type: string]: number } = {};

  fail(reason: string): void {
    this.failed[reason] = (this.failed[reason] ?? 0) + 1;
  }

  drop(reason: string): void {
    this.signalsDropped[reason] = (this.signalsDropped[reason] ?? 0) + 1;
  }

  opened(candidateType: string): void {
    this.sessionsOpened += 1;
    this.selectedCandidates[candidateType] = (this.selectedCandidates[candidateType] ?? 0) + 1;
  }

  sent(bytes: number): void {
    this.chunksSent += 1;
    this.bytesSent += bytes;
  }

  received(bytes: number): void {
    this.chunksReceived += 1;
    this.bytesReceived += bytes;
  }
}
