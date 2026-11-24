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
 * The cell's dialer wrapper (the alarm owns every dial). The core dials the seeds 250 ms apart, a refusal starting
 * the next at once (owner decision 2 of 2026-11-23), so several dials, of one scheme or of ws and wss, are out together: a dial counts as in flight until
 * every one of them has settled, or the alarm would start a second join over the first and two links would be
 * adopted. And the core closes each channel that loses the race: only the channel that is the peer's link when it
 * ends reports a lost link, so a round's losers neither re-arm the alarm nor move the redial table.
 */

import type { Dialer, FrameChannel, Seed } from "@agentspaces/client";

/** The dials in flight across every {@link TrackedDialer} of one cell. */
export class DialTracker {
  private inFlight = 0;

  /** Whether any dial is still out. */
  get dialing(): boolean {
    return this.inFlight > 0;
  }

  track(delta: 1 | -1): void {
    this.inFlight = Math.max(0, this.inFlight + delta);
  }
}

/**
 * Wraps a dialer: counts its dials on `tracker`, and reports `ended` with the time the link came up when a channel it
 * opened ends while it is the peer's link (`link()`). The dialer's close listener runs before the peer's own, which
 * then clears the link, so the check sees the link as it was. A channel dropped before the peer adopted it is not
 * reported: the caller of the join arms the alarm after it, and finds the peer down.
 */
export class TrackedDialer implements Dialer {
  readonly scheme: string;
  constructor(private readonly inner: Dialer, private readonly tracker: DialTracker,
              private readonly ended: (linkedAt: number) => void,
              private readonly link: () => FrameChannel | null) {
    this.scheme = inner.scheme;
  }

  expand(seed: Seed, resolve: boolean): Promise<Seed[]> {
    return this.inner.expand === undefined ? Promise.resolve([seed]) : this.inner.expand(seed, resolve);
  }

  async dial(seed: Seed): Promise<FrameChannel> {
    this.tracker.track(1);
    try {
      const channel = await this.inner.dial(seed);
      const linkedAt = Date.now();
      channel.onClose(() => {
        if (this.link() === channel) {
          this.ended(linkedAt);
        }
      });
      return channel;
    } finally {
      this.tracker.track(-1);
    }
  }
}
