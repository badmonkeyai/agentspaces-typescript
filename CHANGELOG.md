# agentspaces-typescript changelog

What changed in the TypeScript client and its packages, newest first. The Java core's history is in `docs/dvit/CHANGELOG.md` of the AgentSpaces workspace.

## Unreleased: 0.7.0

Work since the 0.6.0 release, for 0.7.0 (SPEC v0.1.34 to v0.1.38, still wire version 3). Nothing is bumped or published: every `package.json` still reads 0.6.0 until the release bump.

- **Fix: a pull made before the first connect is asked again on it (SPEC §5.3, the first round after joining).** `ServiceHost.start()` pulls its spaces before it dials its seed, and that pull reached no link, so a host saw the group's existing entries only at its first anti-entropy round, 10 s later (the Jungle Gym's TypeScript step 09: councillor C never heard the proposal). `Peer.pullSpace` and `Peer.pullAds` now note a pull that reaches no link, and `connectAny` pulls those again once the link is up, through the same code as the reconnect path, which still pulls every space and the ads. A pull made with a link up is not repeated.
- **AgentCard `threads` and the AppCard kind `dynamic` (SPEC v0.1.38).** The `chatThread` decorator and `wire.chatThread(space, key, scope)` name the conversations an agent answers, with the scopes `exact`, `tree` and `all`. The reader checks `threads` (at most 16, all distinct) and accepts the kind `dynamic`. A reader before v0.1.38 drops a card that carries either, so this is a flag day.
- **The loop runs on deadlines and the monotonic clock (SPEC v0.1.36 and v0.1.37).**
  - `DueLoop`, `VirtualTime`, `Watchdog` and `WallStepDetector` in `src/time.ts`, `RedialTable` in `src/redial.ts`, and the TTL floor in `src/ttl.ts`.
  - Seeds are dialed in list order 250 ms apart, and the first to answer wins. Failed rounds wait 5, 10, 20 and 30 s, then 5 s again, each spread by a tenth. A link that held at least 5 s resets the table.
  - A wake from sleep, or a timer more than 30 s late, resets the table and pings the seed. A member whose card lapsed during the pause is probed before it is dropped.
  - The dead-seed rule covers every dialed link on `tcp`, `tls`, `http(s)` and `webrtc`. Bytes of a frame still arriving count as an answer.
  - Browser and Node hosts run anti-entropy and re-advertisement by elapsed time, so a throttled tab keeps its advertisement.
  - The Raft leader's lease guard reads the monotonic clock, and its card changes only at a role or term change or at half its lease.
- **Takes and relayed digests.** A result after a take has lapsed completes nothing and counts in `lateTakes`. A dial-only peer answers its seed's `DIGEST` in full, and a relayed one only with its displaced entries, paced per asker (`relayedAnswersPaced`). The peer reads the core's `hashes`, `digests` and `want` fields.
- **Replication by entry (SPEC v0.1.35).** The trie audit (`wire.ae=2`), the per-entry horizon (`wire.horizon=1`), the pull budget, and the renewal rule (a renewal never shortens a lease). New options `audit`, `auditBudget`, `auditSessions` and `horizon`, and `peer.replicationStatus()`. `docs/replication-by-entry.md` has the detail.
- **A2UI 1.0 (SPEC v0.1.34).** `src/a2ui.ts` writes A2UI 1.0: `@path` bindings and Unicode-identifier component ids. No v0.9.1 reading is kept.
