# agentspaces-typescript documents

Written for: anyone who read the README and wants the rest of the story.

The README is short by design: what this is, the quick start, and how to add it to a build. Everything else lives here, one topic per document.

| Document | Written for | What it holds |
|---|---|---|
| [About @agentspaces/client](about.md) | TypeScript and JavaScript developers who build with @agentspaces/client | What AgentSpaces is, and what this project adds to it. |
| [How to use AI with AgentSpaces](how-to-use-ai.md) | TypeScript and JavaScript developers who build with @agentspaces/client | Tested walk-throughs that build an agent, hand it work from another peer, and survive a crash. |
| [The cross-language guarantee](the-cross-language-guarantee.md) | TypeScript and JavaScript developers who build with @agentspaces/client | The tests prove this client byte-identical against the SAME `agentspaces-spec/golden.json`. |
| [Agents of their own (v0.1.13)](agent-identities.md) | TypeScript and JavaScript developers who build with @agentspaces/client | A TypeScript peer can give each agent a key of its own, certified by the peer and renewed at half-life. |
| [Joining by GroupID](joining-by-group-id.md) | TypeScript and JavaScript developers who build with @agentspaces/client | A group founded with `foundGroup(...)` (SPEC sections 4.4 and 5.1) has a self-certifying id: the hash of its signed founding document. |
| [Bootstrap and invite keys](bootstrap-and-invite-keys.md) | TypeScript and JavaScript developers who build with @agentspaces/client | Discovery SRAD §3.5 and §3.8 (DB-X-02, DB-X-03, DB-X-07). |
| [Layers 3 and 4, TypeScript-shaped](spaces-agents-and-capabilities.md) | TypeScript and JavaScript developers who build with @agentspaces/client | The same AgentSpace and the same capability services the Java annotations bind, as stage-3 decorators on plain classes (`L3L4-COVERAGE.md` §6.5). |
| [Run it](run-it.md) | TypeScript and JavaScript developers who build with @agentspaces/client | The demo runs a Java coordinator publishing six tasks while a Python worker, this TypeScript worker. |
| [On a network](on-a-network.md) | TypeScript and JavaScript developers who build with @agentspaces/client | The client refuses every carrier that is not in the wire encoding, and stays cautious in what it sends (ROBUSTNESS.md; HLC round six, 2026-11-08. |
| [Exact work selection and local snapshots](exact-work-selection.md) | TypeScript and JavaScript developers who build with @agentspaces/client | `takeEntry` accepts an optional `exactEntryId` argument (before the template matcher and the bid function). |
