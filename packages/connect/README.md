# @agentspaces/connect

The connector runtime of the AgentSpaces JavaScript client (srad/agentspaces-js.md §3.8, §4.7,
appendix F): the port of `agentspaces-connect-core` to the portable TypeScript core, plus the
`aspace:cap/asset-invoke` capability in both languages. A provider describes the assets it holds as
AssetCards, answers queries for them through the data space, pushes source changes in as leased
entries, and runs the operations its cards allowlist; agents query and invoke an asset in one call.
No Node module is imported under `src/`, so the package loads in browsers, Workers, Deno, and Bun.

**Architecture position.** Gateways and served interfaces. SPEC §6.1a, §6.3; TECH-SPEC §6.

## Key files

| File | What it is |
| --- | --- |
| `src/entries.ts` | `DataQuery`, `DataResult`, `AssetChange` (byte-identical to `DataQueryEntries.java:45`, `:58`, `:74`), `AssetInvocation`, `AssetInvocationResult` (appendix F, with `v`; readers drop unknown fields), `canonicalHash`. |
| `src/provider.ts` | The SPI: `AssetProvider` (`describeAssets`, `query`, optional `invoke`), `MaterializingAssetProvider` (`materialize(sink)`, `Change`), `assetCard` in Java field order, `TableAssetProvider` as the in-memory reference. |
| `src/runtime.ts` | `ConnectorRuntime`: leased cards on the `ads` stream refreshed at half their TTL; `aspace:cap/data-query` served from the data space pull-once; `AssetChange` leased for the asset's freshness; `aspace:cap/asset-invoke` taken under the claim lattice, refused by the `invoke-ops` rule or the invoke scope, run once, the result written, the take completed. |
| `src/client.ts` | `DataQueryClient` (fetch by asset and parameters, pull-once by canonical hash, trusted issuers), `invoke(space, card, operation, params)` resolving with the connector's result, `assetCards(peer)`. |
| `src/authorizer.ts` | The `Authorizer` seam with the two operations the Java runtime asks about, `scopeAuthorizer` over `aspace:connector-serve:<asset>` and `aspace:connector-invoke:<asset>:<operation>` scope strings. |
| `test/workers/connector-worker.ts` | The Node worker the Java `TypeScriptConnectorTest` drives: a TypeScript connector serving a Java agent over tcp. |

## Key dependencies

`@agentspaces/client` (the portable core: `Peer`, `Space`, `Template`, the CBOR codec, `publishAd`).

## Requirements and the tests that prove them

| Row | What it asks | Proof |
| --- | --- | --- |
| JS-C-01 | `AssetProvider`, `MaterializingAssetProvider`, `ConnectorRuntime`, `DataQueryClient` ported; the three data-query entries byte-identical to Java and pinned by golden vectors | `test/connect.test.ts` (cards refreshed at half TTL; a query answered and the identical one served from the space; materialized changes leased for the freshness); `test/golden.test.ts` (`data_query_cbor`, `data_result_cbor`, `asset_change_cbor`, `data_query_canonical_hash`); Java `TypeScriptConnectorTest` (a Java agent queries the TypeScript connector) |
| JS-C-02 | Serve only under `aspace:connector-serve:<asset>`, invoke only under `aspace:connector-invoke:<asset>:<operation>` when an authorizer is configured | `test/connect.test.ts` "under an authorizer ..." (an asset the connector may not serve is never advertised; a requester without the scope gets `refused-scope` naming the scope and the target never runs); Java `AssetInvocationsClusterTest.underAnAuthorizerOnlyARequesterHoldingTheInvokeScopeIsServed` |
| JS-C-03 | `AssetInvocation(asset, operation, params, invocationId)` and `AssetInvocationResult(...)` in both languages with golden vectors; taken under the claim lattice with a lease, result written, take completed; an operation absent from `invoke-ops` answered with an error and never run | `test/connect.test.ts` "an invocation is taken once ..." and "an operation absent from the card's invoke-ops ..."; `test/golden.test.ts` (`asset_invocation_cbor`, `asset_invocation_result_cbor`); Java `AssetInvocationsClusterTest` |
| JS-C-07 | No operation the card does not list runs; a refused request is answered with an error naming the rule | `test/connect.test.ts` "an operation absent from the card's invoke-ops ..." (`error: unknown-operation`, `result.rule: invoke-ops`); Java `AssetInvocationsClusterTest.anOperationAbsentFromTheCardsInvokeOpsIsRefusedNamingTheRuleAndNeverRun` |
| JS-C-10 | `invoke(space, card, operation, params)` and `DataQueryClient` in TypeScript; `AssetInvocations.invoke` in Java | `test/connect.test.ts` (both clients); Java `TypeScriptConnectorTest` (`AssetInvocations.invoke` against the TypeScript connector, exactly once under a forced retry) |
| JS-F-06 | The asset-invoke entries carry `v` and receivers ignore unknown fields | `test/connect.test.ts` "a receiver ignores fields it does not know ..."; Java `AssetInvocationsClusterTest.readersIgnoreUnknownFields` |
| JS-N-01 | Existing golden vectors byte-identical; the new bodies gain vectors | `tools/golden/GoldenVectors.java` `connectVectors` (additions only; compared before and after regeneration) |
| JS-K-03 | This README and its map | this file |

## Notes

- Run `npm run build` at the client root first (the package resolves `@agentspaces/client` to the
  built core), then `npm run build && npm test` here. The Java cross-language test
  (`agentspaces-connect-core` `TypeScriptConnectorTest`) spawns `build/test/workers/connector-worker.js`
  and skips when it is absent unless `-Dtsclient.required=true`.
- A result over `maxInlineResultBytes` (default the Java 64 KiB inline limit) is answered with an
  error naming the limit: the TypeScript core carries no block exchange yet, so the content-addressed
  path of SPEC §6.1a is pending here; an all-TypeScript fleet may raise the option up to the frame cap.
- Every bound is an option: `pollTimeout`, `queryLease`, `invokeLease`, `errorLease`,
  `maxInlineResultBytes`, `invocationRetention` (how long an answered invocation is remembered so a
  retry under the same id never re-runs the target here; the target's own `once()` of JS-C-04 remains
  the exactly-once rule across takers).
- The claim on an invocation is renewed only when the runtime takes as an agent identity; size
  `invokeLease` to the slowest operation otherwise.
- On an error result, `result` carries `rule` (the rule that refused: `invoke-ops`, the invoke scope
  string, `provider`, `target`) and `detail`; `error` is one of the appendix F codes.
