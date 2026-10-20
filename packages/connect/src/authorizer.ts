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
 * The authorization seam of the connector runtime (srad/agentspaces-js.md
 * JS-C-02, JS-Q-SEC-11): the two `Authorizer.Operation`s the Java runtime
 * asks about, with the OIDC scope strings `OidcAuthorizer` derives from them
 * (`aspace:connector-serve:<asset>` and
 * `aspace:connector-invoke:<asset>:<operation>`), so a token minted for a
 * Java fleet authorizes a TypeScript connector under the same names.
 */

/** The privileged connector operations (`Authorizer.Operation` in Java). */
export type Operation = "CONNECTOR_SERVE" | "CONNECTOR_INVOKE";

/**
 * Answers "may peer P perform operation O in scope S?" as the Java
 * `Authorizer` does. The scope of `CONNECTOR_SERVE` is the asset name; the
 * scope of `CONNECTOR_INVOKE` is `<asset>:<operation>`.
 */
export interface Authorizer {
  permits(peer: string, operation: Operation, scope: string): boolean;
}

/** The scope string `OidcAuthorizer` checks for an operation: `aspace:<operation>` or `aspace:<operation>:<scope>`. */
export function scopeName(operation: Operation, scope = ""): string {
  const name = `aspace:${operation.toLowerCase().replace(/_/g, "-")}`;
  return scope.length === 0 ? name : `${name}:${scope}`;
}

/** The `CONNECTOR_INVOKE` scope of an asset and operation: `<asset>:<operation>`. */
export function invokeScope(asset: string, operation: string): string {
  return `${asset}:${operation}`;
}

/**
 * An authorizer over granted scope strings per peer, judged as
 * `OidcAuthorizer.permits` judges a token's scopes: the fleet-wide name
 * (`aspace:connector-serve`) or the scoped one (`aspace:connector-serve:orders`)
 * permits. A peer with no entry is permitted nothing.
 */
export function scopeAuthorizer(scopesOf: (peer: string) => Iterable<string> | undefined): Authorizer {
  return {
    permits(peer, operation, scope) {
      const granted = new Set(scopesOf(peer) ?? []);
      return granted.has(scopeName(operation)) || (scope.length > 0 && granted.has(scopeName(operation, scope)));
    },
  };
}
