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
 * Seed endpoints: a scheme and an address `host:port[/path]` (SPEC §5.5
 * endpoints; ISSUE-Websocket FR-2 for the path). A seed with no scheme is a
 * `tcp` seed, the form every earlier client used.
 */

/** A seed endpoint this peer may dial. */
export type Seed = { host: string; port: number; scheme?: string; path?: string };

/** The scheme a seed is dialed with. */
export function schemeOf(seed: Seed): string {
  return (seed.scheme ?? "tcp").toLowerCase();
}

/** `host:port[/path]` as an endpoint address prints it (brackets around an IPv6 host). */
export function seedAddress(seed: Seed): string {
  const host = seed.host.includes(":") ? `[${seed.host}]` : seed.host;
  return `${host}:${seed.port}${seed.path ?? ""}`;
}

/** `scheme://host:port/path` for display and for URL-shaped dialers. */
export function seedUrl(seed: Seed): string {
  return `${schemeOf(seed)}://${seedAddress(seed)}`;
}

/**
 * Parses `host:port[/path]`, `[v6]:port[/path]`, or a bare host with the
 * default port; a `scheme://` prefix sets the scheme.
 */
export function parseSeed(text: string, defaultPort = 7500, defaultScheme: string | null = null): Seed {
  let rest = text.trim();
  let scheme = defaultScheme;
  const prefix = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//.exec(rest);
  if (prefix) {
    scheme = prefix[1].toLowerCase();
    rest = rest.substring(prefix[0].length);
  }
  let path: string | undefined;
  const bracketEnd = rest.startsWith("[") ? rest.indexOf("]") : -1;
  const slash = rest.indexOf("/", bracketEnd + 1);
  if (slash >= 0) {
    path = rest.substring(slash);
    rest = rest.substring(0, slash);
  }
  let host: string;
  let port = defaultPort;
  const v6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(rest);
  if (v6) {
    host = v6[1];
    if (v6[2]) {
      port = Number(v6[2]);
    }
  } else {
    const colon = rest.lastIndexOf(":");
    if (colon < 0 || rest.indexOf(":") !== colon) {
      host = rest; // no port, or a bare IPv6 literal
    } else {
      host = rest.substring(0, colon);
      port = Number(rest.substring(colon + 1));
    }
  }
  if (!Number.isInteger(port) || port <= 0 || port > 65535 || host.length === 0) {
    throw new Error(`not a seed address: ${text}`);
  }
  const seed: Seed = { host, port };
  if (scheme !== null) {
    seed.scheme = scheme;
  }
  if (path !== undefined && path.length > 0) {
    seed.path = path;
  }
  return seed;
}
