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
 * The fleet file and the CLI (srad/agentspaces-js.md JS-R-04): the
 * `agentspaces:` subtree of a Java fleet YAML parses, with Java-only keys
 * ignored and the Node-only `ordered-logs` block read; `startFleet` brings
 * up a host with an ordered log over a file store under the file's
 * directory and stops it; the CLI's `id` prints a stable PeerID, and `run`
 * refuses a file with no groups.
 */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Identity, Peer, groupIdFromFounding } from "@agentspaces/client";
import "@agentspaces/client/node";
import { parseFleet, startFleet } from "../src/fleet.js";
import { main } from "../src/cli.js";

const FLEET = `
agentspaces:
  keystore: keys
  bind: 127.0.0.1:0
  tick-millis: 50
  security:
    profile: dev-local
  transport:
    ws:
      bind: 127.0.0.1:0
      allowed-origins: [ "https://app.example" ]
  groups:
    - name: council
      founding: council-v1
      seeds: 127.0.0.1:7460, 127.0.0.1:7461
      spaces:
        - { name: tasks, settle-window-millis: 200 }
        - { name: votes }
      ordered-logs:
        - space: tasks
          members: [ zAlpha, zBeta ]
    - name: side
      group-id: zSelfCertifying
      seeds: [ "ws://127.0.0.1:7462/aspace" ]
`;

test("the agentspaces: subtree of a Java fleet file parses, Java-only keys ignored", () => {
  const fleet = parseFleet(FLEET);
  assert.equal(fleet.keystore, "keys");
  assert.equal(fleet.bind, "127.0.0.1:0");
  assert.equal(fleet.tickMillis, 50);
  assert.equal(fleet.residency, "service");
  assert.deepEqual(fleet.ws, { bind: "127.0.0.1:0", allowedOrigins: ["https://app.example"] });
  assert.equal(fleet.groups.length, 2);
  const [council, side] = fleet.groups;
  assert.equal(council.founding, "council-v1");
  assert.deepEqual(council.seeds, [{ host: "127.0.0.1", port: 7460 }, { host: "127.0.0.1", port: 7461 }]);
  assert.deepEqual(council.spaces, ["tasks", "votes"]);
  assert.deepEqual(council.orderedLogs, [{ space: "tasks", members: ["zAlpha", "zBeta"], logDir: null }]);
  assert.equal(side.groupId, "zSelfCertifying");
  assert.deepEqual(side.seeds, [{ host: "127.0.0.1", port: 7462, scheme: "ws", path: "/aspace" }]);
  assert.throws(() => parseFleet("spring:\n  application:\n    name: x\n"), /no 'agentspaces:' section/);
  assert.throws(() => parseFleet("agentspaces:\n  groups:\n    - name: g\n"), /needs 'founding' or 'group-id'/);
  assert.throws(() => parseFleet("agentspaces:\n  bind: x\n"), /names no groups/);
});

test("startFleet brings up the host with its listeners and ordered log, and stops it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "aspace-fleet-"));
  try {
    const fleet = parseFleet(`
agentspaces:
  keystore: keys
  bind: 127.0.0.1:0
  tick-millis: 50
  groups:
    - name: council
      founding: council-v1
      spaces: [ tasks ]
      ordered-logs:
        - { space: tasks, members: [] }
`);
    const running = await startFleet(fleet, dir, { log: null });
    try {
      assert.equal(running.hosts.length, 1);
      const host = running.hosts[0];
      assert.equal(host.peer.group, groupIdFromFounding("council-v1"));
      assert.ok(existsSync(join(dir, "keys", "peer.key")), "the keystore was created under the file's directory");
      assert.ok(existsSync(join(dir, "keys", "ordered-log-tasks")), "the log store lives under the keystore by default");
      const address = host.addresses.get("tcp")!;
      const port = Number(address.substring(address.lastIndexOf(":") + 1));
      const peer = new Peer(Identity.generate(), host.peer.group);
      await peer.connect("127.0.0.1", port);
      await new Promise((r) => setTimeout(r, 400));
      peer.pullAds();
      await new Promise((r) => setTimeout(r, 300));
      assert.ok([...peer.ads.values()].some((a) => a.ad["capabilityType"] === "aspace:cap/ordered-log"),
        "the single-member log advertised itself (it leads alone)");
      peer.close();
    } finally {
      await running.stop();
    }
    // The same keystore gives the same identity next time.
    const again = await startFleet(fleet, dir, { log: null });
    assert.equal(again.hosts[0].peer.identity.peerId, running.hosts[0].peer.identity.peerId);
    await again.stop();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the CLI prints a stable id and refuses a bad run", async () => {
  const dir = mkdtempSync(join(tmpdir(), "aspace-cli-"));
  const lines: string[] = [];
  const original = console.log;
  console.log = (line: string) => { lines.push(line); };
  try {
    assert.equal(await main(["id", join(dir, "keys")]), 0);
    assert.equal(await main(["id", join(dir, "keys")]), 0);
    assert.equal(lines.length, 2);
    assert.equal(lines[0], lines[1]);
    assert.match(lines[0], /^z[1-9A-HJ-NP-Za-km-z]+$/);
    assert.equal(await main([]), 2);
    writeFileSync(join(dir, "bad.yaml"), "agentspaces:\n  bind: 127.0.0.1:0\n");
    await assert.rejects(main(["run", join(dir, "bad.yaml")]), /names no groups/);
  } finally {
    console.log = original;
    rmSync(dir, { recursive: true, force: true });
  }
});
