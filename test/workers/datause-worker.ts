// A TypeScript agent that declares its data use (S1-G-09): joins a fleet by seed and founding, binds an
// `agent` class carrying `dataUse`, and stays bound for maxSeconds so the console's bridge mirrors it.
//   node build/test/workers/datause-worker.js <host> <port> <founding> [maxSeconds]
import "../../src/node/index.js";
import { Identity, groupIdFromFounding } from "../../src/identity.js";
import { Peer } from "../../src/peer.js";
import { Binder, agent, dataUse, spaceNotify } from "../../src/agents.js";
import { entry } from "../../src/space.js";

@entry("https://badmonkey.ai/console#Finding")
class Finding {
  constructor(readonly text = "") {}
}

@dataUse({ reads: ["claims.policies"], source: "jdbc:postgresql://claims-ts/policies", sensitivity: "internal", freshness: "PT5M" })
@agent("ts-coverage", { description: "Checks coverage from TypeScript" })
class TsCoverage {
  @spaceNotify(Finding, "catalog")
  onFinding(_finding: Finding): void {
    // observes only
  }
}

const [host, port, founding, maxSeconds] = process.argv.slice(2);
const peer = new Peer(Identity.generate(), groupIdFromFounding(founding));
await peer.connect(host, Number(port));
await new Promise((r) => setTimeout(r, 1000));
const bound = new Binder(peer, { agentName: "ts-coverage", cardTtl: "PT2M" }).bind(new TsCoverage());
console.log(JSON.stringify({ ok: bound.dataUse.length > 0, peerId: peer.identity.peerId, entries: bound.dataUse }));
await new Promise((r) => setTimeout(r, Number(maxSeconds ?? 60) * 1000));
await bound.close();
peer.close();
process.exit(0);
