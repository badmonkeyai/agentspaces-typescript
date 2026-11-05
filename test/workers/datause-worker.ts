// A TypeScript agent that declares its data use (S1-G-09): joins a fleet by seed and founding, binds an
// `agent` class carrying `dataUse`, and stays bound for maxSeconds so the console's bridge mirrors it.
//   node build/test/workers/datause-worker.js <host> <port> <founding> [maxSeconds]
import "../../src/node/index.js";
import { Identity, groupIdFromFounding } from "../../src/identity.js";
import { Peer } from "../../src/peer.js";
import { Binder, agent, dataUse, spaceNotify } from "../../src/agents.js";
import { entry } from "../../src/space.js";
import { rules } from "../../src/console.js";

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
// S3-H-06: the console's rule entries read as data, once the group has settled
const until = Date.now() + Number(maxSeconds ?? 60) * 1000;
let reported = false;
while (Date.now() < until) {
  await new Promise((r) => setTimeout(r, 1000));
  if (!reported) {
    const read = rules(peer);
    if (Object.values(read).every((v) => v.length > 0)) {
      console.log(JSON.stringify({ rules: Object.fromEntries(Object.entries(read).map(([k, v]) => [k, v.length])),
        sample: (read.Constraint[0] as { template?: string }).template ?? "" }));
      reported = true;
    }
  }
}
await bound.close();
peer.close();
process.exit(0);
