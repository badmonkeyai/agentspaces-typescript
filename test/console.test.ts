// The console records as data (enterprise platform S3-H-06): the helper names the console's types, decodes what
// the wire carries, and knows the space each record lives in.
import { test } from "node:test";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dumps, loads } from "../src/cbor.js";
import assert from "node:assert/strict";
import { CONSOLE_SPACES, Constraint, AgentConfiguration, JuryDecision, Vocabulary, consoleType, rules, PromptRef, renderPrompt } from "../src/console.js";
import { Template, fromPayload, schemaOf } from "../src/space.js";
import { Identity } from "../src/identity.js";
import { Peer } from "../src/peer.js";

test("the console types are named by the console namespace", () => {
  assert.equal(schemaOf(Constraint), "https://badmonkey.ai/console#Constraint");
  assert.equal(consoleType("JuryDecision"), schemaOf(JuryDecision));
  assert.equal(new Template(Vocabulary).schema, "https://badmonkey.ai/console#Vocabulary");
});

test("a wire payload decodes into an instance carrying the fields", () => {
  const c = fromPayload(Constraint, { schemaVersion: 1, book: "rb-claims", template: "precedence", a: "DamageReport",
    b: "PaymentOrder", enforcement: ["gate"], jury: { quorum: 2 } });
  assert.ok(c instanceof Constraint);
  assert.deepEqual([c.book, c.template, c.a, c.b, c.enforcement, c.jury],
    ["rb-claims", "precedence", "DamageReport", "PaymentOrder", ["gate"], { quorum: 2 }]);
  const a = fromPayload(AgentConfiguration, { agent: "rule-agent", instance: "rules-1", body: { books: ["rb-claims"] } });
  assert.deepEqual(a.body, { books: ["rb-claims"] });
});

test("each record names the space the console writes it into", () => {
  assert.deepEqual(CONSOLE_SPACES, { Vocabulary: "constraints", Constraint: "constraints", AgentConfiguration: "policy",
    JuryDecision: "decisions", Finding: "findings" });
});

test("rules pulls each space once and reads through a space", () => {
  const peer = new Peer(Identity.generate(), "g");
  const pulled: string[] = [];
  (peer as unknown as { pullSpace: (s: string) => void }).pullSpace = (s: string) => { pulled.push(s); };
  const read = rules(peer);
  assert.deepEqual(Object.keys(read).sort(), ["AgentConfiguration", "Constraint", "JuryDecision", "Vocabulary"]);
  assert.deepEqual(pulled, ["constraints", "policy", "decisions"]);
  peer.close();
});

test("a prompt ref renders the fallback until the set names it", () => {
  const ref = new PromptRef("correlation/classify", "Compare {left} and {right}.");
  assert.equal(ref.version, 0);
  assert.equal(ref.text, "Compare {left} and {right}.");
  assert.equal(ref.render({ left: "A", right: "B" }), "Compare A and B.");
  assert.deepEqual(ref.hint, ["prompt.correlation/classify", "0"]);
  const live = { group: "claims-fleet", prompts: [{ id: "correlation/classify", version: 3, hash: "sha256:x", kind: "agent-system",
    text: "You compare {left} with {right}. {hint}", variables: [{ name: "left", required: true }, { name: "right", required: true }, { name: "hint" }] }] };
  const inForce = new PromptRef("correlation/classify", "fallback", () => live);
  assert.equal(inForce.version, 3);
  assert.equal(inForce.render({ left: "A", right: "B" }), "You compare A with B. ");
  assert.throws(() => inForce.render({ left: "A" }), /right/);
  assert.equal(renderPrompt("no placeholders", []), "no placeholders");
});

test("every console golden vector round-trips byte for byte", () => {
  // S4-I-14: the console's golden vectors (the canonical CBOR of every console record as the Java codec writes it)
  // decode and re-encode to the same bytes here, so a TypeScript agent that reads a console record and writes it
  // back changes nothing on the wire.
  const here = dirname(fileURLToPath(import.meta.url));
  const vectors = resolve(here, "..", "..", "..", "enterprise-platform", "bma-console-common", "src", "main", "resources", "console-golden.properties");
  if (!existsSync(vectors)) {
    return;   // the platform's console golden vectors are not beside this checkout
  }
  let count = 0;
  for (const line of readFileSync(vectors, "utf8").split("\n")) {
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const eq = line.indexOf("=");
    const name = line.slice(0, eq);
    const raw = Uint8Array.from(Buffer.from(line.slice(eq + 1).trim(), "hex"));
    const decoded = loads(raw);
    assert.ok(decoded instanceof Map || (typeof decoded === "object" && decoded !== null), name);
    assert.ok(Buffer.compare(Buffer.from(dumps(decoded as never)), Buffer.from(raw)) === 0, `${name} re-encodes to different bytes`);
    count++;
  }
  assert.ok(count >= 60);
});
