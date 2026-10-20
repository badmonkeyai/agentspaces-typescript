// JS-P-09 outside Node and browsers: Deno and Bun run this file directly and it
// prints one JSON line with the conformance results. The workerd run bundles
// conformance-worker.mjs instead (a default export with fetch would make Bun serve).
import { runConformance } from "../../build/test/browser/conformance.js";
import golden from "../golden.json" with { type: "json" };
import social from "../social-golden.json" with { type: "json" };

console.log(JSON.stringify(await runConformance(golden, social)));
