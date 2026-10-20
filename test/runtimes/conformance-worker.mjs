// JS-P-09 in workerd: a module worker whose GET / answers the conformance results as JSON.
import { runConformance } from "../../build/test/browser/conformance.js";
import golden from "../golden.json" with { type: "json" };
import social from "../social-golden.json" with { type: "json" };

export default {
  async fetch() {
    return new Response(JSON.stringify(await runConformance(golden, social)),
      { headers: { "content-type": "application/json" } });
  },
};
