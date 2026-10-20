// JS-P-12: the portable core's browser bundle size, minified and gzipped, with
// the budget the build enforces from phase 2 (srad/agentspaces-js.md §4.1).
import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

const BUDGET_GZIP_BYTES = 64 * 1024;
const out = join(mkdtempSync(join(tmpdir(), "aspace-size-")), "core.min.js");
execFileSync(join("node_modules", ".bin", "esbuild"), ["build/src/index.js", "--bundle", "--minify",
  "--format=esm", "--platform=browser", `--outfile=${out}`, "--log-level=error"], { stdio: "inherit" });
const bytes = readFileSync(out);
const gzip = gzipSync(bytes).length;
console.log(`@agentspaces/client browser bundle: ${(bytes.length / 1024).toFixed(1)} KiB minified, `
  + `${(gzip / 1024).toFixed(1)} KiB gzipped (budget ${BUDGET_GZIP_BYTES / 1024} KiB)`);
if (gzip > BUDGET_GZIP_BYTES) {
  console.error("over budget");
  process.exit(1);
}
