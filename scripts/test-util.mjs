// Unit tests of the logic in src/util: terminal input (prompt detection, the
// typed-line tracker and echo check, paste and snippet keys, highlighting),
// the dialog queue, listener cleanup, the Docker live-log run, per-profile
// storage keys, what a terminal-only session shows, the update check's
// once-per-launch rule, and the file browser's sizes.
// The modules are TypeScript: esbuild (installed with Vite) bundles each one
// for Node, next to the tests in tests/util, and `node --test` runs them.
// Then the tests in tests/scripts: the repository's own scripts, and the
// Android manifest's properties.
// Usage: npm run test:util
import { build } from "esbuild";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MODULES = ["secretPrompt", "terminalInput", "highlight", "dialogQueue", "tauriEvents", "liveStream", "profileStorage", "terminalOnly", "updateCheck", "formatSize"];
const TESTS = join(ROOT, "tests", "util");
const SCRIPT_TESTS = join(ROOT, "tests", "scripts");

const out = mkdtempSync(join(tmpdir(), "solanum-test-util-"));
let status = 1;
try {
  for (const name of MODULES) {
    await build({
      entryPoints: [join(ROOT, "src", "util", `${name}.ts`)],
      bundle: true,
      format: "esm",
      platform: "node",
      logLevel: "warning",
      outfile: join(out, `${name}.mjs`),
    });
  }
  const tests = readdirSync(TESTS).filter((f) => f.endsWith(".test.mjs"));
  for (const f of tests) copyFileSync(join(TESTS, f), join(out, f));
  status = spawnSync(process.execPath, ["--test", ...tests], { cwd: out, stdio: "inherit" }).status ?? 1;
  const scriptTests = readdirSync(SCRIPT_TESTS)
    .filter((f) => f.endsWith(".test.mjs"))
    .map((f) => join(SCRIPT_TESTS, f));
  const scripts = spawnSync(process.execPath, ["--test", ...scriptTests], { cwd: ROOT, stdio: "inherit" }).status ?? 1;
  status = status || scripts;
} finally {
  rmSync(out, { recursive: true, force: true });
}
process.exit(status);
