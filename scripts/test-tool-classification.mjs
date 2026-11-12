// Every Eyas tool (falcon-extras sidecar or lib/eyas-tools) must be classified exactly once: approval-gated
// (REQUIRES_APPROVAL) or reviewed read-only (EXTRAS_READ_ONLY). An
// unclassified tool is gated at runtime as a fail-closed backstop; this test
// catches it at review time instead.
//
// Run as:  npm run test:tool-classification   (spawns this under tsx)

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

if (!process.env.TOOL_CLASS_CHILD) {
  const res = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", import.meta.filename],
    { env: { ...process.env, TOOL_CLASS_CHILD: "1" }, encoding: "utf8" },
  );
  process.stdout.write(res.stdout ?? "");
  if (res.stderr && res.stderr.trim()) process.stderr.write(res.stderr);
  const m = (res.stdout ?? "").match(/::result:: failed=(\d+)/);
  const failed = m ? Number(m[1]) : 1;
  if (failed) {
    console.log(`\n${failed} check(s) failed`);
    process.exit(1);
  }
  console.log("\nAll tool-classification checks passed.");
  process.exit(0);
}

const { pathToFileURL } = await import("node:url");
const { REQUIRES_APPROVAL, EXTRAS_READ_ONLY } = await import(
  pathToFileURL(join(process.cwd(), "lib/mcp/write-tools.ts")).href
);

let failed = 0;
const check = (label, ok, detail) => {
  if (ok) console.log(`  ok  ${label}`);
  else {
    console.log(`  FAIL ${label}${detail ? ` — ${detail}` : ""}`);
    failed++;
  }
};

// Eyas's in-process tools (lib/eyas-tools) follow the same rule.
const { EYAS_TOOLS } = await import(pathToFileURL(join(process.cwd(), "lib/eyas-tools/index.ts")).href);
const eyasNames = new Set(EYAS_TOOLS.map((t) => t.name));

const server = readFileSync(join(process.cwd(), "falcon-extras/server.py"), "utf8");
const registered = new Set(
  [...server.matchAll(/@mcp\.tool\([^)]*\)\s*\n(?:async\s+)?def\s+(extras_\w+)/g)].map((m) => m[1]),
);
const expected = new Set(
  JSON.parse(readFileSync(join(process.cwd(), "falcon-extras/expected_tools.json"), "utf8")).tools.map(
    (t) => (typeof t === "string" ? t : t.name),
  ),
);

// The sidecar registers no tools any more (every tool runs in Eyas); the
// checks below still guard anything it might register again.
check("Eyas serves tools", eyasNames.size > 0, String(eyasNames.size));
const dupes = [...eyasNames].filter((t) => registered.has(t));
check("no tool is served by both Eyas and the sidecar", dupes.length === 0, dupes.join(", "));
const eyasUnclassified = [...eyasNames].filter((t) => !REQUIRES_APPROVAL.has(t) && !EXTRAS_READ_ONLY.has(t));
check("every Eyas tool is classified", eyasUnclassified.length === 0, eyasUnclassified.join(", "));
const unclassified = [...registered].filter((t) => !REQUIRES_APPROVAL.has(t) && !EXTRAS_READ_ONLY.has(t));
check("every registered sidecar tool is classified", unclassified.length === 0, unclassified.join(", "));
const both = [...EXTRAS_READ_ONLY].filter((t) => REQUIRES_APPROVAL.has(t));
check("no tool is both gated and read-only", both.length === 0, both.join(", "));
const staleRo = [...EXTRAS_READ_ONLY].filter((t) => !registered.has(t) && !eyasNames.has(t));
check("read-only list names only registered or Eyas tools", staleRo.length === 0, staleRo.join(", "));
const missingExpected = [...expected].filter((t) => !registered.has(t));
check("expected_tools.json entries are registered", missingExpected.length === 0, missingExpected.join(", "));

console.log(`::result:: failed=${failed}`);
