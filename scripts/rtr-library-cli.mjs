#!/usr/bin/env node
// Command-line access to Eyas's RTR script library (lib/eyas-tools/rtr), for
// the /verify-patch and /audit-remediations skills.
//
//   node scripts/rtr-library-cli.mjs verify <script_id> [<script_id> ...]
//       Render each patch script with representative params, check the
//       output is pure ASCII, and probe its Spotlight pattern for shadowing.
//   node scripts/rtr-library-cli.mjs match < triples.json
//       stdin: [{vendor, product, os}] → stdout: [script_id | null]
//
// Re-spawns itself under tsx so it can import the TypeScript library.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.RTR_CLI_CHILD) {
  const r = spawnSync(
    process.execPath,
    [path.join(root, "node_modules/tsx/dist/cli.mjs"), fileURLToPath(import.meta.url), ...process.argv.slice(2)],
    { cwd: root, stdio: "inherit", env: { ...process.env, RTR_CLI_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

const lib = await import(pathToFileURL(path.join(root, "lib/eyas-tools/rtr/library.ts")).href);
const [cmd, ...args] = process.argv.slice(2);

// Representative params for scripts whose required params have no default.
// url + product have no default on purpose (the generic installer's security
// boundary); omitting sha256 exercises its louder UNVERIFIED banner.
const DEFAULT_PARAMS = {
  "win-update-install": { reboot: "never" },
  "win-dotnet-framework-update": { reboot: "never" },
  "app-temurin": { version: "21" },
  "app-office": { channel: "current" },
  "linux-pkg-upgrade": { package: "curl" },
  "win-app-install": { url: "https://example.com/app.msi", product: "Example App" },
};

// Best-effort literal probe from a pattern: drop anchors, take the first
// top-level alternative, strip optional groups and parens.
function firstAlt(pat) {
  if (!pat) return "";
  let inner = pat.replace(/^\(\?i\)/, "").replace(/^\^|\$$/g, "").replace(/\\\./g, ".");
  inner = inner.split("|")[0];
  inner = inner.replace(/\([^)]*\)\?/g, "");
  return inner.replace(/[()]/g, "");
}

if (cmd === "verify") {
  if (args.length === 0) {
    console.error("usage: rtr-library-cli.mjs verify <script_id> [<script_id> ...]");
    process.exit(2);
  }
  let failed = 0;
  for (const sid of args) {
    const spec = lib.findById("patching", sid);
    if (!spec) {
      console.log(`[FAIL] ${sid}: not in manifest`);
      failed++;
      continue;
    }
    let plan;
    try {
      plan = lib.resolvePlan("patching", sid, DEFAULT_PARAMS[sid] ?? {});
    } catch (e) {
      console.log(`[FAIL] ${sid}: resolvePlan -> ${e instanceof Error ? e.message : String(e)}`);
      failed++;
      continue;
    }
    const nonAscii = [...plan.rendered].filter((c) => c.codePointAt(0) > 127).length;
    if (nonAscii > 0) failed++;
    console.log(
      `[${nonAscii === 0 ? "OK" : "FAIL"}] ${sid}: ${Buffer.byteLength(plan.rendered)}B, ` +
        `runtime=${plan.expected_runtime_minutes}m, reboot=${plan.reboot_risk}, non-ascii=${nonAscii}`,
    );
    const sm = spec.spotlight_match;
    if (sm) {
      // Probe mismatches are informational (complex patterns don't roundtrip);
      // real shadowing shows up in /audit-remediations against live data.
      const v = firstAlt(sm.vendor_pattern ?? "");
      const p = firstAlt(sm.product_pattern ?? "");
      const m = lib.matchRemediation(v, p, spec.os);
      const id = m ? m.id : null;
      const note = id === sid ? "(OK)" : "(probe didn't roundtrip; verify with real Spotlight strings)";
      console.log(`      spotlight probe vendor='${v}' product='${p}' -> ${id} ${note}`);
    }
  }
  console.log();
  if (failed) {
    console.log(`FAILED: ${failed} issue(s)`);
    process.exit(1);
  }
  console.log("All passed.");
} else if (cmd === "match") {
  const triples = JSON.parse(readFileSync(0, "utf8"));
  const out = triples.map((t) => {
    const m = lib.matchRemediation(String(t.vendor ?? ""), String(t.product ?? ""), t.os ?? null);
    return m ? m.id : null;
  });
  process.stdout.write(JSON.stringify(out));
} else {
  console.error("usage: rtr-library-cli.mjs verify <ids...> | match < triples.json");
  process.exit(2);
}
