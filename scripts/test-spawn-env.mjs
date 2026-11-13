// childProcessEnv() must never hand the app's own secrets to eyas-mcp, and stale inherited Falcon credentials must be stripped
// when the active environment has none.
//
// Uses a throwaway FALCON_DATA_DIR; never touches data/.
// Run as:  npm run test:spawn-env   (spawns this under tsx)

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

if (!process.env.SPAWN_ENV_CHILD) {
  const dir = mkdtempSync(join(tmpdir(), "spawn-env-"));
  const res = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", import.meta.filename],
    {
      env: {
        ...process.env,
        SPAWN_ENV_CHILD: "1",
        FALCON_DATA_DIR: dir,
        AUTH_SESSION_SECRET: "test-secret-test-secret-test-secret-0123456789",
        ANTHROPIC_API_KEY: "sk-ant-test-not-real",
        ANTHROPIC_AUTH_TOKEN: "gateway-token-not-real",
        AIDR_DEBUG: "1",
        SCHEDULER_TOKEN: "sched-not-real",
        GITHUB_TOKEN: "gh-not-real",
        OUTBOUND_WEBHOOK_URL: "https://hooks.example.com/x",
        FALCON_MCP_API_KEY: "mcp-key-not-real",
        FALCON_CLIENT_SECRET: "stale-inherited-secret",
        FALCON_MCP_READ_ONLY: "true",
      },
      encoding: "utf8",
    },
  );
  rmSync(dir, { recursive: true, force: true });
  process.stdout.write(res.stdout ?? "");
  if (res.stderr && res.stderr.trim()) process.stderr.write(res.stderr);
  const m = (res.stdout ?? "").match(/::result:: failed=(\d+)/);
  const failed = m ? Number(m[1]) : 1;
  if (failed) {
    console.log(`\n${failed} check(s) failed`);
    process.exit(1);
  }
  console.log("\nAll spawn-env checks passed.");
  process.exit(0);
}

const Module = (await import("node:module")).default;
const stubPath = join(process.cwd(), "node_modules/next/dist/compiled/server-only/empty.js");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === "server-only") return stubPath;
  return origResolve.call(this, request, ...rest);
};
const { pathToFileURL } = await import("node:url");
const imp = (rel) => import(pathToFileURL(join(process.cwd(), rel)).href);
const { runMigrations } = await imp("lib/db/migrate.ts");
runMigrations();
const { childProcessEnv } = await imp("lib/config/spawn-env.ts");

let failed = 0;
const check = (label, ok, detail) => {
  if (ok) console.log(`  ok  ${label}`);
  else {
    console.log(`  FAIL ${label}${detail ? ` — ${detail}` : ""}`);
    failed++;
  }
};

const env = childProcessEnv();
for (const key of [
  "AUTH_SESSION_SECRET",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "AIDR_DEBUG",
  "SCHEDULER_TOKEN",
  "GITHUB_TOKEN",
  "OUTBOUND_WEBHOOK_URL",
  "FALCON_MCP_API_KEY",
  "FALCON_MCP_READ_ONLY",
]) {
  check(`${key} is not passed to children`, !(key in env));
}
check("stale inherited FALCON_CLIENT_SECRET is stripped", !("FALCON_CLIENT_SECRET" in env));
check("FALCON_DATA_DIR still passes through", env.FALCON_DATA_DIR === process.env.FALCON_DATA_DIR);
check("PATH still passes through", Boolean(env.PATH ?? env.Path));

console.log(`::result:: failed=${failed}`);
