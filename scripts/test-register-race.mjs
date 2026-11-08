// Regression test for first-run registration (lib/auth/store.ts registerWith):
// of two concurrent submissions only one persists configuration, and a failed
// persist releases the claim so registration can be retried.
//
// Uses a throwaway FALCON_DATA_DIR; never touches data/.
// Run as:  npm run test:register-race   (spawns this under tsx)

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

if (!process.env.REGISTER_RACE_CHILD) {
  const dir = mkdtempSync(join(tmpdir(), "register-race-"));
  const res = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", import.meta.filename],
    {
      env: {
        ...process.env,
        REGISTER_RACE_CHILD: "1",
        FALCON_DATA_DIR: dir,
        AUTH_SESSION_SECRET: "test-secret-test-secret-test-secret-0123456789",
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
  console.log("\nAll register-race checks passed.");
  process.exit(0);
}

await runChild();

async function runChild() {
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
  const store = await imp("lib/auth/store.ts");

  let failed = 0;
  const check = (label, ok, detail) => {
    if (ok) console.log(`  ok  ${label}`);
    else {
      console.log(`  FAIL ${label}${detail ? ` — ${detail}` : ""}`);
      failed++;
    }
  };

  // A failed persist releases the claim.
  const boom = await store
    .registerWith("first-password-123", async () => {
      throw new Error("disk full");
    })
    .then(() => null, (e) => e);
  check("persist failure is reported", boom?.message === "disk full", String(boom));
  check("claim released after persist failure", (await store.isRegistered()) === false);

  // Two concurrent submissions: exactly one persists.
  const persisted = [];
  const attempt = (who) =>
    store
      .registerWith(`password-of-${who}-123`, async () => {
        await new Promise((r) => setTimeout(r, 20));
        persisted.push(who);
      })
      .then(() => "ok", (e) => e.message);
  const results = await Promise.all([attempt("a"), attempt("b")]);
  check("exactly one submission wins", results.filter((r) => r === "ok").length === 1, JSON.stringify(results));
  check("loser is told it's already registered", results.includes("Already registered."), JSON.stringify(results));
  check("only the winner persisted configuration", persisted.length === 1, JSON.stringify(persisted));
  const winner = results[0] === "ok" ? "a" : "b";
  check("winner's password verifies", await store.verify(`password-of-${winner}-123`));
  check("loser's password does not", !(await store.verify(`password-of-${winner === "a" ? "b" : "a"}-123`)));

  console.log(`::result:: failed=${failed}`);
}
