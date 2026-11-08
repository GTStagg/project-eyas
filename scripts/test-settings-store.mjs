#!/usr/bin/env node
// Smoke test for lib/config/store.ts — the DB-backed settings store.
//
// History: this file used to exercise the legacy JSON-file migration
// (config.json / environments.json → settings.json). The 0.3.0 cut moved
// all runtime config into data/eyas.db (SQLite, column-encrypted) and the
// store no longer touches the filesystem, so those scenarios tested code
// that no longer exists. This rewrite covers the invariants the store
// ACTUALLY has now:
//   1. fresh boot synthesizes one empty "Default" env (version 2);
//   2. mutateSettings round-trips through the DB + emits an audit row;
//   3. the settings-write + audit-append commit ATOMICALLY — a failed
//      audit append rolls back the settings change AND leaves the cache
//      unadvanced (the 2026-06-08 atomicity fix; see audit_followups_2026_06);
//   4. the DB file is mode 0600.
//
// Single process, single temp DB. The store's in-memory cache and the DB
// handle are both globalThis-pinned for the process, so we use ONE temp
// data dir throughout and call invalidateSettingsCache() to force reloads.
//
// Run as:  npm run test:settings-store   (spawns this under tsx)

import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

if (!process.env.SETTINGS_TEST_CHILD) {
  // Parent — spawn the child under tsx so the .ts source loads without a
  // build step (same convention as scripts/test-ir-run-analysis.mjs).
  const dir = mkdtempSync(join(tmpdir(), "settings-store-"));
  const env = {
    ...process.env,
    SETTINGS_TEST_CHILD: "1",
    FALCON_DATA_DIR: dir,
    // 32+ chars — required by lib/db/crypto.ts to derive the column key.
    AUTH_SESSION_SECRET: "test-secret-test-secret-test-secret-0123456789",
  };
  // Strip ambient credentials so the fresh-boot scenario gets a clean slate.
  for (const k of [
    "FALCON_CLIENT_ID",
    "FALCON_CLIENT_SECRET",
    "FALCON_BASE_URL",
    "FALCON_MEMBER_CID",
    "FALCON_QUARANTINE_GROUP_ID",
    "FALCON_SHADOW_AI_BANNED_GROUP_ID",
  ]) {
    delete env[k];
  }
  const res = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", import.meta.filename],
    { env, encoding: "utf8" },
  );
  process.stdout.write(res.stdout);
  if (res.stderr.trim()) process.stderr.write(res.stderr);
  rmSync(dir, { recursive: true, force: true });
  const m = res.stdout.match(/::result:: failed=(\d+)/);
  const failed = m ? Number(m[1]) : 1;
  if (failed) {
    console.log(`\n${failed} check(s) failed`);
    process.exit(1);
  }
  console.log("\nAll settings-store checks passed.");
  process.exit(0);
}

// ───────────────────────────────────────────────────── child runner
await runChild();

async function runChild() {
  // Patch the CJS resolver so "server-only" loads to Next's bundled stub
  // (the store and the whole db/ chain import it).
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
  const { rawDb } = await imp("lib/db/client.ts");
  const store = await imp("lib/config/store.ts");

  let failed = 0;
  const check = (label, ok, detail) => {
    if (ok) console.log(`  ok  ${label}`);
    else {
      console.log(`  FAIL ${label}${detail ? ` — ${detail}` : ""}`);
      failed++;
    }
  };

  // Build the schema in the temp DB.
  runMigrations();

  // ── 1. fresh boot ────────────────────────────────────────────────
  const fresh = store.getSettings();
  check("fresh boot is version 2", fresh.version === 2);
  check("fresh boot synthesizes one env", fresh.environments.length === 1);
  check("synthesized env named Default", fresh.environments[0].name === "Default");
  check("synthesized env has no falcon creds", !fresh.environments[0].falcon.clientId);
  check("active_id matches synthesized env", fresh.active_id === fresh.environments[0].id);

  // ── 2. mutateSettings round-trips + audits ───────────────────────
  const newEnvId = store.newId();
  await store.mutateSettings((s) => ({
    ...s,
    environments: [
      ...s.environments,
      { id: newEnvId, name: "Lab", falcon: { clientId: "LAB-ID", clientSecret: "LAB-SEC" } },
    ],
  }));

  store.invalidateSettingsCache();
  const afterAdd = store.getSettings();
  check("env added (cache invalidated, reloaded from DB)", afterAdd.environments.length === 2);
  const lab = afterAdd.environments.find((e) => e.id === newEnvId);
  check("added env persisted with name", lab?.name === "Lab");
  check("added env clientId round-trips through encryption", lab?.falcon.clientId === "LAB-ID");

  const audit = await store.readAuditLog(50);
  const createRow = audit.find((a) => a.op === "env_create" && a.env_id === newEnvId);
  check("env_create audit row written", Boolean(createRow));

  // ── 3. atomicity: a failed audit append rolls back the whole write ─
  // Rename settings_audit away so appendAuditRows' INSERT throws mid
  // outer-transaction. A non-atomic store would leave the env deleted on
  // disk (persistToDb already ran) and/or advance the cache. The fix wraps
  // persistToDb + appendAuditRows in ONE transaction and only sets the
  // cache after it commits.
  const beforeCount = store.getSettings().environments.length;
  rawDb().exec("ALTER TABLE settings_audit RENAME TO settings_audit_bak");
  let threw = false;
  try {
    await store.mutateSettings((s) => ({
      ...s,
      // a real, audit-producing change: drop the Lab env
      environments: s.environments.filter((e) => e.id !== newEnvId),
      active_id: s.environments[0].id,
    }));
  } catch {
    threw = true;
  }
  rawDb().exec("ALTER TABLE settings_audit_bak RENAME TO settings_audit");

  check("mutateSettings rejected when audit append fails", threw);
  check(
    "in-memory cache did NOT advance past the failed write",
    store.getSettings().environments.length === beforeCount,
  );
  store.invalidateSettingsCache();
  check(
    "DB rolled back — env still present after failed write",
    store.getSettings().environments.some((e) => e.id === newEnvId),
  );

  // store recovers: a normal write still works after the table is restored
  await store.mutateSettings((s) => ({ ...s, anthropic: { model: "claude-opus-4-8" } }));
  store.invalidateSettingsCache();
  check("store recovers after restore", store.getSettings().anthropic?.model === "claude-opus-4-8");

  // ── 4. DB file mode 0600 ─────────────────────────────────────────
  const dbPath = join(process.env.FALCON_DATA_DIR, "eyas.db");
  const mode = statSync(dbPath).mode & 0o777;
  check("eyas.db is mode 0600", mode === 0o600, `got 0${mode.toString(8)}`);
  for (const suffix of ["-wal", "-shm"]) {
    let m = null;
    try {
      m = statSync(dbPath + suffix).mode & 0o777;
    } catch {
      // not present — nothing to leak
    }
    check(`eyas.db${suffix} is mode 0600 (when present)`, m === null || m === 0o600, `got 0${m?.toString(8)}`);
  }

  console.log(`::result:: failed=${failed}`);
  process.exit(0);
}
