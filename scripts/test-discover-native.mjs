#!/usr/bin/env node
// Pure-function tests for the native Discover path: lib/mcp/native-shape.ts
// (result shaping) and lib/discover/inventory.ts (asset merge, nested host).
// Run as: node scripts/test-discover-native.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.DISCOVER_NATIVE_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-discover-native.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, DISCOVER_NATIVE_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

// native-shape.ts imports parse.ts, which imports "server-only" (a throwing
// module outside RSC). Redirect it to Next's empty stub before importing.
import Module from "node:module";
const stub = path.join(root, "node_modules/next/dist/compiled/server-only/empty.js");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === "server-only") return stub;
  return origResolve.call(this, request, ...rest);
};

const { shapeNativePayload } = await import(pathToFileURL(path.join(root, "lib/mcp/native-shape.ts")).href);
const { normalizeAssetPair, normalizeApplications, summarizeDiscover } = await import(
  pathToFileURL(path.join(root, "lib/discover/inventory.ts")).href
);

const envelope = (results, total) =>
  JSON.stringify({ results, pagination: { total, offset: 0, limit: results.length, next: null } });

test("pagination envelope → rows and total", () => {
  const p = shapeNativePayload(envelope([{ id: "a" }, { id: "b" }], 42));
  assert.equal(p.ok, true);
  assert.equal(p.count, 2);
  assert.equal(p.total, 42);
});

test("bare error dict → ok:false with the message", () => {
  const p = shapeNativePayload(
    JSON.stringify({ error: "Failed to search", details: { status_code: 500, body: { errors: [{ message: "boom" }] } } }),
  );
  assert.equal(p.ok, false);
  assert.match(String(p.error), /boom|Failed to search/);
});

test("FQL-error wrapper without pagination is an error, not a row", () => {
  const p = shapeNativePayload(
    JSON.stringify({
      results: [{ error: "Failed to search managed assets", details: { status_code: 400 } }],
      filter_used: "x",
      fql_guide: "...",
      hint: "...",
    }),
  );
  assert.equal(p.ok, false);
});

test("403 inside the FQL wrapper → scope_pending", () => {
  const p = shapeNativePayload(
    JSON.stringify({ results: [{ error: "Permission denied", details: { status_code: 403 } }], fql_guide: "..." }),
  );
  assert.deepEqual(p, { ok: true, scope_pending: true });
});

test("denial wording inside real data is NOT a scope denial", () => {
  const p = shapeNativePayload(
    envelope([{ id: "1", name: "Unauthorized Access Denied Monitor", installation_paths: ["C:\\access denied\\x.exe"] }], 1),
  );
  assert.equal(p.ok, true);
  assert.equal(p.scope_pending, undefined);
  assert.equal(p.count, 1);
});

test("asset pair merges rows, sums totals and keeps per-type totals", () => {
  const m = shapeNativePayload(envelope([{ id: "m1", hostname: "a", entity_type: "managed" }], 900));
  const u = shapeNativePayload(envelope([{ id: "u1", hostname: "b" }], 300));
  const e = normalizeAssetPair(m, u);
  assert.equal(e.total, 1200);
  assert.deepEqual(e.breakdown, { managed: 900, unmanaged: 300 });
  assert.equal(e.items.length, 2);
  assert.equal(e.items[1].entityType, "unmanaged"); // filled from the tool when the row lacks it
  const s = summarizeDiscover({ assets: e, applications: { total: 0, items: [] }, accounts: { total: 0, items: [] } });
  assert.equal(s.assets.managed, 900);
  assert.equal(s.assets.unmanaged, 300);
});

test("one asset call failing keeps the other's rows, drops the breakdown", () => {
  const m = shapeNativePayload(envelope([{ id: "m1" }], 900));
  const e = normalizeAssetPair(m, { ok: false, error: "boom" });
  assert.equal(e.error, "boom");
  assert.equal(e.breakdown, undefined);
  assert.equal(e.items.length, 1);
  const s = summarizeDiscover({ assets: e, applications: { total: 0, items: [] }, accounts: { total: 0, items: [] } });
  assert.equal(s.assets.managed, 1); // sample count, not a fake tenant total
});

test("both asset calls scope-denied → scopePending", () => {
  const e = normalizeAssetPair({ ok: true, scope_pending: true }, { ok: true, scope_pending: true });
  assert.equal(e.scopePending, true);
});

test("applications read the nested host name", () => {
  const e = normalizeApplications(
    shapeNativePayload(envelope([{ id: "x", name: "App", host: { id: "h", hostname: "HOST-1" } }], 172199)),
  );
  assert.equal(e.total, 172199);
  assert.equal(e.items[0].hostHostname, "HOST-1");
});
