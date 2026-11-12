#!/usr/bin/env node
// Pure-function tests for lib/identity/detections.ts: the search arguments and
// the open-only / no-policy-match rules applied to native detection rows.
// Run as: node scripts/test-identity-detections.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.IDENTITY_DETECTIONS_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-identity-detections.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, IDENTITY_DETECTIONS_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const { identityDetectionSearchArgs, shapeIdentityDetections } = await import(
  pathToFileURL(path.join(root, "lib/identity/detections.ts")).href
);

const NOW = new Date("2026-11-11T12:00:00.000Z");

test("default search: last 7 days, open only, newest first", () => {
  const a = identityDetectionSearchArgs({}, NOW);
  assert.equal(
    a.filter,
    "product:'idp'+created_timestamp:>'2026-11-04T12:00:00Z'+status:['new','reopened','in_progress']",
  );
  assert.equal(a.limit, 50);
  assert.equal(a.sort, "created_timestamp.desc");
});

test("includeClosed drops the status clause; hours and limit are clamped", () => {
  const a = identityDetectionSearchArgs({ hours: 0, limit: 9999, includeClosed: true }, NOW);
  assert.equal(a.filter, "product:'idp'+created_timestamp:>'2026-11-11T11:00:00Z'");
  assert.equal(a.limit, 500);
  assert.equal(identityDetectionSearchArgs({ limit: 0 }, NOW).limit, 1);
});

const rows = [
  { composite_id: "c1", tactic: "Credential Access", user_name: "alice", device: { big: "record" } },
  { composite_id: "c2", tactic: "", display_name: "Policy rule match" },
  { composite_id: "c3", display_name: "Policy rule match" },
  null,
  "junk",
];

test("policy-match rows (empty tactic) are dropped by default", () => {
  const out = shapeIdentityDetections(rows);
  assert.deepEqual(out.map((d) => d.composite_id), ["c1"]);
});

test("includePolicyMatches keeps them, with tactic normalized to ''", () => {
  const out = shapeIdentityDetections(rows, { includePolicyMatches: true });
  assert.deepEqual(out.map((d) => d.composite_id), ["c1", "c2", "c3"]);
  assert.equal(out[2].tactic, "");
});

test("only the identity fields are kept", () => {
  const [d] = shapeIdentityDetections(rows);
  assert.deepEqual(d, { composite_id: "c1", tactic: "Credential Access", user_name: "alice" });
});
