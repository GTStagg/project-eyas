#!/usr/bin/env node
// Pure-function tests for lib/dataprotection/posture.ts.
// Run as: node scripts/test-data-protection.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.DP_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-data-protection.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, DP_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const {
  normalizePolicies,
  normalizeContentPatterns,
  classificationNames,
  summarizeDataProtection,
  renderDataProtectionContext,
} = await import(path.join(root, "lib/dataprotection/posture.ts"));

test("normalizePolicies attaches platform + coerces booleans", () => {
  const pols = normalizePolicies(
    [
      { name: "Default", is_enabled: true, is_default: true, precedence: 1 },
      { name: "Custom DLP", is_enabled: "true", is_default: false, precedence: 2 },
      null,
    ],
    "win",
  );
  assert.equal(pols.length, 2);
  assert.equal(pols[0].platform, "win");
  assert.equal(pols[0].isEnabled, true);
  assert.equal(pols[1].isEnabled, true); // "true" coerced
  assert.equal(pols[1].isDefault, false);
});

test("summarize counts enabled/disabled/custom + tallies patterns", () => {
  const policies = [
    ...normalizePolicies([{ name: "Default", is_enabled: true, is_default: true }], "win"),
    ...normalizePolicies([{ name: "Custom", is_enabled: true, is_default: false }], "win"),
    ...normalizePolicies([{ name: "Off", is_enabled: false, is_default: false }], "mac"),
  ];
  const patterns = normalizeContentPatterns([
    { name: "SSN", category: "PII", region: "US" },
    { name: "PAN", category: "Financial", region: "ALL" },
    { name: "Custom1", category: "Custom", region: "EU" },
  ]);
  const classes = classificationNames([{ name: "Confidential" }, { name: "Secret" }, 7]);
  const s = summarizeDataProtection(policies, classes, patterns);
  assert.equal(s.policyCounts.total, 3);
  assert.equal(s.policyCounts.enabled, 2);
  assert.equal(s.policyCounts.disabled, 1);
  assert.equal(s.policyCounts.enabledNonDefault, 1); // "Custom" enabled non-default
  assert.equal(s.classificationCount, 2);
  assert.equal(s.contentPatternCount, 3);
  assert.equal(s.patternsByCategory.PII, 1);
  assert.equal(s.patternsByCategory.Financial, 1);
  assert.equal(s.patternsByRegion.US, 1);
});

test("summarize handles all-empty input", () => {
  const s = summarizeDataProtection([], [], []);
  assert.equal(s.policyCounts.total, 0);
  assert.equal(s.contentPatternCount, 0);
  assert.deepEqual(s.patternsByCategory, {});
});

test("render produces labeled context", () => {
  const s = summarizeDataProtection(
    normalizePolicies([{ name: "Default", is_enabled: true, is_default: true }], "win"),
    ["Confidential"],
    normalizeContentPatterns([{ name: "SSN", category: "PII", region: "US" }]),
  );
  const txt = renderDataProtectionContext(s);
  assert.match(txt, /Data Protection configuration summary/);
  assert.match(txt, /Policies: 1 total/);
  assert.match(txt, /win · Default/);
});
