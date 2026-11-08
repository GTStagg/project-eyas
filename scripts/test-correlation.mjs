#!/usr/bin/env node
// Pure-function tests for lib/correlation/health.ts.
// Run as: node scripts/test-correlation.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.CORRELATION_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-correlation.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, CORRELATION_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const { normalizeCorrelationRules, summarizeCorrelation, renderCorrelationContext } = await import(
  path.join(root, "lib/correlation/health.ts")
);

const NOW = Date.parse("2026-06-05T00:00:00Z");
const daysAgo = (n) => new Date(NOW - n * 86_400_000).toISOString();

test("normalize reads rule_id or id, and mitre pairs", () => {
  const rules = normalizeCorrelationRules([
    {
      rule_id: "r1",
      name: "Suspicious PowerShell",
      status: "active",
      severity: 70,
      mitre_attack: [{ tactic_id: "TA0002", technique_id: "T1059" }],
    },
    { id: "r2", name: "Old rule", status: "inactive", severity: 30, mitre: ["T1003"] },
    42,
  ]);
  assert.equal(rules.length, 2);
  assert.equal(rules[0].id, "r1");
  assert.deepEqual(rules[0].tactics, ["TA0002"]);
  assert.deepEqual(rules[0].techniques, ["T1059"]);
  assert.equal(rules[1].id, "r2");
  assert.deepEqual(rules[1].techniques, ["T1003"]);
});

test("summarize buckets status, severity, mitre, staleness", () => {
  const rules = normalizeCorrelationRules([
    { id: "a", status: "active", severity: 90, mitre_attack: [{ tactic_id: "TA1", technique_id: "T1" }], last_updated_on: daysAgo(10) },
    { id: "b", status: "active", severity: 50, mitre_attack: [{ tactic_id: "TA2", technique_id: "T2" }], last_updated_on: daysAgo(200) }, // stale
    { id: "c", status: "inactive", severity: 70, last_updated_on: daysAgo(5) },
  ]);
  const h = summarizeCorrelation(rules, NOW);
  assert.equal(h.total, 3);
  assert.equal(h.byStatus.active, 2);
  assert.equal(h.byStatus.inactive, 1);
  assert.equal(h.bySeverity.critical, 1); // 90
  assert.equal(h.bySeverity.medium, 1); // 50
  assert.equal(h.bySeverity.high, 1); // 70
  assert.equal(h.mitre.tactics.length, 2);
  // stale: only active rule 'b' at 200d
  assert.equal(h.stale.length, 1);
  assert.equal(h.stale[0].id, "b");
  // inactive list carries 'c'
  assert.equal(h.inactive.length, 1);
  assert.equal(h.inactive[0].id, "c");
});

test("inactive rules are never counted as stale (staleness is active-only)", () => {
  const rules = normalizeCorrelationRules([
    { id: "x", status: "inactive", severity: 50, last_updated_on: daysAgo(999) },
  ]);
  const h = summarizeCorrelation(rules, NOW);
  assert.equal(h.stale.length, 0);
});

test("render produces labeled context", () => {
  const h = summarizeCorrelation(
    normalizeCorrelationRules([
      { id: "a", status: "active", severity: 90, mitre_attack: [{ tactic_id: "TA1", technique_id: "T1" }], last_updated_on: daysAgo(300) },
    ]),
    NOW,
  );
  const txt = renderCorrelationContext(h);
  assert.match(txt, /Deterministic correlation-rule summary/);
  assert.match(txt, /active 1, inactive 0/);
  assert.match(txt, /Stale active rules/);
});
