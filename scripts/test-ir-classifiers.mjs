#!/usr/bin/env node
// Tests for the IR detection classifiers (lib/eyas-tools/ir/detection-classifiers.ts),
// ported from falcon-extras/ir/test_detection_classifiers.py.
//
// These pure functions decide which post-Phase-1 detections are NEW threats
// vs artifacts of the workflow itself or retrospective IOC backfill. A
// regression here would either over-FP-close real new detections (silent) or
// trigger HOLD on a clean run (loud — but burns a re-run). Both classifiers
// are conservative by design: any uncertainty falls back to "real."
//
// Run as: node scripts/test-ir-classifiers.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.IR_CLASSIFIERS_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-ir-classifiers.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, IR_CLASSIFIERS_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const dc = await import(pathToFileURL(path.join(root, "lib/eyas-tools/ir/detection-classifiers.ts")).href);
const q = await import(pathToFileURL(path.join(root, "lib/eyas-tools/quarantine.ts")).href);

const {
  detectionIsRetrospectiveBackfill,
  detectionIsRetrospectiveIocMatch,
  detectionIsShadowAiIocAudit,
  detectionIsWorkflowSelfTriggered,
} = dc;
const { RTR_PREAMBLE_BASE64 } = q;

// RTR preamble snippet operators see in real cmdlines. Wrapping it so the
// test fixtures match what the production sensor reports.
const PREAMBLE_CMDLINE =
  "powershell.exe -Version 5.1 -s -NoLogo -NoProfile -EncodedCommand " +
  RTR_PREAMBLE_BASE64 +
  " -File C:\\some\\cleanup.ps1";

// ===========================================================================
// detectionIsWorkflowSelfTriggered
// ===========================================================================

test("self triggered via top level cmdline", () => {
  const rec = { cmdline: PREAMBLE_CMDLINE };
  assert.equal(detectionIsWorkflowSelfTriggered(rec), true);
});

test("self triggered via parent cmdline", () => {
  // Detection's own process is a child; parent_details carries the RTR
  // preamble. This is the most common shape — IR cleanup spawns a child
  // that fires PShellMimikatz.
  const rec = {
    cmdline: "C:\\Windows\\System32\\whoami.exe",
    parent_details: { cmdline: PREAMBLE_CMDLINE },
  };
  assert.equal(detectionIsWorkflowSelfTriggered(rec), true);
});

test("self triggered via behaviors cmdline", () => {
  const rec = {
    cmdline: "x.exe",
    behaviors: [{ cmdline: PREAMBLE_CMDLINE }],
  };
  assert.equal(detectionIsWorkflowSelfTriggered(rec), true);
});

test("not self triggered when no preamble anywhere", () => {
  const rec = {
    cmdline: "powershell.exe -EncodedCommand AAA", // different base64
    parent_details: { cmdline: "explorer.exe" },
    behaviors: [{ cmdline: "cmd.exe /c whoami" }],
  };
  assert.equal(detectionIsWorkflowSelfTriggered(rec), false);
});

test("not self triggered when record is empty", () => {
  assert.equal(detectionIsWorkflowSelfTriggered({}), false);
});

test("not self triggered with non string cmdline", () => {
  // Defensive: cmdline can be None, missing, or a non-string. Must not
  // crash; must not falsely classify.
  const rec = {
    cmdline: null,
    parent_details: { cmdline: 12345 }, // non-string
    behaviors: [
      { cmdline: ["a", "b"] }, // list, not string
      { cmdline: PREAMBLE_CMDLINE }, // this one IS the match
    ],
  };
  // Last behavior matches → true
  assert.equal(detectionIsWorkflowSelfTriggered(rec), true);
});

test("self triggered partial base64 does not match", () => {
  // A near-miss with a truncated preamble must NOT classify as self.
  const truncated = PREAMBLE_CMDLINE.replace(RTR_PREAMBLE_BASE64, RTR_PREAMBLE_BASE64.slice(0, -4));
  const rec = { cmdline: truncated };
  assert.equal(detectionIsWorkflowSelfTriggered(rec), false);
});

// ===========================================================================
// detectionIsRetrospectiveIocMatch
// ===========================================================================

// Phase 1 quarantine point used by every retrospective test. Far enough in
// the past that we can write tests against it without flake.
const SINCE_TS = 1_700_000_000.0; // 2023-11-14 22:13:20 UTC

test("retrospective when all underlying ts predate quarantine", () => {
  const rec = {
    network_accesses: [
      { access_timestamp: String(Math.trunc(SINCE_TS - 86400)) }, // 1d before
    ],
    behaviors: [
      { timestamp: "2023-11-13T00:00:00Z" }, // also before SINCE_TS
    ],
  };
  const [isRetro, reason] = detectionIsRetrospectiveIocMatch(rec, SINCE_TS);
  assert.equal(isRetro, true);
  assert.ok(reason);
  assert.match(reason, /predate/);
});

test("not retrospective when any underlying ts is after quarantine", () => {
  const rec = {
    network_accesses: [
      { access_timestamp: String(Math.trunc(SINCE_TS - 60)) },
      { access_timestamp: String(Math.trunc(SINCE_TS + 60)) }, // post-quarantine
    ],
  };
  const [isRetro, reason] = detectionIsRetrospectiveIocMatch(rec, SINCE_TS);
  assert.equal(isRetro, false);
  assert.equal(reason, null);
});

test("not retrospective when no underlying ts present", () => {
  // No network_accesses, no behaviors[].timestamp — can't classify.
  // Conservative: return false, let the agent decide.
  const rec = { behaviors: [{ description: "no ts here" }] };
  const [isRetro] = detectionIsRetrospectiveIocMatch(rec, SINCE_TS);
  assert.equal(isRetro, false);
});

test("retrospective via iso 8601 behaviors timestamp", () => {
  // ISO-8601 with Z must parse.
  const rec = {
    behaviors: [{ behavior_timestamp: "2023-11-13T01:23:45Z" }],
  };
  const [isRetro] = detectionIsRetrospectiveIocMatch(rec, SINCE_TS);
  assert.equal(isRetro, true);
});

test("retrospective handles first behavior field", () => {
  // behaviors[].first_behavior is a third accepted ISO field on the
  // detection envelope; must be read alongside timestamp + behavior_timestamp.
  const rec = {
    behaviors: [{ first_behavior: "2023-11-13T00:00:00Z" }],
  };
  const [isRetro] = detectionIsRetrospectiveIocMatch(rec, SINCE_TS);
  assert.equal(isRetro, true);
});

test("retrospective via context timestamp", () => {
  // context_timestamp on the detection root is also valid as an underlying
  // event signal.
  const rec = { context_timestamp: "2023-11-13T00:00:00Z" };
  const [isRetro] = detectionIsRetrospectiveIocMatch(rec, SINCE_TS);
  assert.equal(isRetro, true);
});

test("retrospective handles numeric epoch timestamps", () => {
  // Falcon sometimes returns epoch as int/float instead of string. Both
  // must be accepted.
  const rec = {
    network_accesses: [
      { access_timestamp: SINCE_TS - 3600 }, // number
    ],
  };
  const [isRetro] = detectionIsRetrospectiveIocMatch(rec, SINCE_TS);
  assert.equal(isRetro, true);
});

test("retrospective skips unparseable timestamp strings", () => {
  // Garbage strings shouldn't crash and shouldn't count as evidence.
  const rec = {
    network_accesses: [{ access_timestamp: "not-a-date" }],
  };
  const [isRetro] = detectionIsRetrospectiveIocMatch(rec, SINCE_TS);
  // No parseable underlying ts → false (conservative).
  assert.equal(isRetro, false);
});

test("retrospective mixed epoch and iso", () => {
  // Mixed shapes within a single detection — both predate, so still true.
  const rec = {
    network_accesses: [{ access_timestamp: String(Math.trunc(SINCE_TS - 86400)) }],
    behaviors: [
      { timestamp: "2023-11-13T00:00:00Z" },
      { first_behavior: SINCE_TS - 3600 }, // numeric
    ],
  };
  const [isRetro] = detectionIsRetrospectiveIocMatch(rec, SINCE_TS);
  assert.equal(isRetro, true);
});

test("retrospective boundary timestamp at since ts classifies as real", () => {
  // Exactly at SINCE_TS counts as post-quarantine (>= comparison) — real.
  const rec = {
    network_accesses: [{ access_timestamp: SINCE_TS }],
  };
  const [isRetro] = detectionIsRetrospectiveIocMatch(rec, SINCE_TS);
  assert.equal(isRetro, false);
});

// ===========================================================================
// detectionIsShadowAiIocAudit
//
// The catalog comes from lib/eyas-tools/ai-egress-catalog.json (shared with
// the Shadow-AI hunting catalog).
// ===========================================================================

test("shadow ai audit claude ai", () => {
  const rec = { behaviors: [{ ioc_type: "domain", ioc_value: "claude.ai" }] };
  const [isAudit, matched] = detectionIsShadowAiIocAudit(rec);
  assert.equal(isAudit, true);
  assert.equal(matched, "claude.ai");
});

test("shadow ai audit api anthropic", () => {
  const rec = { behaviors: [{ ioc_type: "domain", ioc_value: "api.anthropic.com" }] };
  const [isAudit, matched] = detectionIsShadowAiIocAudit(rec);
  assert.equal(isAudit, true);
  assert.equal(matched, "api.anthropic.com");
});

test("shadow ai audit case insensitive", () => {
  const rec = { behaviors: [{ ioc_type: "DOMAIN", ioc_value: "CHATGPT.COM" }] };
  const [isAudit, matched] = detectionIsShadowAiIocAudit(rec);
  assert.equal(isAudit, true);
  assert.equal(matched, "chatgpt.com");
});

test("shadow ai audit ignores non catalog domain", () => {
  const rec = { behaviors: [{ ioc_type: "domain", ioc_value: "evil.example.com" }] };
  const [isAudit, matched] = detectionIsShadowAiIocAudit(rec);
  assert.equal(isAudit, false);
  assert.equal(matched, null);
});

test("shadow ai audit ignores non domain ioc", () => {
  // An IOC fire on a hash that happens to be named like a catalog domain
  // shouldn't match — ioc_type must be "domain".
  const rec = { behaviors: [{ ioc_type: "sha256", ioc_value: "deadbeef".repeat(8) }] };
  const [isAudit, matched] = detectionIsShadowAiIocAudit(rec);
  assert.equal(isAudit, false);
  assert.equal(matched, null);
});

test("shadow ai audit no behaviors", () => {
  const rec = { cmdline: "whatever.exe" };
  const [isAudit, matched] = detectionIsShadowAiIocAudit(rec);
  assert.equal(isAudit, false);
  assert.equal(matched, null);
});

test("shadow ai audit partial subdomain does not match", () => {
  // Anchored full-match in the catalog: a subdomain string like
  // "claude.ai.evil.com" must NOT match the "claude.ai" pattern.
  const rec = { behaviors: [{ ioc_type: "domain", ioc_value: "claude.ai.evil.com" }] };
  const [isAudit, matched] = detectionIsShadowAiIocAudit(rec);
  assert.equal(isAudit, false);
  assert.equal(matched, null);
});

test("shadow ai audit mixed behaviors picks match", () => {
  // First behavior is unrelated; second is a Shadow-AI catalog hit. Must
  // return true with the matched value from the right behavior.
  const rec = {
    behaviors: [
      { ioc_type: "ipv4", ioc_value: "1.2.3.4" },
      { ioc_type: "domain", ioc_value: "api.openai.com" },
    ],
  };
  const [isAudit, matched] = detectionIsShadowAiIocAudit(rec);
  assert.equal(isAudit, true);
  assert.equal(matched, "api.openai.com");
});

// ===========================================================================
// detectionIsRetrospectiveBackfill (Phase 0 workflow-entry variant)
//
// Regression guard for the critical bug where Phase 0 compared underlying
// events against `now` — making EVERY recent real detection look retrospective
// (its events are always older than now) and FP-closing real malware. The
// correct signal is the GAP between the fresh created_timestamp and the old
// underlying events.
// ===========================================================================

test("backfill recent real malware is actionable", () => {
  // THE critical regression: a real detection scored ~5 min after its
  // behavior fired. Tiny created-vs-event gap → NOT retrospective, must stay
  // actionable so the workflow quarantines + cleans.
  const rec = {
    created_timestamp: "2026-06-06T12:05:00Z",
    behaviors: [{ timestamp: "2026-06-06T12:00:00Z" }],
    network_accesses: [{ access_timestamp: "1749211200" }], // 12:00:00Z
  };
  const [isRetro, reason] = detectionIsRetrospectiveBackfill(rec);
  assert.equal(isRetro, false, reason ?? undefined);
  assert.equal(reason, null);
});

test("backfill old events fresh envelope is retrospective", () => {
  // True Falcon IOC backfill: events from a month ago, envelope scored now.
  // Wide gap → retrospective, safe to FP-close.
  const rec = {
    created_timestamp: "2026-06-06T12:00:00Z",
    behaviors: [{ timestamp: "2026-05-01T09:00:00Z" }],
  };
  const [isRetro, reason] = detectionIsRetrospectiveBackfill(rec);
  assert.equal(isRetro, true);
  assert.ok(reason);
  assert.match(reason, /backfill/);
});

test("backfill no underlying events is actionable", () => {
  // No underlying timestamps to reason about → can't classify → actionable.
  const rec = { created_timestamp: "2026-06-06T12:00:00Z", cmdline: "evil.exe" };
  const [isRetro, reason] = detectionIsRetrospectiveBackfill(rec);
  assert.equal(isRetro, false);
  assert.equal(reason, null);
});

test("backfill no created timestamp is actionable", () => {
  // Underlying events present but no created_timestamp → can't compute the
  // gap → stay actionable (conservative).
  const rec = { behaviors: [{ timestamp: "2026-05-01T09:00:00Z" }] };
  const [isRetro, reason] = detectionIsRetrospectiveBackfill(rec);
  assert.equal(isRetro, false);
  assert.equal(reason, null);
});

test("backfill mixed one recent event is not retrospective", () => {
  // One ancient event plus one recent event. newest underlying is recent →
  // small gap to created → real new activity, do NOT auto-close.
  const rec = {
    created_timestamp: "2026-06-06T12:10:00Z",
    behaviors: [{ timestamp: "2026-05-01T09:00:00Z" }, { timestamp: "2026-06-06T12:00:00Z" }],
  };
  const [isRetro, reason] = detectionIsRetrospectiveBackfill(rec);
  assert.equal(isRetro, false, reason ?? undefined);
});

test("backfill epoch string network timestamp", () => {
  // network_accesses[].access_timestamp arrives as epoch-seconds strings;
  // created_timestamp as ISO. Old epoch event + fresh ISO envelope → retro.
  const rec = {
    created_timestamp: "2026-06-06T12:00:00Z",
    network_accesses: [{ access_timestamp: "1746090000" }], // 2025-05-01
  };
  const [isRetro] = detectionIsRetrospectiveBackfill(rec);
  assert.equal(isRetro, true);
});

test("backfill gap just under threshold is actionable", () => {
  // 23h gap (< 24h default floor) → not yet retrospective. Guards the
  // boundary so a same-day real detection isn't swept up.
  const rec = {
    created_timestamp: "2026-06-06T23:00:00Z",
    behaviors: [{ timestamp: "2026-06-06T00:00:00Z" }],
  };
  const [isRetro] = detectionIsRetrospectiveBackfill(rec);
  assert.equal(isRetro, false);
});
