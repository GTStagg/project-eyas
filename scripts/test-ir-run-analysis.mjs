#!/usr/bin/env node
// Pure-function tests for lib/chat/ir-run-analysis.ts.
//
// Run as:  node scripts/test-ir-run-analysis.mjs
//
// Uses tsx via spawn to evaluate the TS module under Node's built-in test
// runner. No filesystem state — fixtures are constructed in-memory.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.IR_ANALYSIS_CHILD) {
  // Parent — spawn the child under tsx (via npx, matching the convention in
  // scripts/test-settings-store.mjs) so the .ts source is loaded
  // without a build step. tsx is preferred over Node's --experimental-
  // strip-types because it transpiles type-only imports correctly across
  // the broader project (path aliases, type re-exports, etc.).
  const r = spawnSync(
    process.execPath,
    [
      process.cwd() + "/node_modules/tsx/dist/cli.mjs",
      "--test",
      path.join(here, "test-ir-run-analysis.mjs"),
    ],
    {
      cwd: root,
      stdio: "inherit",
      env: { ...process.env, IR_ANALYSIS_CHILD: "1" },
    },
  );
  process.exit(r.status ?? 1);
}

// ───────────────────────────────────────────────────── child (tsx --test)

import { test } from "node:test";
import assert from "node:assert/strict";

const mod = await import(
  path.join(root, "lib/chat/ir-run-analysis.ts")
);
const {
  classifyCalls,
  callsByPhase,
  extractOutcome,
  extractGuardrails,
  deriveDisposition,
  PHASE_LABEL,
} = mod;

// ───────────────────────────────────────────────────── fixture builders

let nextId = 0;
function call(name, opts = {}) {
  return {
    id: `c${++nextId}`,
    name,
    input: opts.input ?? {},
    approval: opts.approval ?? "none",
    result: opts.result === null ? null : {
      isError: opts.isError ?? false,
      contentExcerpt: opts.text ?? "",
      durationMs: opts.durationMs ?? 100,
    },
    ts: Date.now(),
  };
}

function turn(turnIndex, calls, status = "completed") {
  return {
    turnIndex,
    startedAt: 1_700_000_000_000 + turnIndex * 1000,
    endedAt: 1_700_000_000_000 + turnIndex * 1000 + 500,
    userInput: `turn ${turnIndex}`,
    toolCalls: calls,
    status,
    usage: {
      input_tokens: 1000,
      output_tokens: 500,
      cache_creation_input_tokens: 0,
      cache_read_input_tokens: 0,
    },
    iterations: 1,
  };
}

function record(turns, overrides = {}) {
  return {
    schemaVersion: 1,
    aid: "abc123",
    sessionId: "sess-1",
    startedAt: 1_700_000_000_000,
    lastTouched: 1_700_000_005_000,
    campaignScope: { campaigns: [] },
    playbook: { ok: true, textLength: 1000 },
    turns,
    ...overrides,
  };
}

// ───────────────────────────────────────────────────── tests

test("PHASE_LABEL covers every phase", () => {
  assert.equal(PHASE_LABEL[0], "Discovery");
  assert.equal(PHASE_LABEL[4], "Closure");
});

test("classifyCalls assigns natural phase by tool name", () => {
  const r = record([
    turn(0, [
      call("extras_ir_workflow_playbook"),
      call("extras_ir_campaign_scope"),
      call("extras_host_group_add_members"),
      call("extras_rtr_run_cleanup", { input: { script_id: "host-kill-process" } }),
      call("extras_ir_phase3_verification_scope"),
      call("extras_ir_close_remediated"),
    ]),
  ]);
  const c = classifyCalls(r);
  assert.deepEqual(c.map((x) => x.phase), [0, 0, 1, 2, 3, 4]);
});

test("classifyCalls inherits phase for unclassified read tools", () => {
  // falcon_search_detections has no natural phase; it should pick up the
  // phase of the most recent classified call (Phase 1 here).
  const r = record([
    turn(0, [
      call("extras_host_group_add_members"),
      call("falcon_search_detections"),
    ]),
  ]);
  const c = classifyCalls(r);
  assert.equal(c[0].phase, 1);
  assert.equal(c[1].phase, 1);
});

test("callsByPhase groups into 5 buckets", () => {
  const r = record([
    turn(0, [
      call("extras_host_process_tree"),
      call("extras_host_contain"),
      call("falcon_add_ioc"),
    ]),
  ]);
  const buckets = callsByPhase(r);
  assert.equal(buckets[0].length, 1);
  assert.equal(buckets[1].length, 1);
  assert.equal(buckets[2].length, 1);
  assert.equal(buckets[3].length, 0);
  assert.equal(buckets[4].length, 0);
});

test("extractOutcome captures cleanup primitives by script_id", () => {
  const r = record([
    turn(0, [
      call("extras_rtr_run_cleanup", { input: { script_id: "host-kill-process" }, approval: "allow" }),
      call("extras_rtr_run_cleanup", { input: { script_id: "host-kill-process" }, approval: "allow" }),
      call("extras_rtr_run_cleanup", { input: { script_id: "host-delete-folder" }, approval: "allow" }),
    ]),
  ]);
  const o = extractOutcome(r);
  assert.equal(o.cleanupActions.length, 2);
  assert.deepEqual(o.cleanupActions[0], { scriptId: "host-kill-process", count: 2 });
  assert.deepEqual(o.cleanupActions[1], { scriptId: "host-delete-folder", count: 1 });
});

test("extractOutcome counts denied calls as not-successful", () => {
  const r = record([
    turn(0, [
      call("falcon_add_ioc", { approval: "deny" }),
      call("falcon_add_ioc", { approval: "allow" }),
    ]),
  ]);
  const o = extractOutcome(r);
  assert.equal(o.iocsAdded, 1);
});

test("extractOutcome parses extras_ir_close_remediated payload", () => {
  const closerPayload = JSON.stringify({
    closed: [
      { composite_id: "x", evidence: ["[ledger#0 file_quarantined] sha256 match"] },
      { composite_id: "y", evidence: ["[ledger#1 process_killed] image match"] },
      { composite_id: "z", evidence: ["[ledger#0 file_quarantined] cmdline path"] },
    ],
    unmatched: [{ composite_id: "u" }, { composite_id: "v" }],
  });
  const r = record([
    turn(0, [
      call("extras_ir_close_remediated", { approval: "allow", text: closerPayload }),
    ]),
  ]);
  const o = extractOutcome(r);
  assert.equal(o.detectionsClosed, 3);
  assert.equal(o.detectionsLeftOpen, 2);
  assert.equal(o.ledgerEvidenceCaptured, true);
});

test("closing untouched originals moves them from left-open to closed", () => {
  const r = record([
    turn(0, [
      call("extras_ir_close_remediated", {
        approval: "allow",
        text: JSON.stringify({ closed: [{ composite_id: "a", evidence: ["pid"] }], unmatched: [{}, {}, {}] }),
      }),
    ]),
    turn(1, [
      call("extras_ir_close_untouched_originals", {
        approval: "allow",
        text: JSON.stringify({ updated: 2, scope_count: 2 }),
      }),
    ]),
  ]);
  const o = extractOutcome(r);
  assert.equal(o.detectionsClosed, 3);
  assert.equal(o.detectionsLeftOpen, 1);
  assert.equal(o.bulkClosedHost, false);
});

test("extractOutcome flags bulk closer", () => {
  const r = record([
    turn(0, [
      call("extras_close_all_open_detections_on_host", {
        approval: "allow",
        text: JSON.stringify({ updated: 47 }),
      }),
    ]),
  ]);
  const o = extractOutcome(r);
  assert.equal(o.bulkClosedHost, true);
  assert.equal(o.detectionsClosed, 47);
  assert.equal(o.ledgerEvidenceCaptured, false);
});

test("extractOutcome distinguishes contain vs lift, quarantine vs release", () => {
  const r = record([
    turn(0, [
      call("extras_host_group_add_members", { approval: "allow" }),
      call("extras_host_contain", { approval: "allow" }),
    ]),
    turn(1, [
      call("extras_host_lift_containment", { approval: "allow" }),
      call("extras_host_group_remove_members", { approval: "allow" }),
    ]),
  ]);
  const o = extractOutcome(r);
  assert.equal(o.hostQuarantined, true);
  assert.equal(o.hostContained, true);
  assert.equal(o.hostContainmentLifted, true);
  assert.equal(o.hostReleased, true);
});

test("extractGuardrails surfaces denied + timeout + scope_pending", () => {
  const r = record([
    turn(0, [
      call("falcon_add_ioc", { approval: "deny" }),
      call("extras_host_contain", { approval: "timeout" }),
      call("extras_idp_account_status", {
        text: '{"ok": true, "scope_pending": true, "items": []}',
      }),
    ]),
  ]);
  const g = extractGuardrails(r);
  assert.equal(g.length, 3);
  assert.equal(g[0].kind, "approval_denied");
  assert.equal(g[1].kind, "approval_timeout");
  assert.equal(g[2].kind, "scope_pending");
});

test("extractGuardrails surfaces process-tree anchor recovery", () => {
  const r = record([
    turn(0, [
      call("extras_host_process_tree", {
        text: '{"anchor_recovered": true, "delivery_vector": {"kind": "phishing_doc"}}',
      }),
    ]),
  ]);
  const g = extractGuardrails(r);
  assert.equal(g.length, 1);
  assert.equal(g[0].kind, "anchor_recovered");
});

test("extractGuardrails parses Phase 3 retrospective + workflow-self counts", () => {
  const r = record([
    turn(0, [
      call("extras_ir_phase3_verification_scope", {
        text: '{"real_count": 0, "retrospective_count": 3, "workflow_self_count": 2}',
      }),
    ]),
  ]);
  const g = extractGuardrails(r);
  const kinds = g.map((x) => x.kind);
  assert.ok(kinds.includes("retrospective_classified"));
  assert.ok(kinds.includes("workflow_self_classified"));
});

test("extractGuardrails flags ledger unmatched", () => {
  const r = record([
    turn(0, [
      call("extras_ir_close_remediated", {
        approval: "allow",
        text: JSON.stringify({
          closed: [{ composite_id: "x", evidence: ["[ledger#0 a] b"] }],
          unmatched: [{ composite_id: "u" }, { composite_id: "v" }],
        }),
      }),
    ]),
  ]);
  const g = extractGuardrails(r);
  const unmatched = g.find((x) => x.kind === "unmatched_left_open");
  assert.ok(unmatched);
  assert.match(unmatched.detail, /2 detections? left open/);
});

test("deriveDisposition returns 'released' when host released", () => {
  const r = record([
    turn(0, [
      call("extras_host_group_add_members", { approval: "allow" }),
      call("extras_host_group_remove_members", { approval: "allow" }),
    ]),
  ]);
  const o = extractOutcome(r);
  assert.equal(deriveDisposition(r, o), "released");
});

test("deriveDisposition returns 'held' when detections left open and not released", () => {
  const r = record([
    turn(0, [
      call("extras_host_group_add_members", { approval: "allow" }),
      call("extras_ir_close_remediated", {
        approval: "allow",
        text: JSON.stringify({ closed: [], unmatched: [{ composite_id: "u" }] }),
      }),
    ]),
  ]);
  const o = extractOutcome(r);
  assert.equal(deriveDisposition(r, o), "held");
});

test("deriveDisposition returns 'no_findings' for read-only Phase 0 stop", () => {
  const r = record([
    turn(0, [
      call("extras_ir_workflow_playbook"),
      call("extras_ir_campaign_scope"),
    ]),
  ]);
  const o = extractOutcome(r);
  assert.equal(deriveDisposition(r, o), "no_findings");
});

test("deriveDisposition returns 'errored' when any tool errored", () => {
  const r = record([
    turn(0, [
      call("extras_host_process_tree", { isError: true, text: "boom" }),
    ]),
  ]);
  const o = extractOutcome(r);
  assert.equal(deriveDisposition(r, o), "errored");
});


// eyas-mcp containment names (current) count the same as the retired sidecar
// names (still present in older ir_run_turns).
test("extractOutcome + callsByPhase recognize the native contain / lift names", () => {
  const r = record([
    turn(0, [call("falcon_contain_hosts", { approval: "allow", input: { ids: ["a"] } })]),
    turn(1, [call("falcon_lift_host_containment", { approval: "allow", input: { ids: ["a"] } })]),
  ]);
  const o = extractOutcome(r);
  assert.equal(o.hostContained, true);
  assert.equal(o.hostContainmentLifted, true);
  const buckets = callsByPhase(r);
  assert.equal(buckets[1].length, 1);
  assert.equal(buckets[4].length, 1);
});
