#!/usr/bin/env node
// Tests for the IR scope walkers and closers (lib/eyas-tools/ir/scope.ts,
// lib/eyas-tools/ir/closers.ts) against a fake eyas-mcp that records calls.
// Includes the ports of falcon-extras' test_phase3.py and
// test_close_untouched.py.
// Run as: node scripts/test-ir-scope.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.IR_SCOPE_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-ir-scope.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, IR_SCOPE_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

// The closers import parse.ts (and closers.ts native-dispatch), which import
// "server-only".
import Module from "node:module";
const stub = path.join(root, "node_modules/next/dist/compiled/server-only/empty.js");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === "server-only") return stub;
  return origResolve.call(this, request, ...rest);
};

const load = (p) => import(pathToFileURL(path.join(root, p)).href);
const scope = await load("lib/eyas-tools/ir/scope.ts");
const closers = await load("lib/eyas-tools/ir/closers.ts");
const alerts = await load("lib/eyas-tools/ir/alerts.ts");
const { RTR_PREAMBLE_BASE64 } = await load("lib/eyas-tools/quarantine.ts");

const AID = "a".repeat(32);
const CUTOFF_ISO = "2026-05-01T12:00:00Z";
const CUTOFF_MS = Date.UTC(2026, 4, 1, 12, 0);

const rec = (cid, created, status = "new", extra = {}) => ({ composite_id: cid, status, created_timestamp: created, ...extra });

/** Fake eyas-mcp: falcon_search_detections pages `records` (honouring the
 *  open-status and created_timestamp>= filters), get-by-ids hydrates, update
 *  records the call. */
function fakeCtx(records, { fail = {}, total } = {}) {
  const calls = [];
  const byId = new Map(records.map((r) => [r.composite_id ?? r.id, r]));
  return {
    calls,
    searchNative: async (name, args) => {
      calls.push({ name, args });
      if (fail[name]) return fail[name];
      if (name === "falcon_search_detections") {
        let rows = records;
        if (args.filter.includes("status:['new','reopened','in_progress']")) {
          rows = rows.filter((r) => ["new", "reopened", "in_progress"].includes(String(r.status).toLowerCase()));
        }
        const since = /created_timestamp:>='([^']+)'/.exec(args.filter)?.[1];
        if (since) rows = rows.filter((r) => Date.parse(r.created_timestamp) >= Date.parse(since));
        return { ok: true, items: rows.slice(args.offset, args.offset + args.limit), total: total ?? rows.length };
      }
      if (name === "falcon_get_detection_details") {
        return { ok: true, items: args.ids.map((id) => byId.get(id)).filter(Boolean) };
      }
      return { ok: false, error: `unexpected ${name}` };
    },
    callNative: async (name, args) => {
      calls.push({ name, args });
      if (fail[name]) return fail[name];
      if (name === "falcon_close_host_detections") {
        return { obj: { found: 2, closed: 2, composite_ids: ["x", "y"] }, error: null };
      }
      return { obj: {}, error: null };
    },
  };
}
const updates = (ctx) => ctx.calls.filter((c) => c.name === "falcon_update_detections");

// ---------------------------------------------------------------------------
// classifyPriorOpen (port of test_phase3.py)
// ---------------------------------------------------------------------------

const prior = (cid = "cid-1", status = "new") => ({ composite_id: cid, status });

test("prior re-check: new is open", () => {
  assert.deepEqual(scope.classifyPriorOpen([prior()]), { checked: 1, openIds: ["cid-1"] });
});

test("prior re-check: reopened and in_progress are open", () => {
  assert.deepEqual(scope.classifyPriorOpen([prior("a", "reopened"), prior("b", "in_progress")]), {
    checked: 2,
    openIds: ["a", "b"],
  });
});

test("prior re-check: open status is case-insensitive", () => {
  assert.deepEqual(scope.classifyPriorOpen([prior("cid-1", "NEW")]), { checked: 1, openIds: ["cid-1"] });
});

test("prior re-check: closed and resolved are checked but not open", () => {
  assert.deepEqual(scope.classifyPriorOpen([prior("cid-1", "closed")]), { checked: 1, openIds: [] });
  assert.deepEqual(scope.classifyPriorOpen([prior("cid-1", "resolved")]), { checked: 1, openIds: [] });
});

test("prior re-check: mixed batch reports only the open ones", () => {
  const recs = [prior("closed-1", "closed"), prior("open-1"), prior("closed-2", "resolved"), prior("open-2", "reopened")];
  assert.deepEqual(scope.classifyPriorOpen(recs), { checked: 4, openIds: ["open-1", "open-2"] });
});

test("prior re-check: an id the store no longer returns is not open; empty is zero", () => {
  assert.deepEqual(scope.classifyPriorOpen([prior("survivor")]), { checked: 1, openIds: ["survivor"] });
  assert.deepEqual(scope.classifyPriorOpen([]), { checked: 0, openIds: [] });
});

test("prior re-check: record shapes", () => {
  assert.deepEqual(scope.classifyPriorOpen([{ id: "legacy-id", status: "new" }]), { checked: 1, openIds: ["legacy-id"] });
  assert.deepEqual(scope.classifyPriorOpen(["nope", null, 42, prior()]), { checked: 1, openIds: ["cid-1"] });
  // Open status but no id: inspected, but nothing to report.
  assert.deepEqual(scope.classifyPriorOpen([{ status: "new" }]), { checked: 1, openIds: [] });
  assert.deepEqual(scope.classifyPriorOpen([{ composite_id: "x" }]), { checked: 1, openIds: [] });
});

test("prior re-check: custom status set, and the canonical set is pinned", () => {
  assert.deepEqual(scope.classifyPriorOpen([prior("a"), prior("b", "quarantined")], new Set(["quarantined"])), {
    checked: 2,
    openIds: ["b"],
  });
  // Changing this set changes which detections block a release: make it loud.
  assert.deepEqual([...alerts.OPEN_STATUSES].sort(), ["in_progress", "new", "reopened"]);
});

// ---------------------------------------------------------------------------
// close untouched originals (port of test_close_untouched.py)
// ---------------------------------------------------------------------------

test("only detections from before the cutoff are selected", () => {
  const list = [
    rec("old-1", "2026-04-30T08:00:00Z"),
    rec("old-2", "2026-05-01T11:59:59.123Z"),
    rec("during", "2026-05-01T12:00:00Z"), // at the cutoff: not prior
    rec("after", "2026-05-01T12:30:00Z"),
  ];
  assert.deepEqual(closers.selectUntouchedOriginals(list, CUTOFF_MS), ["old-1", "old-2"]);
});

test("a missing or bad creation time is never closed", () => {
  const list = [{ composite_id: "no-time", status: "new" }, rec("bad-time", "yesterday"), rec("ok", "2026-04-01T00:00:00Z")];
  assert.deepEqual(closers.selectUntouchedOriginals(list, CUTOFF_MS), ["ok"]);
});

test("close runs one batch with tag and comment", async () => {
  const ctx = fakeCtx([
    rec("old-1", "2026-04-30T08:00:00Z"),
    rec("old-2", "2026-04-29T08:00:00Z", "in_progress"),
    rec("closed-already", "2026-04-29T08:00:00Z", "closed"),
    rec("during", "2026-05-01T12:05:00Z"),
  ]);
  const out = await closers.closeUntouchedOriginals(ctx, {
    device_id: AID,
    before_iso: CUTOFF_ISO,
    verdict: "false_positive",
    comment: "reviewed by operator",
  });
  assert.equal(out.ok, true);
  assert.equal(out.scope_count, 2);
  assert.equal(out.updated, 2);
  assert.deepEqual(out.composite_ids, ["old-1", "old-2"]);
  assert.equal(out.left_open_after_cutoff, 1);
  assert.deepEqual(
    updates(ctx).map((c) => c.args),
    [{ ids: ["old-1", "old-2"], status: "closed", add_tags: ["false_positive"], append_comment: "reviewed by operator" }],
  );
});

test("nothing prior closes nothing", async () => {
  const ctx = fakeCtx([rec("during", "2026-05-01T12:05:00Z")]);
  const out = await closers.closeUntouchedOriginals(ctx, { device_id: AID, before_iso: CUTOFF_ISO, verdict: "true_positive" });
  assert.equal(out.ok, true);
  assert.equal(out.updated, 0);
  assert.equal(updates(ctx).length, 0);
});

test("bad inputs are refused before any call", async () => {
  const ctx = fakeCtx([]);
  assert.equal((await closers.closeUntouchedOriginals(ctx, { device_id: AID, before_iso: "not-a-time", verdict: "true_positive" })).ok, false);
  assert.equal((await closers.closeUntouchedOriginals(ctx, { device_id: AID, before_iso: CUTOFF_ISO, verdict: "maybe" })).ok, false);
  assert.equal((await closers.closeUntouchedOriginals(ctx, { device_id: "x' or '1", before_iso: CUTOFF_ISO, verdict: "true_positive" })).ok, false);
  assert.equal(ctx.calls.length, 0);
});

test("ledger close puts counts before the long lists", async () => {
  const ctx = fakeCtx([...Array.from({ length: 30 }, (_, i) => rec(`old-${i}`, "2026-04-30T08:00:00Z")), rec("during", "2026-05-01T12:05:00Z")]);
  const out = await closers.closeRemediated(ctx, { device_id: AID, remediated: [], verdict: "true_positive", before_iso: CUTOFF_ISO });
  const keys = Object.keys(out);
  assert.equal(out.unmatched_prior_count, 30);
  for (const k of ["unmatched_count", "unmatched_prior_count", "unmatched_prior_sample"]) {
    assert.ok(keys.indexOf(k) < keys.indexOf("unmatched"), keys.join(","));
  }
  assert.deepEqual(keys.slice(-2), ["closed", "unmatched"]);
});

// ---------------------------------------------------------------------------
// ledger close
// ---------------------------------------------------------------------------

test("ledger close closes only matched detections, with evidence", async () => {
  const ctx = fakeCtx([
    rec("hit", "2026-05-01T10:00:00Z", "new", { process_id: "111", display_name: "Evil" }),
    rec("miss", "2026-05-01T10:00:00Z", "new", { process_id: "222", display_name: "Other" }),
  ]);
  const out = await closers.closeRemediated(ctx, {
    device_id: AID,
    remediated: [{ kind: "process_killed", pid: 111 }, { kind: "other", note: "x" }, "bad", { pid: 1 }],
  });
  assert.equal(out.ok, true);
  assert.equal(out.verdict, "true_positive");
  assert.equal(out.matched_count, 1);
  assert.equal(out.updated, 1);
  assert.deepEqual(out.closed[0].evidence, ["[ledger#0 process_killed] process_killed pid=111 matches alert pid"]);
  assert.deepEqual(out.unmatched.map((u) => u.composite_id), ["miss"]);
  assert.equal(out.ledger_entries_used, 1);
  assert.deepEqual(out.ledger_entries_unused, [1]);
  assert.deepEqual(out.invalid_ledger_indices, [2, 3]);
  assert.deepEqual(updates(ctx)[0].args, {
    ids: ["hit"],
    status: "closed",
    add_tags: ["true_positive"],
    append_comment: "Closed via Project Eyas IR remediation-ledger match — Phase 4 step 1",
  });
});

test("ledger close with no open detections", async () => {
  const out = await closers.closeRemediated(fakeCtx([rec("c", "2026-05-01T10:00:00Z", "closed")]), {
    device_id: AID,
    remediated: [{ kind: "process_killed", pid: 1 }],
  });
  assert.equal(out.scope_count, 0);
  assert.deepEqual(out.ledger_entries_unused, [0]);
  assert.equal(out.note, "No open detections on this host — nothing to close.");
});

test("close batches are 500 ids; a later failed batch is listed, the rest still run", async () => {
  const many = Array.from({ length: 1201 }, (_, i) => rec(`d${i}`, "2026-04-01T00:00:00Z"));
  let n = 0;
  const ctx = fakeCtx(many);
  const orig = ctx.callNative;
  ctx.callNative = async (name, args) => {
    if (name === "falcon_update_detections" && ++n === 2) {
      ctx.calls.push({ name, args });
      return { obj: null, error: "HTTP 500: upstream" };
    }
    return orig(name, args);
  };
  const out = await closers.closeUntouchedOriginals(ctx, { device_id: AID, before_iso: CUTOFF_ISO, verdict: "true_positive" });
  assert.deepEqual(updates(ctx).map((c) => c.args.ids.length), [500, 500, 201]);
  assert.equal(out.updated, 701);
  assert.equal(out.ok, true);
  assert.deepEqual(out.batch_errors, [{ batch_start: 500, error: "HTTP 500: upstream", size: 500 }]);
});

test("a permission error on the first close batch returns the scope payload", async () => {
  const ctx = fakeCtx([rec("old", "2026-04-01T00:00:00Z")], {
    fail: { falcon_update_detections: { obj: null, error: "Permission denied. The API credentials don't have the required access." } },
  });
  const out = await closers.closeUntouchedOriginals(ctx, { device_id: AID, before_iso: CUTOFF_ISO, verdict: "true_positive" });
  assert.equal(out.scope_pending, true);
  assert.equal(out.surface, "Alerts");
});

// ---------------------------------------------------------------------------
// Phase 0 scope and the actionable partition
// ---------------------------------------------------------------------------

test("phase 0 scope pages open endpoint detections and projects items", async () => {
  const list = [
    rec("n1", "2026-05-01T10:00:00Z", "new", { process_id: 42, display_name: "A", adversary_ids: [7, null], has_adversary: [] }),
    rec("n2", "2026-04-30T10:00:00Z", "in_progress", { behaviors: [{ process_id: 0 }, { target_process_id: "99" }], name: "B" }),
    rec("c1", "2026-04-29T10:00:00Z", "closed"),
  ];
  const ctx = fakeCtx(list);
  const out = await scope.phase0DetectionScope(ctx, { device_id: AID });
  assert.equal(out.ok, true);
  assert.deepEqual(out.composite_ids, ["n1", "n2"]);
  assert.deepEqual(out.pivot_pids, ["42", "99"]);
  assert.equal(out.oldest_open_iso, "2026-04-30T10:00:00Z");
  assert.equal(out.newest_open_iso, "2026-05-01T10:00:00Z");
  assert.deepEqual(out.items[0].adversary_ids, ["7"]);
  assert.equal(out.items[0].has_adversary, false);
  assert.equal(out.items[1].display_name, "B");
  assert.equal(out.items[1].tactic, null);
  assert.equal(out.truncated, false);
  const search = ctx.calls[0].args;
  assert.equal(search.filter, `product:'epp'+device.device_id:'${AID}'+status:['new','reopened','in_progress']`);
  assert.equal(search.sort, "created_timestamp.desc");
});

test("phase 0 scope stops at the hard cap and says so", async () => {
  const many = Array.from({ length: 5200 }, (_, i) => rec(`d${i}`, "2026-04-01T00:00:00Z"));
  const ctx = fakeCtx(many);
  const out = await scope.phase0DetectionScope(ctx, { device_id: AID });
  assert.equal(out.count, 5000);
  assert.equal(out.truncated, true);
  assert.match(out.note, /HARD_CAP hit/);
  assert.equal(ctx.calls.length, 25);
});

test("phase 0 scope refuses a bad device id and passes upstream errors", async () => {
  assert.deepEqual(await scope.phase0DetectionScope(fakeCtx([]), {}), { ok: false, error: "device_id required" });
  const bad = await scope.phase0DetectionScope(fakeCtx([]), { device_id: "abc'+status:'new" });
  assert.equal(bad.error, "device_id must be a 32-character hex Agent ID");
  const err = await scope.phase0DetectionScope(
    fakeCtx([], { fail: { falcon_search_detections: { ok: false, error: "HTTP 500" } } }),
    { device_id: AID },
  );
  assert.deepEqual(err, { ok: false, error: "HTTP 500" });
  const denied = await scope.phase0DetectionScope(
    fakeCtx([], { fail: { falcon_search_detections: { ok: true, scope_pending: true, items: [] } } }),
    { device_id: AID },
  );
  assert.equal(denied.scope_pending, true);
});

const preamble = `powershell.exe -EncodedCommand ${RTR_PREAMBLE_BASE64} -File x.ps1`;

test("actionable partition buckets noise and only pre-composes closes when nothing is actionable", async () => {
  const noise = [
    rec("self", "2026-05-01T10:00:00Z", "new", { cmdline: preamble }),
    rec("audit", "2026-05-01T10:00:00Z", "new", { behaviors: [{ ioc_type: "domain", ioc_value: " Claude.AI " }] }),
    rec("retro", "2026-05-07T04:45:00Z", "new", { network_accesses: [{ access_timestamp: String(Date.UTC(2026, 4, 4) / 1000) }] }),
  ];
  const quiet = await scope.phase0ActionablePartition(fakeCtx(noise), { device_id: AID });
  assert.equal(quiet.should_proceed_with_ir, false);
  assert.equal(quiet.total_open, 3);
  assert.deepEqual(quiet.shadow_ai_ioc_audit[0].matched_domain, "claude.ai");
  assert.match(quiet.retrospective_ioc_match[0].reason, /Falcon IOC backfill/);
  assert.deepEqual(quiet.bulk_close_calls.map((c) => [c.kind, c.ids, c.add_tags ?? null]), [
    ["workflow_self", ["self"], ["false_positive"]],
    ["shadow_ai_audit", ["audit"], null],
    ["retrospective", ["retro"], ["false_positive"]],
  ]);

  const loud = await scope.phase0ActionablePartition(fakeCtx([...noise, rec("real", "2026-05-01T10:00:00Z")]), { device_id: AID });
  assert.equal(loud.should_proceed_with_ir, true);
  assert.deepEqual(loud.actionable.map((a) => a.composite_id), ["real"]);
  assert.deepEqual(loud.bulk_close_calls, []);
  assert.deepEqual(Object.keys(loud.actionable[0]), ["composite_id", "display_name", "severity", "severity_name", "created_timestamp"]);
});

// ---------------------------------------------------------------------------
// Phase 3 verification scope
// ---------------------------------------------------------------------------

test("phase 3 classifies the window and re-checks the originals", async () => {
  const since = "2026-05-01T12:00:00.000Z";
  const list = [
    rec("orig-open", "2026-04-30T10:00:00Z", "new"),
    rec("orig-closed", "2026-04-30T10:00:00Z", "closed"),
    rec("before-window", "2026-04-30T11:00:00Z", "new"),
    rec("retro", "2026-05-01T13:00:00Z", "new", { behaviors: [{ timestamp: "2026-04-28T00:00:00Z" }] }),
    rec("self", "2026-05-01T13:00:00Z", "new", { parent_details: { cmdline: preamble } }),
    rec("real", "2026-05-01T14:00:00Z", "closed"),
  ];
  const ctx = fakeCtx(list);
  const out = await scope.phase3VerificationScope(ctx, {
    device_id: AID,
    since_iso: since,
    prior_composite_ids: ["orig-open", "orig-closed", "orig-open", "purged", 5],
  });
  assert.equal(out.ok, true);
  assert.deepEqual(out.retrospective_composite_ids, ["retro"]);
  assert.deepEqual(out.workflow_self_composite_ids, ["self"]);
  assert.deepEqual(out.real_composite_ids, ["real"]);
  assert.equal(out.real_count, 1);
  assert.equal(out.total, 3);
  assert.deepEqual(out.prior_open_composite_ids, ["orig-open"]);
  assert.equal(out.prior_open_count, 1);
  assert.equal(out.prior_checked_count, 2);
  assert.equal(out.items.find((i) => i.composite_id === "real").status, "closed");
  assert.match(out.items.find((i) => i.composite_id === "retro").retrospective_reason, /predate Phase 1/);
  const search = ctx.calls[0].args;
  assert.equal(search.filter, `product:'epp'+device.device_id:'${AID}'+created_timestamp:>='${since}'`);
  assert.equal(search.sort, "created_timestamp.asc");
  assert.deepEqual(ctx.calls.find((c) => c.name === "falcon_get_detection_details").args.ids, ["orig-open", "orig-closed", "purged"]);
});

test("phase 3 fails closed when the originals can't be re-checked", async () => {
  const ctx = fakeCtx([], { fail: { falcon_get_detection_details: { ok: false, error: "HTTP 500" } } });
  const out = await scope.phase3VerificationScope(ctx, { device_id: AID, since_iso: CUTOFF_ISO, prior_composite_ids: ["x"] });
  assert.deepEqual(out, { ok: false, error: "HTTP 500" });
});

test("phase 3 rejects a since_iso that isn't a plain timestamp (it goes into FQL)", async () => {
  for (const bad of ["2026-05-01T12:00:00Z'+status:'new", "yesterday", "", "2026-13-45T99:00:00Z"]) {
    const ctx = fakeCtx([]);
    const out = await scope.phase3VerificationScope(ctx, { device_id: AID, since_iso: bad });
    assert.equal(out.ok, false, bad);
    assert.equal(ctx.calls.length, 0);
  }
  assert.equal((await scope.phase3VerificationScope(fakeCtx([]), { device_id: AID, since_iso: "2026-05-01" })).ok, true);
});

// ---------------------------------------------------------------------------
// Bulk close
// ---------------------------------------------------------------------------

test("bulk close runs eyas-mcp's host close with Eyas's default comment", async () => {
  const ctx = fakeCtx([]);
  const AIDU = "A".repeat(32);
  const out = await closers.closeAllOpenOnHost(ctx, { device_id: AIDU, verdict: "true_positive" });
  assert.deepEqual(ctx.calls[0], {
    name: "falcon_close_host_detections",
    args: {
      device_id: AID,
      resolution: "true_positive",
      comment: `Bulk-closed via Project Eyas extras_close_all_open_detections_on_host on host ${AIDU}`,
    },
  });
  assert.equal(out.ok, true);
  assert.equal(out.updated, 2);
  assert.equal(out.scope_count, 2);
  assert.equal((await closers.closeAllOpenOnHost(fakeCtx([]), { device_id: AID, verdict: "ignored" })).ok, false);
});
