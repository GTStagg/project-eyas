#!/usr/bin/env node
// Tests for the IR quarantine setup + readiness tools and the host-group
// membership writes (lib/eyas-tools/quarantine.ts, host-group-tools.ts),
// against a fake eyas-mcp context.
// Run as: node scripts/test-quarantine-setup.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.QUARANTINE_SETUP_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-quarantine-setup.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, QUARANTINE_SETUP_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

// quarantine.ts imports parse.ts, which imports "server-only".
import Module from "node:module";
const stub = path.join(root, "node_modules/next/dist/compiled/server-only/empty.js");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === "server-only") return stub;
  return origResolve.call(this, request, ...rest);
};

const q = await import(pathToFileURL(path.join(root, "lib/eyas-tools/quarantine.ts")).href);
const { hostGroupAction } = await import(pathToFileURL(path.join(root, "lib/eyas-tools/host-group-tools.ts")).href);

const GID = "0123456789abcdef0123456789abcdef";
const AID = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
const aggressive = (id) => ({ id, value: { detection: "AGGRESSIVE", prevention: "AGGRESSIVE" } });
const cautious = (id) => ({ id, value: { detection: "CAUTIOUS", prevention: "CAUTIOUS" } });
const policy = (over) => ({
  id: "p1",
  name: "Project Eyas - IR Quarantine (auto, windows)",
  platform_name: "Windows",
  enabled: true,
  groups: [{ id: GID }],
  prevention_settings: [{ name: "Machine Learning", settings: [aggressive("OnSensorMLSlider"), aggressive("CloudAntiMalware")] }],
  ...over,
});
const readinessExclusion = { id: "x1", groups: [{ id: GID }], cl_regex: q.RTR_PREAMBLE_FULL_REGEX, pattern_id: "123" };

function fakeCtx({ groups = { found: [{ id: GID, name: "Q", group_type: "static" }], not_found: [] }, groupError = null, policies = [], exclusions = [], exclusionError = null, detections = [], action = null } = {}) {
  const calls = [];
  return {
    calls,
    callNative: async (name, args) => {
      calls.push({ name, args });
      if (name === "falcon_get_host_groups") return groupError ? { obj: null, error: groupError } : { obj: groups, error: null };
      if (name === "falcon_perform_host_group_action") return action ?? { obj: { id: args.ids[0] }, error: null };
      if (name === "falcon_create_host_group") return { obj: { id: "new-1", name: args.name, group_type: "static" }, error: null };
      return { obj: null, error: `unexpected ${name}` };
    },
    searchNative: async (name, args) => {
      calls.push({ name, args });
      if (name === "falcon_search_policies") return { ok: true, items: policies };
      if (name === "falcon_search_exclusions") return exclusionError ? { ok: false, error: exclusionError } : { ok: true, items: exclusions };
      if (name === "falcon_search_detections") return { ok: true, items: detections };
      if (name === "falcon_search_host_groups") return { ok: true, items: groups.found };
      return { ok: false, error: `unexpected ${name}` };
    },
  };
}

test("diagnose: no group, missing group, and the A / B / C / ready cases", async () => {
  const missing = await q.diagnoseQuarantineSetup(fakeCtx({ groups: { found: [], not_found: [GID] } }), GID);
  assert.equal(missing.case, "group_missing");
  assert.equal(missing.recommended_action.tool, "extras_create_quarantine_host_group");

  const a = await q.diagnoseQuarantineSetup(fakeCtx({ policies: [] }), GID);
  assert.equal(a.case, "A_no_policy");
  assert.equal(a.recommended_action.args.mode, "adopt");

  const ready = await q.diagnoseQuarantineSetup(fakeCtx({ policies: [policy()], exclusions: [readinessExclusion] }), GID);
  assert.equal(ready.case, "ready");
  assert.equal(ready.recommended_action, null);
  assert.equal(ready.ir_readiness_exclusion_present, true);
  assert.deepEqual(ready.policies[0].settings_summary.OnSensorMLSlider, { detection: "AGGRESSIVE", prevention: "AGGRESSIVE" });
  assert.equal("_raw" in ready.policies[0], false);

  // v2 IOA exclusion records (what eyas-mcp reads) scope with host_groups.
  const v2 = { id: "x2", host_groups: [GID], cl_regex: q.RTR_PREAMBLE_FULL_REGEX };
  const readyV2 = await q.diagnoseQuarantineSetup(fakeCtx({ policies: [policy()], exclusions: [v2] }), GID);
  assert.equal(readyV2.case, "ready");
  const v2obj = { id: "x3", host_groups: [{ id: GID, name: "Q" }], cl_regex: q.RTR_PREAMBLE_FULL_REGEX };
  assert.equal((await q.diagnoseIrReadiness(fakeCtx({ exclusions: [v2obj] }), GID)).ready, true);

  const noExcl = await q.diagnoseQuarantineSetup(fakeCtx({ policies: [policy()], exclusions: [] }), GID);
  assert.equal(noExcl.case, "B_dedicated_single_group");

  const low = await q.diagnoseQuarantineSetup(
    fakeCtx({ policies: [policy({ prevention_settings: [cautious("OnSensorMLSlider")] })], exclusions: [readinessExclusion] }),
    GID,
  );
  assert.equal(low.case, "B_dedicated_single_group");

  const shared = await q.diagnoseQuarantineSetup(
    fakeCtx({ policies: [policy({ groups: [{ id: GID }, { id: "other" }], name: "Ops policy" })] }),
    GID,
  );
  assert.equal(shared.case, "C_shared_policy");
  assert.equal(shared.recommended_action.args.mode, "create_dedicated");

  // An unreadable exclusion list reads as "not present", never as an error.
  const exErr = await q.diagnoseQuarantineSetup(fakeCtx({ policies: [policy()], exclusionError: "HTTP 500" }), GID);
  assert.equal(exErr.case, "B_dedicated_single_group");
});

test("diagnose: a group-lookup error is returned, a 403 becomes scope_pending", async () => {
  const err = await q.diagnoseQuarantineSetup(fakeCtx({ groupError: "HTTP 500: upstream" }), GID);
  assert.equal(err.ok, false);
  const scope = await q.diagnoseQuarantineSetup(
    fakeCtx({ groupError: "Permission denied. The API credentials don't have the required access." }),
    GID,
  );
  assert.equal(scope.scope_pending, true);
});

test("slider level: detection only, unknown vocabularies skipped, grouped or flat", () => {
  assert.equal(q.atTargetLevel([aggressive("A"), { id: "B", value: { detection: "EXTRA_AGGRESSIVE" } }]), true);
  assert.equal(q.atTargetLevel([{ settings: [cautious("A")] }]), false);
  assert.equal(q.atTargetLevel([{ id: "A", value: { detection: "ENABLED" } }, { id: "T", value: { enabled: true } }]), true);
  assert.equal(q.atTargetLevel([{ id: "A", value: { detection: "AGGRESSIVE", prevention: "DISABLED" } }]), true);
});

test("readiness: ready, missing exclusion with remediation, unverifiable lookups", async () => {
  const ready = await q.diagnoseIrReadiness(fakeCtx({ exclusions: [readinessExclusion] }), GID);
  assert.equal(ready.ready, true);
  assert.equal(ready.checks.rtr_preamble_exclusion_id, "x1");
  assert.equal(ready.checks.ioa_exclusions_scoped_to_quarantine.length, 1);

  const det = { composite_id: "c1", behaviors: [{ pattern_id: 10197, display_name: "PShellMimikatz" }] };
  const gap = await q.diagnoseIrReadiness(fakeCtx({ exclusions: [], detections: [det] }), GID);
  assert.equal(gap.ready, false);
  const call = gap.remediation.tool_calls[0];
  assert.equal(call.tool, "extras_create_ioa_exclusion");
  assert.equal(call.args.pattern_id, "10197");
  assert.equal(call.args.cl_regex, q.RTR_PREAMBLE_FULL_REGEX);
  assert.equal(call.args.ifn_regex, ".*\\\\powershell\\.exe(\\W.*)?");
  assert.deepEqual(call.args.group_ids, [GID]);

  const noPattern = await q.diagnoseIrReadiness(fakeCtx({ exclusions: [] }), GID);
  assert.equal(noPattern.remediation.tool_calls[0].needs_pattern_id_lookup, true);

  // A transient error must never read as ready.
  const flaky = await q.diagnoseIrReadiness(fakeCtx({ groupError: "HTTP 500", exclusionError: "HTTP 500" }), GID);
  assert.equal(flaky.ready, false);
  assert.equal(flaky.missing.length, 2);
  assert.equal(flaky.remediation.tool_calls.length, 0);

  const gone = await q.diagnoseIrReadiness(fakeCtx({ groups: { found: [], not_found: [GID] } }), GID);
  assert.match(gone.missing[0], /does not exist in Falcon/);
});

test("create and adopt", async () => {
  const ctx = fakeCtx();
  const c = await q.createQuarantineHostGroup(ctx, {});
  assert.equal(c.ok, true);
  assert.equal(c.id, "new-1");
  assert.deepEqual(ctx.calls[0].args.group_type, "static");
  assert.equal(ctx.calls[0].args.name, q.CANONICAL_GROUP_NAME);

  const adopted = await q.adoptQuarantineHostGroup(
    fakeCtx({ groups: { found: [{ id: GID, name: "My Q", group_type: "static" }], not_found: [] } }),
    { name: "My Q" },
  );
  assert.equal(adopted.id, GID);
  const none = await q.adoptQuarantineHostGroup(fakeCtx({ groups: { found: [], not_found: [] } }), { name: "Nope" });
  assert.match(none.error, /no host group named 'Nope'/);
  const dup = await q.adoptQuarantineHostGroup(
    fakeCtx({ groups: { found: [{ id: "1", name: "Q" }, { id: "2", name: "Q" }], not_found: [] } }),
    { name: "Q" },
  );
  assert.match(dup.error, /refusing to guess/);
  assert.equal(dup.candidates.length, 2);
});

test("membership writes: validated ids go to the native action; bad input never does", async () => {
  const run = async (input, ctx = fakeCtx()) => ({ ...JSON.parse((await hostGroupAction("add-hosts", input, ctx)).content), ctx });
  const ok = await run({ group_id: GID, device_ids: [AID] });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.ctx.calls[0], {
    name: "falcon_perform_host_group_action",
    args: { action_name: "add-hosts", ids: [GID], device_ids: [AID] },
  });
  for (const bad of [
    { group_id: "", device_ids: [AID] },
    { group_id: GID, device_ids: [] },
    { group_id: GID, device_ids: ["x' OR 1=1"] },
    { group_id: GID, device_ids: Array(501).fill(AID) },
  ]) {
    const r = await run(bad);
    assert.equal(r.ok, false, JSON.stringify(bad).slice(0, 60));
    assert.equal(r.ctx.calls.length, 0);
  }
  const dyn = await run(
    { group_id: GID, device_ids: [AID] },
    fakeCtx({ action: { obj: null, error: "No change was made. These host groups are dynamic: 'X' (id)." } }),
  );
  assert.equal(dyn.ok, false);
  assert.match(dyn.error, /dynamic/);
});
