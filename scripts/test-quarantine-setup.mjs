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

// ---- provisioning + detach (lib/eyas-tools/quarantine-provision.ts) --------

const prov = await import(pathToFileURL(path.join(root, "lib/eyas-tools/quarantine-provision.ts")).href);

test("settings push: sliders up, toggles on, grouped shape flattened, no-op detected", () => {
  const grouped = [
    { name: "ML", settings: [cautious("OnSensorMLSlider"), { id: "Det", value: { detection: "MODERATE" } }] },
    { name: "Behavior", settings: [{ id: "ScriptControl", value: { enabled: false } }, { id: "Odd", value: { mode: "x" } }] },
  ];
  const p = prov.planMaxProtectiveSettings(grouped);
  assert.equal(p.slidersTouched, 2);
  assert.equal(p.togglesTouched, 1);
  assert.deepEqual(p.flat, [
    { id: "OnSensorMLSlider", value: { detection: "AGGRESSIVE", prevention: "AGGRESSIVE" } },
    { id: "Det", value: { detection: "AGGRESSIVE" } },
    { id: "ScriptControl", value: { enabled: true } },
    { id: "Odd", value: { mode: "x" } },
  ]);
  // The input is not mutated.
  assert.equal(grouped[0].settings[0].value.detection, "CAUTIOUS");
  const done = prov.planMaxProtectiveSettings([aggressive("A"), { id: "T", value: { enabled: true } }]);
  assert.equal(done.slidersTouched + done.togglesTouched, 0);
});

function provCtx({ policies = [], records = {}, exclusions = [], detections = [], fail = {} } = {}) {
  const calls = [];
  let n = 0;
  return {
    calls,
    callNative: async (name, args) => {
      calls.push({ name, args });
      if (fail[name]) return { obj: null, error: fail[name] };
      if (name === "falcon_get_policies") return { obj: { found: [records[args.ids[0]] ?? { id: args.ids[0], prevention_settings: [] }], not_found: [] }, error: null };
      if (name === "falcon_create_policy") return { obj: { id: `new-${args.platform_name}-${++n}` }, error: null };
      if (name === "falcon_create_exclusion") return { obj: { id: "excl-new" }, error: null };
      return { obj: {}, error: null };
    },
    searchNative: async (name) => {
      calls.push({ name });
      if (name === "falcon_search_policies") return { ok: true, items: policies };
      if (name === "falcon_search_exclusions") return { ok: true, items: exclusions };
      if (name === "falcon_search_detections") return { ok: true, items: detections };
      return { ok: false, error: `unexpected ${name}` };
    },
  };
}
const names = (ctx) => ctx.calls.map((c) => c.name);

test("provision adopt: rename, push, precedence first per platform, exclusion already there", async () => {
  const win = policy({ id: "pw", name: "Old IR policy", prevention_settings: [{ settings: [cautious("OnSensorMLSlider")] }] });
  const ctx = provCtx({ policies: [win], records: { pw: win }, exclusions: [readinessExclusion] });
  const r = await prov.provisionQuarantinePolicy(ctx, { host_group_id: GID, mode: "adopt" });
  assert.equal(r.ok, true, JSON.stringify(r.errors));
  // Windows adopted + renamed; Mac and Linux created, attached and enabled.
  assert.deepEqual(r.actions.filter((a) => a.step === "rename").map((a) => a.platform), ["windows"]);
  assert.deepEqual(r.actions.filter((a) => a.step === "create_and_attach").map((a) => a.platform), ["mac", "linux"]);
  const rename = ctx.calls.find((c) => c.name === "falcon_update_policy" && c.args.name);
  assert.equal(rename.args.name, "Project Eyas - IR Quarantine (auto, windows)");
  const push = ctx.calls.find((c) => c.name === "falcon_update_policy" && c.args.settings);
  assert.deepEqual(push.args.settings, [{ id: "OnSensorMLSlider", value: { detection: "AGGRESSIVE", prevention: "AGGRESSIVE" } }]);
  const creates = ctx.calls.filter((c) => c.name === "falcon_create_policy").map((c) => c.args.platform_name);
  assert.deepEqual(creates, ["Mac", "Linux"]);
  const acts = ctx.calls.filter((c) => c.name === "falcon_perform_policy_action").map((c) => c.args.action_name);
  assert.deepEqual(acts, ["add-host-group", "enable", "add-host-group", "enable"]);
  const prec = ctx.calls.filter((c) => c.name === "falcon_set_policy_precedence").map((c) => c.args);
  assert.deepEqual(prec.map((p) => [p.platform_name, p.place_first, typeof p.move_id]), [
    ["Windows", true, "string"], ["Mac", true, "string"], ["Linux", true, "string"],
  ]);
  assert.equal(prec.every((p) => !("ids" in p)), true, "relative mode, never a full id list");
  const ex = r.actions.find((a) => a.step === "ir_readiness_exclusion");
  assert.equal(ex.present, true);
  assert.equal(ex.created, false);
  assert.equal(names(ctx).includes("falcon_create_exclusion"), false);
});

test("provision create_dedicated ignores the shared policy; missing exclusion is created", async () => {
  const shared = policy({ id: "ps", name: "Ops", groups: [{ id: GID }, { id: "other" }] });
  const det = { composite_id: "c1", pattern_id: 10197 };
  const ctx = provCtx({ policies: [shared], exclusions: [], detections: [det] });
  const r = await prov.provisionQuarantinePolicy(ctx, { host_group_id: GID, mode: "create_dedicated" });
  assert.equal(r.ok, true);
  assert.equal(ctx.calls.filter((c) => c.name === "falcon_create_policy").length, 3);
  assert.equal(ctx.calls.some((c) => c.name === "falcon_update_policy" && c.args.id === "ps"), false);
  const ex = ctx.calls.find((c) => c.name === "falcon_create_exclusion").args;
  assert.equal(ex.exclusion_type, "ioa");
  assert.equal(ex.pattern_id, "10197");
  assert.equal(ex.cl_regex, q.RTR_PREAMBLE_FULL_REGEX);
  assert.equal(ex.ifn_regex, q.READINESS_IFN_REGEX);
  assert.deepEqual(ex.host_groups, [GID]);
  assert.equal(ex.skip_if_duplicate, true);
});

test("provision: errors per stage are reported and the rest continues", async () => {
  const ctx = provCtx({ fail: { falcon_create_policy: "HTTP 400: bad", falcon_set_policy_precedence: "HTTP 500" }, exclusions: [readinessExclusion] });
  const r = await prov.provisionQuarantinePolicy(ctx, { host_group_id: GID });
  assert.equal(r.ok, false);
  assert.deepEqual(r.errors.map((e) => [e.platform, e.stage]), [["windows", "create_policies"], ["mac", "create_policies"], ["linux", "create_policies"]]);
  assert.equal(names(ctx).includes("falcon_set_policy_precedence"), false, "nothing to reorder when nothing was provisioned");
  assert.match((await prov.provisionQuarantinePolicy(provCtx(), {})).error, /host_group_id is required/);
  assert.match((await prov.provisionQuarantinePolicy(provCtx(), { host_group_id: GID, mode: "yolo" })).error, /unknown mode/);
});

test("readiness exclusion: unresolvable pattern warns without failing", async () => {
  const r = await prov.ensureReadinessExclusion(provCtx({ exclusions: [], detections: [] }), GID);
  assert.equal(r.ok, true);
  assert.equal(r.pattern_id_unresolved, true);
  assert.match(r.warning, /could NOT be pre-installed/);
});

test("detach runs remove-host-group on the one policy", async () => {
  const ctx = provCtx();
  const r = await prov.detachPreventionPolicy(ctx, { prevention_policy_id: "p1", host_group_id: GID });
  assert.equal(r.ok, true);
  assert.deepEqual(ctx.calls[0], {
    name: "falcon_perform_policy_action",
    args: { policy_type: "prevention", action_name: "remove-host-group", ids: ["p1"], group_id: GID },
  });
  assert.equal((await prov.detachPreventionPolicy(provCtx(), { host_group_id: GID })).ok, false);
});
