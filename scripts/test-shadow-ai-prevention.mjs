#!/usr/bin/env node
// Tests for the Shadow-AI setup and prevention tools
// (lib/eyas-tools/shadow-ai/prevention.ts) against a fake eyas-mcp.
// Includes the port of falcon-extras' shadow_ai/test_prevention_binding.py.
// Run as: node scripts/test-shadow-ai-prevention.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.SA_PREVENTION_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-shadow-ai-prevention.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, SA_PREVENTION_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

import Module from "node:module";
const stub = path.join(root, "node_modules/next/dist/compiled/server-only/empty.js");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === "server-only") return stub;
  return origResolve.call(this, request, ...rest);
};

const P = await import(pathToFileURL(path.join(root, "lib/eyas-tools/shadow-ai/prevention.ts")).href);

const BANNED = "b".repeat(32);
const WIN_RG = P.RULE_GROUP_NAMES.windows;
const MAC_RG = P.RULE_GROUP_NAMES.mac;
const LINUX_RG = P.RULE_GROUP_NAMES.linux;

const rg = (name, { enabled = true, rules = [] } = {}) => ({ name, id: `rgid::${name}`, enabled, rules });
const policy = (name, platform, { enabled = true, bound = null, onBanned = true, groups = null } = {}) => ({
  id: `pol::${name}`,
  name,
  platform_name: platform,
  enabled,
  groups: groups ?? (onBanned ? [{ id: BANNED }] : [{ id: "other" }]),
  ioa_rule_groups: bound ? [{ name: bound, id: `rgid::${bound}` }] : [],
});
const groupsBy = (...gs) => ({
  windows: gs.find((g) => g?.name === WIN_RG) ?? null,
  mac: gs.find((g) => g?.name === MAC_RG) ?? null,
  linux: gs.find((g) => g?.name === LINUX_RG) ?? null,
});
const attached = (res, name) => res.attached_policies.find((p) => p.name === name);

// ------------------------------------------------ binding check (port)

test("binding: a correctly bound macOS policy is not reported broken", () => {
  const res = P.classifyBinding(BANNED, groupsBy(rg(WIN_RG), rg(MAC_RG)), [
    policy("Win Policy", "Windows", { bound: WIN_RG }),
    policy("Mac Policy", "Mac", { bound: MAC_RG }),
  ]);
  assert.equal(attached(res, "Mac Policy").rule_group_bound, true);
  assert.equal(attached(res, "Mac Policy").rule_group_name, MAC_RG);
  assert.equal(attached(res, "Win Policy").rule_group_bound, true);
  assert.equal(res.ready, true);
  assert.deepEqual(res.missing_steps, []);
});

test("binding: a cross-platform bind doesn't count", () => {
  const res = P.classifyBinding(BANNED, groupsBy(rg(WIN_RG), rg(MAC_RG)), [policy("Mac Policy", "Mac", { bound: WIN_RG })]);
  assert.equal(attached(res, "Mac Policy").rule_group_bound, false);
  assert.equal(res.ready, false);
  assert.ok(res.missing_steps.some((s) => s.startsWith("[mac]")));
});

test("binding: a missing Linux rule group blocks ready", () => {
  const res = P.classifyBinding(BANNED, groupsBy(rg(WIN_RG)), [
    policy("Win Policy", "Windows", { bound: WIN_RG }),
    policy("Linux Policy", "Linux"),
  ]);
  assert.equal(res.ready, false);
  assert.ok(res.missing_steps.some((s) => s.includes("[linux]") && s.includes('platform="linux"')));
});

test("binding: Windows-only is still ready; top level mirrors Windows", () => {
  const res = P.classifyBinding(BANNED, groupsBy(rg(WIN_RG)), [policy("Win Policy", "Windows", { bound: WIN_RG })]);
  assert.equal(res.ready, true);
  assert.equal(res.rule_group_name, WIN_RG);
  assert.equal(res.rule_group_exists, true);
});

test("binding: a disabled bound policy is surfaced, not ready", () => {
  const res = P.classifyBinding(BANNED, groupsBy(rg(WIN_RG)), [policy("Win Policy", "Windows", { enabled: false, bound: WIN_RG })]);
  assert.equal(res.ready, false);
  assert.ok(res.missing_steps.some((s) => s.toLowerCase().includes("disabled")));
});

test("binding: no policy attached", () => {
  const res = P.classifyBinding(BANNED, groupsBy(rg(WIN_RG), rg(MAC_RG)), [policy("Other", "Windows", { bound: WIN_RG, onBanned: false })]);
  assert.equal(res.ready, false);
  assert.deepEqual(res.attached_policies, []);
  assert.ok(res.missing_steps.some((s) => s.includes(BANNED)));
});

// ------------------------------------------------ fake eyas-mcp

function fakeCtx(handlers) {
  const calls = [];
  const run = async (name, args) => {
    calls.push({ name, args });
    const h = handlers[name];
    if (!h) throw new Error(`unexpected native ${name}`);
    return h(args, calls);
  };
  return {
    calls,
    writes: () => calls.filter((c) => !/^falcon_(search|get)_/.test(c.name)),
    ctx: {
      callNative: async (name, args) => {
        const out = await run(name, args);
        return out && out.__error ? { obj: null, error: out.__error } : { obj: out, error: null };
      },
      searchNative: async (name, args) => {
        const out = await run(name, args);
        if (out && out.__error) return { ok: false, error: out.__error };
        if (out && out.__scope) return { ok: true, scope_pending: true, items: [] };
        return { ok: true, items: out };
      },
    },
  };
}

test("prevention status reports every platform, hoisting Windows", async () => {
  const { ctx } = fakeCtx({ falcon_search_ioa_rule_groups: () => [rg(WIN_RG, { rules: [{ name: "ShadowAI: Cursor (agentic IDE)" }] }), rg(MAC_RG)] });
  const res = await P.preventionStatus(ctx);
  assert.deepEqual(res.platforms.map((p) => p.platform), ["windows", "mac", "linux"]);
  assert.equal(res.platforms[2].rule_group_exists, false);
  assert.equal(res.rule_group_exists, true);
  assert.equal(res.any_rule_group_exists, true);
  assert.equal(res.installed_rule_count, 1);
  assert.equal(res.missing_rules.length, P.CORPUS_BY_PLATFORM.windows.length - 1);
  assert.equal(res.corpus_count, P.CORPUS_BY_PLATFORM.windows.length);
});

test("prevention status: scope denial", async () => {
  const { ctx } = fakeCtx({ falcon_search_ioa_rule_groups: () => ({ __scope: true }) });
  assert.equal((await P.preventionStatus(ctx)).scope_pending, true);
});

// ------------------------------------------------ diagnose

const fullRules = (plat) => P.CORPUS_BY_PLATFORM[plat].map((r) => ({ name: r.name }));
const managed = (plat) => `${P.CANONICAL_POLICY_PREFIX}, ${plat})`;

test("diagnose: cases", () => {
  const group = { id: BANNED, name: P.CANONICAL_GROUP_NAME, group_type: "static" };
  const all = groupsBy(rg(WIN_RG, { rules: fullRules("windows") }), rg(MAC_RG, { rules: fullRules("mac").slice(1) }));
  const c = (policies, ruleGroups = all) => P.classifyBannedSetup({ hostGroupId: BANNED, group, policies, ruleGroups });

  assert.equal(c([]).case, "A_no_policy");
  assert.equal(c([]).recommended_action.args.mode, "adopt");
  assert.equal(c([policy(managed("windows"), "Windows", { bound: WIN_RG })]).case, "ready");
  const drift = c([policy(managed("windows"), "Windows", { bound: WIN_RG }), policy(managed("mac"), "Mac", { bound: MAC_RG })]);
  assert.equal(drift.case, "rules_incomplete");
  assert.deepEqual(drift.recommended_action.follow_up_tool_calls.map((f) => f.platform), ["mac"]);
  assert.deepEqual(drift.policies[1].rules_missing, [P.CORPUS_BY_PLATFORM.mac[0].name]);
  assert.equal(c([policy("Custom", "Windows", { groups: [{ id: BANNED }, { id: "x" }] })]).case, "C_shared_policy");
  assert.equal(c([policy("Custom", "Windows")]).case, "B_dedicated_single_group");
  // Unreadable rule groups: counts stay 0 and nothing reads as drift.
  assert.equal(c([policy(managed("windows"), "Windows", { bound: WIN_RG })], null).case, "ready");
});

test("diagnose: no group, a missing group (404), a lookup error, a full run", async () => {
  // The saved group id lives in the settings DB; tests pass their own.
  const none = fakeCtx({});
  const noGroup = await P.diagnoseBannedSetup(none.ctx, null, async () => undefined);
  assert.equal(noGroup.case, "no_group_id");
  assert.equal(noGroup.recommended_action.tool, "extras_create_shadow_ai_banned_host_group");
  assert.equal(none.calls.length, 0);

  const missing = fakeCtx({ falcon_get_host_groups: () => ({ __error: "HTTP 404 not found" }) });
  assert.equal((await P.diagnoseBannedSetup(missing.ctx, BANNED)).case, "group_missing");

  const broken = fakeCtx({ falcon_get_host_groups: () => ({ __error: "HTTP 500 boom" }) });
  assert.deepEqual(await P.diagnoseBannedSetup(broken.ctx, BANNED), { ok: false, error: "HTTP 500 boom", surface: "HostGroup" });

  const full = fakeCtx({
    falcon_get_host_groups: () => ({ found: [{ id: BANNED, name: P.CANONICAL_GROUP_NAME, group_type: "static" }] }),
    falcon_search_policies: () => [policy(managed("windows"), "Windows", { bound: WIN_RG })],
    falcon_search_ioa_rule_groups: () => [rg(WIN_RG, { rules: fullRules("windows") })],
  });
  const res = await P.diagnoseBannedSetup(full.ctx, BANNED);
  assert.equal(res.case, "ready");
  assert.equal(res.policies[0].rules_in_group, P.CORPUS_BY_PLATFORM.windows.length);
});

// ------------------------------------------------ create / adopt

test("create and adopt the banned group", async () => {
  const c = fakeCtx({ falcon_create_host_group: (a) => ({ id: "g1", name: a.name, group_type: a.group_type }) });
  const created = await P.createBannedHostGroup(c.ctx, {});
  assert.deepEqual([created.ok, created.id, created.name], [true, "g1", P.CANONICAL_GROUP_NAME]);
  assert.equal(c.calls[0].args.group_type, "static");

  const one = fakeCtx({ falcon_search_host_groups: () => [{ id: "g1", name: P.CANONICAL_GROUP_NAME, group_type: "static" }] });
  assert.equal((await P.adoptBannedHostGroup(one.ctx, {})).id, "g1");
  assert.equal(one.calls[0].args.exact_name, P.CANONICAL_GROUP_NAME);
  const two = fakeCtx({ falcon_search_host_groups: () => [{ id: "a", name: "X" }, { id: "b", name: "X" }] });
  assert.match((await P.adoptBannedHostGroup(two.ctx, { name: "X" })).error, /refusing to guess/);
  const zero = fakeCtx({ falcon_search_host_groups: () => [] });
  assert.match((await P.adoptBannedHostGroup(zero.ctx, { name: "X" })).error, /no host group named 'X'/);
});

// ------------------------------------------------ provision

test("precedence placement: after the IR quarantine policy, else first", () => {
  const ps = [
    { id: "ir-w", name: "Project Eyas - IR Quarantine (auto, windows)", platform_name: "Windows" },
    { id: "std", name: "Standard", platform_name: "Windows" },
    { id: "ir-m", name: "Project Eyas - IR Quarantine (auto, mac)", platform_name: "Mac" },
  ];
  assert.deepEqual(P.bannedPlacement(ps, "windows", "ban"), { place_after: "ir-w" });
  assert.deepEqual(P.bannedPlacement(ps, "linux", "ban"), { place_first: true });
});

test("provision: adopts the windows policy, creates mac + linux, pushes settings, sets precedence", async () => {
  let n = 0;
  const f = fakeCtx({
    falcon_search_policies: () => [
      policy("Old name", "Windows"),
      { id: "ir-m", name: "Project Eyas - IR Quarantine (auto, mac)", platform_name: "Mac", groups: [] },
    ],
    falcon_create_policy: (a) => ({ id: `new-${a.platform_name}-${++n}` }),
    falcon_perform_policy_action: () => ({}),
    falcon_update_policy: () => ({}),
    falcon_get_policies: () => ({ found: [{ prevention_settings: [{ id: "OnSensorMLSlider", value: { detection: "MODERATE", prevention: "MODERATE" } }] }] }),
    falcon_set_policy_precedence: () => ({}),
  });
  const res = await P.provisionBannedPolicy(f.ctx, { host_group_id: BANNED });
  assert.equal(res.ok, true);
  const steps = res.actions.map((a) => `${a.platform}:${a.step}`);
  assert.deepEqual(steps, [
    "windows:rename",
    "windows:push_settings",
    "mac:create_and_attach",
    "mac:push_settings",
    "linux:create_and_attach",
    "linux:push_settings",
    "windows:set_precedence",
    "mac:set_precedence",
    "linux:set_precedence",
  ]);
  const prec = f.calls.filter((c) => c.name === "falcon_set_policy_precedence").map((c) => c.args);
  assert.deepEqual(prec[0], { policy_type: "prevention", platform_name: "Windows", move_id: "pol::Old name", place_first: true });
  assert.equal(prec[1].place_after, "ir-m");
  assert.deepEqual(res.follow_up_tool_calls.map((x) => [x.platform, x.args.mode]), [["windows", "block"], ["mac", "block"], ["linux", "block"]]);
  const rename = f.calls.find((c) => c.name === "falcon_update_policy" && c.args.name);
  assert.equal(rename.args.name, managed("windows"));
});

test("provision: input checks", async () => {
  const f = fakeCtx({});
  assert.match((await P.provisionBannedPolicy(f.ctx, {})).error, /host_group_id/);
  assert.match((await P.provisionBannedPolicy(f.ctx, { host_group_id: BANNED, mode: "x" })).error, /unknown mode/);
});

// ------------------------------------------------ adopt prevention

const RULE_TYPES = [
  { id: "rt-win", platform: "windows", name: "Process Creation" },
  { id: "rt-mac", platform: "mac", name: "Process Creation" },
  { id: "rt-net", platform: "windows", name: "Network Connection" },
];

test("rendering: field values and comment cleaning", () => {
  const r = P.CORPUS_BY_PLATFORM.windows.find((x) => x.cmdline_regex);
  const fv = P.toFieldValues(r);
  assert.deepEqual(fv.map((f) => f.name), ["ImageFilename", "CommandLine"]);
  assert.deepEqual(fv[0].values, [{ label: "include", value: r.image_regex }]);
  assert.equal(P.cleanComment("a\n\tb   c\u0007 "), "a b c");
});

test("adopt prevention: creates the group and rules, converges, enables, binds", async () => {
  let group = null;
  const f = fakeCtx({
    falcon_get_ioa_rule_types: () => RULE_TYPES,
    falcon_search_ioa_rule_groups: () => (group ? [group] : []),
    falcon_create_ioa_rule_group: (a) => {
      group = { id: "rg1", name: a.name, enabled: false, version: 1, rules: [] };
      return group;
    },
    falcon_create_ioa_rule: (a) => {
      if (a.name.includes("DeepSeek")) return { __error: "regex rejected" };
      group.rules.push({ name: a.name, instance_id: String(group.rules.length + 1), enabled: false, disposition_id: a.disposition_id });
      group.version += 1;
      return { name: a.name };
    },
    falcon_update_ioa_rule: (a) => {
      for (const u of a.rule_updates) Object.assign(group.rules.find((r) => r.instance_id === u.instance_id), { enabled: u.enabled });
      group.version += 1;
      return {};
    },
    falcon_update_ioa_rule_group: () => ({}),
    falcon_perform_policy_action: () => ({}),
  });
  const res = await P.adoptPrevention(f.ctx, { prevention_policy_id: "pol1", comment: "Ban\nrun" });
  assert.equal(res.ok, true);
  assert.equal(res.created_rule_group, true);
  assert.equal(res.ruletype_id, "rt-win");
  assert.equal(res.disposition_id, 30);
  const n = P.CORPUS_BY_PLATFORM.windows.length;
  assert.equal(res.rules_added.length, n - 1);
  assert.equal(res.rule_errors.length, 1);
  assert.equal(res.rules_converged.length, n - 1);
  const upd = f.calls.find((c) => c.name === "falcon_update_ioa_rule").args;
  assert.equal(upd.rulegroup_version, 1 + (n - 1));
  assert.deepEqual(Object.keys(upd.rule_updates[0]).sort(), ["disposition_id", "enabled", "instance_id"]);
  const en = f.calls.find((c) => c.name === "falcon_update_ioa_rule_group").args;
  assert.deepEqual([en.enabled, en.rulegroup_version, en.comment], [true, n + 1, "Ban run"]);
  const bind = f.calls.find((c) => c.name === "falcon_perform_policy_action").args;
  assert.deepEqual(bind, { policy_type: "prevention", action_name: "add-rule-group", ids: ["pol1"], group_id: "rg1" });
  assert.equal(f.calls.find((c) => c.name === "falcon_create_ioa_rule").args.comment, `Ban run [${P.CORPUS_BY_PLATFORM.windows[0].rationale_tag}]`);
});

test("adopt prevention: re-run converges only drifted rules; dry run writes nothing", async () => {
  const rules = P.CORPUS_BY_PLATFORM.mac.map((r, i) => ({ name: r.name, instance_id: String(i), enabled: true, disposition_id: 30 }));
  rules[0].enabled = false;
  rules[1].disposition_id = 20;
  const group = { id: "rgm", name: MAC_RG, enabled: true, version: 7, rules };
  const handlers = {
    falcon_get_ioa_rule_types: () => RULE_TYPES,
    falcon_search_ioa_rule_groups: () => [group],
    falcon_update_ioa_rule: () => ({}),
    falcon_update_ioa_rule_group: () => ({}),
    falcon_perform_policy_action: () => ({}),
  };
  const dry = fakeCtx(handlers);
  const plan = await P.adoptPrevention(dry.ctx, { prevention_policy_id: "p", comment: "c", platform: "mac", dry_run: true });
  assert.equal(dry.writes().length, 0);
  assert.deepEqual(plan.plan.would_create_rules, []);
  assert.deepEqual(plan.plan.would_enable_or_redisposition.map((x) => x.name), [rules[0].name, rules[1].name]);
  assert.equal(plan.rendered_count, P.CORPUS_BY_PLATFORM.mac.length);
  // The long rule list goes last, so a capped result keeps the plan.
  assert.equal(Object.keys(plan).at(-1), "rendered_rules");

  const live = fakeCtx(handlers);
  const res = await P.adoptPrevention(live.ctx, { prevention_policy_id: "p", comment: "c", platform: "mac" });
  assert.deepEqual(res.rules_added, []);
  assert.deepEqual(res.rules_converged, [rules[0].name, rules[1].name]);
  assert.equal(res.rules_already_correct.length, rules.length - 2);
});

test("adopt prevention: input checks and a missing rule type", async () => {
  const f = fakeCtx({ falcon_get_ioa_rule_types: () => RULE_TYPES });
  assert.match((await P.adoptPrevention(f.ctx, { comment: "c" })).error, /prevention_policy_id/);
  assert.match((await P.adoptPrevention(f.ctx, { prevention_policy_id: "p" })).error, /comment is required/);
  assert.match((await P.adoptPrevention(f.ctx, { prevention_policy_id: "p", comment: "c", mode: "kill" })).error, /mode must be/);
  assert.match((await P.adoptPrevention(f.ctx, { prevention_policy_id: "p", comment: "c", platform: "bsd" })).error, /platform must be/);
  const r = await P.adoptPrevention(f.ctx, { prevention_policy_id: "p", comment: "c", platform: "linux" });
  assert.match(r.error, /linux Process Creation rule type not found/);
});

test("binding check: no saved group; a full run", async () => {
  const none = fakeCtx({});
  const res = await P.checkPreventionBinding(none.ctx, async () => undefined);
  assert.deepEqual([res.ready, res.banned_group_id, res.missing_steps.length], [false, null, 1]);
  const full = fakeCtx({
    falcon_search_ioa_rule_groups: () => [rg(WIN_RG)],
    falcon_search_policies: () => [policy("Win Policy", "Windows", { bound: WIN_RG })],
  });
  assert.equal((await P.checkPreventionBinding(full.ctx, async () => BANNED)).ready, true);
});
