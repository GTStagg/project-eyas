#!/usr/bin/env node
// Tests for the Project Eyas tenant teardown and its deletes
// (lib/eyas-tools/teardown.ts) against a fake eyas-mcp that records calls.
// Run as: node scripts/test-teardown.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.TEARDOWN_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-teardown.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, TEARDOWN_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const td = await import(pathToFileURL(path.join(root, "lib/eyas-tools/teardown.ts")).href);
const q = await import(pathToFileURL(path.join(root, "lib/eyas-tools/quarantine.ts")).href);

const IDS = { ir: "g-ir", banned: "g-adopted-banned" };
const groups = [
  { id: "g-ir", name: "Project Eyas - IR Quarantine", group_type: "static" },
  { id: "g-adopted-banned", name: "Our AI ban list", group_type: "static" },
  { id: "g-prod", name: "Production", group_type: "dynamic" },
];
const policies = {
  Windows: [
    { id: "p-ir-w", name: "Project Eyas - IR Quarantine (auto, windows)", platform_name: "Windows", enabled: true, groups: [{ id: "g-ir" }] },
    { id: "p-ops", name: "Ops default", platform_name: "Windows", enabled: true, groups: [{ id: "g-prod" }] },
  ],
  Mac: [{ id: "p-ban-m", name: "Project Eyas - Shadow-AI Banned (auto, mac)", platform_name: "Mac", enabled: false, groups: [] }],
  Linux: [],
};
const ruleGroups = [
  { id: "rg-w", name: "Project Eyas - Shadow-AI Block", platform: "windows", enabled: true },
  { id: "rg-other", name: "SOC custom rules", platform: "windows", enabled: true },
];
const exclusions = [
  { id: "x-preamble", host_groups: ["g-ir"], cl_regex: q.RTR_PREAMBLE_FULL_REGEX, comment: "Suppresses PShellMimikatz ..." },
  { id: "x-named", name: q.READINESS_EXCLUSION_NAME, cl_regex: ".*" },
  { id: "x-legacy", comment: "IR-readiness exclusion, made by hand" },
  { id: "x-unrelated", name: "Build farm", cl_regex: ".*msbuild.*" },
];

function fakeCtx({ fail = {} } = {}) {
  const calls = [];
  return {
    calls,
    callNative: async (name, args) => {
      calls.push({ name, args });
      return fail[name] ? { obj: null, error: fail[name] } : { obj: {}, error: null };
    },
    searchNative: async (name, args) => {
      calls.push({ name, args });
      if (name === "falcon_search_host_groups") return { ok: true, items: groups };
      if (name === "falcon_search_policies") {
        const platform = /platform_name:'(\w+)'/.exec(args.filter)?.[1];
        return { ok: true, items: policies[platform] ?? [] };
      }
      if (name === "falcon_search_ioa_rule_groups") return { ok: true, items: ruleGroups };
      if (name === "falcon_search_exclusions") return { ok: true, items: exclusions };
      return { ok: false, error: `unexpected ${name}` };
    },
  };
}
const writes = (ctx) => ctx.calls.filter((c) => !c.name.startsWith("falcon_search_"));

test("readiness exclusion is found by its marker, name or legacy comment", () => {
  assert.equal(td.isReadinessExclusion(exclusions[0]), true);
  assert.equal(td.isReadinessExclusion(exclusions[1]), true);
  assert.equal(td.isReadinessExclusion(exclusions[2]), true);
  assert.equal(td.isReadinessExclusion(exclusions[3]), false);
  // What provisioning actually writes: the old comment-only match missed it.
  assert.equal(td.isReadinessExclusion({ comment: q.READINESS_EXCLUSION_COMMENT_PROVISIONED, cl_regex: q.RTR_PREAMBLE_FULL_REGEX }), true);
  assert.equal(q.READINESS_EXCLUSION_COMMENT_PROVISIONED.includes("IR-readiness"), false);
});

test("dry run discovers only Project Eyas objects and writes nothing", async () => {
  const ctx = fakeCtx();
  const r = await td.teardownProjectEyasManaged(ctx, {}, IDS);
  assert.equal(r.dry_run, true);
  assert.equal(writes(ctx).length, 0);
  assert.deepEqual(r.plan.host_groups.map((g) => [g.id, g.match_reason]), [["g-ir", "canonical_name"], ["g-adopted-banned", "active_env_id"]]);
  assert.deepEqual(r.plan.prevention_policies.map((p) => p.id), ["p-ir-w", "p-ban-m"]);
  assert.deepEqual(r.plan.rule_groups.map((g) => g.id), ["rg-w"]);
  assert.deepEqual(r.plan.ioa_exclusions.map((e) => e.id), ["x-preamble", "x-named", "x-legacy"]);
  assert.deepEqual(r.summary, {
    host_groups_count: 2,
    prevention_policies_count: 2,
    rule_groups_count: 1,
    ioa_exclusions_count: 3,
    discovery_errors_count: 0,
  });
  // Policies are listed per platform.
  const filters = ctx.calls.filter((c) => c.name === "falcon_search_policies").map((c) => c.args.filter);
  assert.deepEqual(filters, ["platform_name:'Windows'", "platform_name:'Mac'", "platform_name:'Linux'"]);
});

test("execute runs in Falcon's dependency order", async () => {
  const ctx = fakeCtx();
  const r = await td.teardownProjectEyasManaged(ctx, { dry_run: false }, IDS);
  assert.equal(r.ok, true);
  assert.deepEqual(
    writes(ctx).map((c) => [c.name, c.args.action_name ?? "", (c.args.ids ?? [])[0]]),
    [
      ["falcon_perform_policy_action", "remove-host-group", "p-ir-w"],
      ["falcon_perform_policy_action", "disable", "p-ir-w"],
      ["falcon_delete_policies", "", "p-ir-w"],
      ["falcon_delete_policies", "", "p-ban-m"],
      ["falcon_delete_ioa_rule_groups", "", "rg-w"],
      ["falcon_delete_exclusions", "", "x-preamble"],
      ["falcon_delete_exclusions", "", "x-named"],
      ["falcon_delete_exclusions", "", "x-legacy"],
      ["falcon_delete_host_groups", "", "g-ir"],
      ["falcon_delete_host_groups", "", "g-adopted-banned"],
    ],
  );
  assert.equal(r.summary.executed_steps, 10);
  assert.equal(r.summary.failed, 0);
});

test("a failed step is reported and the rest still runs", async () => {
  const ctx = fakeCtx({ fail: { falcon_delete_ioa_rule_groups: "HTTP 409: still bound" } });
  const r = await td.teardownProjectEyasManaged(ctx, { dry_run: false }, IDS);
  assert.equal(r.ok, false);
  assert.equal(r.summary.failed, 1);
  const bad = r.steps.find((s) => !s.ok);
  assert.equal(bad.step, "delete_rule_group");
  assert.match(bad.error, /still bound/);
  assert.equal(r.steps.at(-1).step, "delete_host_group");
});

test("single deletes", async () => {
  const ctx = fakeCtx();
  assert.deepEqual(await td.deletePreventionPolicy(ctx, { prevention_policy_id: "p1" }), { ok: true, id: "p1", deleted: true });
  assert.deepEqual(ctx.calls[0].args, { policy_type: "prevention", ids: ["p1"], disable_first: true });
  const rg = await td.deleteIoaRuleGroup(ctx, { rule_group_id: "rg1" });
  assert.equal(rg.ok, true);
  assert.equal(ctx.calls[1].args.comment, "Project Eyas teardown");
  assert.equal((await td.deletePreventionPolicy(fakeCtx(), {})).ok, false);
  const failed = await td.deleteIoaRuleGroup(fakeCtx({ fail: { falcon_delete_ioa_rule_groups: "HTTP 409" } }), { rule_group_id: "rg1" });
  assert.equal(failed.ok, false);
});

test("the readiness exclusion name matches with a plain hyphen too (how Falcon stores it)", () => {
  assert.equal(td.isReadinessExclusion({ name: "Project Eyas IR - RTR runscript preamble", cl_regex: ".*" }), true);
});

test("host groups are paged 500 at a time until the total is reached", async () => {
  const many = Array.from({ length: 1201 }, (_, i) => ({ id: `g${i}`, name: i === 1100 ? "Project Eyas - IR Quarantine" : `G${i}` }));
  const offsets = [];
  const ctx = {
    callNative: async () => ({ obj: {}, error: null }),
    searchNative: async (name, args) => {
      if (name === "falcon_search_host_groups") {
        offsets.push([args.offset, args.limit]);
        return { ok: true, items: many.slice(args.offset, args.offset + args.limit), total: many.length };
      }
      return { ok: true, items: [] };
    },
  };
  const r = await td.teardownProjectEyasManaged(ctx, {}, { ir: "", banned: "" });
  assert.deepEqual(offsets, [[0, 500], [500, 500], [1000, 500]]);
  assert.deepEqual(r.plan.host_groups.map((g) => g.id), ["g1100"]);
});
