// Shadow-AI Banned setup and prevention: the banned host group (diagnose /
// create / adopt), per-platform prevention-policy provisioning, the Custom IOA
// rule bundle (status / adopt) and the end-to-end binding check.
//
// The model is default-allow, opt-in to enforcement: standard prevention
// policies do NOT carry the Shadow-AI rule group, so users can install AI
// tools by default. To block a host, the operator adds it to the
// "Project Eyas - Shadow-AI Banned" group; that group's policy wins by
// precedence (below IR Quarantine, above everything else) and carries the
// platform's Shadow-AI rule group.
//
// Naming:
//   host group       Project Eyas - Shadow-AI Banned
//   policies         Project Eyas - Shadow-AI Banned (auto, <platform>)
//   rule groups      Project Eyas - Shadow-AI Block / … (mac) / … (linux)
//
// Every Falcon call is an eyas-mcp native. The group id comes from an
// explicit argument or the active environment's saved setting, read at call
// time, so a group created or adopted earlier in the same chat turn (the chat
// route's auto-save writes it mid-turn) is seen at once. The rule corpus is
// ./ioa-corpus.json, exported from the sidecar's shadow_ai/ioa_rules.py.
// Ported from the sidecar's shadow_ai/{provision_banned,tools}.py; tested in
// scripts/test-shadow-ai-prevention.mjs.

import type { EyasToolContext } from "../types";
import { groupIdsOf } from "../quarantine";
import { PLATFORMS, planMaxProtectiveSettings } from "../quarantine-provision";
import corpusData from "./ioa-corpus.json";

type Obj = Record<string, unknown>;
type Platform = (typeof PLATFORMS)[number];

export const CANONICAL_GROUP_NAME = "Project Eyas - Shadow-AI Banned";
export const CANONICAL_POLICY_PREFIX = "Project Eyas - Shadow-AI Banned (auto"; // closed by ", <platform>)"
const IR_POLICY_PREFIX = "Project Eyas - IR Quarantine (auto";
const TARGET_LEVEL = "AGGRESSIVE";
const API_PLATFORM: Record<Platform, string> = { windows: "Windows", mac: "Mac", linux: "Linux" };

// Process Creation disposition ids: 10 Monitor, 20 Detect, 30 Block Execution.
export const DISPOSITION_DETECT = 20;
export const DISPOSITION_BLOCK = 30;

export type IoaRule = {
  name: string;
  description: string;
  pattern_severity: string;
  image_regex: string;
  cmdline_regex: string | null;
  parent_image_regex: string | null;
  rationale_tag: string;
};

export const RULE_GROUP_NAMES: Record<Platform, string> = corpusData.rule_group_names as Record<Platform, string>;
export const RULE_GROUP_NAME = RULE_GROUP_NAMES.windows;
export const RULE_GROUP_DESCRIPTION: string = corpusData.rule_group_description;
export const CORPUS_BY_PLATFORM: Record<Platform, IoaRule[]> = corpusData.corpus as Record<Platform, IoaRule[]>;

const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown): string => (typeof v === "string" ? v : "");

/** A rule's match conditions as Custom IOA `field_values`: each an
 *  `excludable` Process-Creation field with one positive value. */
export function toFieldValues(r: IoaRule): Obj[] {
  const out: Obj[] = [];
  const add = (name: string, label: string, value: string | null) => {
    if (value) out.push({ name, label, type: "excludable", values: [{ label: "include", value }] });
  };
  add("ImageFilename", "Image Filename", r.image_regex);
  add("CommandLine", "Command Line", r.cmdline_regex);
  add("ParentImageFilename", "Parent Image Filename", r.parent_image_regex);
  return out;
}

export function ruleCorpusSummary(platform: string): Obj[] {
  return (CORPUS_BY_PLATFORM[platform.toLowerCase() as Platform] ?? []).map((r) => ({
    name: r.name,
    description: r.description,
    pattern_severity: r.pattern_severity,
    rationale_tag: r.rationale_tag,
    image_regex: r.image_regex,
    cmdline_regex: r.cmdline_regex,
    parent_image_regex: r.parent_image_regex,
  }));
}

// ---------------------------------------------------------------- plumbing

function scopePayload(surface: string, diagnostic: string): Obj {
  return {
    ok: true,
    scope_pending: true,
    surface,
    items: [],
    count: 0,
    note:
      `This call returned a permission error. The ${surface} surface renders empty until the Falcon ` +
      "API client is granted the required scope. Tell the operator: 'No data — required Falcon API " +
      `scope for ${surface} is not yet granted on this tenant.'`,
    _diagnostic: diagnostic.slice(0, 200),
  };
}

async function failPayload(surface: string, error: string): Promise<Obj> {
  const { isScopeDenied } = await import("@/lib/mcp/parse");
  return isScopeDenied(error) ? scopePayload(surface, error) : { ok: false, error, surface };
}

/** The active environment's Shadow-AI banned group (read at call time). */
export async function activeBannedGroupId(): Promise<string | undefined> {
  const { getRuntimeConfig } = await import("@/lib/config/runtime");
  return getRuntimeConfig().shadowAiBannedGroupId || undefined;
}

type Fetch<T> = { ok: true; value: T } | { ok: false; payload: Obj };

async function preventionPolicies(ctx: EyasToolContext): Promise<Fetch<Obj[]>> {
  const r = await ctx.searchNative("falcon_search_policies", { policy_type: "prevention", limit: 500 });
  if (!r.ok) return { ok: false, payload: await failPayload("Prevention Policies", r.error) };
  if (r.scope_pending) return { ok: false, payload: scopePayload("Prevention Policies", "permission denied") };
  return { ok: true, value: r.items };
}

/** Every Shadow-AI rule group by platform (null when it doesn't exist),
 *  each with its full rules. One listing, matched by exact name. */
async function shadowAiRuleGroups(ctx: EyasToolContext): Promise<Fetch<Record<Platform, Obj | null>>> {
  const r = await ctx.searchNative("falcon_search_ioa_rule_groups", { limit: 500 });
  if (!r.ok) return { ok: false, payload: await failPayload("CustomIOA", r.error) };
  if (r.scope_pending) return { ok: false, payload: scopePayload("CustomIOA", "permission denied") };
  const out = { windows: null, mac: null, linux: null } as Record<Platform, Obj | null>;
  for (const p of PLATFORMS) out[p] = r.items.find((g) => g.name === RULE_GROUP_NAMES[p]) ?? null;
  return { ok: true, value: out };
}

async function shadowAiRuleGroup(ctx: EyasToolContext, platform: Platform): Promise<Fetch<Obj | null>> {
  const all = await shadowAiRuleGroups(ctx);
  return all.ok ? { ok: true, value: all.value[platform] } : all;
}

const ruleNames = (group: Obj | null): string[] =>
  (Array.isArray(group?.rules) ? (group!.rules as unknown[]) : []).filter(isObj).map((r) => str(r.name)).filter(Boolean);

/** The Process Creation rule type for a platform (ids differ per tenant). */
async function processCreationRuleType(ctx: EyasToolContext, platform: Platform): Promise<Fetch<string>> {
  const r = await ctx.searchNative("falcon_get_ioa_rule_types", { limit: 500 });
  if (!r.ok) return { ok: false, payload: await failPayload("CustomIOA", r.error) };
  if (r.scope_pending) return { ok: false, payload: scopePayload("CustomIOA", "permission denied") };
  if (r.items.length === 0) return { ok: false, payload: { ok: false, error: "no Custom IOA rule types returned" } };
  for (const t of r.items) {
    if (str(t.platform).toLowerCase() === platform && str(t.name).toLowerCase().includes("process creation")) {
      return { ok: true, value: String(t.id) };
    }
  }
  return {
    ok: false,
    payload: {
      ok: false,
      error: `${platform} Process Creation rule type not found in tenant`,
      available_types: r.items.map((t) => `${t.platform ?? null}: ${t.name ?? null}`),
    },
  };
}

// ---------------------------------------------------------------- diagnose

function recommendProvision(hostGroupId: string, mode: "adopt" | "create_dedicated"): Obj {
  const adopt = mode === "adopt";
  return {
    tool: "extras_provision_shadow_ai_banned_policy",
    args: { host_group_id: hostGroupId, mode },
    label: adopt
      ? "Provision the Shadow-AI Banned prevention policy (adopt + standardize)"
      : "Create dedicated prevention policies for Shadow-AI Banned",
    description: adopt
      ? "Adopts the policy currently bound to this group (or attaches a fresh one if none exists), renames it to " +
        `canonical naming, pushes ${TARGET_LEVEL} prevention sliders, and attaches the '${RULE_GROUP_NAME}' Custom ` +
        "IOA rule group. Sets per-platform precedence above standard policies but below IR Quarantine. Per " +
        "platform: Windows, macOS, Linux."
      : `Your existing policy is attached to other host groups, so pushing ${TARGET_LEVEL} settings + the ` +
        "Shadow-AI rule group to it would change posture on those groups too. This action creates a new dedicated " +
        "prevention policy per platform bound ONLY to the Shadow-AI Banned group, leaves the existing policy alone, " +
        "and attaches the rule group + sets precedence.",
  };
}

const platformOf = (p: Obj) => str(p.platform).toLowerCase() || "?";

function recommendCorpusRefresh(policiesOnGroup: Obj[]): Obj {
  const affected = policiesOnGroup.filter((p) => (p.rules_missing as string[]).length > 0);
  const platforms = affected.map((p) => `${platformOf(p)} (${(p.rules_missing as string[]).length} missing)`).join(", ");
  return {
    tool: "extras_shadow_ai_adopt_prevention",
    args: {}, // multi-call shape — the caller iterates follow_up_tool_calls
    label: "Refresh Shadow-AI rule corpus (incomplete coverage)",
    description:
      "The rule groups are bound, but some rules from the per-platform corpus aren't actually in the rule groups: " +
      `${platforms}. The previous adoption run authored a partial set; re-running ` +
      "extras_shadow_ai_adopt_prevention per affected platform fills in the missing rules (idempotent — " +
      "already-present rules are skipped by name).",
    follow_up_tool_calls: affected.map((p) => ({
      tool: "extras_shadow_ai_adopt_prevention",
      args: {
        prevention_policy_id: p.id,
        comment:
          `Project Eyas - Shadow-AI rule corpus refresh (${platformOf(p)}) - filling ` +
          `${(p.rules_missing as string[]).length} rule(s) missing from a prior adoption run.`,
        mode: "block",
        platform: str(p.platform).toLowerCase(),
      },
      platform: str(p.platform).toLowerCase(),
      missing_rules: p.rules_missing,
    })),
  };
}

function createGroupAction(description: string): Obj {
  return {
    tool: "extras_create_shadow_ai_banned_host_group",
    args: { name: CANONICAL_GROUP_NAME },
    label: "Create the Shadow-AI Banned host group",
    description,
  };
}

/** Classify the banned setup from fetched records (pure). `ruleGroups` is
 *  null when the rule groups couldn't be read (counts then stay 0). */
export function classifyBannedSetup(d: {
  hostGroupId: string;
  group: Obj;
  policies: Obj[];
  ruleGroups: Record<Platform, Obj | null> | null;
}): Obj {
  // The rule-group summary inside a policy's ioa_rule_groups[] carries no
  // rules, so rule counts come from the rule groups themselves.
  const namesByGroup = new Map<string, Set<string>>();
  for (const p of PLATFORMS) {
    const g = d.ruleGroups?.[p];
    if (g && str(g.name)) namesByGroup.set(str(g.name), new Set(ruleNames(g)));
  }

  const onGroup: Obj[] = [];
  let attachedAnywhere = false;
  for (const p of d.policies) {
    const attached = groupIdsOf(p);
    if (!attached.includes(d.hostGroupId)) continue;
    const plat = str(p.platform_name).toLowerCase() as Platform;
    const expected = RULE_GROUP_NAMES[plat];
    const ioa = (Array.isArray(p.ioa_rule_groups) ? p.ioa_rule_groups : []).filter(isObj);
    const bound = expected ? ioa.find((rg) => rg.name === expected) ?? null : null;
    const corpus = CORPUS_BY_PLATFORM[plat] ?? [];
    let inGroup = 0;
    const missing: string[] = [];
    if (bound && expected && namesByGroup.has(expected)) {
      const existing = namesByGroup.get(expected) as Set<string>;
      inGroup = existing.size;
      for (const r of corpus) if (!existing.has(r.name)) missing.push(r.name);
    }
    if (bound) attachedAnywhere = true;
    onGroup.push({
      id: p.id ?? null,
      name: p.name ?? null,
      platform: p.platform_name ?? null,
      enabled: p.enabled === undefined ? true : Boolean(p.enabled),
      attached_group_ids: attached,
      is_dedicated: attached.length === 1,
      managed_by_eyas: typeof p.name === "string" && p.name.startsWith(CANONICAL_POLICY_PREFIX),
      rule_group_bound: bound !== null,
      rules_in_group: inGroup,
      rules_expected: corpus.length,
      rules_missing: missing,
    });
  }

  let kase: string;
  let rec: Obj | null;
  if (onGroup.length === 0) {
    kase = "A_no_policy";
    rec = recommendProvision(d.hostGroupId, "adopt");
  } else {
    const anyShared = onGroup.some((p) => !p.is_dedicated);
    const allGood = onGroup.every((p) => p.managed_by_eyas) && onGroup.every((p) => p.rule_group_bound);
    const drift = onGroup.some((p) => (p.rules_missing as string[]).length > 0);
    if (allGood && !drift) {
      kase = "ready";
      rec = null;
    } else if (allGood && drift) {
      kase = "rules_incomplete";
      rec = recommendCorpusRefresh(onGroup);
    } else if (anyShared) {
      kase = "C_shared_policy";
      rec = recommendProvision(d.hostGroupId, "create_dedicated");
    } else {
      kase = "B_dedicated_single_group";
      rec = recommendProvision(d.hostGroupId, "adopt");
    }
  }
  return {
    ok: true,
    case: kase,
    host_group_id: d.hostGroupId,
    host_group: { id: d.group.id ?? null, name: d.group.name ?? null, group_type: d.group.group_type ?? null },
    policies: onGroup,
    rule_group_attached: attachedAnywhere,
    recommended_action: rec,
  };
}

/** extras_diagnose_shadow_ai_banned_setup. */
export async function diagnoseBannedSetup(
  ctx: EyasToolContext,
  explicitGroupId?: string | null,
  savedGroupId: () => Promise<string | undefined> = activeBannedGroupId,
): Promise<Obj> {
  const hostGroupId = explicitGroupId || (await savedGroupId());
  if (!hostGroupId) {
    return {
      ok: true,
      case: "no_group_id",
      host_group_id: null,
      host_group: null,
      policies: [],
      rule_group_attached: false,
      recommended_action: createGroupAction(
        `Creates a new static host group named '${CANONICAL_GROUP_NAME}'. After creation, save the returned id as ` +
          "the Shadow-AI banned group on the active environment, then run extras_provision_shadow_ai_banned_policy " +
          "to attach the prevention policies + Shadow-AI rule group.",
      ),
    };
  }

  const g = await ctx.callNative("falcon_get_host_groups", { ids: [hostGroupId] });
  let group: Obj | undefined;
  if (g.error) {
    // A 404 means the configured id doesn't exist: the friendly CTA, not a
    // raw error.
    if (!g.error.includes("404")) return failPayload("HostGroup", g.error);
  } else {
    const found = Array.isArray(g.obj?.found) ? (g.obj.found as unknown[]).filter(isObj) : [];
    group = found.find((x) => x.id === hostGroupId) ?? found[0];
  }
  if (!group) {
    return {
      ok: true,
      case: "group_missing",
      host_group_id: hostGroupId,
      host_group: null,
      policies: [],
      rule_group_attached: false,
      recommended_action: createGroupAction(
        `The configured group id '${hostGroupId}' does not exist in this tenant. Create a fresh group and update ` +
          "the Shadow-AI banned field with the new id.",
      ),
    };
  }

  const pol = await preventionPolicies(ctx);
  if (!pol.ok) return pol.payload;
  // Non-fatal: unreadable rule groups leave the counts at 0.
  const rg = await shadowAiRuleGroups(ctx);
  return classifyBannedSetup({ hostGroupId, group, policies: pol.value, ruleGroups: rg.ok ? rg.value : null });
}

// ---------------------------------------------------------------- create / adopt

/** extras_create_shadow_ai_banned_host_group. */
export async function createBannedHostGroup(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const name = input.name === undefined || input.name === null ? CANONICAL_GROUP_NAME : input.name;
  if (typeof name !== "string" || !name) return { ok: false, error: "name is required" };
  const description =
    (typeof input.description === "string" && input.description) ||
    "App-managed: hosts placed here are blocked from installing or running unsanctioned AI tools (Claude " +
      "Desktop, Cursor, Ollama, LM Studio, etc.). The Shadow-AI Custom IOA rule group is attached to the " +
      "prevention policy bound to this group; default-allow remains the tenant baseline.";
  const r = await ctx.callNative("falcon_create_host_group", { name, group_type: "static", description });
  if (r.error) return failPayload("HostGroup", r.error);
  const rec = r.obj;
  if (!rec || typeof rec.id !== "string") return { ok: false, error: "create_host_groups returned no record" };
  return {
    ok: true,
    id: rec.id,
    name: rec.name ?? name,
    group_type: rec.group_type ?? "static",
    next_step:
      "The new group id is saved to the active environment automatically — no manual step is needed. Proceed " +
      "directly to extras_provision_shadow_ai_banned_policy with this host_group_id.",
  };
}

/** extras_adopt_shadow_ai_banned_host_group. */
export async function adoptBannedHostGroup(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const name = input.name === undefined || input.name === null ? CANONICAL_GROUP_NAME : input.name;
  if (typeof name !== "string" || !name) return { ok: false, error: "name is required" };
  // exact_name pages through every group and compares case-sensitively; FQL
  // name matching is unreliable for names with spaces and hyphens.
  const r = await ctx.searchNative("falcon_search_host_groups", { exact_name: name, limit: 500 });
  if (!r.ok) return failPayload("HostGroup", r.error);
  if (r.scope_pending) return scopePayload("HostGroup", "permission denied");
  const exact = r.items.filter((g) => g.name === name);
  if (exact.length === 0) {
    return {
      ok: false,
      error: `no host group named '${name}' found in this tenant`,
      hint: "use extras_create_shadow_ai_banned_host_group to create it",
    };
  }
  if (exact.length > 1) {
    return {
      ok: false,
      error: `multiple host groups named '${name}' — refusing to guess`,
      candidates: exact.map((g) => ({ id: g.id ?? null, group_type: g.group_type ?? null })),
    };
  }
  const rec = exact[0];
  return {
    ok: true,
    id: rec.id ?? null,
    name: rec.name ?? null,
    group_type: rec.group_type ?? null,
    next_step: "Saved as the active environment's Shadow-AI banned group.",
  };
}

// ---------------------------------------------------------------- provision

async function pushMaxProtective(ctx: EyasToolContext, policyId: string): Promise<Obj> {
  const got = await ctx.callNative("falcon_get_policies", { policy_type: "prevention", ids: [policyId] });
  if (got.error) return { ok: false, stage: "get_for_update", error: got.error };
  const rec = (Array.isArray(got.obj?.found) ? (got.obj.found as unknown[]).filter(isObj) : [])[0];
  if (!rec) return { ok: false, stage: "get_for_update", error: "no record" };
  const plan = planMaxProtectiveSettings(rec.prevention_settings);
  if (plan.slidersTouched === 0 && plan.togglesTouched === 0) {
    return { ok: true, sliders_touched: 0, toggles_touched: 0, note: "policy already at max-protective state" };
  }
  const upd = await ctx.callNative("falcon_update_policy", { policy_type: "prevention", id: policyId, settings: plan.flat });
  if (upd.error) return { ok: false, stage: "update_settings", error: upd.error };
  return { ok: true, sliders_touched: plan.slidersTouched, toggles_touched: plan.togglesTouched };
}

async function createPolicyAndAttach(ctx: EyasToolContext, name: string, platform: Platform, hostGroupId: string): Promise<Obj> {
  const created = await ctx.callNative("falcon_create_policy", {
    policy_type: "prevention",
    name,
    platform_name: API_PLATFORM[platform],
    description: "App-managed by Project Eyas. AGGRESSIVE prevention sliders + the Shadow-AI rule group for hosts in the Shadow-AI Banned group. Do not edit manually.",
  });
  if (created.error) return { ok: false, stage: "create_policies", error: created.error };
  const policyId = typeof created.obj?.id === "string" ? created.obj.id : null;
  if (!policyId) return { ok: false, stage: "create_policies", error: "no record returned" };
  const attach = await ctx.callNative("falcon_perform_policy_action", {
    policy_type: "prevention",
    action_name: "add-host-group",
    ids: [policyId],
    group_id: hostGroupId,
  });
  if (attach.error) return { ok: false, stage: "attach_group", policy_id: policyId, error: attach.error };
  // New policies are created disabled.
  const enable = await ctx.callNative("falcon_perform_policy_action", { policy_type: "prevention", action_name: "enable", ids: [policyId] });
  if (enable.error) return { ok: false, stage: "enable", policy_id: policyId, error: enable.error };
  return { ok: true, policy_id: policyId };
}

/** Where the banned policy goes in its platform's precedence: directly after
 *  the last IR Quarantine policy when there is one, else first. Pure. */
export function bannedPlacement(policies: Obj[], platform: Platform, targetId: string): { place_after: string } | { place_first: true } {
  const ir = policies.filter(
    (p) =>
      str(p.platform_name).toLowerCase() === platform &&
      p.name !== "platform_default" &&
      p.id !== targetId &&
      str(p.name).startsWith(IR_POLICY_PREFIX) &&
      typeof p.id === "string" &&
      p.id,
  );
  return ir.length ? { place_after: String(ir[ir.length - 1].id) } : { place_first: true };
}

/** extras_provision_shadow_ai_banned_policy. */
export async function provisionBannedPolicy(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const hostGroupId = input.host_group_id;
  if (typeof hostGroupId !== "string" || !hostGroupId) return { ok: false, error: "host_group_id is required" };
  const mode = input.mode === undefined || input.mode === null ? "adopt" : input.mode;
  if (mode !== "adopt" && mode !== "create_dedicated") return { ok: false, error: `unknown mode '${String(mode)}'` };

  const pol = await preventionPolicies(ctx);
  if (!pol.ok) return pol.payload.scope_pending ? pol.payload : { ok: false, error: `policy walk: ${String(pol.payload.error)}` };
  const all = pol.value;

  const existing: Record<Platform, { policy: Obj; attached: string[] }[]> = { windows: [], mac: [], linux: [] };
  for (const p of all) {
    const platform = str(p.platform_name).toLowerCase() as Platform;
    if (!(platform in existing)) continue;
    const attached = groupIdsOf(p);
    if (attached.includes(hostGroupId)) existing[platform].push({ policy: p, attached });
  }

  const actions: Obj[] = [];
  const errors: Obj[] = [];
  const bannedIds: Partial<Record<Platform, string>> = {};
  for (const platform of PLATFORMS) {
    const targetName = `${CANONICAL_POLICY_PREFIX}, ${platform})`;
    let chosen: { policy: Obj; attached: string[] } | null = null;
    if (mode === "adopt" && existing[platform].length) {
      const single = existing[platform].filter((e) => e.attached.length === 1);
      chosen = (single.length ? single : existing[platform])[0];
    }
    let policyId: string;
    if (!chosen) {
      const r = await createPolicyAndAttach(ctx, targetName, platform, hostGroupId);
      if (r.ok !== true) {
        errors.push({ platform, ...r });
        continue;
      }
      policyId = String(r.policy_id);
      actions.push({ platform, step: "create_and_attach", policy_id: policyId, policy_name: targetName });
    } else {
      policyId = String(chosen.policy.id ?? "");
      const currentName = str(chosen.policy.name);
      if (currentName !== targetName) {
        const r = await ctx.callNative("falcon_update_policy", { policy_type: "prevention", id: policyId, name: targetName });
        if (r.error) {
          errors.push({ platform, ok: false, stage: "rename", error: r.error });
          continue;
        }
        actions.push({ platform, step: "rename", policy_id: policyId, from: currentName, to: targetName });
      }
    }
    const push = await pushMaxProtective(ctx, policyId);
    if (push.ok !== true) {
      errors.push({ platform, ...push });
      continue;
    }
    actions.push({
      platform,
      step: "push_settings",
      policy_id: policyId,
      level: TARGET_LEVEL,
      sliders_touched: push.sliders_touched ?? 0,
      toggles_touched: push.toggles_touched ?? 0,
    });
    bannedIds[platform] = policyId;
  }

  // Precedence: IR Quarantine first (when present), then Shadow-AI Banned,
  // then the rest. eyas-mcp builds the complete order itself.
  for (const platform of PLATFORMS) {
    const policyId = bannedIds[platform];
    if (!policyId) continue;
    const placement = bannedPlacement(all, platform, policyId);
    const r = await ctx.callNative("falcon_set_policy_precedence", {
      policy_type: "prevention",
      platform_name: API_PLATFORM[platform],
      move_id: policyId,
      ...placement,
    });
    if (r.error) {
      errors.push({ platform, stage: "set_precedence", ok: false, error: r.error });
      actions.push({
        platform,
        step: "set_precedence",
        policy_id: policyId,
        ok: false,
        warning:
          "Precedence not set — Shadow-AI rules may not enforce if a host is also in another group whose policy has " +
          "higher precedence. Fix in Falcon Console (Endpoint security → Prevention policies → reorder).",
      });
      continue;
    }
    actions.push({
      platform,
      step: "set_precedence",
      policy_id: policyId,
      rank: "above_standard_below_ir",
      ...("place_after" in placement ? { placed_after: placement.place_after } : { placed_first: true }),
    });
  }

  // The rule group is authored and bound per policy by
  // extras_shadow_ai_adopt_prevention (its own approval).
  const followUp = PLATFORMS.filter((p) => bannedIds[p]).map((platform) => ({
    tool: "extras_shadow_ai_adopt_prevention",
    args: {
      prevention_policy_id: bannedIds[platform],
      comment: `Project Eyas - Shadow-AI Banned (${platform}) - auto-provisioned. Authors / refreshes the per-platform rule group and binds to this policy.`,
      mode: "block",
      platform,
    },
    platform,
  }));
  return { ok: errors.length === 0, host_group_id: hostGroupId, mode, actions, errors, follow_up_tool_calls: followUp };
}

// ---------------------------------------------------------------- status

function platformStatus(platform: Platform, group: Obj | null): Obj {
  const corpus = ruleCorpusSummary(platform);
  const corpusNames = corpus.map((r) => String(r.name));
  if (!group) {
    return {
      platform,
      rule_group_exists: false,
      rule_group_name: RULE_GROUP_NAMES[platform],
      rule_group_id: null,
      rule_group_enabled: null,
      installed_rules: [],
      installed_rule_count: 0,
      missing_rules: corpusNames,
      corpus_count: corpus.length,
      corpus,
    };
  }
  const installed = (Array.isArray(group.rules) ? group.rules : []).filter(isObj).map((r) => r.name ?? null);
  return {
    platform,
    rule_group_exists: true,
    rule_group_id: group.id ?? null,
    rule_group_name: group.name ?? null,
    rule_group_enabled: group.enabled ?? null,
    rule_group_version: group.version ?? null,
    rule_group_platform: group.platform ?? null,
    installed_rule_count: installed.length,
    installed_rules: installed,
    missing_rules: corpusNames.filter((n) => !installed.includes(n)),
    corpus_count: corpus.length,
    corpus,
  };
}

// Hoisted from the Windows platform for the setup card, which reads the
// Windows-shaped summary. Per-platform truth is in platforms[].
const STATUS_HOIST_KEYS = [
  "rule_group_exists",
  "rule_group_id",
  "rule_group_name",
  "rule_group_enabled",
  "installed_rules",
  "installed_rule_count",
  "missing_rules",
  "corpus_count",
  "corpus",
];

/** extras_shadow_ai_prevention_status. */
export async function preventionStatus(ctx: EyasToolContext): Promise<Obj> {
  const rg = await shadowAiRuleGroups(ctx);
  if (!rg.ok) return rg.payload;
  const platforms = PLATFORMS.map((p) => platformStatus(p, rg.value[p]));
  const win = platforms[0];
  const out: Obj = { ok: true, platforms, any_rule_group_exists: platforms.some((p) => p.rule_group_exists) };
  for (const k of STATUS_HOIST_KEYS) out[k] = win[k] ?? null;
  if (!win.rule_group_exists) {
    out.note =
      'No Windows rule group with this name exists yet. Run `extras_shadow_ai_adopt_prevention` (platform="windows") ' +
      "to create it. See platforms[] for macOS / Linux state.";
  }
  return out;
}

// ---------------------------------------------------------------- binding check

/** Classify the end-to-end enforcement chain from fetched records (pure). */
export function classifyBinding(bannedGroupId: string, ruleGroups: Record<Platform, Obj | null>, policies: Obj[]): Obj {
  const rgBy: Record<string, Obj> = {};
  for (const p of PLATFORMS) {
    const g = ruleGroups[p];
    rgBy[p] = { platform: p, name: RULE_GROUP_NAMES[p], id: g ? g.id ?? null : null, exists: g !== null, enabled: g ? Boolean(g.enabled) : false };
  }
  const attached: Obj[] = [];
  for (const p of policies) {
    const inBanned = (Array.isArray(p.groups) ? p.groups : []).some((g) => isObj(g) && g.id === bannedGroupId);
    if (!inBanned) continue;
    const plat = str(p.platform_name).toLowerCase();
    const rg = rgBy[plat];
    const expectedName = rg ? rg.name : RULE_GROUP_NAMES[plat as Platform] ?? null;
    const expectedId = rg ? rg.id : null;
    const bound = (Array.isArray(p.ioa_rule_groups) ? p.ioa_rule_groups : []).some(
      (x) => isObj(x) && ((expectedId !== null && x.id === expectedId) || (expectedName !== null && x.name === expectedName)),
    );
    attached.push({
      id: p.id ?? null,
      name: p.name ?? null,
      platform: p.platform_name ?? null,
      enabled: p.enabled === undefined ? true : Boolean(p.enabled),
      rule_group_bound: bound,
      rule_group_name: expectedName ?? null,
      rule_group_exists: rg ? Boolean(rg.exists) : false,
      rule_group_enabled: rg ? Boolean(rg.enabled) : false,
    });
  }

  const missing: string[] = [];
  if (attached.length === 0) {
    missing.push(
      `No Prevention Policy is attached to host group ${bannedGroupId}. In Falcon Console, edit the AI-Banned host ` +
        "group's prevention policy assignment to attach a policy (per platform) whose Custom IOA Rule Groups include " +
        "the matching 'Project Eyas - Shadow-AI Block' group.",
    );
  } else {
    const plats = [...new Set(attached.map((p) => str(p.platform).toLowerCase()).filter(Boolean))].sort();
    for (const plat of plats) {
      const rg = rgBy[plat] ?? {};
      const rgName = str(rg.name) || RULE_GROUP_NAMES[plat as Platform] || plat;
      const mine = attached.filter((p) => str(p.platform).toLowerCase() === plat);
      if (!rg.exists) {
        missing.push(`[${plat}] Run extras_shadow_ai_adopt_prevention(platform="${plat}") to create the '${rgName}' rule group.`);
        continue;
      }
      if (!rg.enabled) {
        missing.push(`[${plat}] Enable the '${rgName}' rule group in Falcon Console (Endpoint Security → Custom IOA Rule Groups).`);
      }
      const unbound = mine.filter((p) => p.enabled && !p.rule_group_bound);
      if (unbound.length) {
        const names = unbound.map((p) => str(p.name) || str(p.id)).join(", ");
        missing.push(
          `[${plat}] '${rgName}' is not bound to the attached ${plat} prevention policy (${names}). Re-run ` +
            `extras_shadow_ai_adopt_prevention with the prevention_policy_id of that policy and platform="${plat}", or bind it via console.`,
        );
      }
      const disabled = mine.filter((p) => p.rule_group_bound && !p.enabled);
      if (disabled.length) {
        const names = disabled.map((p) => str(p.name) || str(p.id)).join(", ");
        missing.push(`[${plat}] Rule group is bound, but the prevention policy carrying it is disabled: ${names}.`);
      }
    }
  }
  const enforcing = attached.filter((p) => p.enabled && p.rule_group_bound && p.rule_group_enabled);
  const unboundAny = attached.filter((p) => p.enabled && !p.rule_group_bound);
  const win = rgBy.windows;
  return {
    ok: true,
    ready: enforcing.length > 0 && unboundAny.length === 0,
    banned_group_id: bannedGroupId,
    rule_groups: PLATFORMS.map((p) => rgBy[p]),
    rule_group_name: win.name ?? null,
    rule_group_id: win.id ?? null,
    rule_group_exists: win.exists ?? false,
    rule_group_enabled: win.enabled ?? false,
    attached_policies: attached,
    missing_steps: missing,
  };
}

/** extras_shadow_ai_check_prevention_binding. */
export async function checkPreventionBinding(
  ctx: EyasToolContext,
  savedGroupId: () => Promise<string | undefined> = activeBannedGroupId,
): Promise<Obj> {
  const banned = await savedGroupId();
  if (!banned) {
    return {
      ok: true,
      ready: false,
      banned_group_id: null,
      missing_steps: [
        'Set the "Shadow-AI banned host group" field on the active environment in /config (Environments manager) — ' +
          "without it Ban+Clean has nowhere to move hosts.",
      ],
    };
  }
  const rg = await shadowAiRuleGroups(ctx);
  if (!rg.ok) return rg.payload;
  const pol = await preventionPolicies(ctx);
  if (!pol.ok) return pol.payload;
  return classifyBinding(banned, rg.value, pol.value);
}

// ---------------------------------------------------------------- adopt prevention

/** Falcon's Custom IOA API rejects control characters in `comment`. */
export const cleanComment = (c: string) => c.replace(/[\x00-\x1f\x7f]+/g, " ").replace(/\s+/g, " ").trim();

const needsConverge = (r: Obj, disposition: number) => !r.enabled || r.disposition_id !== disposition;

// eyas-mcp's falcon_update_ioa_rule takes at most this many rule_updates.
const RULE_UPDATE_BATCH = 100;

/** extras_shadow_ai_adopt_prevention. */
export async function adoptPrevention(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const policyId = input.prevention_policy_id;
  const rawComment = input.comment;
  const rawMode = input.mode ?? "block";
  const dryRun = input.dry_run === true;
  const rawPlatform = input.platform ?? "windows";
  if (!policyId || typeof policyId !== "string") return { ok: false, error: "prevention_policy_id is required" };
  if (!rawComment || typeof rawComment !== "string") {
    return { ok: false, error: "comment is required — recorded in Falcon Console change ledger" };
  }
  const mode = String(rawMode ?? "").trim().toLowerCase();
  if (mode !== "detect" && mode !== "block") return { ok: false, error: `mode must be 'detect' or 'block', got '${String(rawMode)}'` };
  const platform = String(rawPlatform ?? "").trim().toLowerCase() as Platform;
  if (!(platform in CORPUS_BY_PLATFORM)) {
    return { ok: false, error: `platform must be 'windows' / 'mac' / 'linux', got '${String(rawPlatform)}'` };
  }
  const groupName = RULE_GROUP_NAMES[platform];
  const corpus = CORPUS_BY_PLATFORM[platform];
  const disposition = mode === "block" ? DISPOSITION_BLOCK : DISPOSITION_DETECT;
  const comment = cleanComment(rawComment);

  const rt = await processCreationRuleType(ctx, platform);
  if (!rt.ok) return rt.payload;
  const ruletypeId = rt.value;
  const rendered = corpus.map((r) => ({
    name: r.name,
    description: r.description,
    pattern_severity: r.pattern_severity,
    ruletype_id: ruletypeId,
    disposition_id: disposition,
    field_values: toFieldValues(r),
    comment: `${comment} [${r.rationale_tag}]`,
  }));
  const corpusNames = new Set(rendered.map((r) => r.name));
  const liveRulesOf = (g: Obj | null) => (Array.isArray(g?.rules) ? (g!.rules as unknown[]) : []).filter(isObj);

  if (dryRun) {
    const g = await shadowAiRuleGroup(ctx, platform);
    if (!g.ok) return g.payload;
    const byName = new Map(liveRulesOf(g.value).map((r) => [r.name, r] as const));
    const managed = [...byName.entries()].filter(([n]) => corpusNames.has(n as string));
    // The plan and counts come before the long rendered_rules list, so the
    // agent's 12 KB result cap cuts the rule bodies, not the plan.
    return {
      ok: true,
      dry_run: true,
      platform,
      mode,
      ruletype_id: ruletypeId,
      disposition_id: disposition,
      rule_group_name: groupName,
      rule_group_exists: g.value !== null,
      rule_group_enabled: g.value ? Boolean(g.value.enabled) : false,
      rendered_count: rendered.length,
      plan: {
        would_create_rules: [...corpusNames].filter((n) => !byName.has(n)),
        would_enable_or_redisposition: managed
          .filter(([, r]) => needsConverge(r, disposition))
          .map(([n, r]) => ({
            name: n,
            from: { enabled: Boolean(r.enabled), disposition_id: r.disposition_id ?? null },
            to: { enabled: true, disposition_id: disposition },
          })),
        already_correct: managed.filter(([, r]) => !needsConverge(r, disposition)).map(([n]) => n),
      },
      prevention_policy_id: policyId,
      note:
        "dry_run: no write calls were made. A live run would create the listed rules, then set enabled=True + " +
        `disposition_id=${disposition} on every managed rule not already in that state, preserving each rule's live ` +
        "match patterns.",
      rendered_rules: rendered,
    };
  }

  // 1. Resolve or create the rule group.
  const found = await shadowAiRuleGroup(ctx, platform);
  if (!found.ok) return found.payload;
  let group = found.value;
  let createdGroup = false;
  if (!group) {
    const c = await ctx.callNative("falcon_create_ioa_rule_group", {
      name: groupName,
      description: RULE_GROUP_DESCRIPTION,
      platform,
      comment,
    });
    if (c.error) return failPayload("CustomIOA", c.error);
    if (!c.obj) return { ok: false, error: "create_rule_group returned no record" };
    group = c.obj;
    createdGroup = true;
  }
  const groupId = group.id;
  if (!groupId || typeof groupId !== "string") return { ok: false, error: "rule group missing id", raw: group };

  // 2. Create every corpus rule that doesn't exist yet (by name). Falcon
  //    creates them disabled; step 3 enables them.
  const existing = new Set(liveRulesOf(group).map((r) => r.name));
  const added: string[] = [];
  const ruleErrors: Obj[] = [];
  for (const rule of rendered) {
    if (existing.has(rule.name)) continue;
    const r = await ctx.callNative("falcon_create_ioa_rule", {
      rulegroup_id: groupId,
      ruletype_id: ruletypeId,
      disposition_id: disposition,
      name: rule.name,
      description: rule.description,
      pattern_severity: rule.pattern_severity,
      field_values: rule.field_values,
      comment: rule.comment,
    });
    if (r.error) {
      ruleErrors.push({ rule: rule.name, error: await failPayload("CustomIOA", r.error) });
      continue;
    }
    added.push(rule.name);
  }

  // 3. Refetch (new rules now have instance ids), then converge every managed
  //    rule to enabled + the requested disposition. eyas-mcp fills each rule's
  //    other fields from the live rule, so console pattern edits survive.
  const latest = await shadowAiRuleGroup(ctx, platform);
  if (!latest.ok) return latest.payload;
  if (!latest.value) return { ok: false, error: "rule group disappeared mid-adoption" };
  let version = latest.value.version;
  const live = liveRulesOf(latest.value);
  const alreadyCorrect = live.filter((r) => corpusNames.has(r.name as string) && !needsConverge(r, disposition)).map((r) => r.name);
  const updates = live
    .filter((r) => corpusNames.has(r.name as string) && needsConverge(r, disposition))
    .map((r) => ({ instance_id: r.instance_id, name: r.name, enabled: true, disposition_id: disposition }));
  const converged = updates.map((u) => u.name);
  for (let i = 0; i < updates.length; i += RULE_UPDATE_BATCH) {
    const u = await ctx.callNative("falcon_update_ioa_rule", {
      rulegroup_id: groupId,
      rulegroup_version: version,
      comment,
      rule_updates: updates.slice(i, i + RULE_UPDATE_BATCH).map(({ name: _n, ...rest }) => {
        void _n;
        return rest;
      }),
    });
    if (u.error) {
      return {
        ok: false,
        stage: "enable_rules",
        rule_group_id: groupId,
        rules_added: added,
        rules_to_converge: converged,
        rule_errors: ruleErrors,
        error: await failPayload("CustomIOA", u.error),
      };
    }
    // Each update bumps the version.
    const again = await shadowAiRuleGroup(ctx, platform);
    if (!again.ok) return again.payload;
    if (!again.value) return { ok: false, error: "rule group disappeared mid-adoption" };
    version = again.value.version;
  }

  // 4. Enable the rule group itself (idempotent).
  const en = await ctx.callNative("falcon_update_ioa_rule_group", {
    id: groupId,
    rulegroup_version: version,
    name: groupName,
    description: RULE_GROUP_DESCRIPTION,
    enabled: true,
    comment,
  });
  if (en.error) {
    return {
      ok: false,
      stage: "enable_rule_group",
      rule_group_id: groupId,
      rules_added: added,
      rules_converged: converged,
      rule_errors: ruleErrors,
      error: await failPayload("CustomIOA", en.error),
    };
  }

  // 5. Bind to the prevention policy (re-binding is a no-op).
  const bind = await ctx.callNative("falcon_perform_policy_action", {
    policy_type: "prevention",
    action_name: "add-rule-group",
    ids: [policyId],
    group_id: groupId,
  });
  const bindError = bind.error ? await failPayload("PreventionPolicy", bind.error) : null;
  const label = mode === "block" ? "Block Execution (process kill)" : "Detect";
  return {
    ok: true,
    platform,
    created_rule_group: createdGroup,
    rule_group_id: groupId,
    rule_group_name: groupName,
    mode,
    disposition_id: disposition,
    ruletype_id: ruletypeId,
    rules_added: added,
    rules_converged: converged,
    rules_already_correct: alreadyCorrect,
    rule_errors: ruleErrors,
    prevention_policy_id: policyId,
    policy_bind_error: bindError,
    note:
      bindError === null
        ? `Rule group enabled; ${added.length} rule(s) created, ${converged.length} rule(s) set to enabled + ${label}. ` +
          "Bound to the prevention policy; enforces on the next sensor heartbeat for hosts whose policy includes this rule group."
        : "Rules enabled but policy binding failed — attach the rule group in Falcon Console or re-run this tool. See policy_bind_error.",
  };
}
