import type { EyasToolContext } from "./types";
import { READINESS_EXCLUSION_NAME, RTR_PREAMBLE_BASE64, groupIdsOf } from "./quarantine";

// Project Eyas tenant teardown and its two low-level deletes (formerly
// falcon-extras teardown.py). Wipes every Project Eyas-managed object so a
// fresh provisioning run starts clean; used for demo cycles and dev resets.
// Every Falcon call is an eyas-mcp native. The agent-facing tools stay
// approval-gated; dry_run (the default) only discovers.
//
// Execute order is Falcon-enforced:
//   1. detach matched policies from their host groups
//   2. disable them (Falcon refuses to delete an enabled policy)
//   3. delete them
//   4. delete matched Custom IOA rule groups (unbound once their policies go)
//   5. delete the IR-readiness IOA exclusions
//   6. delete matched host groups (they must have no attached policies)
//
// The active environment's saved group ids are NOT cleared; the operator does
// that with /config's Clear button or by provisioning fresh groups.

type Obj = Record<string, unknown>;

export const CANONICAL_HG_NAMES = new Set(["Project Eyas - IR Quarantine", "Project Eyas - Shadow-AI Banned"]);
export const CANONICAL_PP_PREFIX = "Project Eyas - "; // IR + Shadow-AI Banned policies share it
export const CANONICAL_RG_PREFIX = "Project Eyas - Shadow-AI Block"; // one per platform
const LEGACY_EXCLUSION_HINT = "IR-readiness";
const PLATFORMS = ["Windows", "Mac", "Linux"];

export type TeardownPlan = {
  host_groups: Obj[];
  prevention_policies: Obj[];
  rule_groups: Obj[];
  ioa_exclusions: Obj[];
  active_env_hints: Obj;
  discovery_errors: Obj[];
};

/** Is this IOA exclusion Eyas's IR-readiness exclusion? Matched by the RTR
 *  preamble marker in cl_regex (what provisioning and the readiness check key
 *  on) or its canonical name. The former Python matched only "IR-readiness"
 *  in the comment, which neither creation path writes, so it never found it;
 *  that hint is kept for anything created by hand with it. */
export function isReadinessExclusion(e: Obj): boolean {
  const cl = typeof e.cl_regex === "string" ? e.cl_regex : "";
  if (cl.includes(RTR_PREAMBLE_BASE64)) return true;
  // Falcon stores the name with a plain hyphen where Eyas sends an em dash.
  const dashless = (v: unknown) => String(v ?? "").replace(/[\u2013\u2014]/g, "-");
  if (dashless(e.name) === dashless(READINESS_EXCLUSION_NAME)) return true;
  const comment = String(e.comment ?? e.description ?? "");
  return comment.includes(LEGACY_EXCLUSION_HINT);
}

// Falcon pages host groups at most 500 at a time (eyas-mcp's schema allows more,
// but the API rejects a page size over 500).
const HOST_GROUP_PAGE = 500;
const MAX_HOST_GROUP_PAGES = 40;

async function allHostGroups(
  ctx: EyasToolContext,
): Promise<{ ok: true; items: Obj[]; scope_pending?: boolean } | { ok: false; error: string }> {
  const items: Obj[] = [];
  for (let page = 0; page < MAX_HOST_GROUP_PAGES; page++) {
    const r = await ctx.searchNative("falcon_search_host_groups", {
      limit: HOST_GROUP_PAGE,
      offset: page * HOST_GROUP_PAGE,
    });
    if (!r.ok) return r;
    if (r.scope_pending) return { ok: true, items: [], scope_pending: true };
    items.push(...r.items);
    const total = typeof r.total === "number" ? r.total : undefined;
    if (r.items.length < HOST_GROUP_PAGE || (total !== undefined && items.length >= total)) break;
  }
  return { ok: true, items };
}

async function activeGroupIds(): Promise<{ ir: string; banned: string }> {
  const { getRuntimeConfig } = await import("@/lib/config/runtime");
  const cfg = getRuntimeConfig();
  return { ir: cfg.irQuarantineGroupId ?? "", banned: cfg.shadowAiBannedGroupId ?? "" };
}

/** Read-only scan for Project Eyas objects. */
export async function discoverCanonicalObjects(
  ctx: EyasToolContext,
  ids: { ir: string; banned: string },
): Promise<TeardownPlan> {
  const plan: TeardownPlan = {
    host_groups: [],
    prevention_policies: [],
    rule_groups: [],
    ioa_exclusions: [],
    active_env_hints: {},
    discovery_errors: [],
  };
  if (ids.ir) plan.active_env_hints.ir_quarantine_group_id = ids.ir;
  if (ids.banned) plan.active_env_hints.shadow_ai_banned_group_id = ids.banned;

  // Host groups: canonical name, or an id the active environment has saved
  // (catches adopted groups with other names).
  const hg = await allHostGroups(ctx);
  if (!hg.ok) plan.discovery_errors.push({ step: "host_groups", error: hg.error });
  else if (hg.scope_pending) plan.discovery_errors.push({ step: "host_groups", scope_pending: true });
  else {
    for (const g of hg.items) {
      const gid = typeof g.id === "string" ? g.id : "";
      const name = String(g.name ?? "");
      const canonical = CANONICAL_HG_NAMES.has(name);
      const fromEnv = gid !== "" && (gid === ids.ir || gid === ids.banned);
      if (canonical || fromEnv) {
        plan.host_groups.push({
          id: gid,
          name,
          group_type: g.group_type ?? null,
          match_reason: canonical ? "canonical_name" : "active_env_id",
        });
      }
    }
  }

  // Prevention policies, one platform at a time (an unfiltered listing can
  // drop policies).
  for (const platform of PLATFORMS) {
    const r = await ctx.searchNative("falcon_search_policies", {
      policy_type: "prevention",
      filter: `platform_name:'${platform}'`,
      limit: 500,
    });
    if (!r.ok) {
      plan.discovery_errors.push({ step: `prevention_policies_${platform.toLowerCase()}`, error: r.error });
      continue;
    }
    if (r.scope_pending) {
      plan.discovery_errors.push({ step: `prevention_policies_${platform.toLowerCase()}`, scope_pending: true });
      continue;
    }
    for (const p of r.items) {
      const name = String(p.name ?? "");
      if (!name.startsWith(CANONICAL_PP_PREFIX)) continue;
      plan.prevention_policies.push({
        id: p.id ?? null,
        name,
        platform_name: p.platform_name ?? null,
        enabled: p.enabled === undefined ? true : Boolean(p.enabled),
        attached_group_ids: groupIdsOf(p).filter(Boolean),
      });
    }
  }

  const rg = await ctx.searchNative("falcon_search_ioa_rule_groups", { limit: 500 });
  if (!rg.ok) plan.discovery_errors.push({ step: "rule_groups", error: rg.error });
  else if (rg.scope_pending) plan.discovery_errors.push({ step: "rule_groups", scope_pending: true });
  else {
    for (const g of rg.items) {
      const name = String(g.name ?? "");
      if (!name.startsWith(CANONICAL_RG_PREFIX)) continue;
      plan.rule_groups.push({
        id: g.id ?? null,
        name,
        platform: g.platform ?? null,
        enabled: g.enabled === undefined ? true : Boolean(g.enabled),
      });
    }
  }

  const ex = await ctx.searchNative("falcon_search_exclusions", { exclusion_type: "ioa", limit: 500 });
  if (!ex.ok) plan.discovery_errors.push({ step: "ioa_exclusions", error: ex.error });
  else if (ex.scope_pending) plan.discovery_errors.push({ step: "ioa_exclusions", scope_pending: true });
  else {
    for (const e of ex.items) {
      if (!isReadinessExclusion(e)) continue;
      plan.ioa_exclusions.push({
        id: e.id ?? null,
        name: e.name ?? null,
        comment: String(e.comment ?? e.description ?? "").slice(0, 140),
        applied_globally: e.applied_globally ?? false,
        host_group_ids: groupIdsOf(e),
      });
    }
  }
  return plan;
}

function summarize(plan: TeardownPlan) {
  return {
    host_groups_count: plan.host_groups.length,
    prevention_policies_count: plan.prevention_policies.length,
    rule_groups_count: plan.rule_groups.length,
    ioa_exclusions_count: plan.ioa_exclusions.length,
    discovery_errors_count: plan.discovery_errors.length,
  };
}

async function step(
  ctx: EyasToolContext,
  record: Obj,
  name: string,
  args: Obj,
): Promise<Obj> {
  const r = await ctx.callNative(name, args);
  return { ...record, ok: !r.error, ...(r.error ? { error: r.error } : {}) };
}

export async function executeTeardown(ctx: EyasToolContext, plan: TeardownPlan): Promise<Obj[]> {
  const steps: Obj[] = [];
  for (const p of plan.prevention_policies) {
    for (const gid of (p.attached_group_ids as string[]) ?? []) {
      steps.push(
        await step(
          ctx,
          { step: "detach_policy_from_group", policy_id: p.id, policy_name: p.name, host_group_id: gid },
          "falcon_perform_policy_action",
          { policy_type: "prevention", action_name: "remove-host-group", ids: [p.id], group_id: gid },
        ),
      );
    }
  }
  for (const p of plan.prevention_policies) {
    if (!p.enabled) continue;
    steps.push(
      await step(ctx, { step: "disable_policy", policy_id: p.id, policy_name: p.name }, "falcon_perform_policy_action", {
        policy_type: "prevention",
        action_name: "disable",
        ids: [p.id],
      }),
    );
  }
  for (const p of plan.prevention_policies) {
    steps.push(
      await step(ctx, { step: "delete_prevention_policy", policy_id: p.id, policy_name: p.name }, "falcon_delete_policies", {
        policy_type: "prevention",
        ids: [p.id],
      }),
    );
  }
  for (const g of plan.rule_groups) {
    steps.push(
      await step(ctx, { step: "delete_rule_group", rule_group_id: g.id, rule_group_name: g.name }, "falcon_delete_ioa_rule_groups", {
        ids: [g.id],
        comment: "Project Eyas teardown",
      }),
    );
  }
  for (const e of plan.ioa_exclusions) {
    steps.push(
      await step(ctx, { step: "delete_ioa_exclusion", exclusion_id: e.id }, "falcon_delete_exclusions", {
        exclusion_type: "ioa",
        ids: [e.id],
        comment: "Project Eyas teardown",
      }),
    );
  }
  for (const h of plan.host_groups) {
    steps.push(
      await step(ctx, { step: "delete_host_group", host_group_id: h.id, host_group_name: h.name }, "falcon_delete_host_groups", {
        ids: [h.id],
      }),
    );
  }
  return steps;
}

export async function teardownProjectEyasManaged(
  ctx: EyasToolContext,
  input: Obj,
  groupIds?: { ir: string; banned: string },
): Promise<Obj> {
  const dryRun = input.dry_run !== false;
  const plan = await discoverCanonicalObjects(ctx, groupIds ?? (await activeGroupIds()));
  const summary = summarize(plan);
  if (dryRun) {
    return {
      ok: true,
      dry_run: true,
      summary,
      plan,
      note:
        "Re-run with dry_run=False to execute. Order: detach policies from groups → disable policies → delete " +
        "policies → delete rule groups → delete IOA exclusions → delete host groups. The active env's group-id " +
        "fields are NOT cleared automatically; use the /config Clear button after teardown completes.",
    };
  }
  const steps = await executeTeardown(ctx, plan);
  const okCount = steps.filter((s) => s.ok).length;
  const failCount = steps.length - okCount;
  return {
    ok: failCount === 0,
    dry_run: false,
    summary: { ...summary, executed_steps: steps.length, succeeded: okCount, failed: failCount },
    steps,
    discovery_errors: plan.discovery_errors,
    next_step:
      "Clear irQuarantineGroupId + shadowAiBannedGroupId on the active environment via /config Clear button, then " +
      "re-provision via the setup cards to start fresh.",
  };
}

export async function deletePreventionPolicy(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const id = input.prevention_policy_id;
  if (typeof id !== "string" || !id) return { ok: false, error: "prevention_policy_id is required" };
  // disable_first: Falcon refuses to delete an enabled policy.
  const r = await ctx.callNative("falcon_delete_policies", { policy_type: "prevention", ids: [id], disable_first: true });
  if (r.error) return { ok: false, prevention_policy_id: id, error: r.error };
  return { ok: true, id, deleted: true };
}

export async function deleteIoaRuleGroup(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const id = input.rule_group_id;
  if (typeof id !== "string" || !id) return { ok: false, error: "rule_group_id is required" };
  const comment = typeof input.comment === "string" && input.comment ? input.comment : "Project Eyas teardown";
  const r = await ctx.callNative("falcon_delete_ioa_rule_groups", { ids: [id], comment });
  if (r.error) return { ok: false, rule_group_id: id, error: r.error };
  return { ok: true, id, deleted: true };
}
