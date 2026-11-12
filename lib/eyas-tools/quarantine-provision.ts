import type { EyasToolContext } from "./types";
import {
  CANONICAL_POLICY_PREFIX,
  READINESS_EXCLUSION_COMMENT_PROVISIONED,
  READINESS_EXCLUSION_NAME,
  READINESS_IFN_REGEX,
  RTR_PREAMBLE_BASE64,
  RTR_PREAMBLE_FULL_REGEX,
  candidatePatternId,
  groupIdsOf,
} from "./quarantine";

// IR quarantine prevention-policy provisioning and policy detach (formerly
// falcon-extras ir/provision_quarantine.py and the detach wrapper in
// server.py). Every Falcon call is an eyas-mcp native; the agent-facing tool
// stays approval-gated as one action covering the whole chain.
//
// Per platform (Windows / Mac / Linux), adopt the policy already bound only to
// the group (renamed canonical) or create one and attach it, push every slider
// to AGGRESSIVE and every behavioral toggle on, then move each policy to the
// top of its platform's precedence (the additive group model relies on it: a
// quarantined host keeps its other groups, and the IR policy wins by
// precedence). Finally make sure the IR-readiness IOA exclusion exists.

type Obj = Record<string, unknown>;

export const PLATFORMS = ["windows", "mac", "linux"] as const;
type Platform = (typeof PLATFORMS)[number];
const API_PLATFORM: Record<Platform, string> = { windows: "Windows", mac: "Mac", linux: "Linux" };
const TARGET_LEVEL = "AGGRESSIVE";

const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);

/** Raise every slider to TARGET_LEVEL and enable every boolean toggle, and
 *  flatten the grouped `prevention_settings` read shape into the
 *  `[{id, value}]` list the update API takes. Pure; operates on shape, not a
 *  hard-coded id list, so platform schemas can change without code changes. */
export function planMaxProtectiveSettings(existing: unknown): {
  flat: { id: unknown; value: unknown }[];
  slidersTouched: number;
  togglesTouched: number;
} {
  let slidersTouched = 0;
  let togglesTouched = 0;
  const flat: { id: unknown; value: unknown }[] = [];

  const update = (entry: Obj) => {
    const v = entry.value;
    if (!isObj(v)) return;
    const next: Obj = { ...v };
    if ("detection" in v && "prevention" in v) {
      if (v.detection !== TARGET_LEVEL || v.prevention !== TARGET_LEVEL) slidersTouched++;
      next.detection = TARGET_LEVEL;
      next.prevention = TARGET_LEVEL;
    } else if ("detection" in v) {
      if (v.detection !== TARGET_LEVEL) slidersTouched++;
      next.detection = TARGET_LEVEL;
    } else if (typeof v.enabled === "boolean") {
      if (v.enabled !== true) togglesTouched++;
      next.enabled = true;
    } else {
      return;
    }
    entry.value = next;
  };
  const take = (entry: Obj) => {
    update(entry);
    if (entry.id !== undefined && entry.id !== null) flat.push({ id: entry.id, value: entry.value });
  };

  for (const s of Array.isArray(existing) ? existing : []) {
    if (!isObj(s)) continue;
    if (Array.isArray(s.settings)) {
      for (const sub of s.settings) if (isObj(sub)) take({ ...sub });
    } else {
      take({ ...s });
    }
  }
  return { flat, slidersTouched, togglesTouched };
}

async function pushMaxProtectiveSettings(ctx: EyasToolContext, policyId: string): Promise<Obj> {
  const got = await ctx.callNative("falcon_get_policies", { policy_type: "prevention", ids: [policyId] });
  if (got.error) return { ok: false, stage: "get_for_update", error: got.error };
  const found = Array.isArray(got.obj?.found) ? (got.obj.found as unknown[]).filter(isObj) : [];
  const rec = found[0];
  if (!rec) return { ok: false, stage: "get_for_update", error: "no record" };

  const plan = planMaxProtectiveSettings(rec.prevention_settings);
  if (plan.slidersTouched === 0 && plan.togglesTouched === 0) {
    return { ok: true, sliders_touched: 0, toggles_touched: 0, note: "policy already at max-protective state" };
  }
  const upd = await ctx.callNative("falcon_update_policy", {
    policy_type: "prevention",
    id: policyId,
    settings: plan.flat,
  });
  if (upd.error) return { ok: false, stage: "update_settings", error: upd.error };
  return { ok: true, sliders_touched: plan.slidersTouched, toggles_touched: plan.togglesTouched };
}

async function createPolicyAndAttach(
  ctx: EyasToolContext,
  name: string,
  platform: Platform,
  hostGroupId: string,
): Promise<Obj> {
  const created = await ctx.callNative("falcon_create_policy", {
    policy_type: "prevention",
    name,
    platform_name: API_PLATFORM[platform],
    description: "App-managed by Project Eyas. AGGRESSIVE prevention sliders for IR quarantine. Do not edit manually.",
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
  const enable = await ctx.callNative("falcon_perform_policy_action", {
    policy_type: "prevention",
    action_name: "enable",
    ids: [policyId],
  });
  if (enable.error) return { ok: false, stage: "enable", policy_id: policyId, error: enable.error };
  return { ok: true, policy_id: policyId };
}

/** Make sure the IR-readiness IOA exclusion is scoped to the group, creating it
 *  when a PShellMimikatz pattern_id can be resolved. Never fails provisioning
 *  for a fresh tenant with no such detection yet. */
export async function ensureReadinessExclusion(ctx: EyasToolContext, hostGroupId: string): Promise<Obj> {
  const ex = await ctx.searchNative("falcon_search_exclusions", { exclusion_type: "ioa", limit: 500 });
  if (!ex.ok) return { ok: false, error: ex.error };
  if (ex.scope_pending) return { ok: false, scope_pending: true, error: "IOA exclusion scope not granted" };
  for (const r of ex.items) {
    if (!groupIdsOf(r).includes(hostGroupId)) continue;
    if (String(r.cl_regex ?? "").includes(RTR_PREAMBLE_BASE64)) {
      return { ok: true, present: true, id: r.id ?? null, created: false };
    }
  }

  const patternId = await candidatePatternId(ctx);
  if (!patternId) {
    return {
      ok: true,
      present: false,
      created: false,
      pattern_id_unresolved: true,
      warning:
        "IR-readiness IOA exclusion could NOT be pre-installed: no PShellMimikatz detection has ever fired on this " +
        "tenant, so the pattern_id can't be resolved. The first IR engagement after a host is moved into the " +
        "quarantine group will trigger the PowerShell-encoded-command detector once (this fires the PShellMimikatz " +
        "pattern and surfaces its pattern_id); after that, re-running /config IR-Quarantine provisioning will " +
        "install the exclusion eagerly. Until then, the first IR engagement on a freshly-quarantined host will need " +
        "a JIT IOA exclusion install at Phase 0 + the standard 60-90s propagation wait in Phase 1.5.",
    };
  }

  // skip_if_duplicate returns an existing exclusion with the same pattern_id,
  // ifn_regex and cl_regex instead of creating a second one.
  const created = await ctx.callNative("falcon_create_exclusion", {
    exclusion_type: "ioa",
    name: READINESS_EXCLUSION_NAME,
    pattern_id: patternId,
    ifn_regex: READINESS_IFN_REGEX,
    cl_regex: RTR_PREAMBLE_FULL_REGEX,
    comment: READINESS_EXCLUSION_COMMENT_PROVISIONED,
    host_groups: [hostGroupId],
    skip_if_duplicate: true,
  });
  if (created.error) {
    return { ok: false, present: false, created: false, error: created.error };
  }
  return { ok: true, present: true, id: created.obj?.id ?? null, created: true, pattern_id: patternId };
}

export async function provisionQuarantinePolicy(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const hostGroupId = input.host_group_id;
  if (typeof hostGroupId !== "string" || !hostGroupId) return { ok: false, error: "host_group_id is required" };
  const mode = input.mode === undefined || input.mode === null ? "adopt" : input.mode;
  if (mode !== "adopt" && mode !== "create_dedicated") return { ok: false, error: `unknown mode '${String(mode)}'` };

  const all = await ctx.searchNative("falcon_search_policies", { policy_type: "prevention", limit: 500 });
  if (!all.ok) return { ok: false, error: `policy walk: ${all.error}` };
  if (all.scope_pending) return { ok: false, scope_pending: true, error: "Prevention Policies scope not granted" };

  const existing: Record<Platform, { policy: Obj; attached: string[] }[]> = { windows: [], mac: [], linux: [] };
  for (const p of all.items) {
    const platform = String(p.platform_name ?? "").toLowerCase() as Platform;
    if (!(platform in existing)) continue;
    const attached = groupIdsOf(p);
    if (!attached.includes(hostGroupId)) continue;
    existing[platform].push({ policy: p, attached });
  }

  const actions: Obj[] = [];
  const errors: Obj[] = [];
  const irPolicyIds: Partial<Record<Platform, string>> = {};

  for (const platform of PLATFORMS) {
    const targetName = `${CANONICAL_POLICY_PREFIX}, ${platform})`;
    let chosen: { policy: Obj; attached: string[] } | null = null;
    if (mode === "adopt" && existing[platform].length > 0) {
      const single = existing[platform].filter((e) => e.attached.length === 1);
      chosen = (single.length > 0 ? single : existing[platform])[0];
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
      const currentName = String(chosen.policy.name ?? "");
      if (currentName !== targetName) {
        const r = await ctx.callNative("falcon_update_policy", {
          policy_type: "prevention",
          id: policyId,
          name: targetName,
        });
        if (r.error) {
          errors.push({ platform, ok: false, stage: "rename", error: r.error });
          continue;
        }
        actions.push({ platform, step: "rename", policy_id: policyId, from: currentName, to: targetName });
      }
    }

    const push = await pushMaxProtectiveSettings(ctx, policyId);
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
    irPolicyIds[platform] = policyId;
  }

  // Top of each platform's precedence. eyas-mcp builds the complete order
  // itself (explicit platform filter, platform_default left out), so a
  // partial snapshot can't reorder or drop unrelated policies.
  for (const platform of PLATFORMS) {
    const policyId = irPolicyIds[platform];
    if (!policyId) continue;
    const r = await ctx.callNative("falcon_set_policy_precedence", {
      policy_type: "prevention",
      platform_name: API_PLATFORM[platform],
      move_id: policyId,
      place_first: true,
    });
    if (r.error) {
      errors.push({ platform, stage: "set_precedence", ok: false, error: r.error });
      actions.push({
        platform,
        step: "set_precedence",
        policy_id: policyId,
        ok: false,
        warning:
          "Precedence not set — the IR policy may not enforce if a host is also in another group whose policy has " +
          "higher precedence. Fix in Falcon Console (Endpoint security → Prevention policies → reorder).",
      });
      continue;
    }
    actions.push({ platform, step: "set_precedence", policy_id: policyId, rank: "highest" });
  }

  actions.push({ step: "ir_readiness_exclusion", ...(await ensureReadinessExclusion(ctx, hostGroupId)) });

  return { ok: errors.length === 0, host_group_id: hostGroupId, mode, actions, errors };
}

export async function detachPreventionPolicy(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const policyId = input.prevention_policy_id;
  const groupId = input.host_group_id;
  if (typeof policyId !== "string" || !policyId) return { ok: false, error: "prevention_policy_id is required" };
  if (typeof groupId !== "string" || !groupId) return { ok: false, error: "host_group_id is required" };
  const r = await ctx.callNative("falcon_perform_policy_action", {
    policy_type: "prevention",
    action_name: "remove-host-group",
    ids: [policyId],
    group_id: groupId,
  });
  if (r.error) return { ok: false, prevention_policy_id: policyId, host_group_id: groupId, error: r.error };
  return {
    ok: true,
    prevention_policy_id: policyId,
    host_group_id: groupId,
    note:
      "Detached. The policy is unchanged elsewhere (still bound to its other host groups). Hosts in the named " +
      "host group fall to their next-precedence policy on next sensor heartbeat.",
  };
}
