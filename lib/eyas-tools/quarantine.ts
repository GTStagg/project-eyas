import type { EyasToolContext } from "./types";

// IR quarantine group setup and readiness (formerly falcon-extras
// ir/provision_quarantine.py diagnose / create / adopt and
// ir/diagnose_readiness.py). Reads and writes go through eyas-mcp natives.
// The group id defaults to the active environment's saved value, read at call
// time, so a group created or adopted earlier in the same chat turn (saved by
// the chat route's auto-save hook) is already visible.
//
// Policy provisioning (extras_provision_quarantine_policy) is still in the
// sidecar; the recommended actions below name it unchanged.

type Obj = Record<string, unknown>;

export const CANONICAL_GROUP_NAME = "Project Eyas - IR Quarantine";
export const CANONICAL_POLICY_PREFIX = "Project Eyas - IR Quarantine (auto"; // closed by ", <platform>)"
const SLIDER_IDS = ["OnSensorMLSlider", "CloudAntiMalware", "AdwarePUP"];
const TARGET_LEVEL = "AGGRESSIVE";
const LEVEL_RANK: Record<string, number> = {
  DISABLED: 0,
  CAUTIOUS: 1,
  MODERATE: 2,
  AGGRESSIVE: 3,
  EXTRA_AGGRESSIVE: 4,
};

// RTR's `runscript -CloudFile=` runs PowerShell with this fixed
// -EncodedCommand preamble (base64 of `Set-Location 'C:\'`). The IR-readiness
// IOA exclusion is recognised by this substring in its cl_regex.
export const RTR_PREAMBLE_BASE64 = "UwBlAHQALQBMAG8AYwBhAHQAaQBvAG4AIAAnAEMAOgBcACcA";
export const RTR_PREAMBLE_FULL_REGEX = `.*-EncodedCommand ${RTR_PREAMBLE_BASE64}.*`;
const READINESS_IFN_REGEX = ".*\\\\powershell\\.exe(\\W.*)?";

// parse.ts is server-only; loading it lazily keeps this module (and the
// tool list) importable from plain test scripts.
async function isScopeDenied(text: string): Promise<boolean> {
  const { isScopeDenied: check } = await import("@/lib/mcp/parse");
  return check(text);
}

const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
/** Host-group ids a record is scoped to. Policies and ML exclusions use
 *  `groups: [{id, …}]`; v2 IOA exclusions (what eyas-mcp reads) use
 *  `host_groups`, as ids or objects. */
function groupIdsOf(rec: Obj): string[] {
  const out: string[] = [];
  for (const key of ["groups", "host_groups"]) {
    const list = rec[key];
    if (!Array.isArray(list)) continue;
    for (const g of list) {
      if (typeof g === "string") out.push(g);
      else if (isObj(g) && g.id !== undefined && g.id !== null) out.push(String(g.id));
    }
  }
  return out;
}

/** Python repr of a str, for messages that quoted ids with !r. */
const pyQuote = (s: string) => `'${s}'`;

export async function activeQuarantineGroupId(): Promise<string | undefined> {
  const { getRuntimeConfig } = await import("@/lib/config/runtime");
  return getRuntimeConfig().irQuarantineGroupId || undefined;
}

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

/** A host group by id: the record, "missing", or an error / scope payload. */
async function lookupGroup(
  ctx: EyasToolContext,
  groupId: string,
): Promise<{ record: Obj } | { missing: true } | { fail: Obj }> {
  const r = await ctx.callNative("falcon_get_host_groups", { ids: [groupId] });
  if (r.error) {
    if (await isScopeDenied(r.error)) return { fail: scopePayload("HostGroup", r.error) };
    return { fail: { ok: false, error: r.error, surface: "HostGroup" } };
  }
  const found = Array.isArray(r.obj?.found) ? (r.obj.found as unknown[]).filter(isObj) : [];
  const rec = found.find((g) => g.id === groupId) ?? found[0];
  return rec ? { record: rec } : { missing: true };
}

// ---- policy classification (pure) -----------------------------------------

function flattenSettings(settings: unknown): Obj[] {
  const flat: Obj[] = [];
  for (const s of Array.isArray(settings) ? settings : []) {
    if (!isObj(s)) continue;
    if (Array.isArray(s.settings)) flat.push(...s.settings.filter(isObj));
    else flat.push(s);
  }
  return flat;
}

/** The canonical Windows sliders, for display only. */
export function sliderSummary(settings: unknown): Obj {
  const out: Obj = {};
  for (const s of flattenSettings(settings)) {
    const sid = s.id;
    if (typeof sid !== "string" || !SLIDER_IDS.includes(sid)) continue;
    const v = isObj(s.value) ? s.value : {};
    out[sid] = { detection: v.detection ?? null, prevention: v.prevention ?? null };
  }
  return out;
}

/** True when every slider's DETECTION level is at TARGET_LEVEL or above.
 *  Schema-tolerant: any setting whose value has a string `detection` is a
 *  slider; unrecognised vocabularies are skipped. Prevention is informational
 *  (Falcon caps it per slider). A policy with no rankable sliders passes. */
export function atTargetLevel(settings: unknown): boolean {
  const target = LEVEL_RANK[TARGET_LEVEL];
  for (const s of flattenSettings(settings)) {
    const v = s.value;
    if (!isObj(v) || typeof v.detection !== "string") continue;
    const rank = LEVEL_RANK[v.detection.toUpperCase()];
    if (rank === undefined) continue;
    if (rank < target) return false;
  }
  return true;
}

function recommendProvision(hostGroupId: string, mode: "adopt" | "create_dedicated"): Obj {
  const label =
    mode === "adopt"
      ? "Provision the IR quarantine prevention policy (adopt + standardize)"
      : "Create dedicated prevention policies for IR quarantine";
  const description =
    mode === "adopt"
      ? "Adopts the policy currently bound to this group (or attaches a fresh one if none exists), renames it " +
        `to the canonical '${CANONICAL_POLICY_PREFIX}, <platform>)' format, pushes ${TARGET_LEVEL} prevention ` +
        "sliders, and creates the IR-readiness IOA exclusion. Per platform: Windows, macOS, Linux."
      : `Your existing policy is attached to other host groups, so pushing ${TARGET_LEVEL} settings to it ` +
        "would change posture on those groups too. This action creates a new dedicated prevention policy " +
        "per platform bound ONLY to your IR quarantine group, leaves the existing policy alone, and creates " +
        "the IR-readiness IOA exclusion.";
  return {
    tool: "extras_provision_quarantine_policy",
    args: { host_group_id: hostGroupId, mode },
    label,
    description,
  };
}

function createGroupAction(description: string): Obj {
  return {
    tool: "extras_create_quarantine_host_group",
    args: { name: CANONICAL_GROUP_NAME },
    label: "Create the IR quarantine host group",
    description,
  };
}

export type DiagnoseInputs = {
  hostGroupId: string;
  group: Obj;
  policies: Obj[];
  exclusions: Obj[] | null; // null when they couldn't be read
};

/** Classify the quarantine setup from already-fetched records (pure). */
export function classifyQuarantineSetup(d: DiagnoseInputs): Obj {
  const policiesOnGroup: (Obj & { _raw: unknown })[] = [];
  for (const p of d.policies) {
    const attached = groupIdsOf(p);
    if (!attached.includes(d.hostGroupId)) continue;
    const name = str(p.name);
    policiesOnGroup.push({
      id: p.id ?? null,
      name: p.name ?? null,
      platform: p.platform_name ?? null,
      enabled: p.enabled === undefined ? true : Boolean(p.enabled),
      attached_group_ids: attached,
      is_dedicated: attached.length === 1,
      managed_by_eyas: name !== null && name.startsWith(CANONICAL_POLICY_PREFIX),
      settings_summary: sliderSummary(p.prevention_settings),
      _raw: p.prevention_settings,
    });
  }

  let exclusionPresent = false;
  for (const r of d.exclusions ?? []) {
    if (!groupIdsOf(r).includes(d.hostGroupId)) continue;
    if ((str(r.cl_regex) ?? "").includes(RTR_PREAMBLE_BASE64)) {
      exclusionPresent = true;
      break;
    }
  }

  let kase: string;
  let recommendation: Obj | null;
  if (policiesOnGroup.length === 0) {
    kase = "A_no_policy";
    recommendation = recommendProvision(d.hostGroupId, "adopt");
  } else {
    const anyShared = policiesOnGroup.some((p) => !p.is_dedicated);
    const allProvisioned =
      policiesOnGroup.every((p) => p.managed_by_eyas) &&
      policiesOnGroup.every((p) => atTargetLevel(p._raw)) &&
      exclusionPresent;
    if (allProvisioned) {
      kase = "ready";
      recommendation = null;
    } else if (anyShared) {
      kase = "C_shared_policy";
      recommendation = recommendProvision(d.hostGroupId, "create_dedicated");
    } else {
      kase = "B_dedicated_single_group";
      recommendation = recommendProvision(d.hostGroupId, "adopt");
    }
  }

  return {
    ok: true,
    case: kase,
    host_group_id: d.hostGroupId,
    host_group: { id: d.group.id ?? null, name: d.group.name ?? null, group_type: d.group.group_type ?? null },
    policies: policiesOnGroup.map(({ _raw, ...rest }) => {
      void _raw;
      return rest;
    }),
    ir_readiness_exclusion_present: exclusionPresent,
    recommended_action: recommendation,
  };
}

async function allPreventionPolicies(ctx: EyasToolContext): Promise<{ items: Obj[] } | { fail: Obj }> {
  const r = await ctx.searchNative("falcon_search_policies", { policy_type: "prevention", limit: 500 });
  if (!r.ok) return { fail: { ok: false, error: `policy walk: ${r.error}` } };
  if (r.scope_pending) return { fail: scopePayload("Prevention Policies", "permission denied") };
  return { items: r.items };
}

async function allIoaExclusions(ctx: EyasToolContext): Promise<{ items: Obj[] } | { error: string; scope: boolean }> {
  const r = await ctx.searchNative("falcon_search_exclusions", { exclusion_type: "ioa", limit: 500 });
  if (!r.ok) return { error: r.error, scope: await isScopeDenied(r.error) };
  if (r.scope_pending) return { error: "permission denied", scope: true };
  return { items: r.items };
}

// ---- diagnose ----------------------------------------------------------------

export async function diagnoseQuarantineSetup(ctx: EyasToolContext, explicitGroupId?: string | null): Promise<Obj> {
  const hostGroupId = explicitGroupId || (await activeQuarantineGroupId());
  if (!hostGroupId) {
    return {
      ok: true,
      case: "no_group_id",
      host_group_id: null,
      host_group: null,
      policies: [],
      ir_readiness_exclusion_present: false,
      recommended_action: createGroupAction(
        `Creates a new static host group named '${CANONICAL_GROUP_NAME}'. After creation, save the returned ` +
          "id as the IR quarantine group on the active environment, then re-run this diagnostic to provision " +
          "the prevention policy.",
      ),
    };
  }

  const g = await lookupGroup(ctx, hostGroupId);
  if ("fail" in g) return g.fail;
  if ("missing" in g) {
    return {
      ok: true,
      case: "group_missing",
      host_group_id: hostGroupId,
      host_group: null,
      policies: [],
      ir_readiness_exclusion_present: false,
      recommended_action: createGroupAction(
        `The configured group id ${pyQuote(hostGroupId)} does not exist in this tenant. Create a fresh group ` +
          "and update the IR quarantine field with the new id.",
      ),
    };
  }

  const pol = await allPreventionPolicies(ctx);
  if ("fail" in pol) return pol.fail;
  // Exclusions are non-fatal: an unreadable list reads as "not present".
  const exc = await allIoaExclusions(ctx);
  return classifyQuarantineSetup({
    hostGroupId,
    group: g.record,
    policies: pol.items,
    exclusions: "items" in exc ? exc.items : null,
  });
}

// ---- create / adopt ----------------------------------------------------------

export async function createQuarantineHostGroup(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const name = input.name === undefined || input.name === null ? CANONICAL_GROUP_NAME : input.name;
  if (typeof name !== "string" || !name) return { ok: false, error: "name is required" };
  const description =
    (typeof input.description === "string" && input.description) ||
    "App-managed: hosts placed here during incident response. Three platform-specific prevention policies " +
      "(Windows / macOS / Linux) should be attached, all set to AGGRESSIVE.";
  const r = await ctx.callNative("falcon_create_host_group", { name, group_type: "static", description });
  if (r.error) {
    return (await isScopeDenied(r.error)) ? scopePayload("HostGroup", r.error) : { ok: false, error: r.error, surface: "HostGroup" };
  }
  const rec = r.obj;
  if (!rec || typeof rec.id !== "string") return { ok: false, error: "create_host_groups returned no record" };
  return {
    ok: true,
    id: rec.id,
    name: rec.name ?? name,
    group_type: rec.group_type ?? "static",
    next_step:
      "The new group id is saved to the active environment automatically — no manual step is needed. " +
      "Proceed directly to extras_provision_quarantine_policy with this host_group_id.",
  };
}

export async function adoptQuarantineHostGroup(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const name = input.name === undefined || input.name === null ? CANONICAL_GROUP_NAME : input.name;
  if (typeof name !== "string" || !name) return { ok: false, error: "name is required" };
  // exact_name pages through every group and compares case-sensitively; FQL
  // name matching is unreliable for names with spaces and hyphens.
  const r = await ctx.searchNative("falcon_search_host_groups", { exact_name: name, limit: 500 });
  if (!r.ok) return { ok: false, error: r.error, surface: "HostGroup" };
  if (r.scope_pending) return scopePayload("HostGroup", "permission denied");
  const exact = r.items.filter((g) => g.name === name);
  if (exact.length === 0) {
    return {
      ok: false,
      error: `no host group named '${name}' found in this tenant`,
      hint: "use extras_create_quarantine_host_group to create it",
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
    next_step: "Saved as the active environment's IR quarantine group.",
  };
}

// ---- IR readiness -----------------------------------------------------------

const EXCLUSION_NAME = "Project Eyas IR — RTR runscript preamble";

export async function diagnoseIrReadiness(ctx: EyasToolContext, groupIdOverride?: string): Promise<Obj> {
  const quarantineGroupId = groupIdOverride ?? (await activeQuarantineGroupId()) ?? "";
  const checks: Obj & { ioa_exclusions_scoped_to_quarantine: Obj[] } = {
    quarantine_group_configured: Boolean(quarantineGroupId),
    quarantine_group_id: quarantineGroupId || null,
    quarantine_group_exists: false,
    quarantine_group_name: null,
    quarantine_group_type: null,
    ioa_exclusions_scoped_to_quarantine: [],
    rtr_preamble_exclusion_present: false,
    rtr_preamble_exclusion_id: null,
    candidate_pattern_id: null,
    candidate_pattern_name: null,
    candidate_pattern_source_composite_id: null,
  };
  const missing: string[] = [];
  if (!quarantineGroupId) {
    missing.push("The active environment has no IR quarantine host group set");
    return {
      ok: true,
      ready: false,
      checks,
      missing,
      remediation: {
        tool_calls: [],
        notes: [
          "Set the active environment's IR quarantine host group (in /config) to a static Falcon Host Group " +
            "with an aggressive prevention policy, then re-run this diagnostic.",
        ],
      },
    };
  }

  const guardMsg = (scope: boolean, what: string, error: string) =>
    scope
      ? `${what} could not be verified — the required Falcon API scope is not granted on this tenant.`
      : `${what} failed: ${error || "upstream error"}`;

  // 1. The quarantine group exists. An unverifiable lookup is a gap, never
  //    "ready": a transient 500 must not let the gate pass.
  const g = await lookupGroup(ctx, quarantineGroupId);
  if ("record" in g) {
    checks.quarantine_group_exists = true;
    checks.quarantine_group_name = g.record.name ?? null;
    checks.quarantine_group_type = g.record.group_type ?? null;
  } else if ("missing" in g) {
    missing.push(`Quarantine group id ${pyQuote(quarantineGroupId)} does not exist in Falcon`);
  } else {
    const f = g.fail;
    missing.push(guardMsg(f.scope_pending === true, "Quarantine group lookup", String(f.error ?? "")));
  }

  // 2. IOA exclusions scoped to the group; is the RTR-preamble one there?
  let enumerated = false;
  const exc = await allIoaExclusions(ctx);
  if ("items" in exc) {
    enumerated = true;
    for (const r of exc.items) {
      if (!groupIdsOf(r).includes(quarantineGroupId)) continue;
      checks.ioa_exclusions_scoped_to_quarantine.push({
        id: r.id ?? null,
        name: r.name ?? null,
        pattern_id: r.pattern_id ?? null,
        ifn_regex: r.ifn_regex ?? null,
        cl_regex: r.cl_regex ?? null,
      });
      if ((str(r.cl_regex) ?? "").includes(RTR_PREAMBLE_BASE64)) {
        checks.rtr_preamble_exclusion_present = true;
        checks.rtr_preamble_exclusion_id = r.id ?? null;
      }
    }
  } else {
    missing.push(guardMsg(exc.scope, "IOA exclusion enumeration", exc.error));
  }

  // 3. A pattern_id from the most recent PShellMimikatz detection, so the
  //    create-exclusion call can be concrete. Non-fatal.
  const det = await ctx.searchNative("falcon_search_detections", {
    filter: "product:'epp'+display_name:'PShellMimikatz'",
    limit: 1,
    sort: "created_timestamp.desc",
  });
  if (det.ok && !det.scope_pending && det.items.length > 0) {
    const rec = det.items[0];
    let pid = rec.pattern_id;
    let pname = rec.display_name ?? rec.pattern_disposition ?? null;
    if (!pid) {
      for (const b of Array.isArray(rec.behaviors) ? rec.behaviors : []) {
        if (isObj(b) && b.pattern_id) {
          pid = b.pattern_id;
          pname = b.display_name ?? pname;
          break;
        }
      }
    }
    if (pid) {
      checks.candidate_pattern_id = String(pid);
      checks.candidate_pattern_name = pname;
      checks.candidate_pattern_source_composite_id = rec.composite_id ?? null;
    }
  } else if (!det.ok) {
    checks.candidate_pattern_id_lookup_error = det.error;
  }

  // 4. Remediation.
  const toolCalls: Obj[] = [];
  if (checks.quarantine_group_exists && enumerated && !checks.rtr_preamble_exclusion_present) {
    missing.push(
      "RTR runscript preamble IOA exclusion is NOT scoped to the quarantine host group. Phase 2 cleanup " +
        "primitives WILL be blocked by the quarantine policy until this exclusion is created.",
    );
    const pid = checks.candidate_pattern_id;
    if (pid) {
      toolCalls.push({
        tool: "extras_create_ioa_exclusion",
        args: {
          name: EXCLUSION_NAME,
          pattern_id: pid,
          ifn_regex: READINESS_IFN_REGEX,
          cl_regex: RTR_PREAMBLE_FULL_REGEX,
          comment:
            "Suppresses PShellMimikatz / PowerShell-encoded-command detections triggered by Project Eyas's IR " +
            "workflow when RTR invokes runscript -CloudFile=<name>. The encoded preamble decodes to " +
            "Set-Location 'C:\\'. Scoped to the quarantine host group only — production hosts retain full " +
            "PShellMimikatz coverage.",
          group_ids: [quarantineGroupId],
        },
      });
    } else {
      toolCalls.push({
        tool: "extras_create_ioa_exclusion",
        needs_pattern_id_lookup: true,
        note:
          "No PShellMimikatz detection found on this tenant to auto-discover pattern_id. To get one: trigger a " +
          "test detection by running any encoded-command PowerShell on a non-production host, then re-run this " +
          "diagnostic. Alternatively, supply pattern_id manually from a sample detection's behaviors[].pattern_id field.",
        args_template: {
          name: EXCLUSION_NAME,
          pattern_id: "<lookup required>",
          ifn_regex: READINESS_IFN_REGEX,
          cl_regex: RTR_PREAMBLE_FULL_REGEX,
          comment:
            "Suppresses PShellMimikatz / PowerShell-encoded-command detections triggered by Project Eyas's IR " +
            "workflow when RTR invokes runscript -CloudFile=<name>.",
          group_ids: [quarantineGroupId],
        },
      });
    }
  }

  return {
    ok: true,
    ready: missing.length === 0,
    checks,
    missing,
    remediation: {
      tool_calls: toolCalls,
      notes:
        toolCalls.length > 0
          ? [
              "Each remediation tool_call requires explicit user approval at execution time " +
                "(extras_create_ioa_exclusion is in the write-tool registry).",
              "After applying remediation, re-run extras_diagnose_ir_readiness to confirm `ready: true` before " +
                "running the IR workflow on any host.",
            ]
          : ["All IR prerequisites satisfied — workflow can run cleanly on this tenant."],
    },
  };
}
