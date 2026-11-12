import { randomBytes } from "node:crypto";
import { runDispatch } from "@/lib/mcp/native-dispatch";
import { jsonResult, type EyasTool, type EyasToolContext, type EyasToolResult } from "./types";
import { RTR_TOOL_SPECS } from "./rtr/tool-specs";
import {
  findById,
  linuxPkgFallback,
  listCleanupScripts,
  listPatchScripts,
  matchRemediation,
  ParamError,
  resolvePlan,
  validateParams,
  type ResolvedPlan,
  type ScriptSpec,
} from "./rtr/library";

// The curated RTR script library's agent tools (formerly falcon-extras
// rtr_tools.py). Eyas validates and renders; a live run uploads the rendered
// bytes to eyas-mcp as a one-off private script, runs it and deletes it
// (lib/mcp/native-dispatch.ts). The agent supplies a script id and params,
// never script bytes. Result shapes are unchanged from the sidecar so prompts,
// the IR ledger, approval cards and summaries read them as before.

type Obj = Record<string, unknown>;

// Any single batch larger than this needs confirm_large_batch=true. Patch and
// cleanup are per-host work; fanning out a wide rollout in one approval is
// the bug this prevents.
export const LARGE_BATCH_THRESHOLD = 25;

// The generic installer is the only patch script that takes a vendor URL and
// an optional integrity pin at run time; the plan surfaces whether a hash was
// pinned so an approval can never silently accept an unverified install.
const GENERIC_INSTALLER_IDS = new Set(["win-app-install"]);

const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const fail = (error: string, extra: Obj = {}): EyasToolResult => jsonResult({ ok: false, error, ...extra });
const strList = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
const optStr = (v: unknown): string | null => (typeof v === "string" && v.length > 0 ? v : null);
const paramsOf = (v: unknown): Obj => (isObj(v) ? v : {});

function integritySignal(plan: ResolvedPlan): Obj {
  if (!GENERIC_INSTALLER_IDS.has(plan.script_id)) return {};
  return { hash_pinned: Boolean(plan.params.sha256) };
}

/** Resolve a plan, turning a validation failure into the tool's ok:false. */
function tryResolve(
  catalog: "patching" | "cleanup",
  scriptId: unknown,
  params: Obj,
  vouched?: ReadonlySet<string>,
): ResolvedPlan | EyasToolResult {
  try {
    return resolvePlan(catalog, String(scriptId ?? ""), params, vouched);
  } catch (e) {
    if (e instanceof ParamError) return fail(e.message);
    throw e;
  }
}

const isResult = (v: ResolvedPlan | EyasToolResult): v is EyasToolResult => "content" in v;

function batchGuard(deviceIds: string[], confirm: unknown, patch: boolean): EyasToolResult | null {
  if (deviceIds.length === 0) return fail("device_ids must be a non-empty list");
  if (deviceIds.length > LARGE_BATCH_THRESHOLD && confirm !== true) {
    return fail(
      `refusing to execute on ${deviceIds.length} hosts without confirm_large_batch=True (threshold ${LARGE_BATCH_THRESHOLD}).` +
        (patch ? " Re-issue the call with confirm_large_batch=True after a second operator approval." : ""),
      { host_count: deviceIds.length, threshold: LARGE_BATCH_THRESHOLD },
    );
  }
  return null;
}

async function dispatchRun(plan: ResolvedPlan, deviceIds: string[], meta: Obj, ctx: EyasToolContext): Promise<EyasToolResult> {
  const envelope: Obj = {
    ok: true,
    dispatch: { kind: "rtr_script", script_body: plan.rendered, platform: plan.os, device_ids: deviceIds },
    ...meta,
  };
  return jsonResult(await runDispatch(envelope, ctx.callNative));
}

function normalizeOsLabel(raw: unknown): string | null {
  const r = String(raw ?? "").trim().toLowerCase();
  if (r.startsWith("win")) return "windows";
  if (r.startsWith("lin")) return "linux";
  if (r.startsWith("mac") || r === "darwin" || r === "osx" || r === "os x") return "macos";
  return null;
}

function newProfileId(): string {
  return "pp_" + randomBytes(6).toString("hex");
}

function tool(name: string, run: EyasTool["run"], opts: { rawResult?: boolean } = {}): EyasTool {
  const spec = RTR_TOOL_SPECS[name];
  if (!spec) throw new Error(`missing spec for ${name}`);
  return { name, description: spec.description, input_schema: spec.input_schema, run, ...opts };
}

// ---- patch catalog ---------------------------------------------------------

async function resolvePatchPlan(input: Obj): Promise<EyasToolResult> {
  const deviceIds = strList(input.device_ids);
  let params = paramsOf(input.params);
  let spec: ScriptSpec | null;
  const scriptId = optStr(input.script_id);
  if (scriptId) {
    spec = findById("patching", scriptId);
    if (!spec) return fail(`unknown script id: ${scriptId}`);
  } else {
    const rem = paramsOf(input.spotlight_remediation);
    const vendor = String(rem.vendor ?? "");
    const product = String(rem.product ?? "");
    const osHint = typeof input.os_hint === "string" ? input.os_hint.trim().toLowerCase() || null : null;
    if (osHint && !["windows", "linux", "macos"].includes(osHint)) {
      return fail(`os_hint must be one of windows|linux|macos (got '${String(input.os_hint)}')`);
    }
    spec = matchRemediation(vendor, product, osHint);
    let extracted: Obj = {};
    if (!spec && osHint === "linux") {
      const fb = linuxPkgFallback(product);
      if (fb) {
        spec = fb.spec;
        extracted = fb.params;
      }
    }
    if (!spec) {
      const genericOk = osHint === "windows";
      const gap: Obj = {
        ok: false,
        error: "no curated script matches this remediation entity",
        vendor,
        product,
        os_hint: osHint,
        generic_installer_available: genericOk,
      };
      if (genericOk) {
        gap.hint =
          "No app-specific script ships for this Windows product, but the generic installer can patch it. " +
          'Re-resolve with script_id="win-app-install" and params {url (vendor HTTPS download), kind (\'msi\'|\'exe\'), ' +
          "product (friendly name), optional sha256 (STRONGLY preferred — host-side verify-or-abort integrity pin), " +
          "optional silent_args (exe-only)}. This is NOT freehand: the script bytes are baked, only validated params " +
          "pass the regex. Then dry-run via extras_rtr_run_patch (it reports hash_pinned) before executing.";
      }
      return jsonResult(gap);
    }
    // Operator-supplied params override extracted ones (a misparsed package name).
    params = { ...extracted, ...params };
  }
  const plan = tryResolve("patching", spec.id, params);
  if (isResult(plan)) return plan;
  return jsonResult({
    ok: true,
    script_id: plan.script_id,
    title: plan.title,
    os: plan.os,
    params: plan.params,
    preview: plan.preview,
    reboot_risk: plan.reboot_risk,
    expected_runtime_minutes: plan.expected_runtime_minutes,
    read_only: plan.read_only,
    target_device_count: deviceIds.length,
    target_device_sample: deviceIds.slice(0, 5),
    ...integritySignal(plan),
  });
}

async function runPatch(input: Obj, ctx: EyasToolContext): Promise<EyasToolResult> {
  const plan = tryResolve("patching", input.script_id, paramsOf(input.params));
  if (isResult(plan)) return plan;
  const deviceIds = strList(input.device_ids);
  const guard = batchGuard(deviceIds, input.confirm_large_batch, true);
  if (guard) return guard;
  if (input.dry_run !== false) {
    return jsonResult({
      ok: true,
      dry_run: true,
      script_id: plan.script_id,
      title: plan.title,
      params: plan.params,
      preview: plan.preview,
      reboot_risk: plan.reboot_risk,
      expected_runtime_minutes: plan.expected_runtime_minutes,
      host_count: deviceIds.length,
      device_id_sample: deviceIds.slice(0, 5),
      ...integritySignal(plan),
    });
  }
  return dispatchRun(plan, deviceIds, {
    dry_run: false,
    script_id: plan.script_id,
    title: plan.title,
    reboot_risk: plan.reboot_risk,
  }, ctx);
}

async function checkPatchStatus(input: Obj, ctx: EyasToolContext): Promise<EyasToolResult> {
  const ids = strList(input.cloud_request_ids).filter((i) => i.trim());
  if (ids.length === 0) return fail("cloud_request_ids is empty");
  return jsonResult(await runDispatch({ ok: true, dispatch: { kind: "rtr_status", cloud_request_ids: ids } }, ctx.callNative));
}

// ---- cleanup catalog -------------------------------------------------------

async function resolveCleanupPlan(input: Obj): Promise<EyasToolResult> {
  const plan = tryResolve("cleanup", input.script_id, paramsOf(input.params));
  if (isResult(plan)) return plan;
  return jsonResult({
    ok: true,
    script_id: plan.script_id,
    title: plan.title,
    intent: plan.intent,
    params: plan.params,
    preview: plan.preview,
  });
}

async function runCleanup(input: Obj, ctx: EyasToolContext): Promise<EyasToolResult> {
  const evidence = isObj(input.evidence) ? input.evidence : null;
  const vouched = new Set(evidence ? strList(evidence.vouched_param_keys) : []);
  const plan = tryResolve("cleanup", input.script_id, paramsOf(input.params), vouched.size ? vouched : undefined);
  if (isResult(plan)) return plan;
  const deviceIds = strList(input.device_ids);
  const guard = batchGuard(deviceIds, input.confirm_large_batch, false);
  if (guard) return guard;
  const ev = evidence && Object.keys(evidence).length > 0 ? { evidence } : {};
  if (input.dry_run !== false) {
    return jsonResult({
      ok: true,
      dry_run: true,
      script_id: plan.script_id,
      title: plan.title,
      intent: plan.intent,
      params: plan.params,
      preview: plan.preview,
      host_count: deviceIds.length,
      device_id_sample: deviceIds.slice(0, 5),
      ...ev,
    });
  }
  return dispatchRun(plan, deviceIds, { dry_run: false, script_id: plan.script_id, title: plan.title, ...ev }, ctx);
}

// ---- patch profiles --------------------------------------------------------

async function savePatchProfile(input: Obj): Promise<EyasToolResult> {
  const label = String(input.name ?? "").trim();
  if (!label) return fail("name is required");
  if (label.length > 64) return fail("name must be 64 characters or fewer");
  const spec = findById("patching", "win-app-install");
  if (!spec) return fail("generic installer is not available in this build");

  const supplied: Obj = { url: input.url, product: input.product, kind: input.kind };
  if (optStr(input.sha256)) supplied.sha256 = input.sha256;
  if (optStr(input.silent_args)) supplied.silent_args = input.silent_args;
  let validated: Obj;
  try {
    // The same manifest regex boundary resolve/run enforce, so a saved
    // profile can never carry params that wouldn't pass at execution time.
    validated = validateParams(spec.params ?? {}, supplied);
  } catch (e) {
    if (e instanceof ParamError) return fail(e.message);
    throw e;
  }
  const profile: Obj = {
    id: newProfileId(),
    name: label,
    product: validated.product,
    url: validated.url,
    kind: validated.kind,
    createdAt: new Date().toISOString(),
  };
  if (validated.sha256) profile.sha256 = validated.sha256;
  if (validated.silent_args) profile.silentArgs = validated.silent_args;
  // The chat route's auto-save hook appends this to the active environment.
  return jsonResult({ ok: true, profile, hash_pinned: Boolean(profile.sha256) });
}

async function listPatchProfiles(): Promise<EyasToolResult> {
  const { getRuntimeConfig } = await import("@/lib/config/runtime");
  const profiles = getRuntimeConfig().patchProfiles ?? [];
  return jsonResult({ ok: true, profiles, count: profiles.length });
}

// ---- coverage --------------------------------------------------------------

export function classifyPatchCoverage(remediations: unknown): Obj {
  if (!Array.isArray(remediations)) return { ok: false, error: "remediations must be a list" };
  const results = remediations.map((entry) => {
    if (!isObj(entry)) {
      return { vendor: "", product: "", os: null, matched: false, script_id: null, generic_installer_eligible: false };
    }
    const vendor = String(entry.vendor ?? "");
    const product = String(entry.product ?? "");
    const os = normalizeOsLabel(entry.os);
    let spec = matchRemediation(vendor, product, os);
    if (!spec && os === "linux") spec = linuxPkgFallback(product)?.spec ?? null;
    const matched = spec !== null;
    return {
      vendor,
      product,
      os,
      matched,
      script_id: spec ? spec.id : null,
      generic_installer_eligible: os === "windows" && !matched,
    };
  });
  return { ok: true, results, count: results.length };
}

// The two catalog listings skip the bridge's 12 KB result cap: the cleanup
// catalog alone is ~25 KB, and the chat prompt tells the agent to check both
// catalogs before declaring an action impossible, which a truncated list
// defeats. They are Eyas's own content, not Falcon data.
export const RTR_TOOLS: EyasTool[] = [
  tool(
    "extras_rtr_list_patch_scripts",
    async (input) => jsonResult({ ok: true, scripts: listPatchScripts(optStr(input.os_filter)) }),
    { rawResult: true },
  ),
  tool("extras_rtr_resolve_patch_plan", (input) => resolvePatchPlan(input)),
  tool("extras_rtr_run_patch", (input, ctx) => runPatch(input, ctx)),
  tool("extras_rtr_check_patch_status", (input, ctx) => checkPatchStatus(input, ctx)),
  tool(
    "extras_rtr_list_cleanup_scripts",
    async (input) => jsonResult({ ok: true, scripts: listCleanupScripts(optStr(input.os_filter)) }),
    { rawResult: true },
  ),
  tool("extras_rtr_resolve_cleanup_plan", (input) => resolveCleanupPlan(input)),
  tool("extras_rtr_run_cleanup", (input, ctx) => runCleanup(input, ctx)),
  tool("extras_save_patch_profile", (input) => savePatchProfile(input)),
  tool("extras_list_patch_profiles", () => listPatchProfiles()),
  tool("extras_classify_patch_coverage", async (input) => jsonResult(classifyPatchCoverage(input.remediations))),
];

