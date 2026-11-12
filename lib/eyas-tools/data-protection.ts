// Data Protection (DLP) configuration creates — content patterns,
// classifications and policies — formerly the sidecar's data_protection.py.
//
// The chain is built bottom-up: a content pattern (named regexes), a
// classification (content patterns + a detection rule, monitor or enforce),
// then a platform-scoped policy that binds classifications and lands on
// hosts. Every tool is an approval-gated write. The agent supplies the
// identifiers; the heavy bodies are filled in here with monitor-first defaults
// (observe, don't block), not by the model. The write goes through eyas-mcp's
// falcon_create_data_security_entity (hidden from the agent in
// NATIVE_WRITE_SUPPRESS, so these defaults can't be bypassed). Tested in
// scripts/test-exclusions.mjs.

import type { EyasToolContext } from "./types";

type Obj = Record<string, unknown>;

const PROTECTION_MODES = ["enforce", "monitor"];
const PLATFORMS = ["mac", "win"];
const SEVERITIES = ["critical", "high", "informational", "low", "medium"];
const RESPONSE_ACTIONS = ["allow", "block"];
const INSPECTION_DEPTHS = ["balanced", "deep", "shallow"];
const CONFIDENCE_LEVELS = ["high", "low", "medium"];

const pyList = (xs: string[]) => `[${xs.map((x) => `'${x}'`).join(", ")}]`;

/** Em / en dashes become hyphens in names and descriptions: Falcon's DLP
 *  validator rejects them, and the agent writes them in prose. */
export const safeText = (s: string) => s.replace(/[—–]/g, "-");

const isStrList = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

async function failPayload(surface: string, error: string): Promise<Obj> {
  const { isScopeDenied } = await import("@/lib/mcp/parse");
  if (isScopeDenied(error)) {
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
      _diagnostic: error.slice(0, 200),
    };
  }
  return { ok: false, error, surface };
}

async function create(ctx: EyasToolContext, entityType: string, body: Obj, surface: string, platform?: string): Promise<{ id: string | null } | { fail: Obj }> {
  const args: Obj = { entity_type: entityType, body };
  if (platform) args.platform_name = platform;
  const r = await ctx.callNative("falcon_create_data_security_entity", args);
  if (r.error) return { fail: await failPayload(surface, r.error) };
  return { id: r.obj && typeof r.obj.id === "string" ? r.obj.id : null };
}

/** extras_create_data_protection_content_pattern. */
export async function createContentPattern(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const { name, regexes, category } = input;
  const region = typeof input.region === "string" ? input.region : "ALL";
  const minMatch = input.min_match_threshold ?? 1;
  if (!name || typeof name !== "string") return { ok: false, error: "name is required and must be a string" };
  if (!isStrList(regexes) || regexes.length === 0) {
    return { ok: false, error: "regexes is required and must be a non-empty list of strings" };
  }
  if (!category || typeof category !== "string") return { ok: false, error: "category is required and must be a string" };
  const body: Obj = {
    name: safeText(name),
    regexes: [...regexes],
    category,
    region,
    min_match_threshold: Math.trunc(Number(minMatch)),
  };
  if (typeof input.description === "string" && input.description) body.description = safeText(input.description);
  if (typeof input.example === "string" && input.example) body.example = input.example;
  const r = await create(ctx, "content_pattern", body, "DataProtection content pattern");
  if ("fail" in r) return r.fail;
  return { ok: true, id: r.id, name, category, region, regex_count: regexes.length };
}

/** extras_create_data_protection_classification. */
export async function createClassification(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const { name, content_patterns: patterns } = input;
  const mode = input.protection_mode ?? "monitor";
  const severity = input.detection_severity ?? "informational";
  const action = input.response_action ?? "allow";
  if (!name || typeof name !== "string") return { ok: false, error: "name is required and must be a string" };
  if (!Array.isArray(patterns) || patterns.length === 0) {
    return { ok: false, error: "content_patterns is required and must be a non-empty list of pattern ids" };
  }
  if (!PROTECTION_MODES.includes(mode as string)) return { ok: false, error: `protection_mode must be one of ${pyList(PROTECTION_MODES)}` };
  if (!SEVERITIES.includes(severity as string)) return { ok: false, error: `detection_severity must be one of ${pyList(SEVERITIES)}` };
  if (!RESPONSE_ACTIONS.includes(action as string)) return { ok: false, error: `response_action must be one of ${pyList(RESPONSE_ACTIONS)}` };
  const rule = {
    detection_severity: severity,
    response_action: action,
    user_scope: "all",
    web_locations_scope: "all",
    trigger_detection: true,
    notify_end_user: Boolean(input.notify_end_user),
    enable_web_locations: true,
    enable_usb_devices: true,
    enable_printer_egress: true,
  };
  const body = {
    name: safeText(name),
    classification_properties: {
      content_patterns: [...patterns],
      protection_mode: mode,
      file_types: Array.isArray(input.file_types) && input.file_types.length ? [...input.file_types] : [],
      evidence_duplication_enabled: true,
      rules: [rule],
    },
  };
  const r = await create(ctx, "classification", body, "DataProtection classification");
  if ("fail" in r) return r.fail;
  return { ok: true, id: r.id, name, protection_mode: mode, content_patterns: [...patterns] };
}

/** extras_create_data_protection_policy. */
export async function createPolicy(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const { name, platform, classifications } = input;
  const depth = input.inspection_depth ?? "balanced";
  const confidence = input.min_confidence_level ?? "low";
  const flag = (k: string) => (input[k] === undefined || input[k] === null ? true : Boolean(input[k]));
  if (!name || typeof name !== "string") return { ok: false, error: "name is required and must be a string" };
  if (!PLATFORMS.includes(platform as string)) return { ok: false, error: `platform must be one of ${pyList(PLATFORMS)}` };
  if (!Array.isArray(classifications) || classifications.length === 0) {
    return { ok: false, error: "classifications is required and must be a non-empty list of classification ids" };
  }
  if (!INSPECTION_DEPTHS.includes(depth as string)) return { ok: false, error: `inspection_depth must be one of ${pyList(INSPECTION_DEPTHS)}` };
  if (!CONFIDENCE_LEVELS.includes(confidence as string)) {
    return { ok: false, error: `min_confidence_level must be one of ${pyList(CONFIDENCE_LEVELS)}` };
  }
  const body: Obj = {
    name: safeText(name),
    policy_properties: {
      classifications: [...classifications],
      enable_content_inspection: flag("enable_content_inspection"),
      enable_context_inspection: flag("enable_context_inspection"),
      enable_network_inspection: flag("enable_network_inspection"),
      enable_clipboard_inspection: true,
      inspection_depth: depth,
      min_confidence_level: confidence,
      allow_notifications: "default",
      block_notifications: "default",
      block_all_data_access: false,
      browsers_without_active_extension: "allow",
      unsupported_browsers_action: "allow",
      similarity_detection: false,
    },
  };
  if (typeof input.description === "string" && input.description) body.description = safeText(input.description);
  if (input.precedence !== undefined && input.precedence !== null) body.precedence = Math.trunc(Number(input.precedence));
  const r = await create(ctx, "policy", body, "DataProtection policy", platform as string);
  if ("fail" in r) return r.fail;
  return { ok: true, id: r.id, name, platform, classifications: [...classifications] };
}
