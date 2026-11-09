// Prevention-policy posture for /prevention, the home dashboard, Shadow-AI
// setup and the posture snapshot, built on eyas-mcp's falcon_get_prevention_posture.
//
// eyas-mcp reports every ML slider's detection / prevention level per policy
// and its own generic flags. Eyas keeps its narrower opinion of what
// "detect-only" means here: only the sensor ML slider (OnSensorMLSlider) and
// cloud antivirus (CloudAntiMalware) count, so a policy that merely detects
// Adware/PUP isn't flagged as under-protected. shapePosture reduces the native
// result to the shape these surfaces already read:
//   { ok, items: [{id, name, platform, enabled, description, groups, settings, flags}],
//     count, platform_counts, summary: {total, disabled, detect_only} }
// Flags: disabled / ml_detect_only / cloud_av_detect_only.

import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { detectFalconError, isScopeDenied } from "@/lib/mcp/parse";

type Obj = Record<string, unknown>;

export type PostureItem = {
  id: string | null;
  name: string | null;
  platform: string;
  enabled: boolean;
  description: string;
  groups: Array<{ id: string; name: string | null }>;
  settings: Record<string, string>;
  flags: string[];
};

export type PosturePayload =
  | {
      ok: true;
      items: PostureItem[];
      count: number;
      platform_counts: Record<string, number>;
      summary: { total: number; disabled: number; detect_only: number };
      warning?: string;
    }
  | { ok: true; scope_pending: true; items: []; note?: string }
  | { ok: false; error: string };

const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const OFF = new Set(["", "DISABLED", "OFF"]);
const active = (level: unknown) => typeof level === "string" && !OFF.has(level.toUpperCase());

// Slider id → Eyas settings prefix, as the dashboards read them.
const SLIDERS: Record<string, string> = {
  OnSensorMLSlider: "ml",
  CloudAntiMalware: "cloud_anti_malware",
  AdwarePUP: "adware",
};

function shapePolicy(p: Obj): PostureItem {
  const sliders = isObj(p.ml_sliders) ? p.ml_sliders : {};
  const settings: Record<string, string> = {};
  for (const [id, prefix] of Object.entries(SLIDERS)) {
    const s = sliders[id];
    if (!isObj(s)) continue;
    if (typeof s.detection === "string") settings[`${prefix}_detection`] = s.detection;
    if (typeof s.prevention === "string") settings[`${prefix}_prevention`] = s.prevention;
  }
  const enabled = p.enabled !== false;
  const flags: string[] = [];
  if (!enabled) flags.push("disabled");
  if (active(settings.ml_detection) && !active(settings.ml_prevention)) flags.push("ml_detect_only");
  if (active(settings.cloud_anti_malware_detection) && !active(settings.cloud_anti_malware_prevention)) {
    flags.push("cloud_av_detect_only");
  }
  return {
    id: typeof p.id === "string" ? p.id : null,
    name: typeof p.name === "string" ? p.name : null,
    platform: typeof p.platform === "string" && p.platform ? p.platform : "unknown",
    enabled,
    // falcon_get_prevention_posture doesn't carry descriptions; the pages
    // treat an empty one as absent.
    description: "",
    groups: (Array.isArray(p.groups) ? p.groups : [])
      .filter(isObj)
      .filter((g) => typeof g.id === "string")
      .map((g) => ({ id: g.id as string, name: typeof g.name === "string" ? g.name : null })),
    settings,
    flags,
  };
}

/** Native falcon_get_prevention_posture text → the Eyas posture payload. */
export function shapePosture(text: string): PosturePayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    if (isScopeDenied(text)) return { ok: true, scope_pending: true, items: [] };
    return { ok: false, error: text.trim().slice(0, 300) || "No response." };
  }
  const first = Array.isArray(parsed) ? parsed[0] : parsed;
  if (isObj(first) && typeof first.error === "string") {
    if (isScopeDenied(JSON.stringify(first))) return { ok: true, scope_pending: true, items: [] };
    return { ok: false, error: detectFalconError([first]) ?? first.error };
  }
  if (!isObj(first) || !Array.isArray(first.policies)) return { ok: false, error: "Unexpected response." };

  const items = first.policies.filter(isObj).map(shapePolicy);
  // Worst posture first within a platform: disabled, then by name.
  items.sort(
    (a, b) =>
      a.platform.localeCompare(b.platform) ||
      Number(a.enabled) - Number(b.enabled) ||
      (a.name ?? "").localeCompare(b.name ?? ""),
  );
  const platform_counts: Record<string, number> = {};
  for (const it of items) platform_counts[it.platform] = (platform_counts[it.platform] ?? 0) + 1;
  return {
    ok: true,
    items,
    count: items.length,
    platform_counts,
    summary: {
      total: items.length,
      disabled: items.filter((i) => i.flags.includes("disabled")).length,
      detect_only: items.filter((i) => i.flags.some((f) => f.endsWith("_detect_only"))).length,
    },
    ...(typeof first.warning === "string" ? { warning: first.warning } : {}),
  };
}

/** Read the tenant's prevention posture from eyas-mcp. Never throws. */
export async function fetchPreventionPosture(mcp: Client): Promise<PosturePayload> {
  try {
    const r = await mcp.callTool({ name: "falcon_get_prevention_posture", arguments: {} });
    const content = ((r as { content?: unknown }).content ?? []) as Array<{ type: string; text?: string }>;
    return shapePosture(content.map((c) => (c.type === "text" && c.text ? c.text : "")).join("\n"));
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
