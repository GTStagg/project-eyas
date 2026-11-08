// Deterministic enrichment for the /data-protection surface. Pure functions.
// falcon-mcp's Data Security module (renamed from dataprotection in 0.20.0) —
// falcon_search_data_security_entities returns FalconPy
// entities_policy/classification/content_pattern records pass-through. The
// FQL-documented fields (name, is_enabled, is_default, precedence, description
// for policies; name/category/region/type for content patterns) are
// authoritative; the full GetByIds entity schema (host-group + classification
// assignments, regex bodies) isn't enumerated upstream, so extractors stay
// tolerant and the surface reasons over what's reliably present.

export interface DpPolicy {
  name?: string;
  platform: string; // "win" | "mac" — attached at fetch time
  isEnabled: boolean;
  isDefault: boolean;
  precedence?: number;
  description?: string;
}

export interface DpContentPattern {
  name?: string;
  category?: string; // Custom | Financial | PII | Healthcare
  region?: string; // ALL | US | EU
  type?: string; // custom | predefined
}

export interface DpPosture {
  policies: DpPolicy[];
  policyCounts: { total: number; enabled: number; disabled: number; enabledNonDefault: number };
  classificationCount: number;
  classifications: string[]; // names (bounded)
  contentPatternCount: number;
  patternsByCategory: Record<string, number>;
  patternsByRegion: Record<string, number>;
}

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v.trim() ? v.trim() : undefined;
const bool = (v: unknown): boolean => v === true || v === "true" || v === 1;

function firstKey(r: Record<string, unknown>, keys: string[]): unknown {
  for (const k of keys) if (k in r && r[k] != null) return r[k];
  return undefined;
}

export function normalizePolicies(raw: unknown[], platform: string): DpPolicy[] {
  const out: DpPolicy[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const r = item as Record<string, unknown>;
    const precRaw = firstKey(r, ["precedence"]);
    out.push({
      name: str(firstKey(r, ["name"])),
      platform,
      isEnabled: bool(firstKey(r, ["is_enabled", "enabled"])),
      isDefault: bool(firstKey(r, ["is_default", "default"])),
      precedence: typeof precRaw === "number" ? precRaw : Number(precRaw) || undefined,
      description: str(firstKey(r, ["description"])),
    });
  }
  return out;
}

export function normalizeContentPatterns(raw: unknown[]): DpContentPattern[] {
  const out: DpContentPattern[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const r = item as Record<string, unknown>;
    out.push({
      name: str(firstKey(r, ["name"])),
      category: str(firstKey(r, ["category"])),
      region: str(firstKey(r, ["region"])),
      type: str(firstKey(r, ["type"])),
    });
  }
  return out;
}

export function classificationNames(raw: unknown[]): string[] {
  const out: string[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const n = str(firstKey(item as Record<string, unknown>, ["name"]));
    if (n) out.push(n);
  }
  return out;
}

function tally(values: (string | undefined)[]): Record<string, number> {
  const m: Record<string, number> = {};
  for (const v of values) {
    const key = v ?? "unspecified";
    m[key] = (m[key] ?? 0) + 1;
  }
  return m;
}

export function summarizeDataProtection(
  policies: DpPolicy[],
  classifications: string[],
  patterns: DpContentPattern[],
): DpPosture {
  const enabled = policies.filter((p) => p.isEnabled);
  return {
    policies,
    policyCounts: {
      total: policies.length,
      enabled: enabled.length,
      disabled: policies.length - enabled.length,
      enabledNonDefault: enabled.filter((p) => !p.isDefault).length,
    },
    classificationCount: classifications.length,
    classifications: classifications.slice(0, 40),
    contentPatternCount: patterns.length,
    patternsByCategory: tally(patterns.map((p) => p.category)),
    patternsByRegion: tally(patterns.map((p) => p.region)),
  };
}

export function renderDataProtectionContext(p: DpPosture): string {
  const lines: string[] = [
    "# Deterministic Data Protection configuration summary (computed server-side)",
    `Policies: ${p.policyCounts.total} total — ${p.policyCounts.enabled} enabled (${p.policyCounts.enabledNonDefault} non-default), ${p.policyCounts.disabled} disabled.`,
    `Classifications defined: ${p.classificationCount}. Content patterns: ${p.contentPatternCount}.`,
    `Patterns by category: ${JSON.stringify(p.patternsByCategory)}.`,
    `Patterns by region: ${JSON.stringify(p.patternsByRegion)}.`,
  ];
  if (p.policies.length) {
    lines.push("", "Policies (platform · name · enabled · default · precedence):");
    for (const pol of p.policies.slice(0, 30)) {
      lines.push(
        `- ${pol.platform} · ${pol.name ?? "?"} · ${pol.isEnabled ? "enabled" : "disabled"} · ${pol.isDefault ? "default" : "custom"} · prec ${pol.precedence ?? "?"}`,
      );
    }
  }
  return lines.join("\n");
}
