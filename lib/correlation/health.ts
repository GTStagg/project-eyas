// Deterministic enrichment for the /correlation surface. Pure functions —
// staleness takes `now` as a parameter so it stays testable. falcon-mcp 0.11.0's
// correlationrules module returns FalconPy combined_rules_get_v2 records
// pass-through; the FQL-documented fields (status, state, severity, type,
// mitre_attack.*, last_updated_on) are authoritative. The id field is referenced
// as `rule_id` in docstrings but write bodies use `id` — we read both. 0.11.0
// shipped a same-release field-alignment fix (#407), so every extractor is
// tolerant and degrades to a safe default rather than throwing.

export interface CorrelationRule {
  id?: string;
  name?: string;
  status?: string; // active | inactive (execution state)
  state?: string; // published | unpublished | draft (version lifecycle)
  severity: number; // 10/30/50/70/90, 0 if unknown
  type?: string; // correlation | behavioral
  tactics: string[];
  techniques: string[];
  lastUpdated?: string;
  description?: string;
}

export interface CorrelationHealth {
  total: number;
  byStatus: { active: number; inactive: number };
  bySeverity: { critical: number; high: number; medium: number; low: number; informational: number };
  /** Distinct MITRE ATT&CK tactic + technique ids covered by published rules. */
  mitre: { tactics: string[]; techniques: string[] };
  /** Active rules not updated within the staleness window, oldest first. */
  stale: { id?: string; name?: string; lastUpdated?: string; ageDays: number }[];
  /** Inactive rules — present but not executing. */
  inactive: { id?: string; name?: string; severity: number }[];
  rules: CorrelationRule[];
}

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v.trim() ? v.trim() : undefined;

function firstKey(r: Record<string, unknown>, keys: string[]): unknown {
  for (const k of keys) if (k in r && r[k] != null) return r[k];
  return undefined;
}

// mitre_attack is an array of { tactic_id, technique_id } (key names per the FQL
// guide). Tolerant of flat string arrays too.
function mitrePairs(v: unknown): { tactics: string[]; techniques: string[] } {
  const tactics: string[] = [];
  const techniques: string[] = [];
  if (Array.isArray(v)) {
    for (const item of v) {
      if (item && typeof item === "object") {
        const t = str(firstKey(item as Record<string, unknown>, ["tactic_id", "tactic"]));
        const k = str(firstKey(item as Record<string, unknown>, ["technique_id", "technique"]));
        if (t) tactics.push(t);
        if (k) techniques.push(k);
      } else if (typeof item === "string" && item.trim()) {
        techniques.push(item.trim());
      }
    }
  }
  return { tactics, techniques };
}

export function normalizeCorrelationRules(raw: unknown[]): CorrelationRule[] {
  const out: CorrelationRule[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const r = item as Record<string, unknown>;
    const sevRaw = firstKey(r, ["severity"]);
    const severity = typeof sevRaw === "number" ? sevRaw : Number(sevRaw) || 0;
    const m = mitrePairs(firstKey(r, ["mitre_attack", "mitre"]));
    out.push({
      id: str(firstKey(r, ["rule_id", "id"])),
      name: str(firstKey(r, ["name"])),
      status: str(firstKey(r, ["status"])),
      state: str(firstKey(r, ["state"])),
      severity,
      type: str(firstKey(r, ["type"])),
      tactics: m.tactics,
      techniques: m.techniques,
      lastUpdated: str(firstKey(r, ["last_updated_on", "updated_on", "created_on"])),
      description: str(firstKey(r, ["description"])),
    });
  }
  return out;
}

function severityBucket(sev: number): keyof CorrelationHealth["bySeverity"] {
  if (sev >= 90) return "critical";
  if (sev >= 70) return "high";
  if (sev >= 50) return "medium";
  if (sev >= 30) return "low";
  return "informational";
}

const STALE_DAYS = 180;

export function summarizeCorrelation(rules: CorrelationRule[], now: number): CorrelationHealth {
  const byStatus = { active: 0, inactive: 0 };
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  const tactics = new Set<string>();
  const techniques = new Set<string>();
  const stale: CorrelationHealth["stale"] = [];
  const inactive: CorrelationHealth["inactive"] = [];

  for (const r of rules) {
    const isActive = (r.status ?? "").toLowerCase() === "active";
    if (isActive) byStatus.active++;
    else byStatus.inactive++;
    if (!isActive) inactive.push({ id: r.id, name: r.name, severity: r.severity });

    bySeverity[severityBucket(r.severity)]++;
    for (const t of r.tactics) tactics.add(t);
    for (const k of r.techniques) techniques.add(k);

    if (isActive && r.lastUpdated) {
      const ts = Date.parse(r.lastUpdated);
      if (Number.isFinite(ts)) {
        const ageDays = Math.floor((now - ts) / 86_400_000);
        if (ageDays >= STALE_DAYS) {
          stale.push({ id: r.id, name: r.name, lastUpdated: r.lastUpdated, ageDays });
        }
      }
    }
  }

  stale.sort((a, b) => b.ageDays - a.ageDays);
  inactive.sort((a, b) => b.severity - a.severity);

  return {
    total: rules.length,
    byStatus,
    bySeverity,
    mitre: { tactics: [...tactics], techniques: [...techniques] },
    stale,
    inactive,
    rules,
  };
}

export function renderCorrelationContext(h: CorrelationHealth): string {
  const lines: string[] = [
    "# Deterministic correlation-rule summary (computed server-side, published rules only)",
    `Total published rules: ${h.total} — active ${h.byStatus.active}, inactive ${h.byStatus.inactive}.`,
    `Severity spread: critical ${h.bySeverity.critical}, high ${h.bySeverity.high}, medium ${h.bySeverity.medium}, low ${h.bySeverity.low}, informational ${h.bySeverity.informational}.`,
    `MITRE coverage: ${h.mitre.tactics.length} distinct tactics, ${h.mitre.techniques.length} distinct techniques.`,
    `Tactics covered: ${h.mitre.tactics.slice(0, 30).join(", ") || "none"}.`,
  ];
  if (h.stale.length) {
    lines.push("", `Stale active rules (>${STALE_DAYS}d since update):`);
    for (const s of h.stale.slice(0, 15)) {
      lines.push(`- ${s.name ?? s.id ?? "?"} — ${s.ageDays}d old (id ${s.id ?? "?"})`);
    }
  }
  if (h.inactive.length) {
    lines.push("", "Inactive rules (present but not executing):");
    for (const r of h.inactive.slice(0, 15)) {
      lines.push(`- ${r.name ?? r.id ?? "?"} — severity ${r.severity} (id ${r.id ?? "?"})`);
    }
  }
  return lines.join("\n");
}
