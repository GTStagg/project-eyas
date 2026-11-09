// Recon corpus preview: the underground-footprint aggregate for a subject.
//
// falcon_preview_recon_rule estimates how many notifications a prospective
// monitoring rule would raise, which doubles as a corpus-wide mention count.
// It returns a list of named aggregations ({name: "count" | "channel" |
// "site", buckets: [{label, count}]}); summarizeReconPreview flattens that into
// the {total_hits, channels, top_sites} shape the dossier bundle carries.

export type ReconPreviewKind = "domain" | "email" | "ip" | "keyword";

export type ReconPreviewSummary = {
  total_hits: number;
  channels: Array<{ label: string; count: number }>;
  top_sites: Array<{ label: string; count: number }>;
};

const TOPIC: Record<ReconPreviewKind, string> = {
  domain: "SA_DOMAIN",
  email: "SA_EMAIL",
  ip: "SA_IP",
  keyword: "SA_CUSTOM",
};

// Values are interpolated into a rule-filter literal, so they are
// reject-validated, never escaped: no quote or backslash can get through.
const VALUE_RX: Record<ReconPreviewKind, RegExp> = {
  domain: /^[a-z0-9][a-z0-9.-]{0,253}$/,
  email: /^[a-z0-9._%+-]+@[a-z0-9.-]+$/,
  ip: /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/,
  keyword: /^[A-Za-z0-9 ._%+@:/-]{1,200}$/,
};

/** Arguments for falcon_preview_recon_rule, or null when the value is rejected. */
export function reconPreviewArgs(
  value: string,
  kind: ReconPreviewKind,
): { topic: string; filter: string } | null {
  const v = kind === "domain" || kind === "email" ? value.trim().toLowerCase() : value.trim();
  if (!VALUE_RX[kind].test(v)) return null;
  return { topic: TOPIC[kind], filter: `(${kind}:'${v}')` };
}

function buckets(entry: Record<string, unknown>): Array<{ label: string; count: number }> {
  const raw = Array.isArray(entry.buckets) ? (entry.buckets as Array<Record<string, unknown>>) : [];
  return raw
    .map((b) => ({ label: String(b.label ?? ""), count: Number(b.count) || 0 }))
    .filter((b) => b.label);
}

/** Flatten the preview aggregations. Unknown aggregation names are ignored. */
export function summarizeReconPreview(rows: unknown[]): ReconPreviewSummary {
  const out: ReconPreviewSummary = { total_hits: 0, channels: [], top_sites: [] };
  // A list result may arrive as one block per aggregation or as one JSON array.
  for (const row of rows.flat()) {
    if (!row || typeof row !== "object") continue;
    const entry = row as Record<string, unknown>;
    if (entry.name === "count") {
      const first = Array.isArray(entry.buckets) ? (entry.buckets[0] as Record<string, unknown>) : undefined;
      out.total_hits = Number(first?.count) || 0;
    } else if (entry.name === "channel") {
      out.channels = buckets(entry);
    } else if (entry.name === "site") {
      out.top_sites = buckets(entry);
    }
  }
  return out;
}
