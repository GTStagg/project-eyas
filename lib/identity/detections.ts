// Identity Protection detections, read through the native detection search
// with Eyas's rules applied on top (they replaced the sidecar's
// extras_identity_detections):
//   - open only (new / reopened / in_progress) unless includeClosed;
//   - "Policy rule match" enforcement rows dropped unless includePolicyMatches.
//     Those are sensor-side enforcement firings with an empty `tactic`, not
//     attack patterns, and they drown real threats in lab tenants.
// Pure: no I/O, so scripts/test-identity-detections.mjs can cover it.

export type IdentityDetection = {
  composite_id?: string;
  id?: string;
  severity?: number;
  severity_name?: string;
  display_name?: string;
  description?: string;
  created_timestamp?: string;
  status?: string;
  tactic?: string;
  technique?: string;
  user_name?: string;
  source_account_name?: string;
  source_account_domain?: string;
  destination_account_name?: string;
  source_endpoint_host_name?: string;
  destination_endpoint_host_name?: string;
  falcon_host_link?: string;
};

export type IdentityDetectionOptions = {
  hours?: number;
  limit?: number;
  includePolicyMatches?: boolean;
  includeClosed?: boolean;
};

const FIELDS: (keyof IdentityDetection)[] = [
  "composite_id",
  "id",
  "severity",
  "severity_name",
  "display_name",
  "description",
  "created_timestamp",
  "status",
  "tactic",
  "technique",
  "user_name",
  "source_account_name",
  "source_account_domain",
  "destination_account_name",
  "source_endpoint_host_name",
  "destination_endpoint_host_name",
  "falcon_host_link",
];

/** Arguments for falcon_search_detections. `now` is injectable for tests. */
export function identityDetectionSearchArgs(
  opts: IdentityDetectionOptions = {},
  now: Date = new Date(),
): { filter: string; limit: number; sort: string } {
  const hours = Math.max(1, Math.floor(opts.hours ?? 168));
  const limit = Math.min(Math.max(Math.floor(opts.limit ?? 50), 1), 500);
  const cutoff = new Date(now.getTime() - hours * 3_600_000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
  let filter = `product:'idp'+created_timestamp:>'${cutoff}'`;
  if (!opts.includeClosed) filter += "+status:['new','reopened','in_progress']";
  return { filter, limit, sort: "created_timestamp.desc" };
}

/** Drop policy-match rows (unless asked for) and keep the fields the identity
 *  surfaces read. Full alert records are large and noisy. */
export function shapeIdentityDetections(
  rows: unknown[],
  opts: IdentityDetectionOptions = {},
): IdentityDetection[] {
  const out: IdentityDetection[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object" || Array.isArray(row)) continue;
    const r = row as Record<string, unknown>;
    const tactic = typeof r.tactic === "string" ? r.tactic : "";
    if (!opts.includePolicyMatches && !tactic) continue;
    const item: Record<string, unknown> = {};
    for (const f of FIELDS) {
      if (r[f] !== undefined && r[f] !== null) item[f] = r[f];
    }
    item.tactic = tactic;
    out.push(item as IdentityDetection);
  }
  return out;
}
