import type { Detection } from "@/components/DetectionsTable";

export type QueueSource = "epp" | "idp";

export type IdentityOverlap = {
  identity_resolved: boolean;
  last_login_user?: string;
  primary_display_name?: string;
  risk_score?: number;
  risk_score_severity?: string;
  risk_factors?: Array<{ type: string; severity: string }>;
  idp_detection_count: number;
};

export type QueueRow = Detection & {
  source: QueueSource;
  contained: boolean;
  score: number;
  bucket: "top" | "active" | "stale";
  reasons: string[];
  age_hours: number;
  // IDP-specific fields populated only when source === "idp". Endpoint rows
  // leave these undefined.
  idp_user_name?: string;
  idp_source_account?: string;
  idp_source_endpoint?: string;
  // Set on endpoint rows in the `top` bucket after server-side enrichment
  // via falcon_correlate_host_identity. Cross-module priority signal —
  // when present and identity_resolved is true, the host's last-logged-in
  // user has IDP risk and/or open IDP detections.
  identity_overlap?: IdentityOverlap;
};

// Input for ranking — accepts a Detection plus a source discriminator. IDP
// callers normalize their raw rows to this shape before passing in.
export type RankInput = Detection & { source: QueueSource };

const STALE_HOURS = 24 * 7;
const TOP_SCORE_CUTOFF = 15;

function recencyWeight(ageHours: number): number {
  if (ageHours < 1) return 6;
  if (ageHours < 6) return 5;
  if (ageHours < 24) return 4;
  if (ageHours < 72) return 3;
  if (ageHours < STALE_HOURS) return 2;
  return 1;
}

export function rankDetections(
  detections: RankInput[],
  containedAids: Set<string>,
  now: number = Date.now(),
): QueueRow[] {
  const hostCounts = new Map<string, number>();
  for (const d of detections) {
    const host = d.device?.hostname;
    if (host) hostCounts.set(host, (hostCounts.get(host) ?? 0) + 1);
  }

  const rows: QueueRow[] = detections.map((d) => {
    const created = d.created_timestamp
      ? new Date(d.created_timestamp).getTime()
      : now;
    const ageHours = Math.max(0, (now - created) / 3_600_000);
    const sev = d.severity ?? 0;
    const hostname = d.device?.hostname ?? "";
    const aid =
      (d as { device?: { device_id?: string } }).device?.device_id ?? "";
    // Containment overlay only meaningful for endpoint rows — IDP detections
    // aren't host-AID based, so contained stays false.
    const contained =
      d.source === "epp" && aid ? containedAids.has(aid) : false;

    const sevWeight = sev / 10;
    const recency = recencyWeight(ageHours);
    const concentration = Math.min(
      5,
      Math.max(0, (hostCounts.get(hostname) ?? 1) - 1),
    );
    const uncontainedCritBonus =
      d.source === "epp" && sev >= 80 && !contained ? 5 : 0;
    const statusBonus =
      d.status === "new" || d.status === "reopened"
        ? 2
        : d.status === "in_progress"
          ? 0
          : 0;

    const score =
      sevWeight + recency + concentration + uncontainedCritBonus + statusBonus;

    const reasons: string[] = [];
    if (d.source === "idp") reasons.push("identity threat");
    if (sev >= 80)
      reasons.push(contained ? "critical (contained)" : "critical, uncontained");
    else if (sev >= 70) reasons.push("high severity");
    if (concentration > 0)
      reasons.push(`${concentration + 1} detections on this host`);
    if (recency >= 5) reasons.push("very recent");
    else if (recency >= 4) reasons.push("recent");
    if (d.status === "new") reasons.push("new (not yet triaged)");
    else if (d.status === "reopened") reasons.push("reopened");
    else if (d.status === "in_progress") reasons.push("in progress");

    let bucket: QueueRow["bucket"];
    if (ageHours >= STALE_HOURS) bucket = "stale";
    else if (score >= TOP_SCORE_CUTOFF) bucket = "top";
    else bucket = "active";

    return {
      ...d,
      contained,
      score,
      bucket,
      reasons,
      age_hours: ageHours,
    };
  });

  rows.sort((a, b) => b.score - a.score);
  return rows;
}
