import type { QueueRow, RankInput } from "./rank";

// Cross-host campaign clustering. Pure function: detection set → campaigns
// where 2+ unique hosts share a load-bearing artifact. Artifact-based, NOT
// tactic-based — clustering by shared "Initial Access" tactic produces
// noise; clustering by shared SHA-256 produces signal. Three keys:
//
//   1. SHARED_BINARY  — same sha256 across ≥2 hosts. Strongest signal.
//   2. SHARED_COMMAND — same image filename + same MITRE technique across
//      ≥2 hosts. Catches process-injection / fileless campaigns where the
//      hash differs per stage but the dropper's image is consistent.
//   3. LATERAL_MOVEMENT — same user_name across ≥2 hosts where AT LEAST
//      ONE detection carries a Lateral Movement tactic. Catches credential-
//      replay / Kerberoast / pass-the-hash patterns.
//
// Dedup discipline: detections in a SHARED_BINARY cluster are NOT eligible
// for SHARED_COMMAND or LATERAL_MOVEMENT clusters — sha256 wins on overlap.

export type CampaignType = "shared_binary" | "shared_command" | "lateral_movement";

export type CampaignHost = {
  aid?: string;
  hostname: string;
  contained: boolean;
};

export type Campaign = {
  id: string;
  type: CampaignType;
  shared_artifact: string;
  artifact_label: string;
  hosts: CampaignHost[];
  host_count: number;
  detection_count: number;
  composite_ids: string[];
  earliest_ts?: string;
  latest_ts?: string;
  severity_max: number;
  severity_max_name?: string;
  uncontained_count: number;
  techniques: string[];
  reasons: string[];
};

const SEV_NAME = (sev: number): string => {
  if (sev >= 90) return "Critical";
  if (sev >= 70) return "High";
  if (sev >= 50) return "Medium";
  if (sev >= 30) return "Low";
  return "Informational";
};

const isLateral = (det: RankInput): boolean => {
  const tactic = (det.tactic ?? "").toLowerCase();
  const technique = (det.technique ?? "").toLowerCase();
  return (
    tactic.includes("lateral") ||
    technique.includes("lateral") ||
    technique.includes("remote services") ||
    technique.includes("pass the") ||
    technique.includes("kerberoast")
  );
};

// Stable id from artifact + type so the same campaign keeps its id across
// re-fetches. Truncated SHA-1-style hash for compactness.
function campaignId(type: CampaignType, artifact: string): string {
  let h = 0;
  for (let i = 0; i < artifact.length; i++) {
    h = (h * 31 + artifact.charCodeAt(i)) | 0;
  }
  return `${type}-${(h >>> 0).toString(36)}`;
}

function buildCampaign(
  type: CampaignType,
  artifact: string,
  artifactLabel: string,
  members: RankInput[],
  containedAids: Set<string>,
): Campaign | null {
  const hostMap = new Map<string, CampaignHost>();
  const techniqueSet = new Set<string>();
  const compositeIds: string[] = [];
  let sevMax = 0;
  let earliest: string | undefined;
  let latest: string | undefined;

  for (const m of members) {
    const aid = m.device?.device_id;
    const hostname = m.device?.hostname;
    if (!hostname) continue;
    const key = aid ?? hostname;
    if (!hostMap.has(key)) {
      hostMap.set(key, {
        aid,
        hostname,
        contained: aid ? containedAids.has(aid) : false,
      });
    }
    if (m.composite_id) compositeIds.push(m.composite_id);
    if (m.technique) techniqueSet.add(m.technique);
    sevMax = Math.max(sevMax, m.severity ?? 0);
    if (m.created_timestamp) {
      if (!earliest || m.created_timestamp < earliest) earliest = m.created_timestamp;
      if (!latest || m.created_timestamp > latest) latest = m.created_timestamp;
    }
  }

  if (hostMap.size < 2) return null;

  const hosts = [...hostMap.values()];
  const uncontained = hosts.filter((h) => !h.contained).length;

  const reasons: string[] = [];
  if (type === "shared_binary") reasons.push(`same SHA-256 on ${hosts.length} hosts`);
  if (type === "shared_command")
    reasons.push(`same image + technique on ${hosts.length} hosts`);
  if (type === "lateral_movement")
    reasons.push(`same user across ${hosts.length} hosts, lateral movement signal`);
  if (sevMax >= 80) reasons.push(uncontained > 0 ? "critical, uncontained hosts present" : "critical (contained)");
  else if (sevMax >= 70) reasons.push("high severity");
  if (uncontained === hosts.length) reasons.push("no host contained");

  return {
    id: campaignId(type, artifact),
    type,
    shared_artifact: artifact,
    artifact_label: artifactLabel,
    hosts,
    host_count: hosts.length,
    detection_count: members.length,
    composite_ids: compositeIds,
    earliest_ts: earliest,
    latest_ts: latest,
    severity_max: sevMax,
    severity_max_name: sevMax > 0 ? SEV_NAME(sevMax) : undefined,
    uncontained_count: uncontained,
    techniques: [...techniqueSet],
    reasons,
  };
}

export function clusterCampaigns(
  detections: RankInput[],
  containedAids: Set<string>,
): Campaign[] {
  // Endpoint detections only — IDP rows have no AID and clustering across
  // them needs identity-specific signals (not what this clusterer is for).
  const epp = detections.filter((d) => d.source === "epp");

  const claimed = new Set<string>(); // composite_ids consumed by SHARED_BINARY

  // Pass 1 — SHARED_BINARY by sha256.
  const bySha = new Map<string, RankInput[]>();
  for (const d of epp) {
    const sha = d.sha256;
    if (!sha || sha.length < 32) continue;
    if (!bySha.has(sha)) bySha.set(sha, []);
    bySha.get(sha)!.push(d);
  }
  const sharedBinary: Campaign[] = [];
  for (const [sha, members] of bySha) {
    const c = buildCampaign(
      "shared_binary",
      sha,
      `${sha.slice(0, 12)}…${sha.slice(-4)}`,
      members,
      containedAids,
    );
    if (!c) continue;
    sharedBinary.push(c);
    for (const id of c.composite_ids) claimed.add(id);
  }

  // Pass 2 — SHARED_COMMAND by filename + technique. Skip detections already
  // in a SHARED_BINARY cluster.
  const byCmd = new Map<string, RankInput[]>();
  for (const d of epp) {
    if (d.composite_id && claimed.has(d.composite_id)) continue;
    const fn = (d.filename ?? "").toLowerCase();
    const tech = d.technique ?? "";
    if (!fn || !tech) continue;
    const key = `${fn}|${tech}`;
    if (!byCmd.has(key)) byCmd.set(key, []);
    byCmd.get(key)!.push(d);
  }
  const sharedCommand: Campaign[] = [];
  for (const [key, members] of byCmd) {
    const [fn, tech] = key.split("|");
    const c = buildCampaign(
      "shared_command",
      key,
      `${fn} · ${tech}`,
      members,
      containedAids,
    );
    if (!c) continue;
    sharedCommand.push(c);
    for (const id of c.composite_ids) claimed.add(id);
  }

  // Pass 3 — LATERAL_MOVEMENT by user_name across hosts, when at least one
  // detection in the cluster carries a Lateral Movement tactic/technique.
  const byUser = new Map<string, RankInput[]>();
  for (const d of epp) {
    if (d.composite_id && claimed.has(d.composite_id)) continue;
    const user = (d.user_name ?? "").toLowerCase();
    if (!user) continue;
    if (!byUser.has(user)) byUser.set(user, []);
    byUser.get(user)!.push(d);
  }
  const lateral: Campaign[] = [];
  for (const [user, members] of byUser) {
    if (!members.some(isLateral)) continue;
    const c = buildCampaign(
      "lateral_movement",
      user,
      user,
      members,
      containedAids,
    );
    if (c) lateral.push(c);
  }

  return [...sharedBinary, ...sharedCommand, ...lateral].sort((a, b) => {
    if (b.severity_max !== a.severity_max) return b.severity_max - a.severity_max;
    if (b.host_count !== a.host_count) return b.host_count - a.host_count;
    return b.detection_count - a.detection_count;
  });
}

// Reconstruct hand-off primer for a campaign. Pure (no React) so both the
// client CampaignsPanel and server-side dashboard summary build the identical
// instruction — matched by the `Reconstruct the cross-host campaign` template
// in components/primer.ts.
export function reconstructPrimer(c: Campaign): string {
  const hosts = c.hosts.map((h) => h.hostname).join(", ");
  const aids = c.hosts
    .map((h) => h.aid)
    .filter((x): x is string => Boolean(x))
    .join('", "');
  const cidPreview = c.composite_ids.slice(0, 6).join('", "');
  const cidNote =
    c.composite_ids.length > 6 ? ` (and ${c.composite_ids.length - 6} more)` : "";

  const artifactClause =
    c.type === "shared_binary"
      ? `the binary SHA-256 \`${c.shared_artifact}\``
      : c.type === "shared_command"
        ? `the command pattern \`${c.artifact_label}\``
        : `the user \`${c.artifact_label}\` (lateral movement signal)`;

  return [
    `Reconstruct the cross-host campaign anchored on ${artifactClause}.`,
    `Affected hosts: ${hosts}.`,
    aids ? `AIDs: ["${aids}"].` : "(no AIDs available; hostnames only)",
    `Lead composite_ids: ["${cidPreview}"]${cidNote}.`,
  ].join(" ");
}

// Re-export for routes that need both QueueRow and Campaign together.
export type { QueueRow };
