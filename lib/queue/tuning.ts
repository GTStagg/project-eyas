// Detection-tuning analyzer. Pure function: a 30-day window of endpoint
// detections (open + closed, with `resolution` carrying TP/FP verdict on
// closed records) → ranked tuning candidates.
//
// Two signal types — same display_name, different evidence:
//
//   "fp_pattern" — rules with closure history showing a pattern. Closed-as-FP
//     rate ≥ 80% over ≥ 3 closed records, AND zero closed-as-TP. Strongest
//     signal because the operator already disposed of these as benign.
//
//   "queue_drown" — rules without closure history but firing a lot. Total
//     fires ≥ 10, ≥ 3 unique hosts, severity_max < 70 (low/medium only —
//     never recommend tuning a critical/high), 0 closed records. Weaker
//     signal but valuable on tenants that haven't built closure habits yet.
//
// We do NOT recommend on display_names with even one TP closure — that's a
// real detector that occasionally fires on real things; suppressing it
// would create a blind spot.
//
// Schema note: Falcon's Alerts v3 API returns `status` as the macro state
// ("new" / "closed" / "in_progress" / "reopened" / "ignored") and the
// TP/FP verdict separately under `resolution` ("true_positive" /
// "false_positive"). Initially looked at status alone; that's wrong.

import type { Detection } from "@/components/DetectionsTable";

export type TuningSignal = "fp_pattern" | "queue_drown";

export type TuningCandidate = {
  display_name: string;
  signal: TuningSignal;
  total_fires: number;
  fp_count: number;
  tp_count: number;
  open_count: number; // status:new + reopened
  in_progress_count: number;
  closed_other_count: number; // closed but no resolution / ignored
  fp_rate?: number; // 0..1 — only on fp_pattern
  unique_hosts: number;
  hostnames: string[];
  severity_max: number;
  severity_max_name?: string;
  earliest_ts?: string;
  latest_ts?: string;
  sample_composite_ids: string[];
  reasons: string[];
};

const SEV_NAME = (sev: number): string => {
  if (sev >= 90) return "Critical";
  if (sev >= 70) return "High";
  if (sev >= 50) return "Medium";
  if (sev >= 30) return "Low";
  return "Informational";
};

type DetectionWithVerdict = Detection & {
  status?: string;
  resolution?: string;
  composite_id?: string;
};

const FP_MIN_CLOSED = 3;
const FP_MIN_HOSTS = 2;
const FP_RATE_THRESHOLD = 0.8;

const QD_MIN_FIRES = 10;
const QD_MIN_HOSTS = 3;
const QD_MAX_SEVERITY = 69; // exclude High (70+) / Critical (90+)

export function findTuningCandidates(
  detections: DetectionWithVerdict[],
): TuningCandidate[] {
  const groups = new Map<string, DetectionWithVerdict[]>();
  for (const d of detections) {
    const name = (d.display_name ?? "").trim();
    if (!name) continue;
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name)!.push(d);
  }

  const candidates: TuningCandidate[] = [];

  for (const [name, items] of groups) {
    let fp = 0;
    let tp = 0;
    let open = 0;
    let inProgress = 0;
    let closedOther = 0;
    let sevMax = 0;
    let earliest: string | undefined;
    let latest: string | undefined;
    const hostSet = new Set<string>();
    const hostnames: string[] = [];
    const sampleIds: string[] = [];

    for (const d of items) {
      const status = (d.status ?? "").toLowerCase();
      const resolution = (d.resolution ?? "").toLowerCase();
      if (resolution === "false_positive") fp += 1;
      else if (resolution === "true_positive") tp += 1;
      else if (status === "in_progress") inProgress += 1;
      else if (status === "closed" || status === "ignored") closedOther += 1;
      else open += 1; // new, reopened, anything else
      sevMax = Math.max(sevMax, d.severity ?? 0);
      const host = d.device?.hostname;
      if (host && !hostSet.has(host)) {
        hostSet.add(host);
        if (hostnames.length < 5) hostnames.push(host);
      }
      if (d.created_timestamp) {
        if (!earliest || d.created_timestamp < earliest) earliest = d.created_timestamp;
        if (!latest || d.created_timestamp > latest) latest = d.created_timestamp;
      }
      if (d.composite_id && sampleIds.length < 6) sampleIds.push(d.composite_id);
    }

    // Never recommend on detectors with TP closures — real detector firing
    // on real things, even if rare.
    if (tp > 0) continue;

    const closedTotal = fp + tp;
    const sevName = sevMax > 0 ? SEV_NAME(sevMax) : undefined;
    const baseReasons = [`${hostSet.size} unique hosts`];
    if (open > 0) baseReasons.push(`${open} still open`);
    if (sevName) baseReasons.push(`max severity ${sevName}`);

    // Signal 1: fp_pattern — closure history shows a pattern.
    if (closedTotal >= FP_MIN_CLOSED && hostSet.size >= FP_MIN_HOSTS) {
      const fpRate = fp / closedTotal;
      if (fpRate >= FP_RATE_THRESHOLD) {
        candidates.push({
          display_name: name,
          signal: "fp_pattern",
          total_fires: items.length,
          fp_count: fp,
          tp_count: tp,
          open_count: open,
          in_progress_count: inProgress,
          closed_other_count: closedOther,
          fp_rate: fpRate,
          unique_hosts: hostSet.size,
          hostnames,
          severity_max: sevMax,
          severity_max_name: sevName,
          earliest_ts: earliest,
          latest_ts: latest,
          sample_composite_ids: sampleIds,
          reasons: [
            `${fp}/${closedTotal} closed detections closed as FP (${Math.round(fpRate * 100)}%)`,
            ...baseReasons,
          ],
        });
        continue;
      }
    }

    // Signal 2: queue_drown — no closure history, but firing a lot at
    // low/medium severity. Pure volume signal; less authoritative than
    // fp_pattern but actionable.
    if (
      closedTotal === 0 &&
      items.length >= QD_MIN_FIRES &&
      hostSet.size >= QD_MIN_HOSTS &&
      sevMax <= QD_MAX_SEVERITY
    ) {
      candidates.push({
        display_name: name,
        signal: "queue_drown",
        total_fires: items.length,
        fp_count: fp,
        tp_count: tp,
        open_count: open,
        in_progress_count: inProgress,
        closed_other_count: closedOther,
        unique_hosts: hostSet.size,
        hostnames,
        severity_max: sevMax,
        severity_max_name: sevName,
        earliest_ts: earliest,
        latest_ts: latest,
        sample_composite_ids: sampleIds,
        reasons: [
          `${items.length} fires across ${hostSet.size} hosts in 30d, no operator closures`,
          `severity capped at ${sevName ?? "?"} — eligible for tuning`,
        ],
      });
    }
  }

  // Rank: highest noise first. Total fires desc, then host count desc.
  candidates.sort((a, b) => {
    if (b.total_fires !== a.total_fires) return b.total_fires - a.total_fires;
    return b.unique_hosts - a.unique_hosts;
  });
  return candidates;
}
