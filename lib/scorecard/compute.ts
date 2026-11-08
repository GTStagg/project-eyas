import "server-only";
import { rawDb } from "@/lib/db/client";
import { listRecords } from "@/lib/chat/ir-run-record";
import { computePostureTrend, type MetricTrend } from "@/lib/posture/trend";
import {
  emptyActivity,
  emptyOperations,
  emptyPosture,
  type ActivityMetrics,
  type ActivitySurface,
  type OperationsMetrics,
  type PostureDigest,
  type PostureHeadline,
  type Scorecard,
} from "./types";

// Deterministic aggregation for the agentic-SOC scorecard. Pure local-DB reads
// (no LLM, no upstream Falcon calls), so the page is fast and reliable.
//
// Everything here is scoped to a single environment. Environments are separate
// tenants with their own metrics, so the scorecard never blends them: operations
// read ir_runs filtered by env_id, activity reads cost_log filtered by env_id,
// and posture reads the per-env posture_snapshots trend. Rows written before
// env attribution existed (env_id NULL) simply don't match and are excluded —
// honest under-count beats cross-tenant contamination.

const DAY_MS = 86_400_000;
const DEFAULT_WINDOW_DAYS = 30;

function clampDays(d: number): number {
  if (!Number.isFinite(d)) return DEFAULT_WINDOW_DAYS;
  return Math.min(365, Math.max(1, Math.floor(d)));
}

function median(sorted: number[]): number {
  const n = sorted.length;
  const mid = Math.floor(n / 2);
  return n % 2 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
}

// Engagements run from this console for ONE environment, current window vs the
// immediately-preceding window of equal length. Close-duration is a proxy:
// lastTouched − startedAt (an engagement is "closed" when its last turn lands;
// there is no separate explicit close event, so an abandoned run inflates its
// own duration). Detections-resolved and the action tallies come from the
// structured counts captured at tool-result time (ir-run-record.ts) — records
// written before those fields existed contribute 0 for that engagement.
async function computeOperations(
  envId: string,
  now: number,
  windowStart: number,
  priorStart: number,
): Promise<OperationsMetrics> {
  const records = await listRecords(envId);
  if (records.length === 0) return emptyOperations();

  const inWindow = records.filter((r) => r.lastTouched >= windowStart && r.lastTouched <= now);
  const inPrior = records.filter(
    (r) => r.lastTouched >= priorStart && r.lastTouched < windowStart,
  );

  const closeDurations: number[] = [];
  let detectionsResolved = 0;
  let turns = 0;
  let iterations = 0;
  let erroredEngagements = 0;
  const actions = { reviewed: 0, allowed: 0, declined: 0, expired: 0 };

  for (const r of inWindow) {
    const dur = r.lastTouched - r.startedAt;
    if (dur >= 0) closeDurations.push(dur);
    let errored = false;
    for (const t of r.turns) {
      turns += 1;
      iterations += t.iterations ?? 0;
      if (t.status === "errored") errored = true;
      for (const c of t.toolCalls) {
        if (c.result?.isError) errored = true;
        if (c.approval !== "none") {
          actions.reviewed += 1;
          if (c.approval === "allow") actions.allowed += 1;
          else if (c.approval === "deny") actions.declined += 1;
          else if (c.approval === "timeout") actions.expired += 1;
        }
        const m = c.result?.metrics;
        if (m) detectionsResolved += (m.closedCount ?? 0) + (m.updatedCount ?? 0);
      }
    }
    if (errored) erroredEngagements += 1;
  }

  let detectionsResolvedPrev = 0;
  for (const r of inPrior) {
    for (const t of r.turns) {
      for (const c of t.toolCalls) {
        const m = c.result?.metrics;
        if (m) detectionsResolvedPrev += (m.closedCount ?? 0) + (m.updatedCount ?? 0);
      }
    }
  }

  closeDurations.sort((a, b) => a - b);
  const medianCloseMs = closeDurations.length ? median(closeDurations) : null;
  const meanCloseMs = closeDurations.length
    ? Math.round(closeDurations.reduce((acc, d) => acc + d, 0) / closeDurations.length)
    : null;

  return {
    engagements: inWindow.length,
    engagementsPrev: inPrior.length,
    medianCloseMs,
    meanCloseMs,
    detectionsResolved,
    detectionsResolvedPrev,
    actions,
    turns,
    iterations,
    erroredEngagements,
  };
}

type ActivityRow = { surface: string; runs: number; iters: number | null };

// Breadth of agentic work for ONE environment, from cost_log. Mirrors the
// summarizeCost GROUP BY pattern but bounded to the window and the env (indexed
// by cost_log_env_ts_idx). ts is stored as ISO-8601 text, so a lexicographic
// `ts >= <iso>` compare is chronologically correct.
function computeActivity(
  envId: string,
  windowStart: number,
  priorStart: number,
): ActivityMetrics {
  const windowStartIso = new Date(windowStart).toISOString();
  const priorStartIso = new Date(priorStart).toISOString();
  try {
    const rows = rawDb()
      .prepare(
        `SELECT surface, COUNT(*) AS runs, SUM(COALESCE(iterations, 0)) AS iters
           FROM cost_log
          WHERE env_id = ? AND ts >= ?
          GROUP BY surface`,
      )
      .all(envId, windowStartIso) as ActivityRow[];

    const prior = rawDb()
      .prepare(
        `SELECT COUNT(*) AS runs
           FROM cost_log
          WHERE env_id = ? AND ts >= ? AND ts < ?`,
      )
      .get(envId, priorStartIso, windowStartIso) as { runs: number } | undefined;

    let totalRuns = 0;
    let iterations = 0;
    const bySurface: ActivitySurface[] = [];
    for (const r of rows) {
      totalRuns += r.runs;
      iterations += r.iters ?? 0;
      bySurface.push({ surface: r.surface, runs: r.runs });
    }
    bySurface.sort((a, b) => b.runs - a.runs);

    return { totalRuns, totalRunsPrev: prior?.runs ?? 0, iterations, bySurface };
  } catch {
    return emptyActivity();
  }
}

// Curated posture headlines pulled straight off the Feature 1 trend. All are
// metrics where a DECREASE is the good outcome (fewer open detections, fewer
// critical/known-exploited vulns, fewer unmanaged/stale hosts, fewer open
// cases) — the UI colors arrows by that.
const HEADLINE_SPECS: Array<{
  key: string;
  label: string;
  category: string;
  field: string;
  lowerIsBetter: boolean;
}> = [
  { key: "detections_open", label: "Open detections", category: "detections", field: "open", lowerIsBetter: true },
  { key: "vulns_critical", label: "Critical vulnerabilities", category: "vulns", field: "open_critical", lowerIsBetter: true },
  { key: "vulns_kev", label: "Known exploited vulnerabilities", category: "vulns", field: "kev", lowerIsBetter: true },
  { key: "coverage_unmanaged", label: "Unmanaged hosts", category: "coverage", field: "unmanaged", lowerIsBetter: true },
  { key: "coverage_stale", label: "Stale hosts", category: "coverage", field: "stale_hosts", lowerIsBetter: true },
  { key: "cases_open", label: "Open cases", category: "cases", field: "open", lowerIsBetter: true },
];

function computePosture(envId: string, windowDays: number): PostureDigest {
  const result = computePostureTrend(envId, windowDays);
  // Need a current AND a previous snapshot for any movement to exist.
  if (!result.trend || !result.previous) return emptyPosture();

  const trend = result.trend as unknown as Record<string, Record<string, MetricTrend>>;
  const headlines: PostureHeadline[] = [];
  for (const spec of HEADLINE_SPECS) {
    const leaf = trend[spec.category]?.[spec.field];
    if (!leaf) continue;
    headlines.push({
      key: spec.key,
      label: spec.label,
      current: leaf.current,
      previous: leaf.previous,
      delta: leaf.delta,
      direction: leaf.direction,
      lowerIsBetter: spec.lowerIsBetter,
    });
  }

  return { available: true, windowDays: result.windowDays, headlines };
}

// The one entry point. Operations + activity cover the trailing `windowDays`
// (and the equal window before it for the period-over-period read); posture
// uses the same window for its trend gap, falling back to the prior snapshot
// when there isn't a full window of history yet.
export async function computeScorecard(
  envId: string,
  opts: { windowDays?: number } = {},
): Promise<Scorecard> {
  const windowDays = clampDays(opts.windowDays ?? DEFAULT_WINDOW_DAYS);
  const now = Date.now();
  const windowStart = now - windowDays * DAY_MS;
  const priorStart = now - 2 * windowDays * DAY_MS;

  const operations = await computeOperations(envId, now, windowStart, priorStart);
  const activity = computeActivity(envId, windowStart, priorStart);
  const posture = computePosture(envId, windowDays);

  return {
    windowDays,
    generatedAt: new Date(now).toISOString(),
    operations,
    activity,
    posture,
  };
}
