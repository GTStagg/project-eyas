import "server-only";
import { desc, eq, sql } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { postureSnapshots } from "@/lib/db/schema";
import {
  emptyPostureMetrics,
  type Metric,
  type PostureMetrics,
  type PostureSnapshot,
} from "./types";

// Pure read + trend math over posture_snapshots. No LLM, no upstream calls —
// this is the import surface for the MTTR scorecard, the incident narrative,
// and a future executive briefing. Trends need >=2 snapshots; a fresh install
// shows null deltas until the second capture.

// How far back "previous" should ideally sit from "current" for a
// week-over-week read. If no snapshot is that old yet, we fall back to the
// immediately-prior one so an operator still sees movement.
const TREND_WINDOW_DAYS = 7;
const DEFAULT_LIMIT = 60;

function decodeRow(row: {
  id: number;
  capturedAt: string;
  envId: string;
  schemaVersion: number;
  metricsJson: string;
  captureMs: number | null;
  partial: boolean;
}): PostureSnapshot {
  let metrics: PostureMetrics;
  try {
    metrics = JSON.parse(row.metricsJson) as PostureMetrics;
  } catch {
    metrics = emptyPostureMetrics();
  }
  return {
    id: row.id,
    capturedAt: row.capturedAt,
    envId: row.envId,
    schemaVersion: row.schemaVersion,
    metrics,
    captureMs: row.captureMs ?? null,
    partial: row.partial,
  };
}

// Newest-first. `limit` bounds the read; defaults cover ~2 months of daily caps.
export function getRecentSnapshots(envId: string, limit = DEFAULT_LIMIT): PostureSnapshot[] {
  const rows = db()
    .select()
    .from(postureSnapshots)
    .where(eq(postureSnapshots.envId, envId))
    .orderBy(desc(postureSnapshots.capturedAt))
    .limit(limit)
    .all();
  return rows.map(decodeRow);
}

// Total snapshots stored for an env — cheap COUNT, no JSON decode.
export function countSnapshots(envId: string): number {
  const row = db()
    .select({ c: sql<number>`count(*)` })
    .from(postureSnapshots)
    .where(eq(postureSnapshots.envId, envId))
    .get() as { c: number } | undefined;
  return row?.c ?? 0;
}

export type MetricDirection = "up" | "down" | "flat";

export type MetricTrend = {
  current: Metric;
  previous: Metric;
  delta: number | null; // current - previous; null if either side is null
  direction: MetricDirection; // "flat" when delta is null or zero
};

// Mirrors PostureMetrics, every leaf swapped for a MetricTrend.
export type PostureTrend = {
  [K in keyof PostureMetrics]: { [F in keyof PostureMetrics[K]]: MetricTrend };
};

export type PostureTrendResult = {
  envId: string;
  current: PostureSnapshot | null;
  previous: PostureSnapshot | null;
  windowDays: number; // actual gap between current and previous, in days
  trend: PostureTrend | null; // null when there is no current snapshot
};

function leafTrend(current: Metric, previous: Metric): MetricTrend {
  const delta = current !== null && previous !== null ? current - previous : null;
  let direction: MetricDirection = "flat";
  if (delta !== null && delta > 0) direction = "up";
  else if (delta !== null && delta < 0) direction = "down";
  return { current, previous, delta, direction };
}

function buildTrend(current: PostureMetrics, previous: PostureMetrics | null): PostureTrend {
  const out = {} as Record<string, Record<string, MetricTrend>>;
  for (const cat of Object.keys(current) as Array<keyof PostureMetrics>) {
    const curCat = current[cat] as Record<string, Metric>;
    const prevCat = (previous?.[cat] ?? {}) as Record<string, Metric>;
    const catOut: Record<string, MetricTrend> = {};
    for (const field of Object.keys(curCat)) {
      catOut[field] = leafTrend(curCat[field] ?? null, prevCat[field] ?? null);
    }
    out[cat] = catOut;
  }
  return out as PostureTrend;
}

// Newest snapshot that is at least `windowDays` older than the latest; falls
// back to the immediately-prior snapshot when there isn't a full window of
// history yet. Returns null when there's only one (or zero) snapshots.
function pickPrevious(
  snaps: PostureSnapshot[],
  windowDays: number,
): PostureSnapshot | null {
  if (snaps.length < 2) return null;
  const currentMs = Date.parse(snaps[0].capturedAt);
  const threshold = currentMs - windowDays * 86_400_000;
  for (let i = 1; i < snaps.length; i += 1) {
    if (Date.parse(snaps[i].capturedAt) <= threshold) return snaps[i];
  }
  return snaps[1];
}

// Latest vs ~`windowDays`-prior, per metric. Pure over the stored snapshots.
export function computePostureTrend(
  envId: string,
  windowDays = TREND_WINDOW_DAYS,
): PostureTrendResult {
  const snaps = getRecentSnapshots(envId);
  const current = snaps[0] ?? null;
  const previous = pickPrevious(snaps, windowDays);

  if (!current) {
    return { envId, current: null, previous: null, windowDays: 0, trend: null };
  }

  const actualWindowDays = previous
    ? Math.round(
        (Date.parse(current.capturedAt) - Date.parse(previous.capturedAt)) / 86_400_000,
      )
    : 0;

  return {
    envId,
    current,
    previous,
    windowDays: actualWindowDays,
    trend: buildTrend(current.metrics, previous?.metrics ?? null),
  };
}
