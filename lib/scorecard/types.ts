import "server-only";

// Shape of the agentic-SOC scorecard — a deterministic readout of what THIS
// console has accomplished (incident-response engagements run, gated actions
// reviewed, detections resolved), how much agentic work it did across every
// surface, and how the tenant's posture moved while it operated. Pure local-DB
// aggregation: no LLM, no upstream Falcon calls. Each section is empty-safe so
// a fresh install renders zeros/empty states rather than throwing.
//
// All three sections are scoped to the active environment: operations read
// ir_runs filtered by env_id, activity reads cost_log filtered by env_id, and
// posture reads the per-env posture_snapshots trend. Pre-attribution rows
// (env_id NULL) are excluded rather than blended across separate tenants.

export type MetricDirection = "up" | "down" | "flat";

// Incident-response engagements run from this console, aggregated over the
// trailing window. Durations are in ms. "Prev" fields cover the immediately
// preceding window of equal length, for a period-over-period read.
export type OperationsMetrics = {
  engagements: number;
  engagementsPrev: number;
  medianCloseMs: number | null; // null when no engagements in the window
  meanCloseMs: number | null;
  detectionsResolved: number;
  detectionsResolvedPrev: number;
  actions: {
    reviewed: number; // tool calls that hit an approval gate (approval !== "none")
    allowed: number;
    declined: number;
    expired: number; // approval timed out
  };
  turns: number;
  iterations: number;
  erroredEngagements: number;
};

// Breadth of agentic work, from the cost ledger. One row per surface that ran
// at least once in the window. `runs` = agent turns logged for that surface.
export type ActivitySurface = { surface: string; runs: number };
export type ActivityMetrics = {
  totalRuns: number;
  totalRunsPrev: number;
  iterations: number;
  bySurface: ActivitySurface[];
};

// A single posture headline lifted from the Feature 1 trend. `delta` is
// current − previous (null when either side is null); `direction` mirrors it.
export type PostureHeadline = {
  key: string;
  label: string;
  current: number | null;
  previous: number | null;
  delta: number | null;
  direction: MetricDirection;
  // For coloring: true when a *decrease* is the good outcome (detections,
  // vulns, unmanaged hosts). false for metrics where up is good.
  lowerIsBetter: boolean;
};
export type PostureDigest = {
  available: boolean; // false until there are >=2 snapshots with a usable previous
  windowDays: number; // actual gap the trend used
  headlines: PostureHeadline[];
};

export type Scorecard = {
  windowDays: number;
  generatedAt: string;
  operations: OperationsMetrics;
  activity: ActivityMetrics;
  posture: PostureDigest;
};

export function emptyOperations(): OperationsMetrics {
  return {
    engagements: 0,
    engagementsPrev: 0,
    medianCloseMs: null,
    meanCloseMs: null,
    detectionsResolved: 0,
    detectionsResolvedPrev: 0,
    actions: { reviewed: 0, allowed: 0, declined: 0, expired: 0 },
    turns: 0,
    iterations: 0,
    erroredEngagements: 0,
  };
}

export function emptyActivity(): ActivityMetrics {
  return { totalRuns: 0, totalRunsPrev: 0, iterations: 0, bySurface: [] };
}

export function emptyPosture(): PostureDigest {
  return { available: false, windowDays: 0, headlines: [] };
}
