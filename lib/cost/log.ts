import "server-only";
import { desc } from "drizzle-orm";
import { db, rawDb } from "../db/client";
import { costLog } from "../db/schema";
import { getActiveEnvironmentId } from "../config/environments";
import { costOf, type Usage } from "./pricing";

// Cost-log storage. Append-only inserts into the `cost_log` table in
// data/eyas.db. Indexed by (ts) and (surface, ts) so /cost-summary and
// the cost dashboard can run indexed SQL aggregations. New callers
// should query directly via Drizzle; readLog() is the JSONL-shaped
// helper used by the older surfaces.

export type Surface =
  | "chat" | "briefing" | "investigate" | "ngsiem" | "ngsiem-playbook"
  | "triage-vulns" | "triage-detections" | "queue-brief" | "lookup" | "intel"
  | "patch-plan" | "adversary-exposure" | "recon" | "host-groups" | "malquery"
  | "workflows" | "identity" | "threat-graph"
  | "quarantine" | "correlation" | "data-protection" | "discover"
  | "guardian"
  | "incident-report"
  | "blueprint"
  | "intel-dossier"
  | "investigate:fingerprint" | "investigate:threats" | "investigate:posture";

export type CostLogEntry = {
  ts: string;
  model: string;
  surface: Surface;
  iterations?: number;
  usage: Usage;
};

/** Append-one. Best-effort: never throws — a logging failure must not
 *  surface as an agent-loop failure. Stamps the active environment so the
 *  row is attributed to the tenant it ran under (env switch is refused while
 *  a turn is in flight, so the active env at write time is the right one).
 *  Resolved in its own try so a settings hiccup downgrades to an unattributed
 *  row rather than dropping the cost entry entirely. */
export async function logUsage(entry: CostLogEntry): Promise<void> {
  let envId: string | null = null;
  try {
    envId = getActiveEnvironmentId();
  } catch {
    // leave unattributed
  }
  try {
    db().insert(costLog).values({
      ts: entry.ts,
      model: entry.model,
      surface: entry.surface,
      iterations: entry.iterations ?? null,
      usageJson: JSON.stringify(entry.usage),
      envId,
    }).run();
  } catch {
    // intentionally swallowed
  }
}

/** Read the entire log (preserved for back-compat). New callers should
 *  query via Drizzle directly for aggregations. */
export async function readLog(): Promise<CostLogEntry[]> {
  try {
    const rows = db().select().from(costLog).orderBy(desc(costLog.ts)).all();
    const out: CostLogEntry[] = [];
    for (const r of rows) {
      try {
        const usage = JSON.parse(r.usageJson) as Usage;
        out.push({
          ts: r.ts,
          model: r.model,
          surface: r.surface as Surface,
          iterations: r.iterations ?? undefined,
          usage,
        });
      } catch {
        /* skip corrupt row */
      }
    }
    // The old JSONL was append-order (oldest first). Restore that
    // ordering for callers that depended on it.
    return out.reverse();
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Aggregated summary — the surface /cost (and the legacy /api/cost route) read.
// ---------------------------------------------------------------------------

export type CostDayBucket = {
  day: string;
  cost: number;
  turns: number;
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
};
export type CostGroupBucket = { surface: string; cost: number; turns: number };
export type CostModelBucket = { model: string; cost: number; turns: number };
export type CostTotals = {
  cost: number;
  turns: number;
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
};
export type CostSummary = {
  totals: CostTotals;
  days: CostDayBucket[];
  bySurface: CostGroupBucket[];
  byModel: CostModelBucket[];
  recent: Array<CostLogEntry & { cost: number }>;
};

type GroupRow = {
  day: string;
  surface: string;
  model: string;
  turns: number;
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
};
type RecentRow = {
  ts: string;
  model: string;
  surface: string;
  iterations: number | null;
  usage_json: string;
};

/**
 * All-time spend summary, aggregated IN SQLite (GROUP BY day×surface×model with
 * json_extract sums) so we never pull every row into JS or JSON.parse the whole
 * table on each request — only the handful of grouped rows come back, plus the
 * 25 most-recent rows for the activity table. Cost is applied per (model) group
 * in JS since pricing lives here, not in the DB. Empty-safe.
 */
export function summarizeCost(): CostSummary {
  const empty: CostSummary = {
    totals: { cost: 0, turns: 0, input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    days: [],
    bySurface: [],
    byModel: [],
    recent: [],
  };

  let groups: GroupRow[];
  try {
    groups = rawDb()
      .prepare(
        `SELECT substr(ts, 1, 10) AS day, surface, model, COUNT(*) AS turns,
                SUM(COALESCE(json_extract(usage_json, '$.input_tokens'), 0)) AS input,
                SUM(COALESCE(json_extract(usage_json, '$.output_tokens'), 0)) AS output,
                SUM(COALESCE(json_extract(usage_json, '$.cache_read_input_tokens'), 0)) AS cacheRead,
                SUM(COALESCE(json_extract(usage_json, '$.cache_creation_input_tokens'), 0)) AS cacheWrite
           FROM cost_log
          GROUP BY day, surface, model`,
      )
      .all() as GroupRow[];
  } catch {
    return empty;
  }

  const byDay = new Map<string, CostDayBucket>();
  const bySurface = new Map<string, CostGroupBucket>();
  const byModel = new Map<string, CostModelBucket>();
  const totals: CostTotals = { cost: 0, turns: 0, input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };

  for (const g of groups) {
    const usage: Usage = {
      input_tokens: g.input,
      output_tokens: g.output,
      cache_read_input_tokens: g.cacheRead,
      cache_creation_input_tokens: g.cacheWrite,
    };
    const cost = costOf(usage, g.model);

    const d = byDay.get(g.day) ?? {
      day: g.day, cost: 0, turns: 0, input: 0, output: 0, cacheRead: 0, cacheWrite: 0,
    };
    d.cost += cost; d.turns += g.turns; d.input += g.input; d.output += g.output;
    d.cacheRead += g.cacheRead; d.cacheWrite += g.cacheWrite;
    byDay.set(g.day, d);

    const s = bySurface.get(g.surface) ?? { surface: g.surface, cost: 0, turns: 0 };
    s.cost += cost; s.turns += g.turns;
    bySurface.set(g.surface, s);

    const m = byModel.get(g.model) ?? { model: g.model, cost: 0, turns: 0 };
    m.cost += cost; m.turns += g.turns;
    byModel.set(g.model, m);

    totals.cost += cost; totals.turns += g.turns; totals.input += g.input;
    totals.output += g.output; totals.cacheRead += g.cacheRead; totals.cacheWrite += g.cacheWrite;
  }

  let recent: Array<CostLogEntry & { cost: number }> = [];
  try {
    const rows = rawDb()
      .prepare(
        `SELECT ts, model, surface, iterations, usage_json
           FROM cost_log ORDER BY ts DESC LIMIT 25`,
      )
      .all() as RecentRow[];
    recent = rows.map((r) => {
      let usage: Usage = {};
      try {
        usage = JSON.parse(r.usage_json) as Usage;
      } catch {
        /* leave empty */
      }
      return {
        ts: r.ts,
        model: r.model,
        surface: r.surface as Surface,
        iterations: r.iterations ?? undefined,
        usage,
        cost: costOf(usage, r.model),
      };
    });
  } catch {
    /* leave recent empty */
  }

  return {
    totals,
    days: [...byDay.values()].sort((a, b) => a.day.localeCompare(b.day)),
    bySurface: [...bySurface.values()].sort((a, b) => b.cost - a.cost),
    byModel: [...byModel.values()].sort((a, b) => b.cost - a.cost),
    recent,
  };
}
