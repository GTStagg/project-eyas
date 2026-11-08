import { NextResponse } from "next/server";
import { summarizeCost } from "@/lib/cost/log";
import { getAnthropicModel } from "@/lib/llm/anthropic";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// JSON view of all-time spend. Aggregation happens in SQLite (summarizeCost)
// rather than reading the whole cost_log table into JS and JSON-parsing every
// row on each request.
export async function GET() {
  const { totals, days, bySurface, byModel, recent } = summarizeCost();

  // Project monthly: average $/day across the days we have data, × 30.
  const avgPerDay = days.length > 0 ? totals.cost / days.length : 0;

  return NextResponse.json({
    ok: true,
    currentModel: getAnthropicModel(),
    totals,
    projectedMonthly: avgPerDay * 30,
    avgPerDay,
    days,
    bySurface,
    byModel,
    recent: recent.map((e) => ({
      ts: e.ts,
      model: e.model,
      surface: e.surface,
      iterations: e.iterations ?? 1,
      cost: e.cost,
      usage: e.usage,
    })),
  });
}
