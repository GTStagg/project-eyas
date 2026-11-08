import { NextResponse } from "next/server";
import { getActiveEnvironmentId } from "@/lib/config/environments";
import { computeScorecard } from "@/lib/scorecard/compute";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const DEFAULT_DAYS = 30;
const MAX_DAYS = 365;

// Deterministic agentic-SOC scorecard for the active tenant: engagements run,
// gated actions reviewed, detections resolved, agentic activity by surface, and
// how posture moved while the console operated. Pure local-DB reads (no LLM, no
// upstream Falcon calls). Scoped to the active environment — separate tenants
// never blend. Session-authed by the root middleware (not in PUBLIC_PREFIXES).
export async function GET(req: Request) {
  try {
    const envId = getActiveEnvironmentId();
    // An absent or empty `days` means "unspecified" → default window. Parsing
    // null/"" through Number() yields 0 (which is finite), so guard explicitly
    // or a bare request collapses to a 1-day window instead of the default.
    const param = new URL(req.url).searchParams.get("days");
    const raw = param === null || param.trim() === "" ? NaN : Number(param);
    const days = Number.isFinite(raw)
      ? Math.min(MAX_DAYS, Math.max(1, Math.trunc(raw)))
      : DEFAULT_DAYS;

    const scorecard = await computeScorecard(envId, { windowDays: days });

    return NextResponse.json({ ok: true, envId, scorecard });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    );
  }
}
