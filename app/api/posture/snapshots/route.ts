import { NextResponse } from "next/server";
import { getActiveEnvironmentId } from "@/lib/config/environments";
import { computePostureTrend, getRecentSnapshots } from "@/lib/posture/trend";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const DEFAULT_LIMIT = 30;
const MAX_LIMIT = 200;

// Recent posture snapshots for the active tenant plus the latest-vs-prior
// trend. Read-only, pure over stored rows — no upstream Falcon calls. Session
// authed by the root middleware (not in PUBLIC_PREFIXES).
export async function GET(req: Request) {
  try {
    const envId = getActiveEnvironmentId();
    const raw = Number(new URL(req.url).searchParams.get("limit"));
    const limit = Number.isFinite(raw)
      ? Math.min(MAX_LIMIT, Math.max(1, Math.trunc(raw)))
      : DEFAULT_LIMIT;

    const snapshots = getRecentSnapshots(envId, limit);
    const trend = computePostureTrend(envId);

    return NextResponse.json({ ok: true, envId, count: snapshots.length, snapshots, trend });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    );
  }
}
