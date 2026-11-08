import { NextResponse } from "next/server";
import { getHealthReport } from "@/lib/health";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const force = new URL(req.url).searchParams.get("force") === "1";
  const report = await getHealthReport({ force });
  const overall =
    report.anthropic.status === "ok" && report.falconMcp.status === "ok"
      ? "ok"
      : report.anthropic.status === "error" || report.falconMcp.status === "error"
        ? "degraded"
        : report.anthropic.status === "initializing" || report.falconMcp.status === "initializing"
          ? "initializing"
          : "degraded";
  return NextResponse.json({ overall, ...report });
}
