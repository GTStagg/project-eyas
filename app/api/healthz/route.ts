import { NextResponse } from "next/server";

// Cheap public liveness probe. No upstream calls, no diagnostics — just
// confirms the Node process is up and serving HTTP. Suitable for container
// orchestrator health checks and external uptime monitors.
//
// Operational diagnostics (Anthropic / Falcon MCP / extras probes) live on
// /api/health, which requires an authenticated session to avoid letting
// unauthenticated callers fan out upstream API calls.

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const startedAt = Date.now();

export async function GET() {
  return NextResponse.json({
    ok: true,
    uptime_s: Math.round((Date.now() - startedAt) / 1000),
  });
}
