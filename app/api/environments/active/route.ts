import { NextResponse } from "next/server";
import {
  getActiveEnvironmentId,
  getEnvironmentById,
  listEnvironments,
  setActiveEnvironment,
} from "@/lib/config/environments";
import { invalidateHealthCache } from "@/lib/health";
import { inFlightCount, isBusy } from "@/lib/chat/in-flight";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// POST /api/environments/active — switch the active environment. Body:
//   { id: string }
// Refuses with 409 when an agent loop is mid-run; swapping Falcon creds
// while a tool call is hanging on falcon-mcp would attribute the result
// to the wrong tenant in the trace.

export async function POST(request: Request) {
  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return NextResponse.json({ ok: false, error: "invalid JSON body" }, { status: 400 });
  }
  const id = (raw as Record<string, unknown> | null)?.id;
  if (typeof id !== "string" || !id) {
    return NextResponse.json({ ok: false, error: "id is required" }, { status: 400 });
  }
  if (!getEnvironmentById(id)) {
    return NextResponse.json({ ok: false, error: "environment not found" }, { status: 404 });
  }
  if (id === getActiveEnvironmentId()) {
    return NextResponse.json({
      ok: true,
      active_id: id,
      environments: listEnvironments(),
    });
  }
  if (isBusy()) {
    return NextResponse.json(
      {
        ok: false,
        error: `Refusing to switch environments — ${inFlightCount()} agent run(s) in flight. Wait for them to finish or cancel and try again.`,
        in_flight: inFlightCount(),
      },
      { status: 409 },
    );
  }
  await setActiveEnvironment(id);
  invalidateHealthCache();
  return NextResponse.json({
    ok: true,
    active_id: getActiveEnvironmentId(),
    environments: listEnvironments(),
  });
}
