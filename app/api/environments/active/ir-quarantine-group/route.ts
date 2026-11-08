import { NextResponse } from "next/server";
import { updateActiveEnvironment } from "@/lib/config/environments";
import { invalidateHealthCache } from "@/lib/health";
import { isBusy } from "@/lib/chat/in-flight";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// POST /api/environments/active/ir-quarantine-group
//   { id: string }      — set the IR quarantine group id on the active env
//   { id: "" }          — clear it
// Refuses with 409 when an agent loop is mid-run (same rationale as the
// active-env switcher: rotating tenant pointers mid-tool-call would
// attribute the result to the wrong tenant in the trace).
//
// Used as the auto-save target after extras_create_quarantine_host_group
// returns a new id, so the operator doesn't have to copy/paste it back
// into /config.

export async function POST(request: Request) {
  if (isBusy()) {
    return NextResponse.json(
      { ok: false, error: "agent loop is mid-run; finish or cancel before changing tenant config" },
      { status: 409 },
    );
  }
  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return NextResponse.json({ ok: false, error: "invalid JSON body" }, { status: 400 });
  }
  const id = (raw as Record<string, unknown> | null)?.id;
  if (typeof id !== "string") {
    return NextResponse.json({ ok: false, error: "id is required (string, '' to clear)" }, { status: 400 });
  }
  await updateActiveEnvironment({ irQuarantineGroupId: id });
  invalidateHealthCache();
  return NextResponse.json({ ok: true, irQuarantineGroupId: id || null });
}
