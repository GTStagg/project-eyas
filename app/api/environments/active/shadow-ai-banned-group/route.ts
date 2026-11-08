import { NextResponse } from "next/server";
import { updateActiveEnvironment } from "@/lib/config/environments";
import { invalidateHealthCache } from "@/lib/health";
import { isBusy } from "@/lib/chat/in-flight";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// POST /api/environments/active/shadow-ai-banned-group
//   { id: string }      — set the Shadow-AI banned group id on the active env
//   { id: "" }          — clear it
// Auto-save target after extras_create_shadow_ai_banned_host_group returns
// a new id. Refuses with 409 while an agent loop is mid-run.

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
  await updateActiveEnvironment({ shadowAiBannedGroupId: id });
  invalidateHealthCache();
  return NextResponse.json({ ok: true, shadowAiBannedGroupId: id || null });
}
