import { NextResponse } from "next/server";
import { listSessions } from "@/lib/chat/state";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// GET /api/chat/sessions  → list non-expired conversations newest-first.
// Powers the /chat left rail. Returns minimal metadata (id, title, counts,
// expiresAt) — full message bodies come from /api/chat/sessions/[id].

export async function GET() {
  const sessions = listSessions();
  return NextResponse.json({ ok: true, sessions });
}
