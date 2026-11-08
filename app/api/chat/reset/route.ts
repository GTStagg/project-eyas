import { NextResponse } from "next/server";
import { resetConversation } from "@/lib/chat/state";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as { sessionId?: string };
  if (!body.sessionId) {
    return NextResponse.json({ ok: false, error: "sessionId required" }, { status: 400 });
  }
  resetConversation(body.sessionId);
  return NextResponse.json({ ok: true });
}
