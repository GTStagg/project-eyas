import { NextResponse } from "next/server";
import { inspectConversation } from "@/lib/chat/state";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const sessionId = url.searchParams.get("sessionId");
  if (!sessionId) {
    return NextResponse.json({ ok: false, error: "sessionId required" }, { status: 400 });
  }
  const info = inspectConversation(sessionId);
  return NextResponse.json({ ok: true, exists: info !== null, ...(info ?? {}) });
}
