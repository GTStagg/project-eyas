import { NextResponse } from "next/server";
import { clearAllConversations, getStats } from "@/lib/chat/state";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json(getStats());
}

export async function DELETE() {
  const cleared = clearAllConversations();
  return NextResponse.json({ ok: true, cleared });
}
