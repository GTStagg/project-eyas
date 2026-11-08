import { NextResponse } from "next/server";
import { getFullSession, resetConversation } from "@/lib/chat/state";
import { flattenMessagesToTurns } from "@/lib/chat/message-flatten";
import { listPendingForSession } from "@/lib/chat/approvals";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// GET     /api/chat/sessions/[id]  → full resumed conversation: title +
//                                    timestamps + flattened UI Turn[].
// DELETE  /api/chat/sessions/[id]  → drop the conversation.
//
// The flattening happens server-side so the UI doesn't need to know about
// Anthropic message shapes — Chat.tsx gets the same Turn[] shape it builds
// live during streaming.

type Ctx = { params: Promise<{ id: string }> };

export async function GET(_req: Request, ctx: Ctx) {
  const { id } = await ctx.params;
  if (!id) {
    return NextResponse.json({ ok: false, error: "id required" }, { status: 400 });
  }
  const session = getFullSession(id);
  if (!session) {
    return NextResponse.json({ ok: false, error: "not found or expired" }, { status: 404 });
  }
  const turns = flattenMessagesToTurns(session.messages);
  const pending = listPendingForSession(id);
  // Re-stamp `pendingApproval: true` on any tool_use whose approval is
  // still mid-flight server-side. Without this, a tab switch / resume
  // would hide the Allow/Deny buttons on a tool the user still owes a
  // decision on (the in-memory awaitApproval Promise is still waiting).
  if (pending.length > 0) {
    const pendingIds = new Set(pending.map((p) => p.toolUseId));
    for (const turn of turns) {
      if (turn.role !== "assistant") continue;
      for (const tu of turn.toolUses) {
        if (pendingIds.has(tu.id)) tu.pendingApproval = true;
      }
    }
  }
  return NextResponse.json({
    ok: true,
    session: {
      id: session.id,
      title: session.title,
      createdAt: session.createdAt,
      lastTouched: session.lastTouched,
      expiresAt: session.expiresAt,
      irActive: !!session.irMode,
    },
    turns,
    pendingApprovals: pending,
  });
}

export async function DELETE(_req: Request, ctx: Ctx) {
  const { id } = await ctx.params;
  if (!id) {
    return NextResponse.json({ ok: false, error: "id required" }, { status: 400 });
  }
  resetConversation(id);
  return NextResponse.json({ ok: true });
}
