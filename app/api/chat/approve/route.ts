import { NextResponse } from "next/server";
import { resolveApproval, type Decision } from "@/lib/chat/approvals";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Body = { toolUseId?: string; decision?: Decision; sessionId?: string };

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Body;
  const toolUseId = (body.toolUseId ?? "").trim();
  const sessionId = (body.sessionId ?? "").trim();
  const decision = body.decision;

  if (!toolUseId || !sessionId || (decision !== "allow" && decision !== "deny")) {
    return NextResponse.json(
      { ok: false, error: "toolUseId + sessionId + decision (allow|deny) required" },
      { status: 400 },
    );
  }

  const result = resolveApproval(toolUseId, decision, sessionId);
  if (result.ok) return NextResponse.json({ ok: true, found: true });
  if (result.reason === "session_mismatch") {
    return NextResponse.json({ ok: false, error: "session_mismatch" }, { status: 403 });
  }
  return NextResponse.json({ ok: false, found: false });
}
