import { NextResponse } from "next/server";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type ToolText = { type?: string; text?: string };

function parseToolResult(result: unknown): unknown {
  if (!result || typeof result !== "object") return null;
  const content = (result as { content?: ToolText[] }).content;
  if (!Array.isArray(content) || content.length === 0) return null;
  const first = content[0];
  if (!first || typeof first.text !== "string") return null;
  try {
    return JSON.parse(first.text);
  } catch {
    return null;
  }
}

export async function GET() {
  return withFalconExtrasClient(async (client) => {
    const raw = await client.callTool({
      name: "extras_prevention_policy_posture",
      arguments: { limit: 200 },
    });
    return NextResponse.json(parseToolResult(raw) ?? { ok: false, error: "no result" });
  });
}
