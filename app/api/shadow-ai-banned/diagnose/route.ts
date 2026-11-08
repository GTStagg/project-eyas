import { NextResponse } from "next/server";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";
import { parseExtrasObjectResult } from "@/lib/mcp/parse";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Read-only state check for the Shadow-AI Banned setup. Backs the
// "Shadow-AI Banned setup" card on /config. Returns one of:
// no_group_id, group_missing, A_no_policy, B_dedicated_single_group,
// C_shared_policy, ready — plus a recommended_action shape.
export async function GET(request: Request) {
  const url = new URL(request.url);
  const override = url.searchParams.get("host_group_id");
  try {
    const payload = await withFalconExtrasClient(async (client) => {
      const result = await client.callTool({
        name: "extras_diagnose_shadow_ai_banned_setup",
        arguments: override ? { host_group_id: override } : {},
      });
      return parseExtrasObjectResult(result);
    });
    if (payload === null) {
      return NextResponse.json(
        { ok: false, error: "falcon-extras sidecar is disabled" },
        { status: 503 },
      );
    }
    return NextResponse.json(payload);
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}
