import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { makeEyasToolContext } from "@/lib/mcp/tool-bridge";
import { diagnoseBannedSetup } from "@/lib/eyas-tools/shadow-ai/prevention";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Read-only state check for the Shadow-AI Banned setup. Backs the
// "Shadow-AI Banned setup" card on /config. Returns one of:
// no_group_id, group_missing, A_no_policy, B_dedicated_single_group,
// C_shared_policy, rules_incomplete, ready — plus a recommended_action shape.
export async function GET(request: Request) {
  const url = new URL(request.url);
  const override = url.searchParams.get("host_group_id");
  try {
    const payload = await withFalconMcpClient((client) =>
      diagnoseBannedSetup(makeEyasToolContext(client), override),
    );
    return NextResponse.json(payload);
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}
