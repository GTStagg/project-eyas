import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { fetchPreventionPosture } from "@/lib/prevention/posture";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return withFalconMcpClient(async (mcp) => NextResponse.json(await fetchPreventionPosture(mcp)));
}
