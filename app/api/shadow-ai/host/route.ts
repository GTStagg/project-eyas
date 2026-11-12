import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { makeEyasToolContext } from "@/lib/mcp/tool-bridge";
import { hostShadowAiScan } from "@/lib/eyas-tools/shadow-ai/hunt";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  let body: { device_id?: string; hours_back?: number };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ ok: false, error: "invalid JSON" }, { status: 400 });
  }
  const aid = String(body.device_id ?? "").trim();
  if (!/^[a-fA-F0-9]{32}$/.test(aid)) {
    return NextResponse.json(
      { ok: false, error: "device_id must be a 32-char hex AID" },
      { status: 400 },
    );
  }
  const hours = Number.isFinite(body.hours_back) ? Number(body.hours_back) : 72;

  try {
    // extras_host_shadow_ai_scan, run in-process (lib/eyas-tools/shadow-ai).
    const payload = await withFalconMcpClient((client) =>
      hostShadowAiScan(makeEyasToolContext(client), { device_id: aid, hours_back: hours }),
    );
    return NextResponse.json(payload);
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}
