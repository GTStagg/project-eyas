import { NextResponse } from "next/server";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";

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
    const payload = await withFalconExtrasClient(async (client) => {
      const result = await client.callTool({
        name: "extras_host_shadow_ai_scan",
        arguments: { device_id: aid, hours_back: hours },
      });
      const text = (result.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      try {
        return JSON.parse(text);
      } catch {
        return { ok: false, error: "sidecar returned non-JSON" };
      }
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
