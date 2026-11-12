import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { fetchContainedHosts } from "@/lib/hosts/contained";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const r = await withFalconMcpClient((client) => fetchContainedHosts(client, 200));
    if (!r.ok) {
      return NextResponse.json({ ok: false, error: r.error }, { status: 502 });
    }
    return NextResponse.json({ ok: true, items: r.items, total: r.total });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}
