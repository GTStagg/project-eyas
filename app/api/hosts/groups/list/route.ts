import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { nativeSidecarPayload } from "@/lib/mcp/native-payload";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type GroupSummary = {
  id: string;
  name: string;
  group_type?: string;
  description?: string;
};

export async function GET() {
  try {
    const items = await withFalconMcpClient<GroupSummary[]>(async (client) => {
      const payload = await nativeSidecarPayload(client, "falcon_search_host_groups", {
        limit: 500,
        sort: "name.asc",
      });
      if (payload.ok !== true || !Array.isArray(payload.items)) return [];
      return (payload.items as GroupSummary[])
        .map((g) => ({
          id: g.id,
          name: g.name,
          group_type: g.group_type,
          description: g.description,
        }))
        .sort((a, b) => (a.name ?? "").localeCompare(b.name ?? ""));
    });
    return NextResponse.json({ ok: true, items });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}
