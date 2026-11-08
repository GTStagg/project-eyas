import { NextResponse } from "next/server";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";

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
    const items = await withFalconExtrasClient<GroupSummary[]>(async (client) => {
      const r = await client.callTool({
        name: "extras_host_group_list",
        arguments: { limit: 500 },
      });
      const text = (r.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      try {
        const payload = JSON.parse(text);
        if (payload?.ok && Array.isArray(payload.items)) {
          return (payload.items as GroupSummary[])
            .map((g) => ({
              id: g.id,
              name: g.name,
              group_type: g.group_type,
              description: g.description,
            }))
            .sort((a, b) => a.name.localeCompare(b.name));
        }
      } catch {
        // fall through
      }
      return [];
    });
    return NextResponse.json({ ok: true, items });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}
