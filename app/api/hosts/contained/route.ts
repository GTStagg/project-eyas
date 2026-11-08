import { NextResponse } from "next/server";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type ContainedHost = {
  device_id?: string;
  hostname?: string;
  platform_name?: string;
  os_product_name?: string;
  os_version?: string;
  rtr_state?: string;
  status?: string;
  last_seen?: string;
};

export async function GET() {
  try {
    const items = await withFalconExtrasClient(async (client) => {
      const result = await client.callTool({
        name: "extras_host_list_contained",
        arguments: { limit: 200 },
      });
      const text = (result.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      try {
        const payload = JSON.parse(text);
        if (payload && payload.ok && Array.isArray(payload.items)) {
          return payload.items as ContainedHost[];
        }
        if (payload && payload.scope_pending) return [];
        return [];
      } catch {
        return [];
      }
    });

    if (items === null) {
      return NextResponse.json({ ok: true, items: [], extras_disabled: true });
    }
    return NextResponse.json({ ok: true, items });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}
