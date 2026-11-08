import { NextResponse } from "next/server";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { parseConcatenatedJson } from "@/lib/mcp/parse";
import type { Host } from "@/components/HostsTable";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Cap on members fetched per group. The enrichment step builds a single
// `device_id:[...]` FQL filter from these ids, so an unbounded cap would
// blow the filter length; 100 is the safe ceiling. A group larger than this
// is truncated — the response carries `truncated` so the caller can say so
// rather than silently showing a partial roster.
const MEMBER_LIMIT = 100;

type Member = {
  device_id?: string;
  hostname?: string;
  platform_name?: string;
  os_version?: string;
  last_seen?: string;
  tags?: string[];
};

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const groupId = (searchParams.get("group_id") ?? "").trim();
  if (!groupId) {
    return NextResponse.json(
      { ok: false, error: "group_id required" },
      { status: 400 },
    );
  }

  try {
    const members = await withFalconExtrasClient<Member[]>(async (client) => {
      const r = await client.callTool({
        name: "extras_host_group_members",
        arguments: { group_id: groupId, limit: MEMBER_LIMIT },
      });
      const text = (r.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      try {
        const payload = JSON.parse(text);
        if (payload?.ok && Array.isArray(payload.items)) {
          return payload.items as Member[];
        }
      } catch {
        // fall through
      }
      return [];
    });

    // Enrich with full host records so action buttons render correctly
    // (extras_host_group_members projects a thin host shape — no rtr_state /
    // os_product_name / external_ip / status).
    const aids = members.map((m) => m.device_id).filter(Boolean) as string[];
    let enriched: Host[] = members as Host[];
    if (aids.length > 0) {
      const hosts = await withFalconMcpClient<Host[]>(async (client) => {
        const filterValue =
          "device_id:[" + aids.map((a) => `'${a}'`).join(",") + "]";
        const r = await client.callTool({
          name: "falcon_search_hosts",
          arguments: { filter: filterValue, limit: aids.length },
        });
        const text = (r.content as Array<{ type: string; text?: string }>)
          .map((c) => (c.type === "text" && c.text ? c.text : ""))
          .join("\n");
        return parseConcatenatedJson<Host>(text);
      });
      const byId = new Map(
        hosts.map((h) => [h.device_id ?? "", h] as const),
      );
      enriched = members.map((m) => {
        const full = m.device_id ? byId.get(m.device_id) : undefined;
        return { ...m, ...(full ?? {}) } as Host;
      });
    }

    enriched.sort((a, b) =>
      (a.hostname ?? "").localeCompare(b.hostname ?? ""),
    );

    return NextResponse.json({
      ok: true,
      items: enriched,
      truncated: members.length >= MEMBER_LIMIT,
    });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}
