import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { makeEyasToolContext } from "@/lib/mcp/tool-bridge";
import { fleetShadowAiEgress } from "@/lib/eyas-tools/shadow-ai/hunt";
import { detectFalconError, parseConcatenatedJson } from "@/lib/mcp/parse";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type ToolHit = {
  tool: string;
  posture: string;
  query_count: number;
  first_seen_ms: number | null;
  last_seen_ms: number | null;
  sample_domains: string[];
};

type FleetItem = {
  aid: string;
  hostname?: string;
  platform?: string;
  os_product_name?: string;
  os_version?: string;
  rtr_state?: string;
  tools: ToolHit[];
};

type SidecarPayload = {
  ok: boolean;
  items?: Array<{ aid: string; tools: ToolHit[] }>;
  events_scanned?: number;
  hours_back?: number;
  truncated?: boolean;
  scope_pending?: boolean;
  error?: string;
  note?: string;
};

type HostRecord = {
  device_id?: string;
  hostname?: string;
  platform_name?: string;
  os_product_name?: string;
  os_version?: string;
  rtr_state?: string;
};

export async function GET(request: Request) {
  const url = new URL(request.url);
  const hours = Math.max(
    1,
    Math.min(168, Number(url.searchParams.get("hours") ?? "24") || 24),
  );

  try {
    // Run the egress scan FIRST, then enrich the small set of AIDs that
    // came back via a targeted falcon_search_hosts(device_id:[...]) call.
    // Older revisions fan-out fetched all 5K hosts upfront on every page
    // load — that blows past Spotlight's 60s MCP timeout on large tenants
    // and discards 95% of the records. The egress-scan output is bounded
    // by the NGSIEM query, so the enrichment is always cheap and bounded.
    // extras_fleet_shadow_ai_egress, run in-process (lib/eyas-tools/shadow-ai).
    const egressPayload = (await withFalconMcpClient((client) =>
      fleetShadowAiEgress(makeEyasToolContext(client), { hours_back: hours, limit: 5000 }),
    )) as SidecarPayload;

    if (egressPayload.ok === false || egressPayload.scope_pending) {
      if (egressPayload.scope_pending) {
        return NextResponse.json({
          ok: true,
          items: [],
          scope_pending: true,
          note: egressPayload.note,
        });
      }
      return NextResponse.json(
        { ok: false, error: egressPayload.error ?? "egress search failed" },
        { status: 502 },
      );
    }

    const egressAids = Array.from(
      new Set((egressPayload.items ?? []).map((r) => r.aid).filter(Boolean)),
    );
    const aidToHost = new Map<string, HostRecord>();
    if (egressAids.length > 0) {
      try {
        const filterClause = egressAids.map((a) => `'${a}'`).join(",");
        const enriched = await withFalconMcpClient(async (client) => {
          const result = await client.callTool({
            name: "falcon_search_hosts",
            arguments: {
              filter: `device_id:[${filterClause}]`,
              limit: Math.min(egressAids.length, 500),
            },
          });
          const text = (result.content as Array<{ type: string; text?: string }>)
            .map((c) => (c.type === "text" && c.text ? c.text : ""))
            .join("\n");
          const parsed = parseConcatenatedJson<HostRecord>(text);
          if (detectFalconError(parsed)) return [];
          return parsed;
        });
        for (const h of enriched) {
          if (h.device_id) aidToHost.set(h.device_id, h);
        }
      } catch {
        // Enrichment is best-effort — AIDs without hostnames still render.
      }
    }

    const items: FleetItem[] = (egressPayload.items ?? []).map((row) => {
      const h = aidToHost.get(row.aid);
      return {
        aid: row.aid,
        hostname: h?.hostname,
        platform: h?.platform_name,
        os_product_name: h?.os_product_name,
        os_version: h?.os_version,
        rtr_state: h?.rtr_state,
        tools: row.tools,
      };
    });

    return NextResponse.json({
      ok: true,
      items,
      events_scanned: egressPayload.events_scanned ?? 0,
      hours_back: egressPayload.hours_back ?? hours,
      truncated: Boolean(egressPayload.truncated),
    });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}
