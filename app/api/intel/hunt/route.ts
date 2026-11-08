import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { parseConcatenatedJson } from "@/lib/mcp/parse";
import {
  matchIntelToTenant,
  type IntelHuntMatch,
  type IntelIndicator,
  type CustomIoc,
} from "@/lib/intel/hunt";
import type { Detection } from "@/components/DetectionsTable";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Pull the top recent Intel indicators (last N days), the last 30 days of
// tenant detections, and the tenant custom IOC list — then cross-reference
// in JS. Three MCP calls in parallel; deterministic match logic; one route
// returns a decision document.
const INTEL_WINDOW_DAYS = 7;
const INTEL_LIMIT = 100;
const DET_WINDOW_DAYS = 30;
const DET_LIMIT = 500;
const IOC_LIMIT = 500;

export async function GET() {
  const intelCutoff = Math.floor(
    (Date.now() - INTEL_WINDOW_DAYS * 24 * 3600 * 1000) / 1000,
  );
  const detCutoff = new Date(
    Date.now() - DET_WINDOW_DAYS * 24 * 3600 * 1000,
  ).toISOString();

  try {
    const { indicators, detections, iocs } = await withFalconMcpClient(
      async (client) => {
        // Fan all three out in parallel through the same MCP child process.
        // Falcon Intel published_date is epoch seconds — use raw integer in
        // the FQL filter, no quotes.
        const [indResp, detResp, iocResp] = await Promise.all([
          client.callTool({
            name: "falcon_search_indicators",
            arguments: {
              filter: `published_date:>${intelCutoff}+malicious_confidence:['high','medium']`,
              limit: INTEL_LIMIT,
              sort: "published_date|desc",
            },
          }),
          client.callTool({
            name: "falcon_search_detections",
            arguments: {
              filter: `product:'epp'+created_timestamp:>'${detCutoff}'`,
              limit: DET_LIMIT,
              sort: "created_timestamp.desc",
            },
          }),
          client.callTool({
            name: "falcon_search_iocs",
            arguments: { limit: IOC_LIMIT },
          }),
        ]);

        const collect = <T>(resp: typeof indResp): T[] => {
          const text = (resp.content as Array<{ type: string; text?: string }>)
            .map((c) => (c.type === "text" && c.text ? c.text : ""))
            .join("\n");
          return parseConcatenatedJson<T>(text);
        };

        return {
          indicators: collect<IntelIndicator>(indResp),
          detections: collect<Detection>(detResp),
          iocs: collect<CustomIoc>(iocResp),
        };
      },
    );

    const matches: IntelHuntMatch[] = matchIntelToTenant(
      indicators,
      detections,
      iocs,
    );

    return NextResponse.json({
      ok: true,
      matches,
      meta: {
        intel_window_days: INTEL_WINDOW_DAYS,
        detections_window_days: DET_WINDOW_DAYS,
        indicators_pulled: indicators.length,
        detections_pulled: detections.length,
        iocs_pulled: iocs.length,
        active_in_tenant: matches.filter((m) => m.verdict === "active_in_tenant").length,
        covered_by_intel: matches.filter((m) => m.verdict === "covered_by_intel").length,
        watchlist_only: matches.filter((m) => m.verdict === "watchlist_only").length,
      },
    });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}
