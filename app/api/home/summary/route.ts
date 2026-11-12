import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { fetchContainedAids } from "@/lib/hosts/contained";
import { detectFalconError, parseConcatenatedJson } from "@/lib/mcp/parse";
import { rankDetections, type RankInput, type QueueRow } from "@/lib/queue/rank";
import { clusterCampaigns, type Campaign } from "@/lib/queue/campaigns";
import type { Detection } from "@/components/DetectionsTable";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Fast, deterministic dashboard summary. This is the CHEAP subset of
// /api/queue: it runs the endpoint-detection search + contained-host lookup,
// then the pure rankDetections + clusterCampaigns functions — and deliberately
// SKIPS the expensive per-host identity correlation fan-out and adversary
// resolution that make /api/queue ~10s. That keeps /home loadable on every
// visit (~2-3s) while still surfacing the two signals the dashboard hero needs:
// cross-host campaigns and the top-ranked open detections.
//
// Detection-centric by design; the host-centric view lives on /hosts and the
// full ranked queue (with identity + adversary overlays) on /queue.

const WINDOW_DAYS = 14;
const ENDPOINT_LIMIT = 200;
const TOP_N = 6;


export async function GET() {
  const cutoff = new Date(
    Date.now() - WINDOW_DAYS * 24 * 60 * 60 * 1000,
  ).toISOString();

  try {
    const [detections, containedAids] = await Promise.all([
      fetchOpenEndpointDetections(cutoff),
      fetchContainedAids(),
    ]);

    const merged: RankInput[] = detections.map((d) => ({
      ...d,
      source: "epp" as const,
    }));
    const rows: QueueRow[] = rankDetections(merged, containedAids);
    const campaigns: Campaign[] = clusterCampaigns(merged, containedAids);

    const distinctHosts = new Set(
      rows.map((r) => r.device?.hostname).filter(Boolean),
    ).size;

    return NextResponse.json({
      ok: true,
      generatedAt: new Date().toISOString(),
      counts: {
        total: rows.length,
        top: rows.filter((r) => r.bucket === "top").length,
        active: rows.filter((r) => r.bucket === "active").length,
        stale: rows.filter((r) => r.bucket === "stale").length,
        contained: containedAids.size,
        hosts: distinctHosts,
      },
      campaigns,
      top: rows.filter((r) => r.bucket === "top").slice(0, TOP_N),
    });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}

async function fetchOpenEndpointDetections(cutoffIso: string): Promise<Detection[]> {
  return withFalconMcpClient(async (client) => {
    // Same scoping as /api/queue: endpoint detections only, open statuses.
    const filter =
      `product:'epp'+` +
      `created_timestamp:>'${cutoffIso}'+` +
      `status:['new','reopened','in_progress']`;
    const result = await client.callTool({
      name: "falcon_search_detections",
      arguments: { filter, limit: ENDPOINT_LIMIT, sort: "created_timestamp.desc" },
    });
    const text = (result.content as Array<{ type: string; text?: string }>)
      .map((c) => (c.type === "text" && c.text ? c.text : ""))
      .join("\n");
    const detections = parseConcatenatedJson<Detection>(text);
    // Promote a wrapped upstream error / structured scope-denial to a real
    // failure rather than rendering it as junk. detectFalconError (NOT
    // isScopeDenied) — the latter's prose fallback false-positives on
    // legitimate detection names.
    const err = detectFalconError(detections);
    if (err) throw new Error(err);
    return detections;
  });
}

