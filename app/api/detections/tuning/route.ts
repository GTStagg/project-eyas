import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { parseConcatenatedJson } from "@/lib/mcp/parse";
import { findTuningCandidates, type TuningCandidate } from "@/lib/queue/tuning";
import type { Detection } from "@/components/DetectionsTable";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const WINDOW_DAYS = 30;
const FETCH_LIMIT = 500;

export async function GET() {
  const cutoff = new Date(
    Date.now() - WINDOW_DAYS * 24 * 60 * 60 * 1000,
  ).toISOString();

  try {
    const items = await withFalconMcpClient(async (client) => {
      // 30-day window, ALL statuses (need closed FP/TP for the rate calc).
      // product:'epp' to keep NGSIEM correlation rules + IDP policy events
      // out of the analysis — those need their own tuning surface.
      const filter = `product:'epp'+created_timestamp:>'${cutoff}'`;
      const result = await client.callTool({
        name: "falcon_search_detections",
        arguments: {
          filter,
          limit: FETCH_LIMIT,
          sort: "created_timestamp.desc",
        },
      });
      const text = (result.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      return parseConcatenatedJson<Detection & { status?: string }>(text);
    });

    const candidates: TuningCandidate[] = findTuningCandidates(items);

    return NextResponse.json({
      ok: true,
      candidates,
      meta: {
        window_days: WINDOW_DAYS,
        sampled: items.length,
        candidate_count: candidates.length,
        // Signal when the 30-day pull hit the fetch cap — the FP-rate calc is
        // then computed over a sample, not the full window, so a noisy rule
        // just past the cap can be under-counted. The UI surfaces this so an
        // operator doesn't read "0 candidates" as "nothing to tune".
        truncated: items.length >= FETCH_LIMIT,
      },
    });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}
