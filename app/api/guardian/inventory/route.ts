import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { isScopeDenied } from "@/lib/mcp/parse";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Deterministic AI-agent-activity snapshot for the /shadow-ai (AI) page — the
// falcon-mcp 0.19.0 Guardian module (AIDR:read). One cheap summary call
// (falcon_get_guardian_inventory) + the per-agent Agentic Threat Scores, so the
// page can show "what AI agents are running + is anything scoring hot" the
// moment it loads. Read-only. Degrades to scope_pending when AIDR:read is absent.

type ToolText = { type?: string; text?: string };

function joinText(result: unknown): string {
  const content = (result as { content?: ToolText[] })?.content;
  if (!Array.isArray(content)) return "";
  return content.map((c) => (c.type === "text" && c.text ? c.text : "")).join("\n");
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

type Inventory = {
  agents?: { total?: number; by_product?: Record<string, number> };
  sessions?: { total?: number };
  detections?: { hosts_with_detections?: number; max_score?: number };
};
type ScoreRow = { AgentId?: string; AgenticProductTagName?: string; maxDetectionScore?: number };

export async function GET() {
  try {
    return await withFalconMcpClient(async (client) => {
      const invResult = await client.callTool({
        name: "falcon_get_guardian_inventory",
        arguments: { time_range: "7d" },
      });
      const invText = joinText(invResult);
      if (isScopeDenied(invText)) {
        return NextResponse.json({ ok: true, scope_pending: true });
      }
      const inventory = (parseJson(invText) ?? {}) as Inventory;

      // Per-agent Agentic Threat Score — the "act now" signal. Tolerated:
      // if it errors or needs args we don't have, the card just omits scores.
      let scoreRows: ScoreRow[] = [];
      try {
        const scoreResult = await client.callTool({
          name: "falcon_get_guardian_detection_scores",
          arguments: { time_range: "7d" },
        });
        const scoreText = joinText(scoreResult);
        if (!isScopeDenied(scoreText)) {
          const parsed = parseJson(scoreText) as { results?: ScoreRow[] } | null;
          if (Array.isArray(parsed?.results)) scoreRows = parsed!.results;
        }
      } catch {
        /* scores optional */
      }

      // Dedup to one max score per agent, then rank hottest-first.
      const perAgent = new Map<string, { agentId: string; product: string; score: number }>();
      for (const r of scoreRows) {
        const id = r.AgentId ?? "";
        const score = r.maxDetectionScore ?? 0;
        if (!id) continue;
        const cur = perAgent.get(id);
        if (!cur || score > cur.score) {
          perAgent.set(id, { agentId: id, product: r.AgenticProductTagName ?? "Unclassified", score });
        }
      }
      const scored = [...perAgent.values()].sort((a, b) => b.score - a.score);

      const byProduct = inventory.agents?.by_product ?? {};
      const topProducts = Object.entries(byProduct)
        .map(([name, count]) => ({ name, count: Number(count) || 0 }))
        .sort((a, b) => b.count - a.count);

      return NextResponse.json({
        ok: true,
        summary: {
          window: "7d",
          agents: inventory.agents?.total ?? 0,
          sessions: inventory.sessions?.total ?? 0,
          products: Object.keys(byProduct).length,
          topProducts: topProducts.slice(0, 6),
          detections: {
            hosts: inventory.detections?.hosts_with_detections ?? 0,
            maxScore: inventory.detections?.max_score ?? 0,
          },
          // Elevated = the agents worth a look; keep the top handful hottest-first.
          topScored: scored.slice(0, 6),
          elevatedCount: scored.filter((s) => s.score >= 70).length,
        },
      });
    });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}

