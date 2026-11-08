import { NextResponse } from "next/server";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { parseConcatenatedJson, detectFalconError, isScopeDenied } from "@/lib/mcp/parse";
import { serverError } from "@/lib/api/respond";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";
import {
  normalizeCorrelationRules,
  summarizeCorrelation,
  renderCorrelationContext,
  type CorrelationHealth,
} from "@/lib/correlation/health";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// /correlation — "Detection content health". Deterministic layer (GET): the
// tenant's published NGSIEM correlation rules, summarized server-side (active/
// inactive, severity spread, MITRE coverage, staleness). Agentic layer (POST):
// same enrichment fed as context, agent writes the decision document. Writes
// (create/update/delete rule) are gated and handed to chat via primer.

type FetchResult =
  | { kind: "scope_pending"; note: string }
  | { kind: "error"; error: string }
  | { kind: "ok"; health: CorrelationHealth };

async function fetchCorrelation(client: Client, now: number): Promise<FetchResult> {
  // state:'published' → one row per rule (otherwise every version comes back).
  const result = await client.callTool({
    name: "falcon_search_correlation_rules",
    arguments: { filter: "state:'published'", limit: 500, sort: "last_updated_on|desc" },
  });
  const text = (result.content as Array<{ type: string; text?: string }>)
    .map((c) => (c.type === "text" && c.text ? c.text : ""))
    .join("\n");

  if (isScopeDenied(text)) {
    return {
      kind: "scope_pending",
      note: "The Falcon API client does not carry the NGSIEM Correlation Rules scope.",
    };
  }

  const parsed = parseConcatenatedJson<Record<string, unknown>>(text);
  const errMsg = detectFalconError(parsed);
  if (errMsg) return { kind: "error", error: errMsg };

  const health = summarizeCorrelation(normalizeCorrelationRules(parsed), now);
  return { kind: "ok", health };
}

export async function GET() {
  try {
    const now = Date.now();
    const payload = await withFalconMcpClient(async (client) => {
      const r = await fetchCorrelation(client, now);
      if (r.kind === "scope_pending") return { ok: true, scope_pending: true, note: r.note };
      if (r.kind === "error") return { ok: false, error: r.error };
      return { ok: true, health: r.health };
    });
    return NextResponse.json(payload);
  } catch (err) {
    return serverError(err);
  }
}

function buildPrompt(): string {
  return [
    "You are reviewing the health of this tenant's NGSIEM correlation-rule content and producing a short decision document for a detection engineer.",
    "",
    "A deterministic summary of the published rules (active/inactive counts, severity spread, MITRE ATT&CK coverage, stale and inactive rules) is provided as context — treat it as ground truth and do NOT re-fetch the full rule list.",
    "",
    "You MAY call `falcon_search_correlation_rules` with a tight FQL filter (e.g. `name:'…'`) only to inspect a specific rule's definition. Do NOT create, update, or delete rules — those are operator-approved actions taken in chat, not here.",
    "",
    "## Output — produce EXACTLY these sections, in order, no preamble",
    "1. **Verdict** — one or two sentences: is the detection content healthy, or are there real gaps (sparse MITRE coverage, stale rules drifting from current TTPs, high-severity rules left inactive)?",
    "2. **Context** — the shape of the rule set: severity distribution, which MITRE tactics are well-covered vs absent, the stalest active rules, and any inactive rules that look like they should be running. Reference specific rule names.",
    "3. **Recommended actions** — a short ordered list. For each, name the rule and whether to tune/refresh it, enable it, or retire it, and why. If the content is healthy, say so plainly.",
    "",
    "Do not narrate your tool use. Emit the three sections and stop.",
  ].join("\n");
}

export async function POST() {
  return streamAgent(async ({ mcp, emit, signal }) => {
    const r = await fetchCorrelation(mcp, Date.now());
    if (r.kind === "scope_pending") {
      emit("scope_pending", { note: r.note });
      emit("done", { stop_reason: "scope_pending", iterations: 0 });
      return;
    }
    if (r.kind === "error") {
      emit("error", { message: r.error });
      return;
    }

    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildPrompt(),
      contextBlocks: [renderCorrelationContext(r.health)],
      initialMessages: [
        {
          role: "user",
          content: "Review this tenant's correlation-rule content health and produce the decision document.",
        },
      ],
      emit,
      maxTokensPerTurn: 4096,
      maxIterations: 12,
      surface: "correlation",
    });
  });
}
