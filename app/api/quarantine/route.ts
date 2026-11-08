import { NextResponse } from "next/server";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { parseConcatenatedJson, detectFalconError, isScopeDenied } from "@/lib/mcp/parse";
import { serverError } from "@/lib/api/respond";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";
import {
  normalizeQuarantineRecords,
  summarizeQuarantine,
  renderQuarantineContext,
  type QuarantineSummary,
} from "@/lib/quarantine/review";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// /quarantine — "Quarantine review". Deterministic layer (GET): fetch the
// tenant's quarantined files, cluster by host + hash server-side. Agentic layer
// (POST): same enrichment fed as context, agent writes the verdict/context/
// actions decision document. Writes (release / unrelease / delete) are NOT done
// here — they're gated and handed to chat via primer from the page.

// Scope-denial detection is shared with probeFalconMcp() via isScopeDenied()
// (lib/mcp/parse.ts), so the nav capability gate and the page can't disagree
// on scope state.

type FetchResult =
  | { kind: "scope_pending"; note: string }
  | { kind: "error"; error: string }
  | { kind: "ok"; summary: QuarantineSummary };

// Shared fetch + deterministic enrichment for both GET and POST.
async function fetchQuarantine(client: Client): Promise<FetchResult> {
  const result = await client.callTool({
    name: "falcon_search_quarantined_files",
    arguments: { limit: 500, sort: "date_updated|desc" },
  });
  const text = (result.content as Array<{ type: string; text?: string }>)
    .map((c) => (c.type === "text" && c.text ? c.text : ""))
    .join("\n");

  if (isScopeDenied(text)) {
    return {
      kind: "scope_pending",
      note: "The Falcon API client does not carry the Quarantine scope.",
    };
  }

  const parsed = parseConcatenatedJson<Record<string, unknown>>(text);
  const errMsg = detectFalconError(parsed);
  if (errMsg) return { kind: "error", error: errMsg };

  const summary = summarizeQuarantine(normalizeQuarantineRecords(parsed));
  return { kind: "ok", summary };
}

// GET — deterministic summary + scope_pending (no LLM). Drives the page's
// instant summary cards, record table, and scope banner.
export async function GET() {
  try {
    const payload = await withFalconMcpClient(async (client) => {
      const r = await fetchQuarantine(client);
      if (r.kind === "scope_pending") return { ok: true, scope_pending: true, note: r.note };
      if (r.kind === "error") return { ok: false, error: r.error };
      return { ok: true, summary: r.summary };
    });
    return NextResponse.json(payload);
  } catch (err) {
    return serverError(err);
  }
}

function buildPrompt(): string {
  return [
    "You are reviewing the CrowdStrike Falcon quarantine for this tenant and producing a short decision document for a SOC operator.",
    "",
    "A deterministic summary of the current quarantine state (counts, host/hash clusters, sample records) is provided to you as context — treat it as ground truth and do NOT re-fetch the full list.",
    "",
    "You MAY call `falcon_preview_quarantine_actions` with an FQL filter to estimate the blast radius (action counts) of a potential release or delete on a specific host or hash before recommending it. You may call `falcon_search_quarantined_files` only to pull detail on a specific record (filter by `sha256:'…'` or `hostname:'…'`). Do NOT call release / unrelease / delete — those are operator-approved actions taken in chat, not here.",
    "",
    "## Output — produce EXACTLY these sections, in order, no preamble",
    "1. **Verdict** — one or two sentences: is anything in quarantine that needs operator action (a clean file to release, or confirmed-malicious to purge), or is the quarantine healthy and unremarkable?",
    "2. **Context** — what's quarantined: notable host/hash clusters, repeat hosts, possible campaign spread, and how much is already released vs still held. Reference specific hostnames and hashes from the summary.",
    "3. **Recommended actions** — a short ordered list. For each, name the exact host + sha256 and whether you'd release (false positive) or delete (confirmed malicious), and why. Keep it to the items that actually warrant action; if none do, say so plainly.",
    "",
    "Do not narrate your tool use. Emit the three sections and stop.",
  ].join("\n");
}

// POST — agentic decision document. Same deterministic enrichment, injected as
// an uncached context block, then the agent synthesizes.
export async function POST() {
  return streamAgent(async ({ mcp, emit, signal }) => {
    const r = await fetchQuarantine(mcp);
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
      contextBlocks: [renderQuarantineContext(r.summary)],
      initialMessages: [
        {
          role: "user",
          content:
            "Review the current quarantine for this tenant and produce the decision document.",
        },
      ],
      emit,
      maxTokensPerTurn: 4096,
      maxIterations: 12,
      surface: "quarantine",
    });
  });
}
