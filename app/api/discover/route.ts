import { NextResponse } from "next/server";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { nativeDiscoverEntity } from "@/lib/discover/native";
import { serverError } from "@/lib/api/respond";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";
import {
  normalizeAssets,
  normalizeApplications,
  normalizeAccounts,
  summarizeDiscover,
  renderDiscoverContext,
  type DiscoverSnapshot,
  type DiscoverSummary,
} from "@/lib/discover/inventory";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// /discover — Falcon Discover asset / application / account inventory.
// Deterministic layer (GET): fetch a sample of each entity via the sidecar's
// extras_discover_* tools and compute a posture summary (coverage gaps,
// privileged accounts, suspicious software) server-side. Agentic layer (POST):
// same enrichment fed as context; the agent writes the posture decision
// document. Discover is read-only — no writes, no primer hand-off needed.
//
// Assets + applications come from the EXTRAS (FalconPy) client (one record
// shape across managed / unmanaged); accounts come from the MCP server's
// native falcon_search_accounts (a strict superset of the former sidecar
// tool's fields) via lib/discover/native.ts.

const SAMPLE = 100; // Discover query max per entity

function parseToolJson(result: unknown): Record<string, unknown> | null {
  const content = (result as { content?: unknown })?.content;
  const text = (Array.isArray(content) ? content : ([] as Array<{ type: string; text?: string }>))
    .map((c) => (c.type === "text" && c.text ? c.text : ""))
    .join("\n");
  try {
    const j = JSON.parse(text) as unknown;
    return j && typeof j === "object" ? (j as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

async function callDiscover(
  extras: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown> | null> {
  const r = await extras.callTool({ name, arguments: { limit: SAMPLE, ...args } });
  return parseToolJson(r);
}

async function fetchDiscover(extras: Client, mcp: Client): Promise<{
  snapshot: DiscoverSnapshot;
  summary: DiscoverSummary;
}> {
  const [assetsRaw, appsRaw, accountsRaw] = await Promise.all([
    callDiscover(extras, "extras_discover_assets", { scope: "all" }),
    callDiscover(extras, "extras_discover_applications", {}),
    nativeDiscoverEntity(mcp, "falcon_search_accounts", { limit: SAMPLE }),
  ]);
  const snapshot: DiscoverSnapshot = {
    assets: normalizeAssets(assetsRaw),
    applications: normalizeApplications(appsRaw),
    accounts: normalizeAccounts(accountsRaw),
  };
  return { snapshot, summary: summarizeDiscover(snapshot) };
}

// GET — deterministic summary + scope_pending (no LLM). Drives the page's
// instant cards, entity tables, and scope banner.
export async function GET() {
  try {
    const payload = await withFalconMcpClient((mcp) => withFalconExtrasClient(async (extras) => {
      const { snapshot, summary } = await fetchDiscover(extras, mcp);
      if (summary.scopePending) {
        return {
          ok: true,
          scope_pending: true,
          note: "The Falcon API client does not carry the asset-inventory (Falcon Discover) scope.",
        };
      }
      return { ok: true, summary, snapshot };
    }));
    return NextResponse.json(payload);
  } catch (err) {
    return serverError(err);
  }
}

function buildPrompt(): string {
  return [
    "You are reviewing the CrowdStrike Falcon Discover inventory for this tenant and producing a short posture decision document for a SOC operator.",
    "",
    "A deterministic summary of the current inventory (asset / application / account counts, coverage gaps, privileged accounts, suspicious software) is provided to you as context — treat it as ground truth and do NOT re-fetch the full inventory. The counts are a sampled subset; tenant-wide totals are labelled 'total'.",
    "",
    "## Output — produce EXACTLY these sections, in order, no preamble",
    "1. **Verdict** — one or two sentences: does the inventory show anything that warrants operator action (unmanaged endpoints with no sensor, risky local-admin sprawl, suspicious software), or is posture healthy?",
    "2. **Context** — what the inventory shows: managed vs unmanaged asset coverage, notable platforms, privileged / local-admin accounts and password hygiene, and any applications flagged suspicious. Reference specific hostnames, account names, and application names from the summary.",
    "3. **Recommended actions** — a short ordered list. Concrete steps: deploy a sensor to named unmanaged hosts, review named local-admin accounts, investigate named suspicious applications. If nothing warrants action, say so plainly.",
    "",
    "Do not narrate your tool use. Emit the three sections and stop.",
  ].join("\n");
}

// POST — agentic posture decision document. Same deterministic enrichment,
// injected as an uncached context block, then the agent synthesizes.
export async function POST() {
  return streamAgent(async ({ mcp, extras, emit, signal }) => {
    const { summary } = await fetchDiscover(extras, mcp);
    if (summary.scopePending) {
      emit("scope_pending", {
        note: "The Falcon API client does not carry the asset-inventory (Falcon Discover) scope.",
      });
      emit("done", { stop_reason: "scope_pending", iterations: 0 });
      return;
    }

    await runAgentLoop({
      signal,
      mcp,
      extrasMcp: extras,
      systemPrompt: buildPrompt(),
      contextBlocks: [renderDiscoverContext(summary)],
      initialMessages: [
        {
          role: "user",
          content:
            "Review the Falcon Discover inventory for this tenant and produce the posture decision document.",
        },
      ],
      emit,
      maxTokensPerTurn: 4096,
      maxIterations: 10,
      surface: "discover",
    });
  });
}
