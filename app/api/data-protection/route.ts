import { NextResponse } from "next/server";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { serverError } from "@/lib/api/respond";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";
import {
  normalizePolicies,
  normalizeContentPatterns,
  classificationNames,
  summarizeDataProtection,
  renderDataProtectionContext,
  type DpPosture,
} from "@/lib/dataprotection/posture";
import { fetchDataSecurityEntities } from "@/lib/dataprotection/fetch";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// /data-protection — "Data exposure posture". Read-only. Deterministic layer
// (GET): the tenant's DP policies (win+mac), classifications, and content
// patterns, summarized server-side. Agentic layer (POST): same config posture
// fed as context; the agent additionally ties it to live evidence by pulling
// recent `product:'data-protection'` detections. No writes on this surface.

type FetchResult =
  | { kind: "scope_pending"; note: string }
  | { kind: "error"; error: string }
  | { kind: "ok"; posture: DpPosture };

async function fetchDataProtection(client: Client): Promise<FetchResult> {
  // Policies require platform_name. Probe win first — if the scope is missing,
  // short-circuit before the other calls.
  const win = await fetchDataSecurityEntities(client, "policy", { platform_name: "win" });
  if (win.kind === "scope_pending") {
    return {
      kind: "scope_pending",
      note: "The Falcon API client does not carry the Data Protection scope.",
    };
  }
  if (win.kind === "error") return win;

  const [mac, classes, patterns] = await Promise.all([
    fetchDataSecurityEntities(client, "policy", { platform_name: "mac" }),
    fetchDataSecurityEntities(client, "classification"),
    fetchDataSecurityEntities(client, "content_pattern"),
  ]);
  // Don't let a wrapped upstream error on any of the three collapse to an empty
  // posture that falsely reads as "no DLP config". Surface the first failure.
  for (const r of [mac, classes, patterns]) {
    if (r.kind === "error") return r;
  }
  const rowsOf = (r: typeof mac) => (r.kind === "ok" ? r.rows : []);

  const policies = [
    ...normalizePolicies(win.rows, "win"),
    ...normalizePolicies(rowsOf(mac), "mac"),
  ];
  const classifications = classificationNames(rowsOf(classes));
  const contentPatterns = normalizeContentPatterns(rowsOf(patterns));

  return {
    kind: "ok",
    posture: summarizeDataProtection(policies, classifications, contentPatterns),
  };
}

export async function GET() {
  try {
    const payload = await withFalconMcpClient(async (client) => {
      const r = await fetchDataProtection(client);
      if (r.kind === "scope_pending") return { ok: true, scope_pending: true, note: r.note };
      if (r.kind === "error") return { ok: false, error: r.error };
      return { ok: true, posture: r.posture };
    });
    return NextResponse.json(payload);
  } catch (err) {
    return serverError(err);
  }
}

function buildPrompt(): string {
  return [
    "You are assessing this tenant's CrowdStrike Falcon Data Protection posture and producing a short decision document for a security operator.",
    "",
    "A deterministic summary of the Data Protection configuration (policies per platform, classifications, content patterns) is provided as context — treat it as ground truth and do NOT re-fetch that config.",
    "",
    "Tie the configuration to live evidence: call `falcon_search_detections` with `filter` set to `product:'data-protection'` (limit ~100, recent first) to see what is actually firing — which hosts, how often. You MAY also call `falcon_search_data_security_entities` with `entity_type` set to `content_pattern` or `classification` and a tight filter to inspect a specific pattern referenced by a detection (then `falcon_get_data_security_entities` for its full definition). This surface is read-only — do NOT attempt any write.",
    "",
    "## Output — produce EXACTLY these sections, in order, no preamble",
    "1. **Verdict** — one or two sentences: is Data Protection actively enforcing and catching real exposure, only monitoring (default policy, nothing custom enabled), or effectively dormant (firing nothing)?",
    "2. **Context** — the posture: how many policies are enabled vs default-only, the precedence picture, which content-pattern categories exist, and what the recent `product:'data-protection'` detections show (top hosts / patterns firing). Reference specifics.",
    "3. **Recommended actions** — a short ordered list (enable enforcement, reorder precedence, tune a noisy or silent content pattern, add coverage for an unmonitored data category). If posture is healthy, say so plainly.",
    "",
    "Do not narrate your tool use. Emit the three sections and stop.",
  ].join("\n");
}

export async function POST() {
  return streamAgent(async ({ mcp, emit, signal }) => {
    const r = await fetchDataProtection(mcp);
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
      contextBlocks: [renderDataProtectionContext(r.posture)],
      initialMessages: [
        {
          role: "user",
          content: "Assess this tenant's Data Protection posture and produce the decision document.",
        },
      ],
      emit,
      maxTokensPerTurn: 4096,
      maxIterations: 12,
      surface: "data-protection",
    });
  });
}
