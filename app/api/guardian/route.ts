import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// AI-agent-activity posture (falcon-mcp 0.19.0 Guardian module, AIDR:read).
// One-click decision document, same shape as /api/intel + /api/identity: the
// agent calls the read-only guardian tools itself and synthesizes. All Guardian
// tools are reads, so no approval gate is involved.
function buildPrompt(): string {
  return [
    "You are reviewing this CrowdStrike Falcon tenant's AI-agent activity (the Guardian / AIDR surface) and producing a short posture decision document for a SOC operator.",
    "",
    "Gather with the read-only guardian tools — do NOT narrate your tool use, just call them:",
    "- `falcon_get_guardian_inventory` (time_range 7d) — the high-level fleet AI-activity summary. Start here.",
    "- `falcon_search_guardian_agents` — the AI agents seen in the tenant (product, hostname).",
    "- `falcon_get_guardian_detection_scores` — the Agentic Threat Score per agent; lead with anything elevated.",
    "- `falcon_search_guardian_mcp_servers` and `falcon_search_guardian_models` — the MCP servers and models in use.",
    "Call `falcon_search_guardian_tools` / `falcon_search_guardian_prompts` / `falcon_get_guardian_session_activity` only if a specific agent or session warrants a closer look. If any tool reports the AIDR:read scope is missing, say so plainly and stop.",
    "",
    "## Output — produce EXACTLY these sections, in order, no preamble",
    "1. **Verdict** — one or two sentences: is AI-agent activity in this tenant benign and expected, or is there something an operator should act on (an unknown agent, an elevated Agentic Threat Score, an unexpected MCP server or model, sensitive-file access by an agent)?",
    "2. **Context** — what's running: how many agents/sessions/models, which products, notable MCP servers, and any agents with elevated threat scores. Reference specific agent names, hostnames, and model names from the tool results.",
    "3. **Recommended actions** — a short ordered list. Concrete steps: investigate a named high-score agent, review an unexpected MCP server or model, confirm an agent is sanctioned. If activity is healthy, say so plainly.",
    "",
    "Cite tool calls with [N] where N is the tool-call number that produced the fact. Do not invent citations.",
  ].join("\n");
}

export async function POST() {
  return streamAgent(async ({ mcp, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildPrompt(),
      initialMessages: [
        { role: "user", content: "Review AI-agent activity for this tenant now." },
      ],
      emit,
      // Read-only synthesis. Per `feedback_never_disable_approvals`, do NOT pass
      // requiresApproval — let it default to the registry (Guardian has no writes).
      maxTokensPerTurn: 8192,
      maxIterations: 12,
      surface: "guardian",
    });
  });
}
