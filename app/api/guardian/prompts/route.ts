import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Plain-language inspection of AI-agent PROMPT activity (falcon-mcp 0.19.0
// Guardian / AIDR). Prompt text is NOT in NGSIEM on this tenant — the source of
// truth is the Guardian API: falcon_search_guardian_prompts returns the actual
// `AgenticPrompt` text per session. This route lets an operator ask about
// prompts in plain English; the agent chains sessions → prompts and answers.
// Read-only, AIDR:read.
type Body = { input?: string };

function buildPrompt(): string {
  return [
    "You are inspecting AI-agent PROMPT activity for this CrowdStrike Falcon tenant (the Guardian / AIDR surface). The operator wants to ask, in plain language, about the prompts users have submitted to AI agents (Claude Code, ChatGPT Desktop, Copilot, etc.) running in the environment.",
    "",
    "Prompt text is NOT in NGSIEM — the Guardian API is the source. Use the read-only guardian tools; do NOT narrate your tool use:",
    "- `falcon_get_guardian_agent_sessions` — list recent AI-agent sessions (by product/time) to find session_ids.",
    "- `falcon_search_guardian_prompts` — the prompts submitted in a session: pass `session_id` (or `aid` to scope by host). Returns the actual `AgenticPrompt` text, `AgenticSessionId`, `aid`, and `timestamp`. THIS is where the real prompt content lives — quote it.",
    "- `falcon_search_guardian_tool_usage` / `falcon_get_guardian_session_activity` — what the agent then did (tools invoked), only if the operator asks what happened after a prompt.",
    "- `falcon_search_guardian_agents` / `falcon_get_guardian_detection_scores` — to resolve an agent or find hot agents when the operator references one.",
    "If the operator names a host, resolve it to an `aid` and scope prompts by host. If they name a session, go straight to that session's prompts. If they ask generally, pull the most recent sessions' prompts.",
    "If any tool reports the AIDR:read scope is missing, say so plainly and stop.",
    "",
    "## Answer the operator's question directly, then:",
    "- **Quote the relevant prompt text verbatim** (the `AgenticPrompt` field), attributed to its session / agent / host and timestamp. This is the whole point — don't summarize away the actual wording.",
    "- **Flag anything security-relevant** in what was prompted: attempts to access secrets/credentials, disable security controls, exfiltrate data, run destructive commands, or reach unsanctioned services.",
    "- End with a short **Recommended actions** list only if something warrants it; otherwise say the prompt activity looks benign.",
    "",
    "Cite tool calls with [N]. Do not invent prompts or citations — only report what the tools return.",
  ].join("\n");
}

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Body;
  const input =
    typeof body.input === "string" && body.input.trim()
      ? body.input.trim()
      : "Show the most recent AI-agent prompts submitted in this tenant, grouped by session, and flag anything security-relevant.";

  return streamAgent(async ({ mcp, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildPrompt(),
      initialMessages: [{ role: "user", content: input }],
      emit,
      // Read-only. Per `feedback_never_disable_approvals`, no requiresApproval
      // override — Guardian has no writes.
      maxTokensPerTurn: 8192,
      maxIterations: 14,
      surface: "guardian",
    });
  });
}
