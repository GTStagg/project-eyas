import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";
import { buildBriefingPrompt } from "@/lib/briefing/prompt";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST() {
  return streamAgent(async ({ mcp, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildBriefingPrompt(),
      initialMessages: [
        { role: "user", content: "Generate today's security briefing now." },
      ],
      emit,
      // Briefings are read-only by design; bypass the approval gate.
      maxTokensPerTurn: 8192,
      maxIterations: 16,
      surface: "briefing",
    });
  });
}
