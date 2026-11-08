import "server-only";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { buildBriefingPrompt } from "@/lib/briefing/prompt";
import { deliverToWebhook, getOutboundWebhookUrl } from "@/lib/webhook/deliver";
import type { JobDefinition } from "./types";
import type { JobResult } from "@/lib/scheduler/recurring";

async function runDailyBriefing(): Promise<JobResult> {
  if (!getOutboundWebhookUrl()) {
    return { kind: "skipped", message: "OUTBOUND_WEBHOOK_URL is not configured." };
  }

  let buffer = "";
  let agentError: string | null = null;
  try {
    await withFalconMcpClient(async (mcp) => {
      await runAgentLoop({
        mcp,
        systemPrompt: buildBriefingPrompt(),
        initialMessages: [
          { role: "user", content: "Generate today's security briefing now." },
        ],
        emit: (event, data) => {
          if (event === "iteration_start") {
            buffer = "";
          } else if (event === "text" && typeof data === "string") {
            buffer += data;
          } else if (event === "error") {
            const msg =
              typeof data === "object" && data && "message" in data
                ? String((data as { message?: unknown }).message ?? "")
                : String(data ?? "");
            agentError = msg || "agent loop emitted an error event";
          }
        },
        maxTokensPerTurn: 8192,
        maxIterations: 16,
        surface: "briefing",
      });
    });
  } catch (err) {
    return { kind: "error", message: err instanceof Error ? err.message : String(err) };
  }

  if (agentError) return { kind: "error", message: agentError };
  const markdown = buffer.trim();
  if (!markdown) return { kind: "error", message: "Agent produced no markdown." };

  const today = new Date().toISOString().slice(0, 10);
  const result = await deliverToWebhook({
    title: `Daily security briefing — ${today}`,
    source: "scheduled-daily-briefing",
    markdown,
  });
  if (!result.ok) return { kind: "error", message: result.error };
  return {
    kind: "delivered",
    message: `delivered ${result.chunks} chunk(s); ${markdown.length} chars`,
  };
}

export const dailyBriefingJob: JobDefinition = {
  id: "daily-briefing",
  label: "Daily security briefing",
  defaultHour: 9,
  defaultMinute: 0,
  defaultWeekdays: [1, 2, 3, 4, 5], // Mon–Fri
  run: runDailyBriefing,
};
