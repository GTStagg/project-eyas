import "server-only";
import Anthropic from "@anthropic-ai/sdk";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getAnthropicClient, getAnthropicModel } from "@/lib/llm/anthropic";
import { createMessage } from "@/lib/llm/messages";
import { assistantTurnContent, toolUsesToRun } from "@/lib/llm/request";
import { withHistoryCacheMarker } from "@/lib/llm/prompt-cache";
import { buildToolBridge } from "@/lib/mcp/tool-bridge";
import { maybeFenceToolResult } from "@/lib/chat/agent-loop";
import { requiresApproval as defaultRequiresApproval } from "@/lib/mcp/write-tools";
import { logUsage, type Surface } from "@/lib/cost/log";

// Sub-agent loop. A focused, non-streaming agent loop with:
//   - A scoped tool subset (filter by name)
//   - Smaller iteration budget
//   - Returns structured result instead of streaming SSE events
//   - Owns no MCP clients itself — caller passes them; this is intentional so
//     a parent route can spawn N parallel client pairs (one per subagent) for
//     true concurrency, since falcon-mcp serializes requests within a single
//     client per the persistent-singleton lesson.
//
// Use cases:
//   - Parent route fans out 3 parallel "data slice" subagents, each with its
//     own MCP client pair, then synthesizes the slices in a final pass.
//   - Tool-restricted phase isolation: pass a `toolFilter` that excludes
//     write-shape tools so the subagent literally cannot call them
//     (defense-in-depth beyond the approval gate).
//
// What this does NOT do:
//   - Stream tokens as they arrive. Subagents complete fully and return text.
//     The caller can stream a final synthesis pass through the regular
//     runAgentLoop or anthropic.messages.stream if it wants live tokens for
//     the user-facing report.
//   - Handle approval gating. Subagents are read-only by convention — pass a
//     `toolFilter` that excludes write tools rather than relying on the
//     gate. Writes belong in the parent loop where the operator's approval
//     dialogs are stable.

export type SubAgentOptions = {
  mcp: Client;
  systemPrompt: string;
  /** The user message kicking off this subagent. Subagents are typically
   *  one-shot — a single user prompt eliciting a focused report slice. */
  userPrompt: string;
  /** Optional predicate: only tools whose name returns true are exposed to
   *  this subagent. Use to scope the subagent's toolset and to enforce
   *  read-only by tool selection (e.g. exclude any name matching write
   *  patterns). Default: all tools exposed. */
  toolFilter?: (toolName: string) => boolean;
  /** Default: 8. Subagents should be tightly scoped — if you need 20+
   *  iterations, the task probably belongs in the parent or in a different
   *  decomposition. */
  maxIterations?: number;
  maxTokensPerTurn?: number;
  /** Identifies the subagent for cost-log attribution. Surfaces with
   *  multiple subagents should use distinct surface names (e.g.
   *  "investigate:fingerprint", "investigate:threats") so /cost-summary
   *  can show the per-slice breakdown. */
  surface?: Surface;
  /** Inherits the parent route's abort signal. When the user clicks Stop,
   *  the parent's signal aborts; subagents check it at iteration boundaries
   *  and exit cleanly. */
  signal?: AbortSignal;
};

export type SubAgentToolCall = {
  name: string;
  input: unknown;
  output: string;
  is_error: boolean;
  duration_ms: number;
};

export type SubAgentResult = {
  /** Final assistant text (the rendered report slice or analysis). */
  text: string;
  iterations: number;
  /** All tool calls the subagent made, in order. Useful for parent-side
   *  telemetry / surfacing in the UI ("Fingerprint: 4 tool calls in 8s"). */
  toolCalls: SubAgentToolCall[];
  usage: {
    input_tokens: number;
    output_tokens: number;
    cache_creation_input_tokens: number;
    cache_read_input_tokens: number;
  };
  /** Wall-clock duration of the subagent loop. */
  duration_ms: number;
  /** True if loop ended on `end_turn`; false if cancelled, hit max
   *  iterations, or errored. Caller should check this before treating
   *  `text` as authoritative. */
  endedNormally: boolean;
};

const DEFAULT_MAX_ITERATIONS = 8;
const DEFAULT_MAX_TOKENS = 4096;

export async function runSubAgent(opts: SubAgentOptions): Promise<SubAgentResult> {
  const startedAt = Date.now();
  const {
    mcp,
    systemPrompt,
    userPrompt,
    toolFilter,
    maxIterations = DEFAULT_MAX_ITERATIONS,
    maxTokensPerTurn = DEFAULT_MAX_TOKENS,
    surface,
    signal,
  } = opts;

  const isCancelled = () => signal?.aborted === true;

  const bridge = await buildToolBridge(mcp);
  // Belt-and-suspenders: subagents are read-only by convention. If a caller's
  // `toolFilter` accidentally allows a write-shape tool, REQUIRES_APPROVAL
  // would silently bypass here (the subagent loop has no operator-facing
  // approval dialog). Reject write tools at filter time so this can never
  // happen — the safest answer is "the tool isn't even visible to the
  // subagent." If a future use case genuinely needs a subagent to call a
  // write tool, the right answer is to do that write in the parent loop
  // (where approval gating works) and pass the result down, not to relax
  // this guard.
  // Same for the fail-closed backstops: a native tool annotated as a write but
  // missing from the registry, or an Eyas tool not yet classified, is
  // treated as a write and hidden.
  const safeFilter = (name: string): boolean => {
    if (defaultRequiresApproval(name)) return false;
    if (bridge.annotatedNativeWrites.has(name)) return false;
    if (bridge.unclassifiedEyasTools.has(name)) return false;
    return toolFilter ? toolFilter(name) : true;
  };
  const filteredTools = bridge.anthropicTools.filter((t) => safeFilter(t.name));

  // Cache the subagent's tools-block on the last entry. Each subagent has a
  // different tool subset → different cache prefix → independent cache.
  // This is actually a cache *win*: smaller stable toolsets cache cleaner
  // than one giant union of every tool.
  const tools =
    filteredTools.length > 0
      ? filteredTools.map((t, i, arr) =>
          i === arr.length - 1
            ? { ...t, cache_control: { type: "ephemeral" as const, ttl: "1h" as const } }
            : t,
        )
      : filteredTools;

  const anthropic = getAnthropicClient();
  const conversation: Anthropic.Beta.BetaMessageParam[] = [
    { role: "user", content: userPrompt },
  ];

  const totals = {
    input_tokens: 0,
    output_tokens: 0,
    cache_creation_input_tokens: 0,
    cache_read_input_tokens: 0,
  };
  const toolCalls: SubAgentToolCall[] = [];
  let finalText = "";
  let iterationsRun = 0;
  let endedNormally = false;

  outer: for (let iter = 0; iter < maxIterations; iter++) {
    iterationsRun = iter + 1;
    if (isCancelled()) break;

    let finalMessage: Anthropic.Beta.BetaMessage;
    try {
      finalMessage = await createMessage(
        anthropic,
        {
          model: getAnthropicModel(),
          max_tokens: maxTokensPerTurn,
          system: [
            {
              type: "text",
              text: systemPrompt,
              cache_control: { type: "ephemeral", ttl: "5m" },
            },
          ],
          tools,
          // Cache the history so each iteration reads it back (prompt-cache.ts).
          messages: withHistoryCacheMarker(conversation, "5m"),
        },
        { signal },
      );
    } catch (err) {
      if (isCancelled() || (err instanceof Error && err.name === "AbortError")) break;
      throw err;
    }

    const u = finalMessage.usage;
    if (u) {
      totals.input_tokens += u.input_tokens ?? 0;
      totals.output_tokens += u.output_tokens ?? 0;
      totals.cache_creation_input_tokens += u.cache_creation_input_tokens ?? 0;
      totals.cache_read_input_tokens += u.cache_read_input_tokens ?? 0;
    }

    // Capture the assistant's text content from this turn. The last turn's
    // text (when stop_reason === "end_turn") is the subagent's final output.
    const textBlocks = finalMessage.content
      .filter((b): b is Anthropic.Beta.BetaTextBlock => b.type === "text")
      .map((b) => b.text)
      .join("");

    if (finalMessage.stop_reason === "end_turn") {
      conversation.push({ role: "assistant", content: assistantTurnContent(finalMessage.content) });
      finalText = textBlocks;
      endedNormally = true;
      break outer;
    }

    if (finalMessage.stop_reason !== "tool_use") {
      // Unexpected stop (max_tokens, or a safety "refusal") — return what we have.
      finalText =
        textBlocks || (finalMessage.stop_reason === "refusal" ? "(This slice was declined by the model.)" : "");
      break outer;
    }

    conversation.push({ role: "assistant", content: assistantTurnContent(finalMessage.content) });

    const toolUses = toolUsesToRun(finalMessage.content);

    const toolResults: Anthropic.Beta.BetaToolResultBlockParam[] = [];
    for (const tu of toolUses) {
      const input = (tu.input ?? {}) as Record<string, unknown>;
      const tStart = Date.now();
      try {
        const result = await bridge.invoke(tu.name, input);
        // tool-bridge.invoke already joins MCP blocks into a single string (see
        // tool_bridge_content_is_string). The prior `Array.isArray` check was
        // always false here, so every trace rendered an empty result body.
        const text = result.content;
        toolCalls.push({
          name: tu.name,
          input,
          output: text,
          is_error: Boolean(result.isError),
          duration_ms: Date.now() - tStart,
        });
        toolResults.push({
          type: "tool_result",
          tool_use_id: tu.id,
          content: maybeFenceToolResult(tu.name, result.content),
          is_error: result.isError,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        toolCalls.push({
          name: tu.name,
          input,
          output: message,
          is_error: true,
          duration_ms: Date.now() - tStart,
        });
        toolResults.push({
          type: "tool_result",
          tool_use_id: tu.id,
          content: message,
          is_error: true,
        });
      }
    }

    conversation.push({ role: "user", content: toolResults });
  }

  const result: SubAgentResult = {
    text: finalText,
    iterations: iterationsRun,
    toolCalls,
    usage: totals,
    duration_ms: Date.now() - startedAt,
    endedNormally,
  };

  if (surface) {
    void logUsage({
      ts: new Date().toISOString(),
      model: getAnthropicModel(),
      surface,
      iterations: iterationsRun,
      usage: totals,
    });
  }

  return result;
}
