// Request defaults every Claude call in Eyas shares (agent loop, sub-agents,
// /investigate synthesis, /blueprint). Pure — type-only SDK imports, no
// server-only code — so it's unit-tested in scripts/test-model-defaults.mjs.
//
// Why these exist (Claude 5.5 generation, the default since 2026-11):
// - Adaptive thinking is always on for Claude Opus 5.5 and on by default for
//   Claude Sonnet 5.5, and thinking tokens count against `max_tokens`. The old
//   per-route caps (1K–8K) were sized for reply text alone and would truncate
//   mid-answer, so every request gets at least MIN_OUTPUT_TOKENS. All callers
//   but the sub-agent loop stream; 16K also stays under the non-streaming
//   HTTP-timeout guidance.
// - Effort is set explicitly. Claude Opus 5.5 defaults to `medium` and Claude
//   Sonnet 5.5 to `high`; Eyas's routes are multistep tool use, where
//   `medium` is the recommended starting point. Models that reject the
//   parameter (Haiku 4.5, Sonnet 4.5 and older) don't get it.
// - Server-side refusal fallbacks are on for Claude Opus 5.5 and Claude
//   Sonnet 5.5. Their safety classifiers can decline security-adjacent work
//   (stop_reason "refusal"); with `fallbacks: "default"` the API re-runs a
//   declined request on the model Anthropic recommends for that refusal
//   category, inside the same call. The scalar "default" form needs the
//   `server-side-fallback-2026-07-01` beta, so every call goes through
//   `client.beta.messages`. Gateways that reject the beta are handled in
//   lib/llm/messages.ts (one retry without it, then remembered).
//
// No `temperature` / `top_p` / `thinking` / forced `tool_choice` is sent
// anywhere: all of those 400 on the 5.5 models in some form, and sampling
// parameters 400 on every model under API version 2026-10-21 (SDK ≥ 1.0).

import type Anthropic from "@anthropic-ai/sdk";

type BetaCreateParams = Anthropic.Beta.Messages.MessageCreateParamsNonStreaming;
type BetaContentBlock = Anthropic.Beta.Messages.BetaContentBlock;
type BetaContentBlockParam = Anthropic.Beta.Messages.BetaContentBlockParam;

export const MIN_OUTPUT_TOKENS = 16_000;
export const DEFAULT_EFFORT = "medium" as const;
export type Effort = NonNullable<NonNullable<BetaCreateParams["output_config"]>["effort"]>;

/** Beta header for the server-side fallback parameter (scalar `"default"` form). */
export const SERVER_FALLBACK_BETA = "server-side-fallback-2026-07-01" as const;

/**
 * Does this model id accept `output_config.effort`? Effort exists on Opus 4.5+
 * and every 4.6+ / 5.x model; it errors on Sonnet 4.5, Haiku 4.5 and older.
 * Platform prefixes (`anthropic.`, `us.anthropic.`) are tolerated.
 */
export function supportsEffort(modelId: string): boolean {
  const id = modelId.toLowerCase();
  const m = id.match(/claude-(opus|sonnet|haiku|fable|mythos)-(\d+)(?:-(\d+))?/);
  if (!m) return false;
  const family = m[1];
  const major = Number(m[2]);
  const minor = m[3] ? Number(m[3]) : 0;
  if (major >= 5) return true;
  if (major === 4 && minor >= 6) return family !== "haiku";
  if (major === 4 && minor === 5) return family === "opus";
  return false;
}

/**
 * Does this model get server-side refusal fallbacks? Claude Opus 5.5 and
 * Claude Sonnet 5.5 only: Claude Haiku 5.5 has no server-side fallback, and
 * the older models Eyas can be pointed at don't need it. Ids with a cloud
 * platform prefix (`anthropic.claude-…`, `us.anthropic.claude-…`) are
 * excluded — server-side fallback isn't offered on those platforms.
 */
export function supportsServerFallback(modelId: string): boolean {
  return /^claude-(opus|sonnet)-5-5(?![-\d])/.test(modelId.toLowerCase());
}

/** Effort levels the model accepts; xhigh arrived with Opus 4.7. */
function clampEffort(modelId: string, effort: Effort): Effort {
  if (effort === "xhigh" && /claude-(opus|sonnet)-4-6/.test(modelId.toLowerCase())) return "high";
  return effort;
}

export type ModelDefaultsOptions = {
  effort?: Effort;
  /** Attach server-side refusal fallbacks where the model supports them.
   *  Default true; lib/llm/messages.ts passes false for a gateway that has
   *  rejected the beta. */
  fallbacks?: boolean;
};

/**
 * Apply Eyas's defaults to a Messages request: a `max_tokens` floor, an
 * explicit effort where the model supports it, and server-side refusal
 * fallbacks on the 5.5 models. Returns the same params type so call sites
 * keep their SDK typing.
 */
export function withModelDefaults<T extends BetaCreateParams>(
  params: T,
  opts: ModelDefaultsOptions = {},
): T {
  const { effort = DEFAULT_EFFORT, fallbacks = true } = opts;
  const out: T = {
    ...params,
    max_tokens: Math.max(params.max_tokens, MIN_OUTPUT_TOKENS),
  };
  if (supportsEffort(params.model)) {
    out.output_config = { ...params.output_config, effort: clampEffort(params.model, effort) };
  }
  if (fallbacks && supportsServerFallback(params.model)) {
    out.betas = [...new Set([...(params.betas ?? []), SERVER_FALLBACK_BETA])];
    out.fallbacks = "default";
  }
  return out;
}

/** Did `withModelDefaults` attach server-side fallbacks to these params? */
export function hasServerFallback(params: BetaCreateParams): boolean {
  return params.fallbacks != null;
}

/**
 * The same request without server-side fallbacks: drops `fallbacks` and the
 * fallback beta (other betas stay; an emptied list is removed).
 */
export function withoutServerFallback<T extends BetaCreateParams>(params: T): T {
  const { fallbacks: _f, betas, ...rest } = params;
  const kept = (betas ?? []).filter((b) => b !== SERVER_FALLBACK_BETA);
  return (kept.length > 0 ? { ...rest, betas: kept } : rest) as T;
}

// Model-internal blocks that must not be echoed from before a fallback
// boundary: the model that declined wrote them, and the model that took over
// can't continue from them (a request echoing thinking from both sides of the
// boundary is rejected). Text and paired server-tool blocks echo normally.
const DROP_BEFORE_FALLBACK = new Set(["thinking", "redacted_thinking", "tool_use"]);
const SERVER_TOOL_CALLS = new Set(["server_tool_use", "mcp_tool_use"]);

/**
 * The assistant turn to append to the conversation for this response's
 * `content`. Unchanged unless the response contains a `fallback` block (a
 * model declined and another took over in the same call). Then the
 * `fallback` blocks stay exactly where they are, and the thinking, tool-use
 * and unpaired server-tool blocks before the LAST `fallback` block are left
 * out, as the API requires when a fallback turn is echoed back. Everything
 * after the boundary is kept as is.
 */
export function assistantTurnContent(content: BetaContentBlock[]): BetaContentBlockParam[] {
  let boundary = -1;
  content.forEach((b, i) => {
    if (b.type === "fallback") boundary = i;
  });
  if (boundary < 0) return content as BetaContentBlockParam[];
  const resultIds = new Set<string>();
  for (const b of content.slice(0, boundary)) {
    const toolUseId = (b as { tool_use_id?: unknown }).tool_use_id;
    if (!SERVER_TOOL_CALLS.has(b.type) && typeof toolUseId === "string") resultIds.add(toolUseId);
  }
  return content.filter((b, i) => {
    if (i >= boundary) return true;
    if (DROP_BEFORE_FALLBACK.has(b.type)) return false;
    if (SERVER_TOOL_CALLS.has(b.type)) return resultIds.has((b as { id: string }).id);
    return true;
  }) as BetaContentBlockParam[];
}

/**
 * The tool calls Eyas should run for this response: the `tool_use` blocks
 * after the last `fallback` boundary (all of them when there is none) — the
 * same ones `assistantTurnContent` keeps, so every executed call has its
 * `tool_use` in the echoed turn.
 */
export function toolUsesToRun(content: BetaContentBlock[]): Anthropic.Beta.Messages.BetaToolUseBlock[] {
  let boundary = -1;
  content.forEach((b, i) => {
    if (b.type === "fallback") boundary = i;
  });
  return content
    .slice(boundary + 1)
    .filter((b): b is Anthropic.Beta.Messages.BetaToolUseBlock => b.type === "tool_use");
}

/**
 * Did a fallback model serve this response? The `fallback` block marks a
 * switch inside this call, but a conversation that already fell back is
 * routed straight to the fallback model for a while ("sticky") and carries
 * no block — `usage.iterations` has a `fallback_message` entry either way.
 */
export function servedByFallback(message: {
  content: Array<{ type: string }>;
  usage?: { iterations?: Array<{ type: string }> | null } | null;
}): boolean {
  if (message.content.some((b) => b.type === "fallback")) return true;
  return (message.usage?.iterations ?? []).some((it) => it.type === "fallback_message");
}
