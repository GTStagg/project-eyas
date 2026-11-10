// Request defaults every Claude call in Eyas shares (agent loop, sub-agents,
// /investigate synthesis, /blueprint). Pure — no server-only imports — so it's
// unit-tested in scripts/test-model-defaults.mjs.
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
//
// No `temperature` / `top_p` / `thinking` / forced `tool_choice` is sent
// anywhere: all of those 400 on the 5.5 models in some form.

export const MIN_OUTPUT_TOKENS = 16_000;
export const DEFAULT_EFFORT = "medium" as const;
export type Effort = "low" | "medium" | "high" | "xhigh" | "max";

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

/** Effort levels the model accepts; xhigh arrived with Opus 4.7. */
function clampEffort(modelId: string, effort: Effort): Effort {
  if (effort === "xhigh" && /claude-(opus|sonnet)-4-6/.test(modelId.toLowerCase())) return "high";
  return effort;
}

/**
 * Apply Eyas's defaults to a Messages request: a `max_tokens` floor and an
 * explicit effort where the model supports it. Returns the same params type so
 * call sites keep their SDK typing (the pinned SDK predates typed
 * `output_config`, so it's attached untyped).
 */
export function withModelDefaults<T extends { model: string; max_tokens: number }>(
  params: T,
  effort: Effort = DEFAULT_EFFORT,
): T {
  const out: T & { output_config?: { effort: Effort } } = {
    ...params,
    max_tokens: Math.max(params.max_tokens, MIN_OUTPUT_TOKENS),
  };
  if (supportsEffort(params.model)) out.output_config = { effort: clampEffort(params.model, effort) };
  return out;
}
