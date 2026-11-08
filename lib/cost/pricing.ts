// Per-million-token prices in USD for Claude API models, current as of
// late 2025 / early 2026. Update if Anthropic changes pricing.
//
// Schema:
//   input  = standard input tokens
//   output = output tokens
//   cacheWrite = prompt-cache writes, priced at the 1-HOUR TTL rate (2x input),
//                not the 5-minute rate (1.25x). The agent loop caches the 90+
//                tool catalog at ttl=1h on EVERY surface and the chat system
//                prompt at 1h, so the dominant cache-creation volume is 1h
//                writes. Logged usage carries only the aggregate
//                cache_creation_input_tokens (no 5m/1h split), so one rate is
//                unavoidable; 2x is materially closer than the old 1.25x, which
//                systematically undercounted cache cost in /cost,
//                /cost-summary, and the IR cost projection.
//   cacheRead  = prompt-cache hits (charged at 0.1x input)

export type ModelPricing = {
  input: number;
  output: number;
  cacheWrite: number;
  cacheRead: number;
};

const SONNET: ModelPricing = {
  input: 3.0,
  output: 15.0,
  cacheWrite: 6.0,
  cacheRead: 0.3,
};
const OPUS: ModelPricing = {
  input: 15.0,
  output: 75.0,
  cacheWrite: 30.0,
  cacheRead: 1.5,
};
const HAIKU: ModelPricing = {
  input: 1.0,
  output: 5.0,
  cacheWrite: 2.0,
  cacheRead: 0.1,
};

// Match by prefix on the model id. The longest matching prefix wins, so
// keep the more specific entries first if/when they diverge.
const PRICING_BY_PREFIX: Array<{ prefix: string; pricing: ModelPricing }> = [
  { prefix: "claude-opus-4", pricing: OPUS },
  { prefix: "claude-sonnet-4", pricing: SONNET },
  { prefix: "claude-haiku-4", pricing: HAIKU },
  { prefix: "claude-3-5-sonnet", pricing: SONNET },
  { prefix: "claude-3-5-haiku", pricing: HAIKU },
  { prefix: "claude-3-opus", pricing: OPUS },
];

// Family-word fallback. Some Anthropic gateways and proxy deployments
// rename model ids out of the canonical `claude-<family>-<major>-<minor>`
// shape — observed forms include `claude-4-6-sonnet` (segment order
// flipped), `claude-sonnet` (no version), and `anthropic.claude-sonnet-4`
// (vendor prefix). The prefix table can't enumerate all of these, so
// when no exact prefix matches we look for the family word as a token
// in the id and price by family. Less precise (we don't know the version
// for cache-pricing accuracy) but the alternative — silently logging
// $0 forever — is worse.
const FAMILY_FALLBACK: Array<{ token: string; pricing: ModelPricing }> = [
  { token: "opus", pricing: OPUS },
  { token: "sonnet", pricing: SONNET },
  { token: "haiku", pricing: HAIKU },
];

export function pricingFor(modelId: string): ModelPricing | null {
  const id = modelId.toLowerCase();
  let best: { prefix: string; pricing: ModelPricing } | null = null;
  for (const entry of PRICING_BY_PREFIX) {
    if (id.startsWith(entry.prefix)) {
      if (!best || entry.prefix.length > best.prefix.length) best = entry;
    }
  }
  if (best) return best.pricing;
  // Fallback: search for the family word anywhere in the id. Ordered
  // longest-first so `opus` doesn't shadow a hypothetical future family
  // ending in `-opus-…`.
  for (const f of FAMILY_FALLBACK) {
    if (id.includes(f.token)) return f.pricing;
  }
  return null;
}

export type Usage = {
  input_tokens?: number;
  output_tokens?: number;
  cache_creation_input_tokens?: number;
  cache_read_input_tokens?: number;
};

/** Cost in USD for one turn given a usage record and a model id.
 *  Returns 0 if the model is unknown. Cache-creation tokens are billed in
 *  ADDITION to standard input tokens — the Anthropic API counts them
 *  separately from `input_tokens`, which already excludes them. */
export function costOf(usage: Usage, modelId: string): number {
  const p = pricingFor(modelId);
  if (!p) return 0;
  const inTok = usage.input_tokens ?? 0;
  const outTok = usage.output_tokens ?? 0;
  const cwTok = usage.cache_creation_input_tokens ?? 0;
  const crTok = usage.cache_read_input_tokens ?? 0;
  return (
    (inTok * p.input +
      outTok * p.output +
      cwTok * p.cacheWrite +
      crTok * p.cacheRead) /
    1_000_000
  );
}
