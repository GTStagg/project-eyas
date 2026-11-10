// Per-million-token prices in USD for Claude API models (Anthropic first-party
// rates, checked 2026-11-10). Update when Anthropic changes pricing.
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
//   cacheRead  = prompt-cache hits (0.1x input on most models; the 5.5
//                generation and Fable 5.2 list their own, lower read rates).

export type ModelPricing = {
  input: number;
  output: number;
  cacheWrite: number;
  cacheRead: number;
};

const price = (input: number, output: number, cacheRead = input * 0.1): ModelPricing => ({
  input,
  output,
  cacheWrite: input * 2,
  cacheRead,
});

// Current generation.
const OPUS_5_5 = price(4, 20, 0.2);
const SONNET_5_5 = price(2, 10, 0.1);
// Claude Haiku 5.5 is $0.10 / $0.50 for prompts up to 100K tokens ($0.50 /
// $2.50 beyond); logged usage doesn't carry per-request prompt size, so the
// short-prompt card is used.
const HAIKU_5_5 = price(0.1, 0.5, 0.01);
const FABLE_5_2 = price(8, 40, 0.2);
// Earlier models still served.
const FABLE_5 = price(10, 50);
const OPUS_5 = price(5, 25);
const OPUS_4_5_PLUS = price(5, 25); // Opus 4.5 – 4.8
const OPUS_4 = price(15, 75); // Opus 4 / 4.1
const SONNET_5 = price(2, 10);
const SONNET_4 = price(3, 15); // Sonnet 4 – 4.6
const HAIKU_4 = price(1, 5);

// Match by prefix on the model id. The longest matching prefix wins, so a
// specific version (`claude-opus-4-8`) beats its family line (`claude-opus-4`).
const PRICING_BY_PREFIX: Array<{ prefix: string; pricing: ModelPricing }> = [
  { prefix: "claude-opus-5-5", pricing: OPUS_5_5 },
  { prefix: "claude-opus-5", pricing: OPUS_5 },
  { prefix: "claude-opus-4-8", pricing: OPUS_4_5_PLUS },
  { prefix: "claude-opus-4-7", pricing: OPUS_4_5_PLUS },
  { prefix: "claude-opus-4-6", pricing: OPUS_4_5_PLUS },
  { prefix: "claude-opus-4-5", pricing: OPUS_4_5_PLUS },
  { prefix: "claude-opus-4", pricing: OPUS_4 },
  { prefix: "claude-sonnet-5-5", pricing: SONNET_5_5 },
  { prefix: "claude-sonnet-5", pricing: SONNET_5 },
  { prefix: "claude-sonnet-4", pricing: SONNET_4 },
  { prefix: "claude-haiku-5-5", pricing: HAIKU_5_5 },
  { prefix: "claude-haiku-4", pricing: HAIKU_4 },
  { prefix: "claude-fable-5-2", pricing: FABLE_5_2 },
  { prefix: "claude-fable-5", pricing: FABLE_5 },
  { prefix: "claude-3-5-sonnet", pricing: SONNET_4 },
  { prefix: "claude-3-5-haiku", pricing: HAIKU_4 },
  { prefix: "claude-3-opus", pricing: OPUS_4 },
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
// Unknown versions price at the current generation.
const FAMILY_FALLBACK: Array<{ token: string; pricing: ModelPricing }> = [
  { token: "fable", pricing: FABLE_5_2 },
  { token: "opus", pricing: OPUS_5_5 },
  { token: "sonnet", pricing: SONNET_5_5 },
  { token: "haiku", pricing: HAIKU_5_5 },
];

export function pricingFor(modelId: string): ModelPricing | null {
  // Strip platform prefixes (`anthropic.`, `us.anthropic.`) so Bedrock-style ids
  // still hit the exact version entry instead of the family fallback.
  const id = modelId.toLowerCase().replace(/^(?:[a-z]{2,6}\.)?anthropic\./, "");
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
