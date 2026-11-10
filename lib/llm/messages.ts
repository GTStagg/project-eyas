import "server-only";
import Anthropic from "@anthropic-ai/sdk";
import {
  hasServerFallback,
  withModelDefaults,
  withoutServerFallback,
  type ModelDefaultsOptions,
} from "@/lib/llm/request";

// One place every Claude call in Eyas goes through. It applies the request
// defaults (lib/llm/request.ts) and keeps server-side refusal fallbacks from
// ever failing a turn: an Anthropic-compatible gateway configured in /config
// may not know the `server-side-fallback-2026-07-01` beta or the `fallbacks`
// field and reject the request. When a request that carried fallbacks fails
// with a client error before any output, it's sent once more without them;
// if that succeeds, the gateway is remembered (per base URL, for the life of
// the process or until /config changes the client) and later calls skip the
// fallbacks instead of paying for the failed attempt again. A request that
// fails both ways throws the second error, so real request errors still
// surface.

type CreateParams = Anthropic.Beta.Messages.MessageCreateParamsNonStreaming;
type BetaMessage = Anthropic.Beta.Messages.BetaMessage;
type StreamEvent = Anthropic.Beta.Messages.BetaRawMessageStreamEvent;

// Status codes a gateway uses for a body field or beta it doesn't accept.
const REJECTION_STATUSES = new Set([400, 404, 422]);

type FallbackMemo = { unsupported: Set<string> };
const memoKey = "__eyasServerFallbackMemo";
function memo(): FallbackMemo {
  const g = globalThis as unknown as Record<string, FallbackMemo | undefined>;
  return (g[memoKey] ??= { unsupported: new Set() });
}

/** Forget which gateways rejected fallbacks (called when /config changes the client). */
export function resetServerFallbackMemo(): void {
  memo().unsupported.clear();
}

function isRejection(err: unknown): boolean {
  return err instanceof Anthropic.APIError && err.status !== undefined && REJECTION_STATUSES.has(err.status);
}

function prepare<T extends CreateParams>(client: Anthropic, params: T, opts: ModelDefaultsOptions): T {
  const fallbacks = (opts.fallbacks ?? true) && !memo().unsupported.has(client.baseURL);
  return withModelDefaults(params, { ...opts, fallbacks });
}

function rememberUnsupported(client: Anthropic, err: unknown): void {
  const scope = client.baseURL;
  if (memo().unsupported.has(scope)) return;
  memo().unsupported.add(scope);
  const status = err instanceof Anthropic.APIError ? err.status : "?";
  console.warn(
    `[anthropic] the configured endpoint rejected server-side refusal fallbacks (HTTP ${status}); continuing without them`,
  );
}

export type MessageCallOptions = ModelDefaultsOptions & { signal?: AbortSignal };

/** Non-streaming Messages call with Eyas defaults and the fallback degrade. */
export async function createMessage(
  client: Anthropic,
  params: CreateParams,
  opts: MessageCallOptions = {},
): Promise<BetaMessage> {
  const { signal, ...defaults } = opts;
  const body = prepare(client, params, defaults);
  try {
    return await client.beta.messages.create(body, { signal });
  } catch (err) {
    if (!hasServerFallback(body) || !isRejection(err)) throw err;
    const message = await client.beta.messages.create(withoutServerFallback(body), { signal });
    rememberUnsupported(client, err);
    return message;
  }
}

/**
 * Streaming Messages call with Eyas defaults and the fallback degrade.
 * `onEvent` sees every stream event (text deltas for the UI); the resolved
 * value is the final message. The no-fallback retry only happens when the
 * first attempt failed before any event arrived, so nothing is shown twice.
 */
export async function streamMessage(
  client: Anthropic,
  params: CreateParams,
  opts: MessageCallOptions & { onEvent?: (event: StreamEvent) => void } = {},
): Promise<BetaMessage> {
  const { signal, onEvent, ...defaults } = opts;
  const body = prepare(client, params, defaults);
  const run = async (p: CreateParams, seen: { any: boolean }) => {
    const stream = client.beta.messages.stream(p, { signal });
    for await (const event of stream) {
      seen.any = true;
      onEvent?.(event);
    }
    return stream.finalMessage();
  };
  const seen = { any: false };
  try {
    return await run(body, seen);
  } catch (err) {
    if (seen.any || !hasServerFallback(body) || !isRejection(err)) throw err;
    const message = await run(withoutServerFallback(body), { any: false });
    rememberUnsupported(client, err);
    return message;
  }
}
