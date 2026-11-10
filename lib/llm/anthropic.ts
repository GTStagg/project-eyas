import "server-only";
import Anthropic from "@anthropic-ai/sdk";
import { getRuntimeConfig, invalidateConfigCache } from "@/lib/config/runtime";
import { getDeploymentPolicy } from "@/lib/config/deployment-policy";
import { resetServerFallbackMemo } from "@/lib/llm/messages";

let cached: { client: Anthropic; key: string } | null = null;

type AnthropicConfig = ReturnType<typeof getRuntimeConfig>["anthropic"];

function clientKey(cfg: AnthropicConfig): string {
  return JSON.stringify([cfg.apiKey ?? "", cfg.authToken ?? "", cfg.baseURL ?? ""]);
}

/**
 * Apply the build-time deployment lock at the read seam — not just at the
 * /config save path. A locked (gatewayOnly) bundle must never honor a
 * stored API key or an operator-chosen base URL even if the DB row was
 * edited by hand to inject one: drop the key, force the baked gateway URL.
 * Mirrors `validateAnthropicAgainstPolicy`, but enforced where the client
 * is actually constructed so a direct DB write can't repoint a leaked copy.
 */
function applyDeploymentPolicy(cfg: AnthropicConfig): AnthropicConfig {
  const policy = getDeploymentPolicy();
  if (!policy.gatewayOnly) return cfg;
  return {
    ...cfg,
    apiKey: undefined,
    baseURL: policy.forcedGatewayUrl ?? cfg.baseURL,
  };
}

export function getAnthropicClient(): Anthropic {
  const cfg = applyDeploymentPolicy(getRuntimeConfig().anthropic);
  if (!cfg.apiKey && !cfg.authToken) {
    throw new Error(
      "Anthropic credentials are not configured. Set ANTHROPIC_API_KEY (direct API) or ANTHROPIC_AUTH_TOKEN (gateway) via the /register wizard or .env.",
    );
  }
  const key = clientKey(cfg);
  if (cached && cached.key === key) return cached.client;
  cached = { client: new Anthropic(anthropicClientOptions(cfg)), key };
  return cached.client;
}

/**
 * SDK ≥ 1.0 holds one credential per client (passing both throws) and sends
 * an API key as `Authorization: Bearer`. Eyas keeps the headers it has always
 * sent, so gateways configured in /config see no change: an API key goes out
 * as `X-Api-Key` (the Claude API accepts either header), an auth token as
 * `Authorization: Bearer`, and a config with both sends both.
 */
export function anthropicClientOptions(cfg: {
  apiKey?: string;
  authToken?: string;
  baseURL?: string;
}): ConstructorParameters<typeof Anthropic>[0] {
  const opts: ConstructorParameters<typeof Anthropic>[0] = {};
  if (cfg.baseURL) opts.baseURL = cfg.baseURL;
  if (cfg.authToken) {
    opts.authToken = cfg.authToken;
    if (cfg.apiKey) opts.defaultHeaders = { "X-Api-Key": cfg.apiKey };
  } else if (cfg.apiKey) {
    opts.apiKey = cfg.apiKey;
    opts.defaultHeaders = { "X-Api-Key": cfg.apiKey, Authorization: null };
  }
  return opts;
}

export function getAnthropicModel(): string {
  return getRuntimeConfig().anthropic.model;
}

export function resetAnthropicClient(): void {
  cached = null;
  resetServerFallbackMemo();
  invalidateConfigCache();
}
