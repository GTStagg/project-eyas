import "server-only";
import Anthropic from "@anthropic-ai/sdk";
import { getRuntimeConfig, invalidateConfigCache } from "@/lib/config/runtime";
import { getDeploymentPolicy } from "@/lib/config/deployment-policy";

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
  const opts: ConstructorParameters<typeof Anthropic>[0] = {};
  if (cfg.apiKey) opts.apiKey = cfg.apiKey;
  if (cfg.authToken) opts.authToken = cfg.authToken;
  if (cfg.baseURL) opts.baseURL = cfg.baseURL;
  cached = { client: new Anthropic(opts), key };
  return cached.client;
}

export function getAnthropicModel(): string {
  return getRuntimeConfig().anthropic.model;
}

export function resetAnthropicClient(): void {
  cached = null;
  invalidateConfigCache();
}
