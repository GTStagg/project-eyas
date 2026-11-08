import "server-only";
import { BUILD_FLAGS } from "./build-flags";

/**
 * Deployment policy — flags that lock down what can be configured at
 * runtime. Sourced from build-time constants in `build-flags.ts`, NOT
 * from process.env or settings.json — those are operator-editable and
 * would defeat the lock against unauthorized redistribution.
 *
 * Hardening goals for the internal-distribution standalone:
 *   - Only the org's gateway can be used (no direct Anthropic API key,
 *     no operator-chosen base URL). Prevents a leaked bundle from being
 *     repointed at a personal Anthropic account.
 *   - The gateway URL is fixed at build time, baked into the compiled
 *     JavaScript. A copy running outside the authorized channel has no
 *     useful URL to swap to without recompiling from source.
 *
 * Server-side enforcement (`/api/config/anthropic`, `/register` action)
 * uses these helpers so attempts to bypass the wizard by hand-editing
 * settings.json or POSTing directly are also rejected.
 */

export type DeploymentPolicy = {
  /** When true, only authToken (gateway) credentials are accepted. */
  gatewayOnly: boolean;
  /** When set, the wizard locks the base URL to this value and the server
   * rejects any other base URL on save. */
  forcedGatewayUrl: string | null;
};

export function getDeploymentPolicy(): DeploymentPolicy {
  return {
    gatewayOnly: BUILD_FLAGS.gatewayOnly,
    forcedGatewayUrl: BUILD_FLAGS.gatewayOnly ? BUILD_FLAGS.forcedGatewayUrl : null,
  };
}

/**
 * Validate a candidate Anthropic config patch against the deployment
 * policy. Returns null when accepted, or a user-facing error string.
 */
export function validateAnthropicAgainstPolicy(input: {
  apiKey?: string;
  authToken?: string;
  baseURL?: string;
}): string | null {
  const policy = getDeploymentPolicy();
  if (policy.gatewayOnly) {
    if (input.apiKey) {
      return "This build only allows gateway access. Use an auth token, not an API key.";
    }
    if (
      policy.forcedGatewayUrl &&
      input.baseURL &&
      input.baseURL !== policy.forcedGatewayUrl
    ) {
      return `This build is locked to the organization gateway (${policy.forcedGatewayUrl}). Custom base URLs are not allowed.`;
    }
  }
  return null;
}
