import "server-only";
import { getRuntimeConfig } from "./runtime";

/**
 * Build the environment dict for a spawned child process (eyas-mcp,
 * falcon-extras). Inherits parent process.env (PATH, HOME, NODE_ENV,
 * FALCON_DATA_DIR pass through), strips the app's own secrets, then
 * explicitly sets every Falcon credential / per-tenant field from
 * data/eyas.db — using delete to strip any inherited value the active
 * environment doesn't set.
 *
 * Why explicit set-or-strip on every field, not just the per-tenant ones:
 * the DB is the only credential source at runtime; .env is bootstrap-only.
 * If process.env still has stale FALCON_* values (operator launched the
 * dev server with an old .env exported), they must NOT reach the child
 * process — silent cross-tenant credential bleed is the failure mode.
 */
export function childProcessEnv(): Record<string, string> {
  const base = Object.fromEntries(
    Object.entries(process.env).filter(([, v]) => typeof v === "string"),
  ) as Record<string, string>;

  const cfg = getRuntimeConfig();
  const result: Record<string, string> = { ...base };

  // Set when present, strip when not — applied to every field that comes
  // from settings.json so stale inherited .env values can never override
  // a saved setting.
  const setOrStrip = (key: string, value: string | undefined) => {
    if (value) result[key] = value;
    else delete result[key];
  };

  // The app's own secrets never reach the children: neither eyas-mcp nor the
  // FalconPy sidecar reads them, and both run third-party Python packages.
  // AUTH_SESSION_SECRET is the root key that decrypts every stored credential;
  // the Anthropic credentials, scheduler/GitHub tokens and webhook URL are
  // only used by the Next.js process.
  for (const key of Object.keys(result)) {
    if (key.startsWith("ANTHROPIC_") || key.startsWith("AIDR_")) delete result[key];
  }
  for (const key of [
    "AUTH_SESSION_SECRET",
    "SCHEDULER_TOKEN",
    "GITHUB_TOKEN",
    "OUTBOUND_WEBHOOK_URL",
    "FALCON_MCP_API_KEY",
  ]) {
    delete result[key];
  }

  // Falcon credentials.
  setOrStrip("FALCON_CLIENT_ID", cfg.falcon.clientId);
  setOrStrip("FALCON_CLIENT_SECRET", cfg.falcon.clientSecret);
  setOrStrip("FALCON_BASE_URL", cfg.falcon.baseUrl);
  setOrStrip("FALCON_MEMBER_CID", cfg.falcon.memberCid);

  // Per-tenant operational fields.
  setOrStrip("FALCON_QUARANTINE_GROUP_ID", cfg.irQuarantineGroupId);
  setOrStrip("FALCON_SHADOW_AI_BANNED_GROUP_ID", cfg.shadowAiBannedGroupId);

  // The Shadow-AI sanction list is read in-process (lib/eyas-tools/shadow-ai);
  // no child process needs it, so never pass it on.
  setOrStrip("FALCON_SHADOW_AI_SANCTIONED", undefined);

  // Saved patch profiles are read in-process (extras_list_patch_profiles in
  // lib/eyas-tools); no child process needs them, so never pass them on.
  setOrStrip("FALCON_PATCH_PROFILES", undefined);

  // Neutralize falcon-mcp behavior flags that must never be inherited from a
  // stray shell/.env export. 0.16.0 makes read-only + tool-filtering
  // env-readable (FALCON_MCP_READ_ONLY / _TOOLS / _EXCLUDE_TOOLS, #490) and
  // dynamic mode predates it (FALCON_MCP_DYNAMIC). Eyas does per-tool approval
  // gating + tool suppression at the bridge AFTER listTools; any of these would
  // silently break that model — dynamic collapses the surface behind
  // falcon_execute_tool (bypasses per-tool gating + buildToolBridge +
  // /agent-toolbox), and read-only/exclude would delete the adopted native
  // writes and the ungated RTR session tools. We never opt into them, so strip
  // them regardless of the ambient environment. (FALCON_MCP_MODULES / _ARGS are
  // deliberately NOT stripped — they're supported escape hatches.)
  for (const key of [
    "FALCON_MCP_DYNAMIC",
    "FALCON_MCP_READ_ONLY",
    "FALCON_MCP_TOOLS",
    "FALCON_MCP_EXCLUDE_TOOLS",
  ]) {
    delete result[key];
  }

  return result;
}
