import "server-only";
import {
  getSettings,
  invalidateSettingsCache,
  mutateSettings,
  settingsFilePath,
  type EnvironmentRecord,
  type PatchProfile,
  type SettingsFile,
} from "./store";
import { DEFAULT_FALCON_BASE_URL } from "./environments";

// The everyday default; claude-opus-5-5 is the higher-quality option. Request
// defaults for this generation (max_tokens floor, explicit effort) live in
// lib/llm/request.ts.
export const DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5-5";

// Per-turn output-token cap for the /chat surface (operator-editable via
// /config). The default gives long scripts/playbooks room; the ceiling is the
// universal-safe max across the models an operator may still pick — the 5.5
// generation reaches 128K output, but Sonnet 4.6 / Haiku 4.5 cap at 64K, so 64K
// stays model-agnostic and is plenty for chat output (thinking included). The chat loop streams, so high caps carry no
// HTTP-timeout risk. Values are stored as a string in settings and parsed here.
export const DEFAULT_CHAT_MAX_TOKENS = 16384;
export const MIN_CHAT_MAX_TOKENS = 1024;
export const MAX_CHAT_MAX_TOKENS = 64000;

export function parseChatMaxTokens(raw: string | undefined): number {
  if (!raw) return DEFAULT_CHAT_MAX_TOKENS;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) return DEFAULT_CHAT_MAX_TOKENS;
  return Math.min(MAX_CHAT_MAX_TOKENS, Math.max(MIN_CHAT_MAX_TOKENS, n));
}

export type ConfigFile = {
  version: 1;
  anthropic?: SettingsFile["anthropic"];
  falcon?: EnvironmentRecord["falcon"];
  irQuarantineGroupId?: string;
  shadowAiBannedGroupId?: string;
  shadowAiSanctionedTools?: string[];
};

export type RuntimeConfig = {
  anthropic: {
    apiKey?: string;
    authToken?: string;
    baseURL?: string;
    model: string;
    /** Per-turn output-token cap for the /chat surface (parsed + clamped). */
    chatMaxTokens: number;
  };
  falcon: {
    clientId?: string;
    clientSecret?: string;
    baseUrl: string;
    memberCid?: string;
  };
  irQuarantineGroupId?: string;
  shadowAiBannedGroupId?: string;
  shadowAiSanctionedTools: string[];
  patchProfiles?: PatchProfile[];
};

/**
 * Per-field provenance. The wizard uses this to decide which fields to surface
 * and to label fields that came from .env so the operator knows where to edit.
 * Sensitive values are NEVER exposed via this type — only sources/booleans.
 */
export type ConfigStatus = {
  anthropic: {
    credential: { source: Source; kind: "apiKey" | "authToken" | null };
    baseURL: { source: Source };
    model: { source: Source; value: string };
  };
  falcon: {
    clientId: { source: Source };
    clientSecret: { source: Source };
    baseUrl: { source: Source; value: string };
    memberCid: { source: Source };
  };
  irQuarantineGroupId: { source: Source };
  shadowAiBannedGroupId: { source: Source };
  fullyConfigured: boolean;
};

// Tracks whether a config field is set in the DB. `.env` is not consulted
// at runtime, so a field is either present in settings storage or it isn't.
export type Source = "config" | "missing";

function valueSource(v: string | undefined): Source {
  return v !== undefined && v !== "" ? "config" : "missing";
}

function activeEnv(file: SettingsFile): EnvironmentRecord {
  return file.environments.find((e) => e.id === file.active_id) ?? file.environments[0];
}

export function getRuntimeConfig(): RuntimeConfig {
  const file = getSettings();
  const env = activeEnv(file);

  return {
    anthropic: {
      apiKey: file.anthropic?.apiKey,
      authToken: file.anthropic?.authToken,
      baseURL: file.anthropic?.baseURL,
      model: file.anthropic?.model ?? DEFAULT_ANTHROPIC_MODEL,
      chatMaxTokens: parseChatMaxTokens(file.anthropic?.chatMaxTokens),
    },
    falcon: {
      clientId: env.falcon.clientId,
      clientSecret: env.falcon.clientSecret,
      baseUrl: env.falcon.baseUrl ?? DEFAULT_FALCON_BASE_URL,
      memberCid: env.falcon.memberCid,
    },
    irQuarantineGroupId: env.irQuarantineGroupId,
    shadowAiBannedGroupId: env.shadowAiBannedGroupId,
    shadowAiSanctionedTools: env.shadowAiSanctionedTools ?? [],
    patchProfiles: env.patchProfiles,
  };
}

export function getConfigStatus(): ConfigStatus {
  const file = getSettings();
  const env = activeEnv(file);

  const apiKey = file.anthropic?.apiKey;
  const authToken = file.anthropic?.authToken;
  const baseURL = file.anthropic?.baseURL;
  const model = file.anthropic?.model;

  let credential: ConfigStatus["anthropic"]["credential"];
  if (apiKey) credential = { source: "config", kind: "apiKey" };
  else if (authToken) credential = { source: "config", kind: "authToken" };
  else credential = { source: "missing", kind: null };

  const fullyConfigured =
    credential.source !== "missing" && !!env.falcon.clientId && !!env.falcon.clientSecret;

  return {
    anthropic: {
      credential,
      baseURL: { source: valueSource(baseURL) },
      model: { source: valueSource(model), value: model ?? DEFAULT_ANTHROPIC_MODEL },
    },
    falcon: {
      clientId: { source: valueSource(env.falcon.clientId) },
      clientSecret: { source: valueSource(env.falcon.clientSecret) },
      baseUrl: {
        source: valueSource(env.falcon.baseUrl),
        value: env.falcon.baseUrl ?? DEFAULT_FALCON_BASE_URL,
      },
      memberCid: { source: valueSource(env.falcon.memberCid) },
    },
    irQuarantineGroupId: { source: valueSource(env.irQuarantineGroupId) },
    shadowAiBannedGroupId: { source: valueSource(env.shadowAiBannedGroupId) },
    fullyConfigured,
  };
}

/**
 * Merge `patch` into the unified settings file.
 * Pass empty strings to clear a field (it is removed from the saved JSON).
 *
 * Anthropic creds are written directly. Falcon credentials,
 * irQuarantineGroupId, and shadowAiBannedGroupId redirect into the active
 * environment record so /api/config/falcon (and /register Step 2) keep
 * working unchanged.
 */
export async function saveRuntimeConfig(patch: Partial<ConfigFile>): Promise<void> {
  await mutateSettings((current) => {
    const next: SettingsFile = { ...current };

    if (patch.anthropic !== undefined) {
      const merged: NonNullable<SettingsFile["anthropic"]> = { ...current.anthropic };
      for (const [k, v] of Object.entries(patch.anthropic) as Array<
        [keyof NonNullable<SettingsFile["anthropic"]>, string | undefined]
      >) {
        if (v === undefined || v === null || v === "") delete merged[k];
        else merged[k] = v;
      }
      next.anthropic = merged;
    }

    if (
      patch.falcon !== undefined ||
      patch.irQuarantineGroupId !== undefined ||
      patch.shadowAiBannedGroupId !== undefined ||
      patch.shadowAiSanctionedTools !== undefined
    ) {
      const envs = current.environments.map((e) => ({ ...e, falcon: { ...e.falcon } }));
      const idx = envs.findIndex((e) => e.id === current.active_id);
      if (idx < 0) throw new Error("active environment not found");
      const target = envs[idx];
      if (patch.falcon) {
        for (const [k, v] of Object.entries(patch.falcon) as Array<
          [keyof EnvironmentRecord["falcon"], string | undefined]
        >) {
          if (v === undefined) continue;
          if (v === "") {
            // Allow clearing memberCid via empty string. clientId, clientSecret,
            // baseUrl are required; an empty string just leaves them alone
            // (matches /api/config/falcon's existing semantics).
            if (k === "memberCid") delete target.falcon[k];
          } else {
            target.falcon[k] = v;
          }
        }
      }
      if (patch.irQuarantineGroupId !== undefined) {
        if (patch.irQuarantineGroupId === "") delete target.irQuarantineGroupId;
        else target.irQuarantineGroupId = patch.irQuarantineGroupId;
      }
      if (patch.shadowAiBannedGroupId !== undefined) {
        if (patch.shadowAiBannedGroupId === "") delete target.shadowAiBannedGroupId;
        else target.shadowAiBannedGroupId = patch.shadowAiBannedGroupId;
      }
      if (patch.shadowAiSanctionedTools !== undefined) {
        const seen = new Set<string>();
        for (const v of patch.shadowAiSanctionedTools) {
          if (typeof v !== "string") continue;
          const norm = v.trim().toLowerCase();
          if (norm) seen.add(norm);
        }
        if (seen.size === 0) delete target.shadowAiSanctionedTools;
        else target.shadowAiSanctionedTools = [...seen].sort();
      }
      envs[idx] = target;
      next.environments = envs;
    }

    return next;
  });
}

export function invalidateConfigCache(): void {
  invalidateSettingsCache();
}

export function configFilePath(): string {
  // Kept as a public helper for callers that surface the on-disk path
  // (e.g. /status). Now points at settings.json.
  return settingsFilePath();
}
