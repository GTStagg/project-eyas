import "server-only";
import {
  getSettings,
  invalidateSettingsCache,
  mutateSettings,
  newId,
  prunePatchProfiles,
  type EnvironmentRecord,
  type PatchProfile,
} from "./store";

export const DEFAULT_FALCON_BASE_URL = "https://api.crowdstrike.com";
export const DEFAULT_AIDR_BASE_URL = "https://api.crowdstrike.com/aidr/aiguard";

// Allowlist for an operator-supplied AIDR base URL. The AIDR bearer token is
// sent to this host on every chat turn, so an unvalidated value would let a
// PATCH (or hand-edited DB row) ship the token to an attacker-chosen host.
// Accept only CrowdStrike API hosts and Pangea (the AIDR backend) hosts; a
// path such as /aidr/aiguard is allowed.
export const AIDR_BASE_URL_RE =
  /^https:\/\/([a-z0-9-]+\.)*(crowdstrike\.com|pangea\.cloud)(\/[^\s]*)?$/i;

export type { EnvironmentRecord };

// Public projection of an environment with the secret stripped.
// Used everywhere outside the OAuth probe path.
export type EnvironmentView = {
  id: string;
  name: string;
  client_id_masked: string | null;
  client_secret_set: boolean;
  base_url: string;
  member_cid: string | null;
  ir_quarantine_group_id: string | null;
  shadow_ai_banned_group_id: string | null;
  shadow_ai_sanctioned_tools: string[];
  aidr_token_set: boolean;
  aidr_base_url: string;
};

function maskClientId(id: string | undefined): string | null {
  if (!id) return null;
  if (id.length <= 6) return "•".repeat(id.length);
  return `${id.slice(0, 4)}…${id.slice(-4)}`;
}

export function projectEnvironment(env: EnvironmentRecord): EnvironmentView {
  return {
    id: env.id,
    name: env.name,
    client_id_masked: maskClientId(env.falcon.clientId),
    client_secret_set: !!env.falcon.clientSecret,
    base_url: env.falcon.baseUrl ?? DEFAULT_FALCON_BASE_URL,
    member_cid: env.falcon.memberCid ?? null,
    ir_quarantine_group_id: env.irQuarantineGroupId ?? null,
    shadow_ai_banned_group_id: env.shadowAiBannedGroupId ?? null,
    shadow_ai_sanctioned_tools: env.shadowAiSanctionedTools ?? [],
    aidr_token_set: !!env.aidr?.token,
    aidr_base_url: env.aidr?.baseUrl ?? DEFAULT_AIDR_BASE_URL,
  };
}

export function invalidateEnvironmentsCache(): void {
  invalidateSettingsCache();
}

export function listEnvironments(): EnvironmentView[] {
  return getSettings().environments.map(projectEnvironment);
}

export function getActiveEnvironment(): EnvironmentRecord {
  const file = getSettings();
  return file.environments.find((e) => e.id === file.active_id) ?? file.environments[0];
}

export function getActiveEnvironmentId(): string {
  return getSettings().active_id;
}

export function getEnvironmentById(id: string): EnvironmentRecord | null {
  return getSettings().environments.find((e) => e.id === id) ?? null;
}

/** Resolved AIDR credential for the active environment, or null if not
 *  configured. Server-only — the returned token must never reach the client. */
export function getActiveAidrCredential(): { token: string; baseUrl: string } | null {
  const env = getActiveEnvironment();
  const token = env.aidr?.token;
  if (!token) return null;
  return {
    token,
    baseUrl: env.aidr?.baseUrl || DEFAULT_AIDR_BASE_URL,
  };
}

export type EnvironmentPatch = {
  name?: string;
  falcon?: Partial<EnvironmentRecord["falcon"]>;
  irQuarantineGroupId?: string; // empty string clears
  shadowAiBannedGroupId?: string; // empty string clears
  // When set, REPLACES the entire sanctioned-tools list (pass [] to clear).
  // Tool ids are normalized lowercase + deduped server-side.
  shadowAiSanctionedTools?: string[];
  // When set, REPLACES the entire patch-profile list (pass [] to clear). The
  // chat auto-save hook reads the current list and appends, so callers that
  // want append semantics build the merged array themselves; this patch field
  // is a straight replace, shape-guarded server-side.
  patchProfiles?: PatchProfile[];
  // AIDR ("AI Guard") credential — empty string clears the field. Token is
  // column-encrypted via lib/db/crypto.ts; baseUrl is plaintext.
  aidr?: {
    token?: string;
    baseUrl?: string;
  };
};

function applyPatch(env: EnvironmentRecord, patch: EnvironmentPatch): EnvironmentRecord {
  const next: EnvironmentRecord = {
    ...env,
    name: patch.name?.trim() ? patch.name.trim() : env.name,
    falcon: { ...env.falcon },
  };
  if (patch.falcon) {
    for (const [k, v] of Object.entries(patch.falcon) as Array<
      [keyof EnvironmentRecord["falcon"], string | undefined]
    >) {
      if (v === undefined) continue;
      if (v === "") {
        // Allow clearing memberCid via empty string. clientId, clientSecret,
        // baseUrl are required so an empty string just leaves them alone
        // (matches /api/config/falcon's existing semantics).
        if (k === "memberCid") delete next.falcon[k];
      } else {
        next.falcon[k] = v;
      }
    }
  }
  if (patch.irQuarantineGroupId !== undefined) {
    if (patch.irQuarantineGroupId === "") delete next.irQuarantineGroupId;
    else next.irQuarantineGroupId = patch.irQuarantineGroupId;
  }
  if (patch.shadowAiBannedGroupId !== undefined) {
    if (patch.shadowAiBannedGroupId === "") delete next.shadowAiBannedGroupId;
    else next.shadowAiBannedGroupId = patch.shadowAiBannedGroupId;
  }
  if (patch.shadowAiSanctionedTools !== undefined) {
    const norm = normalizeToolList(patch.shadowAiSanctionedTools);
    if (norm.length === 0) delete next.shadowAiSanctionedTools;
    else next.shadowAiSanctionedTools = norm;
  }
  if (patch.patchProfiles !== undefined) {
    const pruned = prunePatchProfiles(patch.patchProfiles);
    if (!pruned) delete next.patchProfiles;
    else next.patchProfiles = pruned;
  }
  if (patch.aidr !== undefined) {
    const cur = next.aidr ? { ...next.aidr } : {};
    if (patch.aidr.token !== undefined) {
      if (patch.aidr.token === "") delete cur.token;
      else cur.token = patch.aidr.token;
    }
    if (patch.aidr.baseUrl !== undefined) {
      if (patch.aidr.baseUrl === "") delete cur.baseUrl;
      else cur.baseUrl = patch.aidr.baseUrl;
    }
    if (cur.token || cur.baseUrl) next.aidr = cur;
    else delete next.aidr;
  }
  return next;
}

function normalizeToolList(list: string[]): string[] {
  const seen = new Set<string>();
  for (const v of list) {
    if (typeof v !== "string") continue;
    const norm = v.trim().toLowerCase();
    if (norm) seen.add(norm);
  }
  return [...seen].sort();
}

export async function updateActiveEnvironment(patch: EnvironmentPatch): Promise<void> {
  await mutateSettings((current) => {
    const idx = current.environments.findIndex((e) => e.id === current.active_id);
    if (idx < 0) throw new Error("active environment not found");
    const envs = [...current.environments];
    envs[idx] = applyPatch(envs[idx], patch);
    return { ...current, environments: envs };
  });
}

export async function updateEnvironment(id: string, patch: EnvironmentPatch): Promise<void> {
  await mutateSettings((current) => {
    const idx = current.environments.findIndex((e) => e.id === id);
    if (idx < 0) throw new Error(`environment not found: ${id}`);
    const envs = [...current.environments];
    envs[idx] = applyPatch(envs[idx], patch);
    return { ...current, environments: envs };
  });
}

export async function createEnvironment(input: {
  name: string;
  falcon: Required<Pick<EnvironmentRecord["falcon"], "clientId" | "clientSecret">> &
    Partial<EnvironmentRecord["falcon"]>;
  irQuarantineGroupId?: string;
  shadowAiBannedGroupId?: string;
  shadowAiSanctionedTools?: string[];
  activate?: boolean;
}): Promise<EnvironmentRecord> {
  const env: EnvironmentRecord = {
    id: newId(),
    name: input.name.trim() || "Untitled",
    falcon: {
      clientId: input.falcon.clientId,
      clientSecret: input.falcon.clientSecret,
      baseUrl: input.falcon.baseUrl || DEFAULT_FALCON_BASE_URL,
      memberCid: input.falcon.memberCid || undefined,
    },
    irQuarantineGroupId: input.irQuarantineGroupId || undefined,
    shadowAiBannedGroupId: input.shadowAiBannedGroupId || undefined,
    shadowAiSanctionedTools: input.shadowAiSanctionedTools
      ? normalizeToolList(input.shadowAiSanctionedTools)
      : undefined,
  };
  for (const k of Object.keys(env.falcon) as Array<keyof typeof env.falcon>) {
    if (!env.falcon[k]) delete env.falcon[k];
  }
  if (!env.irQuarantineGroupId) delete env.irQuarantineGroupId;
  if (!env.shadowAiBannedGroupId) delete env.shadowAiBannedGroupId;
  if (!env.shadowAiSanctionedTools || env.shadowAiSanctionedTools.length === 0) {
    delete env.shadowAiSanctionedTools;
  }

  await mutateSettings((current) => ({
    ...current,
    active_id: input.activate ? env.id : current.active_id,
    environments: [...current.environments, env],
  }));
  return env;
}

export async function deleteEnvironment(id: string): Promise<void> {
  await mutateSettings((current) => {
    if (current.environments.length <= 1) {
      throw new Error("cannot delete the last environment");
    }
    if (current.active_id === id) {
      throw new Error("cannot delete the active environment; switch first");
    }
    return {
      ...current,
      environments: current.environments.filter((e) => e.id !== id),
    };
  });
}

export async function setActiveEnvironment(id: string): Promise<void> {
  await mutateSettings((current) => {
    if (!current.environments.find((e) => e.id === id)) {
      throw new Error(`environment not found: ${id}`);
    }
    if (current.active_id === id) return current;
    return { ...current, active_id: id };
  });
}
