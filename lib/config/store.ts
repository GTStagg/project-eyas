import "server-only";
import crypto from "node:crypto";
import { asc, desc, eq } from "drizzle-orm";
import { db, dbFilePath, rawDb } from "../db/client";
import { decryptColumn, encryptColumn } from "../db/crypto";
import { environments, settings, settingsAudit } from "../db/schema";

// Single source of truth for runtime-configurable state. Backed by
// data/eyas.db (SQLite, WAL, mode 0600). Public API is consumed by
// runtime.ts, environments.ts, spawn-env.ts, and the register/config
// routes — keep it shape-stable.
//
// Security properties:
//  • Credentials are AES-256-GCM encrypted at column granularity (see
//    lib/db/crypto.ts). The on-disk DB file never contains plaintext
//    API tokens, so backup-hygiene mistakes (data/ synced to Dropbox)
//    aren't credential-disclosure incidents.
//  • settings_audit is enforced append-only by SQL triggers. Tampering
//    with the audit trail requires deleting + recreating the DB file.
//  • mutateSettings runs as a single transaction across settings +
//    environments + audit — no partial writes.
//
// Fresh-install only. A first boot with no DB initializes empty state;
// the operator completes /register + /config in the browser.

// A saved generic-installer param-set. This is DATA the operator chose to keep
// (validated params for win-app-install), never script bytes — the baked
// manifest regex stays the security boundary. Persisted per-tenant so a
// consumer of the standalone bundle builds their own runtime catalog with no
// rebuild. Mirrors the shadowAiSanctionedTools shape (JSON array column).
export type PatchProfile = {
  id: string;
  name: string;
  product: string;
  url: string;
  kind: "msi" | "exe";
  sha256?: string;
  silentArgs?: string;
  createdAt: string;
};

export type EnvironmentRecord = {
  id: string;
  name: string;
  falcon: {
    clientId?: string;
    clientSecret?: string;
    baseUrl?: string;
    memberCid?: string;
  };
  irQuarantineGroupId?: string;
  shadowAiBannedGroupId?: string;
  shadowAiSanctionedTools?: string[];
  patchProfiles?: PatchProfile[];
  aidr?: {
    token?: string;
    baseUrl?: string;
  };
};

export type SettingsFile = {
  version: 2;
  anthropic?: {
    apiKey?: string;
    authToken?: string;
    baseURL?: string;
    model?: string;
    // Per-turn output-token cap for the /chat surface. String-stored to reuse
    // the generic anthropic plumbing; parsed + clamped in runtime.ts.
    chatMaxTokens?: string;
  };
  active_id: string;
  environments: EnvironmentRecord[];
};

export type AuditEntry = {
  ts: string;
  op:
    | "bootstrap"
    | "anthropic_update"
    | "env_create"
    | "env_update"
    | "env_delete"
    | "env_set_active";
  env_id?: string;
  env_name?: string;
  fields_changed?: string[];
  active_id_before?: string;
  active_id_after?: string;
};

// ---------------------------------------------------------------------------
// In-memory cache (pinned to globalThis for the same reason the old store
// pinned its cache — Next.js standalone fragments module state across
// chunks, see `module_state_globalthis_pinning`).
// ---------------------------------------------------------------------------

type StoreState = {
  cache: SettingsFile | null;
  writeChain: Promise<void>;
};
const globalForStore = globalThis as unknown as { __falconSettingsStore?: StoreState };
const state: StoreState =
  globalForStore.__falconSettingsStore ??
  (globalForStore.__falconSettingsStore = {
    cache: null,
    writeChain: Promise.resolve(),
  });

export function newId(): string {
  return `env_${crypto.randomBytes(6).toString("hex")}`;
}

const FALCON_FIELDS = ["clientId", "clientSecret", "baseUrl", "memberCid"] as const;

function pruneSanctionedTools(list: string[] | undefined): string[] | undefined {
  if (!Array.isArray(list)) return undefined;
  const seen = new Set<string>();
  for (const v of list) {
    if (typeof v !== "string") continue;
    const norm = v.trim().toLowerCase();
    if (norm) seen.add(norm);
  }
  return seen.size ? [...seen].sort() : undefined;
}

const MAX_PATCH_PROFILES = 200;

// Shape-guard for persisted patch profiles. NOT the security boundary — the
// sidecar re-validates every param against the win-app-install manifest regex
// at save time (extras_save_patch_profile) and again at resolve time, so a
// malformed entry can never reach a runscript. This just keeps the stored JSON
// well-formed: drop non-objects / missing required fields / bad kind, trim
// strings, dedupe by id (last write wins), cap at MAX_PATCH_PROFILES keeping the
// most recent by createdAt. Returns undefined for empty/invalid so the column
// stays NULL rather than "[]".
export function prunePatchProfiles(list: PatchProfile[] | undefined): PatchProfile[] | undefined {
  if (!Array.isArray(list)) return undefined;
  const byId = new Map<string, PatchProfile>();
  for (const raw of list) {
    if (!raw || typeof raw !== "object") continue;
    const id = typeof raw.id === "string" ? raw.id.trim() : "";
    const name = typeof raw.name === "string" ? raw.name.trim() : "";
    const product = typeof raw.product === "string" ? raw.product.trim() : "";
    const url = typeof raw.url === "string" ? raw.url.trim() : "";
    const kind = raw.kind === "msi" || raw.kind === "exe" ? raw.kind : null;
    if (!id || !name || !product || !url || !kind) continue;
    const profile: PatchProfile = {
      id,
      name,
      product,
      url,
      kind,
      createdAt:
        typeof raw.createdAt === "string" && raw.createdAt ? raw.createdAt : new Date().toISOString(),
    };
    if (typeof raw.sha256 === "string" && raw.sha256.trim()) profile.sha256 = raw.sha256.trim();
    if (typeof raw.silentArgs === "string" && raw.silentArgs.trim()) {
      profile.silentArgs = raw.silentArgs.trim();
    }
    byId.set(id, profile); // last write wins
  }
  if (byId.size === 0) return undefined;
  const sorted = [...byId.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  return sorted.slice(0, MAX_PATCH_PROFILES);
}

function pruneFalcon(f: Partial<EnvironmentRecord["falcon"]> | undefined): EnvironmentRecord["falcon"] {
  const out: EnvironmentRecord["falcon"] = {};
  if (!f) return out;
  for (const k of FALCON_FIELDS) {
    const v = f[k];
    if (v) out[k] = v;
  }
  return out;
}

// ---------------------------------------------------------------------------
// DB ↔ SettingsFile codecs
// ---------------------------------------------------------------------------

function decodeEnv(row: typeof environments.$inferSelect): EnvironmentRecord {
  const falcon: EnvironmentRecord["falcon"] = {};
  const clientId = decryptColumn(row.falconClientIdEnc, `env.${row.id}.falcon_client_id`);
  const clientSecret = decryptColumn(row.falconClientSecretEnc, `env.${row.id}.falcon_client_secret`);
  if (clientId) falcon.clientId = clientId;
  if (clientSecret) falcon.clientSecret = clientSecret;
  if (row.falconBaseUrl) falcon.baseUrl = row.falconBaseUrl;
  if (row.falconMemberCid) falcon.memberCid = row.falconMemberCid;
  const out: EnvironmentRecord = {
    id: row.id,
    name: row.name,
    falcon,
  };
  if (row.irQuarantineGroupId) out.irQuarantineGroupId = row.irQuarantineGroupId;
  if (row.shadowAiBannedGroupId) out.shadowAiBannedGroupId = row.shadowAiBannedGroupId;
  if (row.shadowAiSanctionedTools) {
    try {
      const parsed = JSON.parse(row.shadowAiSanctionedTools);
      const pruned = pruneSanctionedTools(Array.isArray(parsed) ? parsed : []);
      if (pruned) out.shadowAiSanctionedTools = pruned;
    } catch {
      /* malformed JSON — drop */
    }
  }
  if (row.patchProfiles) {
    try {
      const parsed = JSON.parse(row.patchProfiles);
      const pruned = prunePatchProfiles(Array.isArray(parsed) ? parsed : []);
      if (pruned) out.patchProfiles = pruned;
    } catch {
      /* malformed JSON — drop */
    }
  }
  const aidrToken = decryptColumn(row.aidrTokenEnc, `env.${row.id}.aidr_token`);
  if (aidrToken || row.aidrBaseUrl) {
    out.aidr = {};
    if (aidrToken) out.aidr.token = aidrToken;
    if (row.aidrBaseUrl) out.aidr.baseUrl = row.aidrBaseUrl;
  }
  return out;
}

function loadFromDb(): SettingsFile {
  const settingsRow = db().select().from(settings).where(eq(settings.id, 1)).get();
  const envRows = db().select().from(environments).orderBy(asc(environments.createdAt)).all();
  const envs = envRows.map(decodeEnv);

  if (!settingsRow || envs.length === 0) {
    // First-boot empty state. Synthesize a placeholder env so the rest of the
    // app has a stable shape; the operator finishes setup through /register
    // and /config.
    const env: EnvironmentRecord = { id: newId(), name: "Default", falcon: {} };
    return { version: 2, active_id: env.id, environments: [env] };
  }

  const anthropicApiKey = decryptColumn(settingsRow.anthropicApiKeyEnc, "settings.anthropic_api_key");
  const anthropicAuthToken = decryptColumn(
    settingsRow.anthropicAuthTokenEnc,
    "settings.anthropic_auth_token",
  );
  const anthropic: SettingsFile["anthropic"] = {};
  if (anthropicApiKey) anthropic.apiKey = anthropicApiKey;
  if (anthropicAuthToken) anthropic.authToken = anthropicAuthToken;
  if (settingsRow.anthropicBaseUrl) anthropic.baseURL = settingsRow.anthropicBaseUrl;
  if (settingsRow.anthropicModel) anthropic.model = settingsRow.anthropicModel;
  if (settingsRow.anthropicChatMaxTokens) anthropic.chatMaxTokens = settingsRow.anthropicChatMaxTokens;

  const activeId = envs.find((e) => e.id === settingsRow.activeEnvId)?.id ?? envs[0].id;

  const file: SettingsFile = {
    version: 2,
    active_id: activeId,
    environments: envs,
  };
  if (Object.keys(anthropic).length) file.anthropic = anthropic;
  return file;
}

function persistToDb(file: SettingsFile): void {
  const now = new Date().toISOString();
  const tx = rawDb().transaction(() => {
    // settings row (upsert)
    const existing = db().select().from(settings).where(eq(settings.id, 1)).get();
    const settingsValues = {
      id: 1 as const,
      anthropicApiKeyEnc: encryptColumn(file.anthropic?.apiKey, "settings.anthropic_api_key"),
      anthropicAuthTokenEnc: encryptColumn(file.anthropic?.authToken, "settings.anthropic_auth_token"),
      anthropicBaseUrl: file.anthropic?.baseURL ?? null,
      anthropicModel: file.anthropic?.model ?? null,
      anthropicChatMaxTokens: file.anthropic?.chatMaxTokens ?? null,
      activeEnvId: file.active_id,
      updatedAt: now,
    };
    if (existing) {
      db().update(settings).set(settingsValues).where(eq(settings.id, 1)).run();
    } else {
      db().insert(settings).values(settingsValues).run();
    }

    // environments — replace-set semantics. Delete any env not in the new
    // list, upsert the rest. createdAt preserved on existing rows.
    const existingEnvs = db().select().from(environments).all();
    const newIds = new Set(file.environments.map((e) => e.id));
    for (const existing of existingEnvs) {
      if (!newIds.has(existing.id)) {
        db().delete(environments).where(eq(environments.id, existing.id)).run();
      }
    }
    const existingById = new Map(existingEnvs.map((e) => [e.id, e]));
    for (const env of file.environments) {
      const sanctioned = pruneSanctionedTools(env.shadowAiSanctionedTools);
      const profiles = prunePatchProfiles(env.patchProfiles);
      const prev = existingById.get(env.id);
      const row = {
        id: env.id,
        name: env.name,
        falconClientIdEnc: encryptColumn(env.falcon?.clientId, `env.${env.id}.falcon_client_id`),
        falconClientSecretEnc: encryptColumn(env.falcon?.clientSecret, `env.${env.id}.falcon_client_secret`),
        falconBaseUrl: env.falcon?.baseUrl ?? null,
        falconMemberCid: env.falcon?.memberCid ?? null,
        irQuarantineGroupId: env.irQuarantineGroupId ?? null,
        shadowAiBannedGroupId: env.shadowAiBannedGroupId ?? null,
        shadowAiSanctionedTools: sanctioned ? JSON.stringify(sanctioned) : null,
        patchProfiles: profiles ? JSON.stringify(profiles) : null,
        aidrTokenEnc: encryptColumn(env.aidr?.token, `env.${env.id}.aidr_token`),
        aidrBaseUrl: env.aidr?.baseUrl ?? null,
        createdAt: prev?.createdAt ?? now,
        updatedAt: now,
      };
      if (prev) {
        db().update(environments).set(row).where(eq(environments.id, env.id)).run();
      } else {
        db().insert(environments).values(row).run();
      }
    }
  });
  tx();
}

// ---------------------------------------------------------------------------
// Audit-log diff (preserved from the JSONL implementation)
// ---------------------------------------------------------------------------

function falconFieldsDiff(
  before: EnvironmentRecord["falcon"] | undefined,
  after: EnvironmentRecord["falcon"] | undefined,
): string[] {
  const changed: string[] = [];
  for (const k of FALCON_FIELDS) {
    if ((before?.[k] ?? "") !== (after?.[k] ?? "")) changed.push(`falcon.${k}`);
  }
  return changed;
}

function envFieldsDiff(
  before: EnvironmentRecord | undefined,
  after: EnvironmentRecord | undefined,
): string[] {
  if (!before && !after) return [];
  if (!before) return ["created"];
  if (!after) return ["deleted"];
  const changed: string[] = [];
  if (before.name !== after.name) changed.push("name");
  changed.push(...falconFieldsDiff(before.falcon, after.falcon));
  if ((before.irQuarantineGroupId ?? "") !== (after.irQuarantineGroupId ?? "")) {
    changed.push("irQuarantineGroupId");
  }
  if ((before.shadowAiBannedGroupId ?? "") !== (after.shadowAiBannedGroupId ?? "")) {
    changed.push("shadowAiBannedGroupId");
  }
  const beforeTools = (before.shadowAiSanctionedTools ?? []).join(",");
  const afterTools = (after.shadowAiSanctionedTools ?? []).join(",");
  if (beforeTools !== afterTools) changed.push("shadowAiSanctionedTools");
  const beforeProfiles = JSON.stringify(prunePatchProfiles(before.patchProfiles) ?? []);
  const afterProfiles = JSON.stringify(prunePatchProfiles(after.patchProfiles) ?? []);
  if (beforeProfiles !== afterProfiles) changed.push("patchProfiles");
  if ((before.aidr?.token ?? "") !== (after.aidr?.token ?? "")) changed.push("aidr.token");
  if ((before.aidr?.baseUrl ?? "") !== (after.aidr?.baseUrl ?? "")) changed.push("aidr.baseUrl");
  return changed;
}

function classifyMutation(before: SettingsFile, after: SettingsFile): AuditEntry[] {
  const entries: AuditEntry[] = [];
  const ts = new Date().toISOString();

  const aBefore = before.anthropic ?? {};
  const aAfter = after.anthropic ?? {};
  const anthropicFields: string[] = [];
  for (const k of ["apiKey", "authToken", "baseURL", "model", "chatMaxTokens"] as const) {
    if ((aBefore[k] ?? "") !== (aAfter[k] ?? "")) anthropicFields.push(`anthropic.${k}`);
  }
  if (anthropicFields.length) {
    entries.push({ ts, op: "anthropic_update", fields_changed: anthropicFields });
  }

  const beforeMap = new Map(before.environments.map((e) => [e.id, e]));
  const afterMap = new Map(after.environments.map((e) => [e.id, e]));
  for (const [id, env] of afterMap) {
    const prev = beforeMap.get(id);
    if (!prev) {
      entries.push({ ts, op: "env_create", env_id: id, env_name: env.name, fields_changed: ["created"] });
    } else {
      const fields = envFieldsDiff(prev, env);
      if (fields.length) {
        entries.push({ ts, op: "env_update", env_id: id, env_name: env.name, fields_changed: fields });
      }
    }
  }
  for (const [id, env] of beforeMap) {
    if (!afterMap.has(id)) {
      entries.push({ ts, op: "env_delete", env_id: id, env_name: env.name, fields_changed: ["deleted"] });
    }
  }

  if (before.active_id !== after.active_id) {
    entries.push({
      ts,
      op: "env_set_active",
      active_id_before: before.active_id,
      active_id_after: after.active_id,
      env_id: after.active_id,
      env_name: afterMap.get(after.active_id)?.name,
    });
  }

  return entries;
}

function appendAuditRows(entries: AuditEntry[]): void {
  if (!entries.length) return;
  const tx = rawDb().transaction(() => {
    for (const e of entries) {
      db().insert(settingsAudit).values({
        ts: e.ts,
        op: e.op,
        envId: e.env_id ?? null,
        envName: e.env_name ?? null,
        fieldsChanged: e.fields_changed ? JSON.stringify(e.fields_changed) : null,
        activeIdBefore: e.active_id_before ?? null,
        activeIdAfter: e.active_id_after ?? null,
      }).run();
    }
  });
  tx();
}

export async function readAuditLog(limit: number = 200): Promise<AuditEntry[]> {
  const rows = db()
    .select()
    .from(settingsAudit)
    .orderBy(desc(settingsAudit.id))
    .limit(limit)
    .all();
  return rows.map((r) => ({
    ts: r.ts,
    op: r.op as AuditEntry["op"],
    env_id: r.envId ?? undefined,
    env_name: r.envName ?? undefined,
    fields_changed: r.fieldsChanged ? (JSON.parse(r.fieldsChanged) as string[]) : undefined,
    active_id_before: r.activeIdBefore ?? undefined,
    active_id_after: r.activeIdAfter ?? undefined,
  }));
}

// ---------------------------------------------------------------------------
// Public API (preserved signatures)
// ---------------------------------------------------------------------------

function load(): SettingsFile {
  if (state.cache) return state.cache;
  const loaded = loadFromDb();
  state.cache = loaded;
  return loaded;
}

export function invalidateSettingsCache(): void {
  state.cache = null;
}

export function getSettings(): SettingsFile {
  return load();
}

export async function mutateSettings(
  mut: (current: SettingsFile) => SettingsFile,
): Promise<void> {
  const job = state.writeChain.then(async () => {
    const current = load();
    const next = mut({ ...current });
    if (next.version !== 2) throw new Error("mutator must preserve version: 2");
    if (!next.environments.length) throw new Error("settings must have at least one environment");
    if (!next.environments.find((e) => e.id === next.active_id)) {
      throw new Error("active_id must match an environment id");
    }
    const stripped = stripEmpties(next);
    const audit = classifyMutation(current, stripped);
    // Settings write + tamper-evidence audit rows commit as ONE transaction
    // (nested rawDb().transaction() calls become savepoints), so a failed
    // audit-append can't leave a persisted change with no audit row. The
    // in-memory cache only advances after the combined commit succeeds.
    rawDb().transaction(() => {
      persistToDb(stripped);
      appendAuditRows(audit);
    })();
    state.cache = stripped;
  });
  state.writeChain = job.catch(() => {
    /* swallow on the chain so future writes still run */
  });
  await job;
}

function stripEmpties(file: SettingsFile): SettingsFile {
  const out: SettingsFile = {
    version: 2,
    active_id: file.active_id,
    environments: file.environments.map((e) => {
      const next: EnvironmentRecord = {
        id: e.id,
        name: e.name,
        falcon: pruneFalcon(e.falcon),
      };
      if (e.irQuarantineGroupId) next.irQuarantineGroupId = e.irQuarantineGroupId;
      if (e.shadowAiBannedGroupId) next.shadowAiBannedGroupId = e.shadowAiBannedGroupId;
      const sanctioned = pruneSanctionedTools(e.shadowAiSanctionedTools);
      if (sanctioned) next.shadowAiSanctionedTools = sanctioned;
      const profiles = prunePatchProfiles(e.patchProfiles);
      if (profiles) next.patchProfiles = profiles;
      if (e.aidr) {
        const aidr: NonNullable<EnvironmentRecord["aidr"]> = {};
        if (e.aidr.token) aidr.token = e.aidr.token;
        if (e.aidr.baseUrl) aidr.baseUrl = e.aidr.baseUrl;
        if (Object.keys(aidr).length) next.aidr = aidr;
      }
      return next;
    }),
  };
  if (file.anthropic) {
    const a: SettingsFile["anthropic"] = {};
    for (const k of Object.keys(file.anthropic) as Array<keyof NonNullable<SettingsFile["anthropic"]>>) {
      const v = file.anthropic[k];
      if (v) a[k] = v;
    }
    if (Object.keys(a).length) out.anthropic = a;
  }
  return out;
}

// Backwards-compat: callers (runtime.ts) used these to render a "where is
// my config" hint in error messages. They now point at the DB file rather
// than the JSON. Keep them so the rest of the app doesn't change.

export function settingsFilePath(): string {
  return dbFilePath();
}

export function auditLogPath(): string {
  return dbFilePath();
}

