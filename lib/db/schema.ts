import "server-only";
import { sqliteTable, integer, text, blob, index } from "drizzle-orm/sqlite-core";

// Single-row table (id check = 1) — single-user app, see auth_architecture.
// password_hash stays plaintext (it's already a one-way scrypt hash; encrypting
// would buy nothing and break verify timing).
export const auth = sqliteTable("auth", {
  id: integer("id").primaryKey(),
  passwordHash: text("password_hash").notNull(),
  createdAt: text("created_at").notNull(),
});

// Single-row global settings. Secret columns are AES-256-GCM (see crypto.ts).
export const settings = sqliteTable("settings", {
  id: integer("id").primaryKey(),
  anthropicApiKeyEnc: blob("anthropic_api_key_enc", { mode: "buffer" }),
  anthropicAuthTokenEnc: blob("anthropic_auth_token_enc", { mode: "buffer" }),
  anthropicBaseUrl: text("anthropic_base_url"),
  anthropicModel: text("anthropic_model"),
  // Per-turn output-token cap for the /chat surface, stored as a string (like
  // model/baseUrl above) and parsed+clamped in runtime.ts. NULL = use the
  // built-in default. See 0009_chat_max_tokens.sql.
  anthropicChatMaxTokens: text("anthropic_chat_max_tokens"),
  activeEnvId: text("active_env_id").notNull(),
  updatedAt: text("updated_at").notNull(),
});

export const environments = sqliteTable("environments", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  falconClientIdEnc: blob("falcon_client_id_enc", { mode: "buffer" }),
  falconClientSecretEnc: blob("falcon_client_secret_enc", { mode: "buffer" }),
  falconBaseUrl: text("falcon_base_url"),
  falconMemberCid: text("falcon_member_cid"),
  irQuarantineGroupId: text("ir_quarantine_group_id"),
  shadowAiBannedGroupId: text("shadow_ai_banned_group_id"),
  shadowAiSanctionedTools: text("shadow_ai_sanctioned_tools"), // JSON array
  patchProfiles: text("patch_profiles"), // JSON array of PatchProfile (see store.ts)
  aidrTokenEnc: blob("aidr_token_enc", { mode: "buffer" }),
  aidrBaseUrl: text("aidr_base_url"),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

// Append-only audit of every AIDR block verdict. Written by the chat route
// when guardChatCompletions returns blocked: true.
export const aidrBlocks = sqliteTable(
  "aidr_blocks",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    ts: text("ts").notNull(),
    envId: text("env_id").notNull(),
    sessionId: text("session_id"),
    eventType: text("event_type").notNull(), // "input" | "output"
    policy: text("policy"),
    displayMessage: text("display_message"),
    detectorsJson: text("detectors_json").notNull(),
    previewHash: text("preview_hash"),
  },
  (t) => ({
    tsIdx: index("aidr_blocks_ts_idx").on(t.ts),
    envTsIdx: index("aidr_blocks_env_ts_idx").on(t.envId, t.ts),
  }),
);

// Append-only via triggers (see 0001_init.sql). Same operations as
// AuditEntry in lib/config/store.ts.
export const settingsAudit = sqliteTable(
  "settings_audit",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    ts: text("ts").notNull(),
    op: text("op").notNull(),
    envId: text("env_id"),
    envName: text("env_name"),
    fieldsChanged: text("fields_changed"), // JSON array
    activeIdBefore: text("active_id_before"),
    activeIdAfter: text("active_id_after"),
  },
  (t) => ({ tsIdx: index("settings_audit_ts_idx").on(t.ts) }),
);

export const costLog = sqliteTable(
  "cost_log",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    ts: text("ts").notNull(),
    model: text("model").notNull(),
    surface: text("surface").notNull(),
    iterations: integer("iterations"),
    usageJson: text("usage_json").notNull(),
    // Environment this agent turn ran under. Nullable: rows written before
    // 0005 (or before the active env is known) stay unattributed rather than
    // mis-attributed across tenants. See 0005_ledger_env_id.sql.
    envId: text("env_id"),
  },
  (t) => ({
    tsIdx: index("cost_log_ts_idx").on(t.ts),
    surfaceTsIdx: index("cost_log_surface_ts_idx").on(t.surface, t.ts),
    envTsIdx: index("cost_log_env_ts_idx").on(t.envId, t.ts),
  }),
);

// Per-IR-session audit record. Composite PK (aid, started_at) matches the
// legacy file basename `<aid>-<startedAt>.json`. campaign_scope_json holds
// the parsed-or-raw extras_ir_campaign_scope output (JSON.stringify'd at the
// edge — see ir-run-record.ts).
export const irRuns = sqliteTable(
  "ir_runs",
  {
    aid: text("aid").notNull(),
    startedAt: integer("started_at").notNull(),
    sessionId: text("session_id").notNull(),
    lastTouched: integer("last_touched").notNull(),
    campaignScopeJson: text("campaign_scope_json").notNull(),
    playbookOk: integer("playbook_ok", { mode: "boolean" }).notNull(),
    playbookError: text("playbook_error"),
    playbookTextLength: integer("playbook_text_length").notNull(),
    schemaVersion: integer("schema_version").notNull().default(1),
    // Host facts captured at kickoff, independent of the agent's prose — the
    // server-side ground truth behind the contain/lift backstop and the
    // "Verified by Eyas" approval card (see lib/chat/ir-ground-truth.ts and
    // 0006_ir_audit_hardening.sql). containedAtStart null = unknown/fetch
    // failed; hostRole is Falcon product_type_desc.
    containedAtStart: integer("contained_at_start", { mode: "boolean" }),
    hostRole: text("host_role"),
    // Environment this engagement ran under. Nullable for the same reason as
    // cost_log.env_id — see 0005_ledger_env_id.sql.
    envId: text("env_id"),
  },
  (t) => ({
    lastTouchedIdx: index("ir_runs_last_touched_idx").on(t.lastTouched),
    aidStartedIdx: index("ir_runs_aid_started_idx").on(t.aid, t.startedAt),
    envLastTouchedIdx: index("ir_runs_env_last_touched_idx").on(t.envId, t.lastTouched),
  }),
);

export const irRunTurns = sqliteTable(
  "ir_run_turns",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    aid: text("aid").notNull(),
    runStartedAt: integer("run_started_at").notNull(),
    turnIndex: integer("turn_index").notNull(),
    startedAt: integer("started_at").notNull(),
    endedAt: integer("ended_at").notNull(),
    userInput: text("user_input").notNull(),
    toolCallsJson: text("tool_calls_json").notNull(),
    status: text("status").notNull(),
    usageJson: text("usage_json").notNull(),
    iterations: integer("iterations").notNull(),
  },
  (t) => ({
    runIdx: index("ir_run_turns_run_idx").on(t.aid, t.runStartedAt, t.turnIndex),
  }),
);

// Write-through cache for the in-memory chat conversation map. messages_json
// is the Anthropic.MessageParam[] for the session; ir_mode_json mirrors the
// IrMode struct on lib/chat/state.ts. Stored as a single blob to match the
// in-memory shape — turns are infrequent and transcripts are small.
export const chatSessions = sqliteTable(
  "chat_sessions",
  {
    id: text("id").primaryKey(),
    messagesJson: text("messages_json").notNull(),
    irModeJson: text("ir_mode_json"),
    lastTouched: integer("last_touched").notNull(),
    title: text("title"),
    createdAt: integer("created_at").notNull().default(0),
  },
  (t) => ({ lastTouchedIdx: index("chat_sessions_last_touched_idx").on(t.lastTouched) }),
);

// Per-environment knowledge base. One row per uploaded reference document;
// `content` is the full extracted plaintext (NOT encrypted — operator reference
// material, not a secret). The FTS5 retrieval index `knowledge_chunks` is a
// virtual table that Drizzle can't model, so it lives only in 0003's SQL and is
// read/written via rawDb() in lib/knowledge/. See knowledge store + retrieve.
export const knowledgeDocs = sqliteTable(
  "knowledge_docs",
  {
    id: text("id").primaryKey(),
    envId: text("env_id").notNull(),
    title: text("title").notNull(),
    sourceFilename: text("source_filename").notNull(),
    mime: text("mime").notNull(),
    content: text("content").notNull(),
    charCount: integer("char_count").notNull(),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (t) => ({ envIdx: index("knowledge_docs_env_idx").on(t.envId) }),
);

// Periodic point-in-time capture of deterministic tenant posture metrics, for
// trending over time. metrics_json holds the full PostureMetrics object
// (lib/posture/types.ts) so new metrics need no migration. partial=true means at
// least one category was unavailable (missing scope / upstream error) and stayed
// null. Append-only by convention (no trigger — a future retention job can prune,
// mirrors cost_log). Scoped per-tenant via env_id (the active environment at
// capture time).
export const postureSnapshots = sqliteTable(
  "posture_snapshots",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    capturedAt: text("captured_at").notNull(),
    envId: text("env_id").notNull(),
    schemaVersion: integer("schema_version").notNull().default(1),
    metricsJson: text("metrics_json").notNull(),
    captureMs: integer("capture_ms"),
    partial: integer("partial", { mode: "boolean" }).notNull().default(false),
  },
  (t) => ({
    capturedAtIdx: index("posture_snapshots_captured_at_idx").on(t.capturedAt),
    envCapturedIdx: index("posture_snapshots_env_captured_idx").on(t.envId, t.capturedAt),
  }),
);

// Migration tracking — the runner (lib/db/migrate.ts) inserts here after
// applying each .sql file. `checksum` is sha256 of the file contents:
// boot refuses to proceed if a previously-applied migration's on-disk
// content no longer matches, which catches the "someone edited a shipped
// migration" foot-gun.
export const migrations = sqliteTable("__migrations", {
  id: text("id").primaryKey(),
  checksum: text("checksum").notNull(),
  appliedAt: text("applied_at").notNull(),
});
