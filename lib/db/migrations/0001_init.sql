-- 0.3.0 fresh-baseline schema for Project Eyas.
-- Single squashed migration — no upgrade path from prior versions exists.
-- Statements are separated by a single '-->' marker on its own line.
-- The migration runner (lib/db/migrate.ts) applies each statement within
-- a single transaction per file.
--
-- Forward-only: NEVER edit this file once shipped. Add a new
-- 000N_<name>.sql for any change. The runner checksums each file and
-- refuses to boot if a shipped migration has been modified.

CREATE TABLE IF NOT EXISTS __migrations (
  id TEXT PRIMARY KEY,
  checksum TEXT NOT NULL,
  applied_at TEXT NOT NULL
);

-->

CREATE TABLE IF NOT EXISTS auth (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-->

CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  anthropic_api_key_enc BLOB,
  anthropic_auth_token_enc BLOB,
  anthropic_base_url TEXT,
  anthropic_model TEXT,
  active_env_id TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-->

CREATE TABLE IF NOT EXISTS environments (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  falcon_client_id_enc BLOB,
  falcon_client_secret_enc BLOB,
  falcon_base_url TEXT,
  falcon_member_cid TEXT,
  ir_quarantine_group_id TEXT,
  shadow_ai_banned_group_id TEXT,
  shadow_ai_sanctioned_tools TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-->

CREATE TABLE IF NOT EXISTS settings_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  op TEXT NOT NULL,
  env_id TEXT,
  env_name TEXT,
  fields_changed TEXT,
  active_id_before TEXT,
  active_id_after TEXT
);

-->

CREATE INDEX IF NOT EXISTS settings_audit_ts_idx ON settings_audit(ts);

-->

-- Append-only enforcement. settings_audit is the durable record of who
-- changed what — silently editing or deleting rows would defeat the point.
CREATE TRIGGER IF NOT EXISTS settings_audit_no_update
BEFORE UPDATE ON settings_audit
BEGIN
  SELECT RAISE(FAIL, 'settings_audit is append-only');
END;

-->

CREATE TRIGGER IF NOT EXISTS settings_audit_no_delete
BEFORE DELETE ON settings_audit
BEGIN
  SELECT RAISE(FAIL, 'settings_audit is append-only');
END;

-->

CREATE TABLE IF NOT EXISTS cost_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  model TEXT NOT NULL,
  surface TEXT NOT NULL,
  iterations INTEGER,
  usage_json TEXT NOT NULL
);

-->

CREATE INDEX IF NOT EXISTS cost_log_ts_idx ON cost_log(ts);

-->

CREATE INDEX IF NOT EXISTS cost_log_surface_ts_idx ON cost_log(surface, ts);

-->

CREATE TABLE IF NOT EXISTS ir_runs (
  aid TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  session_id TEXT NOT NULL,
  last_touched INTEGER NOT NULL,
  campaign_scope_json TEXT NOT NULL,
  playbook_ok INTEGER NOT NULL,
  playbook_error TEXT,
  playbook_text_length INTEGER NOT NULL,
  schema_version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (aid, started_at)
);

-->

CREATE INDEX IF NOT EXISTS ir_runs_last_touched_idx
  ON ir_runs(last_touched DESC);

-->

CREATE INDEX IF NOT EXISTS ir_runs_aid_started_idx
  ON ir_runs(aid, started_at DESC);

-->

CREATE TABLE IF NOT EXISTS ir_run_turns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  aid TEXT NOT NULL,
  run_started_at INTEGER NOT NULL,
  turn_index INTEGER NOT NULL,
  started_at INTEGER NOT NULL,
  ended_at INTEGER NOT NULL,
  user_input TEXT NOT NULL,
  tool_calls_json TEXT NOT NULL,
  status TEXT NOT NULL,
  usage_json TEXT NOT NULL,
  iterations INTEGER NOT NULL,
  FOREIGN KEY (aid, run_started_at)
    REFERENCES ir_runs(aid, started_at)
    ON DELETE CASCADE
);

-->

CREATE INDEX IF NOT EXISTS ir_run_turns_run_idx
  ON ir_run_turns(aid, run_started_at, turn_index);

-->

-- Single-row-per-session chat history. Stored as a JSON blob to mirror
-- the in-memory Anthropic.MessageParam[] shape exactly. The DB is the
-- durability layer so an idle session survives a server restart inside
-- the rolling TTL window (see lib/chat/state.ts).
CREATE TABLE IF NOT EXISTS chat_sessions (
  id TEXT PRIMARY KEY,
  messages_json TEXT NOT NULL,
  ir_mode_json TEXT,
  last_touched INTEGER NOT NULL,
  title TEXT,
  created_at INTEGER NOT NULL DEFAULT 0
);

-->

CREATE INDEX IF NOT EXISTS chat_sessions_last_touched_idx
  ON chat_sessions(last_touched);
