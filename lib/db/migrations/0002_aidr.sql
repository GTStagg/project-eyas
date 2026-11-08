-- AIDR (CrowdStrike AI Detection & Response) "AI Guard" integration.
-- Per-environment Bearer token + base URL, stored alongside Falcon creds.
-- Token is column-encrypted (AES-256-GCM) on the same path as Falcon creds.
--
-- Adds:
--   environments.aidr_token_enc — encrypted Bearer token (nullable = off)
--   environments.aidr_base_url  — literal base URL (default app-supplied)
--   aidr_blocks                 — append-only audit of every block verdict

ALTER TABLE environments ADD COLUMN aidr_token_enc BLOB;

-->

ALTER TABLE environments ADD COLUMN aidr_base_url TEXT;

-->

CREATE TABLE IF NOT EXISTS aidr_blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  env_id TEXT NOT NULL,
  session_id TEXT,
  event_type TEXT NOT NULL,
  policy TEXT,
  display_message TEXT,
  detectors_json TEXT NOT NULL,
  preview_hash TEXT
);

-->

CREATE INDEX IF NOT EXISTS aidr_blocks_ts_idx ON aidr_blocks(ts);

-->

CREATE INDEX IF NOT EXISTS aidr_blocks_env_ts_idx ON aidr_blocks(env_id, ts);

-->

CREATE TRIGGER IF NOT EXISTS aidr_blocks_no_update
BEFORE UPDATE ON aidr_blocks
BEGIN
  SELECT RAISE(FAIL, 'aidr_blocks is append-only');
END;

-->

CREATE TRIGGER IF NOT EXISTS aidr_blocks_no_delete
BEFORE DELETE ON aidr_blocks
BEGIN
  SELECT RAISE(FAIL, 'aidr_blocks is append-only');
END;
