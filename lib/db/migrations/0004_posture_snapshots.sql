-- Periodic point-in-time capture of deterministic tenant posture metrics, for
-- trending over time (week-over-week / period-over-period deltas). One row per
-- snapshot; metrics_json holds the full PostureMetrics object (lib/posture/types.ts)
-- so new metrics can be added without a migration — same pattern as
-- cost_log.usage_json. partial=1 means at least one category was unavailable
-- (missing scope / upstream error) and stayed null.
--
-- Append-only by convention. Unlike aidr_blocks there is NO delete-blocking
-- trigger: snapshots are routine telemetry (mirrors cost_log), so a future
-- retention job can prune old rows without a migration to drop a trigger.

CREATE TABLE IF NOT EXISTS posture_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  captured_at TEXT NOT NULL,
  env_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL DEFAULT 1,
  metrics_json TEXT NOT NULL,
  capture_ms INTEGER,
  partial INTEGER NOT NULL DEFAULT 0
);

-->

CREATE INDEX IF NOT EXISTS posture_snapshots_captured_at_idx ON posture_snapshots(captured_at);

-->

CREATE INDEX IF NOT EXISTS posture_snapshots_env_captured_idx ON posture_snapshots(env_id, captured_at);
