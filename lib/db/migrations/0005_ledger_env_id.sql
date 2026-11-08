-- Per-tenant attribution for the two previously-install-global ledgers.
-- cost_log (agent activity) and ir_runs (incident-response engagements) were
-- written without an environment id, so any metric derived from them blended
-- separate tenants together. Environments are treated as completely separate
-- tenants with their own metrics, so the scorecard (and future per-tenant
-- readouts) must attribute every row to the environment it ran under.
--
-- env_id is nullable: a row written before the active environment is known
-- stays unattributed rather than mis-attributed, and it lets these ALTERs run
-- without rewriting historical rows. Pre-existing rows are then backfilled to
-- whatever environment is active at upgrade time — the best available guess
-- for already-collected activity, and a no-op on a fresh install (no rows yet).
--
-- Forward-only: NEVER edit this file once shipped. Add a new 000N_<name>.sql.

ALTER TABLE cost_log ADD COLUMN env_id TEXT;

-->

ALTER TABLE ir_runs ADD COLUMN env_id TEXT;

-->

UPDATE cost_log
   SET env_id = (SELECT active_env_id FROM settings WHERE id = 1)
 WHERE env_id IS NULL;

-->

UPDATE ir_runs
   SET env_id = (SELECT active_env_id FROM settings WHERE id = 1)
 WHERE env_id IS NULL;

-->

CREATE INDEX IF NOT EXISTS cost_log_env_ts_idx ON cost_log(env_id, ts);

-->

CREATE INDEX IF NOT EXISTS ir_runs_env_last_touched_idx ON ir_runs(env_id, last_touched DESC);
