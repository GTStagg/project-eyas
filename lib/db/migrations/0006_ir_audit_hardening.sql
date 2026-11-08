-- 0006: IR audit hardening.
-- Statements are separated by a single '-->' marker on its own line.
-- Forward-only: NEVER edit this file once shipped. Add a new 000N_<name>.sql.
--
-- Two concerns, one migration:
--   1. (S1) Capture two host facts at IR kickoff so the contain/lift backstop
--      and the "Verified by Eyas" approval card have a server-side ground truth
--      that does NOT depend on the agent's prose (lib/chat/ir-ground-truth.ts):
--        - contained_at_start: was the host already contained when the
--          engagement began (nullable boolean; NULL = unknown / fetch failed).
--        - host_role: Falcon product_type_desc ("Domain Controller" / "Server"
--          / "Workstation") — drives the DC blast-radius warning on the
--          contain approval card.
--   2. (F6) Make ir_run_turns tamper-evident. The per-turn audit rows are the
--      durable record of what the agent did and what the operator approved;
--      silently editing or deleting them would defeat the point — same posture
--      as settings_audit (0001_init.sql).

ALTER TABLE ir_runs ADD COLUMN contained_at_start INTEGER;

-->

ALTER TABLE ir_runs ADD COLUMN host_role TEXT;

-->

-- Append-only enforcement on ir_run_turns ONLY. Deliberately NOT on ir_runs:
-- appendTurn() UPDATEs ir_runs.last_touched on every turn, and S1 stores the
-- two columns above at INSERT time, so ir_runs must stay mutable.
--
-- Cascade note: ir_run_turns has ON DELETE CASCADE from ir_runs, and
-- lib/db/client.ts sets foreign_keys=ON. A DELETE of an ir_runs row therefore
-- attempts to cascade-delete its turn rows, which fires this BEFORE DELETE
-- trigger and ABORTS the whole statement: the parent DELETE fails with
-- "FOREIGN KEY constraint failed" and NOTHING is deleted (verified on SQLite
-- 3.53.1; behaviour is identical whether recursive_triggers is OFF — the
-- default — or ON). So the trigger is not bypassed by the cascade; it blocks
-- it, which is the tamper-evidence we want. This is moot today — nothing in the
-- codebase deletes ir_runs or ir_run_turns — but a future retention/prune job
-- must DROP these triggers explicitly before it can delete either table's rows,
-- which is the intended friction.
CREATE TRIGGER IF NOT EXISTS ir_run_turns_no_update
BEFORE UPDATE ON ir_run_turns
BEGIN
  SELECT RAISE(FAIL, 'ir_run_turns is append-only');
END;

-->

CREATE TRIGGER IF NOT EXISTS ir_run_turns_no_delete
BEFORE DELETE ON ir_run_turns
BEGIN
  SELECT RAISE(FAIL, 'ir_run_turns is append-only');
END;
