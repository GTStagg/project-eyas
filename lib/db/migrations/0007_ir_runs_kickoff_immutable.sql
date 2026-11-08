-- 0007: ir_runs kickoff facts are immutable (tamper-resistance for the IR
-- safety-core ground truth — friction + loud-fail on edit, NOT cryptographic
-- tamper-evidence; a privileged actor can DROP this trigger. See SECURITY.md
-- "IR engagement audit integrity").
-- Statements are separated by a single '-->' marker on its own line.
-- Forward-only: NEVER edit this file once shipped. Add a new 000N_<name>.sql.
--
-- 0006 made ir_run_turns append-only but deliberately left ir_runs mutable,
-- because appendTurn() UPDATEs ir_runs.last_touched on every turn. That left a
-- gap: the KICKOFF FACTS on ir_runs are the server-side ground truth the IR
-- backstops read INSTEAD of trusting the agent's prose (lib/chat/ir-ground-truth.ts):
--   - campaign_scope_json     : the Phase-0 open-detection scope the F2b release
--     gate re-checks — and whose both-arrays-present shape is the captured-vs-
--     not-captured signal the gate fails closed on;
--   - contained_at_start      : whether the host was already contained at
--     kickoff (the F1 lift backstop refuses to lift a containment THIS workflow
--     did not apply);
--   - host_role               : Falcon product_type_desc (the Domain Controller
--     blast-radius warning on the contain approval card);
--   - session_id / env_id / playbook_ok / playbook_error / playbook_text_length
--     / schema_version : the engagement provenance.
-- Silently rewriting any of these after kickoff would let a tamper (or a bug)
-- flip a backstop's input without leaving a trace. Lock them at the DB layer so
-- the deterministic checks can't be quietly defeated.
--
-- COLUMN-SELECTIVE BEFORE UPDATE trigger: it RAISEs only when a locked column's
-- value actually changes, so the one legitimate post-insert mutation —
-- appendTurn() bumping last_touched (ir-run-record.ts) — still succeeds.
--   * `IS NOT` (the null-safe "distinct from" operator) is used rather than
--     `<>`: a change that sets a nullable column to/from NULL (e.g.
--     contained_at_start NULL -> 1, or host_role "Server" -> NULL) must still
--     be caught, but `<>` evaluates to NULL when either side is NULL and the
--     WHEN clause would then NOT fire — silently allowing exactly the tamper we
--     mean to block.
--   * RAISE(FAIL, ...) mirrors the 0006 ir_run_turns triggers: better-sqlite3
--     surfaces it as a thrown error on the offending .run(), and the UPDATE is
--     rejected.
--
-- DELETE is intentionally NOT trapped on ir_runs: the ir_run_turns no-delete
-- trigger (0006) already blocks deleting a run that has turns (ON DELETE CASCADE
-- fires that trigger and aborts the parent DELETE). A future retention/prune job
-- must DROP these triggers explicitly before it can delete either table — the
-- intended friction.
--
-- MAINTENANCE: last_touched is the ONLY ir_runs column meant to change after
-- INSERT. If a future migration adds another kickoff-immutable column, add it to
-- the WHEN clause (drop + recreate this trigger in that new migration).
CREATE TRIGGER IF NOT EXISTS ir_runs_kickoff_facts_immutable
BEFORE UPDATE ON ir_runs
WHEN
  NEW.aid IS NOT OLD.aid
  OR NEW.started_at IS NOT OLD.started_at
  OR NEW.session_id IS NOT OLD.session_id
  OR NEW.campaign_scope_json IS NOT OLD.campaign_scope_json
  OR NEW.playbook_ok IS NOT OLD.playbook_ok
  OR NEW.playbook_error IS NOT OLD.playbook_error
  OR NEW.playbook_text_length IS NOT OLD.playbook_text_length
  OR NEW.schema_version IS NOT OLD.schema_version
  OR NEW.contained_at_start IS NOT OLD.contained_at_start
  OR NEW.host_role IS NOT OLD.host_role
  OR NEW.env_id IS NOT OLD.env_id
BEGIN
  SELECT RAISE(FAIL, 'ir_runs kickoff facts are immutable; only last_touched may change');
END;
