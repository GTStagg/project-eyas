import { test, expect } from "@playwright/test";
import Database from "better-sqlite3";
import path from "node:path";

// Incident-report generation, end to end through the UI. The /ir-runs/[file]
// detail page mounts <IrReportPanel>; clicking "Generate report" POSTs to
// /api/ir-report, which synthesizes a layered report from the FROZEN engagement
// record (no upstream Falcon calls). This spec seeds one realistic engagement
// (quarantine -> cleanup -> denied IOC -> ledger close, 3 closed / 1 left open =>
// "held"), drives the panel, and asserts the VISIBLE report — the executive
// summary, a technical section, and the Print button — not derived metadata.
// Self-contained: seeds in beforeAll, deletes in afterAll, so it leaves no residue.

const AID = "abad1deaabad1deaabad1deaabad1dea";
const START = 1739111222000;
const KEY = `${AID}-${START}.json`;
const ACTIVE_ENV = "env_d79dcb4445ed";
const DB_PATH = path.join(process.cwd(), "data", "eyas.db");

function openDb() {
  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  return db;
}

// ir_run_turns is append-only in prod (migration 0006 BEFORE UPDATE/DELETE
// triggers). Test fixtures legitimately need to clear their own seed rows, so
// they drop the triggers, delete, then recreate them — leaving the dev DB
// exactly as found. This mirrors the migration's own note that a retention/prune
// job must DROP these triggers explicitly before deleting either table's rows.
// Both deletes need the triggers gone: ir_run_turns has ON DELETE CASCADE from
// ir_runs, so even DELETE FROM ir_runs fires the turn trigger and aborts.
const RECREATE_TRIGGERS = `
CREATE TRIGGER IF NOT EXISTS ir_run_turns_no_update
BEFORE UPDATE ON ir_run_turns
BEGIN
  SELECT RAISE(FAIL, 'ir_run_turns is append-only');
END;
CREATE TRIGGER IF NOT EXISTS ir_run_turns_no_delete
BEFORE DELETE ON ir_run_turns
BEGIN
  SELECT RAISE(FAIL, 'ir_run_turns is append-only');
END;`;

function clearSeed(db: Database.Database) {
  db.exec(
    "DROP TRIGGER IF EXISTS ir_run_turns_no_delete; DROP TRIGGER IF EXISTS ir_run_turns_no_update;",
  );
  try {
    db.prepare("DELETE FROM ir_run_turns WHERE aid = ?").run(AID);
    db.prepare("DELETE FROM ir_runs WHERE aid = ?").run(AID);
  } finally {
    db.exec(RECREATE_TRIGGERS);
  }
}

test.beforeAll(() => {
  const db = openDb();
  const ok = (excerpt: string, metrics?: Record<string, unknown>) => ({
    isError: false,
    contentExcerpt: excerpt,
    durationMs: 700,
    ...(metrics ? { metrics } : {}),
  });
  const calls = [
    { id: "c0", name: "extras_ir_workflow_playbook", input: { aid: AID }, approval: "none", result: ok("Loaded 5-phase IR playbook."), ts: START + 1000 },
    { id: "c1", name: "extras_ir_phase0_detection_scope", input: { aid: AID }, approval: "none", result: ok('{"open_detections":4,"techniques":["T1059.001","T1547.001"]}'), ts: START + 20000 },
    { id: "c2", name: "extras_host_group_add_members", input: { device_id: AID, name: "Project Eyas — Quarantine" }, approval: "allow", result: ok('{"ok":true,"added":1}'), ts: START + 60000 },
    { id: "c3", name: "extras_rtr_run_cleanup", input: { device_id: AID, script_id: "win-clear-run-keys" }, approval: "allow", result: ok('{"ok":true,"stdout":"removed 2 Run keys"}'), ts: START + 120000 },
    { id: "c4", name: "falcon_add_ioc", input: { type: "sha256", value: "deadbeef", action: "prevent" }, approval: "deny", result: null, ts: START + 160000 },
    { id: "c5", name: "extras_ir_close_remediated", input: { aid: AID }, approval: "allow", result: ok('{"closed":[{"id":"d1","evidence":["run-key"]}],"unmatched":["d4"]}', { closedCount: 3, unmatchedCount: 1, closedHasEvidence: true }), ts: START + 300000 },
  ];

  clearSeed(db);
  db.prepare(
    `INSERT INTO ir_runs (aid, started_at, session_id, last_touched, campaign_scope_json, playbook_ok, playbook_error, playbook_text_length, schema_version, env_id)
     VALUES (?, ?, ?, ?, ?, 1, NULL, 4096, 1, ?)`,
  ).run(AID, START, "spec-session", START + 360000, JSON.stringify({ summary: "single-host engagement" }), ACTIVE_ENV);
  db.prepare(
    `INSERT INTO ir_run_turns (aid, run_started_at, turn_index, started_at, ended_at, user_input, tool_calls_json, status, usage_json, iterations)
     VALUES (?, ?, 0, ?, ?, ?, ?, 'completed', ?, ?)`,
  ).run(
    AID,
    START,
    START,
    START + 360000,
    "Run the agentic IR workflow on host WIN-IR-DEMO-01.",
    JSON.stringify(calls),
    JSON.stringify({ input_tokens: 5200, output_tokens: 1400, cache_creation_input_tokens: 0, cache_read_input_tokens: 4100 }),
    8,
  );
  db.pragma("wal_checkpoint(PASSIVE)");
  db.close();
});

test.afterAll(() => {
  const db = openDb();
  clearSeed(db);
  db.pragma("wal_checkpoint(PASSIVE)");
  db.close();
});

function filterDevModeNoise(err: string): boolean {
  if (/HMR|webpack-hmr|websocket/i.test(err)) return false;
  if (/hydrat/i.test(err) && /caret-color/i.test(err)) return false;
  return true;
}

test("generates a layered incident report from an IR engagement", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  await page.goto(`/ir-runs/${encodeURIComponent(KEY)}`, {
    waitUntil: "domcontentloaded",
    timeout: 60_000,
  });

  // The IR detail page rendered (the AID is in the hero).
  await expect(page.getByText(AID, { exact: true }).first()).toBeVisible({ timeout: 30_000 });

  // The report CTA card is present, collapsed: heading + Generate button.
  await expect(page.getByRole("heading", { name: "Generate incident report" })).toBeVisible();
  const generate = page.getByRole("button", { name: "Generate report" });
  await expect(generate).toBeVisible();

  // Generate. Synthesis-only loop: one LLM turn, no upstream calls — but allow a
  // generous budget for model latency + cold MCP client spawn.
  await generate.click();

  // The streamed report renders. Assert VISIBLE report content: the executive
  // summary heading (leadership layer) + a technical section heading (analyst
  // layer). The model title-cases headings, so match case-insensitively.
  await expect(page.getByRole("heading", { name: /executive summary/i })).toBeVisible({
    timeout: 90_000,
  });
  await expect(
    page.getByRole("heading", { name: /response actions taken/i }),
  ).toBeVisible({ timeout: 90_000 });

  // The capture path (Print / PDF) appears only once the run completes with a
  // non-empty report — proves the `done` event fired and text is rendered.
  await expect(page.getByRole("button", { name: /Print \/ PDF/i })).toBeVisible({
    timeout: 30_000,
  });

  // No raw tool identifiers leaked into the rendered report (plain-operator copy).
  const reportText = await page.locator("[data-print-target]").innerText();
  expect(reportText).not.toMatch(/extras_|falcon_add_ioc|script_id|device_id/);

  const realErrors = consoleErrors.filter(filterDevModeNoise);
  expect(realErrors).toEqual([]);
});
