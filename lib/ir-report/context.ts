import "server-only";
import type { IrRunRecord } from "@/lib/chat/ir-run-record";
import {
  callsByPhase,
  deriveDisposition,
  extractGuardrails,
  extractOutcome,
  PHASE_LABEL,
  turnsTotalActions,
  turnsTotalIterations,
  type Phase,
  type RunDisposition,
} from "@/lib/chat/ir-run-analysis";

// Deterministic context block for the incident-report generator. Turns a frozen
// IrRunRecord into a compact, structured digest the model synthesizes prose
// from — built ENTIRELY from the existing replay extractors (extractOutcome /
// extractGuardrails / callsByPhase / deriveDisposition), so the report and the
// /ir-runs/[file] technical replay can never tell two different stories.
//
// This text is fed to Claude as the user turn, NOT shown to an operator, so it
// may carry raw tool/script identifiers — the system prompt instructs the model
// to translate them into plain language in the OUTPUT.

// Per-call excerpt budget. Excerpts are already truncated to 2048 bytes at
// capture; we trim further here and stop including them once the cumulative
// budget is hit so a 50-call engagement can't blow the context window. Calls
// past the budget are still listed (name · approval · errored · input) — only
// their result excerpt is dropped.
const PER_CALL_EXCERPT = 400;
const PER_CALL_INPUT = 200;
const TOTAL_EXCERPT_BUDGET = 12_000;

const DISPOSITION_LABEL: Record<RunDisposition, string> = {
  remediated: "Remediated",
  released: "Released from quarantine",
  held: "Held for review",
  in_progress: "In progress",
  errored: "Completed with errors",
  no_findings: "No action taken",
};

function truncate(s: string, n: number): string {
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length <= n ? flat : flat.slice(0, n) + `…[+${flat.length - n} chars]`;
}

function compactInput(input: unknown): string {
  if (input === null || input === undefined) return "(none)";
  let s: string;
  try {
    s = typeof input === "string" ? input : JSON.stringify(input);
  } catch {
    s = String(input);
  }
  return truncate(s, PER_CALL_INPUT);
}

function fmtSpan(startedAt: number, lastTouched: number): string {
  const ms = Math.max(0, lastTouched - startedAt);
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min} min`;
  return `${(min / 60).toFixed(1)}h`;
}

/** Build the deterministic engagement digest the report model synthesizes from.
 *  Pure function — no DB, no upstream calls. */
export function renderIrReportContext(record: IrRunRecord): string {
  const outcome = extractOutcome(record);
  const guardrails = extractGuardrails(record);
  const buckets = callsByPhase(record);
  const disposition = deriveDisposition(record, outcome);

  const lines: string[] = [];

  lines.push("# Incident-response engagement record");
  lines.push("");
  lines.push(
    "Below is the complete, frozen record of one agentic incident-response engagement this console ran on a single host. Write the report from THIS DATA ONLY — make no claims it does not support.",
  );
  lines.push("");

  // --- Header facts ---------------------------------------------------------
  lines.push("## Engagement facts");
  lines.push(`- Affected host (AID): ${record.aid}`);
  lines.push(`- Started (UTC): ${new Date(record.startedAt).toISOString()}`);
  lines.push(`- Last activity (UTC): ${new Date(record.lastTouched).toISOString()}`);
  lines.push(`- Wall-clock span: ${fmtSpan(record.startedAt, record.lastTouched)}`);
  lines.push(`- Conversational turns: ${record.turns.length}`);
  lines.push(`- Total actions (tool calls): ${turnsTotalActions(record.turns)}`);
  lines.push(`- Total agent iterations: ${turnsTotalIterations(record.turns)}`);
  lines.push(`- Final disposition: ${DISPOSITION_LABEL[disposition]} (${disposition})`);
  lines.push("");

  // --- Outcome --------------------------------------------------------------
  lines.push("## What changed on the host (deterministic outcome)");
  const o: string[] = [];
  if (outcome.hostQuarantined) o.push("- Host was moved into the quarantine host group.");
  if (outcome.hostReleased) o.push("- Host was removed from the quarantine host group (released).");
  if (outcome.hostContained) o.push("- Network containment was applied to the host during this run.");
  if (outcome.hostContainmentLifted) o.push("- Network containment was lifted during closure.");
  for (const c of outcome.cleanupActions) {
    o.push(`- Cleanup action \`${c.scriptId}\` ran ${c.count} time${c.count === 1 ? "" : "s"} (operator-approved).`);
  }
  if (outcome.iocsAdded > 0) o.push(`- ${outcome.iocsAdded} custom IOC(s) added to the tenant watchlist.`);
  if (outcome.iocsRemoved > 0) o.push(`- ${outcome.iocsRemoved} custom IOC(s) removed.`);
  if (outcome.exclusionsAdded > 0) o.push(`- ${outcome.exclusionsAdded} detection exclusion(s) created.`);
  if (outcome.detectionsClosed > 0) {
    const how = outcome.bulkClosedHost
      ? "via bulk host close"
      : outcome.ledgerEvidenceCaptured
        ? "with per-detection ledger evidence"
        : "";
    o.push(`- ${outcome.detectionsClosed} detection(s) closed${how ? ` ${how}` : ""}.`);
  }
  if (outcome.detectionsLeftOpen > 0) {
    o.push(
      `- ${outcome.detectionsLeftOpen} detection(s) were deliberately LEFT OPEN — no Phase 2 action touched their evidence, so the workflow did not close them (operator review).`,
    );
  }
  if (o.length === 0) {
    o.push(
      "- No remediating actions were recorded. Either Phase 0 ran read-only and stopped (clean host), or every gated action was declined.",
    );
  }
  lines.push(...o);
  lines.push("");

  // --- Guardrails -----------------------------------------------------------
  lines.push("## Human oversight & guardrails that fired");
  if (guardrails.length === 0) {
    lines.push(
      "- None. Every approval was granted, no tool errored, and no deterministic classifier needed to flag a result.",
    );
  } else {
    for (const g of guardrails) {
      lines.push(`- [${g.kind}] ${g.detail} (tool: ${g.toolName})`);
    }
  }
  lines.push("");

  // --- Phase-by-phase timeline ---------------------------------------------
  lines.push("## Phase-by-phase action log");
  lines.push(
    "Tool calls grouped by IR phase, in order. `approval` is the human decision on a gated write (none = read-only). Use this to write the timeline and the per-phase response narrative.",
  );
  lines.push("");

  let excerptBudget = TOTAL_EXCERPT_BUDGET;
  for (const phase of [0, 1, 2, 3, 4] as Phase[]) {
    const calls = buckets[phase];
    lines.push(`### Phase ${phase} — ${PHASE_LABEL[phase]}`);
    if (calls.length === 0) {
      lines.push("- (no actions in this phase)");
      lines.push("");
      continue;
    }
    for (const { call } of calls) {
      const errored = call.result?.isError === true ? " · ERRORED" : "";
      lines.push(`- \`${call.name}\` · approval=${call.approval}${errored}`);
      lines.push(`  - input: ${compactInput(call.input)}`);
      const excerpt = call.result?.contentExcerpt ?? "";
      if (excerpt) {
        if (excerptBudget > 0) {
          const slice = truncate(excerpt, Math.min(PER_CALL_EXCERPT, excerptBudget));
          excerptBudget -= slice.length;
          lines.push(`  - result: ${slice}`);
        } else {
          lines.push("  - result: [excerpt omitted to bound report length]");
        }
      }
    }
    lines.push("");
  }

  return lines.join("\n");
}
