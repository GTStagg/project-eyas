// Pure-function helpers that turn an IrRunRecord into a narrative for the
// /ir-runs/[file] replay surface. The data on disk is a transcript; this
// module produces the "incident report" view: which tool calls belong to
// which phase, what changed on the host (the outcome), and what the
// guardrails caught (the trust signal).
//
// All functions are deterministic and read-only. No tests against the
// schema — they take an IrRunRecord directly so fixtures stay simple.

import type { IrRunRecord, ToolCallRecord, TurnRecord } from "./ir-run-record";

export type Phase = 0 | 1 | 2 | 3 | 4;

export const PHASE_LABEL: Record<Phase, string> = {
  0: "Discovery",
  1: "Quarantine",
  2: "Remediation",
  3: "Verification",
  4: "Closure",
};

// Static name → phase classification. Read tools that can fire in any phase
// (falcon_search_*, projections) are intentionally absent — they inherit the
// phase of the prior classified call (see phaseForToolCall).
const NATURAL_PHASE: Record<string, Phase> = {
  // Phase 0 — Discovery
  extras_ir_workflow_playbook: 0,
  extras_ir_campaign_scope: 0,
  extras_ir_phase0_detection_scope: 0,
  extras_diagnose_ir_readiness: 0,
  extras_host_process_tree: 0,
  extras_host_rat_install_scan: 0,
  falcon_get_host_group_membership: 0,
  extras_host_group_membership_for_device: 0, // retired sidecar name — older runs
  // Phase 1 — Quarantine
  extras_host_group_add_members: 1,
  falcon_contain_hosts: 1,
  extras_host_contain: 1, // retired sidecar name — older runs
  // Phase 2 — Remediation
  extras_rtr_run_cleanup: 2,
  falcon_add_ioc: 2,
  falcon_remove_iocs: 2,
  extras_create_ml_exclusion: 2,
  extras_create_ioa_exclusion: 2,
  falcon_delete_exclusions: 2,
  // Phase 3 — Verification
  extras_ir_phase3_verification_scope: 3,
  // Phase 4 — Closure
  extras_ir_close_remediated: 4,
  extras_ir_close_untouched_originals: 4,
  extras_close_all_open_detections_on_host: 4,
  falcon_update_detections: 4,
  extras_update_detection_status: 4, // retired sidecar name — older runs
  falcon_lift_host_containment: 4,
  extras_host_lift_containment: 4, // retired sidecar name — older runs
  extras_host_group_remove_members: 4,
};

export type ClassifiedCall = {
  call: ToolCallRecord;
  turnIndex: number;
  phase: Phase;
};

/** Walk every tool call across every turn in chronological order and assign
 *  each one a phase. Calls with a natural phase use it; unclassified calls
 *  inherit from the last classified call (so a falcon_search_detections in
 *  the middle of Phase 2 cleanup ends up in Phase 2, where the operator
 *  expects to see it). */
export function classifyCalls(record: IrRunRecord): ClassifiedCall[] {
  const out: ClassifiedCall[] = [];
  let inheritedPhase: Phase = 0;
  for (const turn of record.turns) {
    for (const call of turn.toolCalls) {
      const natural = NATURAL_PHASE[call.name];
      const phase = natural ?? inheritedPhase;
      if (natural !== undefined) inheritedPhase = natural;
      out.push({ call, turnIndex: turn.turnIndex, phase });
    }
  }
  return out;
}

export function callsByPhase(record: IrRunRecord): Record<Phase, ClassifiedCall[]> {
  const buckets: Record<Phase, ClassifiedCall[]> = { 0: [], 1: [], 2: [], 3: [], 4: [] };
  for (const c of classifyCalls(record)) buckets[c.phase].push(c);
  return buckets;
}

// ---------------------------------------------------------------------------
// Outcome extraction
// ---------------------------------------------------------------------------

export type Outcome = {
  /** Host placed into the quarantine group at least once. */
  hostQuarantined: boolean;
  /** Network containment applied during this run (operator-applied containment
   *  pre-existing the run is NOT counted — that's contained_at_start). */
  hostContained: boolean;
  /** Containment lifted during Phase 4. */
  hostContainmentLifted: boolean;
  /** Host removed from quarantine group during Phase 4. */
  hostReleased: boolean;
  /** Cleanup primitives the operator approved (script_id × N successful runs). */
  cleanupActions: { scriptId: string; count: number }[];
  /** IOCs added to the tenant-wide watchlist (write side; remove ledger lives
   *  in the run record but is rare in IR proper). */
  iocsAdded: number;
  iocsRemoved: number;
  exclusionsAdded: number;
  /** Detections closed via the Phase 4 ledger closer; comes from parsing the
   *  result excerpt of extras_ir_close_remediated. */
  detectionsClosed: number;
  /** Detections the closer left open because no ledger entry matched their
   *  evidence — the trust-building number, since it tells the operator
   *  exactly what wasn't touched. */
  detectionsLeftOpen: number;
  /** True if the closer ran and reported per-detection ledger evidence. */
  ledgerEvidenceCaptured: boolean;
  /** Bulk-close rescue lane fired (out-of-band). */
  bulkClosedHost: boolean;
};

function tryParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function isObj(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

/** A tool call is "successful" when it returned without isError and the
 *  operator either approved it or it wasn't approval-gated. Denied / timed-
 *  out calls don't count toward the outcome. */
function callSucceeded(c: ToolCallRecord): boolean {
  if (c.approval === "deny" || c.approval === "timeout") return false;
  if (!c.result) return false;
  return c.result.isError !== true;
}

export function extractOutcome(record: IrRunRecord): Outcome {
  const cleanupCounts = new Map<string, number>();
  let iocsAdded = 0;
  let iocsRemoved = 0;
  let exclusionsAdded = 0;
  let hostQuarantined = false;
  let hostContained = false;
  let hostContainmentLifted = false;
  let hostReleased = false;
  let detectionsClosed = 0;
  let detectionsLeftOpen = 0;
  let ledgerEvidenceCaptured = false;
  let bulkClosedHost = false;

  for (const turn of record.turns) {
    for (const c of turn.toolCalls) {
      if (!callSucceeded(c)) continue;
      switch (c.name) {
        case "extras_host_group_add_members":
          hostQuarantined = true;
          break;
        case "falcon_contain_hosts":
        case "extras_host_contain":
          hostContained = true;
          break;
        case "falcon_lift_host_containment":
        case "extras_host_lift_containment":
          hostContainmentLifted = true;
          break;
        case "extras_host_group_remove_members":
          hostReleased = true;
          break;
        case "extras_rtr_run_cleanup": {
          const inp = isObj(c.input) ? c.input : null;
          const scriptId = (inp?.script_id as string | undefined) ?? "(unknown)";
          cleanupCounts.set(scriptId, (cleanupCounts.get(scriptId) ?? 0) + 1);
          break;
        }
        case "falcon_add_ioc":
          iocsAdded++;
          break;
        case "falcon_remove_iocs":
          iocsRemoved++;
          break;
        case "extras_create_ml_exclusion":
        case "extras_create_ioa_exclusion":
          exclusionsAdded++;
          break;
        case "extras_ir_close_remediated": {
          // Prefer the capture-time metrics — the contentExcerpt is truncated
          // to 2048 bytes, so a multi-detection ledger close JSON.parses to
          // null here and silently counts 0. Old records (no metrics) fall
          // back to parsing the excerpt.
          const m = c.result?.metrics;
          if (m && (m.closedCount !== undefined || m.unmatchedCount !== undefined)) {
            detectionsClosed += m.closedCount ?? 0;
            detectionsLeftOpen += m.unmatchedCount ?? 0;
            if (m.closedHasEvidence) ledgerEvidenceCaptured = true;
            break;
          }
          const parsed = c.result ? tryParse(c.result.contentExcerpt) : null;
          if (isObj(parsed)) {
            const closed = Array.isArray(parsed.closed) ? parsed.closed.length : 0;
            const unmatched = Array.isArray(parsed.unmatched)
              ? parsed.unmatched.length
              : 0;
            detectionsClosed += closed;
            detectionsLeftOpen += unmatched;
            // Evidence is captured when at least one closed entry has a
            // populated evidence array — that's what makes the ledger
            // closer different from the bulk closer.
            const closedArr = parsed.closed as unknown[] | undefined;
            if (closedArr?.some((e) => isObj(e) && Array.isArray(e.evidence) && e.evidence.length > 0)) {
              ledgerEvidenceCaptured = true;
            }
          }
          break;
        }
        case "extras_ir_close_untouched_originals": {
          // Operator-approved close of the Phase 0 originals the ledger
          // didn't match: they move from "left open" to "closed".
          const m = c.result?.metrics;
          let updated = 0;
          if (m && m.updatedCount !== undefined) {
            updated = m.updatedCount;
          } else {
            const parsed = c.result ? tryParse(c.result.contentExcerpt) : null;
            if (isObj(parsed) && typeof parsed.updated === "number") updated = parsed.updated;
          }
          detectionsClosed += updated;
          detectionsLeftOpen = Math.max(0, detectionsLeftOpen - updated);
          break;
        }
        case "extras_close_all_open_detections_on_host": {
          bulkClosedHost = true;
          const m = c.result?.metrics;
          if (m && m.updatedCount !== undefined) {
            detectionsClosed += m.updatedCount;
            break;
          }
          const parsed = c.result ? tryParse(c.result.contentExcerpt) : null;
          if (isObj(parsed)) {
            const updated = typeof parsed.updated === "number" ? parsed.updated : 0;
            detectionsClosed += updated;
          }
          break;
        }
      }
    }
  }

  const cleanupActions = Array.from(cleanupCounts.entries())
    .map(([scriptId, count]) => ({ scriptId, count }))
    .sort((a, b) => b.count - a.count);

  return {
    hostQuarantined,
    hostContained,
    hostContainmentLifted,
    hostReleased,
    cleanupActions,
    iocsAdded,
    iocsRemoved,
    exclusionsAdded,
    detectionsClosed,
    detectionsLeftOpen,
    ledgerEvidenceCaptured,
    bulkClosedHost,
  };
}

// ---------------------------------------------------------------------------
// Guardrails — what the system caught
// ---------------------------------------------------------------------------

export type GuardrailKind =
  | "approval_denied" // operator denied a write
  | "approval_timeout" // 5-min approval timeout fired
  | "tool_errored" // tool returned isError
  | "scope_pending" // staged-build pattern caught a missing API scope
  | "anchor_recovered" // process-tree wide-probe re-anchored a behavioral alert
  | "retrospective_classified" // Phase 3 classified a fresh detection as backfilled history
  | "workflow_self_classified" // Phase 3 classified a fresh detection as workflow self-trigger
  | "unmatched_left_open" // ledger closer left detections open
  | "cql_lint_blocked"; // pre-flight CQL linter rejected a query

export type Guardrail = {
  kind: GuardrailKind;
  /** Tool call this guardrail was attached to (basename string), so the UI
   *  can link the chip back to the call detail. */
  toolName: string;
  /** Operator-readable summary, ≤ ~140 chars. */
  detail: string;
};

function countMatches(text: string, key: string): number {
  // Match a JSON-ish key:value pair like  "real_count": 4   or "retrospective_count":12
  const rx = new RegExp(`"${key}"\\s*:\\s*(\\d+)`);
  const m = rx.exec(text);
  return m ? Number(m[1]) : 0;
}

export function extractGuardrails(record: IrRunRecord): Guardrail[] {
  const out: Guardrail[] = [];
  for (const turn of record.turns) {
    for (const c of turn.toolCalls) {
      if (c.approval === "deny") {
        out.push({
          kind: "approval_denied",
          toolName: c.name,
          detail: `Operator denied ${c.name} — write blocked at the gate.`,
        });
        continue;
      }
      if (c.approval === "timeout") {
        out.push({
          kind: "approval_timeout",
          toolName: c.name,
          detail: `Approval timed out for ${c.name} — write skipped after 5-min wait.`,
        });
        continue;
      }
      if (c.result?.isError === true) {
        out.push({
          kind: "tool_errored",
          toolName: c.name,
          detail: `${c.name} returned an error — workflow logged it instead of acting on a bad result.`,
        });
        // fall through; result excerpt may still carry guardrail signals
      }
      const text = c.result?.contentExcerpt ?? "";
      if (!text) continue;
      if (text.includes('"scope_pending": true') || text.includes('"scope_pending":true')) {
        out.push({
          kind: "scope_pending",
          toolName: c.name,
          detail: `${c.name} surfaced a staged-build placeholder — scope pending grant, no fabricated result.`,
        });
      }
      if (text.includes('"anchor_recovered": true') || text.includes('"anchor_recovered":true')) {
        out.push({
          kind: "anchor_recovered",
          toolName: c.name,
          detail: `Process-tree window re-anchored on actual process start — recovered ancestry that would have been missed.`,
        });
      }
      if (text.includes('"cql_lint"') && text.includes('"errors"')) {
        out.push({
          kind: "cql_lint_blocked",
          toolName: c.name,
          detail: `CQL pre-flight linter rejected the query before it hit NGSIEM — agent retried with a fix instead of guessing against a 400.`,
        });
      }
      if (c.name === "extras_ir_phase3_verification_scope") {
        const m = c.result?.metrics;
        const retro = m?.retrospectiveCount ?? countMatches(text, "retrospective_count");
        const wfself = m?.workflowSelfCount ?? countMatches(text, "workflow_self_count");
        if (retro > 0) {
          out.push({
            kind: "retrospective_classified",
            toolName: c.name,
            detail: `${retro} detection${retro === 1 ? "" : "s"} classified as retrospective IOC backfill — old events surfaced post-write, not new activity.`,
          });
        }
        if (wfself > 0) {
          out.push({
            kind: "workflow_self_classified",
            toolName: c.name,
            detail: `${wfself} detection${wfself === 1 ? "" : "s"} classified as workflow self-trigger (RTR runscript preamble) — discounted from HOLD trigger.`,
          });
        }
      }
      if (c.name === "extras_ir_close_remediated") {
        const m = c.result?.metrics;
        const unmatched =
          m?.unmatchedCount ??
          (() => {
            const parsed = tryParse(text);
            return isObj(parsed) && Array.isArray(parsed.unmatched)
              ? parsed.unmatched.length
              : 0;
          })();
        if (unmatched > 0) {
          out.push({
            kind: "unmatched_left_open",
            toolName: c.name,
            detail: `${unmatched} detection${unmatched === 1 ? "" : "s"} left open — no Phase 2 action touched their evidence (operator review).`,
          });
        }
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Run-level summary helpers (used by both the list page and the detail page)
// ---------------------------------------------------------------------------

export function turnsTotalActions(turns: TurnRecord[]): number {
  return turns.reduce((acc, t) => acc + t.toolCalls.length, 0);
}

export function turnsTotalIterations(turns: TurnRecord[]): number {
  return turns.reduce((acc, t) => acc + (t.iterations ?? 0), 0);
}

export function runHasErrors(record: IrRunRecord): boolean {
  return record.turns.some(
    (t) =>
      t.status === "errored" ||
      t.toolCalls.some((c) => c.result?.isError === true),
  );
}

/** Run-level disposition derived from outcome — what to render in the
 *  operator-facing pill at the top of the detail page. */
export type RunDisposition = "remediated" | "released" | "held" | "in_progress" | "errored" | "no_findings";

export function deriveDisposition(record: IrRunRecord, outcome: Outcome): RunDisposition {
  if (runHasErrors(record)) return "errored";
  if (outcome.detectionsClosed === 0 && outcome.cleanupActions.length === 0 && !outcome.hostQuarantined) {
    return "no_findings";
  }
  if (outcome.hostReleased) return "released";
  if (outcome.detectionsLeftOpen > 0 && !outcome.hostReleased) return "held";
  if (outcome.detectionsClosed > 0 || outcome.cleanupActions.length > 0) return "remediated";
  return "in_progress";
}
