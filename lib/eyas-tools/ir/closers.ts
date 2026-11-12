// IR Phase 4 closers and the on-request bulk close.
//
// * closeRemediated: walks every open detection on the host, matches each one
//   against the agent's remediation ledger (ledger-matcher.ts) and closes
//   only the matched ones, each with the evidence that matched. Unmatched
//   detections stay open for the operator.
// * closeUntouchedOriginals: on the operator's say-so after the ledger close,
//   closes the detections still open from before the engagement began (the
//   Phase 0 originals no remediation touched), which otherwise block release.
// * closeAllOpenOnHost: "the host is clean, close everything open on it".
//   eyas-mcp's falcon_close_host_detections does the work (runDispatch).
//
// Result shapes are the former sidecar tools'.

import { runDispatch } from "@/lib/mcp/native-dispatch";
import type { EyasToolContext } from "../types";
import {
  alertId,
  checkDeviceId,
  checkVerdict,
  closeIds,
  displayName,
  OPEN_STATUSES,
  parseIso,
  pick,
  statusOf,
  walkHostAlerts,
  type Obj,
  type Verdict,
} from "./alerts";
import { ledgerEntryMatchesAlert } from "./ledger-matcher";

/** Every open endpoint detection on the host, hydrated. */
async function openEppAlerts(ctx: EyasToolContext, deviceId: string): Promise<{ alerts: Obj[] } | { payload: Obj }> {
  const walk = await walkHostAlerts(ctx, deviceId, { openOnly: true });
  if (!walk.ok) return { payload: walk.payload };
  return { alerts: walk.alerts.filter((r) => OPEN_STATUSES.has(statusOf(r)) && alertId(r)) };
}

/** Pure alert → ledger classification. */
export function classifyAlertsAgainstLedger(
  alerts: Obj[],
  validEntries: Array<[number, Obj]>,
): { closed: Obj[]; unmatched: Obj[]; matchedIds: string[]; usedIndices: Set<number> } {
  const closed: Obj[] = [];
  const unmatched: Obj[] = [];
  const matchedIds: string[] = [];
  const usedIndices = new Set<number>();
  for (const alert of alerts) {
    const id = alertId(alert);
    const evidence: string[] = [];
    for (const [idx, entry] of validEntries) {
      const [matched, reason] = ledgerEntryMatchesAlert(entry, alert);
      if (matched && reason) {
        evidence.push(`[ledger#${idx} ${entry.kind as string}] ${reason}`);
        usedIndices.add(idx);
      }
    }
    if (evidence.length) {
      matchedIds.push(id as string);
      closed.push({
        composite_id: id,
        display_name: displayName(alert),
        created_timestamp: pick(alert, "created_timestamp"),
        evidence,
      });
    } else {
      unmatched.push({
        composite_id: id,
        display_name: displayName(alert),
        created_timestamp: pick(alert, "created_timestamp"),
        pivot_pid: pick(alert, "process_id"),
        tactic: pick(alert, "tactic"),
        technique: pick(alert, "technique"),
      });
    }
  }
  return { closed, unmatched, matchedIds, usedIndices };
}

/** Created strictly before `cutoffMs`. No readable creation time is not
 *  prior: the detection stays open rather than closing on a guess. */
function createdBefore(alert: Obj, cutoffMs: number): boolean {
  const created = alert.created_timestamp;
  if (typeof created !== "string") return false;
  const ms = parseIso(created);
  return ms !== null && ms < cutoffMs;
}

/** Composite ids of the open detections created before the engagement. */
export function selectUntouchedOriginals(alerts: Obj[], cutoffMs: number): string[] {
  const out: string[] = [];
  for (const a of alerts) {
    const id = alertId(a);
    if (id && createdBefore(a, cutoffMs)) out.push(id);
  }
  return out;
}

export async function closeRemediated(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const deviceId = input.device_id;
  const bad = checkDeviceId(deviceId);
  if (bad) return bad;
  const verdict = input.verdict ?? "true_positive";
  const badVerdict = checkVerdict(verdict);
  if (badVerdict) return badVerdict;
  const remediated = input.remediated;
  if (!Array.isArray(remediated)) return { ok: false, error: "remediated must be a list of ledger entries" };

  // Entries without a kind are reported, not silently dropped.
  const validEntries: Array<[number, Obj]> = [];
  const invalidIndices: number[] = [];
  remediated.forEach((e, i) => {
    if (e && typeof e === "object" && !Array.isArray(e) && typeof (e as Obj).kind === "string" && (e as Obj).kind) {
      validEntries.push([i, e as Obj]);
    } else {
      invalidIndices.push(i);
    }
  });
  const comment =
    typeof input.comment === "string"
      ? input.comment
      : "Closed via Project Eyas IR remediation-ledger match — Phase 4 step 1";

  const open = await openEppAlerts(ctx, deviceId as string);
  if ("payload" in open) return open.payload;
  const scopeCount = open.alerts.length;
  if (scopeCount === 0) {
    return {
      ok: true,
      device_id: deviceId,
      scope_count: 0,
      matched_count: 0,
      unmatched_count: 0,
      updated: 0,
      closed: [],
      unmatched: [],
      ledger_entries_used: 0,
      ledger_entries_unused: validEntries.map(([i]) => i),
      invalid_ledger_indices: invalidIndices,
      note: "No open detections on this host — nothing to close.",
    };
  }

  const { closed, unmatched, matchedIds, usedIndices } = classifyAlertsAgainstLedger(open.alerts, validEntries);
  let updated = 0;
  let batchErrors: Obj[] = [];
  if (matchedIds.length > 0) {
    const r = await closeIds(ctx, matchedIds, verdict as Verdict, comment);
    if (r.denied) return r.denied;
    updated = r.updated;
    batchErrors = r.batchErrors;
  }
  const unused = validEntries.map(([i]) => i).filter((i) => !usedIndices.has(i));

  // With the quarantine time, count the unmatched detections that predate the
  // engagement: the untouched Phase 0 originals that block release until the
  // operator decides on them (extras_ir_close_untouched_originals).
  let prior: Obj = {};
  const beforeIso = input.before_iso;
  if (beforeIso) {
    const cutoff = parseIso(beforeIso);
    if (cutoff === null) {
      prior = { before_iso_error: `before_iso is not an ISO 8601 timestamp: '${String(beforeIso)}'` };
    } else {
      const before = unmatched.filter((u) => createdBefore(u, cutoff));
      prior = {
        unmatched_prior_count: before.length,
        unmatched_prior_sample: before
          .slice(0, 10)
          .map((u) => u.display_name)
          .filter(Boolean),
      };
    }
  }

  // Key order matters: the agent reads this through the ~12 KB cap, and
  // `closed` / `unmatched` grow with the host's detection count. Every count
  // and decision field goes first so a large host can't truncate them away.
  const result: Obj = {
    ok: matchedIds.length === 0 || updated > 0,
    device_id: deviceId,
    verdict,
    scope_count: scopeCount,
    matched_count: matchedIds.length,
    unmatched_count: unmatched.length,
    updated,
    ...prior,
    ledger_entries_used: usedIndices.size,
    ledger_entries_unused: unused,
    invalid_ledger_indices: invalidIndices,
    note:
      `Closed ${updated} of ${matchedIds.length} matched detection(s) as ${verdict as string}. ` +
      `${unmatched.length} unmatched left open for operator review (no Phase 2 action touched their evidence).`,
    closed,
    unmatched,
  };
  if (batchErrors.length) {
    result.batch_errors = batchErrors;
    if (updated === 0 && matchedIds.length > 0) {
      result.ok = false;
      result.error = `all ${batchErrors.length} close batches failed; first error: ${String(batchErrors[0].error)}`;
    }
  }
  return result;
}

export async function closeUntouchedOriginals(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const deviceId = input.device_id;
  const bad = checkDeviceId(deviceId);
  if (bad) return bad;
  const verdict = input.verdict;
  const badVerdict = checkVerdict(verdict);
  if (badVerdict) return badVerdict;
  const beforeIso = input.before_iso;
  const cutoff = parseIso(beforeIso);
  if (cutoff === null) {
    return {
      ok: false,
      error: "before_iso must be the Phase 1 quarantine time as ISO 8601, e.g. 2026-05-01T12:00:00Z",
    };
  }
  const comment =
    typeof input.comment === "string"
      ? input.comment
      : "Closed at the operator's request after a Project Eyas IR engagement: open before the engagement " +
        "began and not remediated by the workflow";

  const open = await openEppAlerts(ctx, deviceId as string);
  if ("payload" in open) return open.payload;
  const ids = selectUntouchedOriginals(open.alerts, cutoff);
  if (ids.length === 0) {
    return {
      ok: true,
      device_id: deviceId,
      verdict,
      before_iso: beforeIso,
      scope_count: 0,
      updated: 0,
      composite_ids: [],
      note: "No open detections from before the engagement — nothing to close.",
    };
  }
  const r = await closeIds(ctx, ids, verdict as Verdict, comment);
  if (r.denied) return r.denied;
  const result: Obj = {
    ok: r.updated > 0,
    device_id: deviceId,
    verdict,
    before_iso: beforeIso,
    scope_count: ids.length,
    updated: r.updated,
    composite_ids: ids,
    left_open_after_cutoff: open.alerts.length - ids.length,
  };
  if (r.batchErrors.length) {
    result.batch_errors = r.batchErrors;
    if (r.updated === 0) result.error = `all close batches failed; first error: ${String(r.batchErrors[0].error)}`;
  }
  return result;
}

export async function closeAllOpenOnHost(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const deviceId = input.device_id;
  const bad = checkDeviceId(deviceId);
  if (bad) return bad;
  const verdict = input.verdict;
  const badVerdict = checkVerdict(verdict);
  if (badVerdict) return badVerdict;
  const comment =
    typeof input.comment === "string"
      ? input.comment
      : `Bulk-closed via Project Eyas extras_close_all_open_detections_on_host on host ${deviceId as string}`;
  return runDispatch(
    {
      ok: true,
      dispatch: {
        kind: "close_host_detections",
        device_id: (deviceId as string).toLowerCase(),
        resolution: verdict,
        comment,
        include_multi_host: input.include_multi_host === true,
      },
    },
    ctx.callNative,
  );
}
