// IR detection scope, server-side and deterministic:
//
// * phase0DetectionScope: every open detection on the host (the older,
//   un-clustered Phase 0 scope).
// * phase0ActionablePartition: workflow-entry triage. Splits the open
//   detections into actionable vs noise (the IR's own RTR preamble fires,
//   Shadow-AI audit IOC fires, retrospective IOC backfill) and pre-composes
//   the close calls for a host with nothing actionable. The chat route
//   prefetches it with the playbook and campaign scope on an IR primer.
// * phase3VerificationScope: every detection since the quarantine point,
//   classified retrospective / workflow-self / real; the release gate also
//   re-checks the Phase 0 originals by id.
//
// The agent used to page these itself and routinely truncated them, leaving
// detections open after Phase 4. Result shapes are the former sidecar tools'.

import type { EyasToolContext } from "../types";
import {
  alertId,
  alertsByIds,
  checkDeviceId,
  displayName,
  isIsoTimestamp,
  OPEN_STATUSES,
  parseIso,
  pick,
  statusOf,
  walkHostAlerts,
  type Obj,
} from "./alerts";
import {
  detectionIsRetrospectiveBackfill,
  detectionIsRetrospectiveIocMatch,
  detectionIsShadowAiIocAudit,
  detectionIsWorkflowSelfTriggered,
} from "./detection-classifiers";

/** Python truthiness, for flags read off alert records. */
function truthy(v: unknown): boolean {
  if (Array.isArray(v)) return v.length > 0;
  if (v && typeof v === "object") return Object.keys(v).length > 0;
  return Boolean(v);
}

/** Open alerts only: open status and an id. */
function openAlerts(alerts: Obj[]): Obj[] {
  return alerts.filter((r) => OPEN_STATUSES.has(statusOf(r)) && alertId(r));
}

/** The process a detection pivots on: its own process_id, else the first
 *  behavior's process_id / target_process_id. */
function pivotPid(r: Obj): string | null {
  if (r.process_id !== null && r.process_id !== undefined) return String(r.process_id);
  for (const b of Array.isArray(r.behaviors) ? r.behaviors : []) {
    if (!b || typeof b !== "object") continue;
    const bo = b as Obj;
    for (const k of ["process_id", "target_process_id"]) {
      if (bo[k]) return String(bo[k]);
    }
  }
  return null;
}

function phase0Item(r: Obj): Obj {
  return {
    composite_id: alertId(r),
    created_timestamp: pick(r, "created_timestamp"),
    severity: pick(r, "severity"),
    severity_name: pick(r, "severity_name"),
    status: statusOf(r),
    display_name: displayName(r),
    tactic: pick(r, "tactic"),
    technique: pick(r, "technique"),
    pivot_pid: pivotPid(r),
    has_adversary: truthy(r.has_adversary),
    adversary_ids: (Array.isArray(r.adversary_ids) ? r.adversary_ids : [])
      .filter((a) => a !== null && a !== undefined)
      .map(String),
  };
}

export async function phase0DetectionScope(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const deviceId = input.device_id;
  const bad = checkDeviceId(deviceId);
  if (bad) return bad;
  const walk = await walkHostAlerts(ctx, deviceId as string, { openOnly: true });
  if (!walk.ok) return walk.payload;

  const items = openAlerts(walk.alerts).map(phase0Item);
  const compositeIds = items.map((i) => i.composite_id as string);
  const timestamps = items
    .map((i) => i.created_timestamp)
    .filter((t): t is string => typeof t === "string")
    .sort();
  const pivotPids = [...new Set(items.map((i) => i.pivot_pid).filter((p): p is string => !!p))].sort();

  return {
    ok: true,
    device_id: deviceId,
    count: compositeIds.length,
    composite_ids: compositeIds,
    pivot_pids: pivotPids,
    truncated: walk.truncated,
    oldest_open_iso: timestamps[0] ?? null,
    newest_open_iso: timestamps.at(-1) ?? null,
    note:
      "These are the IR scope detections — pass `composite_ids` verbatim to Phase 4's " +
      "falcon_update_detections close call (as `ids`)." +
      (walk.truncated
        ? " HARD_CAP hit — tenant has 5000+ open detections on this host; bulk-close out-of-band before running IR."
        : ""),
    // Last, so the cap never cuts the counts (see Phase 3).
    items,
  };
}

export async function phase0ActionablePartition(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const deviceId = input.device_id;
  const bad = checkDeviceId(deviceId);
  if (bad) return bad;
  const walk = await walkHostAlerts(ctx, deviceId as string, { openOnly: true });
  if (!walk.ok) return walk.payload;

  const actionable: Obj[] = [];
  const workflowSelf: Obj[] = [];
  const shadowAiAudit: Obj[] = [];
  const retrospective: Obj[] = [];
  for (const r of openAlerts(walk.alerts)) {
    const base: Obj = {
      composite_id: alertId(r),
      display_name: displayName(r),
      severity: pick(r, "severity"),
      severity_name: pick(r, "severity_name"),
      created_timestamp: pick(r, "created_timestamp"),
    };
    // Most specific first, as in Phase 3: a preamble fire that is also a
    // backfill counts as retrospective.
    const [retro, reason] = detectionIsRetrospectiveBackfill(r);
    if (retro) {
      retrospective.push({ ...base, reason });
      continue;
    }
    if (detectionIsWorkflowSelfTriggered(r)) {
      workflowSelf.push(base);
      continue;
    }
    const [audit, domain] = detectionIsShadowAiIocAudit(r);
    if (audit) {
      shadowAiAudit.push({ ...base, matched_domain: domain });
      continue;
    }
    actionable.push(base);
  }

  const shouldProceed = actionable.length > 0;
  // falcon_update_detections arguments (plus `kind`), so a host with nothing
  // actionable closes its noise without the agent working out the shape.
  const bulkClose: Obj[] = [];
  if (!shouldProceed) {
    const ids = (rows: Obj[]) => rows.map((d) => d.composite_id);
    if (workflowSelf.length) {
      bulkClose.push({
        ids: ids(workflowSelf),
        status: "closed",
        add_tags: ["false_positive"],
        append_comment:
          "Workflow-self-triggered — RTR runscript preamble matched the PowerShell-encoded-command " +
          "detector. Not real attacker activity.",
        kind: "workflow_self",
      });
    }
    if (shadowAiAudit.length) {
      bulkClose.push({
        ids: ids(shadowAiAudit),
        status: "closed",
        append_comment:
          "Shadow-AI audit IOC fire — detect-only domain IOC created by Ban+Clean Phase 4 fired on " +
          "continued AI-provider DNS. Working as designed; no IR remediation appropriate.",
        kind: "shadow_ai_audit",
      });
    }
    if (retrospective.length) {
      bulkClose.push({
        ids: ids(retrospective),
        status: "closed",
        add_tags: ["false_positive"],
        append_comment:
          "Retrospective IOC match — fresh detection envelope, underlying event timestamps predate " +
          "the workflow window. Falcon backfill, not new activity.",
        kind: "retrospective",
      });
    }
  }

  return {
    ok: true,
    device_id: deviceId,
    total_open: actionable.length + workflowSelf.length + shadowAiAudit.length + retrospective.length,
    actionable,
    workflow_self_triggered: workflowSelf,
    shadow_ai_ioc_audit: shadowAiAudit,
    retrospective_ioc_match: retrospective,
    should_proceed_with_ir: shouldProceed,
    bulk_close_calls: bulkClose,
  };
}

/** Which of these (hydrated Phase 0 original) records still carry an open
 *  status. An id the store no longer returns never reaches here: absent is
 *  not an open detection on the host, the conservative read for a release
 *  gate. */
export function classifyPriorOpen(
  recs: unknown[],
  openStatuses: ReadonlySet<string> = OPEN_STATUSES,
): { checked: number; openIds: string[] } {
  let checked = 0;
  const openIds: string[] = [];
  for (const r of recs) {
    if (!r || typeof r !== "object" || Array.isArray(r)) continue;
    checked += 1;
    const id = alertId(r as Obj);
    if (id && openStatuses.has(statusOf(r as Obj))) openIds.push(id);
  }
  return { checked, openIds };
}

export async function phase3VerificationScope(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const deviceId = input.device_id;
  const bad = checkDeviceId(deviceId);
  if (bad) return bad;
  const sinceIso = input.since_iso;
  if (!sinceIso || typeof sinceIso !== "string") return { ok: false, error: "since_iso required" };
  // Strict: since_iso goes into an FQL literal.
  if (!isIsoTimestamp(sinceIso)) return { ok: false, error: `bad since_iso: ${sinceIso}` };
  const sinceTsS = (parseIso(sinceIso) as number) / 1000;

  const walk = await walkHostAlerts(ctx, deviceId as string, {
    extraFql: `created_timestamp:>='${sinceIso}'`,
    sort: "created_timestamp.asc",
  });
  if (!walk.ok) return walk.payload;

  const realIds: string[] = [];
  const selfIds: string[] = [];
  const retroIds: string[] = [];
  const items: Obj[] = [];
  for (const r of walk.alerts) {
    const id = alertId(r);
    if (!id) continue;
    const [retro, retroReason] = detectionIsRetrospectiveIocMatch(r, sinceTsS);
    const self = retro ? false : detectionIsWorkflowSelfTriggered(r);
    let classification: string;
    if (retro) {
      retroIds.push(id);
      classification = "retrospective_ioc_match";
    } else if (self) {
      selfIds.push(id);
      classification = "workflow_self_triggered";
    } else {
      realIds.push(id);
      classification = "real";
    }
    items.push({
      composite_id: id,
      created_timestamp: pick(r, "created_timestamp"),
      severity: pick(r, "severity"),
      severity_name: pick(r, "severity_name"),
      status: pick(r, "status"),
      display_name: displayName(r),
      tactic: pick(r, "tactic"),
      technique: pick(r, "technique"),
      classification,
      workflow_self_triggered: self,
      retrospective_ioc_match: retro,
      retrospective_reason: retroReason,
    });
  }

  // Release-gate re-check: the time-windowed scan above only sees detections
  // created after since_iso, but the Phase 0 originals predate it. Hydrate
  // those ids directly and report the ones still open. Any error fails the
  // whole call (the release gate blocks on it).
  let priorOpen: string[] = [];
  let priorChecked = 0;
  const prior = Array.isArray(input.prior_composite_ids) ? input.prior_composite_ids : [];
  const uniqPrior = [...new Set(prior.filter((c): c is string => typeof c === "string" && !!c))];
  if (uniqPrior.length > 0) {
    const got = await alertsByIds(ctx, uniqPrior);
    if (!got.ok) return got.payload;
    const { checked, openIds } = classifyPriorOpen(got.alerts);
    priorChecked = checked;
    priorOpen = openIds;
  }

  return {
    ok: true,
    device_id: deviceId,
    since_iso: sinceIso,
    real_composite_ids: realIds,
    workflow_self_composite_ids: selfIds,
    retrospective_composite_ids: retroIds,
    real_count: realIds.length,
    workflow_self_count: selfIds.length,
    retrospective_count: retroIds.length,
    total: realIds.length + selfIds.length + retroIds.length,
    truncated: walk.truncated,
    prior_open_composite_ids: priorOpen,
    prior_open_count: priorOpen.length,
    prior_checked_count: priorChecked,
    note:
      "Pass `workflow_self_composite_ids` AND `retrospective_composite_ids` to falcon_update_detections " +
      "(status='closed', add_tags=['false_positive']) (both buckets are never real — workflow-self is RTR " +
      "runscript preamble noise; retrospective is Falcon's IOC engine surfacing historical telemetry as " +
      "fresh detections after a custom IOC was added during the IR). `real_composite_ids` are the genuine " +
      "new detections during the workflow window — surface as `[REAL]` and use that count to drive RELEASE/HOLD.",
    // Last: it grows with the window, and the agent reads this through the
    // ~12 KB cap. The counts above must survive it.
    items,
  };
}
