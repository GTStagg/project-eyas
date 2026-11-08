// Server-side summarisers for tool results. A "summary" is a single short
// line surfaced on the collapsed tool-call bubble in the chat UI so the
// operator can read what landed without expanding the raw JSON payload.
//
// Only a small set of tools get summarised today — the IR Phase 0 prefetch
// triple (which lands as the first three bubbles in any IR engagement) and
// the engagement bookends (`extras_ir_close_remediated`, the rescue-lane
// close, and `extras_update_detection_status` since it fires repeatedly
// during Phase 4). Everything else falls through and renders unchanged.

function parseJson(content: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(content);
    if (v && typeof v === "object" && !Array.isArray(v)) {
      return v as Record<string, unknown>;
    }
  } catch {
    // fall through
  }
  return null;
}

function asNumber(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function pluralize(n: number, singular: string, plural?: string): string {
  return `${n} ${n === 1 ? singular : plural ?? singular + "s"}`;
}

/** Map an internal verdict id to operator-language text. */
function verdictLabel(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  if (v === "true_positive") return "true positive";
  if (v === "false_positive") return "false positive";
  return v;
}

export function summarizeToolResult(
  toolName: string,
  content: string,
  isError: boolean,
): string | undefined {
  if (isError) return "unavailable";
  const p = parseJson(content);
  if (!p) return undefined;
  if (p.ok === false) {
    const err = typeof p.error === "string" ? p.error : "unavailable";
    return `unavailable — ${err}`;
  }

  // -----------------------------------------------------------------------
  // IR Phase 0 prefetch (route.ts injects these before the agent loop runs)
  // -----------------------------------------------------------------------

  if (toolName === "extras_ir_workflow_playbook") {
    return "playbook loaded";
  }

  if (toolName === "extras_ir_campaign_scope") {
    const campaigns = asArray(p.campaigns);
    const totalOpen = asNumber(p.total_open) ?? 0;
    if (campaigns.length === 0 && totalOpen === 0) {
      return "0 open detections";
    }
    const vectorCounts = new Map<string, number>();
    for (const c of campaigns) {
      const dv = (c as Record<string, unknown>).delivery_vector;
      const kind =
        dv && typeof dv === "object"
          ? String((dv as Record<string, unknown>).kind ?? "unknown")
          : "unknown";
      vectorCounts.set(kind, (vectorCounts.get(kind) ?? 0) + 1);
    }
    const primary = [...vectorCounts.entries()].sort(
      (a, b) => b[1] - a[1],
    )[0]?.[0];
    const parts = [
      pluralize(campaigns.length, "campaign"),
      `${pluralize(totalOpen, "open detection")}`,
    ];
    if (primary && primary !== "unknown") parts.push(`primary: ${primary}`);
    if (p.capped) parts.push("capped");
    return parts.join(" · ");
  }

  if (toolName === "extras_ir_phase0_actionable_check") {
    const total = asNumber(p.total_open) ?? 0;
    const actionable = asArray(p.actionable).length;
    const selfTrigger = asArray(p.workflow_self_triggered).length;
    const shadowAi = asArray(p.shadow_ai_ioc_audit).length;
    const retro = asArray(p.retrospective_ioc_match).length;
    const noise = selfTrigger + shadowAi + retro;
    if (p.should_proceed_with_ir === false) {
      const noiseBits: string[] = [];
      if (selfTrigger) noiseBits.push(`${selfTrigger} workflow self-trigger`);
      if (shadowAi) noiseBits.push(`${shadowAi} shadow-AI audit`);
      if (retro) noiseBits.push(`${retro} retrospective`);
      const reason = noiseBits.length ? ` (${noiseBits.join(", ")})` : "";
      return `engagement clean — ${total} noise to close${reason}`;
    }
    return [`${actionable} actionable`, `${noise} noise`, `${total} total`].join(
      " · ",
    );
  }

  // -----------------------------------------------------------------------
  // Engagement bookends — Phase 4 close + bulk close + verdict update
  // -----------------------------------------------------------------------

  if (toolName === "extras_ir_close_remediated") {
    const updated = asNumber(p.updated) ?? 0;
    const matched = asNumber(p.matched_count) ?? 0;
    const unmatched = asNumber(p.unmatched_count) ?? 0;
    const usedEntries = asNumber(p.ledger_entries_used) ?? 0;
    const unusedEntries = asArray(p.ledger_entries_unused).length;
    const verdict = verdictLabel(p.verdict);
    const parts: string[] = [];
    if (matched === 0 && updated === 0) {
      parts.push("nothing to close");
    } else {
      parts.push(`closed ${updated} of ${matched} matched`);
    }
    if (verdict) parts.push(`verdict: ${verdict}`);
    if (unmatched > 0) parts.push(`${unmatched} left open for review`);
    if (usedEntries + unusedEntries > 0) {
      parts.push(`ledger ${usedEntries}/${usedEntries + unusedEntries} used`);
    }
    const batchErrors = asArray(p.batch_errors).length;
    if (batchErrors > 0) parts.push(`${batchErrors} batch error${batchErrors === 1 ? "" : "s"}`);
    return parts.join(" · ");
  }

  if (toolName === "extras_close_all_open_detections_on_host") {
    const updated = asNumber(p.updated) ?? 0;
    const scope = asNumber(p.scope_count) ?? 0;
    const verdict = verdictLabel(p.verdict);
    const parts: string[] = [`closed ${updated} of ${scope}`];
    if (verdict) parts.push(`verdict: ${verdict}`);
    const batchErrors = asArray(p.batch_errors).length;
    if (batchErrors > 0) parts.push(`${batchErrors} batch error${batchErrors === 1 ? "" : "s"}`);
    return parts.join(" · ");
  }

  if (toolName === "extras_update_detection_status") {
    const updated = asNumber(p.updated) ?? 0;
    const requested = asNumber(p.requested) ?? 0;
    const status = typeof p.status === "string" ? p.status : undefined;
    const verdict = verdictLabel(p.verdict);
    const parts: string[] = [];
    if (requested === 0) {
      parts.push("no detections requested");
    } else {
      parts.push(`updated ${updated} of ${requested}`);
    }
    if (status) parts.push(`status: ${status}`);
    if (verdict) parts.push(`verdict: ${verdict}`);
    return parts.join(" · ");
  }

  return undefined;
}
