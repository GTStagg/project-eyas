import type { ToolCallRecord } from "@/lib/chat/ir-run-record";

// Pure (no server-only, no DB) IR ground-truth derivations. Split out from
// ir-ground-truth.ts so the load-bearing logic — containment provenance, the
// Phase-0 scope union, the contain/group-add turn scan — is unit-testable
// without a SQLite handle. ir-ground-truth.ts does the DB reads and delegates
// the reasoning here. See `feedback_deterministic_over_agent_instruction`.

/** Does a recorded tool call's `device_ids` target this run's aid? The agent
 *  could contain / add a DIFFERENT host mid-engagement; that must not count
 *  toward "this workflow acted on THIS host". `device_ids` is the gated param
 *  (pinned in expected_tools.json); accept the array or bare-string shapes the
 *  agent may emit. Case-insensitive: an upper-cased or mixed-case aid (the
 *  route captures it via a `[A-Fa-f0-9]+` regex, and Falcon AIDs are hex but a
 *  primer / operator could pass any case) must still match, or the guard that
 *  reuses this would fail OPEN (skip the backstop) while this reader fails
 *  SAFE — an asymmetry a skeptic audit flagged. Falcon AIDs are canonically
 *  lowercase hex, so lowercasing both sides is loss-free. */
// Network-contain / lift tools. The retired sidecar names are what every IR run before
// the eyas-mcp migration recorded; the native names are eyas-mcp's. Ground
// truth recognizes both so historical ir_run_turns keep reading the same.
export const CONTAIN_TOOLS: ReadonlySet<string> = new Set(["extras_host_contain", "falcon_contain_hosts"]);
export const LIFT_TOOLS: ReadonlySet<string> = new Set([
  "extras_host_lift_containment",
  "falcon_lift_host_containment",
]);

// The device-id list a containment-family call targets: the retired sidecar tools took
// `device_ids`, eyas-mcp's take `ids`.
function targetIds(input: unknown): unknown {
  if (!input || typeof input !== "object") return undefined;
  const o = input as Record<string, unknown>;
  return o.device_ids ?? o.ids;
}

export function containTargetsAid(input: unknown, aid: string): boolean {
  if (!input || typeof input !== "object") return false;
  const want = aid.toLowerCase();
  const ids = targetIds(input);
  if (Array.isArray(ids)) return ids.some((x) => String(x).toLowerCase() === want);
  if (typeof ids === "string") return ids.toLowerCase() === want;
  return false;
}

/** Extract the device_ids a tool call targets, as a string[]. Mirrors the
 *  array-or-bare-string shapes `containTargetsAid` accepts; non-string elements
 *  and a missing / non-object input yield []. Used by the route's guard to
 *  resolve WHICH host an IR release write (lift / group-remove) targets when the
 *  current chat session isn't the one that ran the engagement — the guard then
 *  looks each id up in ir_runs to re-arm the deterministic backstop by aid. */
export function extractDeviceIds(input: unknown): string[] {
  if (!input || typeof input !== "object") return [];
  const ids = targetIds(input);
  if (Array.isArray(ids)) return ids.filter((x): x is string => typeof x === "string");
  if (typeof ids === "string") return [ids];
  return [];
}

/** Domain Controller detection from a Falcon product_type_desc. Network
 *  containment of a DC severs domain authentication fleet-wide, so this drives
 *  the blast-radius warning on the contain approval card (F4). */
/** Did a contain / lift call's RESULT confirm the action took effect for `aid`?
 *  A non-error MCP result isn't enough: the retired sidecar reported an API
 *  failure as a normal `{ok:false, errors}` payload (older recorded runs), and
 *  eyas-mcp reports a partial failure
 *  as `{partial_failure:true, succeeded_ids, failed_ids}` — both arrive with
 *  isError=false. Counting those as "the workflow contained this host" would
 *  let the F1 lift backstop release a containment the workflow never applied
 *  (e.g. a host already contained at kickoff). Unparseable content counts as
 *  unconfirmed: wrongly keeping a host contained is the safe failure. */
export function containResultConfirms(content: unknown, aid: string): boolean {
  // tool-bridge hands callbacks a joined string; accept the raw MCP block
  // array too (tool_bridge_content_is_string).
  if (Array.isArray(content)) {
    content = content
      .map((c) => (c && typeof c === "object" && typeof (c as { text?: unknown }).text === "string" ? (c as { text: string }).text : ""))
      .join("\n");
  }
  if (typeof content !== "string" || !content.trim()) return false;
  let body: unknown;
  try {
    body = JSON.parse(content);
  } catch {
    return false;
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return false;
  const o = body as Record<string, unknown>;
  if (typeof o.error === "string" || o.ok === false) return false;
  const want = aid.toLowerCase();
  if (Array.isArray(o.succeeded_ids)) {
    return o.succeeded_ids.some((x) => String(x).toLowerCase() === want);
  }
  return o.ok === true;
}

export function isDomainController(hostRole: string | null | undefined): boolean {
  return !!hostRole && /domain controller/i.test(hostRole);
}

export type DerivedContainment = {
  /** Did THIS workflow apply NETWORK containment to this run's host? Drives the
   *  F1 lift backstop. */
  agentContained: boolean;
  /** Host-group ids THIS workflow placed this run's host into, via an approved,
   *  successful extras_host_group_add_members whose device_ids include the aid.
   *  Phase 1 quarantine IS a group-add (the quarantine group is the PRIMARY
   *  containment mechanism — ir_playbook Phase 1), and Phase 4 release removes
   *  the host from it. The group-remove backstop refuses to remove the host
   *  from a group this workflow did not place it in — the sacred "only release
   *  what you applied" invariant at the GROUP layer. Without this, F1 only
   *  covered the network-contain layer, leaving the group-remove release path
   *  (the one Phase 4 actually uses) ungated behind the agent's judgment. */
  agentAddedGroupIds: string[];
};

/** Derive what THIS workflow did to this host from the persisted per-turn audit
 *  rows. Authoritative over the playbook's advisory `agent_contained` /
 *  `agent_added` prose flags — keyed off the recorded ToolCallRecord (name +
 *  approval + result.isError + gated device_ids), never the agent's narration.
 *  Scans EVERY turn (no early break): one pass collects both the network-contain
 *  provenance and the set of groups the host was added to. */
export function deriveContainmentFromTurns(
  turns: { toolCallsJson: string }[],
  aid: string,
): DerivedContainment {
  let agentContained = false;
  const agentAddedGroupIds = new Set<string>();

  for (const t of turns) {
    let calls: ToolCallRecord[];
    try {
      calls = JSON.parse(t.toolCallsJson) as ToolCallRecord[];
    } catch {
      continue;
    }
    if (!Array.isArray(calls)) continue;
    for (const c of calls) {
      if (
        c.approval !== "allow" ||
        c.result === null ||
        c.result.isError !== false ||
        !containTargetsAid(c.input, aid)
      ) {
        continue;
      }
      if (CONTAIN_TOOLS.has(c.name)) {
        if (containResultConfirms(c.result.contentExcerpt, aid)) agentContained = true;
      } else if (c.name === "extras_host_group_add_members") {
        const gid = (c.input as Record<string, unknown>).group_id;
        if (typeof gid === "string" && gid) agentAddedGroupIds.add(gid);
      }
    }
  }

  return { agentContained, agentAddedGroupIds: [...agentAddedGroupIds] };
}

/** Result of reading the persisted Phase-0 campaign scope
 *  (ir_runs.campaign_scope_json — the verbatim extras_ir_campaign_scope output).
 *
 *  `captured` is the load-bearing discriminator behind the F2b release gate: a
 *  SUCCESSFUL extras_ir_campaign_scope result ALWAYS carries both a `campaigns`
 *  array and an `unclustered` array — even on a clean kickoff with zero open
 *  detections (both are then `[]`). A FAILED / pending / non-scope payload
 *  (error object, scope_pending, truncated JSON, the degenerate "null" record)
 *  carries neither. So:
 *    - `captured === true,  ids === []`  → genuine clean kickoff: there were no
 *      originals to re-check, so the release gate may safely skip the
 *      prior-originals check.
 *    - `captured === true,  ids.length>0` → re-check these exact originals.
 *    - `captured === false`               → we never recorded what the host's
 *      originals were. The release gate must NOT treat this as "nothing to
 *      re-check" (that's the silent fail-open this split closes) — it fails
 *      closed instead. `ids` is always `[]` in this case.
 *
 *  `ids` unions every campaign's `composite_ids` with the `unclustered`
 *  detections' `composite_id` (unclustered are deliberately included: a release
 *  must not skip an original detection just because its ancestry couldn't be
 *  reconstructed), deduped. */
export type Phase0Scope = {
  captured: boolean;
  ids: string[];
};

export function parsePhase0Scope(campaignScopeJson: string): Phase0Scope {
  const uncaptured: Phase0Scope = { captured: false, ids: [] };
  let parsed: unknown;
  try {
    parsed = JSON.parse(campaignScopeJson);
  } catch {
    return uncaptured;
  }
  if (!parsed || typeof parsed !== "object") return uncaptured;

  const scope = parsed as { campaigns?: unknown; unclustered?: unknown };
  // Both arrays present ⇔ a real scope payload (success shape). An error /
  // scope_pending / partial object that merely parses as JSON carries neither.
  if (!Array.isArray(scope.campaigns) || !Array.isArray(scope.unclustered)) {
    return uncaptured;
  }

  const out = new Set<string>();
  for (const c of scope.campaigns) {
    if (!c || typeof c !== "object") continue;
    const ids = (c as Record<string, unknown>).composite_ids;
    if (!Array.isArray(ids)) continue;
    for (const id of ids) {
      if (typeof id === "string" && id) out.add(id);
    }
  }
  for (const u of scope.unclustered) {
    if (!u || typeof u !== "object") continue;
    const id = (u as Record<string, unknown>).composite_id;
    if (typeof id === "string" && id) out.add(id);
  }
  return { captured: true, ids: [...out] };
}
