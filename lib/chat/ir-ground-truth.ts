import "server-only";
import { and, desc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { irRuns, irRunTurns } from "@/lib/db/schema";
import {
  deriveContainmentFromTurns,
  parsePhase0Scope,
  type Phase0Scope,
} from "@/lib/chat/ir-ground-truth-pure";

// Server-side IR ground truth. Everything here is DERIVED from the audit
// tables (ir_runs / ir_run_turns) and the kickoff host-facts capture — never
// from the agent's prose or the playbook's advisory flags. The contain/lift
// backstop (F1), the group-remove backstop (F1-group), and the release gate
// (F2b) read this so the highest-blast-radius transitions have a deterministic
// check behind the agent's judgment. The DB reads live here; the reasoning is
// pure + unit-tested in ir-ground-truth-pure.ts. See
// `feedback_deterministic_over_agent_instruction`: invariants in code, not
// prompt.

// Re-exported for the route's guard / approval card + Chat. The pure module is
// the single home; consumers import from here so server-only stays enforced.
export {
  CONTAIN_TOOLS,
  LIFT_TOOLS,
  containResultConfirms,
  containTargetsAid,
  extractDeviceIds,
  isDomainController,
  type Phase0Scope,
} from "@/lib/chat/ir-ground-truth-pure";

export type ContainmentGroundTruth = {
  /** Was the host already contained when the engagement started? Captured at
   *  kickoff from falcon_search_hosts. null = unknown (fetch failed/absent). */
  containedAtStart: boolean | null;
  /** Did THIS workflow apply NETWORK containment to this run's host? Derived
   *  authoritatively from the persisted turns — independent of the playbook's
   *  advisory `agent_contained` flag, scoped to a contain whose device_ids
   *  include this run's aid. NOTE: ir_run_turns is written post-turn
   *  (appendTurn), so a contain applied in the CURRENT, still-running turn is
   *  not yet reflected here; the route's guard augments this with a turn-local
   *  observation for the same-turn case. */
  agentContained: boolean;
  /** Host-group ids THIS workflow placed this run's host into (quarantine being
   *  the load-bearing one — Phase 1 quarantine is a group-add). The
   *  group-remove release backstop refuses to remove the host from a group this
   *  workflow did not add it to. Same post-turn caveat as agentContained; the
   *  route augments with a turn-local observation. */
  agentAddedGroupIds: string[];
  /** Falcon product_type_desc captured at kickoff, e.g. "Domain Controller". */
  hostRole: string | null;
};

/** Resolve the most recent IR run identity for a host, keyed by aid alone.
 *  The (aid, startedAt) composite the other readers need isn't always in hand:
 *  a lift / group-remove can arrive from a DIFFERENT chat session than the one
 *  that ran the engagement, or after the 72h IR-mode idle TTL evicted the
 *  session's IrMode — in both cases the route has no session-scoped identity to
 *  arm the backstops with, yet ir_runs still holds the ground truth keyed by
 *  aid and never expires. The route's guard uses this to re-arm the F1 lift /
 *  F1-group-remove / F2b release backstops aid-keyed when no live session
 *  identity matches the targeted host. Picks the LATEST run (max startedAt) —
 *  the engagement whose containment/quarantine a release would be undoing.
 *  Synchronous (better-sqlite3 reads are sync); aid lowercased to match the
 *  canonical-hex storage. */
export function getLatestIrRunIdentity(
  aid: string,
): { aid: string; startedAt: number } | null {
  const row = db()
    .select({ aid: irRuns.aid, startedAt: irRuns.startedAt })
    .from(irRuns)
    .where(eq(irRuns.aid, aid.toLowerCase()))
    .orderBy(desc(irRuns.startedAt))
    .limit(1)
    .get();
  return row ?? null;
}

/** Read the containment ground truth for one IR run, keyed by its composite
 *  (aid, startedAt). Synchronous — better-sqlite3 reads are sync. */
export function getContainmentGroundTruth(
  aid: string,
  startedAt: number,
): ContainmentGroundTruth {
  const run = db()
    .select()
    .from(irRuns)
    .where(and(eq(irRuns.aid, aid), eq(irRuns.startedAt, startedAt)))
    .get();

  const turns = db()
    .select({ toolCallsJson: irRunTurns.toolCallsJson })
    .from(irRunTurns)
    .where(and(eq(irRunTurns.aid, aid), eq(irRunTurns.runStartedAt, startedAt)))
    .all();

  const { agentContained, agentAddedGroupIds } = deriveContainmentFromTurns(
    turns,
    aid,
  );

  return {
    containedAtStart: run?.containedAtStart ?? null,
    agentContained,
    agentAddedGroupIds,
    hostRole: run?.hostRole ?? null,
  };
}

/** The Phase-0 detection scope captured at kickoff — read from
 *  ir_runs.campaign_scope_json (the persisted extras_ir_campaign_scope output).
 *  Returns `{ captured, ids }` (see Phase0Scope): `captured` distinguishes a
 *  genuine clean kickoff (zero open detections, both scope arrays present and
 *  empty) from a capture that never happened / failed (no run row, or an error /
 *  pending payload). The F2b release gate fails CLOSED when `!captured` rather
 *  than silently treating an uncaptured scope as "no originals to re-check".
 *  Parsing/union logic lives in parsePhase0Scope (pure + unit-tested).
 *
 *  When `captured`, `ids` are the exact ORIGINAL detections by composite_id; a
 *  release must confirm these are now closed, not merely that nothing new fired
 *  after kickoff. */
export function getPhase0Scope(aid: string, startedAt: number): Phase0Scope {
  const run = db()
    .select({ campaignScopeJson: irRuns.campaignScopeJson })
    .from(irRuns)
    .where(and(eq(irRuns.aid, aid), eq(irRuns.startedAt, startedAt)))
    .get();
  if (!run) return { captured: false, ids: [] };
  return parsePhase0Scope(run.campaignScopeJson);
}
