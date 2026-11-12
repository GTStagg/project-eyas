"""Agentic Identity IR workflow playbook.

Returned by the extras_identity_ir_workflow_playbook tool. Mirrors the host
IR playbook (ir_playbook.py) but pivots on an identity entity rather than
an AID. Falcon's IDP write surface is narrow (only create_policy_rule /
delete_policy_rules in FalconPy), so this workflow's load-bearing action is
the endpoint cascade — run the host IR playbook on each machine the user
has been logged into recently.

Sacred-state invariants (mirroring host IR):
  - watched_at_start: was this entity already on the IDP watchlist when
    the workflow started? If yes, do NOT remove from watchlist on RELEASE.
  - agent_quarantine_rule_id: the policy rule id THIS workflow created.
    Phase 4 deletes only that rule — never operator-authored ones.
"""

from __future__ import annotations


def render_identity_ir_playbook(entity_id: str | None, sam_account_name: str | None) -> tuple[str, str | None]:
    """Render the Identity IR workflow playbook for a specific entity.

    Either entity_id or sam_account_name (or both) may be provided. The agent
    will resolve the other half during Phase 0.

    Returns (playbook_text, error). Returns a non-empty error and empty text
    when both inputs are missing.
    """
    if not entity_id and not sam_account_name:
        return ("", "Identity IR workflow requires an entity_id or sam_account_name.")

    # The agent gets a parametric handle into the playbook text either way.
    handle = entity_id or sam_account_name or "(unknown)"
    sam = sam_account_name or "(resolve from entity)"
    eid = entity_id or "(resolve from samAccountName)"

    parts: list[str] = [
        f"You are running an agentic identity-IR workflow on entity `{handle}` in a CrowdStrike Falcon tenant. The operator decided this user warrants the full workflow: investigate cross-module exposure, contain the threat surface (hosts the user is active on + optional IDP policy-rule quarantine), verify clean, restore. You orchestrate the multi-step plan; the operator gates each consequential write through the approval UI.",
        "",
        f"Target entity: entity_id=`{eid}`, samAccountName=`{sam}`.",
        "",
        "The defining shape of identity IR vs host IR is the **endpoint cascade**: Falcon's IDP API surface is narrow (no disable-account, no kill-sessions, no reset-password — those are AD/IdP actions, not Falcon actions), so the load-bearing remediation is to run the host IR playbook on each endpoint the user has been logged into recently. That's where actual attacker dwell lives, and that's what Falcon RTR can act on.",
        "",
        "WORKFLOW PHASES — execute in order. Each write tool call pauses for explicit operator approval. Phase boundaries are gated by the writes inside them; you don't need to ask 'shall I proceed?' between phases.",
        "",
        "## Phase 0 — Discovery (read-only, no approval)",
        "Fan out in parallel:",
        f"- `falcon_search_risky_identities` limit=200 — find the entity record. Match the `accounts` array on samAccountName=`{sam}` (case-insensitive). Capture: primaryDisplayName, secondaryDisplayName, riskScore, riskScoreSeverity, riskFactors[], and the AD account descriptor (domain, samAccountName, enabled, passwordAttributes). Set a private flag `enabled_at_start = accounts[0].enabled` so Phase 4 can preserve that state if the operator pre-disabled the account.",
        f"- `falcon_search_detections` with filter=`product:'idp'+created_timestamp:>'<14 days ago, ISO 8601>'`, limit=100, sort=`created_timestamp.desc` — pull every IDP detection from the last 14 days. Filter client-side to ones where `user_name`, `source_account_name`, or `destination_account_name` matches `{sam}` (case-insensitive). Capture composite_id of every open detection — these are the IR-scope detection ids that Phase 4 closes on RELEASE.",
        f"- `falcon_get_user_endpoint_history` user_name=`{sam}` hours=168 limit=100 — REQUIRED. Returns the AIDs of every host this user has been logged into in the last 7 days, with the most-recent-login timestamp per host. This is the endpoint cascade target list. If empty, the user has no recent endpoint footprint and Phase 1's endpoint cascade is skipped.",
        "- (Optional) `falcon_search_idp_policy_rules` enabled=true — list current enabled IDP policy rules so you have context on which rules ALREADY scope this user (don't author a redundant rule).",
        "",
        "From the discovery output, build a private working list of remediation actions. Identify (a) the endpoint cascade targets — AIDs from endpoint_history, ranked by most-recent login first, capped at 5 (operator can re-run for additional hosts later), (b) whether an IDP policy-rule quarantine is warranted (see Phase 2 criteria), (c) which open IDP detections will be closed in Phase 4.",
        "",
        "Emit a `## Phase 0 — Discovery` section: executive verdict (one sentence), the entity context table (display name | risk severity | risk factors | account enabled), the IDP detections table (composite_id | severity | display_name | tactic | created_timestamp), and the endpoint cascade table (AID | hostname | last_login_timestamp). If there are zero detections AND zero recent endpoints, state explicitly that there's no actionable IR surface and STOP — emit the report, do NOT proceed to Phase 1.",
        "",
        "## Phase 1 — Endpoint cascade (N writes via host IR sub-workflow)",
        "For each AID in the cascade target list (top 3-5), kick off the host IR workflow as a sub-workflow. The cleanest pattern:",
        "1. Call `extras_ir_workflow_playbook` with the AID — this returns the host IR playbook text. Don't act on it directly; the host IR playbook is itself an agentic workflow that you should now walk in-line as a nested phase.",
        "2. Walk Phase 0 (Discovery) of the host IR for that AID — read-only, no approval. Report findings as a sub-section under this phase.",
        "3. If host IR Phase 0 produces findings (real persistence, malicious processes, etc.), continue with host IR Phases 1-4 for that host as a nested workflow — every write inside is approval-gated as usual.",
        "4. If host IR Phase 0 is clean (no findings), emit a one-line 'Host X clean — no host-side IR needed' and move to the next AID.",
        "",
        "The endpoint cascade is the load-bearing remediation in identity IR. Walking 3-5 nested host IR workflows is intentional: a compromised user identity often means multiple compromised endpoints, and per-host clean-up is where Falcon's actual write capability lives.",
        "",
        "Emit a `## Phase 1 — Endpoint cascade` section: one sub-section per AID with the host IR summary (clean / quarantined+remediated / held), and a final 'cascade complete' line.",
        "",
        "## Phase 2 — Optional IDP policy quarantine (1 write, gated)",
        "Decide whether to author a high-priority IDP policy rule scoped to this entity. This is a policy-level lever — Falcon's IDP enforcement engine evaluates rules at every authentication, so a 'block' or 'require MFA' policy rule scoped to this user effectively quarantines them from authenticating until the rule is removed.",
        "",
        "Apply the IDP policy quarantine when ANY of these signals hold:",
        "- A Phase 0 IDP detection has tactic `Initial Access` / `Credential Access` / `Lateral Movement` AND status is `new` or `reopened` (active attacker presence).",
        "- The risk score severity is HIGH or CRITICAL.",
        "- Two or more IDP detections fired within the last 4 hours.",
        "- The endpoint cascade in Phase 1 had to network-contain at least one host (signals an active threat the operator wants gone from the environment, not just from the host).",
        "",
        "Skip the policy quarantine when findings are stale or noise-grade — over-rotating with policy rules creates clutter for the IDP team and erodes operator trust.",
        "",
        "If applying: call `extras_identity_create_quarantine_policy_rule` with the samAccountName and a clear `reason` string explaining why (e.g. 'IR workflow 2026-05-03 — active credential-access detections'). The reason is stored on the rule for audit. The call returns `rule_id` — capture it as `agent_quarantine_rule_id` (this is sacred state — Phase 4 deletes only this rule). If the call returns `scope_pending: true` (IDP Policy Rules:write not granted), surface that in the output and continue without the rule — the rest of the workflow still runs.",
        "",
        "Emit a `## Phase 2 — Identity quarantine` section stating whether a policy rule was applied (with rule_id) or skipped (with reason).",
        "",
        "## Phase 3 — Verification (read-only, no approval)",
        "Re-run the identity discovery reads:",
        f"- `falcon_search_risky_identities` limit=200, then match on samAccountName=`{sam}` again. Has the risk score changed? Are the riskFactors different?",
        f"- `falcon_search_detections` with filter=`product:'idp'+created_timestamp:>'<24 hours ago, ISO 8601>'` — has any NEW IDP detection fired since Phase 0 naming this user? A new detection during/after remediation is the strongest signal that something is still active.",
        "- For each cascade AID, run a single `falcon_search_detections` filtered to that device.device_id with limit 10 sort newest, looking for new endpoint detections.",
        "",
        "Emit a `## Phase 3 — Verification` section: each Phase 0 finding mapped to its current state (resolved / still present / unverified), plus any new detections.",
        "",
        "## Phase 4 — Release decision",
        "Decide release / hold:",
        "- RELEASE if: no new IDP detection naming this user fired during remediation AND no new high/critical endpoint detection on any cascade AID AND every Phase 1 host IR sub-workflow either released or was operator-completed.",
        "- HOLD if: any new high/critical detection fired during remediation, OR any cascade host is still in HOLD state, OR risk score INCREASED during the run.",
        "",
        "If RELEASE, call the release tools in this strict order. EACH is approval-gated separately:",
        "1. **If `agent_quarantine_rule_id` is set** → call `extras_identity_delete_policy_rule` with that rule_id. Removing the policy rule restores normal authentication for the user. SKIP this call if Phase 2 didn't author a rule (`agent_quarantine_rule_id` is unset). Never delete a policy rule the agent didn't author — that's an operator-owned object.",
        "2. **Close in-scope IDP detections** — call `falcon_update_detections` ONCE with `ids` set to the array of Phase 0 IDP composite_ids you captured and `status=\"closed\"`. Single approval covers the bulk close. Scope: only detections open at Phase 0 — NOT new detections that fired during remediation (those stay open). If Phase 0 captured zero open IDP detections (clean entity that was IR'd anyway), skip this call.",
        "",
        "If HOLD: do NOT call the release tools. The IDP policy rule (if authored) stays in place. Emit a `## Phase 4 — Hold` section explaining why and recommend the operator either (a) re-run identity IR after manual investigation, (b) leave the policy quarantine in place while doing AD-side actions (disable account, kill sessions, reset password — those live outside Falcon API), or (c) escalate.",
        "",
        "## Final summary",
        "Emit a `## Summary` section (always, regardless of release/hold/clean): one paragraph for the operator's records covering original-state, what was found, what was done (which hosts cascaded, whether a policy rule was authored), what was left, current entity risk state, and explicit AD-side recommendations the operator should take outside Falcon (since Falcon's IDP write surface doesn't include account-disable / session-kill / password-reset).",
        "",
        "Style:",
        "- Markdown only. Phase headings as H2 (##). Tables for findings + verification mappings.",
        "- Be terse. The operator is reading this in real time as the workflow runs.",
        "- Do NOT narrate between tool calls. Make the calls, then emit the section for the phase.",
        "- Cite tool calls inline as [N] using the order they were called.",
        "",
        "OUTPUT DISCIPLINE:",
        "- Emit each phase section as soon as that phase's tool calls finish, before starting the next phase's calls.",
        "- The `agent_quarantine_rule_id` flag is sacred: only delete a policy rule THIS workflow authored. Operator-authored policy rules are off-limits.",
        "- The `enabled_at_start` flag is informational — Falcon API can't toggle account enabled status, so this tracks state for the operator's records but doesn't drive a workflow decision.",
    ]
    return "\n".join(parts), None
