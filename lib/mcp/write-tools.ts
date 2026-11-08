// Tools that mutate Falcon state. The agent loop pauses for explicit user
// approval before invoking any of these. List is intentionally inclusive —
// when in doubt, ask.
//
// Notable omissions (deliberate):
// - RTR (init_rtr_session, execute_rtr_read_only_command, delete_rtr_session,
//   pulse_rtr_session, and eyas-mcp's multi-host
//   run_rtr_read_only_command_on_hosts, which uses the read-only BatchCmd
//   endpoint + the same client-side allowlist): falcon-mcp v0.9 only exposes the *read_only* command
//   variant, which CrowdStrike enforces server-side against a whitelist of
//   non-mutating commands (ps, ls, dir, cat, env, registry-read, etc.).
//   Session create/delete/pulse are session-lifecycle operations with no
//   host-side effect. Three approval clicks per "show me running processes"
//   query would cripple the live-host-investigation UX. If a future
//   falcon-mcp version exposes execute_rtr_active_responder_command or
//   execute_rtr_admin_command (which DO run mutating commands), those MUST
//   be added here.
export const REQUIRES_APPROVAL: ReadonlySet<string> = new Set<string>([
  // IOC management
  "falcon_add_ioc",
  "falcon_remove_iocs",
  // Firewall
  "falcon_create_firewall_rule_group",
  "falcon_delete_firewall_rule_groups",
  // Custom IOA
  "falcon_create_ioa_rule",
  "falcon_create_ioa_rule_group",
  "falcon_update_ioa_rule",
  "falcon_update_ioa_rule_group",
  "falcon_delete_ioa_rules",
  "falcon_delete_ioa_rule_groups",
  // Scheduled reports
  "falcon_launch_scheduled_report",
  // Case Management (falcon-mcp 0.10.0 cases module — replaced the removed
  // incidents module). Cases are intentionally exposed to the agent now that
  // the upstream Cases API is usable; every mutation is approval-gated.
  // create_case in particular files a real Falcon case, so it must gate.
  "falcon_create_case",
  "falcon_update_case",
  "falcon_add_case_alert_evidence",
  "falcon_add_case_event_evidence",
  "falcon_manage_case_tags",
  // Cloud / CSPM (falcon-mcp 0.10.0 cloud module). No cloud scope granted on
  // this tenant, so these currently fail closed via the scope_pending
  // pattern — but they're gated anyway so a future scope grant can't make
  // an ungated write reachable.
  "falcon_create_cspm_suppression_rule",
  "falcon_delete_cspm_suppression_rules",
  // Falcon Shield / SaaS Security (falcon-mcp 0.10.0 shield module). Same
  // posture as the cloud writes above: no scope today, gated regardless.
  "falcon_dismiss_shield_check",
  // Quarantine (falcon-mcp 0.11.0 quarantine module). update_ releases /
  // un-releases / deletes quarantined files; delete_ purges them outright —
  // both mutate Falcon-held artifacts, so they gate. preview_ is a read-only
  // action-count preview and is intentionally NOT listed. The bridge exposes
  // every upstream tool by default, so an un-gated write here would otherwise
  // be reachable the moment the quarantine scope is granted.
  "falcon_update_quarantined_files",
  "falcon_delete_quarantined_files",
  // Correlation Rules (falcon-mcp 0.11.0 correlationrules module). create /
  // update / delete persist NGSIEM correlation-rule definitions tenant-wide.
  // Gated regardless of current scope, same fail-closed posture as the cloud
  // and shield writes above.
  "falcon_create_correlation_rule",
  "falcon_update_correlation_rule",
  "falcon_delete_correlation_rules",
  // Native detections / host_groups / exclusions / policies writes (falcon-mcp
  // 0.12.0). All 13 are gated here regardless of whether the agent can see them.
  // They split at the bridge (NATIVE_WRITE_SUPPRESS in lib/mcp/tool-bridge.ts):
  //   - 8 are SUPPRESSED and never reach the agent — each has a richer FalconPy
  //     twin (extras_update_detection_status / extras_*_exclusion / extras_*_host
  //     _group / extras_*_policy) whose pre-write or in-sidecar value-add can't be
  //     re-injected onto a native path; gating is the fail-closed backstop.
  //   - 5 are ADOPTED and exposed to the agent as the primary write path
  //     (falcon_delete_exclusions / falcon_update_host_group /
  //     falcon_delete_host_groups / falcon_update_policy /
  //     falcon_perform_policy_action) — no twin or only a thin by-id twin, so
  //     they're exposed-and-gated like UPSTREAM_WRITES.
  // /audit-write-tools asserts every suppressed native write is gated AND
  // suppressed, every adopted native write is gated AND NOT suppressed, and the
  // two sets stay disjoint (its NATIVE_WRITES / NATIVE_ADOPTED lists are the
  // authoritative accounting — see also the 0.16.0 grouping-tag + 0.17.0
  // Fusion/AgentWorks writes below).
  "falcon_update_detections",
  "falcon_create_exclusion",
  "falcon_update_exclusion",
  "falcon_delete_exclusions",
  "falcon_create_host_group",
  "falcon_update_host_group",
  "falcon_delete_host_groups",
  "falcon_perform_host_group_action",
  "falcon_create_policy",
  "falcon_update_policy",
  "falcon_delete_policies",
  "falcon_perform_policy_action",
  "falcon_set_policy_precedence",
  // Native host grouping-tag write (falcon-mcp 0.16.0 #487). ADOPTED — no
  // sidecar twin (Eyas quarantines via STATIC host-group membership, not
  // FalconGroupingTags), so there's no pre-write value-add to route around;
  // native is the primary path, gated. NOT in NATIVE_WRITE_SUPPRESS. The
  // annotation backstop already gates it fail-closed (readOnlyHint:false); this
  // explicit entry keeps the registry authoritative and clears the
  // /agent-toolbox annotated-but-ungated drift banner. Grouping tags can drive
  // dynamic host-group → policy assignment, so this changes security posture.
  "falcon_manage_host_grouping_tags",
  // Fusion SOAR + AgentWorks writes (falcon-mcp 0.17.0). Gated regardless of
  // their suppress/adopt disposition at the bridge:
  //   - falcon_execute_workflow → KEEP suppressed (NATIVE_WRITE_SUPPRESS): the
  //     twin extras_workflows_execute resolves the on-demand trigger and projects
  //     the execution record — pre-write value-add a native path can't re-inject.
  //   - falcon_invoke_agentworks_agent → ADOPTED (NOT suppressed): invokes a
  //     Charlotte AI agent; no sidecar twin, so native is the primary path.
  //     User-approved adopt — the approval gate keeps it human-in-the-loop even
  //     though agent-invocation is autonomous-AI-adjacent.
  "falcon_execute_workflow",
  "falcon_invoke_agentworks_agent",
  // Data Security native writes (falcon-mcp 0.20.0 #576 — the dataprotection
  // module was renamed datasecurity and gained generic entity_type-keyed
  // create/update). Gated regardless of bridge disposition:
  //   - falcon_create_data_security_entity → KEEP suppressed: the
  //     extras_create_data_protection_* twins apply monitor-first defaults
  //     (protection_mode="monitor", response_action="allow") before the write;
  //     the native takes an opaque body, so that can't be re-injected.
  //   - falcon_update_data_security_entity → ADOPTED (NOT suppressed): no twin,
  //     so native is the only edit path. User-approved adopt; an update can
  //     flip a fleet-wide DLP policy to enforce, so the gate is load-bearing.
  "falcon_create_data_security_entity",
  "falcon_update_data_security_entity",
  // eyas-mcp's sidecar port native ports of sidecar writes — KEEP suppressed
  // until their family migrates (NATIVE_WRITE_SUPPRESS); gated regardless.
  "falcon_contain_hosts",
  "falcon_lift_host_containment",
  // Data Protection (DLP) configuration writes. These FalconPy-backed sidecar
  // tools create the content-pattern -> classification -> policy chain with
  // monitor-first defaults. Tenant-wide config writes, gated fail-closed like
  // the correlation-rule writes above.
  "extras_create_data_protection_content_pattern",
  "extras_create_data_protection_classification",
  "extras_create_data_protection_policy",
  // falcon-extras (FalconPy-backed sidecar) — host containment
  "extras_host_contain",
  "extras_host_lift_containment",
  // falcon-extras — detection lifecycle. Verdict transitions (true_positive,
  // false_positive, closed, ignored, reopened) come through the agent loop
  // and gate here. The `in_progress` claim fires server-side on Queue button
  // click via /api/queue/claim and bypasses this gate by design — it's
  // bookkeeping, not a verdict.
  "extras_update_detection_status",
  // One-shot bulk close — every open detection on a host. Single approval
  // covers the whole bulk close (200-500+ detections in one card). Used
  // both as the IR rescue lane (operator says "host is clean, just close
  // them all") and as the agent's preferred tool when the IR workflow
  // would otherwise require it to wrangle composite_id arrays itself.
  "extras_close_all_open_detections_on_host",
  // Production IR Phase 4 closer. Closes only those detections whose
  // evidence intersects the supplied remediation ledger; unmatched
  // detections stay open. Per-id audit trail records WHICH ledger entry
  // triggered each close. This is the IR-context closer; the bulk
  // closer above is for out-of-band rescue / queue drain.
  "extras_ir_close_remediated",
  // falcon-extras — host group membership (static groups only)
  "extras_host_group_add_members",
  "extras_host_group_remove_members",
  // falcon-extras — Fusion workflow on-demand execution. The READ companion
  // (extras_workflows_execution_result) is intentionally NOT gated.
  "extras_workflows_execute",
  // falcon-extras — RTR-driven patching. Only the executor is gated; the
  // catalog/resolver tools are read-only.
  "extras_rtr_run_patch",
  // falcon-extras — saving a generic-installer param-set as a reusable per-
  // tenant patch profile. Gated because saving establishes a TRUSTED, reusable
  // install source (a vendor URL the operator blesses for future one-click
  // runs); that's a conscious decision distinct from running it once. No script
  // bytes are stored — params are re-validated against the win-app-install
  // manifest regex at save time. The read companion (extras_list_patch_profiles)
  // is NOT gated; running a saved profile gates separately at extras_rtr_run_patch.
  "extras_save_patch_profile",
  // falcon-extras — RTR-driven host cleanup (incident-response remediation).
  // Only the executor is gated; list / resolve are read-only.
  "extras_rtr_run_cleanup",
  // RTR readiness probe. The payload is a fixed no-op (`exit 0`), but each
  // probe uploads a cloud script, opens an RTR admin session and runs
  // `runscript` on whichever device_id the agent picks, so it gates like
  // the other RTR admin paths.
  "extras_rtr_wait_until_ready",
  // falcon-extras — detection-tuning exclusion CREATES. Long-lived artifacts;
  // create is the consequential write and stays on the sidecar because it runs
  // the IOA zero-width-assertion + single-quote pre-flight before writing.
  // By-id DELETE is handled by native falcon_delete_exclusions (adopted in
  // 0.6.7); the thin extras_delete_*_exclusion twins were un-registered.
  // List variants stay read-only.
  "extras_create_ml_exclusion",
  "extras_create_ioa_exclusion",
  // falcon-extras — Shadow-AI prevention bundle. Creates a Custom IOA rule
  // group + rules and binds it to a Prevention Policy. Idempotent but the
  // first run on a tenant has fleet-wide effect once the policy is attached
  // to a host group, so it's gated. Status / dry-run paths are separate
  // tools or flags and remain read-only.
  "extras_shadow_ai_adopt_prevention",
  // falcon-extras — IR quarantine setup. One-time tenant provisioning.
  // Creates the canonical "Project Eyas - IR Quarantine" host group OR
  // creates / adopts the prevention policies bound to it (per-platform:
  // Windows / macOS / Linux) at AGGRESSIVE prevention sliders. Persistent
  // tenant changes; gated. The companion read-only diagnostic
  // (extras_diagnose_quarantine_setup) is NOT gated.
  "extras_create_quarantine_host_group",
  "extras_adopt_quarantine_host_group",
  "extras_provision_quarantine_policy",
  // falcon-extras — generic prevention-policy → host-group detach.
  // Inverse of the add-host-group action we use during provisioning.
  // Used to clean up legacy operator-created policies that are still
  // attached to the IR Quarantine / Shadow-AI Banned groups alongside
  // the new app-managed dedicated policies.
  "extras_detach_prevention_policy_from_host_group",
  // falcon-extras — Shadow-AI Banned setup. Mirrors the IR pattern:
  // creates the "Project Eyas - Shadow-AI Banned" host group OR provisions
  // the prevention policies bound to it. Operator-driven, not a per-host
  // action — the per-host "ban" is a separate extras_host_group_add_members
  // call. Read-only diagnostic (extras_diagnose_shadow_ai_banned_setup) is
  // not gated.
  "extras_create_shadow_ai_banned_host_group",
  "extras_adopt_shadow_ai_banned_host_group",
  "extras_provision_shadow_ai_banned_policy",
  // falcon-extras — tenant teardown. Single high-level wipe of every
  // canonical Project Eyas-managed object (host groups, prevention
  // policies, custom IOA rule groups, IR-readiness exclusion). Used
  // during demo cycles + dev resets. Dry-run path is read-only but the
  // tool itself stays gated because the agent picks dry_run=False on
  // the second call without re-asking and the consequences are large
  // (loses all prevention coverage that Project Eyas was managing).
  "extras_teardown_project_eyas_managed",
  // Low-level delete primitives — the teardown tool composes these
  // internally but they're also useful for surgical fixes (e.g. cleaning
  // up a single orphaned policy without nuking the whole setup).
  // extras_delete_host_group was un-registered in 0.6.7 — native
  // falcon_delete_host_groups (adopted) covers ad-hoc host-group deletes, and
  // teardown calls hg.delete_host_groups directly rather than the tool wrapper.
  "extras_delete_prevention_policy",
  "extras_delete_ioa_rule_group",
]);

export function requiresApproval(toolName: string): boolean {
  return REQUIRES_APPROVAL.has(toolName);
}

// falcon-extras tools reviewed as read-only (2026-11-08): queries, playbook
// text, diagnostics and RTR command-status polling. The sidecar sets no MCP
// annotations, so this list is the classification: a sidecar tool that is in
// neither REQUIRES_APPROVAL nor this set is treated as an unclassified write
// and gated (see ToolBridge.unclassifiedSidecarTools). Every sidecar tool in
// falcon-extras/expected_tools.json must be in exactly one of the two lists;
// scripts/test-tool-classification.mjs enforces that in CI.
export const EXTRAS_READ_ONLY: ReadonlySet<string> = new Set<string>([
  "extras_classify_patch_coverage",
  "extras_data_protection_provision_playbook",
  "extras_diagnose_ir_readiness",
  "extras_diagnose_quarantine_setup",
  "extras_diagnose_shadow_ai_banned_setup",
  "extras_discover_applications",
  "extras_discover_assets",
  "extras_fleet_shadow_ai_egress",
  "extras_host_group_list",
  "extras_host_group_members",
  "extras_host_group_membership_for_device",
  "extras_host_list_contained",
  "extras_host_process_tree",
  "extras_host_rat_install_scan",
  "extras_host_shadow_ai_scan",
  "extras_identity_detections",
  "extras_identity_ir_workflow_playbook",
  "extras_ir_campaign_scope",
  "extras_ir_phase0_actionable_check",
  "extras_ir_phase0_detection_scope",
  "extras_ir_phase3_verification_scope",
  "extras_ir_workflow_playbook",
  "extras_list_ioa_exclusions",
  "extras_list_ml_exclusions",
  "extras_list_patch_profiles",
  "extras_ngsiem_provisioning_status",
  "extras_ngsiem_search",
  "extras_prevention_policy_posture",
  "extras_recon_list_rules",
  "extras_recon_preview_corpus_search",
  "extras_recon_search_exposed_records",
  "extras_recon_search_notifications",
  "extras_rtr_check_patch_status",
  "extras_rtr_list_cleanup_scripts",
  "extras_rtr_list_patch_scripts",
  "extras_rtr_resolve_cleanup_plan",
  "extras_rtr_resolve_patch_plan",
  "extras_shadow_ai_check_prevention_binding",
  "extras_shadow_ai_prevention_status",
  "extras_shadow_ai_workflow_playbook",
  "extras_workflows_execution_result",
  "extras_workflows_list_definitions",
  "extras_workflows_list_executions",
]);
