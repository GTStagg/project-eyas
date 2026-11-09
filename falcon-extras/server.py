"""falcon-extras: tiny MCP sidecar exposing FalconPy-only capabilities that
falcon-mcp v0.9 doesn't provide (notably host containment).

This is the demo's "art of the possible" companion server: it shows that the
manual agent loop in the Next.js app can plug in additional MCP servers
alongside the upstream falcon-mcp, with no protocol-level differences. The
intentionally-small surface area is two tools: contain a host, lift
containment. Both are write-capable and gated by the Next.js approval flow.

Transport: stdio. The Next.js process spawns this as a child and the lifecycle
follows the dev server.
"""

from __future__ import annotations

import json
import os
import sys
from importlib import metadata
from typing import Any

from mcp.server.fastmcp import FastMCP

from falcon_helpers import swallow_exc
from ir_playbook import render_ir_playbook
from data_protection_playbook import render_data_protection_playbook

# All cluster-specific imports (FalconPy clients, shadow_ai catalog, patching
# library, etc.) live in the per-cluster impl modules now. Each @mcp.tool()
# wrapper below pulls what it needs lazily inside the function body.

LARGE_BATCH_THRESHOLD = 25


# Strict input validation for Recon FQL — anything that fails these regexes is
# rejected before being interpolated into a filter string. Recon's filter
# language is FQL; single quotes are the literal delimiter, so a value
# containing one would either error or change query semantics. The patterns
# here only accept characters that are unambiguously safe inside a single-
# quoted FQL literal.


mcp = FastMCP("falcon-extras")


def _pkg_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "unknown"


@mcp.resource("falcon-extras://about")
def about() -> str:
    """Runtime metadata about this sidecar — surfaced on the app's /status page
    so operators can see exactly what versions are running without shelling in.
    """
    payload = {
        "name": "falcon-extras",
        "purpose": "FalconPy-backed MCP sidecar for capabilities upstream falcon-mcp v0.9 doesn't ship (host containment).",
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "falconpy": _pkg_version("crowdstrike-falconpy"),
        "mcp_sdk": _pkg_version("mcp"),
        "required_falcon_scopes": [
            "Hosts:write",  # containment
            "Real Time Response:read",  # patch-plan resolve (catalog only, no host I/O yet)
            "Real Time Response (Admin):write",  # reserved for run_patch (Phase 2)
            "Monitoring Rules (Falcon Intelligence Recon):read",  # /recon surface
            "Assets (Falcon Discover):read",  # /discover surface (console label may be "Assets" or "Falcon Discover" by edition)
            "Host Group:read",  # /host-groups surface listing
            "Host Group:write",  # add/remove members on static groups
            "Workflow:read",  # /workflows surface listing
            "Workflow:write",  # on-demand execute
            "Identity Protection Entities:read",  # /identity surface
            "Identity Protection Detections:read",
            "Identity Protection Timeline:read",
            "NGSIEM Data Connections API:read",  # /ngsiem pipeline-health strip — list_data_connections (third-party connectors only)
            "NGSIEM Lookup Files:read",  # /ngsiem pipeline-health strip — list_lookup_files (search_domain=search-all)
            "NGSIEM Parsers:read",  # /ngsiem pipeline-health strip — list_parsers (repository=search-all)
            "Cloud Security API Detections:read",  # cloud module (falcon-mcp 0.10.0) — IOA/IOM findings
            "Cloud Security API Assets:read",  # cloud module (falcon-mcp 0.10.0) — cloud asset inventory
        ],
        "base_url": os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
        "member_cid_set": bool(os.environ.get("FALCON_MEMBER_CID")),
    }
    return json.dumps(payload)


@mcp.tool()
def extras_update_detection_status(
    composite_ids: list[str],
    status: str | None = None,
    verdict: str | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    """Update one or more detection (alert) lifecycle statuses and/or record a
    verdict. Closes the triage loop on the agentic Triage Queue: when the
    agent reaches a verdict, this updates the row in Falcon so it leaves
    `new`/`reopened` and stops resurfacing in the queue.

    WRITE ACTION — gated by the operator-approval registry. The Queue UI
    fires a separate server-side `in_progress` claim on click that bypasses
    this tool; only verdict transitions (true_positive / false_positive /
    closed / reopened) reach the agent loop and the gate.

    Wraps FalconPy `Alerts.update_alerts_v3`. The v3 Alerts API only accepts
    `new` / `in_progress` / `reopened` / `closed` for the lifecycle status.
    The TP/FP verdict is a separate concept recorded via the literal verdict
    tag (`true_positive` / `false_positive`) — the same tag the Falcon console
    writes when an operator sets a verdict on a v3 alert — pass `verdict` to
    set it, NOT `status`. When `verdict` is set without an
    explicit `status`, status is forced to `closed` so the row leaves the
    queue.

    Args:
        composite_ids: List of `composite_id` strings from
            `falcon_search_detections`. Composite ids look like
            `<cid>:ind:<aid>:<sha256>`.
        status: Target lifecycle state — one of `new`, `in_progress`,
            `reopened`, `closed`. Optional if `verdict` is supplied
            (defaults to `closed` in that case).
        verdict: Optional TP/FP verdict — `true_positive` or
            `false_positive`. Records the literal verdict tag (matches the
            console).
        comment: Optional free-text comment appended to the detection
            (visible in Falcon Console). Useful to document reasoning when
            recording a verdict.
    """
    from host_actions import update_detection_status as _impl
    return _impl(composite_ids, status, verdict, comment)


@mcp.tool()
def extras_close_all_open_detections_on_host(
    device_id: str,
    verdict: str,
    comment: str | None = None,
) -> dict[str, Any]:
    """Bulk-close every open detection on a single host. WRITE — gated.

    Walks the v3 Alerts API server-side for every detection on the host in
    status `new` / `in_progress` / `reopened`, chunks the close calls at
    500/batch, and returns aggregate counts. Single approval gate covers
    the entire bulk close.

    **Why this exists separate from the IR workflow:** the IR workflow
    captures detection scope in Phase 0 and closes in Phase 4, but the
    agent-side path through five phases has multiple failure modes
    (agent uses wrong tool, truncates capture, mis-orders Phase 4 steps).
    This tool is the rescue lane — when an operator says "the host is
    clean, just close everything open on it" without wanting to rerun
    the full workflow, this is the one-shot answer. Single approval,
    server-side deterministic, idempotent.

    Idempotent: re-running on a host with no remaining open detections
    returns ok=True with `requested: 0, updated: 0`.

    Args:
        device_id: Falcon AID of the target host.
        verdict: `true_positive` (cleaned-up real attack — the IR case)
            or `false_positive` (workflow-self noise / operator-confirmed
            FP). Records the literal verdict tag (matches the console) and
            forces status to `closed`.
        comment: Optional one-line audit string. Defaults to a generic
            "bulk-closed via Project Eyas" if omitted; supply a specific
            reason ("post-IR cleanup", "workflow-self FP sweep") for
            better forensic trail.

    Returns:
        ok, device_id, scope_count, updated, requested, batches,
        batch_errors? (only if any batch failed),
        composite_ids: list of every id closed (for audit-trail purposes).
    """
    from host_actions import close_all_open_detections_on_host as _impl
    return _impl(device_id, verdict, comment)


# ---------------------------------------------------------------------------
# IR remediation-ledger driven close
# ---------------------------------------------------------------------------
#
# `extras_ir_close_remediated` is the production-grade Phase 4 closer. It
# accepts a structured ledger of what Phase 2 actually did to the host and
# closes only those detections whose evidence intersects the ledger. Every
# closure carries per-id `match_evidence` linking the close back to the
# specific ledger entry that justified it — that audit trail is the reason
# this exists separately from the bulk-everything closer.
#
# Ledger entry shapes (all `kind` values agent-supplied):
#
#   {kind: "process_killed",   pid, image?}        # pid is Falcon graph id
#   {kind: "file_quarantined", path?, sha256?, md5?}
#   {kind: "file_deleted",     path?, sha256?, md5?}
#   {kind: "folder_deleted",   path}
#   {kind: "registry_reverted",path}               # registry value path
#   {kind: "ifeo_removed",     image}              # IFEO debugger hijack
#   {kind: "ioa_pattern_excluded", pattern_id}
#   {kind: "ml_exclusion_added",   sha256?, path?}
#   {kind: "ioc_added",        type, value}        # type: sha256/md5/domain/ipv4/ipv6/url
#   {kind: "rat_uninstalled",  product, image?}    # AnyDesk, TeamViewer, etc.
#   {kind: "service_removed",  service_name}
#   {kind: "scheduled_task_removed", task_name}
#   {kind: "wmi_persistence_removed", filter_name}
#   {kind: "other",            note}               # free-form, never matches
#
# NOTE: host containment / lift / reboot have NO ledger kind. They are
# host/network state changes, not per-detection remediation (persistence
# survives a reboot), so they never close a detection. The Phase 4 lift
# decision is tracked via the `agent_contained` flag, not the ledger.
#
# Detection record fields consulted for matching:
#
#   - top-level `process_id` (Falcon graph id) + `local_process_id` (OS pid)
#   - top-level `cmdline`, `parent_details.cmdline`
#   - `behaviors[].{process_id, target_process_id, cmdline, ioc_value,
#                   ioc_type, sha256, md5, pattern_id}`
#
# Matching is intentionally generous on cmdline substring (case-insensitive,
# normalized backslashes) because the same path can appear with different
# quoting/casing in different telemetry sources. The audit trail records
# WHICH match fired so an operator can spot-check.


@mcp.tool()
def extras_ir_close_remediated(
    device_id: str,
    remediated: list[dict[str, Any]],
    verdict: str = "true_positive",
    comment: str | None = None,
) -> dict[str, Any]:
    """Production Phase 4 closer. WRITE — gated.

    Walks every open detection on the host, matches each one's evidence
    (process_id / cmdline / parent_details.cmdline / behaviors[].{cmdline,
    ioc_value, sha256, md5, pattern_id}) against a structured `remediated`
    ledger of what Phase 2 actually did, and closes ONLY matched
    detections. Unmatched stay open for operator review.

    Every closure carries per-id `match_evidence` linking it back to the
    specific ledger entry that justified the close — that audit trail is
    the reason this exists separately from the bulk closer.

    **Use this in IR Phase 4 step 1** instead of the bulk closer. The
    bulk closer (`extras_close_all_open_detections_on_host`) remains for
    out-of-band rescue / queue drain when no IR workflow is running.

    Ledger entry shapes (kind values, all artifact fields optional unless
    noted):
        process_killed   {pid, image?}                — pid is Falcon graph id
        file_quarantined {path?, sha256?, md5?}
        file_deleted     {path?, sha256?, md5?}
        folder_deleted   {path}                       — required
        registry_reverted{path}                       — required
        ifeo_removed     {image}                      — required
        ioa_pattern_excluded {pattern_id}             — required
        ml_exclusion_added   {sha256?, path?}
        ioc_added        {type, value}                — both required
        rat_uninstalled  {product, image?}
        service_removed  {service_name}
        scheduled_task_removed {task_name}
        wmi_persistence_removed {filter_name}         — required
        other            {note}                       — never matches

    Containment / lift / reboot are host-wide state changes, NOT
    per-detection remediation — they have no kind here and never close
    anything. The lift decision is tracked via `agent_contained`.

    Args:
        device_id: Falcon AID of the target host.
        remediated: ordered ledger of Phase 2 actions.
        verdict: `true_positive` (default — actual cleaned attack) or
            `false_positive` (only if you can attest detections are noise).
        comment: optional one-line audit string. Defaults to a generic
            "remediation-ledger close via Project Eyas IR" if omitted.

    Returns:
        ok, device_id, scope_count, matched_count, unmatched_count,
        updated, verdict,
        closed: [{composite_id, evidence: [reason, ...]}, ...],
        unmatched: [{composite_id, display_name?, created_timestamp?,
                     pivot_pid?}],
        ledger_entries_used: int (count of ledger entries that fired ≥1 match),
        ledger_entries_unused: list of ledger indices that matched nothing
            (operator hint — you cleaned something but no detection
            referenced it; either the detection telemetry doesn't carry
            the artifact field, or the cleanup was preventative),
        batch_errors? (only if any batch failed).
    """
    from ir.close_remediated import close_remediated as _impl
    return _impl(device_id, remediated, verdict, comment)


@mcp.tool()
def extras_host_list_contained(limit: int = 100) -> dict[str, Any]:
    """List hosts currently in network containment (or with a containment
    state change pending). Read-only. Pairs with falcon_contain_hosts /
    falcon_lift_host_containment so the agent can answer "which hosts are
    contained right now?" without the operator having to remember.

    Returns hostname + AID + platform + last_seen + status. Status values
    surface FalconPy's raw labels: 'contained', 'containment_pending',
    'lift_containment_pending'.

    Args:
        limit: Max hosts to return (1-5000). Default 100.
    """
    from host_actions import host_list_contained as _impl
    return _impl(limit)


@mcp.tool()
def extras_rtr_list_patch_scripts(os_filter: str | None = None) -> dict[str, Any]:
    """Return the curated patch-script catalog. Read-only. The agent calls
    this to discover what scripts exist; it cannot supply script content.

    Args:
        os_filter: Optional. Restrict to one OS family ('windows', 'macos',
            'linux'). Omit for everything.
    """
    from rtr_tools import rtr_list_patch_scripts as _impl
    return _impl(os_filter)


@mcp.tool()
def extras_rtr_resolve_patch_plan(
    spotlight_remediation: dict[str, Any],
    device_ids: list[str],
    params: dict[str, Any] | None = None,
    script_id: str | None = None,
    os_hint: str | None = None,
) -> dict[str, Any]:
    """Build a patch plan for a Spotlight remediation entity. Read-only — does
    NOT execute. Returns the matched script id, resolved params (with defaults
    filled in), target device count, a script preview, and execution metadata.
    Use this to compose the decision document the user reviews before approval.

    Args:
        spotlight_remediation: The Spotlight remediation entity, with at least
            'vendor' and 'product' (and optionally 'version'). The library
            matches the first script whose patterns match.
        device_ids: List of Falcon device IDs (AIDs) the plan targets. Not
            used at resolve time except to compute counts and a sample.
        params: Optional. Per-script parameters. Validated against the
            script's schema; required params with no default raise an error.
        script_id: Optional. Skip remediation matching and resolve a specific
            script id directly (e.g. 'win-update-status' for diagnostics).
    """
    from rtr_tools import rtr_resolve_patch_plan as _impl
    return _impl(spotlight_remediation, device_ids, params, script_id, os_hint)


@mcp.tool()
def extras_rtr_run_patch(
    script_id: str,
    device_ids: list[str],
    params: dict[str, Any] | None = None,
    dry_run: bool = True,
    confirm_large_batch: bool = False,
) -> dict[str, Any]:
    """Execute a curated patch script via RTR batch session. WRITE ACTION —
    this tool is approval-gated by the Next.js agent loop. The agent calls it,
    the loop pauses, the operator reviews, and only then is the call dispatched.

    Default is `dry_run=True`, which returns the resolved plan + script preview
    WITHOUT calling the CrowdStrike RTR API. Use this to render a final
    pre-flight summary the operator can review before flipping `dry_run=False`.

    Hard guard: when device_ids has more than 25 entries, the call is rejected
    unless `confirm_large_batch=True` is passed explicitly. This prevents the
    agent from accidentally fanning out a wide rollout in a single approval.

    Args:
        script_id: Must match an id from extras_rtr_list_patch_scripts. The
            script content is resolved server-side; the agent cannot author bytes.
        device_ids: Falcon device IDs (AIDs) to target.
        params: Per-script parameters; validated against the manifest schema.
        dry_run: Default True. When True, returns the resolved plan + preview
            and does not invoke RTR. Set False to execute.
        confirm_large_batch: Required (True) when device_ids count > 25.
    """
    from rtr_tools import rtr_run_patch as _impl
    return _impl(script_id, device_ids, params, dry_run, confirm_large_batch)


@mcp.tool()
def extras_rtr_check_patch_status(
    cloud_request_ids: list[str],
) -> dict[str, Any]:
    """Poll in-flight RTR commands. Read-only. Use after extras_rtr_run_patch
    when one or more host results returned `complete: false` and a non-null
    `cloud_request_id` — typical for long-running scripts (Windows Update
    install, etc.) that exceed the synchronous batch_admin_command timeout.

    Args:
        cloud_request_ids: One per still-running host. Typically taken from
            the run_patch response's `results[].cloud_request_id` for any
            entry where `complete` was false.
    """
    from rtr_tools import rtr_check_patch_status as _impl
    return _impl(cloud_request_ids)


@mcp.tool()
def extras_rtr_list_cleanup_scripts(os_filter: str | None = None) -> dict[str, Any]:
    """Return the curated host-cleanup script catalog. Read-only. Distinct
    from the patching catalog (extras_rtr_list_patch_scripts): cleanup is
    incident-response remediation — stop a service, remove a scheduled task,
    delete an autorun registry value, kill a process. Use after a persistence
    audit or detection-triage finding to pick the right id and validated params.
    """
    from rtr_tools import rtr_list_cleanup_scripts as _impl
    return _impl(os_filter)


@mcp.tool()
def extras_rtr_resolve_cleanup_plan(
    script_id: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve a cleanup script id + params to a render preview without
    executing. Read-only. Use this to confirm parameter validation passes and
    to show the operator the rendered $Params block before triggering the
    write call. Mirrors extras_rtr_resolve_patch_plan.
    """
    from rtr_tools import rtr_resolve_cleanup_plan as _impl
    return _impl(script_id, params)


@mcp.tool()
def extras_rtr_run_cleanup(
    script_id: str,
    device_ids: list[str],
    params: dict[str, Any] | None = None,
    dry_run: bool = True,
    confirm_large_batch: bool = False,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute a curated cleanup script via RTR batch session. WRITE ACTION —
    approval-gated by the Next.js agent loop. Default `dry_run=True`, which
    returns the resolved plan + script preview without calling the RTR API.

    Hard guard: when device_ids has more than 25 entries, the call is rejected
    unless `confirm_large_batch=True`. Cleanup is per-host work; large fanout
    is almost certainly wrong.

    ``evidence`` opens the detection-vouched path widening. When a param's
    value is a path that came directly out of a true-positive detection's
    evidence (cmdline_artifacts.downloaded_files / extract_targets,
    behaviors[].cmdline / .ioc_value, etc.), supply ``evidence`` to use a
    wider regex for those params instead of the strict default. Use this
    when the strict pattern rejects a real attacker artifact name (paths
    with `+`, `=`, `,`, `[`, `]`, `{`, `}`, `&`, `#`, `@`, `!`, `'` —
    valid Windows file/folder characters that the conservative default
    pattern excludes). Windows-invalid characters (`*?<>|"`) and the
    null byte stay banned even with evidence vouching.

    The evidence dict is recorded in the return payload (and therefore in
    the IR run audit record) so the "why was the strict regex bypassed"
    question has a per-call answer.

    Expected ``evidence`` shape::

        {
            "composite_id": "<detection composite id>",
            "source": "cmdline_artifacts.downloaded_files",
            "vouched_param_keys": ["path"]
        }

    Args:
        script_id: id from extras_rtr_list_cleanup_scripts.
        device_ids: Falcon AIDs to target. Typically a single host.
        params: Per-script parameters; validated against the manifest schema.
        dry_run: Default True. Set False to execute.
        confirm_large_batch: Required (True) when device_ids count > 25.
        evidence: Optional detection-vouching for path-shaped params.
    """
    from rtr_tools import rtr_run_cleanup as _impl
    return _impl(script_id, device_ids, params, dry_run, confirm_large_batch, evidence)


@mcp.tool()
def extras_ir_workflow_playbook(device_id: str) -> dict[str, Any]:
    """Return the agentic IR workflow playbook for a single host. Read-only.

    Call this when the operator asks for an agentic IR / quarantine-and-clean
    workflow on a specific host (e.g. they say "run the IR workflow on
    WIN11-HR-03" or click the IR button on the /hosts page). The returned
    `playbook` text is your working instruction set for the rest of the
    conversation — follow it verbatim, phase by phase.

    The playbook is parameterized with the target device_id and the
    operator-configured quarantine host group id. Returns ok=False with a
    clear error if FALCON_QUARANTINE_GROUP_ID is not set on the server.

    Args:
        device_id: Falcon AID of the target host.
    """
    if not device_id or not isinstance(device_id, str):
        return {"ok": False, "error": "device_id required"}
    playbook, err = render_ir_playbook(device_id)
    if err:
        return {"ok": False, "error": err}
    return {"ok": True, "device_id": device_id, "playbook": playbook}


@mcp.tool()
def extras_ir_phase0_detection_scope(device_id: str) -> dict[str, Any]:
    """Server-side deterministic detection scope for IR Phase 0. Read-only.

    Walks the v3 Alerts API for every open detection on this host
    (status `new` / `reopened` / `in_progress`), paginating server-side
    until exhausted, and returns the full composite_id list as a
    structured array.

    **Why this exists:** the IR playbook previously instructed the agent
    to capture `composite_id` of every open detection via
    `falcon_search_detections` with explicit `offset=200, 400, ...`
    pagination. Agents routinely truncate large detection captures
    (200+ records on a noisy host), leaving the Phase 4 close loop
    with only the first N composite_ids. The rest stay open in the
    triage queue, the operator re-runs IR, the second run finds nothing
    to remediate (already cleaned) — wasting approval clicks while the
    backlog never drains. Bug observed 2026-05-07: 17 of 152
    detections closed; 135 left in queue.

    Switching from agent-instructed-pagination to server-side-deterministic
    pagination eliminates the failure mode entirely. The agent calls this
    ONCE in Phase 0; the returned `composite_ids` array is the
    authoritative scope for Phase 4 close.

    Args:
        device_id: Falcon AID of the target host.

    Returns:
        ok, items[], composite_ids[], pivot_pids[], count, truncated,
        oldest_open_iso, newest_open_iso, scope_pending?, error?
    """
    from ir.phase0 import phase0_detection_scope as _impl
    return _impl(device_id)


# Identifying substring of the RTR runscript preamble cmdline. RTR's
# `runscript -CloudFile=<name>` transport invokes PowerShell with this
# fixed `-EncodedCommand` block as the preamble before sourcing the cloud
# file — it base64-decodes to `Set-Location 'C:\'`. Aggressive PowerShell
# behavioral detectors (PShellMimikatz et al.) fire on `-EncodedCommand`
# regardless of payload, so on hosts in a quarantine policy that *prevents*
# encoded-command PowerShell, every IR cleanup invocation is killed at
# the sensor before it can run.


@mcp.tool()
def extras_ir_phase3_verification_scope(
    device_id: str,
    since_iso: str,
    prior_composite_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Server-side deterministic Phase 3 verification scope. Read-only.

    Walks the v3 Alerts API for every detection on this host with
    `created_timestamp >= since_iso`, paginating server-side until
    exhausted. Classifies each detection into one of three buckets:

      `retrospective_ioc_match` — `created_timestamp` is post-IR but
        every underlying event timestamp (`network_accesses[].
        access_timestamp`, `behaviors[].timestamp`, `context_timestamp`)
        predates the Phase 1 quarantine point. This is Falcon's IOC
        matching engine surfacing historical telemetry as a fresh
        detection because a custom IOC was added during/after the IR.
        Same triage shape as workflow_self: FP-close, never real.

      `workflow_self_triggered` — the RTR runscript preamble matched the
        PowerShell-encoded-command detector. Same triage: FP-close.

      `real` — actual new activity during the workflow window. Drives
        RELEASE/HOLD.

    Classification order: retrospective first (requires data, strongest
    signal), then workflow_self (cmdline regex), then real. The first
    two are mutually exclusive in practice (retrospective requires old
    underlying timestamps; workflow_self detections have current ones).

    **Why this exists:** the IR playbook's old Phase 3 instructed the
    agent to call `falcon_search_detections ... limit 10 sort newest` to
    sample new detections during the workflow window. On a host where
    cleanup primitives self-trigger 100+ PShellMimikatz detections (RTR
    preamble matches the PowerShell-encoded-command behavioral rule),
    only the most recent 10 were captured. The other 90+ stayed open
    forever. Same agent-truncation failure as Phase 0 capture, same
    structural fix. Retrospective classification was added 2026-05-07
    after observing custom-IOC creation at end-of-IR triggering a wave
    of detections for May-4 connections fired May-7 04:45 UTC.

    Args:
        device_id: Falcon AID of the target host.
        since_iso: ISO 8601 timestamp marking the workflow start
            (typically the Phase 1 quarantine call's timestamp). Only
            detections at or after this point are scoped.
        prior_composite_ids: Optional. The detections captured at Phase-0
            kickoff. When supplied, these exact ids are re-hydrated (no
            time filter) and the still-open ones are reported via
            `prior_open_*`. The release gate passes these so a release is
            blocked when an ORIGINAL detection remains open — not only when
            something new fired after `since_iso`. Agents normally omit it.

    Returns:
        ok, real_composite_ids, workflow_self_composite_ids,
        retrospective_composite_ids, items[], real_count,
        workflow_self_count, retrospective_count, total, truncated,
        prior_open_composite_ids, prior_open_count, prior_checked_count
    """
    from ir.phase3 import phase3_verification_scope as _impl
    return _impl(device_id, since_iso, prior_composite_ids)


@mcp.tool()
def extras_diagnose_ir_readiness() -> dict[str, Any]:
    """Diagnose whether the IR workflow is correctly provisioned on this
    tenant. Read-only.

    Checks: (1) FALCON_QUARANTINE_GROUP_ID is set; (2) the configured group
    actually exists in Falcon; (3) IOA exclusions scoped to that group are
    enumerated; (4) heuristically determines whether the RTR-runscript-
    preamble exclusion is present (the exclusion that prevents the quarantine
    policy from blocking RTR cleanup primitives); (5) auto-discovers a
    `pattern_id` from a recent PShellMimikatz detection on the tenant if
    available, so the create-exclusion call can be composed concretely.

    Returns `ready=true` only when all checks pass. When prerequisites are
    missing, the response includes `remediation.tool_calls[]` — concrete
    `extras_create_ioa_exclusion` invocations the operator can review and
    fire (the create itself is approval-gated; this diagnostic does not
    write).

    Why this matters: IR's Phase 2 cleanup primitives all flow through
    `runscript -CloudFile=`, which the sensor invokes with a fixed
    `-EncodedCommand` PowerShell preamble. On a properly aggressive
    quarantine prevention policy, that preamble is *blocked at the sensor*
    — every cleanup attempt returns `batch_init_sessions: no successful
    hosts initialized on RTR` (HTTP 404) and Phase 2 is silently a no-op.
    The IOA exclusion this diagnostic recommends scopes the preamble
    pattern to the quarantine host group only, keeping production hosts
    fully covered.
    """
    from ir.diagnose_readiness import diagnose_ir_readiness as _impl
    return _impl()


@mcp.tool()
def extras_diagnose_quarantine_setup(host_group_id: str | None = None) -> dict[str, Any]:
    """Read-only diagnostic for the IR quarantine setup state on this tenant.

    Detects which migration case the tenant is in and returns the right
    next-step CTA for the /config UI to surface:

      - ``no_group_id`` — no quarantine group configured. Recommendation:
        run ``extras_create_quarantine_host_group``.
      - ``group_missing`` — configured group id doesn't exist.
        Recommendation: re-create.
      - ``A_no_policy`` — group has no dedicated prevention policy
        attached. Recommendation: ``extras_provision_quarantine_policy``
        with ``mode="adopt"``.
      - ``B_dedicated_single_group`` — group has a policy attached only
        to it. Recommendation: same, ``mode="adopt"``.
      - ``C_shared_policy`` — group has a policy that's also attached to
        other groups. Recommendation:
        ``extras_provision_quarantine_policy`` with
        ``mode="create_dedicated"`` (creates a brand-new dedicated
        policy, leaves the existing shared one alone).
      - ``ready`` — all three platform policies are app-managed,
        AGGRESSIVE, and the IR-readiness IOA exclusion is in place.

    Args:
        host_group_id: Defaults to ``FALCON_QUARANTINE_GROUP_ID`` from the
            active environment.
    """
    from ir.provision_quarantine import diagnose_quarantine_setup as _impl
    return _impl(host_group_id=host_group_id)


@mcp.tool()
def extras_create_quarantine_host_group(
    name: str = "Project Eyas - IR Quarantine",
    description: str | None = None,
) -> dict[str, Any]:
    """Create a new STATIC host group for IR quarantine. WRITE — approval-gated.

    Creates the host group with the canonical app-managed naming so it's
    identifiable later. Returns ``{ok, id, name, group_type}``. After
    creation, save the new id to the active environment's
    ``irQuarantineGroupId`` field via ``POST /api/environments/active/ir-quarantine-group``.

    The created group is empty — no hosts attached. Use
    ``extras_provision_quarantine_policy`` next to attach the prevention
    policies.

    Args:
        name: Group name (default: canonical "Project Eyas - IR Quarantine").
        description: Optional override for the group description.
    """
    from ir.provision_quarantine import create_quarantine_host_group as _impl
    return _impl(name=name, description=description)


@mcp.tool()
def extras_adopt_quarantine_host_group(
    name: str = "Project Eyas - IR Quarantine",
) -> dict[str, Any]:
    """Adopt an EXISTING host group as the IR quarantine group. WRITE —
    approval-gated.

    Looks up a host group by exact name in the active tenant and returns
    ``{ok, id, name, group_type}``. The chat auto-save hook persists the
    returned ``id`` as the active environment's ``irQuarantineGroupId``.
    Use this when the group has already been created out-of-band (e.g.
    from a previous install) and you just need Project Eyas to know its id.

    Returns ``ok: false`` if zero or more than one group matches the name.

    Args:
        name: Exact group name (default: canonical "Project Eyas - IR Quarantine").
    """
    from ir.provision_quarantine import adopt_quarantine_host_group as _impl
    return _impl(name=name)


@mcp.tool()
def extras_provision_quarantine_policy(
    host_group_id: str,
    mode: str = "adopt",
) -> dict[str, Any]:
    """Provision IR quarantine prevention policies for the named host group.
    WRITE — approval-gated.

    Per platform (Windows / macOS / Linux):
      - mode="adopt": adopt the existing policy bound to this group
        (rename to canonical, push AGGRESSIVE sliders), or attach a fresh
        canonical policy if none exists. Use for migration cases A and B.
      - mode="create_dedicated": always create a brand-new dedicated
        policy bound only to this group, leave any existing shared policy
        alone. Use for migration case C.

    Pushes EVERY slider on the policy (detection + prevention pairs and
    detection-only sliders) to AGGRESSIVE, AND enables EVERY boolean
    behavioral toggle (script monitoring, encoded-command, volume-shadow-
    copy protection, etc.). Operates on setting shape (slider vs toggle
    detected by value structure), not on a hard-coded enumeration, so
    the policy schema can evolve without code changes.

    Verifies the IR-readiness IOA exclusion is in place; if not, returns a
    ``follow_up_tool_call`` shape pointing to ``extras_create_ioa_exclusion``
    (which is its own approval gate — exclusions are not bundled into
    this approval).

    Args:
        host_group_id: The IR quarantine host group id.
        mode: "adopt" (Cases A / B) or "create_dedicated" (Case C). Use
            ``extras_diagnose_quarantine_setup`` first to determine which.
    """
    from ir.provision_quarantine import provision_quarantine_policy as _impl
    return _impl(host_group_id=host_group_id, mode=mode)


@mcp.tool()
def extras_detach_prevention_policy_from_host_group(
    prevention_policy_id: str,
    host_group_id: str,
) -> dict[str, Any]:
    """Detach a prevention policy from a host group. WRITE — approval-gated.

    Calls the Falcon Prevention Policies API with action_name=
    "remove-host-group". The policy itself is NOT deleted — it stays
    attached to whatever other host groups it was bound to. This is the
    inverse of the "add-host-group" action used during provisioning.

    Use case: an operator-created legacy policy is attached to multiple
    groups including the IR Quarantine or Shadow-AI Banned groups, and
    the operator wants to detach it from those specific groups so the
    new dedicated app-managed policies are the only ones applying via
    precedence.

    Args:
        prevention_policy_id: The Prevention Policy id.
        host_group_id: The Host Group id to detach from.

    Returns:
        ok, prevention_policy_id, host_group_id, status_code, errors.
    """
    if not prevention_policy_id or not isinstance(prevention_policy_id, str):
        return {"ok": False, "error": "prevention_policy_id is required"}
    if not host_group_id or not isinstance(host_group_id, str):
        return {"ok": False, "error": "host_group_id is required"}
    try:
        from falcon_helpers import _check_response, _get_prevention_client
        prev = _get_prevention_client()
        resp = prev.perform_policies_action(
            action_name="remove-host-group",
            ids=prevention_policy_id,
            group_id=host_group_id,
        )
        guard = _check_response(resp, "Prevention Policies")
        if guard:
            return {
                "ok": False,
                "prevention_policy_id": prevention_policy_id,
                "host_group_id": host_group_id,
                **guard,
            }
        body = (resp or {}).get("body", {}) if isinstance(resp, dict) else {}
        status_code = (resp or {}).get("status_code") if isinstance(resp, dict) else None
        return {
            "ok": True,
            "prevention_policy_id": prevention_policy_id,
            "host_group_id": host_group_id,
            "status_code": status_code,
            "errors": body.get("errors") or [],
            "note": (
                "Detached. The policy is unchanged elsewhere (still bound "
                "to its other host groups). Hosts in the named host group "
                "fall to their next-precedence policy on next sensor "
                "heartbeat."
            ),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "prevention_policy_id": prevention_policy_id,
            "host_group_id": host_group_id,
            "error": f"{type(exc).__name__}: {exc}",
        }


@mcp.tool()
def extras_diagnose_shadow_ai_banned_setup(host_group_id: str | None = None) -> dict[str, Any]:
    """Read-only diagnostic for the Shadow-AI Banned setup state on this tenant.

    Mirrors ``extras_diagnose_quarantine_setup``. Detects:

      - ``no_group_id`` — no banned group configured.
      - ``group_missing`` — configured group id doesn't exist.
      - ``A_no_policy`` — group has no dedicated prevention policy attached.
      - ``B_dedicated_single_group`` — group has a single-attachment policy.
        Recommendation: adopt + standardize.
      - ``C_shared_policy`` — group's policy is also attached to other groups.
        Recommendation: create dedicated.
      - ``ready`` — all platform policies are app-managed AND the
        Shadow-AI Custom IOA rule group is attached.

    Args:
        host_group_id: Defaults to ``FALCON_SHADOW_AI_BANNED_GROUP_ID`` from
            the active environment.
    """
    from shadow_ai.provision_banned import diagnose_shadow_ai_banned_setup as _impl
    return _impl(host_group_id=host_group_id)


@mcp.tool()
def extras_create_shadow_ai_banned_host_group(
    name: str = "Project Eyas - Shadow-AI Banned",
    description: str | None = None,
) -> dict[str, Any]:
    """Create a new STATIC host group for Shadow-AI banning. WRITE — approval-gated.

    Creates an empty host group with canonical naming. Returns
    ``{ok, id, name, group_type}``. After creation, save the new id to
    the active environment's ``shadowAiBannedGroupId`` field via
    ``POST /api/environments/active/shadow-ai-banned-group``.

    Args:
        name: Group name (default: canonical "Project Eyas - Shadow-AI Banned").
        description: Optional override for the group description.
    """
    from shadow_ai.provision_banned import create_shadow_ai_banned_host_group as _impl
    return _impl(name=name, description=description)


@mcp.tool()
def extras_adopt_shadow_ai_banned_host_group(
    name: str = "Project Eyas - Shadow-AI Banned",
) -> dict[str, Any]:
    """Adopt an EXISTING host group as the Shadow-AI banned group. WRITE —
    approval-gated.

    Looks up a host group by exact name and returns ``{ok, id, name,
    group_type}``. The chat auto-save hook persists the returned ``id``
    as the active environment's ``shadowAiBannedGroupId``. Use this when
    the group already exists in the tenant (e.g. carried over from a
    previous install) and Project Eyas just needs to know its id.

    Returns ``ok: false`` if zero or more than one group matches the name.

    Args:
        name: Exact group name (default: canonical "Project Eyas - Shadow-AI Banned").
    """
    from shadow_ai.provision_banned import adopt_shadow_ai_banned_host_group as _impl
    return _impl(name=name)


@mcp.tool()
def extras_provision_shadow_ai_banned_policy(
    host_group_id: str,
    mode: str = "adopt",
) -> dict[str, Any]:
    """Provision Shadow-AI Banned prevention policies for the named host group.
    WRITE — approval-gated.

    Per platform (Windows / macOS / Linux): create or adopt a prevention
    policy bound to this group, push AGGRESSIVE sliders + enabled
    toggles, set per-platform precedence above standard policies but
    below IR Quarantine (so IR still wins when both apply).

    The Shadow-AI Custom IOA rule group itself is created/refreshed via
    a SEPARATE approval-gated tool — ``extras_shadow_ai_adopt_prevention``
    — which this tool returns as ``follow_up_tool_calls[]`` (one per
    provisioned policy). The operator runs each follow-up to attach the
    rule group; that's where the actual rule corpus authoring happens.

    Args:
        host_group_id: The Shadow-AI Banned host group id.
        mode: "adopt" (Cases A / B) or "create_dedicated" (Case C). Use
            ``extras_diagnose_shadow_ai_banned_setup`` first to determine
            which case applies.
    """
    from shadow_ai.provision_banned import provision_shadow_ai_banned_policy as _impl
    return _impl(host_group_id=host_group_id, mode=mode)


@mcp.tool()
def extras_rtr_wait_until_ready(
    device_id: str,
    timeout_s: int = 300,
    interval_s: int = 15,
) -> dict[str, Any]:
    """Block until RTR cleanup is actually executable on the target host.
    Not read-only: each probe uploads a no-op cloud script, opens an RTR
    admin session and runs it, then deletes the script. Approval-gated.

    Probes the full ``runscript -CloudFile=`` transport in a loop (uploading
    a no-op `exit 0` PowerShell payload, opening a session, dispatching the
    runscript, then deleting the script) until the probe succeeds or
    ``timeout_s`` elapses. Each iteration takes ~5–10s of API work; the
    loop sleeps ``interval_s`` between probes. The first probe fires
    immediately, so a sensor that's already ready returns in one round trip.

    Use between Phase 1 (host moved into the quarantine host group) and
    Phase 2 (first cleanup primitive). The new prevention policy + IOA
    exclusion typically take 60–90s to propagate from backend to sensor;
    until that completes, every cleanup primitive returns
    ``batch_init_sessions: 404`` and Phase 2 is silently a no-op.

    Returns ``{ok, ready, waited_s, iterations, first_ready_iteration,
    last_error, timed_out}``. ``ok`` is whether the tool itself ran;
    ``ready`` is the actual outcome. When ``timed_out`` is true, the
    ``last_error`` field carries the most recent probe failure shape so
    the playbook can decide whether to HOLD the workflow or retry with
    operator confirmation.

    Bounds: ``timeout_s`` is clamped to [30, 600], ``interval_s`` to [5, 60].
    """
    from ir.wait_for_rtr import wait_until_rtr_ready as _impl
    return _impl(device_id=device_id, timeout_s=timeout_s, interval_s=interval_s)


@mcp.tool()
def extras_save_patch_profile(
    name: str,
    product: str,
    url: str,
    kind: str,
    sha256: str | None = None,
    silent_args: str | None = None,
) -> dict[str, Any]:
    """Persist a reusable generic-installer param-set as a named patch profile.
    WRITE ACTION — approval-gated by the Next.js agent loop. Saving establishes
    a trusted, reusable install source for this tenant, so it is a conscious
    operator decision (running a profile is separately gated at run_patch).

    This does NOT store script bytes and does NOT create any Falcon-side object.
    It validates the supplied params against the SAME win-app-install manifest
    schema the resolve/run path enforces — the security boundary is reused, so a
    saved profile can never carry params that wouldn't pass at execution time.
    The agent supplies a vendor HTTPS URL it already knows; it never invents one.
    On success the active environment's per-tenant catalog gains this profile.

    Args:
        name: Operator-facing label for the profile (1-64 chars), e.g.
            "Firefox ESR" or "7-Zip x64".
        product: Friendly product name shown in install logs. Validated against
            the win-app-install 'product' pattern.
        url: Vendor HTTPS download URL. Validated against the 'url' pattern
            (https only; shell metacharacters rejected).
        kind: Required. 'msi' (msiexec /qn) or 'exe' (silent switches via
            silent_args). Choose deliberately — the URL extension is not a
            reliable signal of installer type.
        sha256: Optional integrity pin (64 hex). STRONGLY preferred — host-side
            verify-or-abort before install. Omit only when no published hash
            exists; the install then proceeds on HTTPS trust + approval alone.
        silent_args: Optional exe-only silent switches (ignored for kind=msi).
    """
    from rtr_tools import save_patch_profile as _impl
    return _impl(name, product, url, kind, sha256, silent_args)


@mcp.tool()
def extras_list_patch_profiles() -> dict[str, Any]:
    """List this tenant's saved patch profiles. Read-only. Each profile is a
    reusable generic-installer param-set the operator previously saved. To use
    one: pick a profile, then call extras_rtr_resolve_patch_plan with
    script_id="win-app-install" and the profile's params, then dry-run via
    extras_rtr_run_patch before executing.

    Note: a profile saved earlier in THIS SAME turn is not yet visible here —
    the save is persisted after the tool returns and this reads the per-tenant
    catalog captured when the session started. Save, let the turn finish, then
    list on a later step.
    """
    from rtr_tools import list_patch_profiles as _impl
    return _impl()


@mcp.tool()
def extras_classify_patch_coverage(
    remediations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Classify a batch of Spotlight remediation entities against the curated
    patch catalog. Read-only — does NOT resolve, render, or execute anything.
    For each entity it reports whether a curated script (or the Linux generic
    upgrade fallback) covers it, and whether the Windows generic installer
    could close the gap.

    Built for the /vulnerabilities page's server-side coverage enrichment: the
    page batches the distinct (vendor, product, os) triples it renders and
    attaches a capability-gap flag beside each row, so a missing app-specific
    script is discoverable in the table rather than only surfacing mid-chat.

    Args:
        remediations: List of entities, each a dict with 'vendor', 'product',
            and 'os' (platform string — 'Windows' | 'Linux' | 'Mac' or any
            recognizable variant). Order is preserved in the result so callers
            can zip results back to inputs.

    Returns per entity: {vendor, product, os (normalized | null), matched,
    script_id (curated id when matched, else null), generic_installer_eligible
    (true only when os is Windows AND no curated script matched)}.
    """
    from rtr_tools import classify_patch_coverage as _impl
    return _impl(remediations)


@mcp.tool()
def extras_recon_list_rules(limit: int = 50) -> dict[str, Any]:
    """List active Falcon Adversary Intelligence Recon monitoring rules. Read-only.
    Returns each rule's id, name, topic, filter, status, priority, and timestamps.
    Use this to understand what the tenant is already watching for so you don't
    propose redundant coverage.

    Args:
        limit: Max rules to return (1-500). Default 50.
    """
    from recon import recon_list_rules as _impl
    return _impl(limit)


@mcp.tool()
def extras_recon_search_notifications(
    q: str | None = None, limit: int = 50
) -> dict[str, Any]:
    """Free-text search across Recon notifications already generated by tenant
    monitoring rules. The Recon corpus surfaces dark-web forum mentions,
    Telegram channel posts, paste-site dumps, breach-source leaks, and
    typosquat / brand-impersonation domains. Read-only.

    Note: this only returns matches against rules that already exist in the
    tenant. For ad-hoc lookup against the full Recon data lake, see
    extras_recon_search_exposed_records (which queries the credential-exposure
    corpus directly without requiring a pre-existing rule).

    Args:
        q: Free-text query (matches across all indexed notification fields).
        limit: Max notifications to return (1-500). Default 50.
    """
    from recon import recon_search_notifications as _impl
    return _impl(q, limit)


@mcp.tool()
def extras_recon_search_exposed_records(
    query: str,
    kind: str = "domain",
    limit: int = 50,
) -> dict[str, Any]:
    """Search the Recon exposed-data-records corpus (leaked credentials from
    breach dumps, paste sites, dark-web markets) by domain or email. Read-only.

    This is the primary tool for "are any of our users' credentials in known
    breaches" workflows. Unlike search_notifications, this queries the full
    credential-exposure corpus directly and does not require a pre-existing
    monitoring rule.

    Args:
        query: The value to search for. Strict per `kind`:
            - domain: lowercase hostname/registrable-domain (e.g. 'example.com')
            - email: full address (e.g. 'analyst@example.com')
            - free: free-text fallback (limited charset; see kind below).
        kind: 'domain' | 'email' | 'free'. Default 'domain'.
        limit: Max records to return (1-500). Default 50.
    """
    from recon import recon_search_exposed_records as _impl
    return _impl(query, kind, limit)


@mcp.tool()
def extras_recon_preview_corpus_search(
    query: str,
    kind: str = "domain",
) -> dict[str, Any]:
    """Search the full Falcon Adversary Intelligence Recon data lake for any
    mention of a domain, email, IP, or keyword — across criminal marketplaces,
    forums, public repos (GitHub paste-leaks), Telegram channels, social media,
    and breach dumps. Read-only.

    This is the right tool when the operator is asking "is anyone talking
    about us anywhere on the underground" — it queries the underlying corpus
    directly rather than tenant-scoped notifications, so it returns hits even
    when the tenant has no monitoring rules in place.

    The Recon API exposes this through the rule-preview endpoint: it returns
    aggregate counts by `channel` (criminal_marketplace / forum / public_repo /
    chat_medium / social_media) and by `site` (specific source like
    breachforums.cz, telegram.org, github.com). Raw items are NOT returned —
    that is by design from CrowdStrike. Counts + breakdown are the surface.

    Args:
        query: The value to search for. Strict per `kind`:
            - domain: registrable hostname (e.g. 'bankofamerica.com')
            - email: full address (e.g. 'analyst@example.com')
            - ip: IPv4 address (e.g. '203.0.113.1')
            - keyword: free-text brand string or VIP name; broadest topic
        kind: 'domain' | 'email' | 'ip' | 'keyword'. Default 'domain'.
    """
    from recon import recon_preview_corpus_search as _impl
    return _impl(query, kind)


# ---------------------------------------------------------------------------
# Falcon Discover — asset / application / account inventory (read-only)
# ---------------------------------------------------------------------------


@mcp.tool()
def extras_discover_assets(
    filter: str | None = None, limit: int = 100, scope: str = "all"
) -> dict[str, Any]:
    """List endpoint assets from Falcon Discover (managed + unmanaged). Read-only.
    Managed = a Falcon sensor is installed; unmanaged = discovered on the network
    with no sensor (a coverage gap worth surfacing). Returns hostname, platform,
    OS, IPs, first/last-seen, manufacturer and entity_type per asset.

    Args:
        filter: Optional FQL filter (e.g. platform_name:'Windows',
            last_seen_timestamp:>'now-30d').
        limit: Max assets to return (1-100). Default 100.
        scope: 'managed', 'unmanaged', or 'all' (default).
    """
    from discover import discover_assets as _impl
    return _impl(filter, limit, scope)


@mcp.tool()
def extras_discover_applications(
    filter: str | None = None, limit: int = 100, host_aid: str | None = None
) -> dict[str, Any]:
    """List installed applications inventoried by Falcon Discover. Read-only.
    Returns name, vendor, version, software_type, installation paths, last-used
    timestamp, and the is_suspicious flag, joined to the host that runs it.

    This is Falcon's periodically-synced inventory, not a live host query — it
    can lag or under-report what is *currently* installed. For an authoritative
    "installed right now" answer on a live Windows host, use the RTR
    InstalledProgram script (falcon_run_falcon_script) instead.

    Args:
        host_aid: Optional device AID (32-char hex) to scope to a single host —
            the "apps installed on host X" query. Pass the AID from
            falcon_search_hosts; do NOT hand-write a host filter (the field is
            ``host.aid``, not ``host_info.aid`` or bare ``aid``).
        filter: Optional FQL filter. Wildcard/contains: ``name:'*chrome*'``
            (asterisk in the value — NOT ``name:~``). Other examples:
            ``is_suspicious:true``, ``vendor.name:'Oracle'``,
            ``software_type:'browser_extension'``. Combined (AND) with host_aid.
        limit: Max applications to return (1-100). Default 100.
    """
    from discover import discover_applications as _impl
    return _impl(filter, limit, host_aid)


# ---------------------------------------------------------------------------
# Host groups (read-only v1)
# ---------------------------------------------------------------------------


@mcp.tool()
def extras_host_group_list(
    filter: str | None = None, limit: int = 50
) -> dict[str, Any]:
    """List Falcon Host Groups in the tenant. Read-only.

    Returns each group's id, name, description, group_type (static |
    dynamic), assignment_rule (FQL filter that defines membership for
    dynamic groups), created/modified timestamps + actors. Member counts
    are NOT included here — call extras_host_group_members per group when
    you need them.

    Args:
        filter: Optional FQL filter on group fields. Wildcard/contains on
            name: ``name:'*quarantine*'`` (asterisk in value — NOT ``name:~``).
            Other examples: ``group_type:'static'``, ``created_by:'user@example.com'``.
        limit: Max groups to return (1-5000). Default 50.
    """
    from host_groups import host_group_list as _impl
    return _impl(filter, limit)


@mcp.tool()
def extras_host_group_members(group_id: str, limit: int = 50) -> dict[str, Any]:
    """List the hosts that are members of a Falcon Host Group. Read-only.

    Returns hostname, platform, OS version, last-seen, AID for up to `limit`
    members. Use this to size a group ahead of a staged rollout.

    Args:
        group_id: The host group id (returned by extras_host_group_list).
        limit: Max members to return (1-5000). Default 50.
    """
    from host_groups import host_group_members as _impl
    return _impl(group_id, limit)


@mcp.tool()
def extras_host_group_membership_for_device(device_id: str) -> dict[str, Any]:
    """Resolve the full Host Group membership for a single device. Read-only.

    The `groups` array returned by falcon_search_hosts and Falcon's device
    entity endpoints is unreliable: dynamic-group memberships (assignment_rule
    FQL) and sometimes static-group memberships are omitted depending on API
    projection and timing. This tool walks every host group in the tenant and
    returns those that actually contain the given AID.

    Use this in IR workflows where you must capture original membership before
    moving a host (so you can restore it accurately later). The walk is one
    membership probe per group, but probes run concurrently, so wall time stays
    bounded (~10s for a typical <100-group tenant) even though the call count is
    still 1 + N.

    Args:
        device_id: Falcon AID to resolve membership for.

    Returns:
        ok, device_id, items (list of {id, name, group_type, assignment_rule
        if dynamic}), count.
    """
    from host_groups import host_group_membership_for_device as _impl
    return _impl(device_id)


@mcp.tool()
def extras_host_group_add_members(
    group_id: str, device_ids: list[str]
) -> dict[str, Any]:
    """Add one or more hosts to a static Falcon Host Group. WRITE ACTION —
    requires explicit user approval in the UI before execution.

    Accepts both 'static' (added-by-name) and 'staticByID' (added-by-AID)
    group flavors. Dynamic groups (group_type='dynamic') determine membership
    via their assignment_rule FQL — the pre-flight check rejects those.

    Args:
        group_id: The host group id (must be static or staticByID). From
            extras_host_group_list.
        device_ids: List of Falcon device (AID) IDs to add. Cap 500 per call.
    """
    from host_groups import host_group_add_members as _impl
    return _impl(group_id, device_ids)


@mcp.tool()
def extras_host_group_remove_members(
    group_id: str, device_ids: list[str]
) -> dict[str, Any]:
    """Remove one or more hosts from a static Falcon Host Group. WRITE
    ACTION — requires explicit user approval in the UI before execution.

    Accepts both 'static' and 'staticByID' group flavors.

    Args:
        group_id: The host group id (must be static or staticByID).
        device_ids: List of Falcon device (AID) IDs to remove. Cap 500 per call.
    """
    from host_groups import host_group_remove_members as _impl
    return _impl(group_id, device_ids)


# ---------------------------------------------------------------------------
# Fusion Workflows (read-only v1)
# ---------------------------------------------------------------------------


@mcp.tool()
def extras_workflows_list_definitions(
    filter: str | None = None, limit: int = 50
) -> dict[str, Any]:
    """List Fusion SOAR workflow definitions in the tenant. Read-only.

    Returns each definition's id, name, description, status (enabled?),
    trigger type, last modified. Use this to answer "what automation does
    this tenant have" without going to the console.

    Args:
        filter: Optional FQL filter (e.g. status:'enabled', trigger.kind:'detection').
        limit: Max definitions to return (1-500). Default 50.
    """
    from workflows import workflows_list_definitions as _impl
    return _impl(filter, limit)


@mcp.tool()
def extras_workflows_list_executions(
    filter: str | None = None, limit: int = 50
) -> dict[str, Any]:
    """List recent Fusion SOAR workflow executions. Read-only.

    Returns each execution's id, definition id, status (success / failed /
    in-progress), start/end timestamps, trigger source. Use this to surface
    "which automations fired in the last 24h, which failed, which are
    still in flight."

    A default 7-day recency window is applied when no `filter` is supplied —
    without it the upstream WorkflowExecutionsCombined endpoint walks the
    entire execution ledger and times out on busy tenants. Pass an explicit
    filter to override (e.g. `started_timestamp:>'<iso>'`, `status:'failed'`,
    or any combination). The response echoes the resolved filter in
    `filter_applied` and `default_window_applied`.

    Args:
        filter: Optional FQL filter (e.g. `status:'failed'`,
            `started_timestamp:>'<iso>'`). Field is `started_timestamp`,
            NOT `start_timestamp`. When supplied, replaces the default
            7-day recency window.
        limit: Max executions to return (1-200). Default 50. Hard-capped
            at 200 — the upstream endpoint times out past that on busy
            tenants. Paginate via `started_timestamp:<` if you need more.
    """
    from workflows import workflows_list_executions as _impl
    return _impl(filter, limit)


@mcp.tool()
def extras_workflows_execute(
    definition_id: str,
    payload: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    """Execute an on-demand Fusion workflow. WRITE ACTION — requires explicit
    user approval in the UI before execution. The approval prompt surfaces
    the full resolved payload so the operator can verify trigger inputs
    before they fire.

    Payload shape is per-workflow: it must match the workflow's expected
    on-demand trigger inputs. Discover available workflows + their schemas
    via extras_workflows_list_definitions; the trigger contract lives on
    each definition. If the workflow has no on-demand trigger, execute will
    fail upstream — list the triggers first via falcon_list_workflow_triggers
    if uncertain.

    The response contains the new execution_id; poll
    extras_workflows_execution_result to retrieve outputs.

    Args:
        definition_id: The workflow definition id (preferred over name; ids
            are unambiguous when multiple workflows share a name).
        payload: On-demand trigger input dict. Defaults to {}.
        key: Optional dedup key. Falcon suppresses duplicate executions sharing
            the same key within its dedup window. Omit for a fresh UUID.
    """
    from workflows import workflows_execute as _impl
    return _impl(definition_id, payload, key)


@mcp.tool()
def extras_workflows_execution_result(execution_id: str) -> dict[str, Any]:
    """Fetch the result of a workflow execution. Read-only. Use after
    extras_workflows_execute to confirm completion + retrieve outputs.

    Workflow executions are asynchronous — a freshly-returned execution id
    may not have results yet. If the result set is empty, wait briefly and
    retry; do not interpret an empty result as a failed execution.

    Args:
        execution_id: Execution id returned by extras_workflows_execute.
    """
    from workflows import workflows_execution_result as _impl
    return _impl(execution_id)


# ---------------------------------------------------------------------------
# Identity Protection (scope pending on this tenant — staged build)
# ---------------------------------------------------------------------------
#
# IMPORTANT: As of this build, the API client lacks Identity Protection
# scope. All tools below will return scope_pending=true via the shared
# _is_permission_error guard. The page is intentionally built so the agent
# can render a clean "scope pending" decision document — when a key with
# `Identity Protection Entities:read` (and friends) is applied, no code
# changes are needed; the surface lights up automatically.


# IDP GraphQL query for at-risk entities. Limited to 25 — IDP entity counts
# can be in the millions on large tenants and the GraphQL API caps page sizes.


@mcp.tool()
def extras_identity_detections(
    hours: int = 168,
    limit: int = 50,
    include_policy_matches: bool = False,
    include_closed: bool = False,
) -> dict[str, Any]:
    """List recent Identity Protection detections via the Alerts API
    (filter `product:'idp'`). Read-only.

    Returns each alert's composite_id, severity_name, display_name,
    created_timestamp, status, and the user_name / source_account_name /
    destination_account_name fields specific to identity detections
    (Pass-the-Hash, Golden Ticket, Kerberoasting, suspicious LDAP, etc.).

    By default filters to **open** detections (new / in_progress / reopened)
    and **excludes "Policy rule match" enforcement events** — those are
    sensor-side enforcement firings, not attack-pattern detections, and
    drown out real threats in lab tenants. Set the include_* flags to true
    to bring them back.

    Args:
        hours: How far back to search (default 168 = last 7 days).
        limit: Max detections to return (1-500). Default 50.
        include_policy_matches: When True, includes "Policy rule match"
            rows. Default False — filters them by checking that `tactic`
            is non-empty (policy-match rows have no tactic).
        include_closed: When True, includes closed/resolved detections.
            Default False — restricts to status in {new, reopened, in_progress}.
    """
    from identity import identity_detections as _impl
    return _impl(hours, limit, include_policy_matches, include_closed)


@mcp.tool()
def extras_identity_ir_workflow_playbook(
    entity_id: str | None = None, sam_account_name: str | None = None
) -> dict[str, Any]:
    """Return the agentic identity-IR workflow playbook for a specific entity.
    Read-only. Mirrors extras_ir_workflow_playbook (host) but pivots on an
    identity entity rather than an AID.

    The agent calls this when the operator asks for an agentic identity IR
    workflow on a user; the returned text becomes the agent's working
    playbook for the rest of the conversation. The defining shape of
    identity IR is the **endpoint cascade** — Falcon's IDP API surface
    doesn't include account-disable / session-kill / password-reset, so the
    load-bearing remediation is to run the host IR playbook on each
    endpoint the user has been logged into recently.

    Args:
        entity_id: Optional. IDP entity id from the GraphQL API.
        sam_account_name: Optional. AD samAccountName. At least one of
            entity_id or sam_account_name must be provided.
    """
    from identity import identity_ir_workflow_playbook as _impl
    return _impl(entity_id, sam_account_name)


# ---------------------------------------------------------------------------
# NGSIEM operational introspection (read-only)
# ---------------------------------------------------------------------------
#
# These tools answer the operational questions "what's plumbed in, what's
# parsing, what lookup data is available" — distinct from query execution
# (which falcon-mcp's falcon_search_ngsiem already covers). Closes the gap
# where an agent runs a CQL query, gets zero results, and has no way to
# diagnose whether the query was wrong or the data simply isn't ingested.


@mcp.tool()
def extras_ngsiem_provisioning_status(cids: list[str]) -> dict[str, Any]:
    """Get NGSIEM provisioning status for one or more CIDs. Read-only.

    The endpoint is MSSP-shaped: it returns provisioning health for a list
    of customer IDs you supply. NOT a tenant-wide health check — for that,
    look at falcon_list_ngsiem_data_connections + falcon_list_ngsiem_lookup_files
    + falcon_list_ngsiem_parsers, which collectively prove the API and ingest
    paths work.

    Args:
        cids: One or more Falcon customer IDs (UUIDs). 1-100 entries.
    """
    from ngsiem.management import ngsiem_provisioning_status as _impl
    return _impl(cids)


# Known remote-access-tool image-name catalog. Each entry is
# (regex_alternation_atom, canonical_tool, family). The regex atoms are
# joined into one CQL alternation; a match on the image basename routes
# to the canonical tool name (used to dedupe + classify findings) and a
# family bucket the playbook can act on.
#
# Curated for the IR-thorough RAT-install scan. Limited to actively-marketed
# RAT and RMM products that operators in the field treat as suspicious when
# unexpected — matches ATT&CK T1219 (Remote Access Software). Not exhaustive
# (legitimate vendor tooling like SCCM, Intune, Tanium is intentionally
# excluded — those are usually corp-managed and not the install pattern
# Phase 0 is hunting for).

# Compiled once at import. The CQL regex is the same alternation,
# wrapped to be full-match-anchored against the image basename — CQL
# `=/regex/i` is full-match per CLAUDE.md's NGSIEM gotcha block, so
# `.*` framing is required to allow the rest of the basename / path.


@mcp.tool()
def extras_host_rat_install_scan(
    device_id: str, hours_back: int = 48
) -> dict[str, Any]:
    """Scan NGSIEM ProcessRollup2 events on a single host for executions of
    known remote-access tools (RATs / RMMs). Read-only.

    Implements the THOROUGH leg of the IR Phase 0 RAT-install check: a
    detection-time-window NGSIEM query catches historical installs even when
    the installer process has long since exited, complementing the cheap
    `Process` falconscript pass which only catches currently-running
    processes. Driven by ATT&CK T1219 (Remote Access Software) -- attackers
    routinely install legitimate, signed RATs alongside malicious activity
    so the access channel survives the cleanup of the original detection.

    The catalog (AnyDesk, TeamViewer, ScreenConnect, Atera, Splashtop,
    RustDesk, NetSupport, VNC, DWService, RemoteUtilities, LogMeIn, GoTo,
    Kaseya, NinjaOne, Pulseway, Action1, Chrome Remote Desktop) is a
    deliberately-narrow list of products that flag as suspicious in the
    field when unexpected. Corp-managed agents (SCCM, Intune, Tanium) are
    intentionally excluded.

    Findings are grouped by canonical tool name -- two AnyDesk executions
    with different installer paths collapse into one item with both paths
    captured. Phase 0's invariant: every returned item must map to a Phase
    2 cleanup action (e.g. uninstall-anydesk, kill-process + delete-file).

    Args:
        device_id: Falcon AID (32-char hex).
        hours_back: Look-back window in hours (1-168, default 48). Wider
            windows are slower but catch installs that predate the
            triggering detection.
    """
    from ir.rat_scan import host_rat_install_scan as _impl
    return _impl(device_id, hours_back)


# ---------------------------------------------------------------------------
# Shadow-AI hunting (per-host + fleet egress).
#
# Three signal layers from one NGSIEM-backed sidecar pass:
#   1. ProcessRollup2 image-name match against AI_APP_CATALOG (Cursor,
#      Ollama, LM Studio, Claude Desktop, ComfyUI, ...).
#   2. ProcessRollup2 cmdline match against MCP_CMDLINE_CATALOG (MCP
#      servers, agentic frameworks).
#   3. DnsRequest domain match against AI_EGRESS_CATALOG (api.openai.com,
#      claude.ai, huggingface, smithery.ai, ...).
#
# Combined into a single posture verdict (model_developer / mcp_host /
# agentic_developer / unsanctioned_saas / code_assistant / image_video_gen
# / no_signal) which drives /shadow-ai grouping + remediation primer.
#
# Falcon for IT (osquery) covers Layer 1 today; the value here is Layers
# 2 and 3 — the parts no vendor catalogs in one place — and the
# correlation across layers in a single pass.
# ---------------------------------------------------------------------------


@mcp.tool()
def extras_host_shadow_ai_scan(
    device_id: str, hours_back: int = 72
) -> dict[str, Any]:
    """Four-layer shadow-AI scan on a single host. Read-only.

    Combines four NGSIEM passes (executed sequentially on one search
    job each — falcon-mcp serializes per client):

      1. ProcessRollup2 → image-name match (AI desktop apps).
      2. ProcessRollup2 → cmdline match (MCP servers, agentic frameworks).
      3. DnsRequest → domain match (AI egress endpoints).
      4. NetworkConnect → local-inference port match (loopback confirms a
         locally-running model server is actively serving; non-loopback
         flags this host as a *consumer* of a peer's local LLM, e.g. a
         browser/IDE here talking to Ollama on a coworker's workstation).

    Returns a structured payload the /shadow-ai page renders:

      {
        "ok": true,
        "device_id": "...",
        "verdict": "mcp_host" | "model_developer" | ...,
        "apps":           [{tool, family, posture, image_paths, exec_count, last_seen_ms, top_user}],
        "mcp":            [{tool, family, posture, matched_token, image, cmdline, last_seen_ms, top_user}],
        "egress":         [{tool, posture, domain, query_count, last_seen_ms, top_image}],
        "local_inference":[{tool, port, scope, posture, remote_addresses, conn_count, last_seen_ms, top_image, top_user}],
        "events_scanned": int,
      }

    Args:
        device_id: Falcon AID (32-char hex).
        hours_back: Look-back window in hours (1-336, default 72). 72h
            covers a working week's worth of intermittent use.
    """
    from shadow_ai.tools import host_shadow_ai_scan as _impl
    return _impl(device_id, hours_back)


@mcp.tool()
def extras_fleet_shadow_ai_egress(
    hours_back: int = 24, limit: int = 5000
) -> dict[str, Any]:
    """Fleet-wide DnsRequest scan for AI egress endpoints, grouped by AID
    and tool. Read-only.

    The cheap path for /shadow-ai's initial fleet view: one NGSIEM
    search returns every DNS query in the window matching the AI egress
    catalog, then we group server-side by (AID, tool). Compared to the
    per-host fan-out, this trades depth (no app / MCP layer) for breadth
    (every host in one call).

    Pairs with extras_host_shadow_ai_scan: the page can list every host
    with egress signal here, then drill in for the full triple-layer
    profile per host on operator request.

    Args:
        hours_back: Look-back window in hours (1-168, default 24).
        limit: Maximum DNS rows returned (capped at 10000). Increase if
            the fleet is large or the window is wide; default 5000 is
            comfortable for ~200 hosts over 24h.

    Returns:
        {
          "ok": true,
          "items": [
             {aid, hostname?, tools: [{tool, posture, query_count,
              first_seen_ms, last_seen_ms, sample_domains: [...]}]},
             ...
          ],
          "events_scanned": int,
          "hours_back": int,
        }
    """
    from shadow_ai.tools import fleet_shadow_ai_egress as _impl
    return _impl(hours_back, limit)


# ---------------------------------------------------------------------------
# Process-tree reconstruction + delivery-vector classification
# ---------------------------------------------------------------------------
#
# Walks ProcessRollup2 events around a detection's pivot pid to reconstruct
# the ancestry chain, then runs the classifier over that chain to produce
# a delivery_vector verdict (phishing_doc, browser_drive_by, lateral_winrm,
# scheduled_task_persistence, ...). The verdict is decision-grade for IR
# Phase 0 — it tells the operator what the channel was, not just what
# fired. Read-only.


# ---------------------------------------------------------------------------
# Shadow-AI prevention bundle (Custom IOA rule group + policy attachment).
#
# Operator workflow:
#   1. Operator creates a host group "AI-Banned" in Falcon Console
#      (or via extras_create_host_group). Notes the id and exports it
#      as FALCON_SHADOW_AI_BANNED_GROUP_ID.
#   2. Operator creates / picks a Prevention Policy bound to that host
#      group (Falcon Console → Prevention Policies). Notes the policy id.
#   3. Operator runs `extras_shadow_ai_adopt_prevention(prevention_
#      policy_id=..., comment=..., mode='detect')` once to seed the rule
#      group in detect-only. Verifies in Falcon Console that the rules
#      enumerate correctly.
#   4. Flips to mode='block' (re-runs the same call). The adoption tool
#      is idempotent: rule group is reused by name, only missing rules
#      are added, the policy attachment short-circuits if already set.
#   5. From `/shadow-ai`, the operator hits "Ban+Clean" on a flagged
#      host. That moves the host into AI-Banned (host-group write,
#      already gated) and fires the per-product uninstall scripts.
#      Prevention rules start enforcing on next sensor heartbeat.
#
# The disposition_override / `mode` knob exists because shipping a
# brand-new IOA rule group at disposition=block is operationally risky
# on a fresh tenant — a malformed regex on a high-volume image (e.g.
# `python.exe`) would block legitimate Python work fleetwide. The detect
# pass surfaces every match in the detection feed first.
# ---------------------------------------------------------------------------


@mcp.tool()
def extras_shadow_ai_workflow_playbook(device_id: str) -> dict[str, Any]:
    """Return the agentic Shadow-AI ban-and-clean workflow playbook for one host. Read-only.

    Call this when the operator clicks "Ban + Clean" on a host in /shadow-ai
    or asks for the agentic Shadow-AI workflow on a specific host. The
    returned `playbook` text is your working instruction set for the rest of
    the conversation — follow it phase by phase.

    The playbook is parameterized with the target device_id and the
    operator-configured banned host group id. Returns ok=False with a clear
    error if FALCON_SHADOW_AI_BANNED_GROUP_ID is unset on the server.

    Args:
        device_id: Falcon AID of the target host.
    """
    from shadow_ai.tools import shadow_ai_workflow_playbook as _impl
    return _impl(device_id)


@mcp.tool()
def extras_shadow_ai_prevention_status() -> dict[str, Any]:
    """Report Shadow-AI prevention deployment state. READ-ONLY.

    Returns the corpus the adoption tool would author, plus the live
    state of the rule group (if it exists): id, enabled flag, rule
    count, names of currently-installed rules vs missing rules. Does
    NOT read prevention-policy bindings (separate API; cheap to add if
    needed).
    """
    from shadow_ai.tools import shadow_ai_prevention_status as _impl
    return _impl()


@mcp.tool()
def extras_shadow_ai_adopt_prevention(
    prevention_policy_id: str,
    comment: str,
    mode: str = "block",
    dry_run: bool = False,
    platform: str = "windows",
) -> dict[str, Any]:
    """Author the Shadow-AI Custom IOA rule bundle and bind it to a
    Prevention Policy. WRITE ACTION — requires explicit user approval.

    Per-platform: Falcon Custom IOA rule groups are platform-scoped and
    can't bind across platforms. Each platform has its own canonical
    rule group + corpus:
      - windows → 'Project Eyas - Shadow-AI Block'
      - mac → 'Project Eyas - Shadow-AI Block (mac)'
      - linux → 'Project Eyas - Shadow-AI Block (linux)'

    The provisioning tool ``extras_provision_shadow_ai_banned_policy``
    returns one ``follow_up_tool_calls[]`` entry per platform; pass the
    matching ``platform`` here.

    Idempotent + self-healing: looking up the per-platform rule group by
    name reuses an existing one; missing corpus rules are created, and
    every managed rule is CONVERGED to enabled=True + the chosen
    disposition (Custom IOA rules are created disabled by Falcon, so this
    is what actually turns enforcement on). Re-running with a different
    `mode` re-dispositions the existing rules; a previously-broken
    (disabled) ruleset is repaired in place. Each rule's live match
    patterns are preserved.

    Args:
        prevention_policy_id: The Prevention Policy id to bind the rule
            group to. Must be the same platform as the rule group.
        comment: Required free-text reason. Recorded in Falcon Console's
            change ledger for audit.
        mode: 'block' (disposition 30, "Block Execution" — prevents the
            process; the default) or 'detect' (disposition 20, detection
            only).
        dry_run: When true, returns the create/converge plan without writes.
        platform: 'windows' / 'mac' / 'linux'. Default 'windows' for
            backward compat.
    """
    from shadow_ai.tools import shadow_ai_adopt_prevention as _impl
    return _impl(prevention_policy_id, comment, mode, dry_run, platform)


@mcp.tool()
def extras_host_process_tree(
    device_id: str,
    pivot_pid: int | None = None,
    pivot_image: str | None = None,
    pivot_ts_iso: str | None = None,
    window_minutes: int = 10,
    ancestry_max: int = 12,
    descendants_max: int = 200,
) -> dict[str, Any]:
    """Reconstruct the process tree around a detection pivot and classify
    the delivery vector. Read-only.

    Walks NGSIEM ProcessRollup2 events on `device_id` over a window
    centered on `pivot_ts_iso`. Locates the pivot by `pivot_pid` (preferred)
    or by fuzzy-matching `pivot_image` near the timestamp. Then walks
    `ParentProcessId` upward to build the ancestry chain (the load-bearing
    output for IR — explains how the attack arrived) and `ContextProcessId`
    downward for descendants (blast radius — what else got spawned).

    The classifier inspects the ancestry and returns a `delivery_vector`
    verdict — `phishing_doc`, `phishing_email_direct`, `browser_drive_by`,
    `archive_extraction`, `user_executed_dropper`, `lateral_winrm`,
    `lateral_psexec`, `scheduled_task_persistence`, `wmi_persistence`,
    `malicious_service`, `malicious_document_lateral`, `lolbin_initial`,
    or `unknown` — plus a confidence (`high` / `medium` / `low`) and
    a one-sentence rationale that names the anchor.

    The vector is decision-grade for IR Phase 0: it tells the operator
    where the attack arrived (pull email, audit browser, isolate lateral
    source) and not just what fired on the host.

    Args:
        device_id: Falcon AID (32-char hex).
        pivot_pid: Triggering process pid from the detection's behaviors[].
            One of pivot_pid or pivot_image is required.
        pivot_image: Triggering process basename (e.g. `powershell.exe`),
            used to fuzzy-match when pivot_pid isn't known.
        pivot_ts_iso: Detection created_timestamp (ISO 8601). Required —
            anchors the search window.
        window_minutes: Time window radius around pivot_ts_iso (1-120,
            default 10). The walker may widen once to ±60 min for a single
            ancestor lookup if the parent isn't in the initial window.
        ancestry_max: Max depth to walk upward (1-30, default 12).
        descendants_max: Max descendant nodes to return (1-1000, default 200).
    """
    from ir.process_tree import host_process_tree as _impl
    return _impl(device_id, pivot_pid=pivot_pid, pivot_image=pivot_image, pivot_ts_iso=pivot_ts_iso, window_minutes=window_minutes, ancestry_max=ancestry_max, descendants_max=descendants_max)


# ---------------------------------------------------------------------------
# IR campaign clustering — used by extras_ir_campaign_scope to group open
# detections by shared process-tree ancestry. Each detection's pivot_pid is
# walked upward through ProcessRollup2; detections whose ancestry chains
# share at least one non-system ancestor pid are members of the same
# campaign cluster. The cluster's "root" is the highest-up shared ancestor.

# System pids / processes that connect EVERYTHING (every user process
# eventually hits explorer.exe / services.exe / wininit / smss / csrss).
# Excluded from cluster-shared-ancestor matching so unrelated user campaigns
# don't get merged through the system root.


@mcp.tool()
def extras_ir_campaign_scope(device_id: str) -> dict[str, Any]:
    """Server-side campaign-aware IR Phase 0 scope. Read-only.

    For every open detection on the host, walks the process-tree ancestry
    via ProcessRollup2 (caching per unique pivot_pid so detections sharing
    a pivot pay one walk, not N), then UnionFind-clusters detections by
    shared NON-SYSTEM ancestor pid. Each cluster is one "campaign" — the
    set of detections rooted in the same attacker chain. System processes
    (explorer, services, svchost, lsass, etc.) are excluded from the
    shared-ancestor match so unrelated user campaigns don't merge through
    the OS root.

    **Why this exists** (vs `extras_close_all_open_detections_on_host`):
    on a host with multiple distinct campaigns or background detections
    unrelated to the current IR engagement, bulk-closing everything is
    wrong. Phase 0 should scope to the campaign the operator is
    responding to — and the agent should not be trusted to do the
    clustering itself (it's tedious, ancestry-tree comparison is the kind
    of work LLMs skip). Server-side clustering returns explicit
    `campaigns[]` so Phase 4 can close one campaign cleanly without
    touching unrelated alerts.

    For each campaign cluster, the tool also runs the existing delivery-
    vector classifier on the deepest ancestry chain — same `kind`
    (`phishing_doc`, `browser_drive_by`, `c2_agent`, etc.) and confidence
    the IR playbook already consumes from `extras_host_process_tree`.

    Operator workflow:
        1. Call this tool in Phase 0.
        2. Pick the campaign matching the IR engagement (usually the
           largest cluster, or the one with the most-recent activity).
        3. Pass that campaign's `composite_ids` to Phase 4 close.

    Args:
        device_id: Falcon AID of the target host.

    Returns:
        ok, campaigns: list of {campaign_id, count, composite_ids[],
        root_pid, root_image, delivery_vector, first_ts, last_ts,
        sample_ancestry[]}, unclustered: composite_ids without ancestry
        data (telemetry aged out / pivot_pid missing), total_open,
        unique_pivots_walked, walk_seconds.
    """
    from ir.campaign_scope import ir_campaign_scope as _impl
    return _impl(device_id)


@mcp.tool()
def extras_ir_phase0_actionable_check(device_id: str) -> dict[str, Any]:
    """Workflow-entry triage: partition every open detection on the host
    into actionable vs noise BEFORE the IR workflow commits to Phase 1
    quarantine. Read-only.

    The IR workflow can be triggered on a host whose open detections are
    entirely noise — RTR runscript preamble self-trigger fires from a
    prior IR engagement, Shadow-AI Ban+Clean's detect-only audit IOCs
    firing on continued AI-provider DNS, retrospective IOC backfill of
    pre-existing telemetry. None of these warrant a full quarantine +
    cleanup cycle.

    This tool walks every open detection on the host and classifies each:

    * ``workflow_self_triggered`` — RTR preamble self-trigger
      (PShellMimikatz / encoded-command). Detected by matching the fixed
      `-EncodedCommand <preamble base64>` substring in cmdline /
      parent_details.cmdline / behaviors[].cmdline.
    * ``shadow_ai_ioc_audit`` — Shadow-AI Ban+Clean detect-only IOC fire.
      Detected by walking behaviors[].ioc_type=="domain" and matching
      ioc_value against the Shadow-AI egress catalog.
    * ``retrospective_ioc_match`` — fresh envelope, all underlying event
      timestamps predate the workflow window. Same classifier as Phase 3.
    * ``actionable`` — anything else.

    Returns ``should_proceed_with_ir`` (True iff actionable[] is
    non-empty) plus pre-composed ``bulk_close_calls[]`` the agent fires
    verbatim to close the noise when short-circuiting.

    **Called from the chat route's IR primer prefetch** alongside
    ``extras_ir_workflow_playbook`` and ``extras_ir_campaign_scope``, so
    the agent sees the partition result before its first turn and can
    short-circuit the entire engagement on a clean host. Also callable
    directly via MCP for mid-engagement re-checks.

    Returns:
        {ok, device_id, total_open, actionable[], workflow_self_triggered[],
        shadow_ai_ioc_audit[], retrospective_ioc_match[],
        should_proceed_with_ir, bulk_close_calls[]}
    """
    from ir.phase0_actionable import phase0_actionable_partition as _impl
    return _impl(device_id)


@mcp.tool()
def extras_prevention_policy_posture(limit: int = 100) -> dict[str, Any]:
    """List prevention policies across every platform with a posture summary
    per policy. Returns:
      - per-policy: id, name, platform, enabled, description, key prevention
        settings (ML detection/prevention, AV detection/prevention, etc.),
        posture flags (disabled / ml_detect_only / cloud_av_detect_only /
        sensor_av_detect_only)
      - per-platform breakdown
      - tenant-level flags

    Operator question this answers: "what do we have set to detect-only that
    should be blocking?" — escalates the no-redundant-custom-coverage idea
    from chat-time precheck to dashboard-time review.
    """
    from prevention import prevention_policy_posture as _impl
    return _impl(limit)


# ---------------------------------------------------------------------------
# ML + IOA exclusions
#
# Long-lived tuning artifacts. Both write paths must surface uniqueness checks
# BEFORE submission — duplicate exclusions clutter the tenant and an existing
# match means the operator's prior decision still applies. Both write paths are
# gated by the operator-approval registry.
# ---------------------------------------------------------------------------


@mcp.tool()
def extras_list_ml_exclusions(
    limit: int = 100,
    filter: str | None = None,
) -> dict[str, Any]:
    """List ML (machine-learning) detection exclusions on this tenant. Read-only.
    Always run this BEFORE proposing a new ML exclusion so you can show the
    operator any existing matches and avoid duplicates.

    Args:
        limit: Max records (1-500). Default 100.
        filter: Optional FQL filter. Common forms:
            - `value:'C:\\\\path\\\\to\\\\binary.exe'` — exact match on excluded value
            - `applied_globally:true` — only globally-applied exclusions
            - `created_by:'analyst@example.com'` — by author
    """
    from exclusions import list_ml_exclusions as _impl
    return _impl(limit, filter)


@mcp.tool()
def extras_create_ml_exclusion(
    value: str,
    comment: str,
    excluded_from: list[str] | None = None,
    group_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Create an ML (machine-learning) detection exclusion. WRITE ACTION —
    requires explicit user approval in the UI before execution.

    PRE-FLIGHT REQUIRED: this tool calls extras_list_ml_exclusions internally
    with a `value:'<value>'` filter and refuses to proceed if a match already
    exists, returning the existing exclusion's id. The agent should also
    surface this to the operator as part of the approval prompt.

    Args:
        value: The path / file glob to exclude. Use Falcon glob syntax:
            single `*` matches within a path segment, `**` matches across
            segments. Examples:
              - `C:\\Program Files\\MyApp\\bin\\worker.exe`
              - `/opt/datadog-agent/bin/agent`
              - `C:\\Users\\*\\AppData\\Local\\Temp\\build-*.exe`
        comment: Required free-text comment recorded with the exclusion.
            Document WHY this is benign — what the operator confirmed. Visible
            in Falcon Console; this is the audit trail.
        excluded_from: Which ML detection surface(s) to suppress. List of
            `blocking` (on-write ML prevention) and/or `extraction` (offline
            ML scan during file extraction). Default: `["blocking"]`.
        group_ids: Optional host-group ids to scope the exclusion to. Omit
            to apply globally — note that global is the heavier commitment.
    """
    from exclusions import create_ml_exclusion as _impl
    return _impl(value, comment, excluded_from, group_ids)


@mcp.tool()
def extras_list_ioa_exclusions(
    limit: int = 100,
    filter: str | None = None,
) -> dict[str, Any]:
    """List IOA (indicator-of-attack) exclusions on this tenant. Read-only.
    Always run this BEFORE proposing a new IOA exclusion so you can show the
    operator any existing matches and avoid duplicates.

    Args:
        limit: Max records (1-500). Default 100.
        filter: Optional FQL filter. Common forms:
            - `pattern_id:'12345'` — exclusions for a specific behavior pattern
            - `applied_globally:true`
            - `created_by:'analyst@example.com'`
    """
    from exclusions import list_ioa_exclusions as _impl
    return _impl(limit, filter)


@mcp.tool()
def extras_create_ioa_exclusion(
    name: str,
    pattern_id: str,
    ifn_regex: str,
    comment: str,
    cl_regex: str | None = None,
    description: str | None = None,
    group_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Create an IOA (indicator-of-attack) exclusion. WRITE ACTION — requires
    explicit user approval in the UI before execution.

    IOA exclusions suppress a specific behavior PATTERN combined with an image
    file (and optionally a cmdline) regex. Use when ML exclusion is too broad
    (would suppress all detections on a binary, not just one specific behavior).

    PRE-FLIGHT REQUIRED: this tool calls extras_list_ioa_exclusions internally
    with `pattern_id:'<pattern_id>'` and refuses to proceed if a match exists
    with the same `ifn_regex`, returning the existing id.

    Args:
        name: Short human-readable name for the exclusion.
        pattern_id: The Falcon behavior pattern id this exclusion suppresses.
            Get this from the detection's `behaviors[].pattern_id` field —
            do NOT guess. The agent should pull a sample detection via
            falcon_search_detections before composing this call.
        ifn_regex: Image file name regex (full-match anchored). Required.
            Example: `.*\\\\bin\\\\worker\\.exe$`
        comment: Required free-text comment — document WHY this behavior
            is benign on this binary. Visible in Falcon Console (audit trail).
        cl_regex: Optional command-line regex (full-match anchored). Narrows
            the exclusion to specific invocation patterns of the binary. Omit
            for "all invocations of this image."
        description: Optional longer description.
        group_ids: Optional host-group ids to scope to. Omit for global.
    """
    from exclusions import create_ioa_exclusion as _impl
    return _impl(name, pattern_id, ifn_regex, comment, cl_regex, description, group_ids)


# ---------------------------------------------------------------------------
# Data Protection (DLP) configuration writes. falcon-mcp 0.20.0's Data Security
# module has native generic create/update, suppressed at the bridge in favor of
# these: the agentic provisioning workflow (playbook) + the monitor-first
# create side of the
# content-pattern -> classification -> policy chain via FalconPy's
# DataProtectionConfiguration collection. The creates are WRITE ACTIONS,
# approval-gated in lib/mcp/write-tools.ts, monitor-first defaults.
# ---------------------------------------------------------------------------


@mcp.tool()
def extras_data_protection_provision_playbook() -> dict[str, Any]:
    """Return the agentic Data Protection provisioning playbook. Read-only.

    Call this when the operator asks to provision / set up / stand up Data
    Protection (DLP) coverage for a sensitive-data type — e.g. "watch for SSNs
    on Windows", "protect our internal codenames", or they click "Provision
    coverage" on the /data-protection page. The returned `playbook` text is
    your working instruction set for the rest of the conversation: precheck
    existing coverage, synthesize + validate the regexes from the operator's
    description, then build the monitor-first content-pattern -> classification
    -> policy chain (each create approval-gated). Follow it step by step.
    """
    return {"ok": True, "playbook": render_data_protection_playbook()}


@mcp.tool()
def extras_create_data_protection_content_pattern(
    name: str,
    regexes: list[str],
    category: str,
    region: str = "ALL",
    min_match_threshold: int = 1,
    description: str | None = None,
    example: str | None = None,
) -> dict[str, Any]:
    """Create a Data Protection content pattern — the regex-matcher layer of
    the DLP chain. WRITE ACTION — requires explicit user approval.

    A content pattern is a named bundle of regexes that match a sensitive
    string (an internal codename, an account-number format, etc.). It's the
    bottom layer: reference it from a classification next.

    Args:
        name: Display name for the pattern.
        regexes: One or more regexes that match the sensitive string.
        category: Pattern category label — "Custom", "PII", "PCI DSS",
            "ITAR", or "Secret".
        region: Region scope — "ALL" or an ISO-3166 alpha-3 country code
            (e.g. "USA"). Default "ALL". Do not use "global" — Falcon rejects it.
        min_match_threshold: Regex hits required to count as a match. Default 1.
        description: Optional description of what the pattern detects.
        example: Optional non-sensitive sample string demonstrating a match.
    """
    from data_protection import create_content_pattern as _impl
    return _impl(name, regexes, category, region, min_match_threshold, description, example)


@mcp.tool()
def extras_create_data_protection_classification(
    name: str,
    content_patterns: list[str],
    protection_mode: str = "monitor",
    file_types: list[str] | None = None,
    detection_severity: str = "informational",
    response_action: str = "allow",
    notify_end_user: bool = False,
) -> dict[str, Any]:
    """Create a Data Protection classification — binds content patterns + a
    detection rule. WRITE ACTION — requires explicit user approval. Defaults
    to monitor mode (observe, don't block).

    A classification is the "what counts as sensitive data" unit: it
    references one or more content pattern ids and carries the rule (severity,
    response action, monitor vs enforce). Reference it from a policy next.

    Args:
        name: Display name for the classification.
        content_patterns: Content pattern ids this classification matches on
            (from extras_create_data_protection_content_pattern or
            falcon_search_data_security_entities entity_type="content_pattern"). At least one.
        protection_mode: "monitor" (detect only) or "enforce". Default
            "monitor" — the safe first deployment.
        file_types: Optional file-type ids to scope matching to. Omit for all.
        detection_severity: informational / low / medium / high / critical.
            Default "informational".
        response_action: "allow" (monitor) or "block". Only meaningful when
            protection_mode="enforce". Default "allow".
        notify_end_user: Notify the end user on a match. Default False.
    """
    from data_protection import create_classification as _impl
    return _impl(
        name, content_patterns, protection_mode, file_types,
        detection_severity, response_action, notify_end_user,
    )


@mcp.tool()
def extras_create_data_protection_policy(
    name: str,
    platform: str,
    classifications: list[str],
    description: str | None = None,
    precedence: int | None = None,
    enable_content_inspection: bool = True,
    enable_context_inspection: bool = True,
    enable_network_inspection: bool = True,
    inspection_depth: str = "balanced",
    min_confidence_level: str = "low",
) -> dict[str, Any]:
    """Create a Data Protection policy — the platform-scoped enforcement rule
    set that binds classifications and lands on hosts. WRITE ACTION — requires
    explicit user approval. Built with monitor-safe defaults (inspection on,
    block_all_data_access off).

    Args:
        name: Display name for the policy.
        platform: "win" or "mac" (required; DLP policies are platform-scoped).
        classifications: Classification ids this policy enforces (from
            extras_create_data_protection_classification or
            falcon_search_data_security_entities entity_type="classification"). At least one.
        description: Optional description.
        precedence: Optional ordering; lower evaluates first. Omit to append.
        enable_content_inspection: Inspect file/clipboard content. Default True.
        enable_context_inspection: Inspect source/destination context. Default True.
        enable_network_inspection: Inspect network/upload egress. Default True.
        inspection_depth: shallow / balanced / deep. Default "balanced".
        min_confidence_level: low / medium / high. Default "low".
    """
    from data_protection import create_policy as _impl
    return _impl(
        name, platform, classifications, description, precedence,
        enable_content_inspection, enable_context_inspection,
        enable_network_inspection, inspection_depth, min_confidence_level,
    )


@mcp.tool()
def extras_ngsiem_search(
    cql: str,
    start_iso: str | None = None,
    end_iso: str | None = None,
    hours_back: int = 24,
    repository: str = "search-all",
) -> dict[str, Any]:
    """Run an ad-hoc CQL search against NGSIEM. Read-only.

    Wraps a single LogScale search-all query through the same runner that
    powers the IR ancestry walks, the Shadow-AI scan, and the RAT-install
    scan. The runner runs a pre-flight CQL lint (``ngsiem.syntax.lint``)
    that short-circuits the most common syntax traps (``limit()`` vs
    ``head()``, single-quoted strings, missing ``#`` tag prefix,
    ``sort()`` default-truncation) before the query reaches the API.

    Time window: pass either ``start_iso`` + ``end_iso`` (ISO 8601) or
    ``hours_back`` (the runner converts to ms epoch). If both, the ISO
    pair wins.

    Args:
        cql: The CQL query string. Lints before submit.
        start_iso: Window start (ISO 8601). Optional.
        end_iso: Window end (ISO 8601). Optional. Defaults to now if
            ``start_iso`` is supplied without one.
        hours_back: Used when no explicit ISO window is given. 1-168.
        repository: LogScale repository. Default ``search-all``.

    Returns:
        ok, events (capped at 100 rows in the result; full ``row_count``
        also surfaced), row_count, truncated, repository, cql.
    """
    from datetime import datetime, timezone, timedelta
    import time as _time
    from ngsiem.search import run_ngsiem_search

    try:
        if not isinstance(cql, str) or not cql.strip():
            return {"ok": False, "error": "cql is required"}
        if start_iso:
            try:
                s_dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
            except ValueError:
                return {"ok": False, "error": f"bad start_iso: {start_iso}"}
            if end_iso:
                try:
                    e_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
                except ValueError:
                    return {"ok": False, "error": f"bad end_iso: {end_iso}"}
            else:
                e_dt = datetime.now(timezone.utc)
            start_ms = int(s_dt.timestamp() * 1000)
            end_ms = int(e_dt.timestamp() * 1000)
        else:
            if not isinstance(hours_back, int) or hours_back < 1 or hours_back > 168:
                return {"ok": False, "error": "hours_back must be 1-168"}
            end_ms = int(_time.time() * 1000)
            start_ms = end_ms - hours_back * 3600 * 1000
        repo = (repository or "search-all").strip() or "search-all"

        events, err = run_ngsiem_search(cql, start_ms, end_ms, budget_s=50.0, repository=repo)
        if err is not None:
            return err
        if events is None:
            return {
                "ok": True,
                "events": [],
                "row_count": 0,
                "truncated": True,
                "repository": repo,
                "cql": cql,
                "note": "NGSIEM search did not complete within 50s.",
            }
        ROW_CAP = 100
        return {
            "ok": True,
            "events": events[:ROW_CAP],
            "row_count": len(events),
            "truncated": len(events) > ROW_CAP,
            "repository": repo,
            "cql": cql,
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


@mcp.tool()
def extras_shadow_ai_check_prevention_binding() -> dict[str, Any]:
    """Diagnose whether the Shadow-AI Custom IOA rule group is actually
    enforcing on hosts moved into the AI-Banned host group. READ-ONLY.

    Checks the chain operators routinely miss: env var → host group →
    prevention policy attachment → IOA rule group binding → rule group
    enabled. Returns ``ready`` only when every step checks out, and
    ``missing_steps[]`` with operator-facing remediation pointers
    otherwise. ``extras_shadow_ai_adopt_prevention`` only binds to ONE
    prevention-policy id passed in by the operator and doesn't verify
    that policy is the one actually attached to the AI-Banned host group;
    this tool walks the live state and tells the operator exactly what
    to fix in console (FalconPy doesn't expose policy↔host-group
    attachment as a write — that's a console step).
    """
    from shadow_ai.tools import shadow_ai_check_prevention_binding as _impl
    return _impl()


@mcp.tool()
def extras_teardown_project_eyas_managed(dry_run: bool = True) -> dict[str, Any]:
    """Wipe all canonical Project Eyas-managed objects from the tenant.
    WRITE (in execute mode) — approval-gated.

    Discovers host groups, prevention policies, custom IOA rule groups,
    and IOA exclusions that Project Eyas created (matched by canonical
    name prefix plus the active env's saved group ids), and tears them
    down in Falcon-enforced dependency order:

      1. Detach prevention policies from host groups
      2. Disable prevention policies
      3. Delete prevention policies
      4. Delete custom IOA rule groups
      5. Delete IR-readiness IOA exclusions
      6. Delete host groups

    Use during demo cycles or dev resets to return the tenant to a clean
    state before re-running the /config setup cards.

    The active env's saved ``irQuarantineGroupId`` + ``shadowAiBannedGroupId``
    are NOT cleared automatically — operator clears them via the /config
    Clear button after this completes, OR re-provisions fresh groups (the
    auto-save hook overwrites with the new id).

    Args:
        dry_run: When True (default), returns a structured plan without
            touching the tenant. When False, executes the teardown and
            returns per-step results.
    """
    from teardown import teardown_project_eyas_managed as _impl
    return _impl(dry_run=dry_run)


@mcp.tool()
def extras_delete_prevention_policy(prevention_policy_id: str) -> dict[str, Any]:
    """Delete a single Falcon prevention policy by id. WRITE — approval-gated.

    The policy MUST already be detached from every host group (Falcon
    refuses delete on still-attached policies). This tool also disables
    the policy before delete as a courtesy (Falcon also refuses delete on
    enabled policies). Use ``extras_detach_prevention_policy_from_host_group``
    to detach first.

    Args:
        prevention_policy_id: Prevention policy id.
    """
    from teardown import delete_prevention_policy as _impl
    return _impl(prevention_policy_id=prevention_policy_id)


@mcp.tool()
def extras_delete_ioa_rule_group(
    rule_group_id: str,
    comment: str = "Project Eyas teardown",
) -> dict[str, Any]:
    """Delete a single Custom IOA rule group by id. WRITE — approval-gated.

    Falcon refuses delete if the rule group is still bound to any
    prevention policy — delete the binding policies first, or unbind via
    a policy update.

    Args:
        rule_group_id: Custom IOA rule group id.
        comment: Reason for deletion (Falcon audit-trail field).
    """
    from teardown import delete_ioa_rule_group as _impl
    return _impl(rule_group_id=rule_group_id, comment=comment)


if __name__ == "__main__":
    try:
        mcp.run()
    except Exception as exc:  # pragma: no cover - surface fatal init errors
        print(f"falcon-extras fatal: {exc}", file=sys.stderr)
        sys.exit(1)
