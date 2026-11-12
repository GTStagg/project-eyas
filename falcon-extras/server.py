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
def extras_close_all_open_detections_on_host(
    device_id: str,
    verdict: str,
    comment: str | None = None,
    include_multi_host: bool = False,
) -> dict[str, Any]:
    """Bulk-close every open detection on a single host. WRITE — gated.

    Finds every open detection on the host server-side (status `new` /
    `in_progress` / `reopened`, any product — including NGSIEM correlation
    alerts that name the host), closes them in batches, and returns aggregate
    counts. Single approval gate covers the entire bulk close.

    A correlation alert that also names OTHER hosts is not closed by default;
    it's listed in `skipped_multi_host` (count + composite_ids). Tell the
    operator about those and let them choose: close specific ones by id with
    falcon_update_detections, or rerun this with
    `include_multi_host=true` to close them all (they then leave every named
    host's queue).

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
        include_multi_host: Default False. True also closes correlation
            alerts that name other hosts besides this one — only when the
            operator has said so after seeing `skipped_multi_host`.

    Returns:
        ok, device_id, scope_count, updated, requested,
        composite_ids (every id closed), matched_by (how each was found),
        skipped_multi_host? ({count, composite_ids}), warning?.
    """
    from host_actions import close_all_open_detections_on_host as _impl
    return _impl(device_id, verdict, comment, include_multi_host)


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
    before_iso: str | None = None,
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
        before_iso: the Phase 1 quarantine time (ISO 8601). When given, the
            result adds `unmatched_prior_count` + `unmatched_prior_sample`:
            the untouched Phase 0 detections that still block release.

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
    return _impl(device_id, remediated, verdict, comment, before_iso)


@mcp.tool()
def extras_ir_close_untouched_originals(
    device_id: str,
    before_iso: str,
    verdict: str,
    comment: str | None = None,
) -> dict[str, Any]:
    """Close the Phase 0 detections the IR workflow did not remediate. WRITE — gated.

    Use ONLY in IR Phase 4, AFTER extras_ir_close_remediated, and ONLY when
    the operator has said to close them (with the verdict they chose). Eyas's
    release safeguard refuses to lift containment or remove the host from
    quarantine while any Phase 0 detection is still open; this is the
    operator's way past that for detections the workflow never touched.

    Closes, server-side, every endpoint detection on the host that is still
    open AND was created before `before_iso` (the Phase 1 quarantine time).
    After the ledger close those are exactly the untouched originals.
    Anything that fired during the engagement is left alone; a detection
    with no readable creation time is never closed. Don't pass ids — the
    tool finds them itself.

    Args:
        device_id: Falcon AID of the host.
        before_iso: the Phase 1 quarantine call's ISO 8601 timestamp (the
            same value passed to extras_ir_phase3_verification_scope).
        verdict: `true_positive` or `false_positive`, as the operator chose.
        comment: optional audit string. Defaults to "closed at the operator's
            request after IR: open before the engagement and not remediated".

    Returns:
        ok, device_id, verdict, before_iso, scope_count, updated,
        composite_ids, left_open_after_cutoff, batch_errors?.
    """
    from ir.close_remediated import close_untouched_originals as _impl
    return _impl(device_id, before_iso, verdict, comment)


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


# ---------------------------------------------------------------------------
# Host groups (read-only v1)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Fusion Workflows (read-only v1)
# ---------------------------------------------------------------------------


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
# anchored against the image basename. CQL `=/regex/i` matches anywhere in
# the value unless anchored, so the explicit framing is what pins it to the
# basename.


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


if __name__ == "__main__":
    try:
        mcp.run()
    except Exception as exc:  # pragma: no cover - surface fatal init errors
        print(f"falcon-extras fatal: {exc}", file=sys.stderr)
        sys.exit(1)
