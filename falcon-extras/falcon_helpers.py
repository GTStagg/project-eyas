"""Shared FalconPy plumbing — service-class builders + response guards +
cross-cutting constants used by every sidecar tool.

Lifted out of ``server.py`` so per-feature modules under ``ir/``,
``shadow_ai/``, etc. can build FalconPy clients and inspect responses
without circling back through the MCP server module. Anything that's
both (a) tool-feature-agnostic and (b) FalconPy-bound belongs here.
"""

from __future__ import annotations

import os
import re
import sys
import traceback
from typing import Any

from falconpy import (
    Alerts,
    DataProtectionConfiguration,
    Discover,
    HostGroup,
    Hosts,
    IOAExclusions,
    MLExclusions,
    NGSIEM,
    PreventionPolicy,
    Recon,
    Workflows,
)


# ---------------------------------------------------------------------------
# Auth — env-driven; the parent process (Next.js dev / standalone start.sh)
# overlays runtime config via spawn-env.ts before launching the sidecar.
# ---------------------------------------------------------------------------


def _falcon_kwargs() -> dict[str, Any]:
    """Shared FalconPy auth kwargs. Centralizes env validation so every
    service-class wrapper is a one-liner."""
    client_id = os.environ.get("FALCON_CLIENT_ID")
    client_secret = os.environ.get("FALCON_CLIENT_SECRET")
    base_url = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com")
    if not client_id or not client_secret:
        raise RuntimeError(
            "FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set in the "
            "environment of the falcon-extras process."
        )
    member_cid = os.environ.get("FALCON_MEMBER_CID")
    kwargs: dict[str, Any] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "base_url": base_url,
    }
    if member_cid:
        kwargs["member_cid"] = member_cid
    return kwargs


# ---------------------------------------------------------------------------
# Per-tenant host-group id resolution (override-aware).
#
# The sidecar receives the configured IR-quarantine / Shadow-AI-banned host
# group ids as SPAWN-TIME env vars (FALCON_QUARANTINE_GROUP_ID /
# FALCON_SHADOW_AI_BANNED_GROUP_ID). The parent runs ONE sidecar per chat turn
# (lib/chat/stream-agent.ts wraps the whole turn in a single
# withFalconExtrasClient), so os.environ is frozen for the process lifetime.
#
# When the agent CREATES or ADOPTS a group mid-turn, the Next.js side persists
# the new id to the DB — but this already-running sidecar keeps its stale
# (empty) env. A same-turn diagnose / provision / playbook call that resolved
# the id purely from os.environ would then wrongly report the group as
# unconfigured. That is the exact foot-gun that made adopt -> re-diagnose
# return no_group_id and sent operators to paste ids into /config by hand.
#
# Fix: create/adopt record the resolved id in a process-local override here;
# every env fallback resolves through resolve_group_id(), which prefers an
# explicit arg, then the same-process override, then the spawn-time env. The
# override lives only for this sidecar's lifetime — the next turn spawns a
# fresh process whose env already carries the now-persisted id.
# ---------------------------------------------------------------------------

GROUP_KIND_ENV_VARS: dict[str, str] = {
    "quarantine": "FALCON_QUARANTINE_GROUP_ID",
    "shadow_ai_banned": "FALCON_SHADOW_AI_BANNED_GROUP_ID",
}

_RUNTIME_GROUP_OVERRIDES: dict[str, str] = {}


def set_runtime_group_id(kind: str, group_id: str | None) -> None:
    """Record a host-group id created/adopted earlier in THIS sidecar process
    so sibling tools in the same turn resolve it without waiting for the next
    spawn. No-op on empty/blank ids. Raises on an unknown ``kind`` (programmer
    error, not runtime input)."""
    if kind not in GROUP_KIND_ENV_VARS:
        raise ValueError(f"unknown group kind {kind!r}")
    if isinstance(group_id, str) and group_id.strip():
        _RUNTIME_GROUP_OVERRIDES[kind] = group_id.strip()


def resolve_group_id(kind: str, explicit: str | None = None) -> str | None:
    """Resolve a per-tenant host-group id with precedence:
    explicit arg > same-process runtime override > spawn-time env var.
    Returns None when none is set."""
    if kind not in GROUP_KIND_ENV_VARS:
        raise ValueError(f"unknown group kind {kind!r}")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    override = _RUNTIME_GROUP_OVERRIDES.get(kind)
    if override:
        return override
    env = (os.environ.get(GROUP_KIND_ENV_VARS[kind]) or "").strip()
    return env or None


def _get_client() -> Hosts:
    return Hosts(**_falcon_kwargs())


def _get_host_group_client(timeout: int | None = None) -> HostGroup:
    # `timeout` bounds a single hung request (passed straight to requests).
    # host_group_membership_for_device fans out one probe per group across a
    # thread pool and needs a straggler bound so one stuck connection can't
    # hold a worker until the MCP transport kills the whole call. Default None
    # preserves the unbounded behavior every other caller relies on.
    if timeout is not None:
        return HostGroup(timeout=timeout, **_falcon_kwargs())
    return HostGroup(**_falcon_kwargs())


def _get_workflows_client() -> Workflows:
    # Tight HTTP timeout so a slow `WorkflowExecutionsCombined` upstream
    # surfaces as a structured exception inside our 60s MCP envelope rather
    # than getting killed by the MCP transport with an opaque "Request timed
    # out" error. 45s leaves headroom for response read + projection.
    return Workflows(timeout=45, **_falcon_kwargs())


def _get_alerts_client() -> Alerts:
    return Alerts(**_falcon_kwargs())


def _get_recon_client() -> Recon:
    return Recon(**_falcon_kwargs())


def _get_discover_client() -> Discover:
    return Discover(**_falcon_kwargs())


def _get_ml_exclusions_client() -> MLExclusions:
    return MLExclusions(**_falcon_kwargs())


def _get_ioa_exclusions_client() -> IOAExclusions:
    return IOAExclusions(**_falcon_kwargs())


def _get_prevention_client() -> PreventionPolicy:
    return PreventionPolicy(**_falcon_kwargs())


def _get_ngsiem_client() -> NGSIEM:
    return NGSIEM(**_falcon_kwargs())


def _get_data_protection_client() -> DataProtectionConfiguration:
    return DataProtectionConfiguration(**_falcon_kwargs())


# ---------------------------------------------------------------------------
# Response guards — staged-build pattern (see CLAUDE.md "Sidecar response
# handling"). Every wrapped FalconPy call MUST run results through
# _check_response before reading body.resources.
# ---------------------------------------------------------------------------


def swallow_exc(exc: BaseException) -> dict[str, Any]:
    """Standard catch-all return for sidecar tools. Logs the full traceback
    to stderr so the Next.js parent process (which inherits sidecar stderr)
    surfaces the failure in its log stream, then returns the clean
    MCP-friendly error dict the caller expects. Use anywhere a tool
    swallows ``Exception`` — without this, sidecar failures disappear
    silently and ops only sees the route's downstream error.
    """
    print(f"[sidecar:swallowed-exc] {type(exc).__name__}: {exc}", file=sys.stderr)
    traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)
    return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


_AID_RX = re.compile(r"\A[0-9a-fA-F]{32}\Z")


def reject_unsafe_device_id(device_id: Any) -> dict[str, Any] | None:
    """Guard a device_id before it is interpolated into a single-quoted FQL
    literal (``device.device_id:'<id>'``). A Falcon Agent ID is always 32 hex
    characters; anything else — in particular a value containing ``'`` or ``\\``
    — is a typo or an FQL-injection attempt. Reject-don't-escape, same posture
    as eyas-mcp's identity tools (strict user-name charset, AID as 32 hex). The IR
    scope walkers are reachable by the agent (``extras_ir_phase3_verification_scope``
    is not in the route's IR tool filter), so this is the sidecar-side
    defense-in-depth behind the route's IR_PRIMER_RX hex capture.

    Returns an error dict for the caller to return verbatim, or None when safe.
    """
    if not isinstance(device_id, str) or not _AID_RX.match(device_id):
        return {"ok": False, "error": "device_id must be a 32-character hex Agent ID"}
    return None


def _scope_denied_payload(exc_or_status: Any, surface: str) -> dict[str, Any]:
    """Friendly empty-state for surfaces whose Falcon API scope hasn't been
    granted yet on this tenant. Identity Protection in particular: customer
    may not have the module licensed at all, so a 403 is expected and the
    agent must say so cleanly rather than report an error."""
    return {
        "ok": True,
        "scope_pending": True,
        "surface": surface,
        "items": [],
        "count": 0,
        "note": (
            f"This call returned a permission error. The {surface} surface "
            "renders empty until the Falcon API client is granted the "
            "required scope. Tell the operator: 'No data — required Falcon "
            f"API scope for {surface} is not yet granted on this tenant.'"
        ),
        "_diagnostic": str(exc_or_status)[:200],
    }


def _is_permission_error(resp: dict[str, Any]) -> bool:
    """Recognize the FalconPy shape for 401/403 — different surfaces phrase
    these differently (`access denied, scope not permitted`, `unauthorized`).
    All map to: the API key lacks the required scope for this endpoint."""
    if not isinstance(resp, dict):
        return False
    status = resp.get("status_code")
    if status in (401, 403):
        return True
    body = resp.get("body") or {}
    errors = body.get("errors") or []
    for e in errors:
        msg = (e.get("message") or "").lower()
        if "scope not permitted" in msg or "access denied" in msg or "unauthorized" in msg:
            return True
    return False


def _upstream_error(resp: dict[str, Any]) -> str | None:
    """Surface non-2xx upstream errors that aren't permission-related. Catches
    the silent-mask bug where a 400 'sort is not an allowable value' was
    previously masked by `body.get('resources') or []` returning ``[]``."""
    if not isinstance(resp, dict):
        return "non-dict response from FalconPy"
    status = resp.get("status_code")
    body = resp.get("body") or {}
    errors = body.get("errors") or []
    if status is not None and not (200 <= int(status) < 300):
        if errors:
            msg = errors[0].get("message") or "upstream error"
            return f"upstream HTTP {status} — {msg}"
        return f"upstream HTTP {status}"
    if errors:
        msg = errors[0].get("message") or "upstream error"
        return f"upstream error — {msg}"
    return None


def _check_response(
    resp: dict[str, Any], surface: str
) -> dict[str, Any] | None:
    """Composed guard: permission-pending check + upstream-error check.
    Returns None when the response is healthy and the caller should proceed
    to read body.resources. Otherwise returns the appropriate {ok: ...}
    payload the caller should return immediately."""
    if _is_permission_error(resp):
        return _scope_denied_payload(resp, surface)
    err = _upstream_error(resp)
    if err:
        return {"ok": False, "error": err, "surface": surface}
    return None


# ---------------------------------------------------------------------------
# Cross-cutting constants
# ---------------------------------------------------------------------------


# v3 Alerts API status values for `update_status`. Note: TP/FP is NOT in here
# — that's a tag, not a status (see CLAUDE.md "v3 Alerts API: status is
# lifecycle-only; TP/FP is a tag").
_VALID_DETECTION_STATUSES = {"new", "in_progress", "reopened", "closed"}

_VALID_DETECTION_VERDICTS = {"true_positive", "false_positive"}

# The tag value written for each TP/FP verdict. These MUST match what the
# Falcon console writes when an operator sets a verdict on a v3 alert — which
# is the literal string (`true_positive` / `false_positive`), NOT the legacy
# `FalconUITagged*` prefix. The prefix was a legacy `/detects` (v1/v2)
# convention for UI-applied tags; the v3 unified-detections experience dropped
# it. Confirmed empirically (2026-06-22): in our us-2 tenant 396 console-tagged
# alerts carry zero `FalconUITagged*` and the verdict tag present is literal
# (`ignored`), and falcon-mcp 0.12.0's native `falcon_update_detections` passes
# the verdict straight through as `add_tag: <verdict>`. Writing the literal
# keeps our verdicts identical to console-applied ones.
_VERDICT_TAG = {
    "true_positive": "true_positive",
    "false_positive": "false_positive",
}


# ---------------------------------------------------------------------------
# Recon FQL input validation — strict allowlists. Recon's filter language
# uses single-quoted literals, so a value with an embedded apostrophe would
# either error or change query semantics.
# ---------------------------------------------------------------------------


_RECON_DOMAIN_RX = re.compile(r"^[a-z0-9][a-z0-9.\-]{0,253}$")
_RECON_EMAIL_RX = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+$")
_RECON_FREETEXT_RX = re.compile(r"^[A-Za-z0-9 ._%+@:/\-]{1,200}$")


def _project_exposed_record(rec: dict[str, Any]) -> dict[str, Any]:
    """Strip heavy fields and produce a flat row the agent can table directly.
    The full `rec` payload is large (full file metadata, location, financial
    fields). We keep just what a credential-exposure decision document needs.

    Field names confirmed against a live us-2 dump (2026-06-29): the identity
    field is `full_name` (NOT user_name, which the API does not return); `rule`
    and `file` are nested objects. The raw leaked-credential file payload is
    deliberately omitted — only file.name + exposure metadata surface.
    """
    rule_block = rec.get("rule") or {}
    file_block = rec.get("file") or {}
    return {
        "id": rec.get("id"),
        "email": rec.get("email"),
        "domain": rec.get("domain"),
        "credentials_domain": rec.get("credentials_domain"),
        "credential_status": rec.get("credential_status"),
        "full_name": rec.get("full_name"),
        "source_category": rec.get("source_category"),
        "site": rec.get("site"),
        "exposure_date": rec.get("exposure_date"),
        "event_date": rec.get("event_date"),
        "created_date": rec.get("created_date"),
        "notification_id": rec.get("notification_id"),
        "rule_id": rule_block.get("id"),
        "rule_topic": rule_block.get("topic"),
        "file_name": file_block.get("name"),
    }


def _project_notification(rec: dict[str, Any]) -> dict[str, Any]:
    """Flatten a Recon notification into a compact row.

    GetNotificationsDetailedV1 returns each record as
    {id, notification: {...}, breach_details}, so the useful fields are nested
    under `notification` (rule_* are flat INSIDE that object; there is no
    top-level `content` — the substance of a breach hit is `breach_summary`).
    Confirmed against a live us-2 dump (2026-06-29). Falls back to the top level
    so a future flattened passthrough still projects. The bulky logs[] /
    risk_score_matching_criteria[] / breach_details are dropped.
    """
    note = rec.get("notification")
    if not isinstance(note, dict):
        note = rec
    return {
        "id": rec.get("id") or note.get("id"),
        "status": note.get("status"),
        "created_date": note.get("created_date"),
        "updated_date": note.get("updated_date"),
        "rule_id": note.get("rule_id"),
        "rule_name": note.get("rule_name"),
        "rule_topic": note.get("rule_topic"),
        "rule_priority": note.get("rule_priority"),
        "item_type": note.get("item_type"),
        "item_date": note.get("item_date"),
        "item_site": note.get("item_site"),
        "item_author": note.get("item_author"),
        "source_category": note.get("source_category"),
        "actor_slug": note.get("actor_slug"),
        "risk_score_label": note.get("risk_score_label"),
        "breach_summary": note.get("breach_summary"),
    }
