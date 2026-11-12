"""falcon-extras: the Python add-on (sidecar) holding the Eyas tools that
have not yet moved into the console.

It plugs into the same agent loop as eyas-mcp, with no protocol-level
differences. It is being retired: Eyas's own tools move into lib/eyas-tools/
one family at a time, and generic Falcon operations belong in eyas-mcp.

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


# All cluster-specific imports (FalconPy clients etc.) live in the per-cluster
# impl modules now. Each @mcp.tool()
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
        "purpose": "Eyas's remaining add-on tools (exclusions, data-protection setup) while they move into the console itself.",
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


if __name__ == "__main__":
    try:
        mcp.run()
    except Exception as exc:  # pragma: no cover - surface fatal init errors
        print(f"falcon-extras fatal: {exc}", file=sys.stderr)
        sys.exit(1)
