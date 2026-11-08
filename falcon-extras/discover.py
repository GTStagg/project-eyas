"""Falcon Discover asset / application / account inventory.

Backs the /discover surface. falcon-mcp 0.11.0 only ships
`falcon_search_applications` + `falcon_search_unmanaged_assets`; the Accounts
entity, managed-asset inventory, and login history are FalconPy-only, so they
live here. All read-only.

Two-step FQL pattern (same as recon.py): query_* returns ids, get_* hydrates.
Every wrapped call runs through `_check_response` so a 403 surfaces as the
staged-build `scope_pending` payload and a non-permission 4xx/5xx surfaces as
`{ok: false, error}` instead of silently collapsing to count: 0.
"""

from __future__ import annotations

import re
from typing import Any

from falcon_helpers import (
    _check_response,
    _get_discover_client,
    swallow_exc,
)

# Per-entity projection whitelists — keep the surface token-bounded on the chat
# path and predictable on the page. Defensive: missing keys are simply absent.
_ASSET_KEEP = (
    "id", "cid", "hostname", "entity_type", "platform_name", "os_version",
    "product_type_desc", "machine_domain", "ou", "current_local_ip",
    "external_ip", "first_seen_timestamp", "last_seen_timestamp",
    "system_manufacturer", "system_product_name", "kernel_version",
    "agent_version", "confidence", "country", "city", "tags",
    "discoverer_count", "discoverer_platform_names", "aid",
)
_APP_KEEP = (
    "id", "cid", "name", "vendor", "version", "name_vendor", "name_vendor_version",
    "software_type", "is_suspicious", "is_normalized", "installation_paths",
    "first_seen_timestamp", "last_used_timestamp", "last_updated_timestamp",
    "host",
)
_ACCOUNT_KEEP = (
    "id", "cid", "account_name", "username", "domain", "login_domain",
    "account_type", "admin_privileges", "user_sid",
    "password_last_set_timestamp", "last_successful_login_timestamp",
    "last_successful_login_type", "last_successful_login_hostname",
    "host",
)


def _compact(resource: dict[str, Any], keep: tuple[str, ...]) -> dict[str, Any]:
    """Pick whitelisted keys; collapse a nested `host` object to aid+hostname."""
    if not isinstance(resource, dict):
        return {}
    out: dict[str, Any] = {}
    for k in keep:
        if k not in resource:
            continue
        v = resource[k]
        if k == "host" and isinstance(v, dict):
            out["host_aid"] = v.get("aid")
            out["host_hostname"] = v.get("hostname")
            continue
        out[k] = v
    return out


def _query_hydrate(
    query_attr: str,
    get_attr: str,
    surface: str,
    keep: tuple[str, ...],
    *,
    filter_: str | None,
    limit: int,
    sort: str | None,
) -> dict[str, Any]:
    """Shared query -> hydrate -> project pipeline for a Discover entity."""
    try:
        client = _get_discover_client()
        capped = min(max(int(limit), 1), 100)  # Discover query max is 100
        params: dict[str, Any] = {"limit": capped}
        if filter_:
            params["filter"] = filter_
        if sort:
            params["sort"] = sort
        q = getattr(client, query_attr)(parameters=params)
        guard = _check_response(q, surface)
        if guard:
            return guard
        ids = (q.get("body", {}) if isinstance(q, dict) else {}).get("resources") or []
        total = (
            (q.get("body", {}) if isinstance(q, dict) else {})
            .get("meta", {})
            .get("pagination", {})
            .get("total")
        )
        if not ids:
            return {"ok": True, "items": [], "count": 0, "total": total or 0}
        d = getattr(client, get_attr)(ids=ids)
        dguard = _check_response(d, surface)
        if dguard:
            return dguard
        raw = (d.get("body", {}) if isinstance(d, dict) else {}).get("resources") or []
        items = [_compact(r, keep) for r in raw]
        return {
            "ok": True,
            "items": items,
            "count": len(items),
            "total": total if total is not None else len(items),
        }
    except Exception as exc:
        return swallow_exc(exc)


def discover_assets(
    filter: str | None = None,
    limit: int = 100,
    scope: str = "all",
) -> dict[str, Any]:
    """List endpoint assets from Falcon Discover (managed + unmanaged). Read-only.

    Args:
        filter: Optional FQL filter (e.g. ``platform_name:'Windows'``,
            ``last_seen_timestamp:>'now-30d'``). Combined with the scope filter.
        limit: Max assets (1-100). Default 100.
        scope: ``managed`` (Falcon-sensor hosts), ``unmanaged`` (discovered but
            no sensor), or ``all`` (default).
    """
    scope = (scope or "all").lower()
    clauses = []
    if scope in ("managed", "unmanaged"):
        clauses.append(f"entity_type:'{scope}'")
    if filter:
        clauses.append(f"({filter})")
    combined = "+".join(clauses) if clauses else None
    return _query_hydrate(
        "query_hosts", "get_hosts", "Discover (assets)", _ASSET_KEEP,
        filter_=combined, limit=limit, sort="last_seen_timestamp|desc",
    )


def discover_applications(
    filter: str | None = None, limit: int = 100, host_aid: str | None = None
) -> dict[str, Any]:
    """List installed applications inventoried by Falcon Discover. Read-only.

    NOTE: This is Falcon's periodically-synced inventory, not a live host query,
    so it can lag or under-report what is *currently* on a host. For an
    authoritative "what is installed right now" answer on a live Windows host,
    prefer the RTR InstalledProgram script (falcon_run_falcon_script).

    Args:
        host_aid: Optional device AID (32-char hex) to scope results to a single
            host — the common "apps installed on host X" query. Resolves to the
            FQL clause ``host.aid:'<aid>'`` server-side; combined (AND) with
            ``filter`` if both are given. Get the AID from falcon_search_hosts.
        filter: Optional FQL filter. Supported patterns:
            - Exact name: ``name:'Google Chrome'``
            - Wildcard/contains: ``name:'*chrome*'``  (asterisk in value, NOT ``name:~``)
            - Suspicious only: ``is_suspicious:true``
            - By vendor: ``vendor.name:'Oracle'``
            - By type: ``software_type:'browser_extension'``
            - By host: ``host.aid:'<aid>'`` or ``host.hostname:'HOST-NAME'``
              (the record nests host data under ``host.*``; ``host_info.*`` and
              bare ``aid`` are rejected by the API). Prefer the ``host_aid`` arg.
            Multiple clauses joined with ``+`` (AND) or ``,`` (OR).
        limit: Max applications (1-100). Default 100.
    """
    clauses: list[str] = []
    if host_aid:
        aid = host_aid.strip()
        # Reject-don't-escape: AID is a well-defined 32-char hex string and is
        # interpolated into a single-quoted FQL literal. Anything else is a bug
        # or an injection attempt — fail loud rather than round-trip to Falcon.
        if not re.fullmatch(r"[0-9a-fA-F]{32}", aid):
            return {
                "ok": False,
                "error": "invalid_host_aid",
                "detail": (
                    "host_aid must be a 32-character hex device AID "
                    "(get it from falcon_search_hosts)."
                ),
            }
        clauses.append(f"host.aid:'{aid}'")
    if filter:
        clauses.append(f"({filter})")
    combined = "+".join(clauses) if clauses else None
    return _query_hydrate(
        "query_applications", "get_applications", "Discover (applications)",
        _APP_KEEP, filter_=combined, limit=limit, sort="last_used_timestamp|desc",
    )

