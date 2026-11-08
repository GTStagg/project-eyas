"""Auto-extracted tool implementations.

See ``server.py`` ``@mcp.tool()`` wrappers for the public docstrings;
these are the worker functions they delegate to.
"""

from __future__ import annotations

from typing import Any
from falcon_helpers import _check_response, _get_ngsiem_client
from falcon_helpers import swallow_exc

def _project_data_connection(c: dict[str, Any]) -> dict[str, Any]:
    # Real API shape (verified 2026-05-05): id, name, vendor_name,
    # vendor_product_name, parser_name, status (Active/Idle/Pending),
    # source_type, last_ingested_volume_one_day, ingest_url. There is no
    # `enabled` / `last_event_at` / `created_at` / `updated_at` field —
    # status drives health and last_ingested_volume_one_day is the staleness
    # signal ("0 B" means nothing arrived in the last 24h).
    return {
        "id": c.get("id"),
        "name": c.get("name"),
        "vendor": c.get("vendor_name"),
        "product": c.get("vendor_product_name"),
        "parser_name": c.get("parser_name"),
        "source_type": c.get("source_type"),
        "status": c.get("status"),
        "last_ingested_volume_one_day": c.get("last_ingested_volume_one_day"),
    }


def _project_parser(p: Any) -> dict[str, Any]:
    # Parsers may come back as bare strings (id/name) or dicts depending on
    # the upstream API surface. Normalize to a name-keyed dict either way.
    if isinstance(p, str):
        return {"name": p}
    if isinstance(p, dict):
        return {
            "name": p.get("name") or p.get("id"),
            "id": p.get("id"),
            "type": p.get("parser_type") or p.get("type"),
            "repository": p.get("repository"),
            "update_available": p.get("update_available"),
        }
    return {"name": str(p)}


def _project_lookup_file(f: Any) -> dict[str, Any]:
    # Real API shape (verified 2026-05-05): resources is a flat list of
    # filename strings, not dicts. Older falcon-extras versions assumed
    # dicts and silently dropped every row.
    if isinstance(f, str):
        return {"name": f}
    if isinstance(f, dict):
        return {"name": f.get("name") or f.get("id"), **f}
    return {"name": str(f)}


def ngsiem_provisioning_status(cids: list[str]) -> dict[str, Any]:
    """Get NGSIEM provisioning status for one or more CIDs. Read-only.

    The endpoint is MSSP-shaped: it returns provisioning health for a list
    of customer IDs you supply. NOT a tenant-wide health check — for that,
    look at falcon_list_ngsiem_data_connections + falcon_list_ngsiem_lookup_files
    + falcon_list_ngsiem_parsers, which collectively prove the API and ingest
    paths work.

    Args:
        cids: One or more Falcon customer IDs (UUIDs). 1-100 entries.
    """
    try:
        if not cids or not isinstance(cids, list):
            return {"ok": False, "error": "cids must be a non-empty list"}
        if len(cids) > 100:
            return {"ok": False, "error": "max 100 cids per call"}
        client = _get_ngsiem_client()
        r = client.get_provisioning_status(parameters={"ids": cids})
        guard = _check_response(r, "NGSIEM")
        if guard:
            return guard
        b = r.get("body", {}) if isinstance(r, dict) else {}
        return {
            "ok": True,
            "resources": b.get("resources"),
            "meta": b.get("meta"),
        }
    except Exception as exc:
        return swallow_exc(exc)


_VALID_NGSIEM_REPOSITORIES = {
    "search-all",
    "investigate_view",
    "third-party",
    "falcon_for_it_view",
    "forensics_view",
}

