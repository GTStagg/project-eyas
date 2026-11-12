"""IR Phase 0 detection-scope walker.

Server-side deterministic enumeration of every open detection on a host.
Replaces agent-instructed pagination via ``falcon_search_detections`` —
agents routinely truncate large captures and Phase 4 closes only the
captured slice. This walker paginates the v3 Alerts API server-side until
exhausted (or a ``HARD_CAP`` of 5000), filters to open statuses, and
returns the authoritative ``composite_ids`` array for Phase 4.

See ``server.py``'s ``extras_ir_phase0_detection_scope`` for the full
docstring + result-shape contract.
"""

from __future__ import annotations

from typing import Any

from falcon_helpers import _check_response, _get_alerts_client
from falcon_helpers import reject_unsafe_device_id, swallow_exc


_PAGE = 200
_HARD_CAP = 5000  # 25 pages — extreme noise floor; surfaces as truncated.
_OPEN_STATUSES = {"new", "reopened", "in_progress"}


def phase0_detection_scope(device_id: str) -> dict[str, Any]:
    if not device_id or not isinstance(device_id, str):
        return {"ok": False, "error": "device_id required"}
    bad = reject_unsafe_device_id(device_id)
    if bad is not None:
        return bad

    try:
        client = _get_alerts_client()
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)

    composite_ids: list[str] = []
    items: list[dict[str, Any]] = []
    truncated = False
    offset = 0
    while offset < _HARD_CAP:
        q = client.query_alerts_v2(
            filter=f"product:'epp'+device.device_id:'{device_id}'",
            limit=_PAGE,
            offset=offset,
            sort="created_timestamp.desc",
        )
        guard = _check_response(q, "Alerts")
        if guard is not None:
            return guard
        ids = ((q or {}).get("body") or {}).get("resources") or []
        if not ids:
            break
        # Hydrate so we can filter by status server-side. v3 get_alerts_v2
        # caps at 100 ids per call.
        for chunk_start in range(0, len(ids), 100):
            chunk = ids[chunk_start : chunk_start + 100]
            d = client.get_alerts_v2(body={"composite_ids": chunk})
            d_guard = _check_response(d, "Alerts")
            if d_guard is not None:
                return d_guard
            recs = ((d or {}).get("body") or {}).get("resources") or []
            for r in recs:
                if not isinstance(r, dict):
                    continue
                status = (r.get("status") or "").lower()
                if status not in _OPEN_STATUSES:
                    continue
                cid = r.get("composite_id") or r.get("id")
                if not cid:
                    continue
                composite_ids.append(cid)
                items.append(_project_phase0_item(r, status))
        if len(ids) < _PAGE:
            break
        offset += _PAGE
    if offset >= _HARD_CAP:
        truncated = True

    timestamps = [
        i["created_timestamp"]
        for i in items
        if isinstance(i.get("created_timestamp"), str)
    ]
    timestamps.sort()
    pivot_pids = sorted(
        {i["pivot_pid"] for i in items if i.get("pivot_pid")}
    )

    return {
        "ok": True,
        "device_id": device_id,
        "items": items,
        "composite_ids": composite_ids,
        "pivot_pids": pivot_pids,
        "count": len(composite_ids),
        "truncated": truncated,
        "oldest_open_iso": timestamps[0] if timestamps else None,
        "newest_open_iso": timestamps[-1] if timestamps else None,
        "note": (
            "These are the IR scope detections — pass `composite_ids` "
            "verbatim to Phase 4's falcon_update_detections close call (as `ids`)."
            + (
                " HARD_CAP hit — tenant has 5000+ open detections on this "
                "host; bulk-close out-of-band before running IR."
                if truncated
                else ""
            )
        ),
    }


def _project_phase0_item(r: dict[str, Any], status: str) -> dict[str, Any]:
    """Thin item shape — enough for the playbook to build delivery-vector
    / persistence enrichment loops without re-fetching the full record."""
    pivot = None
    pid_field = r.get("process_id")
    if pid_field is not None:
        pivot = str(pid_field)
    else:
        for b in r.get("behaviors") or []:
            if isinstance(b, dict):
                for k in ("process_id", "target_process_id"):
                    v = b.get(k)
                    if v:
                        pivot = str(v)
                        break
            if pivot:
                break
    return {
        "composite_id": r.get("composite_id") or r.get("id"),
        "created_timestamp": r.get("created_timestamp"),
        "severity": r.get("severity"),
        "severity_name": r.get("severity_name"),
        "status": status,
        "display_name": r.get("display_name") or r.get("name"),
        "tactic": r.get("tactic"),
        "technique": r.get("technique"),
        "pivot_pid": pivot,
        "has_adversary": bool(r.get("has_adversary")),
        "adversary_ids": [
            str(a)
            for a in (r.get("adversary_ids") or [])
            if a is not None
        ],
    }
