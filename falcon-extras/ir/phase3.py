"""IR Phase 3 verification-scope walker.

Server-side deterministic walk of every detection on a host with
``created_timestamp >= since_iso``. Classifies each into one of three
buckets via ``detection_classifiers``:

* ``retrospective_ioc_match`` — fresh envelope, old underlying events;
  Falcon's IOC engine surfacing history after a custom IOC was added.
  FP-close.
* ``workflow_self_triggered`` — RTR runscript preamble matched the
  PowerShell-encoded-command detector. FP-close.
* ``real`` — actual new activity during the workflow window. Drives
  RELEASE / HOLD.

Replaces agent-instructed sample-newest-N capture, which truncates on
hosts where cleanup primitives self-trigger 100+ PShellMimikatz events.

See ``server.py``'s ``extras_ir_phase3_verification_scope`` for the full
docstring + result-shape contract.
"""

from __future__ import annotations

from typing import Any

from falcon_helpers import _check_response, _get_alerts_client
from falcon_helpers import reject_unsafe_device_id, swallow_exc

from .detection_classifiers import (
    _detection_is_retrospective_ioc_match,
    _detection_is_workflow_self_triggered,
)


_PAGE = 200
_HARD_CAP = 5000

# Canonical open-status set (mirrors ir.campaign_scope / ir.phase0). A prior
# Phase-0 detection still carrying one of these has NOT been remediated/closed.
_OPEN_STATUSES = {"new", "reopened", "in_progress"}


def _classify_prior_open(
    recs: list[dict[str, Any]],
    open_statuses: set[str] | None = None,
) -> tuple[int, list[str]]:
    """Given hydrated alert records for the Phase-0 original composite_ids,
    return ``(checked, open_ids)`` — how many records were inspected and which
    still carry an open status. A record with a non-open status (closed,
    resolved) counts as checked-but-not-open; an id the store no longer returns
    at all never reaches here (absent = not an open detection on the host, the
    conservative read for a release gate). Pure: no network, fully testable.

    This is the teeth of the F2b release gate's prior-open re-check — keep it a
    plain function so a unit test can pin "open status ⇒ reported open, closed/
    purged ⇒ not open" without standing up a Falcon client."""
    checked = 0
    open_ids: list[str] = []
    statuses = open_statuses if open_statuses is not None else _OPEN_STATUSES
    for r in recs:
        if not isinstance(r, dict):
            continue
        checked += 1
        cid = r.get("composite_id") or r.get("id")
        status = (r.get("status") or "").lower()
        if cid and status in statuses:
            open_ids.append(cid)
    return checked, open_ids


def phase3_verification_scope(
    device_id: str,
    since_iso: str,
    prior_composite_ids: list[str] | None = None,
) -> dict[str, Any]:
    if not device_id or not isinstance(device_id, str):
        return {"ok": False, "error": "device_id required"}
    bad = reject_unsafe_device_id(device_id)
    if bad is not None:
        return bad
    if not since_iso or not isinstance(since_iso, str):
        return {"ok": False, "error": "since_iso required"}

    try:
        from datetime import datetime
        _since_dt = datetime.fromisoformat(since_iso.replace("Z", "+00:00"))
        since_ts_s = _since_dt.timestamp()
    except ValueError:
        return {"ok": False, "error": f"bad since_iso: {since_iso}"}

    try:
        client = _get_alerts_client()
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)

    real_ids: list[str] = []
    self_ids: list[str] = []
    retro_ids: list[str] = []
    items: list[dict[str, Any]] = []
    truncated = False
    offset = 0
    while offset < _HARD_CAP:
        # FQL `created_timestamp:>='<iso>'` — strict string comparison on
        # ISO-8601 timestamps works correctly because they sort
        # lexicographically.
        q = client.query_alerts_v2(
            filter=(
                f"product:'epp'+device.device_id:'{device_id}'"
                f"+created_timestamp:>='{since_iso}'"
            ),
            limit=_PAGE,
            offset=offset,
            sort="created_timestamp.asc",
        )
        guard = _check_response(q, "Alerts")
        if guard is not None:
            return guard
        ids = ((q or {}).get("body") or {}).get("resources") or []
        if not ids:
            break
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
                cid = r.get("composite_id") or r.get("id")
                if not cid:
                    continue
                retro, retro_reason = _detection_is_retrospective_ioc_match(
                    r, since_ts_s
                )
                self_triggered = (
                    False if retro else _detection_is_workflow_self_triggered(r)
                )
                if retro:
                    retro_ids.append(cid)
                    classification = "retrospective_ioc_match"
                elif self_triggered:
                    self_ids.append(cid)
                    classification = "workflow_self_triggered"
                else:
                    real_ids.append(cid)
                    classification = "real"
                items.append(
                    {
                        "composite_id": cid,
                        "created_timestamp": r.get("created_timestamp"),
                        "severity": r.get("severity"),
                        "severity_name": r.get("severity_name"),
                        "status": r.get("status"),
                        "display_name": r.get("display_name") or r.get("name"),
                        "tactic": r.get("tactic"),
                        "technique": r.get("technique"),
                        "classification": classification,
                        "workflow_self_triggered": self_triggered,
                        "retrospective_ioc_match": retro,
                        "retrospective_reason": retro_reason,
                    }
                )
        if len(ids) < _PAGE:
            break
        offset += _PAGE
    if offset >= _HARD_CAP:
        truncated = True

    # Optional release-gate re-check: confirm the EXACT detections captured at
    # Phase-0 kickoff (passed by the route's guard from ir_runs.campaign_scope_json)
    # are now closed. The time-windowed scan above only sees detections that
    # fired AFTER `since_iso`; the original campaign detections were created
    # BEFORE the window opens, so a release gate keying only off `real_count`
    # would wave through a release while an ORIGINAL detection sits unremediated.
    # Hydrate those ids directly (no time filter) and report which still carry an
    # open status. An id no longer returned by the store (purged/aged out) is
    # treated as not-open — it is no longer an open detection on the host.
    prior_open_ids: list[str] = []
    prior_checked = 0
    if prior_composite_ids:
        uniq_prior = [
            c for c in dict.fromkeys(prior_composite_ids) if isinstance(c, str) and c
        ]
        for chunk_start in range(0, len(uniq_prior), 100):
            chunk = uniq_prior[chunk_start : chunk_start + 100]
            d = client.get_alerts_v2(body={"composite_ids": chunk})
            d_guard = _check_response(d, "Alerts")
            if d_guard is not None:
                # Fail-closed: the caller (release gate) blocks on any error.
                return d_guard
            recs = ((d or {}).get("body") or {}).get("resources") or []
            chunk_checked, chunk_open = _classify_prior_open(recs)
            prior_checked += chunk_checked
            prior_open_ids.extend(chunk_open)

    return {
        "ok": True,
        "device_id": device_id,
        "since_iso": since_iso,
        "real_composite_ids": real_ids,
        "workflow_self_composite_ids": self_ids,
        "retrospective_composite_ids": retro_ids,
        "items": items,
        "real_count": len(real_ids),
        "workflow_self_count": len(self_ids),
        "retrospective_count": len(retro_ids),
        "total": len(real_ids) + len(self_ids) + len(retro_ids),
        "truncated": truncated,
        # Phase-0 originals still open (empty unless prior_composite_ids passed).
        "prior_open_composite_ids": prior_open_ids,
        "prior_open_count": len(prior_open_ids),
        "prior_checked_count": prior_checked,
        "note": (
            "Pass `workflow_self_composite_ids` AND `retrospective_composite_ids` "
            "to falcon_update_detections (status='closed', add_tags=['false_positive']) "
            "(both buckets are never real — workflow-self is RTR runscript "
            "preamble noise; retrospective is Falcon's IOC engine surfacing "
            "historical telemetry as fresh detections after a custom IOC was "
            "added during the IR). `real_composite_ids` are the genuine new "
            "detections during the workflow window — surface as `[REAL]` and "
            "use that count to drive RELEASE/HOLD."
        ),
    }
