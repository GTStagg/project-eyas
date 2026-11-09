"""Auto-extracted tool implementations.

See ``server.py`` ``@mcp.tool()`` wrappers for the public docstrings;
these are the worker functions they delegate to.
"""

from __future__ import annotations

from typing import Any
from falcon_helpers import (
    _check_response,
    _get_alerts_client,
    _get_client,
    _is_permission_error,
    _scope_denied_payload,
    _upstream_error,
    _VALID_DETECTION_STATUSES,
    _VALID_DETECTION_VERDICTS,
    _VERDICT_TAG,
    reject_unsafe_device_id,
)
from falcon_helpers import swallow_exc

def update_detection_status(
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
    if not composite_ids:
        return {"ok": False, "error": "composite_ids must not be empty"}
    if verdict is not None and verdict not in _VALID_DETECTION_VERDICTS:
        return {
            "ok": False,
            "error": (
                f"invalid verdict '{verdict}', must be one of "
                f"{sorted(_VALID_DETECTION_VERDICTS)}"
            ),
        }
    if status is None:
        status = "closed" if verdict else None
    if status is None:
        return {
            "ok": False,
            "error": "either status or verdict must be supplied",
        }
    if status not in _VALID_DETECTION_STATUSES:
        return {
            "ok": False,
            "error": (
                f"invalid status '{status}', must be one of "
                f"{sorted(_VALID_DETECTION_STATUSES)}. "
                f"For TP/FP verdicts, pass verdict='true_positive' or "
                f"'false_positive' instead — the v3 Alerts API records "
                f"verdict via tag, not status."
            ),
        }
    actions: list[dict[str, str]] = [
        {"name": "update_status", "value": status},
    ]
    if verdict:
        actions.append({"name": "add_tag", "value": _VERDICT_TAG[verdict]})
    if comment:
        actions.append({"name": "append_comment", "value": comment})
    # Chunk server-side. The v3 update_alerts_v3 endpoint caps per-call at
    # ~1000 composite_ids; passing more silently truncates and the call
    # reports success on only the first batch. IR Phase 4 routinely passes
    # 150-500 ids on a noisy host, well within one batch — but the same
    # tool gets called with larger arrays from /api/queue bulk-close paths,
    # and a single server cap shouldn't be the agent's problem to discover.
    # Chunk at 500 (well below the cap) so a hiccup mid-list doesn't lose
    # both halves.
    BATCH_SIZE = 500
    try:
        client = _get_alerts_client()
        all_ids = list(composite_ids)
        updated = 0
        batch_errors: list[dict[str, Any]] = []
        for batch_start in range(0, len(all_ids), BATCH_SIZE):
            chunk = all_ids[batch_start : batch_start + BATCH_SIZE]
            body = {
                "composite_ids": chunk,
                "action_parameters": actions,
            }
            r = client.update_alerts_v3(body=body)
            if _is_permission_error(r):
                # First-batch scope denial bubbles immediately — no point
                # paying for further attempts. If a later batch hits this,
                # surface as a partial success with the scope error attached.
                if updated == 0:
                    return _scope_denied_payload(r, "Alerts")
                batch_errors.append(
                    {"batch_start": batch_start, "error": "scope_pending"}
                )
                break
            err = _upstream_error(r)
            if err:
                batch_errors.append({"batch_start": batch_start, "error": err})
                continue
            updated += len(chunk)
        result: dict[str, Any] = {
            "ok": updated > 0 or not all_ids,
            "updated": updated,
            "requested": len(all_ids),
            "status": status,
            "batches": (len(all_ids) + BATCH_SIZE - 1) // BATCH_SIZE,
        }
        if verdict:
            result["verdict"] = verdict
        if batch_errors:
            result["batch_errors"] = batch_errors
            if updated == 0:
                result["ok"] = False
                result["error"] = (
                    f"all batches failed; first error: {batch_errors[0]['error']}"
                )
        return result
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def close_all_open_detections_on_host(
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
    if not device_id or not isinstance(device_id, str):
        return {"ok": False, "error": "device_id required"}
    # device_id scopes the bulk-close FQL filter below
    # (device.device_id:'<id>'); a value carrying ' or \ is a typo or an
    # injection that would widen the close beyond the intended host.
    # Reject-don't-escape, same posture as the IR scope walkers.
    bad = reject_unsafe_device_id(device_id)
    if bad is not None:
        return bad
    if verdict not in _VALID_DETECTION_VERDICTS:
        return {
            "ok": False,
            "error": (
                f"verdict must be one of {sorted(_VALID_DETECTION_VERDICTS)}; "
                f"got '{verdict}'"
            ),
        }
    if comment is None:
        comment = (
            f"Bulk-closed via Project Eyas extras_close_all_open_detections_on_host "
            f"on host {device_id}"
        )

    # Closed by Eyas through eyas-mcp's falcon_close_host_detections
    # (lib/mcp/native-dispatch.ts): it finds every open detection on the host
    # (status new / in_progress / reopened, any product), closes them in
    # batches with the verdict tag and comment, and reports the ids. The
    # sidecar only validates and supplies Eyas's default audit comment.
    return {
        "ok": True,
        "dispatch": {
            "kind": "close_host_detections",
            "device_id": device_id.lower(),
            "resolution": verdict,
            "comment": comment,
        },
    }

def host_list_contained(limit: int = 100) -> dict[str, Any]:
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
    try:
        client = _get_client()
        capped = min(max(limit, 1), 5000)
        # The Hosts query filter accepts 'status' for containment state.
        # Includes pending transitions so the operator sees in-flight changes.
        flt = "status:'contained',status:'containment_pending',status:'lift_containment_pending'"
        r = client.query_devices_by_filter(
            filter=flt, limit=capped, sort="last_seen.desc"
        )
        if _is_permission_error(r):
            return _scope_denied_payload(r, "Hosts")
        err = _upstream_error(r)
        if err:
            return {"ok": False, "error": err}
        body = r.get("body", {}) if isinstance(r, dict) else {}
        ids = body.get("resources") or []
        meta = body.get("meta") or {}
        total = (meta.get("pagination") or {}).get("total")
        if not ids:
            return {"ok": True, "items": [], "count": 0, "total": total or 0}
        d = client.get_device_details_v2(ids=ids)
        derr = _upstream_error(d)
        if derr:
            return {"ok": False, "error": derr}
        details = (d.get("body", {}) if isinstance(d, dict) else {}).get(
            "resources"
        ) or []
        items = [
            {
                "device_id": h.get("device_id"),
                "hostname": h.get("hostname"),
                "platform_name": h.get("platform_name"),
                "os_product_name": h.get("os_product_name"),
                "os_version": h.get("os_version"),
                "last_seen": h.get("last_seen"),
                "status": h.get("status"),
                "rtr_state": h.get("rtr_state"),
            }
            for h in details
        ]
        return {
            "ok": True,
            "items": items,
            "count": len(items),
            "total": total if total is not None else len(items),
        }
    except Exception as exc:
        return swallow_exc(exc)

