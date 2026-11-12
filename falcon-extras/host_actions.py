"""Auto-extracted tool implementations.

See ``server.py`` ``@mcp.tool()`` wrappers for the public docstrings;
these are the worker functions they delegate to.
"""

from __future__ import annotations

from typing import Any
from falcon_helpers import (
    _VALID_DETECTION_VERDICTS,
    reject_unsafe_device_id,
)

def close_all_open_detections_on_host(
    device_id: str,
    verdict: str,
    comment: str | None = None,
    include_multi_host: bool = False,
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
            "include_multi_host": include_multi_host is True,
        },
    }
