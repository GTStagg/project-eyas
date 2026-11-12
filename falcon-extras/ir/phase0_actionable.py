"""IR Phase 0 actionable-detection partition (workflow-entry triage).

Before the IR workflow commits to quarantining the host + running through
five phases of cleanup, classify every open detection on the host:

* ``workflow_self_triggered`` — fired on the RTR runscript preamble
  (a previous IR run's cleanup self-trigger). FP-close, no remediation.
* ``shadow_ai_ioc_audit`` — fired on a Shadow-AI Ban+Clean detect-only
  domain IOC (audit trail of continued AI use, not malware). Close as
  expected continued use.
* ``retrospective_ioc_match`` — fresh detection envelope, underlying
  events predate the workflow window. FP-close.
* ``actionable`` — anything else. THESE drive Phase 1+ quarantine.

If ``actionable`` is empty, the workflow has nothing real to do — the
trigger detections were all noise (workflow self-trigger artifacts +
Shadow-AI audit IOC fires + retrospective backfill). Caller short-circuits
to a single bulk-close call and skips Phases 1-4 entirely. The host is
NEVER quarantined for a clean-room set of detections.

The classifier is intentionally conservative: anything we can't
confidently bucket as noise stays ``actionable`` and the workflow proceeds
normally. False negatives (mis-classify noise as actionable) waste a
quarantine cycle but never miss real malware; false positives
(mis-classify malware as noise) skip needed cleanup, which is the
unacceptable error class.

Used in two paths:

* ``app/api/chat/route.ts`` pre-fetches this server-side alongside
  ``extras_ir_workflow_playbook`` + ``extras_ir_campaign_scope`` on IR
  primer arrival, so the agent sees the partition result before its first
  turn. The playbook tells the agent how to react.
* ``extras_ir_phase0_actionable_check`` exposes it as an MCP tool for
  direct agent invocation if needed (e.g., a mid-engagement re-check
  after the operator declines to proceed).
"""

from __future__ import annotations

from typing import Any

from falcon_helpers import _check_response, _get_alerts_client
from falcon_helpers import reject_unsafe_device_id, swallow_exc

from .detection_classifiers import (
    _detection_is_retrospective_backfill,
    _detection_is_shadow_ai_ioc_audit,
    _detection_is_workflow_self_triggered,
)


_PAGE = 200
_HARD_CAP = 5000
_OPEN_STATUSES = {"new", "reopened", "in_progress"}


def phase0_actionable_partition(device_id: str) -> dict[str, Any]:
    """Enumerate open detections on ``device_id`` and partition them by
    actionability. See module docstring for the semantics.

    Retrospective classification at workflow entry uses the GAP between each
    detection's fresh ``created_timestamp`` and its old underlying events
    (``_detection_is_retrospective_backfill``) — NOT a "older than now"
    cutoff. Every real detection's underlying events are older than now, so a
    now-cutoff would mis-bucket recent real malware as retrospective and
    FP-close it. Only a wide created-vs-event gap signals Falcon IOC backfill.

    Returns:
        {
            "ok": bool,
            "device_id": str,
            "total_open": int,
            "actionable": [{composite_id, display_name, severity, created_timestamp}, ...],
            "workflow_self_triggered": [...same shape...],
            "shadow_ai_ioc_audit": [{...shape..., "matched_domain": "claude.ai"}],
            "retrospective_ioc_match": [{...shape..., "reason": "..."}],
            "should_proceed_with_ir": bool,   # True iff actionable[] is non-empty
            "bulk_close_calls": [             # When should_proceed_with_ir=False,
                                              # ready-to-fire close-call descriptors
                                              # the agent surfaces verbatim.
                {   # falcon_update_detections arguments, plus `kind`
                    "ids": [...],
                    "status": "closed",
                    "add_tags": ["false_positive"],   # omitted for shadow_ai_audit
                    "append_comment": "...",
                    "kind": "workflow_self" | "shadow_ai_audit" | "retrospective",
                },
                ...
            ],
        }
    """
    if not device_id or not isinstance(device_id, str):
        return {"ok": False, "error": "device_id required"}
    bad = reject_unsafe_device_id(device_id)
    if bad is not None:
        return bad

    try:
        client = _get_alerts_client()
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)

    actionable: list[dict[str, Any]] = []
    workflow_self: list[dict[str, Any]] = []
    shadow_ai_audit: list[dict[str, Any]] = []
    retrospective: list[dict[str, Any]] = []

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
                base = {
                    "composite_id": cid,
                    "display_name": r.get("display_name") or r.get("name"),
                    "severity": r.get("severity"),
                    "severity_name": r.get("severity_name"),
                    "created_timestamp": r.get("created_timestamp"),
                }

                # Classification order matters — most specific first.
                # Retrospective wins over self-triggered because a
                # self-triggered preamble fire that was *also* a
                # retrospective backfill should be tagged retrospective
                # (rare, but mirrors Phase 3's classification order).
                retro, retro_reason = _detection_is_retrospective_backfill(r)
                if retro:
                    item = dict(base, reason=retro_reason)
                    retrospective.append(item)
                    continue

                is_self = _detection_is_workflow_self_triggered(r)
                if is_self:
                    workflow_self.append(base)
                    continue

                is_audit, matched_domain = _detection_is_shadow_ai_ioc_audit(r)
                if is_audit:
                    item = dict(base, matched_domain=matched_domain)
                    shadow_ai_audit.append(item)
                    continue

                actionable.append(base)
        if len(ids) < _PAGE:
            break
        offset += _PAGE

    total_open = (
        len(actionable)
        + len(workflow_self)
        + len(shadow_ai_audit)
        + len(retrospective)
    )
    should_proceed = len(actionable) > 0

    # Pre-compose the bulk-close calls (falcon_update_detections arguments) so
    # the agent doesn't have to reason about status/tag/comment shape when
    # short-circuiting.
    bulk_close: list[dict[str, Any]] = []
    if not should_proceed:
        if workflow_self:
            bulk_close.append({
                "ids": [d["composite_id"] for d in workflow_self],
                "status": "closed",
                "add_tags": ["false_positive"],
                "append_comment": (
                    "Workflow-self-triggered — RTR runscript preamble matched "
                    "the PowerShell-encoded-command detector. Not real attacker "
                    "activity."
                ),
                "kind": "workflow_self",
            })
        if shadow_ai_audit:
            bulk_close.append({
                "ids": [d["composite_id"] for d in shadow_ai_audit],
                "status": "closed",
                "append_comment": (
                    "Shadow-AI audit IOC fire — detect-only domain IOC created "
                    "by Ban+Clean Phase 4 fired on continued AI-provider DNS. "
                    "Working as designed; no IR remediation appropriate."
                ),
                "kind": "shadow_ai_audit",
            })
        if retrospective:
            bulk_close.append({
                "ids": [d["composite_id"] for d in retrospective],
                "status": "closed",
                "add_tags": ["false_positive"],
                "append_comment": (
                    "Retrospective IOC match — fresh detection envelope, "
                    "underlying event timestamps predate the workflow window. "
                    "Falcon backfill, not new activity."
                ),
                "kind": "retrospective",
            })

    return {
        "ok": True,
        "device_id": device_id,
        "total_open": total_open,
        "actionable": actionable,
        "workflow_self_triggered": workflow_self,
        "shadow_ai_ioc_audit": shadow_ai_audit,
        "retrospective_ioc_match": retrospective,
        "should_proceed_with_ir": should_proceed,
        "bulk_close_calls": bulk_close,
    }
