"""Phase 4 closer for the agentic IR workflow.

Walks every open detection on the host, matches each one against the
agent's structured ``remediated[]`` ledger via
``ir.ledger_matcher.ledger_entry_matches_alert``, and closes ONLY matched
detections via v3 Alerts ``update_alerts_v3``. Unmatched stay open for
operator review. Each close carries a per-id ``evidence`` list naming the
specific ledger entry / field that fired — that audit trail is the reason
this exists separately from the bulk closer.

Lives in its own module (rather than inside ``server.py``) so the heavy
walking + matching logic is unit-testable against canned alert / ledger
fixtures, without spinning up MCP. ``server.py`` exposes the tool via a
thin ``@mcp.tool()`` wrapper that delegates here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from falcon_helpers import (
    _check_response,
    _get_alerts_client,
    _is_permission_error,
    _scope_denied_payload,
    _upstream_error,
    _VALID_DETECTION_VERDICTS,
    _VERDICT_TAG,
)
from falcon_helpers import reject_unsafe_device_id, swallow_exc

from .ledger_matcher import ledger_entry_matches_alert

# Page size for the alert-enumeration loop. Falcon's v2 query endpoint allows
# up to 10000 but we hydrate every id with get_alerts_v2 (chunked at 100), so
# a smaller page keeps memory bounded for noisy hosts.
_QUERY_PAGE = 200

# Hard cap on alert hydration. A host with > 5000 open detections is broken
# in some other way — the ledger close isn't the right tool for that situation
# and the bulk closer (extras_close_all_open_detections_on_host) should run
# first. The cap bounds wall-clock so we don't hit the MCP 60s ceiling.
_HARD_CAP = 5000

# Chunk size for v3 update_alerts. Falcon's API caps per-call at 500.
_UPDATE_BATCH = 500

# Open-status set: alerts in any other state are skipped (already closed,
# already true_positive-tagged, etc).
_OPEN_STATUSES = {"new", "reopened", "in_progress"}


def close_remediated(
    device_id: str,
    remediated: list[dict[str, Any]],
    verdict: str = "true_positive",
    comment: str | None = None,
    before_iso: str | None = None,
) -> dict[str, Any]:
    """Implementation for ``extras_ir_close_remediated``.

    See ``server.py``'s tool docstring for the full ledger-entry contract
    and result shape — this function is the worker that ``@mcp.tool()``
    wraps.
    """
    if not device_id or not isinstance(device_id, str):
        return {"ok": False, "error": "device_id required"}
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
    if not isinstance(remediated, list):
        return {"ok": False, "error": "remediated must be a list of ledger entries"}

    # Filter out non-dict / kind-less entries with a structured note rather
    # than silently dropping them.
    valid_entries: list[tuple[int, dict[str, Any]]] = []
    invalid_indices: list[int] = []
    for i, e in enumerate(remediated):
        if isinstance(e, dict) and isinstance(e.get("kind"), str) and e["kind"]:
            valid_entries.append((i, e))
        else:
            invalid_indices.append(i)

    if comment is None:
        comment = (
            "Closed via Project Eyas IR remediation-ledger match — Phase 4 step 1"
        )

    try:
        client = _get_alerts_client()
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)

    # Step 1: enumerate open detections AND hydrate each — we need the full
    # record (cmdline / behaviors / parent_details) for ledger matching, not
    # just composite_ids.
    full_alerts, guard = _open_epp_alerts(client, device_id)
    if guard is not None:
        return guard

    scope_count = len(full_alerts)
    if scope_count == 0:
        return {
            "ok": True,
            "device_id": device_id,
            "scope_count": 0,
            "matched_count": 0,
            "unmatched_count": 0,
            "updated": 0,
            "closed": [],
            "unmatched": [],
            "ledger_entries_used": 0,
            "ledger_entries_unused": [i for i, _ in valid_entries],
            "invalid_ledger_indices": invalid_indices,
            "note": "No open detections on this host — nothing to close.",
        }

    # Step 2: per-detection ledger matching. Pure logic, exercised by the
    # unit suite in ir/test_ledger_matcher.py via ledger_entry_matches_alert.
    closed_records, unmatched_records, matched_composite_ids, used_indices = (
        _classify_alerts_against_ledger(full_alerts, valid_entries)
    )
    matched_count = len(matched_composite_ids)
    unmatched_count = len(unmatched_records)

    # Step 3: chunked close on matched only.
    actions = [
        {"name": "update_status", "value": "closed"},
        {"name": "add_tag", "value": _VERDICT_TAG[verdict]},
        {"name": "append_comment", "value": comment},
    ]
    updated = 0
    batch_errors: list[dict[str, Any]] = []
    if matched_count > 0:
        updated, batch_errors, denied = _close_ids(client, matched_composite_ids, actions)
        if denied is not None:
            return denied

    unused = [i for i, _ in valid_entries if i not in used_indices]

    # With the quarantine start time, count the unmatched detections that
    # predate the engagement: the untouched Phase 0 originals that block
    # release until the operator decides on them
    # (extras_ir_close_untouched_originals).
    prior: dict[str, Any] = {}
    if before_iso:
        cutoff = _parse_iso(before_iso)
        if cutoff is None:
            prior = {"before_iso_error": f"before_iso is not an ISO 8601 timestamp: {before_iso!r}"}
        else:
            before = [u for u in unmatched_records if _created_before(u, cutoff)]
            prior = {
                "unmatched_prior_count": len(before),
                "unmatched_prior_sample": [
                    u.get("display_name") for u in before[:10] if u.get("display_name")
                ],
            }

    result: dict[str, Any] = {
        "ok": (matched_count == 0) or (updated > 0),
        "device_id": device_id,
        "verdict": verdict,
        "scope_count": scope_count,
        "matched_count": matched_count,
        "unmatched_count": unmatched_count,
        "updated": updated,
        "closed": closed_records,
        "unmatched": unmatched_records,
        "ledger_entries_used": len(used_indices),
        "ledger_entries_unused": unused,
        "invalid_ledger_indices": invalid_indices,
        **prior,
        "note": (
            f"Closed {updated} of {matched_count} matched detection(s) as "
            f"{verdict}. {unmatched_count} unmatched left open for operator "
            f"review (no Phase 2 action touched their evidence)."
        ),
    }
    if batch_errors:
        result["batch_errors"] = batch_errors
        if updated == 0 and matched_count > 0:
            result["ok"] = False
            result["error"] = (
                f"all {len(batch_errors)} close batches failed; "
                f"first error: {batch_errors[0].get('error')}"
            )
    return result


def _classify_alerts_against_ledger(
    full_alerts: list[dict[str, Any]],
    valid_entries: list[tuple[int, dict[str, Any]]],
) -> tuple[
    list[dict[str, Any]],  # closed_records (with evidence)
    list[dict[str, Any]],  # unmatched_records
    list[str],             # matched_composite_ids
    set[int],              # used ledger indices
]:
    """Pure-logic alert → ledger classification. No FalconPy calls.

    Extracted as a separate function so the test suite can exercise it
    against canned alert lists + canned ledger entries without mocking
    the Alerts client.
    """
    closed_records: list[dict[str, Any]] = []
    unmatched_records: list[dict[str, Any]] = []
    matched_composite_ids: list[str] = []
    used_indices: set[int] = set()

    for alert in full_alerts:
        cid = alert.get("composite_id") or alert.get("id")
        evidence: list[str] = []
        for orig_idx, entry in valid_entries:
            matched, reason = ledger_entry_matches_alert(entry, alert)
            if matched and reason:
                evidence.append(f"[ledger#{orig_idx} {entry['kind']}] {reason}")
                used_indices.add(orig_idx)
        if evidence:
            matched_composite_ids.append(cid)
            closed_records.append(
                {
                    "composite_id": cid,
                    "display_name": alert.get("display_name") or alert.get("name"),
                    "created_timestamp": alert.get("created_timestamp"),
                    "evidence": evidence,
                }
            )
        else:
            unmatched_records.append(
                {
                    "composite_id": cid,
                    "display_name": alert.get("display_name") or alert.get("name"),
                    "created_timestamp": alert.get("created_timestamp"),
                    "pivot_pid": alert.get("process_id"),
                    "tactic": alert.get("tactic"),
                    "technique": alert.get("technique"),
                }
            )
    return closed_records, unmatched_records, matched_composite_ids, used_indices


def _open_epp_alerts(
    client: Any, device_id: str
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Every open endpoint detection on the host, hydrated. (alerts, error)."""
    full_alerts: list[dict[str, Any]] = []
    offset = 0
    while offset < _HARD_CAP:
        q = client.query_alerts_v2(
            filter=f"product:'epp'+device.device_id:'{device_id}'",
            limit=_QUERY_PAGE,
            offset=offset,
            sort="created_timestamp.desc",
        )
        guard = _check_response(q, "Alerts")
        if guard is not None:
            return [], guard
        ids = ((q or {}).get("body") or {}).get("resources") or []
        if not ids:
            break
        for chunk_start in range(0, len(ids), 100):
            chunk = ids[chunk_start : chunk_start + 100]
            d = client.get_alerts_v2(body={"composite_ids": chunk})
            d_guard = _check_response(d, "Alerts")
            if d_guard is not None:
                return [], d_guard
            recs = ((d or {}).get("body") or {}).get("resources") or []
            for r in recs:
                if not isinstance(r, dict):
                    continue
                status = (r.get("status") or "").lower()
                if status not in _OPEN_STATUSES:
                    continue
                if not (r.get("composite_id") or r.get("id")):
                    continue
                full_alerts.append(r)
        if len(ids) < _QUERY_PAGE:
            break
        offset += _QUERY_PAGE
    return full_alerts, None


def _close_ids(
    client: Any, composite_ids: list[str], actions: list[dict[str, Any]]
) -> tuple[int, list[dict[str, Any]], dict[str, Any] | None]:
    """Close ids in API-sized batches. (updated, batch_errors, scope_denied)."""
    updated = 0
    batch_errors: list[dict[str, Any]] = []
    for batch_start in range(0, len(composite_ids), _UPDATE_BATCH):
        chunk = composite_ids[batch_start : batch_start + _UPDATE_BATCH]
        try:
            r = client.update_alerts_v3(
                body={"composite_ids": chunk, "action_parameters": actions}
            )
            if _is_permission_error(r):
                # First batch with no successful close yet → render the
                # canonical scope-denied payload so the operator sees one
                # clean message instead of "0 of N closed".
                if updated == 0:
                    return 0, [], _scope_denied_payload(r, "Alerts")
                batch_errors.append({"batch_start": batch_start, "error": "scope_pending"})
                break
            err = _upstream_error(r)
            if err:
                batch_errors.append(
                    {"batch_start": batch_start, "error": err, "size": len(chunk)}
                )
                continue
            updated += len(chunk)
        except Exception as exc:  # noqa: BLE001
            batch_errors.append(
                {
                    "batch_start": batch_start,
                    "error": f"{type(exc).__name__}: {exc}",
                    "size": len(chunk),
                }
            )
    return updated, batch_errors, None


def _parse_iso(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _created_before(alert: dict[str, Any], cutoff: datetime) -> bool:
    """True when the detection was created strictly before ``cutoff``. A
    detection without a readable creation time is NOT treated as prior: it
    stays open rather than being closed on a guess."""
    created = alert.get("created_timestamp")
    if not isinstance(created, str):
        return False
    dt = _parse_iso(created)
    return dt is not None and dt < cutoff


def select_untouched_originals(
    alerts: list[dict[str, Any]], cutoff: datetime
) -> list[str]:
    """Composite ids of open detections created before the engagement began.
    Pure; unit-tested in ir/test_close_untouched.py."""
    out: list[str] = []
    for a in alerts:
        cid = a.get("composite_id") or a.get("id")
        if isinstance(cid, str) and _created_before(a, cutoff):
            out.append(cid)
    return out


def close_untouched_originals(
    device_id: str,
    before_iso: str,
    verdict: str,
    comment: str | None = None,
) -> dict[str, Any]:
    """Implementation for ``extras_ir_close_untouched_originals``.

    Run after the ledger close (``extras_ir_close_remediated``) and only on
    the operator's say-so: closes every endpoint detection on the host that
    is still open and was created before ``before_iso`` (the Phase 1
    quarantine time). After the ledger close those are exactly the Phase 0
    originals no remediation touched, which otherwise block release.
    Detections that fired during the engagement are left alone.
    """
    if not device_id or not isinstance(device_id, str):
        return {"ok": False, "error": "device_id required"}
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
    cutoff = _parse_iso(before_iso) if isinstance(before_iso, str) else None
    if cutoff is None:
        return {
            "ok": False,
            "error": (
                "before_iso must be the Phase 1 quarantine time as ISO 8601, "
                "e.g. 2026-05-01T12:00:00Z"
            ),
        }
    if comment is None:
        comment = (
            "Closed at the operator's request after a Project Eyas IR engagement: "
            "open before the engagement began and not remediated by the workflow"
        )

    try:
        client = _get_alerts_client()
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)

    alerts, guard = _open_epp_alerts(client, device_id)
    if guard is not None:
        return guard
    ids = select_untouched_originals(alerts, cutoff)
    if not ids:
        return {
            "ok": True,
            "device_id": device_id,
            "verdict": verdict,
            "before_iso": before_iso,
            "scope_count": 0,
            "updated": 0,
            "composite_ids": [],
            "note": "No open detections from before the engagement — nothing to close.",
        }

    actions = [
        {"name": "update_status", "value": "closed"},
        {"name": "add_tag", "value": _VERDICT_TAG[verdict]},
        {"name": "append_comment", "value": comment},
    ]
    updated, batch_errors, denied = _close_ids(client, ids, actions)
    if denied is not None:
        return denied
    result: dict[str, Any] = {
        "ok": updated > 0,
        "device_id": device_id,
        "verdict": verdict,
        "before_iso": before_iso,
        "scope_count": len(ids),
        "updated": updated,
        "composite_ids": ids,
        "left_open_after_cutoff": len(alerts) - len(ids),
    }
    if batch_errors:
        result["batch_errors"] = batch_errors
        if updated == 0:
            result["error"] = (
                f"all close batches failed; first error: {batch_errors[0].get('error')}"
            )
    return result
