"""Process-ancestry walker — single pivot pid → list of ancestor PR2 rows.

Used by ``ir.campaign_scope`` (one walk per unique pivot) and inlined
inside ``ir.process_tree`` for the full single-detection reconstruction.

Bounded NGSIEM cost: one query for the window + at most one widen lookup
per missing parent, plus one anchor-recovery probe when the primary
window misses (behavioral detections fire hours after the offending
process actually launched, so the alert-time-centered window often won't
contain the pivot's ProcessRollup2 row).

Per-walk budgets default to 15/8/12 seconds (worst-case ~35s). Callers
running many walks in parallel under a global deadline pass smaller
values to bound straggler cost.
"""

from __future__ import annotations

import re
from typing import Any

from ngsiem.search import (
    ms_now,
    normalize_pr2_row,
    pr2_select,
    run_ngsiem_search,
)


# System pids / processes that connect EVERYTHING (every user process
# eventually hits explorer.exe / services.exe / wininit / smss / csrss).
# Excluded from cluster-shared-ancestor matching so unrelated user
# campaigns don't get merged through the system root.
_SYSTEM_ANCESTOR_BASENAMES: set[str] = {
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "userinit.exe",
    "dwm.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "ctfmon.exe",
    "searchhost.exe",
    "searchindexer.exe",
}


def basename_lower(image: str | None) -> str:
    if not image or not isinstance(image, str):
        return ""
    return image.lower().rsplit("\\", 1)[-1]


def walk_ancestry_pids(
    device_id: str,
    pivot_pid: int,
    pivot_ts_iso: str,
    window_minutes: int = 30,
    ancestry_max: int = 12,
    primary_budget_s: float = 15.0,
    probe_budget_s: float = 8.0,
    rewalk_budget_s: float = 12.0,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Walk ancestry for a single ``pivot_pid``.

    Returns ``(ancestry_rows, error_dict_or_None)``. ``ancestry_rows``
    has the pivot first and the deepest ancestor last. On upstream /
    scope errors the error dict is populated and the row list is empty —
    callers should mark the detection unclustered rather than retry.
    """
    from datetime import datetime, timezone, timedelta

    if not isinstance(device_id, str) or not re.fullmatch(
        r"[a-fA-F0-9]{32}", device_id
    ):
        return [], {"error": "device_id must be a 32-char hex AID"}
    try:
        pivot_dt = datetime.fromisoformat(pivot_ts_iso.replace("Z", "+00:00"))
        if pivot_dt.tzinfo is None:
            pivot_dt = pivot_dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return [], {"error": f"bad pivot_ts_iso: {pivot_ts_iso}"}

    window = timedelta(minutes=window_minutes)
    start_ms = int((pivot_dt - window).timestamp() * 1000)
    end_ms = int((pivot_dt + window).timestamp() * 1000)

    cql = (
        f'#event_simpleName=ProcessRollup2 aid="{device_id}"\n'
        f"| select({pr2_select()})\n"
        f"| sort(@timestamp, order=asc, limit=5000)\n"
        f"| head(5000)"
    )
    events, err = run_ngsiem_search(cql, start_ms, end_ms, budget_s=primary_budget_s)
    if err is not None or not events:
        # Anchor recovery for behavioral detections: try a wide
        # TargetProcessId probe to find the actual process_start ts.
        wide_end_ms = ms_now()
        wide_start_ms = wide_end_ms - 7 * 24 * 60 * 60 * 1000
        probe_cql = (
            f'#event_simpleName=ProcessRollup2 aid="{device_id}" '
            f'TargetProcessId="{pivot_pid}"\n'
            f"| select({pr2_select()})\n"
            f"| head(1)"
        )
        probe_events, _probe_err = run_ngsiem_search(
            probe_cql, wide_start_ms, wide_end_ms, budget_s=probe_budget_s
        )
        if not probe_events:
            return [], None  # truly missing; mark unclustered
        probe_row = normalize_pr2_row(probe_events[0])
        try:
            actual_ts_ms = int(float(probe_row.get("ts") or 0) * 1000)
        except (TypeError, ValueError):
            actual_ts_ms = 0
        if actual_ts_ms <= 0:
            return [], None
        new_pivot_dt = datetime.fromtimestamp(actual_ts_ms / 1000, tz=timezone.utc)
        new_start_ms = int((new_pivot_dt - window).timestamp() * 1000)
        new_end_ms = int((new_pivot_dt + window).timestamp() * 1000)
        events, err = run_ngsiem_search(
            cql, new_start_ms, new_end_ms, budget_s=rewalk_budget_s
        )
        if err is not None or not events:
            return [], None

    rows = [normalize_pr2_row(e) for e in events]
    pid_index: dict[int, dict[str, Any]] = {}
    for r in rows:
        pid = r.get("pid")
        if isinstance(pid, int) and pid not in pid_index:
            pid_index[pid] = r

    pivot = pid_index.get(pivot_pid)
    if pivot is None:
        return [], None  # mark unclustered

    ancestry: list[dict[str, Any]] = [pivot]
    seen_pids: set[int] = {pivot_pid}
    cur = pivot
    for _ in range(ancestry_max):
        ppid = cur.get("ppid")
        if not isinstance(ppid, int) or ppid in seen_pids:
            break
        parent = pid_index.get(ppid)
        if parent is None:
            break
        seen_pids.add(ppid)
        ancestry.append(parent)
        cur = parent
    return ancestry, None
