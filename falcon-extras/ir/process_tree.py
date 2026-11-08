"""Single-detection process-tree reconstruction with delivery-vector
classification.

Walks NGSIEM ProcessRollup2 events around the pivot timestamp on the
target host, locates the pivot by pid (or by image-basename fuzzy match),
walks ``ParentProcessId`` upward for the ancestry chain and
``ContextProcessId`` downward for descendants, then runs the deterministic
delivery-vector classifier on the chain.

The classifier verdict (``phishing_doc`` / ``browser_drive_by`` /
``lateral_winrm`` / ``c2_agent`` / etc.) is decision-grade for IR Phase 0:
it tells the operator where the attack arrived, not just what fired on
the host. See ``process_tree.classifier`` for the rule set.

Anchor-recovery: behavioral detections (Meterpreter, IFEO, CredentialDump)
fire hours after the offending process actually launched. The default
window is centered on alert time, so the pivot's PR2 row sits outside it.
When ``pivot_pid`` is known but missing from the window, we run one wide
probe keyed on ``TargetProcessId`` to find the real ``process_start``
timestamp, then re-anchor the window. Bounded to one extra NGSIEM call.
"""

from __future__ import annotations

import re

from falcon_helpers import swallow_exc
from typing import Any

from process_tree import classify_delivery_vector
from process_tree.classifier import annotate_node_verdicts

from ngsiem.search import (
    ms_now,
    normalize_pr2_row,
    pr2_select,
    run_ngsiem_search,
)


def host_process_tree(
    device_id: str,
    pivot_pid: int | None = None,
    pivot_image: str | None = None,
    pivot_ts_iso: str | None = None,
    window_minutes: int = 10,
    ancestry_max: int = 12,
    descendants_max: int = 200,
) -> dict[str, Any]:
    try:
        if not isinstance(device_id, str) or not re.fullmatch(
            r"[a-fA-F0-9]{32}", device_id
        ):
            return {"ok": False, "error": "device_id must be a 32-char hex AID"}
        if not pivot_ts_iso or not isinstance(pivot_ts_iso, str):
            return {
                "ok": False,
                "error": "pivot_ts_iso (ISO 8601 detection timestamp) is required",
            }
        if pivot_pid is None and not pivot_image:
            return {
                "ok": False,
                "error": "one of pivot_pid or pivot_image is required",
            }
        if not isinstance(window_minutes, int) or not (1 <= window_minutes <= 120):
            return {"ok": False, "error": "window_minutes must be an integer in 1-120"}
        if not isinstance(ancestry_max, int) or not (1 <= ancestry_max <= 30):
            return {"ok": False, "error": "ancestry_max must be an integer in 1-30"}
        if not isinstance(descendants_max, int) or not (
            1 <= descendants_max <= 1000
        ):
            return {"ok": False, "error": "descendants_max must be an integer in 1-1000"}
        if pivot_image is not None and (
            not isinstance(pivot_image, str)
            or not re.fullmatch(r"[A-Za-z0-9_. \-]{1,96}", pivot_image)
        ):
            return {
                "ok": False,
                "error": "pivot_image must be a basename like 'powershell.exe'",
            }

        from datetime import datetime, timezone, timedelta

        try:
            pivot_dt = datetime.fromisoformat(pivot_ts_iso.replace("Z", "+00:00"))
            if pivot_dt.tzinfo is None:
                pivot_dt = pivot_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return {
                "ok": False,
                "error": f"pivot_ts_iso could not be parsed as ISO 8601: {pivot_ts_iso}",
            }

        window = timedelta(minutes=window_minutes)
        start_ms = int((pivot_dt - window).timestamp() * 1000)
        end_ms = int((pivot_dt + window).timestamp() * 1000)

        # Initial CQL: pull every ProcessRollup2 row on the AID inside the
        # window, capped at 5000. sort() defaults to limit=200 so pass the
        # explicit limit even though head(5000) would otherwise look like
        # the ceiling.
        cql = (
            f'#event_simpleName=ProcessRollup2 aid="{device_id}"\n'
            f"| select({pr2_select()})\n"
            f"| sort(@timestamp, order=asc, limit=5000)\n"
            f"| head(5000)"
        )

        events, err = run_ngsiem_search(cql, start_ms, end_ms, budget_s=30.0)
        if err is not None:
            return err
        if events is None:
            return {
                "ok": True,
                "pivot": None,
                "delivery_vector": {
                    "kind": "unknown",
                    "confidence": "low",
                    "rationale": (
                        "NGSIEM search did not complete within the polling "
                        "budget. Re-run with a tighter window_minutes."
                    ),
                },
                "ancestry": [],
                "descendants": [],
                "truncated": True,
            }
        if not events:
            return {
                "ok": True,
                "pivot": None,
                "delivery_vector": {
                    "kind": "unknown",
                    "confidence": "low",
                    "rationale": (
                        "No ProcessRollup2 events found on this host within "
                        f"±{window_minutes}m of the detection timestamp. NGSIEM "
                        "retention may have aged out, or telemetry isn't flowing "
                        "for this AID."
                    ),
                },
                "ancestry": [],
                "descendants": [],
                "truncated": False,
            }

        rows = [normalize_pr2_row(e) for e in events]
        pid_index: dict[int, dict[str, Any]] = {}
        for r in rows:
            pid = r.get("pid")
            if isinstance(pid, int) and pid not in pid_index:
                pid_index[pid] = r

        pivot: dict[str, Any] | None = None
        if pivot_pid is not None and pivot_pid in pid_index:
            pivot = pid_index[pivot_pid]
        elif pivot_image:
            target = pivot_image.lower()
            pivot_ts_ms = int(pivot_dt.timestamp() * 1000)
            best: tuple[int, dict[str, Any]] | None = None
            for r in rows:
                img = (r.get("image") or "").lower().rsplit("\\", 1)[-1]
                if not img.endswith(target):
                    continue
                try:
                    ts_ms = int(r.get("ts") or 0)
                except (TypeError, ValueError):
                    continue
                delta = abs(ts_ms - pivot_ts_ms)
                if best is None or delta < best[0]:
                    best = (delta, r)
            if best is not None:
                pivot = best[1]

        # Anchor-recovery: see CLAUDE.md "Process-tree reconstruction +
        # delivery-vector classification — anchor-recovery for behavioral
        # detections". One wide probe to find the actual process_start
        # timestamp, then re-anchor the window there.
        anchor_recovered = False
        if pivot is None and pivot_pid is not None:
            wide_end_ms = ms_now()
            wide_start_ms = wide_end_ms - 7 * 24 * 60 * 60 * 1000
            probe_cql = (
                f'#event_simpleName=ProcessRollup2 aid="{device_id}" '
                f'TargetProcessId="{pivot_pid}"\n'
                f"| select({pr2_select()})\n"
                f"| head(1)"
            )
            probe_events, _probe_err = run_ngsiem_search(
                probe_cql, wide_start_ms, wide_end_ms, budget_s=15.0
            )
            if probe_events:
                probe_row = normalize_pr2_row(probe_events[0])
                try:
                    actual_ts_ms = int(float(probe_row.get("ts") or 0) * 1000)
                except (TypeError, ValueError):
                    actual_ts_ms = 0
                if actual_ts_ms > 0:
                    new_pivot_dt = datetime.fromtimestamp(
                        actual_ts_ms / 1000, tz=timezone.utc
                    )
                    new_start_ms = int(
                        (new_pivot_dt - window).timestamp() * 1000
                    )
                    new_end_ms = int(
                        (new_pivot_dt + window).timestamp() * 1000
                    )
                    re_cql = (
                        f'#event_simpleName=ProcessRollup2 aid="{device_id}"\n'
                        f"| select({pr2_select()})\n"
                        f"| sort(@timestamp, order=asc, limit=5000)\n"
                        f"| head(5000)"
                    )
                    re_events, re_err = run_ngsiem_search(
                        re_cql, new_start_ms, new_end_ms, budget_s=30.0
                    )
                    if re_err is None and re_events:
                        events = re_events
                        rows = [normalize_pr2_row(e) for e in events]
                        pid_index = {}
                        for r in rows:
                            pid = r.get("pid")
                            if isinstance(pid, int) and pid not in pid_index:
                                pid_index[pid] = r
                        if pivot_pid in pid_index:
                            pivot = pid_index[pivot_pid]
                            anchor_recovered = True
                            pivot_dt = new_pivot_dt

        if pivot is None:
            return {
                "ok": True,
                "pivot": None,
                "delivery_vector": {
                    "kind": "unknown",
                    "confidence": "low",
                    "rationale": (
                        "Pivot process not found in NGSIEM ProcessRollup2 "
                        "for this AID over the last 7 days. The detection "
                        "may reference a process whose telemetry never "
                        "landed in NGSIEM, or NGSIEM retention has aged it "
                        "out. Falcon Console's process explorer may still "
                        "have the chain via Threat Graph."
                    ),
                },
                "ancestry": [],
                "descendants": [],
                "events_scanned": len(events),
                "truncated": False,
            }

        # Walk ancestry.
        window_widened = False
        ancestry: list[dict[str, Any]] = [pivot]
        seen_pids: set[int] = set()
        if isinstance(pivot.get("pid"), int):
            seen_pids.add(pivot["pid"])
        cur = pivot
        for _ in range(ancestry_max):
            ppid = cur.get("ppid")
            if not isinstance(ppid, int) or ppid in seen_pids:
                break
            parent = pid_index.get(ppid)
            if parent is None:
                # One-shot widen: try ±60 min for THIS ppid only.
                if window_widened:
                    break
                widen = timedelta(minutes=60)
                wstart = int((pivot_dt - widen).timestamp() * 1000)
                wend = int((pivot_dt + widen).timestamp() * 1000)
                widen_cql = (
                    f'#event_simpleName=ProcessRollup2 aid="{device_id}" '
                    f'TargetProcessId="{ppid}"\n'
                    f"| select({pr2_select()})\n"
                    f"| head(5)"
                )
                wevents, werr = run_ngsiem_search(
                    widen_cql, wstart, wend, budget_s=15.0
                )
                window_widened = True
                if werr is not None or not wevents:
                    break
                parent = normalize_pr2_row(wevents[0])
                if isinstance(parent.get("pid"), int):
                    pid_index.setdefault(parent["pid"], parent)
            seen_pids.add(ppid)
            ancestry.append(parent)
            cur = parent

        # Walk descendants — single pass over the row list, BFS by ppid.
        children_by_ppid: dict[int, list[dict[str, Any]]] = {}
        for r in rows:
            ppid = r.get("ppid")
            if isinstance(ppid, int):
                children_by_ppid.setdefault(ppid, []).append(r)

        descendants: list[dict[str, Any]] = []
        descendants_truncated = False
        if isinstance(pivot.get("pid"), int):
            queue: list[tuple[int, int]] = [(pivot["pid"], 1)]
            seen_d: set[int] = {pivot["pid"]}
            while queue and len(descendants) < descendants_max:
                parent_pid, depth = queue.pop(0)
                for child in children_by_ppid.get(parent_pid, []):
                    cpid = child.get("pid")
                    if not isinstance(cpid, int) or cpid in seen_d:
                        continue
                    seen_d.add(cpid)
                    enriched = dict(child)
                    enriched["depth"] = depth
                    descendants.append(enriched)
                    if len(descendants) >= descendants_max:
                        descendants_truncated = True
                        break
                    queue.append((cpid, depth + 1))

        # Annotate verdicts BEFORE classify (which then overrides one
        # node to initial-access-anchor).
        for i, node in enumerate(ancestry):
            node["depth"] = i
        annotate_node_verdicts(ancestry)
        delivery_vector = classify_delivery_vector(
            ancestry, window_widened=window_widened
        )

        # Surface unaccounted-for ppids — IR playbook reads this to
        # decide whether to widen further or escalate.
        unaccounted_pids: list[int] = []
        if ancestry:
            top = ancestry[-1]
            if (
                isinstance(top.get("ppid"), int)
                and top["ppid"] not in seen_pids
                and top["ppid"] not in pid_index
            ):
                unaccounted_pids.append(top["ppid"])

        return {
            "ok": True,
            "pivot": {
                "pid": pivot.get("pid"),
                "image": pivot.get("image"),
                "cmdline": pivot.get("cmdline"),
                "ts": pivot.get("ts"),
            },
            "delivery_vector": delivery_vector,
            "ancestry": ancestry,
            "descendants": descendants,
            "unaccounted_pids": unaccounted_pids,
            "events_scanned": len(events),
            "window_widened": window_widened,
            "anchor_recovered": anchor_recovered,
            "truncated": descendants_truncated,
        }
    except Exception as exc:
        return swallow_exc(exc)
