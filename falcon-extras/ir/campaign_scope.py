"""Server-side campaign-aware IR Phase 0 scope.

For every open detection on the host, walks the process-tree ancestry
(caching per unique pivot_pid so detections sharing a pivot pay one walk,
not N), then UnionFind-clusters detections by shared NON-SYSTEM ancestor
pid. Each cluster is one "campaign" — the set of detections rooted in
the same attacker chain.

System processes (explorer / services / svchost / lsass / etc.) are
excluded from the shared-ancestor match so unrelated user campaigns
don't merge through the OS root.

Embarrassingly parallel: each unique pivot's walk is a separate NGSIEM
job, run on its own ``APIHarnessV2`` instance. Bounded by a global
deadline (default 50s under the 60s MCP cap) and a hard per-call cap on
unique pivots so a host with hundreds of distinct pivots can't blow the
budget.
"""

from __future__ import annotations

import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any

from falcon_helpers import _check_response, _get_alerts_client
from falcon_helpers import reject_unsafe_device_id, swallow_exc
from process_tree import classify_delivery_vector
from process_tree.classifier import annotate_node_verdicts

from .ancestry import (
    _SYSTEM_ANCESTOR_BASENAMES,
    basename_lower,
    walk_ancestry_pids,
)


def ir_campaign_scope(device_id: str) -> dict[str, Any]:
    started_at = time.time()
    if not device_id or not isinstance(device_id, str):
        return {"ok": False, "error": "device_id required"}
    bad = reject_unsafe_device_id(device_id)
    if bad is not None:
        return bad

    # Step 1: enumerate open detections (mirrors ir.phase0).
    PAGE = 200
    HARD_CAP = 5000
    OPEN_STATUSES = {"new", "reopened", "in_progress"}
    try:
        client = _get_alerts_client()
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)

    items: list[dict[str, Any]] = []
    offset = 0
    while offset < HARD_CAP:
        q = client.query_alerts_v2(
            filter=f"product:'epp'+device.device_id:'{device_id}'",
            limit=PAGE,
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
                if status not in OPEN_STATUSES:
                    continue
                cid = r.get("composite_id") or r.get("id")
                if not cid:
                    continue
                pivot = _extract_pivot_pid(r)
                items.append(
                    {
                        "composite_id": cid,
                        "created_timestamp": r.get("created_timestamp"),
                        "severity": r.get("severity"),
                        "severity_name": r.get("severity_name"),
                        "display_name": r.get("display_name") or r.get("name"),
                        "tactic": r.get("tactic"),
                        "technique": r.get("technique"),
                        "pivot_pid": pivot,
                    }
                )
        if len(ids) < PAGE:
            break
        offset += PAGE

    if not items:
        return {
            "ok": True,
            "device_id": device_id,
            "campaigns": [],
            "unclustered": [],
            "total_open": 0,
            "unique_pivots_walked": 0,
            "walk_seconds": 0.0,
            "note": "No open detections on this host.",
        }

    # Step 2: group by unique pivot_pid.
    by_pivot: dict[int, list[dict[str, Any]]] = {}
    no_pivot: list[dict[str, Any]] = []
    for it in items:
        pid = it.get("pivot_pid")
        if isinstance(pid, int):
            by_pivot.setdefault(pid, []).append(it)
        else:
            no_pivot.append(it)

    # Step 3: walk ancestry per unique pivot in parallel under a global
    # deadline. Each walk is an independent NGSIEM job.
    GLOBAL_DEADLINE_S = 50.0  # 10s headroom under MCP 60s
    MAX_PIVOTS = 24
    PARALLEL_WORKERS = 4

    deadline = started_at + GLOBAL_DEADLINE_S

    pivot_order = sorted(
        by_pivot.items(),
        key=lambda kv: max(
            (d.get("created_timestamp") or "" for d in kv[1]), default=""
        ),
        reverse=True,
    )
    walked_pivots = pivot_order[:MAX_PIVOTS]
    deferred_pivots = pivot_order[MAX_PIVOTS:]

    ancestry_by_pivot: dict[int, list[dict[str, Any]]] = {}
    walk_failures: dict[int, str] = {}
    for pid, _det_group in deferred_pivots:
        walk_failures[pid] = (
            f"deferred — host has {len(by_pivot)} unique pivots, "
            f"capped at {MAX_PIVOTS} per call (sorted by recency)"
        )

    def _walk_one(pid: int, det_group: list[dict[str, Any]]) -> tuple[
        int, list[dict[str, Any]] | None, str | None
    ]:
        ts_iso = max(
            (d.get("created_timestamp") or "" for d in det_group),
            default="",
        )
        if not ts_iso:
            return pid, None, "no created_timestamp on any detection"
        # Per-walk budget shrinks with remaining global time so a single
        # straggler can't consume the whole window.
        remaining = max(deadline - time.time(), 5.0)
        primary_b = min(15.0, remaining * 0.6)
        probe_b = min(8.0, remaining * 0.3)
        rewalk_b = min(12.0, remaining * 0.5)
        ancestry, err = walk_ancestry_pids(
            device_id,
            pid,
            ts_iso,
            primary_budget_s=primary_b,
            probe_budget_s=probe_b,
            rewalk_budget_s=rewalk_b,
        )
        if err is not None:
            return pid, None, str(err.get("error", "walk failed"))
        if not ancestry:
            return pid, None, (
                "ancestry not reconstructible (telemetry aged out or pivot missing)"
            )
        return pid, ancestry, None

    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as ex:
        futures: dict[Future, int] = {
            ex.submit(_walk_one, pid, det_group): pid
            for pid, det_group in walked_pivots
        }
        for fut in as_completed(futures):
            if time.time() >= deadline:
                for pending, pending_pid in futures.items():
                    if not pending.done():
                        pending.cancel()
                        walk_failures.setdefault(
                            pending_pid,
                            "deadline reached before walk completed",
                        )
                break
            pid, ancestry, fail_reason = fut.result()
            if ancestry is not None:
                ancestry_by_pivot[pid] = ancestry
            elif fail_reason is not None:
                walk_failures[pid] = fail_reason

    # Step 4-6: cluster + build output records.
    cluster_to_pivots = _cluster_by_shared_ancestry(ancestry_by_pivot)
    campaigns = _build_campaign_records(
        cluster_to_pivots, ancestry_by_pivot, by_pivot
    )

    # Unclustered: detections whose pivot couldn't be resolved.
    unclustered: list[dict[str, Any]] = []
    for det in no_pivot:
        unclustered.append(
            {
                "composite_id": det["composite_id"],
                "created_timestamp": det.get("created_timestamp"),
                "display_name": det.get("display_name"),
                "reason": "no pivot_pid on detection",
            }
        )
    for pid, reason in walk_failures.items():
        for det in by_pivot.get(pid, []):
            unclustered.append(
                {
                    "composite_id": det["composite_id"],
                    "created_timestamp": det.get("created_timestamp"),
                    "display_name": det.get("display_name"),
                    "pivot_pid": pid,
                    "reason": reason,
                }
            )

    walk_seconds = round(time.time() - started_at, 2)
    deadline_reached = time.time() >= deadline
    capped = len(deferred_pivots) > 0
    note = (
        "Phase 0 IR scope: pick the campaign matching the engagement "
        "(usually largest count + matching delivery_vector), pass its "
        "`composite_ids` to Phase 4 close. `unclustered` are detections "
        "whose ancestry couldn't be reconstructed — surface to operator "
        "for manual decision (do NOT bulk-include or bulk-exclude)."
    )
    if capped or deadline_reached:
        note += (
            f" PARTIAL RESULT: walked {len(ancestry_by_pivot)} of "
            f"{len(by_pivot)} unique pivots"
            + (" (deadline reached)" if deadline_reached else "")
            + (f" (capped at {MAX_PIVOTS})" if capped else "")
            + ". Operator should review unclustered list for additional "
            "campaigns before closing."
        )
    return {
        "ok": True,
        "device_id": device_id,
        "campaigns": campaigns,
        "unclustered": unclustered,
        "total_open": len(items),
        "unique_pivots_walked": len(ancestry_by_pivot),
        "unique_pivots_total": len(by_pivot),
        "deadline_reached": deadline_reached,
        "capped": capped,
        "walk_seconds": walk_seconds,
        "note": note,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_pivot_pid(rec: dict[str, Any]) -> int | None:
    """Mirror the projection-layer pivot extraction."""
    pid_field = rec.get("process_id")
    if pid_field is not None:
        try:
            return int(pid_field)
        except (TypeError, ValueError):
            pass
    for b in rec.get("behaviors") or []:
        if isinstance(b, dict):
            for k in ("process_id", "target_process_id"):
                v = b.get(k)
                if v is not None:
                    try:
                        return int(v)
                    except (TypeError, ValueError):
                        continue
    return None


def _cluster_by_shared_ancestry(
    ancestry_by_pivot: dict[int, list[dict[str, Any]]],
) -> dict[int, list[int]]:
    """UnionFind cluster pivots by shared NON-SYSTEM ancestor pid."""
    parent: dict[int, int] = {}

    def _find(x: int) -> int:
        while parent.get(x, x) != x:
            parent[x] = parent.get(parent[x], parent[x])
            x = parent[x]
        return x

    def _union(a: int, b: int) -> None:
        ra, rb = _find(a), _find(b)
        if ra != rb:
            parent[ra] = rb

    for pid in ancestry_by_pivot:
        parent[pid] = pid

    nonsystem_ancestor_to_pivots: dict[int, list[int]] = {}
    for pivot_pid, ancestry in ancestry_by_pivot.items():
        for node in ancestry:
            apid = node.get("pid")
            if not isinstance(apid, int):
                continue
            base = basename_lower(node.get("image"))
            if base in _SYSTEM_ANCESTOR_BASENAMES:
                continue
            nonsystem_ancestor_to_pivots.setdefault(apid, []).append(pivot_pid)

    for shared_apid, pivots in nonsystem_ancestor_to_pivots.items():
        if len(pivots) < 2:
            continue
        first = pivots[0]
        for other in pivots[1:]:
            _union(first, other)

    cluster_to_pivots: dict[int, list[int]] = {}
    for pivot_pid in ancestry_by_pivot:
        root = _find(pivot_pid)
        cluster_to_pivots.setdefault(root, []).append(pivot_pid)
    return cluster_to_pivots


def _build_campaign_records(
    cluster_to_pivots: dict[int, list[int]],
    ancestry_by_pivot: dict[int, list[dict[str, Any]]],
    by_pivot: dict[int, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Emit per-cluster campaign records with delivery_vector + sample
    ancestry. Sorted by detection count descending so the dominant
    cluster surfaces first."""
    campaigns: list[dict[str, Any]] = []
    for cluster_root_pivot, member_pivots in cluster_to_pivots.items():
        composite_ids: list[str] = []
        timestamps: list[str] = []
        all_ancestor_pids: dict[int, int] = {}
        deepest_ancestry: list[dict[str, Any]] = []
        for pp in member_pivots:
            for it in by_pivot[pp]:
                composite_ids.append(it["composite_id"])
                ts = it.get("created_timestamp")
                if isinstance(ts, str):
                    timestamps.append(ts)
            anc = ancestry_by_pivot[pp]
            for node in anc:
                apid = node.get("pid")
                if isinstance(apid, int):
                    all_ancestor_pids[apid] = all_ancestor_pids.get(apid, 0) + 1
            if len(anc) > len(deepest_ancestry):
                deepest_ancestry = anc

        # Campaign root = the non-system ancestor pid that appears in the
        # most member chains AND is highest up. Pick most-shared as
        # tiebreaker.
        root_pid: int | None = None
        root_image: str | None = None
        best_score = -1
        for apid, count in all_ancestor_pids.items():
            for pp in member_pivots:
                anc = ancestry_by_pivot[pp]
                for depth, node in enumerate(anc):
                    if node.get("pid") == apid:
                        base = basename_lower(node.get("image"))
                        if base in _SYSTEM_ANCESTOR_BASENAMES:
                            continue
                        score = count * 10 + depth
                        if score > best_score:
                            best_score = score
                            root_pid = apid
                            root_image = node.get("image")
                        break

        try:
            for i, node in enumerate(deepest_ancestry):
                node["depth"] = i
            annotate_node_verdicts(deepest_ancestry)
            dv = classify_delivery_vector(deepest_ancestry, window_widened=False)
        except Exception as exc:  # noqa: BLE001
            dv = {
                "kind": "unknown",
                "confidence": "low",
                "rationale": f"classifier error: {type(exc).__name__}: {exc}",
            }

        timestamps.sort()
        campaigns.append(
            {
                "campaign_id": f"cluster-{cluster_root_pivot}",
                "count": len(composite_ids),
                "composite_ids": composite_ids,
                "member_pivot_pids": sorted(member_pivots),
                "root_pid": root_pid,
                "root_image": root_image,
                "delivery_vector": dv,
                "first_ts": timestamps[0] if timestamps else None,
                "last_ts": timestamps[-1] if timestamps else None,
                "sample_ancestry": [
                    {
                        "pid": n.get("pid"),
                        "image": n.get("image"),
                        "cmdline": (n.get("cmdline") or "")[:200],
                        "ppid": n.get("ppid"),
                        "ts": n.get("ts"),
                    }
                    for n in deepest_ancestry
                ],
            }
        )

    campaigns.sort(key=lambda c: (-c["count"], c.get("first_ts") or ""))
    return campaigns
