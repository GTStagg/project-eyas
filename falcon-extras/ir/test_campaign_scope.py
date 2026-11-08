"""Unit tests for the IR campaign-scope clustering function.

The UnionFind merge in ``_cluster_by_shared_ancestry`` is the load-bearing
piece of ``extras_ir_campaign_scope`` — it decides which open detections
share a campaign and which are independent. A regression here would either
over-cluster (merging unrelated user activity through a shared system
ancestor) or under-cluster (failing to spot two detections rooted in the
same dropper). Both bias the operator's read of the host's blast radius.

Run:
    python3 falcon-extras/.venv/bin/python3 falcon-extras/ir/test_campaign_scope.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Import the function as a package-relative module so its sibling imports
# (``from .ancestry import …``) resolve. Add the falcon-extras/ root to
# sys.path so the ``ir`` package is discoverable from any cwd.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ir.campaign_scope import _cluster_by_shared_ancestry  # noqa: E402


def _node(pid: int, image: str | None) -> dict:
    return {"pid": pid, "image": image}


# ---------------------------------------------------------------------------
# Trivial shapes
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty():
    assert _cluster_by_shared_ancestry({}) == {}


def test_single_pivot_no_ancestry_is_its_own_cluster():
    out = _cluster_by_shared_ancestry({1234: []})
    assert out == {1234: [1234]}


def test_single_pivot_with_ancestry_is_its_own_cluster():
    out = _cluster_by_shared_ancestry({
        1234: [_node(900, r"C:\Users\a\dropper.exe"), _node(800, "explorer.exe")],
    })
    assert list(out.values()) == [[1234]]


# ---------------------------------------------------------------------------
# No merge: independent pivots
# ---------------------------------------------------------------------------


def test_two_pivots_no_shared_ancestor_stay_separate():
    out = _cluster_by_shared_ancestry({
        100: [_node(50, r"C:\a\one.exe")],
        200: [_node(60, r"C:\b\two.exe")],
    })
    # Two distinct cluster roots, each containing exactly one pivot.
    pivot_groups = sorted(sorted(v) for v in out.values())
    assert pivot_groups == [[100], [200]]


def test_two_pivots_sharing_only_system_ancestor_stay_separate():
    # explorer.exe is in the system blocklist — must NOT cause a merge.
    out = _cluster_by_shared_ancestry({
        100: [_node(900, r"C:\a\one.exe"), _node(50, "explorer.exe")],
        200: [_node(901, r"C:\b\two.exe"), _node(50, "explorer.exe")],
    })
    pivot_groups = sorted(sorted(v) for v in out.values())
    assert pivot_groups == [[100], [200]]


def test_system_ancestor_basenames_path_normalized():
    # Full Windows path to svchost — basename_lower should pull svchost.exe
    # out and the function should treat it as system.
    out = _cluster_by_shared_ancestry({
        100: [_node(900, r"C:\a\one.exe"), _node(50, r"C:\Windows\System32\svchost.exe")],
        200: [_node(901, r"C:\b\two.exe"), _node(50, r"C:\Windows\System32\svchost.exe")],
    })
    pivot_groups = sorted(sorted(v) for v in out.values())
    assert pivot_groups == [[100], [200]]


# ---------------------------------------------------------------------------
# Merge: shared non-system ancestor
# ---------------------------------------------------------------------------


def test_two_pivots_sharing_non_system_ancestor_merge():
    # Both pivots share pid 999 (a real attacker dropper). MUST merge into
    # one cluster.
    dropper = _node(999, r"C:\Users\victim\dropper.exe")
    out = _cluster_by_shared_ancestry({
        100: [dropper, _node(50, "explorer.exe")],
        200: [dropper, _node(50, "explorer.exe")],
    })
    assert len(out) == 1
    pivots = sorted(next(iter(out.values())))
    assert pivots == [100, 200]


def test_three_pivots_with_transitive_merge():
    # 100↔200 share dropper A (pid 900). 200↔300 share dropper B (pid 901).
    # Result: all three end up in one cluster via transitive union.
    a = _node(900, r"C:\a.exe")
    b = _node(901, r"C:\b.exe")
    out = _cluster_by_shared_ancestry({
        100: [a],
        200: [a, b],
        300: [b],
    })
    assert len(out) == 1
    pivots = sorted(next(iter(out.values())))
    assert pivots == [100, 200, 300]


def test_two_clusters_remain_distinct_when_no_bridge():
    # 100↔200 share A. 300↔400 share B. No process bridges the two pairs.
    a = _node(900, r"C:\a.exe")
    b = _node(901, r"C:\b.exe")
    out = _cluster_by_shared_ancestry({
        100: [a],
        200: [a],
        300: [b],
        400: [b],
    })
    pivot_groups = sorted(sorted(v) for v in out.values())
    assert pivot_groups == [[100, 200], [300, 400]]


# ---------------------------------------------------------------------------
# Defensive: malformed ancestry nodes don't blow up
# ---------------------------------------------------------------------------


def test_ancestry_node_with_no_pid_is_ignored():
    # An ancestry node missing its pid (or with non-int pid) MUST be skipped
    # without crashing. Pivots stay independent.
    out = _cluster_by_shared_ancestry({
        100: [{"image": r"C:\noisy.exe"}],          # no pid
        200: [{"pid": "not an int", "image": "x"}], # bogus pid type
    })
    pivot_groups = sorted(sorted(v) for v in out.values())
    assert pivot_groups == [[100], [200]]


def test_ancestry_node_with_no_image_is_treated_as_non_system():
    # An ancestry node with no image and a real pid SHOULD still anchor a
    # merge — basename_lower(None) is "", which isn't in the system set.
    a_no_image = {"pid": 999}  # no image field at all
    out = _cluster_by_shared_ancestry({
        100: [a_no_image],
        200: [a_no_image],
    })
    assert len(out) == 1
    assert sorted(next(iter(out.values()))) == [100, 200]


def main() -> int:
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  ok   {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e:
            failed += 1
            print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
