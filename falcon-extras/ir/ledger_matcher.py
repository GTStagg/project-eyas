"""Pure ledger-entry → detection matcher for ``extras_ir_close_remediated``.

The Phase 4 closer in the agentic IR workflow walks every open detection on
the host and asks: "did Phase 2 actually touch this?" Each ``remediated[]``
entry from the agent's structured ledger gets matched against an alert's
evidence (process ids, cmdline corpus across alert/parent/behaviors, hashes,
pattern ids). A match closes the detection with a per-id audit string naming
the ledger entry and the field that fired.

Match policy (CLAUDE.md "extras_ir_close_remediated matcher contract"):

* Generous on cmdline substring — case-insensitive, backslashes normalized,
  because the same path appears with different quoting / casing across
  alert.cmdline vs parent_details.cmdline vs behaviors[].cmdline /
  behaviors[].ioc_value / behaviors[].filepath.
* Strict on identifiers — pid / sha256 / md5 / pattern_id / WMI filter_name
  must equal exactly (substring on those would over-close).
* Host/network state changes — containment, lift, reboot — are NOT remediation
  and never close a detection: isolating or rebooting a host doesn't remove the
  threat (persistence survives a reboot). A detection closes only when a ledger
  entry names the specific artifact (pid / hash / path / …) that was acted on.
* Unknown / "other" kinds never match — they're notes, not actions.

Adding a new remediation primitive: add a ``kind ==`` branch here, add a
Phase 2 instruction in ``lib/eyas-tools/playbooks/ir.ts`` telling the agent to emit that
ledger entry on success, and add a unit test exercising the matcher branch.
"""

from __future__ import annotations

import re
from typing import Any

# Minimum length for a basename / name to be eligible for the *bounded-token*
# cmdline fallback. Short common tokens (cmd.exe, time, run) substring-match
# huge swaths of the queue, closing detections nothing remediated. The matcher
# biases toward UNDER-close (an unmatched detection stays open for operator
# review; an over-matched one hides a real threat), so the fallback only fires
# for distinctive names. Exact-identifier matches (pid/sha/md5/pattern_id) and
# exact-basename-equality against the alert's own process image are unaffected.
_BOUNDED_TOKEN_FLOOR = 6


def _bounded_token_in_blob(needle: str, blob: str) -> bool:
    """True when ``needle`` appears in ``blob`` as a delimited token — bounded
    on each side by something that is NOT a word char or a dot (path separator,
    quote, whitespace, comma, paren, or string edge) — rather than a bare
    substring. ``cmd.exe`` will not match inside ``cmd.exe.bak`` or a longer
    word; a service named ``time`` will not match ``runtime``. Inputs are
    expected already lowercased + backslash-normalized (see _alert_cmdline_corpus).
    Caller enforces the length floor."""
    if not needle or not blob:
        return False
    return re.search(r"(?<![\w.])" + re.escape(needle) + r"(?![\w.])", blob) is not None


def _norm_path(p: str | None) -> str:
    if not p or not isinstance(p, str):
        return ""
    return p.lower().replace("/", "\\").strip().rstrip("\\")


def _alert_cmdline_corpus(alert: dict[str, Any]) -> str:
    """Join every cmdline-bearing field on an alert into one searchable
    blob (lowercased, backslashes normalized). Substring matches against
    this catch path / filename / URL artifacts regardless of which source
    emitted them."""
    parts: list[str] = []
    cl = alert.get("cmdline")
    if isinstance(cl, str):
        parts.append(cl)
    pd = alert.get("parent_details")
    if isinstance(pd, dict):
        pcl = pd.get("cmdline")
        if isinstance(pcl, str):
            parts.append(pcl)
    for b in alert.get("behaviors") or []:
        if isinstance(b, dict):
            for k in ("cmdline", "ioc_value", "filepath", "filename"):
                v = b.get(k)
                if isinstance(v, str):
                    parts.append(v)
    return " ".join(parts).lower().replace("/", "\\")


def _alert_image_basenames(alert: dict[str, Any]) -> set[str]:
    """Basenames of every process-IMAGE field on an alert — the files the
    detection is *about*, as opposed to strings that merely appear in a command
    line. ``process_killed image=cmd.exe`` should match a detection whose
    process IS cmd.exe, not one whose cmdline happens to mention it. Lowercased
    + backslash-normalized to match the ledger image normalization."""
    out: set[str] = set()

    def add(v: Any) -> None:
        if isinstance(v, str) and v:
            base = v.lower().replace("/", "\\").rsplit("\\", 1)[-1]
            if base:
                out.add(base)

    for k in ("filename", "filepath", "image_filename", "image_file_name"):
        add(alert.get(k))
    for b in alert.get("behaviors") or []:
        if isinstance(b, dict):
            for k in ("filename", "filepath"):
                add(b.get(k))
    return out


def _alert_pids(alert: dict[str, Any]) -> set[str]:
    """All Falcon graph pids referenced by an alert (top-level + behaviors).
    Returned as strings so int/str ledger values both compare cleanly."""
    pids: set[str] = set()
    for k in ("process_id",):
        v = alert.get(k)
        if v is not None:
            pids.add(str(v))
    for b in alert.get("behaviors") or []:
        if isinstance(b, dict):
            for k in ("process_id", "target_process_id"):
                v = b.get(k)
                if v is not None:
                    pids.add(str(v))
    return pids


def _alert_hashes(alert: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for b in alert.get("behaviors") or []:
        if isinstance(b, dict):
            for k in ("sha256", "md5"):
                v = b.get(k)
                if isinstance(v, str) and v:
                    out.add(v.lower())
            iv = b.get("ioc_value")
            it = (b.get("ioc_type") or "").lower()
            if isinstance(iv, str) and it in {"sha256", "hash_sha256", "md5", "hash_md5"}:
                out.add(iv.lower())
    return out


def _alert_pattern_ids(alert: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for b in alert.get("behaviors") or []:
        if isinstance(b, dict):
            v = b.get("pattern_id")
            if v is not None:
                out.add(str(v))
    return out


def ledger_entry_matches_alert(
    entry: dict[str, Any], alert: dict[str, Any]
) -> tuple[bool, str | None]:
    """Return ``(matched, reason)``. ``reason`` is the human-readable evidence
    string for the audit trail (or ``None`` when not matched)."""
    kind = (entry.get("kind") or "").lower()

    cmdline_blob = _alert_cmdline_corpus(alert)
    pids = _alert_pids(alert)
    hashes = _alert_hashes(alert)
    pattern_ids = _alert_pattern_ids(alert)
    image_basenames = _alert_image_basenames(alert)

    if kind == "process_killed":
        pid = entry.get("pid")
        if pid is not None and str(pid) in pids:
            return True, f"process_killed pid={pid} matches alert pid"
        image = entry.get("image")
        if isinstance(image, str) and image:
            base = image.lower().replace("/", "\\").rsplit("\\", 1)[-1]
            # Exact basename equality against the alert's OWN process image —
            # "I killed X" matches "the detection is *about* X", not "X appears
            # somewhere in a command line". No cmdline fallback here on purpose:
            # a killed common interpreter (cmd.exe, powershell.exe) is mentioned
            # in countless unrelated cmdlines, and a bare-token cmdline match
            # would close them all. Process identity is pid + image, nothing else.
            if base and base in image_basenames:
                return True, f"process_killed image={base} matches alert process image"
        return False, None

    if kind in {"file_quarantined", "file_deleted"}:
        sha = (entry.get("sha256") or "").lower()
        md5 = (entry.get("md5") or "").lower()
        if sha and sha in hashes:
            return True, f"{kind} sha256={sha[:12]}… matches alert hash"
        if md5 and md5 in hashes:
            return True, f"{kind} md5={md5[:12]}… matches alert hash"
        path = _norm_path(entry.get("path"))
        # Full-path substring stays — a full path is specific enough to be safe.
        if path and path in cmdline_blob:
            return True, f"{kind} path={entry.get('path')} appears in cmdline"
        if path:
            base = path.rsplit("\\", 1)[-1]
            if base and len(base) >= _BOUNDED_TOKEN_FLOOR and _bounded_token_in_blob(base, cmdline_blob):
                return True, f"{kind} filename={base} appears as a delimited token in cmdline"
        return False, None

    if kind == "folder_deleted":
        path = _norm_path(entry.get("path"))
        if path and path in cmdline_blob:
            return True, f"folder_deleted path={entry.get('path')} appears in cmdline"
        return False, None

    if kind == "registry_reverted":
        # Match the full normalized registry path as a *delimited token*
        # (consistent with the rest of the matcher), not a bare bidirectional
        # substring. The old `path in iv or iv in path` over-closed two ways:
        # the reverse direction let a short generic ioc_value fragment (e.g.
        # "run") match inside a longer ledger path, and the forward bare
        # substring let a "…\\Run\\EvilApp" ledger entry close a
        # "…\\Run\\EvilAppData" detection. Bounded-token + floor biases to
        # UNDER-close. The leaf-image-in-IFEO case is handled by `ifeo_removed`.
        path = _norm_path(entry.get("path"))
        if path and len(path) >= _BOUNDED_TOKEN_FLOOR:
            for b in alert.get("behaviors") or []:
                if isinstance(b, dict):
                    iv = (b.get("ioc_value") or "").lower().replace("/", "\\")
                    if iv and _bounded_token_in_blob(path, iv):
                        return True, f"registry_reverted path={entry.get('path')} matches behavior.ioc_value"
            if _bounded_token_in_blob(path, cmdline_blob):
                return True, f"registry_reverted path={entry.get('path')} appears in cmdline"
        return False, None

    if kind == "ifeo_removed":
        image = entry.get("image")
        if isinstance(image, str) and image:
            base = image.lower().rsplit("\\", 1)[-1]
            for b in alert.get("behaviors") or []:
                if isinstance(b, dict):
                    iv = (b.get("ioc_value") or "").lower()
                    if iv and ("image file execution options" in iv or "\\ifeo\\" in iv) and base in iv:
                        return True, f"ifeo_removed image={base} matches IFEO behavior.ioc_value"
        return False, None

    if kind == "ioa_pattern_excluded":
        pid = entry.get("pattern_id")
        if pid is not None and str(pid) in pattern_ids:
            return True, f"ioa_pattern_excluded pattern_id={pid} matches behavior.pattern_id"
        return False, None

    if kind == "ml_exclusion_added":
        sha = (entry.get("sha256") or "").lower()
        if sha and sha in hashes:
            return True, f"ml_exclusion_added sha256={sha[:12]}… matches alert hash"
        path = _norm_path(entry.get("path"))
        if path and path in cmdline_blob:
            return True, f"ml_exclusion_added path={entry.get('path')} appears in cmdline"
        return False, None

    if kind == "ioc_added":
        v = (entry.get("value") or "")
        t = (entry.get("type") or "").lower()
        if not v:
            return False, None
        vlow = v.lower()
        if t in {"sha256", "md5"} and vlow in hashes:
            return True, f"ioc_added {t}={vlow[:12]}… matches alert hash"
        if vlow in cmdline_blob:
            return True, f"ioc_added {t}={v} appears in cmdline"
        return False, None

    if kind == "rat_uninstalled":
        # Image-basename only — the generic `product` substring (e.g. "AnyDesk"
        # in any cmdline mentioning anydesk) over-closed. Match the binary the
        # same way process_killed does: exact basename equality, then a bounded
        # distinctive-token cmdline fallback.
        image = entry.get("image") or ""
        if isinstance(image, str) and image:
            base = image.lower().replace("/", "\\").rsplit("\\", 1)[-1]
            if base and base in image_basenames:
                return True, f"rat_uninstalled image={base} matches alert process image"
            if base and len(base) >= _BOUNDED_TOKEN_FLOOR and _bounded_token_in_blob(base, cmdline_blob):
                return True, f"rat_uninstalled image={base} appears as a delimited token in cmdline"
        return False, None

    if kind in {"service_removed", "scheduled_task_removed"}:
        name = entry.get("service_name") or entry.get("task_name") or ""
        if (
            isinstance(name, str)
            and len(name) >= _BOUNDED_TOKEN_FLOOR
            and _bounded_token_in_blob(name.lower(), cmdline_blob)
        ):
            return True, f"{kind} name={name} appears as a delimited token in cmdline"
        return False, None

    if kind == "wmi_persistence_removed":
        # Match by exact filter_name (case-insensitive), bounded so a short or
        # common filter name can't substring-match unrelated telemetry. Random
        # attacker-generated names mean substring fuzziness is unsafe.
        fname = (entry.get("filter_name") or "").lower()
        if fname and len(fname) >= _BOUNDED_TOKEN_FLOOR:
            for b in alert.get("behaviors") or []:
                if isinstance(b, dict):
                    iv = (b.get("ioc_value") or "").lower()
                    if iv and _bounded_token_in_blob(fname, iv):
                        return True, f"wmi_persistence_removed filter_name={entry.get('filter_name')} matches behavior.ioc_value"
            if _bounded_token_in_blob(fname, cmdline_blob):
                return True, f"wmi_persistence_removed filter_name={entry.get('filter_name')} appears in cmdline"
        return False, None

    # host_contained / host_lifted / host_rebooted (host/network state changes,
    # not per-detection remediation), plus unknown / "other" / unmappable:
    # never match. A detection closes only on a specific-artifact match above.
    return False, None
