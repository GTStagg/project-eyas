"""Delivery-vector classifier for process-tree ancestry chains.

Pure-function: given an ordered ancestry list (pivot at index 0, walking
upward toward the root) it returns the {kind, confidence, rationale, ...}
verdict that drives the IR playbook's Phase 0 decision logic.

The point of the classifier is to convert "process X fired a detection"
into "this attack arrived via Y" so the operator's Phase 2 response
includes the delivery channel (pull email, audit browser, isolate lateral
source) and not just the on-host cleanup.

Walking rules:

- Anchors are images that explain *how* the attack started (Outlook,
  Chrome, WINWORD, services.exe, wsmprovhost.exe, ...).
- We walk pivot→root and look for the *most specific* anchor; if both an
  Office app AND a mail client are in the chain, that's a phishing-doc
  delivery (more specific) rather than direct phishing-email or generic
  malicious-doc.
- Confidence is "high" when an explicit anchor matches without widening
  the time-window, "medium" when the parent had to be looked up outside
  the normal window, "low" when only a LOLBin or unknown-ancestor fits.

Per-node verdicts (for UI rendering only — they don't drive logic):

  initial-access-anchor  — the matched anchor row.
  office-with-doc        — Office image + doc cmdline.
  lolbin                 — cmd / powershell / wscript / cscript / mshta /
                           regsvr32 / rundll32 mid-chain.
  signed-system          — services.exe / svchost.exe / explorer.exe etc.
  malicious              — pivot itself or descendants flagged by the
                           detection record (set by the caller, not here).
  unknown                — anything else.
"""

from __future__ import annotations

import os
import re
from typing import Any


# --- Anchor catalog ---------------------------------------------------------
#
# Each entry: (image_basename_lowercase, anchor_kind). The anchor_kind drives
# the second-pass logic in classify_delivery_vector.

MAIL_CLIENTS = {
    "outlook.exe",
    "olk.exe",
    "hxoutlook.exe",
    "thunderbird.exe",
    "lync.exe",
}

OFFICE_APPS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "msaccess.exe",
    "mspub.exe",
    "visio.exe",
    "onenote.exe",
    "outlook.exe",  # Outlook is here too (spawn-from-mail-attachment edge)
}

BROWSERS = {
    "chrome.exe",
    "msedge.exe",
    "iexplore.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "safari.exe",
}

ARCHIVE_TOOLS = {
    "7zfm.exe",
    "7zg.exe",
    "winrar.exe",
    "rar.exe",
    "bandizip.exe",
    "peazip.exe",
}

LOLBINS = {
    "cmd.exe",
    "powershell.exe",
    "powershell_ise.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "msbuild.exe",
}

# Interpreter / runtime hosts that frequently host C2 agents (sliver,
# havoc, mythic, custom python implants). The interpreter image alone
# doesn't classify — we additionally require a cmdline matching one of
# C2_AGENT_CMDLINE_RX so legit Python tooling (build scripts, jupyter)
# doesn't get false-positived.
C2_AGENT_HOSTS = {
    "python.exe",
    "pythonw.exe",
    "python3.exe",
    "python3.12.exe",
    "py.exe",
    "node.exe",
    "ruby.exe",
    "perl.exe",
}

# Cmdline patterns that strongly suggest an interpreter is hosting a
# remote-control beacon: explicit C2 server URLs, beacon/agent script
# names, listener ports, common C2 framework runtime args.
C2_AGENT_CMDLINE_RX = re.compile(
    r"""(
        --server\s+https?://         # `--server http://10.x.x.x:4444` (sliver, agent.py style)
      | -c2\s                        # `-c2 host:port` (havoc, brc4)
      | --c2-?(server|host|url)\s    # `--c2-server`, `--c2host`
      | --listener\s                 # `--listener http`
      | --beacon[=\s]                # `--beacon`
      | \\agent[\w-]*\.py\b          # `agent-windows.py`, `agent.py`, `agent_x64.py`
      | \\beacon[\w-]*\.py\b
      | \\implant[\w-]*\.py\b
      | \\sliver[\w-]*\.(py|exe)\b
      | \\(mythic|havoc|brc4|cobalt)
      | https?://[\w.\-]+:\d{4,5}\b  # bare `http://host:4444` style (port 4xxx-9xxx)
    )""",
    re.IGNORECASE | re.VERBOSE,
)

SYSTEM_HOSTS = {
    "services.exe",
    "svchost.exe",
    "winlogon.exe",
    "userinit.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "explorer.exe",
}

LATERAL_HOSTS = {
    "wsmprovhost.exe",       # WinRM remoting target
    "psexesvc.exe",
    "paexec.exe",
    "remcomsvc.exe",
}

SCHED_HOSTS = {
    "taskhostw.exe",
    "taskhost.exe",
    "schtasks.exe",
}

WMI_HOSTS = {
    "wmiprvse.exe",
    "scrcons.exe",
}

# Email-temp-path substrings that indicate an Office process opened a
# document originating from an email attachment. Case-insensitive match
# against the cmdline.
EMAIL_TEMP_FRAGMENTS = (
    "\\inetcache\\content.outlook\\",
    "\\temporary internet files\\content.outlook",
    "\\appdata\\local\\microsoft\\olk\\",
    "\\appdata\\roaming\\microsoft\\outlook\\",
)

# User-download / staging path substrings — used for browser-driveby and
# user-executed-dropper classification.
USER_DROP_FRAGMENTS = (
    "\\downloads\\",
    "\\desktop\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
)


ANCHOR_CATALOG = {
    "mail": MAIL_CLIENTS,
    "office": OFFICE_APPS,
    "browser": BROWSERS,
    "archive": ARCHIVE_TOOLS,
    "lolbin": LOLBINS,
    "system": SYSTEM_HOSTS,
    "lateral": LATERAL_HOSTS,
    "scheduled": SCHED_HOSTS,
    "wmi": WMI_HOSTS,
}


def _basename(image: str | None) -> str:
    if not image:
        return ""
    # Handle both forward and backslashes; ProcessRollup2 ImageFileName is
    # typically `\Device\HarddiskVolume3\Windows\System32\cmd.exe`.
    parts = re.split(r"[\\/]", image)
    return (parts[-1] if parts else image).lower()


def _has(images: list[str], catalog: set[str]) -> int | None:
    """Return the lowest depth (closest to pivot) where catalog matches,
    or None. Index 0 = pivot itself."""
    for i, img in enumerate(images):
        if img in catalog:
            return i
    return None


def _is_c2_agent(image: str, cmdline: str) -> bool:
    """An interpreter image whose cmdline matches a C2-beacon pattern.
    Distinct from a plain lolbin because the *runtime* (python, node) is
    legitimate but the *script it's running* is the implant — same shape
    as a malicious-doc-with-Office, just for interpreters."""
    if _basename(image) not in C2_AGENT_HOSTS:
        return False
    return bool(C2_AGENT_CMDLINE_RX.search(cmdline or ""))


def _node_verdict(image: str, cmdline: str) -> str:
    img = _basename(image)
    cmd = (cmdline or "").lower()
    if _is_c2_agent(image, cmdline):
        return "c2-agent"
    if img in OFFICE_APPS and any(p in cmd for p in EMAIL_TEMP_FRAGMENTS):
        return "office-with-doc"
    if img in OFFICE_APPS and re.search(
        r"\.(docm?|xlsm?|xlsb|pptm?|ppam?|dotm|xlam|rtf)\b", cmd
    ):
        return "office-with-doc"
    if img in LOLBINS:
        return "lolbin"
    if img in MAIL_CLIENTS or img in BROWSERS or img in ARCHIVE_TOOLS:
        return "initial-access-anchor"
    if img in SYSTEM_HOSTS:
        return "signed-system"
    if img in LATERAL_HOSTS:
        return "initial-access-anchor"
    if img in SCHED_HOSTS:
        return "signed-system"
    if img in WMI_HOSTS:
        return "signed-system"
    return "unknown"


def annotate_node_verdicts(ancestry: list[dict[str, Any]]) -> None:
    """Mutates each node in the ancestry list to add a `verdict` field used
    for UI rendering. Called after the classifier so the matched anchor
    can be marked initial-access-anchor specifically."""
    for node in ancestry:
        if "verdict" not in node:
            node["verdict"] = _node_verdict(
                node.get("image", ""), node.get("cmdline", "")
            )


def classify_delivery_vector(
    ancestry: list[dict[str, Any]],
    *,
    window_widened: bool = False,
) -> dict[str, Any]:
    """Walk the ancestry chain and produce a delivery-vector verdict.

    Args:
        ancestry: Ordered list of process nodes, pivot at index 0, walking
            upward toward init/root. Each node: {pid, image, cmdline,
            user?, signed?, ts?}.
        window_widened: True if the ancestry walk had to widen the search
            window to find a parent (downgrades confidence one tier).

    Returns:
        {kind, confidence, rationale, initial_access_pid?,
         initial_access_image?, weaponized_artifact?}
    """
    if not ancestry:
        return {
            "kind": "unknown",
            "confidence": "low",
            "rationale": "No ancestry data available for the pivot process.",
        }

    images = [_basename(n.get("image")) for n in ancestry]

    def _node(idx: int) -> dict[str, Any]:
        return ancestry[idx]

    def _emit(
        kind: str,
        confidence: str,
        rationale: str,
        anchor_idx: int | None = None,
        weaponized_artifact: str | None = None,
    ) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": kind,
            "confidence": confidence,
            "rationale": rationale,
        }
        if anchor_idx is not None and 0 <= anchor_idx < len(ancestry):
            anchor = _node(anchor_idx)
            out["initial_access_pid"] = anchor.get("pid")
            out["initial_access_image"] = anchor.get("image")
            ancestry[anchor_idx]["verdict"] = "initial-access-anchor"
        if weaponized_artifact:
            out["weaponized_artifact"] = weaponized_artifact
        # Confidence demotion if we widened the window.
        if window_widened and confidence == "high":
            out["confidence"] = "medium"
        return out

    # --- Phishing doc: Office in chain, optionally rooted in mail client.
    office_idx = _has(images, OFFICE_APPS)
    mail_idx = _has(images, MAIL_CLIENTS)

    if office_idx is not None:
        office = _node(office_idx)
        office_cmd = (office.get("cmdline") or "").lower()
        weaponized = _extract_doc_path(office.get("cmdline") or "")
        is_email_temp = any(p in office_cmd for p in EMAIL_TEMP_FRAGMENTS)
        if mail_idx is not None and mail_idx > office_idx:
            return _emit(
                "phishing_doc",
                "high",
                f"{_basename(_node(mail_idx).get('image')).upper()} → "
                f"{_basename(office.get('image')).upper()} opened "
                f"{weaponized or 'a document'} before child process spawn",
                anchor_idx=mail_idx,
                weaponized_artifact=weaponized,
            )
        if is_email_temp:
            return _emit(
                "phishing_doc",
                "high",
                f"{_basename(office.get('image')).upper()} opened "
                f"{weaponized or 'a document'} from an email-attachment temp path",
                anchor_idx=office_idx,
                weaponized_artifact=weaponized,
            )
        # Office without mail-client ancestry and without email-temp path
        # — could still be malicious, but the channel is unclear (network
        # share, USB, manually-saved doc). Lower-stakes vector.
        return _emit(
            "malicious_document_lateral",
            "medium",
            f"{_basename(office.get('image')).upper()} spawned malicious child "
            f"chain from {weaponized or 'a document'}; no mail-client ancestor",
            anchor_idx=office_idx,
            weaponized_artifact=weaponized,
        )

    # --- Direct phishing email: mail client → pivot without Office.
    if mail_idx is not None:
        return _emit(
            "phishing_email_direct",
            "high",
            f"{_basename(_node(mail_idx).get('image')).upper()} spawned the "
            f"malicious chain directly (likely an executable/script attachment)",
            anchor_idx=mail_idx,
        )

    # --- Browser drive-by.
    browser_idx = _has(images, BROWSERS)
    if browser_idx is not None:
        # Only call it browser-drive-by if the pivot or a near-descendant
        # spawned from a Downloads/Temp path; otherwise the browser is
        # likely a sibling in the chain (user clicked an .exe, etc.).
        leaked_drop = _find_drop_path(ancestry, USER_DROP_FRAGMENTS)
        if leaked_drop:
            return _emit(
                "browser_drive_by",
                "medium",
                f"{_basename(_node(browser_idx).get('image')).upper()} ancestry "
                f"with malicious child executing from {leaked_drop}",
                anchor_idx=browser_idx,
                weaponized_artifact=leaked_drop,
            )
        return _emit(
            "browser_drive_by",
            "low",
            f"{_basename(_node(browser_idx).get('image')).upper()} in ancestry "
            f"but no Downloads/Temp drop path identified",
            anchor_idx=browser_idx,
        )

    # --- Archive extraction (user double-clicked a zip).
    archive_idx = _has(images, ARCHIVE_TOOLS)
    if archive_idx is not None:
        return _emit(
            "archive_extraction",
            "medium",
            f"{_basename(_node(archive_idx).get('image')).upper()} extracted "
            f"and the resulting payload spawned the malicious chain",
            anchor_idx=archive_idx,
        )

    # --- Lateral movement (WinRM, PsExec).
    lateral_idx = _has(images, LATERAL_HOSTS)
    if lateral_idx is not None:
        img = _basename(_node(lateral_idx).get("image"))
        if img == "wsmprovhost.exe":
            return _emit(
                "lateral_winrm",
                "high",
                "WinRM remoting target host process is a direct ancestor — "
                "another tenant host invoked PowerShell remoting against this AID",
                anchor_idx=lateral_idx,
            )
        return _emit(
            "lateral_psexec",
            "high",
            f"{img.upper()} (PsExec-class service) is a direct ancestor — "
            "another host invoked SMB-based lateral execution",
            anchor_idx=lateral_idx,
        )

    # --- Scheduled-task / service / WMI persistence anchors.
    sched_idx = _has(images, SCHED_HOSTS)
    if sched_idx is not None and sched_idx >= 1:
        return _emit(
            "scheduled_task_persistence",
            "medium",
            "Scheduled-task host is a direct ancestor — payload was launched "
            "by a previously-installed task (persistence trigger)",
            anchor_idx=sched_idx,
        )

    wmi_idx = _has(images, WMI_HOSTS)
    if wmi_idx is not None:
        return _emit(
            "wmi_persistence",
            "medium",
            "WMI provider host is a direct ancestor — payload was launched "
            "by a previously-installed __EventConsumer (T1546.003)",
            anchor_idx=wmi_idx,
        )

    # --- Explorer / dropper (user double-clicked an exe in Downloads).
    explorer_idx = next(
        (i for i, img in enumerate(images) if img == "explorer.exe"), None
    )
    if explorer_idx is not None:
        leaked_drop = _find_drop_path(ancestry, USER_DROP_FRAGMENTS)
        if leaked_drop:
            return _emit(
                "user_executed_dropper",
                "medium",
                f"explorer.exe spawned the chain from {leaked_drop} — user "
                f"likely double-clicked an executable in a download/staging path",
                anchor_idx=explorer_idx,
                weaponized_artifact=leaked_drop,
            )

    # --- C2-agent runtime in the chain (python/node hosting an implant).
    # Walk pivot→root looking for an interpreter row whose cmdline
    # matches the C2 pattern. Place AFTER mail/Office/browser anchors
    # because if Outlook is the root and python is the implant in the
    # middle, the delivery vector is still phishing — but BEFORE the
    # lolbin/explorer/services fallbacks because a python C2 explains
    # the chain better than "the chain terminates at powershell".
    c2_idx: int | None = None
    for i, node in enumerate(ancestry):
        if _is_c2_agent(node.get("image", ""), node.get("cmdline", "")):
            c2_idx = i
            break
    if c2_idx is not None:
        c2_node = _node(c2_idx)
        c2_image = _basename(c2_node.get("image"))
        # Try to extract the C2 server URL from the cmdline for the
        # rationale — that's the IOC the operator hunts on.
        url_match = re.search(
            r"https?://[\w.\-]+(?::\d+)?(?:/\S*)?",
            (c2_node.get("cmdline") or ""),
        )
        c2_url = url_match.group(0) if url_match else None
        return _emit(
            "c2_agent",
            "high",
            f"{c2_image} hosting an implant"
            + (f" beaconing to {c2_url}" if c2_url else "")
            + " — the interpreter runtime is legitimate, the script it's "
            "running is the malicious payload (T1059)",
            anchor_idx=c2_idx,
            weaponized_artifact=c2_url,
        )

    # --- Highest non-system ancestor is a LOLBin → initial-LOLBin.
    lolbin_idx = _has(images, LOLBINS)
    if lolbin_idx is not None and lolbin_idx == len(ancestry) - 1:
        return _emit(
            "lolbin_initial",
            "low",
            f"Chain terminates at {_basename(_node(lolbin_idx).get('image')).upper()} "
            "with no upstream context (mail/browser parent may have aged out of the window)",
            anchor_idx=lolbin_idx,
        )

    # --- Service-spawned binary.
    svc_idx = next(
        (i for i, img in enumerate(images) if img == "services.exe"), None
    )
    if svc_idx is not None and svc_idx >= 1:
        return _emit(
            "malicious_service",
            "medium",
            "services.exe is a direct ancestor — payload runs under a Windows "
            "service the attacker installed for persistence",
            anchor_idx=svc_idx,
        )

    # --- Fallback: nothing fit.
    return {
        "kind": "unknown",
        "confidence": "low",
        "rationale": (
            "Ancestry chain has no recognized initial-access anchor "
            "(mail/browser/Office/archive/lateral/persistence). Sensor data "
            "may have aged out of the search window, or the chain is rooted "
            "in a context not yet covered by the classifier."
        ),
    }


# --- Helpers ---------------------------------------------------------------


_DOC_PATH_RX = re.compile(
    r"""['"]?([A-Za-z]:\\[^'"<>|]+?\.(?:docm?|xlsm?|xlsb|pptm?|ppam?|dotm|xlam|rtf|pdf))['"]?""",
    re.IGNORECASE,
)


def _extract_doc_path(cmdline: str) -> str | None:
    """Pull the first plausible Office-document path out of an Office-app
    cmdline. Returns None when nothing matches — the rationale falls back
    to a generic 'a document' string."""
    if not cmdline:
        return None
    m = _DOC_PATH_RX.search(cmdline)
    return m.group(1) if m else None


def _find_drop_path(
    ancestry: list[dict[str, Any]], fragments: tuple[str, ...]
) -> str | None:
    """Walk the chain looking for an image path or cmdline mentioning a
    user-drop fragment. Returns the first hit (image-path preferred over
    cmdline)."""
    for node in ancestry:
        img = (node.get("image") or "").lower()
        for frag in fragments:
            if frag in img:
                return node.get("image")
        cmd = (node.get("cmdline") or "").lower()
        for frag in fragments:
            if frag in cmd:
                # Try to extract a path from the cmdline; otherwise return
                # the fragment itself so the rationale has *something*.
                m = re.search(r"[A-Za-z]:\\[^\s'\"<>|]+", node.get("cmdline") or "")
                if m:
                    return m.group(0)
                return frag
    return None
