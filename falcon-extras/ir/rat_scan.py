"""IR Phase 0 RAT-install thorough scan.

Detection-time-window NGSIEM query that catches historical installs of
known remote-access tooling (RATs / RMMs) even when the installer process
has long since exited. Complementary to the cheap ``Process``
falconscript pass which only catches currently-running RATs.

Driven by ATT&CK T1219: attackers routinely install legitimate, signed
RATs alongside malicious activity so the access channel survives the
cleanup of the original detection. The catalog here is a deliberately-
narrow list of products that flag as suspicious in the field when
unexpected — corp-managed agents (SCCM, Intune, Tanium) are intentionally
excluded.

Findings are grouped by canonical tool name so two AnyDesk executions
with different installer paths collapse into one item with both paths
captured. Phase 0's invariant: every returned item must map to a Phase 2
cleanup action.
"""

from __future__ import annotations

import re
import time
from typing import Any

from falcon_helpers import swallow_exc

from ngsiem.search import run_ngsiem_search


# Known remote-access-tool image-name catalog. Each entry is
# ``(regex_alternation_atom, canonical_tool, family)``. The regex atoms
# are joined into one CQL alternation; a match on the image basename
# routes to the canonical tool name (used to dedupe + classify findings)
# and a family bucket the playbook can act on.
_RAT_IMAGE_CATALOG: list[tuple[str, str, str]] = [
    (r"AnyDesk[\w]*", "AnyDesk", "anydesk"),
    (r"TeamViewer[\w]*", "TeamViewer", "teamviewer"),
    (r"ScreenConnect[\w.]*", "ConnectWise ScreenConnect", "screenconnect"),
    (r"ConnectWiseControl[\w.]*", "ConnectWise ScreenConnect", "screenconnect"),
    (r"AteraAgent[\w]*", "Atera RMM", "atera"),
    (r"Splashtop[\w]*", "Splashtop", "splashtop"),
    (r"SRStreamer[\w]*", "Splashtop", "splashtop"),
    (r"RustDesk[\w]*", "RustDesk", "rustdesk"),
    (r"Supremo[\w]*", "Supremo", "supremo"),
    (r"client32", "NetSupport Manager", "netsupport"),
    (r"NSM[\w]*", "NetSupport Manager", "netsupport"),
    (r"tvnserver", "TightVNC", "tightvnc"),
    (r"winvnc[\w]*", "UltraVNC / TightVNC", "vnc"),
    (r"vncserver[\w]*", "VNC", "vnc"),
    (r"DWAGENT[\w]*", "DWService", "dwservice"),
    (r"dwagsvc[\w]*", "DWService", "dwservice"),
    (r"rutserv[\w]*", "Remote Utilities", "remoteutilities"),
    (r"rfusclient[\w]*", "Remote Utilities", "remoteutilities"),
    (r"LogMeIn[\w]*", "LogMeIn", "logmein"),
    (r"g2[mw][\w]*", "GoToAssist / GoToMyPC", "gotomypc"),
    (r"AgentMon[\w]*", "Kaseya VSA", "kaseya"),
    (r"KaseyaAgent[\w]*", "Kaseya VSA", "kaseya"),
    (r"NinjaRMMAgent[\w]*", "NinjaOne (NinjaRMM)", "ninjaone"),
    (r"PulsewayAgent[\w]*", "Pulseway", "pulseway"),
    (r"Action1Agent[\w]*", "Action1", "action1"),
    (r"chromeremotedesktophost", "Chrome Remote Desktop", "chromeremote"),
]


def _classify_rat_image(image_path: str) -> tuple[str | None, str | None]:
    """Match an image path against the RAT catalog. Returns
    ``(tool, family)`` or ``(None, None)`` when no match. Match runs
    against the basename; tool returned is the canonical display name
    from the first matching atom.
    """
    if not image_path:
        return None, None
    basename = image_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    for atom, tool, family in _RAT_IMAGE_CATALOG:
        if re.fullmatch(atom + r"\.exe", basename, re.IGNORECASE):
            return tool, family
    return None, None


def host_rat_install_scan(device_id: str, hours_back: int = 48) -> dict[str, Any]:
    try:
        if not isinstance(device_id, str) or not re.fullmatch(
            r"[a-fA-F0-9]{32}", device_id
        ):
            return {"ok": False, "error": "device_id must be a 32-char hex AID"}
        if not isinstance(hours_back, int) or hours_back < 1 or hours_back > 168:
            return {"ok": False, "error": "hours_back must be an integer in 1-168"}

        # CQL: full-match-anchored regex per CLAUDE.md NGSIEM syntax block;
        # double-quote the AID literal; head(N) not limit(N). 500 rows max.
        rat_alt = "|".join(atom for atom, _, _ in _RAT_IMAGE_CATALOG)
        cql = (
            f'#event_simpleName=ProcessRollup2 aid="{device_id}"\n'
            f"| ImageFileName=/.*\\\\(?:{rat_alt})\\.exe$/i\n"
            f"| select([@timestamp, ImageFileName, CommandLine, "
            f"ParentBaseFileName, FileSignInfo, UserName])\n"
            f"| sort(@timestamp, order=desc, limit=500)\n"
            f"| head(500)"
        )

        now_ms = int(time.time() * 1000)
        start_ms = now_ms - hours_back * 3600 * 1000

        BUDGET_S = 50.0
        events, ngsiem_err = run_ngsiem_search(
            cql, start_ms, now_ms, budget_s=BUDGET_S
        )
        if ngsiem_err is not None:
            return ngsiem_err
        if events is None:
            return {
                "ok": True,
                "items": [],
                "truncated": True,
                "note": (
                    f"NGSIEM search did not complete within {int(BUDGET_S)}s. "
                    "Re-run with a smaller hours_back, or fall back to the "
                    "Process falconscript for currently-running RATs only."
                ),
            }

        # Group by canonical tool name. For each tool keep first/last seen
        # timestamps, exec count, distinct image paths, the most common
        # parent / signer / user, and a representative command line.
        groups: dict[str, dict[str, Any]] = {}
        for ev in events:
            if not isinstance(ev, dict):
                continue
            image = str(ev.get("ImageFileName") or "")
            tool, family = _classify_rat_image(image)
            if not tool:
                continue
            ts = ev.get("@timestamp")
            try:
                ts_int = int(ts) if ts is not None else None
            except (TypeError, ValueError):
                ts_int = None
            g = groups.setdefault(
                tool,
                {
                    "tool": tool,
                    "family": family,
                    "image_paths": set(),
                    "command_lines": [],
                    "parents": {},
                    "signers": {},
                    "users": {},
                    "exec_count": 0,
                    "first_seen_ms": None,
                    "last_seen_ms": None,
                },
            )
            g["image_paths"].add(image)
            cmd = str(ev.get("CommandLine") or "")
            if cmd and len(g["command_lines"]) < 3:
                g["command_lines"].append(cmd[:240])
            for field, key in (
                ("ParentBaseFileName", "parents"),
                ("FileSignInfo", "signers"),
                ("UserName", "users"),
            ):
                v = ev.get(field)
                if v:
                    g[key][str(v)] = g[key].get(str(v), 0) + 1
            g["exec_count"] += 1
            if ts_int is not None:
                if g["first_seen_ms"] is None or ts_int < g["first_seen_ms"]:
                    g["first_seen_ms"] = ts_int
                if g["last_seen_ms"] is None or ts_int > g["last_seen_ms"]:
                    g["last_seen_ms"] = ts_int

        def _top(d: dict[str, int]) -> str | None:
            if not d:
                return None
            return max(d.items(), key=lambda kv: kv[1])[0]

        items: list[dict[str, Any]] = []
        for g in groups.values():
            items.append(
                {
                    "tool": g["tool"],
                    "family": g["family"],
                    "image_paths": sorted(g["image_paths"]),
                    "exec_count": g["exec_count"],
                    "first_seen_ms": g["first_seen_ms"],
                    "last_seen_ms": g["last_seen_ms"],
                    "top_parent": _top(g["parents"]),
                    "top_signer": _top(g["signers"]),
                    "top_user": _top(g["users"]),
                    "sample_command_line": (
                        g["command_lines"][0] if g["command_lines"] else None
                    ),
                }
            )
        items.sort(key=lambda it: it.get("last_seen_ms") or 0, reverse=True)

        return {
            "ok": True,
            "items": items,
            "count": len(items),
            "events_scanned": len(events),
            "hours_back": hours_back,
        }
    except Exception as exc:
        return swallow_exc(exc)
