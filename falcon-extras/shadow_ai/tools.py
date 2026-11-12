"""Shadow-AI hunting + prevention adoption tools.

Three signal layers + an operator-elected prevention bundle, all moved out
of ``server.py`` into this module. ``@mcp.tool()`` wrappers in server.py
delegate here.
"""

from __future__ import annotations

import re
import time
from typing import Any

from falcon_helpers import (
    _check_response,
    _falcon_kwargs,
    _get_prevention_client,
    resolve_group_id,
)
from falcon_helpers import swallow_exc
from falconpy import CustomIOA
from ngsiem.search import run_ngsiem_search

from shadow_ai import (
    AI_APP_CATALOG,
    AI_EGRESS_CATALOG,
    DISPOSITION_BLOCK,
    DISPOSITION_DETECT,
    LOCAL_INFERENCE_PORTS_HIGH_CONFIDENCE,
    MCP_CMDLINE_CATALOG,
    SHADOW_AI_RULE_CORPUS,
    SHADOW_AI_RULE_GROUP_DESCRIPTION,
    classify_app_image,
    classify_egress_domain,
    classify_local_inference_port,
    classify_mcp_cmdline,
    classify_posture,
    cleanup_plan,
    is_loopback_ipv4,
)
from shadow_ai import domain_regex_alternation as _ai_domain_regex_alternation
from shadow_ai import image_regex_alternation as _ai_image_regex_alternation
from shadow_ai.catalog import get_sanctioned_tools


def _get_custom_ioa_client() -> CustomIOA:
    return CustomIOA(**_falcon_kwargs())


# Rename for use inside this module (prevention helpers below pull from
# falcon_helpers but the prevention-policy client builder lives in
# server.py; we re-import lazily from there inside the binding-check tool
# so we don't pull a circular dep at module import time).


def _shadow_ai_normalize_dns_event(ev: dict[str, Any]) -> tuple[str | None, str | None]:
    """Pull (domain, image) out of a DnsRequest event row, lower-casing
    the domain. Returns (None, None) if no domain present.
    """
    if not isinstance(ev, dict):
        return None, None
    domain = (
        ev.get("DomainName")
        or ev.get("DnsRequestQuery")
        or ev.get("DomainQueryName")
    )
    if not isinstance(domain, str) or not domain.strip():
        return None, None
    image = ev.get("ContextImageFileName") or ev.get("ImageFileName") or ""
    return domain.strip().lower().rstrip("."), str(image)


def _resolve_windows_process_creation_ruletype_id(
    client: CustomIOA,
) -> tuple[str | None, dict[str, Any] | None]:
    """Backward-compat alias — resolves the Windows Process Creation
    ruletype id. Use ``_resolve_process_creation_ruletype_id`` for
    per-platform resolution.
    """
    return _resolve_process_creation_ruletype_id(client, "windows")


def _resolve_process_creation_ruletype_id(
    client: CustomIOA,
    platform: str,
) -> tuple[str | None, dict[str, Any] | None]:
    """Find the Custom IOA Process Creation ruletype_id for the named
    platform (windows / mac / linux).

    Rule type IDs are deterministic per Falcon platform deployment but
    not constant across tenants. Discover at adoption time.

    Returns (ruletype_id, error_payload). Exactly one is non-None.
    """
    target_platform = platform.lower()
    q = client.query_rule_types(limit=500)
    guard = _check_response(q, "CustomIOA")
    if guard is not None:
        return None, guard
    ids = ((q or {}).get("body") or {}).get("resources") or []
    if not ids:
        return None, {"ok": False, "error": "no Custom IOA rule types returned"}
    d = client.get_rule_types(ids=ids)
    guard = _check_response(d, "CustomIOA")
    if guard is not None:
        return None, guard
    types = ((d or {}).get("body") or {}).get("resources") or []
    for t in types:
        if not isinstance(t, dict):
            continue
        plat = (t.get("platform") or "").lower()
        name = (t.get("name") or "").lower()
        if plat == target_platform and "process creation" in name:
            return str(t.get("id")), None
    return None, {
        "ok": False,
        "error": f"{target_platform} Process Creation rule type not found in tenant",
        "available_types": [
            f"{tt.get('platform')}: {tt.get('name')}" for tt in types if isinstance(tt, dict)
        ],
    }




def _find_shadow_ai_rule_group(
    client: CustomIOA,
    platform: str = "windows",
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Look up the Shadow-AI rule group by name for the named platform.
    Returns (group_record, error). group_record is None if not found
    and there's no error.
    """
    from .ioa_rules import SHADOW_AI_RULE_GROUP_NAMES
    name = SHADOW_AI_RULE_GROUP_NAMES.get(platform.lower())
    if not name:
        return None, {"ok": False, "error": f"unknown platform {platform!r}"}
    q = client.query_rule_groupsMixin0(filter=f"name:'{name}'", limit=10)
    guard = _check_response(q, "CustomIOA")
    if guard is not None:
        return None, guard
    ids = ((q or {}).get("body") or {}).get("resources") or []
    if not ids:
        return None, None
    d = client.get_rule_groupsMixin0(ids=ids)
    guard = _check_response(d, "CustomIOA")
    if guard is not None:
        return None, guard
    records = ((d or {}).get("body") or {}).get("resources") or []
    for r in records:
        if isinstance(r, dict) and r.get("name") == name:
            return r, None
    return None, None


def _cleanup_fields(family: str, image_paths: list[str]) -> dict[str, Any]:
    """Flatten catalog.cleanup_plan into the per-app scan fields."""
    form, ms_managed, cleanup = cleanup_plan(family, image_paths)
    return {
        "distribution_form": form,
        "microsoft_managed": ms_managed,
        "cleanup": cleanup,
    }


def host_shadow_ai_scan(
    device_id: str, hours_back: int = 72
) -> dict[str, Any]:
    """Four-layer shadow-AI scan on a single host. Read-only.

    Combines four NGSIEM passes (executed sequentially on one search
    job each — falcon-mcp serializes per client):

      1. ProcessRollup2 → image-name match (AI desktop apps).
      2. ProcessRollup2 → cmdline match (MCP servers, agentic frameworks).
      3. DnsRequest → domain match (AI egress endpoints).
      4. NetworkConnect → local-inference port match (loopback confirms a
         locally-running model server is actively serving; non-loopback
         flags this host as a *consumer* of a peer's local LLM, e.g. a
         browser/IDE here talking to Ollama on a coworker's workstation).

    Returns a structured payload the /shadow-ai page renders:

      {
        "ok": true,
        "device_id": "...",
        "verdict": "mcp_host" | "model_developer" | ...,
        "apps":           [{tool, family, posture, image_paths, distribution_form, microsoft_managed, cleanup:[{script_id,params}], exec_count, last_seen_ms, top_user}],
        "mcp":            [{tool, family, posture, matched_token, image, cmdline, last_seen_ms, top_user}],
        "egress":         [{tool, posture, domain, query_count, last_seen_ms, top_image}],
        "local_inference":[{tool, port, scope, posture, remote_addresses, conn_count, last_seen_ms, top_image, top_user}],
        "events_scanned": int,
      }

    Args:
        device_id: Falcon AID (32-char hex).
        hours_back: Look-back window in hours (1-336, default 72). 72h
            covers a working week's worth of intermittent use.
    """
    try:
        if not isinstance(device_id, str) or not re.fullmatch(
            r"[a-fA-F0-9]{32}", device_id
        ):
            return {"ok": False, "error": "device_id must be a 32-char hex AID"}
        if not isinstance(hours_back, int) or hours_back < 1 or hours_back > 336:
            return {"ok": False, "error": "hours_back must be an integer in 1-336"}

        import time as _time

        now_ms = int(_time.time() * 1000)
        start_ms = now_ms - hours_back * 3600 * 1000

        # Per-pass budget: keep total under MCP 60s timeout. Four
        # sequential NGSIEM passes at 12s each = ~48s worst case. The
        # NetworkConnect pass is cheap (small port whitelist) so the
        # budget mostly absorbs PR2 / DNS variability.
        BUDGET_S = 12.0

        # ---------------- Pass 1+2: ProcessRollup2 (apps + MCP cmdline) ----------------
        # One CQL query covers both image-name catalog AND cmdline
        # signature matching — the cmdline match runs in Python after
        # we get the rows back. We anchor the image filter loosely (any
        # process running on this host) and pull a generous row cap;
        # the catalog match in Python keeps token usage bounded.
        #
        # Rather than blast every PR2 row on the host (can be 100k+ in
        # 72h), we filter to rows that touch one of the catalog atoms
        # OR contain a likely MCP cmdline keyword. False-negative risk
        # if the agent uses a really obscure MCP package, accepted.
        app_alt = _ai_image_regex_alternation()
        # Cmdline keywords that catch the bulk of MCP signatures. Kept
        # short; full classifier runs over the returned rows.
        cmdline_keywords = (
            "modelcontextprotocol",
            "mcp-server",
            "langchain",
            "langgraph",
            "autogen",
            "crewai",
            "llama_index",
            "llamaindex",
            "openinterpreter",
            "open-interpreter",
            "@anthropic-ai",
            "uvx mcp",
            "npx -y @modelcontextprotocol",
        )
        # CQL OR composition: every alternative must be the same shape
        # (`field=/regex/i`). Mixing a regex match with `wildcard()` calls
        # inside one OR clause parses as malformed and LogScale returns a
        # bare HTTP 400 ("No content was received"). Build the cmdline
        # alternatives as a single regex alternation instead — same
        # semantics, valid CQL.
        kw_alt = "|".join(re.escape(kw) for kw in cmdline_keywords)
        pr2_cql = (
            f'#event_simpleName=ProcessRollup2 aid="{device_id}"\n'
            f"| (ImageFileName=/.*\\\\(?:{app_alt})\\.exe$/i "
            f"or CommandLine=/(?:{kw_alt})/i)\n"
            f"| select([@timestamp, ImageFileName, CommandLine, "
            f"ParentBaseFileName, FileSignInfo, UserName])\n"
            f"| sort(@timestamp, order=desc, limit=2000)\n"
            f"| head(2000)"
        )

        pr2_events, pr2_err = run_ngsiem_search(
            pr2_cql, start_ms, now_ms, budget_s=BUDGET_S
        )
        # Soft-fail: if PR2 errors, the egress pass might still produce
        # signal. Track partial-result state.
        pr2_partial = pr2_err is not None or pr2_events is None
        pr2_events = pr2_events or []

        # ---------------- Pass 3: DnsRequest (egress) ----------------
        # DnsRequest is the cheapest egress signal — fires once per
        # unique domain per host per cache TTL, doesn't require full
        # NetworkConnect telemetry, and survives encrypted-tunnel use
        # (TLS SNI is later).
        domain_alt = _ai_domain_regex_alternation()
        dns_cql = (
            f'#event_simpleName=DnsRequest aid="{device_id}"\n'
            f"| DomainName=/^(?:{domain_alt})$/i\n"
            f"| select([@timestamp, DomainName, ContextImageFileName])\n"
            f"| sort(@timestamp, order=desc, limit=2000)\n"
            f"| head(2000)"
        )
        dns_events, dns_err = run_ngsiem_search(
            dns_cql, start_ms, now_ms, budget_s=BUDGET_S
        )
        dns_partial = dns_err is not None or dns_events is None
        dns_events = dns_events or []

        # ---------------- Pass 4: NetworkConnect (local-inference ports) ----------------
        # Catches two distinct cases that the first three layers miss:
        #   - Loopback hits (RemoteAddressIP4 in 127.0.0.0/8) confirm a
        #     locally-running model server is actively serving (not just
        #     installed). Layer 1 sees the binary; this proves it ran.
        #   - Peer hits (any non-loopback) are the unique value: a
        #     browser/IDE here talking to Ollama on a coworker's box has
        #     no Layer-1 / Layer-2 / Layer-3 signal locally — the only
        #     way to flag this consumer-side is the remote port.
        #
        # Filter to LOCAL_INFERENCE_PORTS_HIGH_CONFIDENCE (8080/8000/3000
        # excluded — too shared with web tooling). NGSIEM CQL doesn't
        # support `RemotePort in (...)`, so we OR the literals.
        port_or = " or ".join(
            f"RemotePort={p}" for p in LOCAL_INFERENCE_PORTS_HIGH_CONFIDENCE
        )
        nc_cql = (
            f'#event_simpleName=NetworkConnect aid="{device_id}"\n'
            f"| ({port_or})\n"
            f"| select([@timestamp, ImageFileName, RemoteAddressIP4, "
            f"RemotePort, UserName])\n"
            f"| sort(@timestamp, order=desc, limit=2000)\n"
            f"| head(2000)"
        )
        nc_events, nc_err = run_ngsiem_search(
            nc_cql, start_ms, now_ms, budget_s=BUDGET_S
        )
        nc_partial = nc_err is not None or nc_events is None
        nc_events = nc_events or []

        # ---------------- Aggregate Pass 1+2 ----------------
        apps_by_family: dict[str, dict[str, Any]] = {}
        mcp_by_family: dict[str, dict[str, Any]] = {}
        for ev in pr2_events:
            if not isinstance(ev, dict):
                continue
            image = str(ev.get("ImageFileName") or "")
            cmdline = str(ev.get("CommandLine") or "")
            user = ev.get("UserName")
            ts = ev.get("@timestamp")
            try:
                ts_int = int(ts) if ts is not None else None
            except (TypeError, ValueError):
                ts_int = None

            # Layer 1: app match
            tool, family, posture = classify_app_image(image)
            if tool and family and posture:
                g = apps_by_family.setdefault(
                    family,
                    {
                        "tool": tool,
                        "family": family,
                        "posture": posture,
                        "image_paths": set(),
                        "users": {},
                        "exec_count": 0,
                        "first_seen_ms": None,
                        "last_seen_ms": None,
                        "sample_command_line": None,
                    },
                )
                g["image_paths"].add(image)
                if user:
                    g["users"][str(user)] = g["users"].get(str(user), 0) + 1
                g["exec_count"] += 1
                if cmdline and not g["sample_command_line"]:
                    g["sample_command_line"] = cmdline[:240]
                if ts_int is not None:
                    if g["first_seen_ms"] is None or ts_int < g["first_seen_ms"]:
                        g["first_seen_ms"] = ts_int
                    if g["last_seen_ms"] is None or ts_int > g["last_seen_ms"]:
                        g["last_seen_ms"] = ts_int

            # Layer 2: MCP / agentic-framework cmdline match
            mcp_match = classify_mcp_cmdline(cmdline)
            if mcp_match:
                g = mcp_by_family.setdefault(
                    mcp_match.family,
                    {
                        "tool": mcp_match.tool,
                        "family": mcp_match.family,
                        "posture": mcp_match.posture,
                        "matched_tokens": set(),
                        "images": set(),
                        "users": {},
                        "exec_count": 0,
                        "first_seen_ms": None,
                        "last_seen_ms": None,
                        "sample_command_line": None,
                    },
                )
                g["matched_tokens"].add(mcp_match.matched_token[:80])
                if image:
                    g["images"].add(image)
                if user:
                    g["users"][str(user)] = g["users"].get(str(user), 0) + 1
                g["exec_count"] += 1
                if not g["sample_command_line"]:
                    g["sample_command_line"] = cmdline[:240]
                if ts_int is not None:
                    if g["first_seen_ms"] is None or ts_int < g["first_seen_ms"]:
                        g["first_seen_ms"] = ts_int
                    if g["last_seen_ms"] is None or ts_int > g["last_seen_ms"]:
                        g["last_seen_ms"] = ts_int

        # ---------------- Aggregate Pass 3 ----------------
        egress_by_domain: dict[str, dict[str, Any]] = {}
        for ev in dns_events:
            domain, image = _shadow_ai_normalize_dns_event(ev)
            if not domain:
                continue
            tool, posture = classify_egress_domain(domain)
            if not tool:
                continue
            ts = ev.get("@timestamp")
            try:
                ts_int = int(ts) if ts is not None else None
            except (TypeError, ValueError):
                ts_int = None
            g = egress_by_domain.setdefault(
                domain,
                {
                    "tool": tool,
                    "posture": posture,
                    "domain": domain,
                    "query_count": 0,
                    "first_seen_ms": None,
                    "last_seen_ms": None,
                    "images": {},
                },
            )
            g["query_count"] += 1
            if image:
                g["images"][image] = g["images"].get(image, 0) + 1
            if ts_int is not None:
                if g["first_seen_ms"] is None or ts_int < g["first_seen_ms"]:
                    g["first_seen_ms"] = ts_int
                if g["last_seen_ms"] is None or ts_int > g["last_seen_ms"]:
                    g["last_seen_ms"] = ts_int

        # ---------------- Aggregate Pass 4 ----------------
        # Bucket by (port, scope) where scope is "loopback" or "peer".
        # We split scopes because they mean different things to the
        # operator: loopback = host runs the model server, peer = host
        # is a consumer of someone else's local LLM.
        local_inf_by_key: dict[tuple[int, str], dict[str, Any]] = {}
        for ev in nc_events:
            if not isinstance(ev, dict):
                continue
            try:
                port = int(ev.get("RemotePort"))
            except (TypeError, ValueError):
                continue
            tool = classify_local_inference_port(port)
            if not tool:
                continue
            remote = ev.get("RemoteAddressIP4")
            scope = "loopback" if is_loopback_ipv4(remote) else "peer"
            ts = ev.get("@timestamp")
            try:
                ts_int = int(ts) if ts is not None else None
            except (TypeError, ValueError):
                ts_int = None
            image = str(ev.get("ImageFileName") or "")
            user = ev.get("UserName")
            g = local_inf_by_key.setdefault(
                (port, scope),
                {
                    "tool": tool,
                    "port": port,
                    "scope": scope,
                    "posture": "model_developer",
                    "remote_addresses": {},
                    "images": {},
                    "users": {},
                    "conn_count": 0,
                    "first_seen_ms": None,
                    "last_seen_ms": None,
                },
            )
            if isinstance(remote, str) and remote:
                g["remote_addresses"][remote] = (
                    g["remote_addresses"].get(remote, 0) + 1
                )
            if image:
                g["images"][image] = g["images"].get(image, 0) + 1
            if user:
                g["users"][str(user)] = g["users"].get(str(user), 0) + 1
            g["conn_count"] += 1
            if ts_int is not None:
                if g["first_seen_ms"] is None or ts_int < g["first_seen_ms"]:
                    g["first_seen_ms"] = ts_int
                if g["last_seen_ms"] is None or ts_int > g["last_seen_ms"]:
                    g["last_seen_ms"] = ts_int

        def _top(d: dict[str, int]) -> str | None:
            if not d:
                return None
            return max(d.items(), key=lambda kv: kv[1])[0]

        apps = [
            {
                "tool": g["tool"],
                "family": g["family"],
                "posture": g["posture"],
                "image_paths": sorted(g["image_paths"]),
                # Deterministic uninstall routing (see catalog.cleanup_plan):
                # install form + a ready-to-fire cleanup[] the ban-and-clean
                # workflow runs verbatim, so the agent never has to decide
                # MSIX-vs-Squirrel from paths itself.
                **_cleanup_fields(g["family"], sorted(g["image_paths"])),
                "exec_count": g["exec_count"],
                "first_seen_ms": g["first_seen_ms"],
                "last_seen_ms": g["last_seen_ms"],
                "top_user": _top(g["users"]),
                "sample_command_line": g["sample_command_line"],
            }
            for g in apps_by_family.values()
        ]
        apps.sort(key=lambda x: x.get("last_seen_ms") or 0, reverse=True)

        mcp = [
            {
                "tool": g["tool"],
                "family": g["family"],
                "posture": g["posture"],
                "matched_tokens": sorted(g["matched_tokens"]),
                "images": sorted(g["images"]),
                "exec_count": g["exec_count"],
                "first_seen_ms": g["first_seen_ms"],
                "last_seen_ms": g["last_seen_ms"],
                "top_user": _top(g["users"]),
                "sample_command_line": g["sample_command_line"],
            }
            for g in mcp_by_family.values()
        ]
        mcp.sort(key=lambda x: x.get("last_seen_ms") or 0, reverse=True)

        egress = [
            {
                "tool": g["tool"],
                "posture": g["posture"],
                "domain": g["domain"],
                "query_count": g["query_count"],
                "first_seen_ms": g["first_seen_ms"],
                "last_seen_ms": g["last_seen_ms"],
                "top_image": _top(g["images"]),
            }
            for g in egress_by_domain.values()
        ]
        egress.sort(key=lambda x: x.get("query_count") or 0, reverse=True)

        local_inference = [
            {
                "tool": g["tool"],
                "port": g["port"],
                "scope": g["scope"],
                "posture": g["posture"],
                "remote_addresses": sorted(
                    g["remote_addresses"].keys(),
                    key=lambda k: g["remote_addresses"][k],
                    reverse=True,
                )[:10],
                "conn_count": g["conn_count"],
                "first_seen_ms": g["first_seen_ms"],
                "last_seen_ms": g["last_seen_ms"],
                "top_image": _top(g["images"]),
                "top_user": _top(g["users"]),
            }
            for g in local_inf_by_key.values()
        ]
        # Peer connections sort first (the interesting case), then by recency.
        local_inference.sort(
            key=lambda x: (
                0 if x["scope"] == "peer" else 1,
                -(x.get("last_seen_ms") or 0),
            )
        )

        # Per-tenant operator sanction list. Tools on this list are
        # tagged with `sanctioned: true` and dropped from the signal
        # bag so they don't trigger e.g. mcp_host. If every observed
        # tool is sanctioned, verdict collapses to "sanctioned".
        from shadow_ai.catalog import get_sanctioned_tools
        sanctioned_set = get_sanctioned_tools()
        any_signal = bool(apps) or bool(mcp) or bool(egress) or bool(local_inference)

        signal_bag: list[tuple[str, str]] = []
        for a in apps:
            a["sanctioned"] = a["tool"].lower() in sanctioned_set
            if not a["sanctioned"]:
                signal_bag.append(("app", a["posture"]))
        for m in mcp:
            m["sanctioned"] = m["tool"].lower() in sanctioned_set
            if not m["sanctioned"]:
                signal_bag.append(("mcp", m["posture"]))
        for e in egress:
            e["sanctioned"] = e["tool"].lower() in sanctioned_set
            if not e["sanctioned"]:
                signal_bag.append(("egress", e["posture"]))
        for li in local_inference:
            li["sanctioned"] = li["tool"].lower() in sanctioned_set
            if not li["sanctioned"]:
                signal_bag.append(("local_inference", li["posture"]))

        if any_signal and not signal_bag:
            verdict = "sanctioned"
        else:
            verdict = classify_posture(signal_bag)

        return {
            "ok": True,
            "device_id": device_id,
            "verdict": verdict,
            "apps": apps,
            "mcp": mcp,
            "egress": egress,
            "local_inference": local_inference,
            "events_scanned": len(pr2_events) + len(dns_events) + len(nc_events),
            "hours_back": hours_back,
            "partial": pr2_partial or dns_partial or nc_partial,
            "errors": {
                "process_rollup2": pr2_err,
                "dns_request": dns_err,
                "network_connect": nc_err,
            }
            if (pr2_partial or dns_partial or nc_partial)
            else None,
        }
    except Exception as exc:
        return swallow_exc(exc)




def fleet_shadow_ai_egress(
    hours_back: int = 24, limit: int = 5000
) -> dict[str, Any]:
    """Fleet-wide DnsRequest scan for AI egress endpoints, grouped by AID
    and tool. Read-only.

    The cheap path for /shadow-ai's initial fleet view: one NGSIEM
    search returns every DNS query in the window matching the AI egress
    catalog, then we group server-side by (AID, tool). Compared to the
    per-host fan-out, this trades depth (no app / MCP layer) for breadth
    (every host in one call).

    Pairs with extras_host_shadow_ai_scan: the page can list every host
    with egress signal here, then drill in for the full triple-layer
    profile per host on operator request.

    Args:
        hours_back: Look-back window in hours (1-168, default 24).
        limit: Maximum DNS rows returned (capped at 10000). Increase if
            the fleet is large or the window is wide; default 5000 is
            comfortable for ~200 hosts over 24h.

    Returns:
        {
          "ok": true,
          "items": [
             {aid, hostname?, tools: [{tool, posture, query_count,
              first_seen_ms, last_seen_ms, sample_domains: [...]}]},
             ...
          ],
          "events_scanned": int,
          "hours_back": int,
        }
    """
    try:
        if not isinstance(hours_back, int) or hours_back < 1 or hours_back > 168:
            return {"ok": False, "error": "hours_back must be an integer in 1-168"}
        if not isinstance(limit, int) or limit < 100 or limit > 10000:
            return {"ok": False, "error": "limit must be an integer in 100-10000"}

        import time as _time

        now_ms = int(_time.time() * 1000)
        start_ms = now_ms - hours_back * 3600 * 1000

        domain_alt = _ai_domain_regex_alternation()
        cql = (
            f"#event_simpleName=DnsRequest\n"
            f"| DomainName=/^(?:{domain_alt})$/i\n"
            f"| select([@timestamp, aid, DomainName, ContextImageFileName])\n"
            f"| sort(@timestamp, order=desc, limit={limit})\n"
            f"| head({limit})"
        )

        events, err = run_ngsiem_search(cql, start_ms, now_ms, budget_s=50.0)
        if err is not None:
            return err
        if events is None:
            return {
                "ok": True,
                "items": [],
                "truncated": True,
                "note": (
                    "NGSIEM fleet egress search did not complete within 50s. "
                    "Reduce hours_back or limit."
                ),
            }

        # Group: aid → tool → record
        per_aid: dict[str, dict[str, dict[str, Any]]] = {}
        for ev in events:
            domain, image = _shadow_ai_normalize_dns_event(ev)
            if not domain:
                continue
            aid = ev.get("aid")
            if not isinstance(aid, str) or not aid:
                continue
            tool, posture = classify_egress_domain(domain)
            if not tool:
                continue
            ts = ev.get("@timestamp")
            try:
                ts_int = int(ts) if ts is not None else None
            except (TypeError, ValueError):
                ts_int = None
            tool_map = per_aid.setdefault(aid, {})
            g = tool_map.setdefault(
                tool,
                {
                    "tool": tool,
                    "posture": posture,
                    "query_count": 0,
                    "first_seen_ms": None,
                    "last_seen_ms": None,
                    "sample_domains": set(),
                },
            )
            g["query_count"] += 1
            g["sample_domains"].add(domain)
            if ts_int is not None:
                if g["first_seen_ms"] is None or ts_int < g["first_seen_ms"]:
                    g["first_seen_ms"] = ts_int
                if g["last_seen_ms"] is None or ts_int > g["last_seen_ms"]:
                    g["last_seen_ms"] = ts_int

        from shadow_ai.catalog import get_sanctioned_tools
        sanctioned_set = get_sanctioned_tools()

        items: list[dict[str, Any]] = []
        for aid, tool_map in per_aid.items():
            tools = []
            for g in tool_map.values():
                tools.append(
                    {
                        "tool": g["tool"],
                        "posture": g["posture"],
                        "query_count": g["query_count"],
                        "first_seen_ms": g["first_seen_ms"],
                        "last_seen_ms": g["last_seen_ms"],
                        "sample_domains": sorted(g["sample_domains"])[:5],
                        "sanctioned": g["tool"].lower() in sanctioned_set,
                    }
                )
            tools.sort(key=lambda x: x.get("query_count") or 0, reverse=True)
            # Hide hosts whose only signals are all sanctioned tools — the
            # fleet view exists to surface unsanctioned exposure. Operator
            # can still see the sanctioned coverage in the per-host drill-in.
            if tools and all(t["sanctioned"] for t in tools):
                continue
            items.append({"aid": aid, "tools": tools})

        # Sort hosts by total query count (busiest first).
        items.sort(
            key=lambda h: sum(t.get("query_count") or 0 for t in h["tools"]),
            reverse=True,
        )

        return {
            "ok": True,
            "items": items,
            "events_scanned": len(events),
            "hours_back": hours_back,
            "truncated": len(events) >= limit,
        }
    except Exception as exc:
        return swallow_exc(exc)




def _platform_rule_group_status(
    client: CustomIOA, platform: str
) -> dict[str, Any] | tuple[None, dict[str, Any]]:
    """Live rule-group state for ONE platform. Returns the per-platform
    summary dict, or (None, error) if the lookup faulted."""
    from .ioa_rules import SHADOW_AI_RULE_GROUP_NAMES, rule_corpus_summary_for_platform

    corpus = rule_corpus_summary_for_platform(platform)
    corpus_names = [r["name"] for r in corpus]
    rg_name = SHADOW_AI_RULE_GROUP_NAMES[platform]
    group, err = _find_shadow_ai_rule_group(client, platform)
    if err is not None:
        return None, err
    if group is None:
        return {
            "platform": platform,
            "rule_group_exists": False,
            "rule_group_name": rg_name,
            "rule_group_id": None,
            "rule_group_enabled": None,
            "installed_rules": [],
            "installed_rule_count": 0,
            "missing_rules": corpus_names,
            "corpus_count": len(corpus),
            "corpus": corpus,
        }
    rules = group.get("rules") or []
    installed = [r.get("name") for r in rules if isinstance(r, dict)]
    missing = [n for n in corpus_names if n not in installed]
    return {
        "platform": platform,
        "rule_group_exists": True,
        "rule_group_id": group.get("id"),
        "rule_group_name": group.get("name"),
        "rule_group_enabled": group.get("enabled"),
        "rule_group_version": group.get("version"),
        "rule_group_platform": group.get("platform"),
        "installed_rule_count": len(installed),
        "installed_rules": installed,
        "missing_rules": missing,
        "corpus_count": len(corpus),
        "corpus": corpus,
    }


# Keys hoisted to the top level from the Windows platform for backward
# compatibility with app/api/shadow-ai/setup/route.ts (which reads the
# Windows-shaped rule-group summary). Per-platform truth is in platforms[].
_STATUS_HOIST_KEYS = (
    "rule_group_exists",
    "rule_group_id",
    "rule_group_name",
    "rule_group_enabled",
    "installed_rules",
    "installed_rule_count",
    "missing_rules",
    "corpus_count",
    "corpus",
)


def shadow_ai_prevention_status() -> dict[str, Any]:
    """Report Shadow-AI prevention deployment state across ALL platforms
    (Windows / macOS / Linux). READ-ONLY.

    For each platform returns the per-platform corpus the adoption tool
    would author plus the live rule-group state (id, enabled flag,
    installed vs missing rules). `platforms[]` carries every platform;
    top-level keys mirror the Windows platform for backward compatibility
    with the setup card. Does NOT read prevention-policy bindings — see
    `extras_shadow_ai_check_prevention_binding` for that.
    """
    from .ioa_rules import SHADOW_AI_RULE_GROUP_NAMES

    try:
        client = _get_custom_ioa_client()
        platforms_out: list[dict[str, Any]] = []
        for plat in SHADOW_AI_RULE_GROUP_NAMES:  # windows, mac, linux
            result = _platform_rule_group_status(client, plat)
            if isinstance(result, tuple):  # (None, error)
                return result[1]
            platforms_out.append(result)

        win = next(
            (p for p in platforms_out if p["platform"] == "windows"),
            platforms_out[0],
        )
        out: dict[str, Any] = {
            "ok": True,
            "platforms": platforms_out,
            "any_rule_group_exists": any(p["rule_group_exists"] for p in platforms_out),
        }
        for k in _STATUS_HOIST_KEYS:
            out[k] = win.get(k)
        if not win["rule_group_exists"]:
            out["note"] = (
                "No Windows rule group with this name exists yet. Run "
                '`extras_shadow_ai_adopt_prevention` (platform="windows") to '
                "create it. See platforms[] for macOS / Linux state."
            )
        return out
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)




def shadow_ai_check_prevention_binding() -> dict[str, Any]:
    """Diagnose whether the Shadow-AI Custom IOA rule group is actually
    enforcing on hosts moved into the AI-Banned host group. READ-ONLY.

    The Ban+Clean workflow only succeeds end-to-end when:
      1. FALCON_SHADOW_AI_BANNED_GROUP_ID is set on the active env.
      2. The host group exists in Falcon.
      3. At least one Prevention Policy is attached to that host group.
      4. The Shadow-AI rule group ("Project Eyas - Shadow-AI Block") is
         bound to one of those policies AND the policy is enabled.
      5. The rule group itself is enabled.

    Operators routinely miss step 4 — `extras_shadow_ai_adopt_prevention`
    only binds the rule group to ONE prevention policy id passed in by
    the operator; it doesn't verify that policy is the one actually
    attached to the AI-Banned host group. This tool walks the live state
    and reports exactly which step is broken so the operator can fix it
    in console (FalconPy doesn't expose policy-to-host-group attachment
    as a write — that's a console step).

    Platform-aware: Falcon rejects cross-platform IOA binds, so each
    attached policy is checked against ITS OWN platform's rule group
    (`Project Eyas - Shadow-AI Block` / `... (mac)` / `... (linux)`),
    not the Windows group alone. A correctly-bound macOS or Linux policy
    no longer reports as broken.

    Returns:
        ok: bool
        ready: bool — true when at least one platform is fully enforcing
            and no enabled attached policy is left unbound
        banned_group_id: str | None
        rule_groups: list[{platform, name, id, exists, enabled}]
        attached_policies: list[{id, name, platform, enabled,
            rule_group_bound, rule_group_name, rule_group_exists,
            rule_group_enabled}]
        missing_steps: list[str] — operator-facing remediation steps,
            prefixed with the platform they apply to
        (rule_group_name / _id / _exists / _enabled are also hoisted to
        the top level from the Windows platform for backward compat.)
    """
    from .ioa_rules import SHADOW_AI_RULE_GROUP_NAMES

    try:
        # Override-aware: a group adopted/created earlier this turn is honored
        # before the (frozen) spawn-time env var.
        banned_group_id = resolve_group_id("shadow_ai_banned") or ""
        if not banned_group_id:
            return {
                "ok": True,
                "ready": False,
                "banned_group_id": None,
                "missing_steps": [
                    'Set the "Shadow-AI banned host group" field on the active '
                    "environment in /config (Environments manager) — without "
                    "it Ban+Clean has nowhere to move hosts."
                ],
            }

        # Steps 2 + 5: per-platform rule group state. Each platform binds
        # its OWN rule group (Falcon rejects cross-platform binds).
        ioa_client = _get_custom_ioa_client()
        rg_by_platform: dict[str, dict[str, Any]] = {}
        for plat, rg_name in SHADOW_AI_RULE_GROUP_NAMES.items():
            group, err = _find_shadow_ai_rule_group(ioa_client, plat)
            if err is not None:
                return err
            rg_by_platform[plat] = {
                "platform": plat,
                "name": rg_name,
                "id": group.get("id") if group else None,
                "exists": group is not None,
                "enabled": bool(group.get("enabled")) if group else False,
            }

        # Steps 3 + 4: walk every prevention policy, find the ones attached
        # to the banned host group, and check whether each carries ITS
        # platform's rule group.
        prev_client = _get_prevention_client()
        resp = prev_client.query_combined_policies(parameters={"limit": 200})
        guard = _check_response(resp, "Prevention Policies")
        if guard:
            return guard
        policies = ((resp or {}).get("body") or {}).get("resources") or []

        attached: list[dict[str, Any]] = []
        for p in policies:
            if not isinstance(p, dict):
                continue
            groups = p.get("groups") or []
            in_banned = any(
                isinstance(g, dict) and g.get("id") == banned_group_id for g in groups
            )
            if not in_banned:
                continue
            plat = (p.get("platform_name") or "").lower()
            rg = rg_by_platform.get(plat)
            expected_rg_name = rg["name"] if rg else SHADOW_AI_RULE_GROUP_NAMES.get(plat)
            expected_rg_id = rg["id"] if rg else None
            ioa_groups = p.get("ioa_rule_groups") or []
            bound = any(
                isinstance(rgi, dict)
                and (
                    (expected_rg_id is not None and rgi.get("id") == expected_rg_id)
                    or (expected_rg_name is not None and rgi.get("name") == expected_rg_name)
                )
                for rgi in ioa_groups
            )
            attached.append(
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "platform": p.get("platform_name"),
                    "enabled": bool(p.get("enabled", True)),
                    "rule_group_bound": bound,
                    "rule_group_name": expected_rg_name,
                    "rule_group_exists": bool(rg["exists"]) if rg else False,
                    "rule_group_enabled": bool(rg["enabled"]) if rg else False,
                }
            )

        missing: list[str] = []
        if not attached:
            missing.append(
                f"No Prevention Policy is attached to host group "
                f"{banned_group_id}. In Falcon Console, edit the AI-Banned "
                "host group's prevention policy assignment to attach a policy "
                "(per platform) whose Custom IOA Rule Groups include the "
                "matching 'Project Eyas - Shadow-AI Block' group."
            )
        else:
            platforms_in_play = sorted(
                {(p["platform"] or "").lower() for p in attached if p["platform"]}
            )
            for plat in platforms_in_play:
                rg = rg_by_platform.get(plat) or {}
                rg_name = rg.get("name") or SHADOW_AI_RULE_GROUP_NAMES.get(plat, plat)
                plat_policies = [p for p in attached if (p["platform"] or "").lower() == plat]
                if not rg.get("exists"):
                    missing.append(
                        f"[{plat}] Run extras_shadow_ai_adopt_prevention("
                        f'platform="{plat}") to create the \'{rg_name}\' rule group.'
                    )
                    continue
                if not rg.get("enabled"):
                    missing.append(
                        f"[{plat}] Enable the '{rg_name}' rule group in Falcon "
                        "Console (Endpoint Security → Custom IOA Rule Groups)."
                    )
                enabled_unbound = [
                    p for p in plat_policies if p["enabled"] and not p["rule_group_bound"]
                ]
                if enabled_unbound:
                    names = ", ".join(p["name"] or p["id"] for p in enabled_unbound)
                    missing.append(
                        f"[{plat}] '{rg_name}' is not bound to the attached {plat} "
                        f"prevention policy ({names}). Re-run "
                        "extras_shadow_ai_adopt_prevention with the prevention_policy_id "
                        f'of that policy and platform="{plat}", or bind it via console.'
                    )
                disabled_with_bind = [
                    p for p in plat_policies if p["rule_group_bound"] and not p["enabled"]
                ]
                if disabled_with_bind:
                    names = ", ".join(p["name"] or p["id"] for p in disabled_with_bind)
                    missing.append(
                        f"[{plat}] Rule group is bound, but the prevention policy "
                        f"carrying it is disabled: {names}."
                    )

        # ready: at least one platform fully enforcing (enabled policy +
        # bound + that platform's rule group enabled), and no enabled
        # attached policy left unbound on any platform.
        enforcing = [
            p
            for p in attached
            if p["enabled"] and p["rule_group_bound"] and p["rule_group_enabled"]
        ]
        enabled_unbound_any = [
            p for p in attached if p["enabled"] and not p["rule_group_bound"]
        ]
        ready = bool(enforcing) and not enabled_unbound_any

        # Backward-compat top-level summary (Windows representative for the
        # legacy single-line audit UI; per-platform truth is in rule_groups[]).
        win_rg = rg_by_platform.get("windows", {})
        return {
            "ok": True,
            "ready": ready,
            "banned_group_id": banned_group_id,
            "rule_groups": list(rg_by_platform.values()),
            "rule_group_name": win_rg.get("name"),
            "rule_group_id": win_rg.get("id"),
            "rule_group_exists": win_rg.get("exists", False),
            "rule_group_enabled": win_rg.get("enabled", False),
            "attached_policies": attached,
            "missing_steps": missing,
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)




def shadow_ai_adopt_prevention(
    prevention_policy_id: str,
    comment: str,
    mode: str = "block",
    dry_run: bool = False,
    platform: str = "windows",
) -> dict[str, Any]:
    """Author the Shadow-AI Custom IOA rule bundle and bind it to a
    Prevention Policy. WRITE ACTION — requires explicit user approval.

    Idempotent: looking up the per-platform rule group by name reuses
    an existing one, and per-rule dedup runs by rule name. Rerunning
    after a corpus change appends only the missing rules; no existing
    rule is modified (operator console edits are preserved).

    Args:
        prevention_policy_id: The Prevention Policy id to bind the rule
            group to. Must match the platform of the rule group —
            Falcon rejects cross-platform binds.
        comment: Required free-text reason. Recorded in Falcon Console's
            change ledger for audit.
        mode: 'block' (disposition_id=30, "Block Execution" — prevents the
            process from running; the default) or 'detect' (disposition_id=
            20, raises a detection only). Rules are created AND enabled
            (Falcon creates Custom IOA rules disabled, so the tool flips
            them on via update_rules). On re-run, existing managed rules
            CONVERGE to the chosen enabled+disposition state — re-running
            with a different mode actually re-dispositions them, and a
            previously-broken (disabled) ruleset is repaired in place.
        dry_run: When true, returns the rendered create_rule payloads
            without making any write calls.
        platform: 'windows' / 'mac' / 'linux'. Selects the per-platform
            rule corpus, ruletype, and rule group name. Default
            'windows' for backward-compat with existing callers.
    """
    from .ioa_rules import (
        CORPUS_BY_PLATFORM,
        SHADOW_AI_RULE_GROUP_NAMES,
    )

    if not prevention_policy_id or not isinstance(prevention_policy_id, str):
        return {"ok": False, "error": "prevention_policy_id is required"}
    if not comment or not isinstance(comment, str):
        return {
            "ok": False,
            "error": "comment is required — recorded in Falcon Console change ledger",
        }
    mode_norm = (mode or "").strip().lower()
    if mode_norm not in ("detect", "block"):
        return {
            "ok": False,
            "error": f"mode must be 'detect' or 'block', got {mode!r}",
        }
    platform_norm = (platform or "").strip().lower()
    if platform_norm not in CORPUS_BY_PLATFORM:
        return {
            "ok": False,
            "error": f"platform must be 'windows' / 'mac' / 'linux', got {platform!r}",
        }
    rule_group_name = SHADOW_AI_RULE_GROUP_NAMES[platform_norm]
    corpus = CORPUS_BY_PLATFORM[platform_norm]
    disposition_id = DISPOSITION_BLOCK if mode_norm == "block" else DISPOSITION_DETECT
    # Falcon's Custom IOA API rejects HTTP 400 on any control character
    # (newline, tab, etc.) inside the `comment` field. Sanitize at the
    # boundary so it can't happen regardless of how the operator's
    # comment got assembled (chat-model formatting, terminal wrapping,
    # primer interpolation across line breaks).
    import re as _re
    comment = _re.sub(r"[\x00-\x1f\x7f]+", " ", comment)
    comment = _re.sub(r"\s+", " ", comment).strip()

    try:
        client = _get_custom_ioa_client()

        ruletype_id, err = _resolve_process_creation_ruletype_id(client, platform_norm)
        if err is not None:
            return err

        rendered_rules = [
            {
                "name": r.name,
                "description": r.description,
                "pattern_severity": r.pattern_severity,
                "ruletype_id": ruletype_id,
                "disposition_id": disposition_id,
                "field_values": r.to_field_values(),
                "comment": f"{comment} [{r.rationale_tag}]",
            }
            for r in corpus
        ]

        # Shared converge predicate: a managed rule is "correct" only when it
        # is BOTH enabled AND at the requested disposition. Falcon creates
        # Custom IOA rules DISABLED, and a prior run may have left them at a
        # different disposition, so adoption must converge both.
        def _needs_converge(live_rule: dict[str, Any]) -> bool:
            return (
                not bool(live_rule.get("enabled"))
                or live_rule.get("disposition_id") != disposition_id
            )

        corpus_names = {r["name"] for r in rendered_rules}

        if dry_run:
            # Read-only: report what a live run WOULD do against current state.
            group, err = _find_shadow_ai_rule_group(client, platform_norm)
            if err is not None:
                return err
            live_rules = (group.get("rules") or []) if group else []
            live_by_name = {
                r.get("name"): r for r in live_rules if isinstance(r, dict)
            }
            would_create = [n for n in corpus_names if n not in live_by_name]
            would_converge = [
                {
                    "name": r.get("name"),
                    "from": {
                        "enabled": bool(r.get("enabled")),
                        "disposition_id": r.get("disposition_id"),
                    },
                    "to": {"enabled": True, "disposition_id": disposition_id},
                }
                for n, r in live_by_name.items()
                if n in corpus_names and _needs_converge(r)
            ]
            already_correct = [
                n
                for n, r in live_by_name.items()
                if n in corpus_names and not _needs_converge(r)
            ]
            return {
                "ok": True,
                "dry_run": True,
                "platform": platform_norm,
                "mode": mode_norm,
                "ruletype_id": ruletype_id,
                "disposition_id": disposition_id,
                "rule_group_name": rule_group_name,
                "rule_group_exists": group is not None,
                "rule_group_enabled": bool(group.get("enabled")) if group else False,
                "rendered_rules": rendered_rules,
                "rendered_count": len(rendered_rules),
                "plan": {
                    "would_create_rules": would_create,
                    "would_enable_or_redisposition": would_converge,
                    "already_correct": already_correct,
                },
                "prevention_policy_id": prevention_policy_id,
                "note": (
                    "dry_run: no write calls were made. A live run would create "
                    "the listed rules, then set enabled=True + "
                    f"disposition_id={disposition_id} on every managed rule not "
                    "already in that state, preserving each rule's live match "
                    "patterns."
                ),
            }

        # 1. Resolve / create the rule group.
        group, err = _find_shadow_ai_rule_group(client, platform_norm)
        if err is not None:
            return err
        created_group = False
        if group is None:
            create = client.create_rule_groupMixin0(
                name=rule_group_name,
                description=SHADOW_AI_RULE_GROUP_DESCRIPTION,
                platform=platform_norm,
                comment=comment,
            )
            guard = _check_response(create, "CustomIOA")
            if guard is not None:
                return guard
            new_records = ((create or {}).get("body") or {}).get("resources") or []
            if not new_records:
                return {
                    "ok": False,
                    "error": "create_rule_group returned no record",
                    "raw": (create or {}).get("body"),
                }
            group = new_records[0]
            created_group = True

        rule_group_id = group.get("id")
        if not rule_group_id:
            return {"ok": False, "error": "rule group missing id", "raw": group}

        # 2. Create any corpus rule that doesn't exist yet (dedup by name).
        # Falcon creates Custom IOA rules DISABLED regardless of group state,
        # so create alone does NOT enforce — the enable happens in step 3 via
        # update_rules. (Skipping that step was the original bug: every rule
        # sat enabled=False forever, so the whole group was inert.)
        existing_names = {
            r.get("name") for r in (group.get("rules") or []) if isinstance(r, dict)
        }
        added: list[str] = []
        rule_errors: list[dict[str, Any]] = []
        for rule in rendered_rules:
            if rule["name"] in existing_names:
                continue
            resp = client.create_rule(
                rulegroup_id=rule_group_id,
                ruletype_id=ruletype_id,
                disposition_id=disposition_id,
                name=rule["name"],
                description=rule["description"],
                pattern_severity=rule["pattern_severity"],
                field_values=rule["field_values"],
                comment=rule["comment"],
            )
            guard = _check_response(resp, "CustomIOA")
            if guard is not None:
                rule_errors.append({"rule": rule["name"], "error": guard})
                continue
            added.append(rule["name"])

        # 3. Refetch the group (so freshly created rules carry instance_ids +
        # Falcon's auto-populated field_values), then CONVERGE every managed
        # rule to enabled=True + the requested disposition. Each rule's LIVE
        # field_values are passed straight back — they are the complete
        # server-validated set (all ruletype fields, unused ones defaulted),
        # so the GET→PATCH round-trips cleanly AND any console pattern edits
        # are preserved.
        latest_group, err = _find_shadow_ai_rule_group(client, platform_norm)
        if err is not None:
            return err
        if latest_group is None:
            return {"ok": False, "error": "rule group disappeared mid-adoption"}
        version = latest_group.get("version")
        live_rules = latest_group.get("rules") or []
        already_correct = [
            r.get("name")
            for r in live_rules
            if isinstance(r, dict)
            and r.get("name") in corpus_names
            and not _needs_converge(r)
        ]
        rule_updates: list[dict[str, Any]] = []
        for r in live_rules:
            if not isinstance(r, dict) or r.get("name") not in corpus_names:
                continue  # leave non-managed rules alone
            if not _needs_converge(r):
                continue  # already enabled at the requested disposition
            rule_updates.append(
                {
                    "instance_id": r.get("instance_id"),
                    "name": r.get("name"),
                    "description": r.get("description") or "",
                    "pattern_severity": r.get("pattern_severity") or "medium",
                    "disposition_id": disposition_id,
                    "enabled": True,
                    "field_values": r.get("field_values") or [],
                    "rulegroup_version": version,
                }
            )

        converged = [u["name"] for u in rule_updates]
        if rule_updates:
            upd_resp = client.update_rules(
                body={
                    "rulegroup_id": rule_group_id,
                    "rulegroup_version": version,
                    "comment": comment,
                    "rule_updates": rule_updates,
                }
            )
            guard = _check_response(upd_resp, "CustomIOA")
            if guard is not None:
                return {
                    "ok": False,
                    "stage": "enable_rules",
                    "rule_group_id": rule_group_id,
                    "rules_added": added,
                    "rules_to_converge": converged,
                    "rule_errors": rule_errors,
                    "error": guard,
                }
            # update_rules bumped the version; refetch for the group-enable.
            latest_group, err = _find_shadow_ai_rule_group(client, platform_norm)
            if err is not None:
                return err
            if latest_group is None:
                return {"ok": False, "error": "rule group disappeared mid-adoption"}
            version = latest_group.get("version")

        # 4. Enable the rule group itself (no-op if already enabled — Falcon
        # accepts the PATCH idempotently).
        enable_resp = client.update_rule_groupMixin0(
            id=rule_group_id,
            name=rule_group_name,
            description=SHADOW_AI_RULE_GROUP_DESCRIPTION,
            enabled=True,
            rulegroup_version=version,
            comment=comment,
        )
        guard = _check_response(enable_resp, "CustomIOA")
        if guard is not None:
            return {
                "ok": False,
                "stage": "enable_rule_group",
                "rule_group_id": rule_group_id,
                "rules_added": added,
                "rules_converged": converged,
                "rule_errors": rule_errors,
                "error": guard,
            }

        # 5. Bind to the prevention policy. add-rule-group is idempotent at
        # Falcon's side — re-attaching an already-attached rule group is a
        # 200 with no change.
        prev_client = _get_prevention_client()
        bind_resp = prev_client.perform_policies_action(
            action_name="add-rule-group",
            ids=[prevention_policy_id],
            action_parameters=[{"name": "rule_group_id", "value": rule_group_id}],
        )
        guard = _check_response(bind_resp, "PreventionPolicy")
        bind_error = guard if guard is not None else None

        action_label = "Block Execution (process kill)" if mode_norm == "block" else "Detect"
        return {
            "ok": True,
            "platform": platform_norm,
            "created_rule_group": created_group,
            "rule_group_id": rule_group_id,
            "rule_group_name": rule_group_name,
            "mode": mode_norm,
            "disposition_id": disposition_id,
            "ruletype_id": ruletype_id,
            "rules_added": added,
            "rules_converged": converged,
            "rules_already_correct": already_correct,
            "rule_errors": rule_errors,
            "prevention_policy_id": prevention_policy_id,
            "policy_bind_error": bind_error,
            "note": (
                (
                    f"Rule group enabled; {len(added)} rule(s) created, "
                    f"{len(converged)} rule(s) set to enabled + {action_label}. "
                    "Bound to the prevention policy; enforces on the next sensor "
                    "heartbeat for hosts whose policy includes this rule group."
                )
                if bind_error is None
                else (
                    "Rules enabled but policy binding failed — attach the rule "
                    "group in Falcon Console or re-run this tool. See "
                    "policy_bind_error."
                )
            ),
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


