"""NGSIEM search runner — start / poll / fetch a single CQL query.

Used by the Shadow-AI hunter. (/ngsiem and Eyas's own tools use eyas-mcp's
falcon_search_ngsiem.)
Lifted out of ``server.py`` so per-feature modules can share the runner
without each one re-importing FalconPy + the CQL linter.

Three-state return makes the "completed empty" / "timed out" /
"upstream errored" trichotomy explicit, which matters for graceful
degradation in the callers.
"""

from __future__ import annotations

import time
from typing import Any

from falconpy import APIHarnessV2

from falcon_helpers import _check_response, _falcon_kwargs

from . import syntax as cql_syntax


def run_ngsiem_search(
    cql: str,
    start_ms: int,
    end_ms: int,
    *,
    budget_s: float = 30.0,
    repository: str = "search-all",
) -> tuple[list[dict[str, Any]] | None, dict[str, Any] | None]:
    """Submit, poll, and return events for a single CQL search.

    Return encoding distinguishes three outcomes:

      ``(events: list, None)`` — search completed, possibly empty
      ``(None, None)``         — polling timed out before completion
      ``([], dict)``            — error (auth / scope_pending / upstream 4xx/5xx)

    The ``[]`` vs ``None`` distinction matters: an NGSIEM search that
    COMPLETES with zero rows is a real result; a search that TIMES OUT
    before the poll budget elapses is a degraded outcome the caller may
    want to surface differently (e.g. "narrow your query, the data
    exists").

    Uses the FalconPy uber class (``APIHarnessV2``) rather than the typed
    NGSIEM service class. In FalconPy 1.6.1 the typed
    ``NGSIEM.start_search(body=..., repository=...)`` form silently drops
    the body, surfacing as a 500 "must provide repository and search
    arguments" — uncaught by ``_is_permission_error`` so it never falls
    through to scope_pending. The uber class ``.command()`` form passes
    the body through correctly, matching upstream falcon-mcp's approach.
    """
    # Pre-flight CQL lint — short-circuits the most common syntax traps
    # (limit() vs head(), single-quoted strings, missing # tag prefix,
    # sort() default-truncation) before the query leaves the sidecar.
    # Without this the agent spends multiple iterations correcting
    # syntax against live 400 responses; with it the agent gets one
    # structured error + canonical fix in hand.
    lint_result = cql_syntax.lint(cql)
    if not lint_result.ok:
        return [], {
            "ok": False,
            "error": "CQL lint failed — fix syntax before submitting to NGSIEM",
            "cql_lint": lint_result.to_dict(),
            "cql": cql,
        }

    client = APIHarnessV2(**_falcon_kwargs())
    repo = repository or "search-all"
    start_resp = client.command(
        "StartSearchV1",
        repository=repo,
        body={"queryString": cql, "start": start_ms, "end": end_ms},
    )
    guard = _check_response(start_resp, "NGSIEM")
    if guard:
        return [], guard
    job_id = (start_resp.get("body", {}) or {}).get("id")
    if not job_id:
        return [], {
            "ok": False,
            "error": "NGSIEM start_search returned no job id",
            "details": start_resp.get("body"),
        }
    POLL_S = 1.5
    # Budget against wall clock, not accumulated sleep. Each iteration also does
    # a GetSearchStatusV1 HTTP round-trip (often ~0.5–1s); counting only POLL_S
    # let real wall clock run 30–100% over budget_s, so a 50s budget routinely
    # blew the MCP SDK's 60s transport timeout — the transport aborted mid-poll,
    # the agent got an opaque timeout, and the live NGSIEM job was never stopped.
    # A monotonic deadline makes budget_s a true wall-clock cap (worst-case
    # overshoot is one POLL_S + one round-trip), keeping the 50s caller
    # (the Shadow-AI egress hunt)
    # safely under 60s. See mcp_timeout_vs_falcon_wait.
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        time.sleep(POLL_S)
        # FalconPy's uber-class path-templater for GetSearchStatusV1 uses
        # `search_id` as the placeholder keyword (not `id`); passing `id=`
        # raises KeyError: 'search_id' inside FalconPy. Match upstream
        # falcon-mcp's idiom.
        poll = client.command(
            "GetSearchStatusV1", repository=repo, search_id=job_id
        )
        pguard = _check_response(poll, "NGSIEM")
        if pguard:
            return [], pguard
        pbody = poll.get("body", {}) if isinstance(poll, dict) else {}
        if pbody.get("done"):
            return list(pbody.get("events") or []), None
    # Timed out — best-effort cleanup and return None to signal the
    # caller that the search didn't complete (distinct from "completed
    # with zero rows").
    try:
        client.command("StopSearchV1", repository=repo, search_id=job_id)
    except Exception:
        pass
    return None, None
