"""Auto-extracted tool implementations.

See ``server.py`` ``@mcp.tool()`` wrappers for the public docstrings;
these are the worker functions they delegate to.
"""

from __future__ import annotations

import json
import re
from typing import Any
from falcon_helpers import _check_response, _get_ioa_exclusions_client, _get_ml_exclusions_client
from falcon_helpers import swallow_exc


# Zero-width assertions the Falcon IOA DFA engine rejects. Detecting these
# in unescaped position (not preceded by a backslash) catches the common
# author mistakes; this isn't a full regex parser, just a heuristic worth
# the false-positive-free cases it covers.
_ZERO_WIDTH_PATTERNS = (r"\b", r"\A", r"\Z", r"\B")


def _find_zero_width_assertion(pattern: str) -> str | None:
    # Backslashes pair-canceled: a `\\$` is a literal backslash + `$`, fine.
    # Iterate, tracking escape state AND character-class context: inside a
    # `[...]` class, `^` is negation (DFA-legal) and `$` is a literal dollar,
    # so neither is a zero-width anchor there. Flagging them produced false
    # rejects on valid patterns like `[^/]*` / `[$]`.
    escaped = False
    in_class = False
    class_start = -1  # index where the current class opened (for `[^`/`[]` rules)
    for i, ch in enumerate(pattern):
        if escaped:
            escaped = False
            # Inside a class, `\b` is a backspace literal, not a word boundary —
            # the DFA accepts it; only flag escape-form assertions outside a class.
            if not in_class:
                seq = "\\" + ch
                if seq in _ZERO_WIDTH_PATTERNS:
                    return seq
            continue
        if ch == "\\":
            escaped = True
            continue
        if in_class:
            # A `]` closes the class, except when it's the first member
            # (`[]` or `[^]`), where it's a literal `]`.
            if ch == "]" and i > class_start + (2 if pattern[class_start + 1 : class_start + 2] == "^" else 1):
                in_class = False
            continue
        if ch == "[":
            in_class = True
            class_start = i
            continue
        if ch == "^":
            return "^"
        if ch == "$":
            return "$"
    return None

# `excluded_from` values accepted by the Falcon ML exclusion API.
#   blocking   — on-write ML prevention (the runtime detection surface)
#   extraction — offline ML scan during file extraction
_VALID_ML_EXCLUDED_FROM = {"blocking", "extraction"}

def list_ml_exclusions(
    limit: int = 100,
    filter: str | None = None,
) -> dict[str, Any]:
    """List ML (machine-learning) detection exclusions on this tenant. Read-only.
    Always run this BEFORE proposing a new ML exclusion so you can show the
    operator any existing matches and avoid duplicates.

    Args:
        limit: Max records (1-500). Default 100.
        filter: Optional FQL filter. Common forms:
            - `value:'C:\\\\path\\\\to\\\\binary.exe'` — exact match on excluded value
            - `applied_globally:true` — only globally-applied exclusions
            - `created_by:'analyst@example.com'` — by author
    """
    try:
        client = _get_ml_exclusions_client()
        capped = min(max(limit, 1), 500)
        # FalconPy combined-endpoint sort uses dot, not pipe (the pipe form in
        # legacy docstrings 400s with "is not an allowable value").
        params: dict[str, Any] = {"limit": capped, "sort": "last_modified.desc"}
        if filter:
            params["filter"] = filter
        q = client.search_exclusions_v2(parameters=params)
        guard = _check_response(q, "MLExclusions")
        if guard is not None:
            return guard
        ids = ((q or {}).get("body") or {}).get("resources") or []
        if not ids:
            return {"ok": True, "items": [], "count": 0}
        d = client.get_exclusions_by_id(ids=ids)
        guard = _check_response(d, "MLExclusions")
        if guard is not None:
            return guard
        records = ((d or {}).get("body") or {}).get("resources") or []
        items = [
            {
                "id": r.get("id"),
                "value": r.get("value"),
                "regexp_value": r.get("regexp_value"),
                "value_hash": r.get("value_hash"),
                "applied_globally": r.get("applied_globally"),
                "groups": [g.get("name") for g in (r.get("groups") or []) if isinstance(g, dict)],
                "group_ids": [g.get("id") for g in (r.get("groups") or []) if isinstance(g, dict)],
                "excluded_from": r.get("excluded_from") or [],
                "description": r.get("description") or "",
                "created_by": r.get("created_by"),
                "created_on": r.get("created_on"),
                "last_modified": r.get("last_modified"),
                "modified_by": r.get("modified_by"),
            }
            for r in records
            if isinstance(r, dict)
        ]
        return {"ok": True, "items": items, "count": len(items)}
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


def create_ml_exclusion(
    value: str,
    comment: str,
    excluded_from: list[str] | None = None,
    group_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Create an ML (machine-learning) detection exclusion. WRITE ACTION —
    requires explicit user approval in the UI before execution.

    PRE-FLIGHT REQUIRED: this tool calls extras_list_ml_exclusions internally
    with a `value:'<value>'` filter and refuses to proceed if a match already
    exists, returning the existing exclusion's id. The agent should also
    surface this to the operator as part of the approval prompt.

    Args:
        value: The path / file glob to exclude. Use Falcon glob syntax:
            single `*` matches within a path segment, `**` matches across
            segments. Examples:
              - `C:\\Program Files\\MyApp\\bin\\worker.exe`
              - `/opt/datadog-agent/bin/agent`
              - `C:\\Users\\*\\AppData\\Local\\Temp\\build-*.exe`
        comment: Required free-text comment recorded with the exclusion.
            Document WHY this is benign — what the operator confirmed. Visible
            in Falcon Console; this is the audit trail.
        excluded_from: Which ML detection surface(s) to suppress. List of
            `blocking` (on-write ML prevention) and/or `extraction` (offline
            ML scan during file extraction). Default: `["blocking"]`.
        group_ids: Optional host-group ids to scope the exclusion to. Omit
            to apply globally — note that global is the heavier commitment.
    """
    if not value or not isinstance(value, str):
        return {"ok": False, "error": "value is required and must be a string"}
    if not comment or not isinstance(comment, str):
        return {
            "ok": False,
            "error": "comment is required — document WHY this exclusion is safe (audit trail)",
        }
    if excluded_from is None:
        excluded_from = ["blocking"]
    bad = [x for x in excluded_from if x not in _VALID_ML_EXCLUDED_FROM]
    if bad:
        return {
            "ok": False,
            "error": (
                f"invalid excluded_from values {bad}; must be from "
                f"{sorted(_VALID_ML_EXCLUDED_FROM)}"
            ),
        }
    # Pre-flight uniqueness check — saves an approval round-trip on a no-op.
    # FQL string literals are single-quote delimited; reject embedded single
    # quotes rather than trying to escape (would change query semantics).
    if "'" in value:
        return {
            "ok": False,
            "error": "value cannot contain a single-quote character (FQL literal delimiter)",
        }
    try:
        client = _get_ml_exclusions_client()
        existing = client.search_exclusions_v2(
            parameters={"filter": f"value:'{value}'", "limit": 5}
        )
        guard = _check_response(existing, "MLExclusions")
        if guard is not None:
            return guard
        existing_ids = ((existing or {}).get("body") or {}).get("resources") or []
        if existing_ids:
            return {
                "ok": False,
                "duplicate": True,
                "existing_ids": existing_ids,
                "error": (
                    f"An ML exclusion with value={value!r} already exists "
                    f"(id={existing_ids[0]}). Verify the existing exclusion "
                    f"covers your case before creating another."
                ),
            }
        body: dict[str, Any] = {
            "exclusions": [
                {
                    "value": value,
                    "comment": comment,
                    "excluded_from": list(excluded_from),
                }
            ]
        }
        if group_ids:
            body["exclusions"][0]["groups"] = list(group_ids)
        r = client.create_exclusions_v2(body=body)
        guard = _check_response(r, "MLExclusions")
        if guard is not None:
            return guard
        created = ((r or {}).get("body") or {}).get("resources") or []
        new_id = created[0].get("id") if created and isinstance(created[0], dict) else None
        return {
            "ok": True,
            "id": new_id,
            "value": value,
            "scope": "groups" if group_ids else "global",
            "excluded_from": list(excluded_from),
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


def list_ioa_exclusions(
    limit: int = 100,
    filter: str | None = None,
) -> dict[str, Any]:
    """List IOA (indicator-of-attack) exclusions on this tenant. Read-only.
    Always run this BEFORE proposing a new IOA exclusion so you can show the
    operator any existing matches and avoid duplicates.

    Args:
        limit: Max records (1-500). Default 100.
        filter: Optional FQL filter. Common forms:
            - `pattern_id:'12345'` — exclusions for a specific behavior pattern
            - `applied_globally:true`
            - `created_by:'analyst@example.com'`
    """
    try:
        client = _get_ioa_exclusions_client()
        capped = min(max(limit, 1), 500)
        # IOA exclusions endpoint rejects sort= entirely on this tenant
        # (HTTP 400 "Query string parameter 'sort' is not an allowable value")
        # — observed empirically. Omit it; default order is fine, and the
        # caller can apply their own ordering on `last_modified` from the
        # hydrated records.
        params: dict[str, Any] = {"limit": capped}
        if filter:
            params["filter"] = filter
        q = client.query_exclusions(parameters=params)
        guard = _check_response(q, "IOAExclusions")
        if guard is not None:
            return guard
        ids = ((q or {}).get("body") or {}).get("resources") or []
        if not ids:
            return {"ok": True, "items": [], "count": 0}
        d = client.get_exclusions(ids=ids)
        guard = _check_response(d, "IOAExclusions")
        if guard is not None:
            return guard
        records = ((d or {}).get("body") or {}).get("resources") or []
        items = [
            {
                "id": r.get("id"),
                "name": r.get("name"),
                "description": r.get("description"),
                "pattern_id": r.get("pattern_id"),
                "pattern_name": r.get("pattern_name"),
                "ifn_regex": r.get("ifn_regex"),
                "cl_regex": r.get("cl_regex"),
                "applied_globally": r.get("applied_globally"),
                "groups": [g.get("name") for g in (r.get("groups") or []) if isinstance(g, dict)],
                "group_ids": [g.get("id") for g in (r.get("groups") or []) if isinstance(g, dict)],
                "created_by": r.get("created_by"),
                "created_on": r.get("created_on"),
                "last_modified": r.get("last_modified"),
                "modified_by": r.get("modified_by"),
            }
            for r in records
            if isinstance(r, dict)
        ]
        return {"ok": True, "items": items, "count": len(items)}
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


def create_ioa_exclusion(
    name: str,
    pattern_id: str,
    ifn_regex: str,
    comment: str,
    cl_regex: str | None = None,
    description: str | None = None,
    group_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Create an IOA (indicator-of-attack) exclusion. WRITE ACTION — requires
    explicit user approval in the UI before execution.

    IOA exclusions suppress a specific behavior PATTERN combined with an image
    file (and optionally a cmdline) regex. Use when ML exclusion is too broad
    (would suppress all detections on a binary, not just one specific behavior).

    PRE-FLIGHT REQUIRED: this tool calls extras_list_ioa_exclusions internally
    with `pattern_id:'<pattern_id>'` and refuses to proceed if a match exists
    with the same `ifn_regex`, returning the existing id.

    Args:
        name: Short human-readable name for the exclusion.
        pattern_id: The Falcon behavior pattern id this exclusion suppresses.
            Get this from the detection's `behaviors[].pattern_id` field —
            do NOT guess. The agent should pull a sample detection via
            falcon_search_detections before composing this call.
        ifn_regex: Image file name regex (full-match anchored). Required.
            Example: `.*\\\\bin\\\\worker\\.exe$`
        comment: Required free-text comment — document WHY this behavior
            is benign on this binary. Visible in Falcon Console (audit trail).
        cl_regex: Optional command-line regex (full-match anchored). Narrows
            the exclusion to specific invocation patterns of the binary. Omit
            for "all invocations of this image."
        description: Optional longer description.
        group_ids: Optional host-group ids to scope to. Omit for global.
    """
    if not name or not isinstance(name, str):
        return {"ok": False, "error": "name is required"}
    if not pattern_id or not isinstance(pattern_id, str):
        return {"ok": False, "error": "pattern_id is required (from detection behaviors[].pattern_id)"}
    if not ifn_regex or not isinstance(ifn_regex, str):
        return {"ok": False, "error": "ifn_regex is required"}
    if not comment or not isinstance(comment, str):
        return {
            "ok": False,
            "error": "comment is required — document WHY this is safe (audit trail)",
        }
    if "'" in pattern_id:
        return {
            "ok": False,
            "error": "pattern_id cannot contain a single-quote (FQL literal delimiter)",
        }
    # Pre-flight: IOA engine rejects zero-width assertions (^, $, \b) and
    # rejects \A, \Z too. Catching this locally avoids a Falcon round-trip
    # that returns a cryptic "invalid DFA pattern" error and burns agent
    # tokens. See falcon_ioa_no_zero_width_assertions memory.
    for field_name, pattern in (("ifn_regex", ifn_regex), ("cl_regex", cl_regex)):
        if not isinstance(pattern, str):
            continue
        bad = _find_zero_width_assertion(pattern)
        if bad:
            return {
                "ok": False,
                "error": (
                    f"{field_name}: contains zero-width assertion {bad!r}, which the "
                    f"Falcon IOA engine rejects. Drop the anchor and bound with \\W "
                    f"trailing context instead (e.g. '...exe(\\W.*)?')."
                ),
            }
    try:
        client = _get_ioa_exclusions_client()
        existing = client.query_exclusions(
            parameters={"filter": f"pattern_id:'{pattern_id}'", "limit": 50}
        )
        guard = _check_response(existing, "IOAExclusions")
        if guard is not None:
            return guard
        existing_ids = ((existing or {}).get("body") or {}).get("resources") or []
        if existing_ids:
            d = client.get_exclusions(ids=existing_ids)
            d_guard = _check_response(d, "IOAExclusions")
            if d_guard is None:
                records = ((d or {}).get("body") or {}).get("resources") or []
                dupes = [
                    r.get("id")
                    for r in records
                    if isinstance(r, dict) and r.get("ifn_regex") == ifn_regex
                ]
                if dupes:
                    return {
                        "ok": False,
                        "duplicate": True,
                        "existing_ids": dupes,
                        "error": (
                            f"An IOA exclusion with pattern_id={pattern_id!r} and "
                            f"ifn_regex={ifn_regex!r} already exists (id={dupes[0]}). "
                            f"Verify it covers your case before creating another."
                        ),
                    }
        kwargs: dict[str, Any] = {
            "name": name,
            "pattern_id": pattern_id,
            "ifn_regex": ifn_regex,
            "comment": comment,
        }
        if cl_regex:
            kwargs["cl_regex"] = cl_regex
        if description:
            kwargs["description"] = description
        if group_ids:
            kwargs["groups"] = list(group_ids)
        # detection_json is required by the API to anchor the exclusion to a
        # concrete sample. Provide a minimal envelope referencing the pattern;
        # FalconPy passes it through as a string.
        kwargs["detection_json"] = json.dumps({"pattern_id": pattern_id})
        r = client.create_exclusions(**kwargs)
        guard = _check_response(r, "IOAExclusions")
        if guard is not None:
            return guard
        created = ((r or {}).get("body") or {}).get("resources") or []
        new_id = created[0].get("id") if created and isinstance(created[0], dict) else None
        return {
            "ok": True,
            "id": new_id,
            "name": name,
            "pattern_id": pattern_id,
            "ifn_regex": ifn_regex,
            "scope": "groups" if group_ids else "global",
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)

