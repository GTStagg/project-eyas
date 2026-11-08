"""CQL pre-flight linter and syntax-lookup support.

The agent loop burns iterations correcting CQL syntax — a single 400 from the
NGSIEM API against a malformed query costs one round-trip and one
self-correction guess (often wrong). This module short-circuits the most
common traps *before* the query leaves the sidecar, so the agent gets one
structured ``cql_lint_error`` with the canonical fix in hand instead of
repeated trial-and-error against the live API.

Catalog (``catalog.json``, scraped from LogScale's public docs by
``build_catalog.py``) is the source of truth for "is this a real function?";
the rest of the rules encode the documented traps from ``CLAUDE.md``'s
"NGSIEM CQL syntax" section.

Public API:
    load_catalog() -> Catalog
    lint(cql, catalog=None) -> LintResult
    lookup_function(name, catalog=None) -> dict | None

Output shape stays JSON-clean so the linter can be surfaced through both the
sidecar's pre-flight error path and an MCP lookup tool.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CATALOG_PATH = Path(__file__).parent / "catalog.json"


# ---------------------------------------------------------------------------
# Catalog loading
# ---------------------------------------------------------------------------


@dataclass
class Catalog:
    by_name: dict[str, dict[str, Any]] = field(default_factory=dict)
    source: str = ""

    @property
    def function_names(self) -> set[str]:
        return set(self.by_name.keys())


_CACHED: Catalog | None = None


def load_catalog(path: Path | None = None) -> Catalog:
    """Load and memoize the function catalog. Falls back to an empty catalog
    if the JSON file is missing — the linter degrades to syntax-only checks
    rather than crashing the sidecar."""
    global _CACHED
    if _CACHED is not None and path is None:
        return _CACHED
    p = path or CATALOG_PATH
    try:
        data = json.loads(p.read_text())
    except FileNotFoundError:
        cat = Catalog()
        if path is None:
            _CACHED = cat
        return cat
    cat = Catalog(
        by_name={f["name"]: f for f in data.get("functions", [])},
        source=data.get("source", ""),
    )
    if path is None:
        _CACHED = cat
    return cat


def lookup_function(name: str, catalog: Catalog | None = None) -> dict[str, Any] | None:
    """Return the catalog record for ``name`` or ``None`` if unknown."""
    cat = catalog or load_catalog()
    return cat.by_name.get(name)


# ---------------------------------------------------------------------------
# Lint result types
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    code: str  # stable identifier — agent can key off this in error handling
    severity: str  # "error" | "warning"
    message: str
    position: int | None = None  # 0-based offset in the source CQL
    fix: str | None = None  # one-line suggested rewrite


@dataclass
class LintResult:
    ok: bool
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": [
                {
                    "code": f.code,
                    "message": f.message,
                    "position": f.position,
                    "fix": f.fix,
                }
                for f in self.findings
                if f.severity == "error"
            ],
            "warnings": [
                {
                    "code": f.code,
                    "message": f.message,
                    "position": f.position,
                    "fix": f.fix,
                }
                for f in self.findings
                if f.severity == "warning"
            ],
        }


# ---------------------------------------------------------------------------
# Tokenization helpers
# ---------------------------------------------------------------------------


# Strip comments + string literals before structural scans so a function-name
# regex doesn't match "groupBy(" inside a comment, and a single-quote scan
# doesn't false-positive on apostrophes inside double-quoted strings.
_LINE_COMMENT_RX = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RX = re.compile(r"/\*.*?\*/", re.S)
_DOUBLE_STR_RX = re.compile(r'"(?:\\.|[^"\\])*"')
# Slash-delimited regex literal — `field=/pattern/i`. Must contain at least
# one character, allow escaped slashes inside. We require the match to be
# preceded by an operator-ish character so eval-style `x/y` divisions don't
# get treated as the start of a regex.
_REGEX_LITERAL_RX = re.compile(r"(?<=[=~(,|\s])/(?:\\.|[^/\\\n]){1,400}?/[a-zA-Z]*")


def _blank(match: re.Match) -> str:
    """Replace a match with whitespace of the same length so character offsets
    in downstream regexes stay aligned with the original source."""
    return " " * (match.end() - match.start())


def _strip_for_scan(cql: str) -> str:
    s = _BLOCK_COMMENT_RX.sub(_blank, cql)
    s = _LINE_COMMENT_RX.sub(_blank, s)
    s = _DOUBLE_STR_RX.sub(_blank, s)
    s = _REGEX_LITERAL_RX.sub(_blank, s)
    return s


# Function-call detector: after a `|`, after `(`/`,`, or at start of query.
# Matches name + open paren. Captures the name.
_FN_CALL_RX = re.compile(
    r"(?:^|[|(,:=\s])([A-Za-z][A-Za-z0-9]*(?::[A-Za-z][A-Za-z0-9]*)?)\s*\("
)


# Reserved CQL keywords that look like function calls but aren't catalog
# functions (we shouldn't flag them as unknown).
_RESERVED_KEYWORDS = {
    "case",  # conditional construct
    # Logical operators (uppercase canonical, lowercase tolerated). These
    # commonly precede a grouping paren — `... OR (cond)` — and the function-
    # call detector would otherwise flag them as unknown functions.
    "OR",
    "AND",
    "NOT",
    "or",
    "and",
    "not",
    "IN",
    "in",
    "IS",
    "is",
    "TRUE",
    "FALSE",
    "true",
    "false",
}


# ---------------------------------------------------------------------------
# Lint rules
# ---------------------------------------------------------------------------


def _rule_unknown_function(cql: str, scan: str, cat: Catalog, out: list[Finding]) -> None:
    """Any function-call-shaped token whose name isn't in the catalog is
    almost certainly a typo or a hallucinated function name. Special-case
    the documented ``limit(`` trap with the canonical fix."""
    if not cat.by_name:
        return  # no catalog loaded → skip; would false-positive on every name
    seen: set[tuple[str, int]] = set()
    for m in _FN_CALL_RX.finditer(scan):
        name = m.group(1)
        pos = m.start(1)
        key = (name, pos)
        if key in seen:
            continue
        seen.add(key)
        if name in cat.by_name or name in _RESERVED_KEYWORDS:
            continue
        # Skip lowercase identifiers that are clearly used as field names (no
        # leading pipe). The detector regex requires `(`, so this catches
        # syntax like ``foo(...)`` mid-expression — usually a function call.
        if name == "limit":
            out.append(
                Finding(
                    code="cql.no_limit_function",
                    severity="error",
                    message=(
                        "`limit(N)` is not a CQL function. Use `head(N)` to keep the "
                        "first N rows or `tail(N)` for the last N. To cap a `sort()` "
                        "result, pass `limit=N` as a parameter inside `sort(...)`."
                    ),
                    position=pos,
                    fix=re.sub(r"\blimit\s*\(", "head(", cql, count=1),
                )
            )
            continue
        out.append(
            Finding(
                code="cql.unknown_function",
                severity="error",
                message=(
                    f"`{name}(...)` is not a documented CQL function. "
                    f"Check spelling, namespace prefix (e.g. `array:` / `time:` / `math:`), "
                    f"or call falcon_lookup_cql_function to find the right name."
                ),
                position=pos,
                fix=None,
            )
        )


def _rule_single_quoted_string(cql: str, scan: str, out: list[Finding]) -> None:
    """CQL string literals are double-quoted only. Single-quoted forms are a
    SQL/PromQL muscle-memory trap (CLAUDE.md NGSIEM section). We scan the
    *stripped* source so apostrophes inside ``"don't"`` aren't flagged."""
    # A single-quoted token: at least one char between quotes, no embedded \n.
    rx = re.compile(r"'(?:\\.|[^'\\\n])*'")
    seen_pos: set[int] = set()
    for m in rx.finditer(scan):
        if m.start() in seen_pos:
            continue
        seen_pos.add(m.start())
        literal = cql[m.start() : m.end()]
        # Convert to double-quoted form for the fix suggestion. Escape any
        # double-quotes that were inside.
        inner = literal[1:-1].replace('"', '\\"')
        fix_token = f'"{inner}"'
        out.append(
            Finding(
                code="cql.single_quoted_string",
                severity="error",
                message=(
                    "CQL string literals must be double-quoted. "
                    "Single-quoted strings are rejected by the parser."
                ),
                position=m.start(),
                fix=cql[: m.start()] + fix_token + cql[m.end() :],
            )
        )


def _rule_sort_without_limit(cql: str, scan: str, out: list[Finding]) -> None:
    """`sort()` defaults to `limit=200` and silently truncates regardless of a
    later `head(N)`. Only warn when there's evidence the user wants more than
    200 rows — explicit `head(>200)` / `tail(>200)`, or no row-cap at all.
    Suppresses the warning on the safe-by-construction `sort() | head(N≤200)`
    shape used by every existing playbook."""
    # Find the largest head(N) / tail(N) row-cap in the query, if any.
    head_caps = [int(m.group(1)) for m in re.finditer(r"\b(?:head|tail)\s*\(\s*(\d+)\s*\)", scan)]
    max_head = max(head_caps) if head_caps else None

    i = 0
    while True:
        m = re.search(r"\bsort\s*\(", scan[i:])
        if not m:
            return
        start = i + m.start()
        depth = 0
        j = i + m.end() - 1  # position of the '('
        end = None
        while j < len(scan):
            c = scan[j]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    end = j
                    break
            j += 1
        if end is None:
            return
        body = scan[i + m.end() : end]
        has_explicit_limit = bool(re.search(r"\blimit\s*=", body))
        # Suppress when sort() is followed/preceded by a head/tail that's
        # already ≤ the default 200 — the truncation can't change the result.
        safe_by_head = max_head is not None and max_head <= 200
        if not has_explicit_limit and not safe_by_head:
            out.append(
                Finding(
                    code="cql.sort_default_limit",
                    severity="warning",
                    message=(
                        "`sort()` defaults to `limit=200` and silently truncates "
                        "even when followed by `head(N)` for larger N. "
                        "Pass `limit=N` explicitly inside the sort call when you "
                        "expect more than 200 rows."
                    ),
                    position=start,
                    fix=None,
                )
            )
        i = end + 1


def _rule_unanchored_dotted_regex(cql: str, scan: str, out: list[Finding]) -> None:
    """Regex must be full-match anchored. Patterns like ``\\.(top|xyz)$`` look
    correct but only match if the *entire field value* starts with a dot —
    they miss ``evil.top``. Same trap with leading ``(^|\\.)``. Heuristic:
    flag double-quoted regex literals that start with one of these forms."""
    # Re-parse double-quoted literals (they were stripped from `scan`, so we
    # operate on the original source).
    for m in _DOUBLE_STR_RX.finditer(cql):
        body = m.group(0)[1:-1]
        # Only flag in regex-y contexts: very crude — preceded by `regex(` or
        # `=~ ` or `/` somewhere nearby. Cheap heuristic: look back 32 chars
        # for `regex` or `=~`.
        ctx = cql[max(0, m.start() - 40) : m.start()]
        if not re.search(r"regex\s*\(|=~|\/regex\b", ctx):
            continue
        bad = re.match(r"^(?:\\\.|\(\^\|\\\.\))", body)
        if not bad:
            continue
        out.append(
            Finding(
                code="cql.regex_unanchored_full_match",
                severity="warning",
                message=(
                    "CQL regex matches must be full-match anchored — leading "
                    "`\\.` or `(^|\\.)` only matches field values that start "
                    "with the dotted segment. Prepend `.*` to match anywhere "
                    "(e.g. `.*\\.(top|xyz)$`)."
                ),
                position=m.start() + 1,
                fix=None,
            )
        )


def _rule_tag_field_prefix(cql: str, scan: str, out: list[Finding]) -> None:
    """Tag fields require a leading ``#`` (CLAUDE.md). We can't know which
    fields are tags from the catalog alone, but we can flag the very common
    Falcon NGSIEM tag fields when used without ``#``."""
    # Known Falcon NGSIEM tag fields — list grows as we encounter false-
    # negatives. Keep the set tight to avoid noise.
    tag_fields = ("repo", "type", "Vendor")
    for tag in tag_fields:
        # Match `tag=` not preceded by `#` and not part of a longer identifier.
        rx = re.compile(rf"(?<![#A-Za-z0-9_]){re.escape(tag)}\s*=")
        for m in rx.finditer(scan):
            out.append(
                Finding(
                    code="cql.missing_tag_prefix",
                    severity="warning",
                    message=(
                        f"`{tag}` is a tag field — prefix with `#` "
                        f"(e.g. `#{tag}=...`) or the parser treats it as a regular field."
                    ),
                    position=m.start(),
                    fix=None,
                )
            )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def lint(cql: str, catalog: Catalog | None = None) -> LintResult:
    """Run all rules against ``cql`` and return a LintResult.

    The result is JSON-serializable via ``LintResult.to_dict()`` for direct
    return as a sidecar tool error payload."""
    cat = catalog or load_catalog()
    scan = _strip_for_scan(cql)
    findings: list[Finding] = []
    _rule_unknown_function(cql, scan, cat, findings)
    _rule_single_quoted_string(cql, scan, findings)
    _rule_sort_without_limit(cql, scan, findings)
    _rule_unanchored_dotted_regex(cql, scan, findings)
    _rule_tag_field_prefix(cql, scan, findings)
    has_error = any(f.severity == "error" for f in findings)
    return LintResult(ok=not has_error, findings=findings)
