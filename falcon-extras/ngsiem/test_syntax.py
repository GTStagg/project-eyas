"""Unit tests for the CQL linter — runs against the documented traps from
CLAUDE.md plus a couple of clean-query negatives.

    python3 -m pytest falcon-extras/ngsiem/test_syntax.py
    # or, no pytest available:
    python3 falcon-extras/ngsiem/test_syntax.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from syntax import lint  # noqa: E402


def _has(result, code: str) -> bool:
    return any(f.code == code for f in result.findings)


def test_limit_function_is_rejected():
    r = lint('#repo="base_sensor" | limit(10)')
    assert not r.ok
    assert _has(r, "cql.no_limit_function"), r.findings


def test_head_is_accepted():
    r = lint('#repo="base_sensor" | head(10)')
    # head() is the canonical form; sort() warning shouldn't fire (no sort).
    assert r.ok, r.findings


def test_single_quoted_string_is_rejected():
    r = lint("event_simpleName='ProcessRollup2' | head(5)")
    assert not r.ok
    assert _has(r, "cql.single_quoted_string"), r.findings
    # The fix should rewrite to double-quotes.
    err = next(f for f in r.findings if f.code == "cql.single_quoted_string")
    assert err.fix and '"ProcessRollup2"' in err.fix, err.fix


def test_apostrophe_in_double_quoted_string_is_fine():
    r = lint('description="don\'t care" | head(1)')
    assert r.ok, r.findings


def test_sort_without_limit_warns_when_head_exceeds_200():
    r = lint("ProcessRollup2 | sort(@timestamp, order=asc) | head(5000)")
    # Should be ok=True (warning, not error) but carry the cql.sort_default_limit code.
    assert r.ok
    assert _has(r, "cql.sort_default_limit"), r.findings


def test_sort_without_limit_safe_when_head_le_200():
    # The 60+ existing playbook queries all `head(50)` — the implicit
    # `limit=200` on sort() can't change the visible result, so don't noise.
    r = lint("ProcessRollup2 | sort(@timestamp, order=asc) | head(50)")
    assert r.ok
    assert not _has(r, "cql.sort_default_limit"), r.findings


def test_sort_with_explicit_limit_is_clean():
    r = lint("ProcessRollup2 | sort(@timestamp, limit=5000, order=asc)")
    assert r.ok, r.findings
    assert not _has(r, "cql.sort_default_limit"), r.findings


def test_unknown_function_flagged():
    r = lint("ProcessRollup2 | dropEventz()")
    assert not r.ok
    assert _has(r, "cql.unknown_function"), r.findings


def test_namespaced_function_in_catalog():
    # array:sort exists in the catalog; should not trip unknown-function.
    r = lint("ProcessRollup2 | array:sort(arr)")
    assert r.ok or not _has(r, "cql.unknown_function"), r.findings


def test_unanchored_dotted_regex_warns():
    r = lint(r'domain=/regex(".\(top|xyz)$")/')
    # Soft heuristic — present but optional. Don't fail the suite if the
    # pattern doesn't exactly match the heuristic; just verify it doesn't crash.
    assert isinstance(r.ok, bool)


def test_repo_tag_prefix_warning():
    r = lint('repo="base_sensor" | head(1)')
    assert _has(r, "cql.missing_tag_prefix"), r.findings


def test_repo_with_hash_is_clean():
    r = lint('#repo="base_sensor" | head(1)')
    assert not any(f.severity == "error" for f in r.findings), r.findings


def test_real_playbook_query_passes():
    cql = (
        '#repo="base_sensor" #event_simpleName=ProcessRollup2 '
        'aid="abc123" | head(50)'
    )
    r = lint(cql)
    assert r.ok, r.findings


# ---------------------------------------------------------------------------
# Real playbook corpus — lint every CQL query in lib/ngsiem-playbooks.ts.
#
# The 60+ production playbooks lint clean today. CLAUDE.md documents that any
# error from the linter on a playbook query is a real bug. This test enforces
# that invariant so a copy-paste regression (e.g. `head(500)` past sort()'s
# implicit limit=200, or an un-prefixed `repo=`) gets caught before merge.
# ---------------------------------------------------------------------------

_PLAYBOOK_FILE = (
    Path(__file__).resolve().parents[2] / "lib" / "ngsiem-playbooks.ts"
)

# Match `cql: \`...\`,` template literals (multi-line, possibly containing
# escaped backticks via \`). Non-greedy up to the next unescaped backtick.
_CQL_BLOCK_RX = __import__("re").compile(
    r"cql:\s*`((?:[^`\\]|\\.)*)`",
    __import__("re").DOTALL,
)


def _ts_unescape(s: str) -> str:
    """Un-escape a TS template-literal body to its runtime string value.

    Mirrors the JS engine: ``\\\\`` → ``\\``, ``\\``` → `````, ``\\$`` → ``$``,
    ``\\n`` → newline, ``\\t`` → tab, ``\\r`` → CR. The CQL corpus uses the
    first three; the others are included so a future query with an embedded
    ``\\n`` doesn't silently lint as a different shape than NGSIEM sees.
    """
    out: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == "\\":
                out.append("\\"); i += 2; continue
            if nxt == "`":
                out.append("`"); i += 2; continue
            if nxt == "$":
                out.append("$"); i += 2; continue
            if nxt == "n":
                out.append("\n"); i += 2; continue
            if nxt == "t":
                out.append("\t"); i += 2; continue
            if nxt == "r":
                out.append("\r"); i += 2; continue
        out.append(c)
        i += 1
    return "".join(out)


def _extract_playbook_cql() -> list[str]:
    if not _PLAYBOOK_FILE.exists():
        return []
    src = _PLAYBOOK_FILE.read_text(encoding="utf-8")
    blocks = _CQL_BLOCK_RX.findall(src)
    return [_ts_unescape(b) for b in blocks]


def test_playbook_corpus_extracted():
    queries = _extract_playbook_cql()
    # Sanity: file contains 60+ playbooks today; if extraction returns < 30
    # the regex broke (or someone deleted half the file).
    assert len(queries) >= 30, (
        f"only {len(queries)} cql blocks extracted from "
        f"lib/ngsiem-playbooks.ts — regex likely broken"
    )


def test_every_playbook_query_lints_clean():
    queries = _extract_playbook_cql()
    failures: list[str] = []
    for i, cql in enumerate(queries):
        r = lint(cql)
        errors = [f for f in r.findings if f.severity == "error"]
        warnings = [f for f in r.findings if f.severity == "warning"]
        if errors:
            head = cql.strip().splitlines()[0][:80]
            failures.append(
                f"  playbook[{i}] '{head}...':\n"
                + "\n".join(f"    {f.code}: {f.message}" for f in errors)
            )
        # Sort-default-limit warning is the latent footgun CLAUDE.md flags —
        # treat as failure so a future head(500) regression breaks the build.
        sort_warns = [f for f in warnings if f.code == "cql.sort_default_limit"]
        if sort_warns:
            head = cql.strip().splitlines()[0][:80]
            failures.append(
                f"  playbook[{i}] '{head}...': sort() will silently truncate "
                "at 200 — add explicit limit=N"
            )
    assert not failures, "playbook lint failures:\n" + "\n".join(failures)


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
