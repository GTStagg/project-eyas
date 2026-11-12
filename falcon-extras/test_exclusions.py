"""Unit tests for the IOA-exclusion regex pre-flight check.

Falcon's IOA DFA engine rejects zero-width assertions (``^``, ``$``,
``\\b``, ``\\A``, ``\\Z``, ``\\B``). ``_find_zero_width_assertion`` runs on
every ``ifn_regex`` / ``cl_regex`` before the create call so the operator
gets a local, useful error instead of an opaque Falcon rejection. It must
also NOT flag the legal look-alikes: escaped anchors, and ``^`` / ``$`` /
``\\b`` inside a character class.

Run:
    falcon-extras/.venv/bin/python3 falcon-extras/test_exclusions.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from exclusions import _find_zero_width_assertion as f  # noqa: E402

CASES = [
    # (pattern, expected)
    (r".*\\powershell\.exe(\W.*)?", None),  # the IR-readiness pattern
    (r".*\\powershell\.exe$", "$"),
    (r"^.*\\cmd\.exe", "^"),
    (r".*\bmimikatz\b.*", r"\b"),
    (r"\A.*", r"\A"),
    (r".*\Z", r"\Z"),
    (r".*\B.*", r"\B"),
    (r".*\$HOME.*", None),  # escaped dollar is a literal
    (r".*\\\\$", "$"),  # escaped backslash, then a real anchor
    (r"[^/]*\.exe", None),  # class negation
    (r"[$]x", None),  # dollar inside a class
    (r"[\b]x", None),  # backspace inside a class
    (r"[]^]x", None),  # leading ] is a literal, ^ inside the class
    (r"[^]$]x", None),
    (r"[a-z]+$", "$"),  # the class closed before the anchor
    ("", None),
]


def main() -> int:
    failed = 0
    for pattern, want in CASES:
        got = f(pattern)
        ok = got == want
        failed += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {pattern!r} -> {got!r}" + ("" if ok else f" (want {want!r})"))
    print(f"\n{len(CASES) - failed}/{len(CASES)} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
