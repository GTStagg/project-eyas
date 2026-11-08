"""NGSIEM/CQL syntax support — pre-flight linter and function catalog.

The linter short-circuits the most common CQL traps before a query reaches
the NGSIEM API, so the agent gets one structured ``cql_lint_error`` with the
canonical fix instead of burning iterations on trial-and-error against live
400 responses. The catalog is scraped offline by ``build_catalog.py`` and
committed for offline operation.
"""

from .syntax import (
    Catalog,
    Finding,
    LintResult,
    lint,
    load_catalog,
    lookup_function,
)

__all__ = [
    "Catalog",
    "Finding",
    "LintResult",
    "lint",
    "load_catalog",
    "lookup_function",
]
