"""Process-tree reconstruction + delivery-vector classification.

Used by the extras_host_process_tree sidecar tool. Kept as its own package
so the classifier ruleset is unit-testable in isolation from the NGSIEM
query plumbing.
"""

from .classifier import classify_delivery_vector, ANCHOR_CATALOG

__all__ = ["classify_delivery_vector", "ANCHOR_CATALOG"]
