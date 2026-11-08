"""Shadow-AI catalog + classification.

Used by the extras_host_shadow_ai_scan + extras_fleet_shadow_ai_egress
sidecar tools. Kept as its own package so the catalog (which grows weekly
as new tools ship) is editable without touching server.py.
"""

from .ioa_rules import (
    DISPOSITION_BLOCK,
    DISPOSITION_DETECT,
    SHADOW_AI_RULE_CORPUS,
    SHADOW_AI_RULE_GROUP_DESCRIPTION,
    SHADOW_AI_RULE_GROUP_NAME,
    ShadowAiIoaRule,
    rule_corpus_summary,
)
from .catalog import (
    AI_APP_CATALOG,
    AI_EGRESS_CATALOG,
    MCP_CMDLINE_CATALOG,
    LOCAL_INFERENCE_PORTS,
    LOCAL_INFERENCE_PORTS_HIGH_CONFIDENCE,
    classify_app_image,
    classify_egress_domain,
    classify_mcp_cmdline,
    classify_local_inference_port,
    classify_posture,
    classify_distribution_form,
    cleanup_plan,
    image_regex_alternation,
    domain_regex_alternation,
    is_loopback_ipv4,
)

__all__ = [
    "AI_APP_CATALOG",
    "AI_EGRESS_CATALOG",
    "MCP_CMDLINE_CATALOG",
    "LOCAL_INFERENCE_PORTS",
    "LOCAL_INFERENCE_PORTS_HIGH_CONFIDENCE",
    "classify_app_image",
    "classify_egress_domain",
    "classify_mcp_cmdline",
    "classify_local_inference_port",
    "classify_posture",
    "classify_distribution_form",
    "cleanup_plan",
    "image_regex_alternation",
    "domain_regex_alternation",
    "is_loopback_ipv4",
    "DISPOSITION_BLOCK",
    "DISPOSITION_DETECT",
    "SHADOW_AI_RULE_CORPUS",
    "SHADOW_AI_RULE_GROUP_DESCRIPTION",
    "SHADOW_AI_RULE_GROUP_NAME",
    "ShadowAiIoaRule",
    "rule_corpus_summary",
]
