"""Shadow-AI prevention: the Custom IOA rule corpus and the banned-group
provisioning. The hunting catalog lives in Eyas
(lib/eyas-tools/shadow-ai/catalog.ts).
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
__all__ = [
    "DISPOSITION_BLOCK",
    "DISPOSITION_DETECT",
    "SHADOW_AI_RULE_CORPUS",
    "SHADOW_AI_RULE_GROUP_DESCRIPTION",
    "SHADOW_AI_RULE_GROUP_NAME",
    "ShadowAiIoaRule",
    "rule_corpus_summary",
]
