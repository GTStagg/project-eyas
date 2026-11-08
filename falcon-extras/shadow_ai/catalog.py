"""Shadow-AI catalog: generative-AI desktop apps, SaaS egress endpoints,
MCP-server cmdline signatures, and local-inference listening ports.

Three signal layers correspond to three workplace risks:

  1. APPS — installed / running generative-AI desktop apps (Cursor, LM
     Studio, Ollama, Claude Desktop, etc.). Falcon for IT (osquery) covers
     this today; we replicate it from ProcessRollup2 so we can correlate
     with the other two layers in one pass.

  2. EGRESS — outbound traffic to public AI inference / chat endpoints
     (api.openai.com, api.anthropic.com, *.huggingface.co inference, etc.).
     This is the layer Falcon for IT misses entirely — a browser tab on
     chat.openai.com or a `curl api.openai.com/v1/chat/completions` from a
     dev's laptop never lands a binary on disk and never fires an
     osquery-shaped finding.

  3. MCP / agentic infra — process cmdline matching MCP-server
     conventions (`@modelcontextprotocol/...`, `mcp-server-*`, `uvx`
     spawning a known MCP package, agentic frameworks like LangChain /
     LangGraph / AutoGen / CrewAI). This is the layer no vendor catalogs
     today; the workplace risk is "an unsanctioned agent now has shell /
     RTR / source-control access."

Catalog is deliberately broad-but-curated. Sanctioned tools (org-deployed
GitHub Copilot Business, Microsoft 365 Copilot, Falcon GenAI itself) are
NOT excluded — the verdict layer flags them as `sanctioned` rather than
hiding them, so the operator sees coverage as well as gaps. The
operator-side allow-list (env-driven, future) overrides the verdict.

Refresh cadence: this catalog will go stale within weeks of any release
cycle. Treat it like the NGSIEM CQL function catalog — a seed list the
operator extends. Adding an entry is one tuple per layer.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Iterable


def get_sanctioned_tools() -> set[str]:
    """Return the set of tool ids the operator has sanctioned for this
    tenant.

    Read from `FALCON_SHADOW_AI_SANCTIONED` (comma-separated). The
    runtime overlays this from the active environment on each
    child-process spawn (lib/config/spawn-env.ts), so changes apply on
    the next sidecar invocation without a restart. Tool ids match the
    `tool` field in this catalog (e.g. "github-copilot",
    "m365-copilot", "falcon-genai").
    """
    raw = os.environ.get("FALCON_SHADOW_AI_SANCTIONED") or ""
    out: set[str] = set()
    for tok in raw.split(","):
        norm = tok.strip().lower()
        if norm:
            out.add(norm)
    return out

# ---------------------------------------------------------------------------
# Layer 1: AI desktop apps (image basename → canonical tool, family,
# posture-tag). Posture-tag drives the verdict layer:
#   - "model_developer"    : local model training / fine-tuning / inference
#                            (Ollama, LM Studio, llama.cpp, vLLM, ComfyUI)
#   - "agentic_client"     : MCP-aware agentic clients (Claude Desktop,
#                            Cursor, Cline, Continue) — strong correlation
#                            with MCP signal layer
#   - "saas_chat_client"   : desktop wrappers for SaaS chat (ChatGPT
#                            desktop, Perplexity desktop, Poe)
#   - "code_assistant"     : IDE-level code-completion clients (GitHub
#                            Copilot CLI, Cody, Tabby, Codeium)
#   - "image_video_gen"    : local image / video generation (ComfyUI,
#                            Automatic1111, Pinokio launcher)
# ---------------------------------------------------------------------------

# Each entry: (image_atom_regex, canonical_tool, family, posture_tag).
# The atom is anchored against the basename (case-insensitive); `\.exe$`
# is appended at compile-time. Atoms are kept narrow so they don't shadow
# unrelated binaries (e.g. `cursor` not `cur` so it doesn't catch `curl`).
AI_APP_CATALOG: list[tuple[str, str, str, str]] = [
    # Local inference / model developer tooling
    (r"ollama(?:\s+app)?", "Ollama", "ollama", "model_developer"),
    (r"ollama-app", "Ollama", "ollama", "model_developer"),
    (r"lm[\s_-]?studio", "LM Studio", "lmstudio", "model_developer"),
    (r"jan(?:-app)?", "Jan", "jan", "model_developer"),
    (r"msty", "Msty", "msty", "model_developer"),
    (r"gpt4all(?:[\w-]*)?", "GPT4All", "gpt4all", "model_developer"),
    (r"anythingllm(?:[\w-]*)?", "AnythingLLM", "anythingllm", "model_developer"),
    (r"llama[\s_-]?cpp", "llama.cpp", "llamacpp", "model_developer"),
    (r"text-generation-webui", "text-generation-webui", "tgwui", "model_developer"),
    (r"koboldcpp(?:[\w-]*)?", "KoboldCpp", "koboldcpp", "model_developer"),
    (r"vllm", "vLLM", "vllm", "model_developer"),
    # Agentic clients (these correlate strongly with MCP signal)
    (r"claude(?:[\s_-]?desktop)?", "Claude Desktop", "claude_desktop", "agentic_client"),
    (r"cursor", "Cursor", "cursor", "agentic_client"),
    (r"windsurf", "Windsurf", "windsurf", "agentic_client"),
    (r"cline", "Cline", "cline", "agentic_client"),
    (r"continue", "Continue", "continue", "agentic_client"),
    (r"goose", "Goose", "goose", "agentic_client"),
    # SaaS chat desktop wrappers
    (r"chatgpt", "ChatGPT (desktop)", "chatgpt_desktop", "saas_chat_client"),
    (r"perplexity", "Perplexity (desktop)", "perplexity_desktop", "saas_chat_client"),
    (r"poe", "Poe (desktop)", "poe_desktop", "saas_chat_client"),
    (r"you(?:[\s_-]?app)?", "You.com (desktop)", "you_desktop", "saas_chat_client"),
    # Code assistants
    (r"copilot(?:[\s_-]?cli)?", "GitHub Copilot CLI", "copilot_cli", "code_assistant"),
    (r"cody", "Sourcegraph Cody", "cody", "code_assistant"),
    (r"tabby", "Tabby", "tabby", "code_assistant"),
    (r"codeium", "Codeium", "codeium", "code_assistant"),
    (r"aider", "Aider", "aider", "code_assistant"),
    # Image / video generation
    (r"comfyui", "ComfyUI", "comfyui", "image_video_gen"),
    (r"pinokio", "Pinokio", "pinokio", "image_video_gen"),
    (r"a1111", "AUTOMATIC1111", "automatic1111", "image_video_gen"),
    (r"stable[\s_-]?diffusion", "Stable Diffusion (UI)", "sd_ui", "image_video_gen"),
    (r"invokeai", "InvokeAI", "invokeai", "image_video_gen"),
]

# Compiled basename matcher used by classify_app_image.
_AI_APP_PYRX = [
    (re.compile(rf"^{atom}\.exe$", re.IGNORECASE), tool, family, posture)
    for atom, tool, family, posture in AI_APP_CATALOG
]


def image_regex_alternation() -> str:
    """Return CQL-safe alternation of all AI app image atoms (without
    `.exe$`). Caller wraps this in `=/.*\\\\(?:<alt>)\\.exe$/i` for the
    full-match-anchored basename match the CQL parser requires.
    """
    return "|".join(atom for atom, _, _, _ in AI_APP_CATALOG)


def classify_app_image(image_path: str) -> tuple[str | None, str | None, str | None]:
    """Match an image path basename against AI_APP_CATALOG. Returns
    (tool, family, posture_tag) or (None, None, None) when no match.
    """
    if not image_path:
        return None, None, None
    basename = image_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    for rx, tool, family, posture in _AI_APP_PYRX:
        if rx.fullmatch(basename):
            return tool, family, posture
    return None, None, None


# ---------------------------------------------------------------------------
# Layer 1b: cleanup routing (deterministic uninstall selection).
#
# The ban-and-clean playbook used to carry a MANDATORY prompt instruction
# telling the agent to inspect each app's image paths, decide MSIX vs
# Squirrel, and pick the right uninstaller itself. That is exactly the
# "REQUIRED" step agents skip (feedback_deterministic_over_agent_instruction)
# — and skipping it fires the curated Squirrel script against an MSIX install,
# which no-ops and leaves the package to re-stage on next logon. So we compute
# it here instead: the scan hands each app entry a ready-to-fire cleanup plan
# and the agent just runs what's in it.
#
# family (from AI_APP_CATALOG) -> curated uninstaller id. These target the
# Squirrel / traditional per-user install form (DisplayName + registry
# Uninstall\<DisplayName>, root under %LOCALAPPDATA%). The MSIX/AppX form is
# handled by host-uninstall-appx-package instead.
# ---------------------------------------------------------------------------

FAMILY_CLEANUP_SCRIPT: dict[str, str] = {
    "cursor": "host-uninstall-cursor",
    "ollama": "host-uninstall-ollama",
    "lmstudio": "host-uninstall-lmstudio",
    "claude_desktop": "host-uninstall-claude-desktop",
    "comfyui": "host-uninstall-comfyui",
}

_APPX_SCRIPT = "host-uninstall-appx-package"


def _is_msix_path(p: str) -> bool:
    """MSIX/AppX install signature: the binary runs from WindowsApps (folder
    name carries the `__<publisherHash>` suffix) or per-user package state
    lives under AppData\\Local\\Packages\\<publisherHash>."""
    lp = p.lower()
    return "\\windowsapps\\" in lp or "\\appdata\\local\\packages\\" in lp


def _is_squirrel_path(p: str) -> bool:
    """Squirrel / per-user install signature: install root under %LOCALAPPDATA%
    (AppData\\Local\\...) but NOT the MSIX Packages subtree."""
    lp = p.lower()
    return "\\appdata\\local\\" in lp and "\\appdata\\local\\packages\\" not in lp


def _is_microsoft_windowsapps(p: str) -> bool:
    """A Microsoft-published Store package (WindowsApps\\Microsoft.*). Never
    host-uninstalled — host-uninstall-appx-package refuses `^Microsoft\\.` and
    the Copilot family is Group-Policy/Intune-managed, not a separable app."""
    return "\\windowsapps\\microsoft." in p.lower()


def _msix_package_pattern(image_paths: list[str]) -> str | None:
    """Derive the AppX package family name (the WindowsApps folder segment up
    to the first underscore) for host-uninstall-appx-package's
    `package_name_pattern`. E.g. ...\\WindowsApps\\Claude_1.2_x64__abc\\Claude.exe
    -> 'Claude'. Returns None when no WindowsApps path is present or the derived
    token wouldn't satisfy the script's param regex."""
    marker = "\\windowsapps\\"
    for p in image_paths:
        idx = p.lower().find(marker)
        if idx == -1:
            continue
        seg = p[idx + len(marker):].split("\\", 1)[0]  # <Family>_<ver>_<arch>__<hash>
        family = seg.split("_", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z0-9.*-]{1,128}", family):
            return family
    return None


def classify_distribution_form(image_paths: list[str]) -> str:
    """Classify an app's install form from its observed image paths:
    'msix', 'squirrel', 'both' (rare — user installed both), or 'unknown'."""
    paths = [p for p in image_paths if p]
    has_msix = any(_is_msix_path(p) for p in paths)
    has_squirrel = any(_is_squirrel_path(p) for p in paths)
    if has_msix and has_squirrel:
        return "both"
    if has_msix:
        return "msix"
    if has_squirrel:
        return "squirrel"
    return "unknown"


def cleanup_plan(
    family: str, image_paths: list[str]
) -> tuple[str, bool, list[dict[str, Any]]]:
    """Compute (distribution_form, microsoft_managed, cleanup[]) for one app.

    `cleanup` is the ordered list of {script_id, params} the ban-and-clean
    workflow fires via extras_rtr_run_cleanup — 0, 1, or 2 entries:
      - MSIX (non-Microsoft)    -> host-uninstall-appx-package + package_name_pattern
      - Squirrel/unknown + curated family -> the curated uninstaller (params {})
      - both forms observed     -> fire both
      - Microsoft Store package -> [] + microsoft_managed=True (Copilot STOP)
      - no curated script + unknown/squirrel form -> [] (kill+delete fallback)
    """
    form = classify_distribution_form(image_paths)
    if any(_is_microsoft_windowsapps(p) for p in image_paths if p):
        # Never auto-uninstall a Microsoft-published Store package.
        return form, True, []
    curated = FAMILY_CLEANUP_SCRIPT.get(family)
    plan: list[dict[str, Any]] = []
    if form in ("msix", "both"):
        pattern = _msix_package_pattern(image_paths)
        if pattern:
            plan.append(
                {"script_id": _APPX_SCRIPT, "params": {"package_name_pattern": pattern}}
            )
    if form in ("squirrel", "unknown", "both") and curated:
        plan.append({"script_id": curated, "params": {}})
    return form, False, plan



# ---------------------------------------------------------------------------
# Layer 2: Egress endpoints. These are FQDNs (not URL paths) — DNS
# resolution is the cheapest and most reliable signal in NGSIEM.
#
# Each entry: (domain_atom_regex, canonical_tool, posture_tag).
# Atoms are full-match-anchored against the FQDN (lowercased). `(?:.*\.)?`
# prefix is added at compile time so subdomains match (e.g. an atom like
# `openai\.com` matches both `api.openai.com` and `chat.openai.com`).
#
# posture_tag for egress collapses to the SaaS / agent / dev categories:
#   - "saas_inference_api"  : programmatic API endpoints (api.openai.com,
#                             api.anthropic.com) — typically dev / agent
#                             traffic, not browser
#   - "saas_chat_browser"   : human-facing chat UIs (chatgpt.com,
#                             claude.ai, gemini.google.com)
#   - "code_assistant_api"  : Copilot / Cody / Tabby / Codeium auth+infer
#                             endpoints
#   - "model_hub"           : model/dataset hosting (huggingface.co,
#                             replicate.com, modelscope, civitai)
#   - "agent_infra"         : MCP registries, agent platform APIs
#                             (smithery.ai, langsmith)
# ---------------------------------------------------------------------------

AI_EGRESS_CATALOG: list[tuple[str, str, str]] = [
    # SaaS inference APIs (programmatic)
    (r"api\.openai\.com", "OpenAI API", "saas_inference_api"),
    (r"api\.anthropic\.com", "Anthropic API", "saas_inference_api"),
    (r"generativelanguage\.googleapis\.com", "Google Gemini API", "saas_inference_api"),
    (r"api\.mistral\.ai", "Mistral API", "saas_inference_api"),
    (r"api\.cohere\.(?:com|ai)", "Cohere API", "saas_inference_api"),
    (r"api\.perplexity\.ai", "Perplexity API", "saas_inference_api"),
    (r"api\.together\.(?:ai|xyz)", "Together AI", "saas_inference_api"),
    (r"api\.fireworks\.ai", "Fireworks AI", "saas_inference_api"),
    (r"api\.groq\.com", "Groq API", "saas_inference_api"),
    (r"api\.deepseek\.com", "DeepSeek API", "saas_inference_api"),
    (r"api\.x\.ai", "xAI API", "saas_inference_api"),
    (r"api\.deepinfra\.com", "DeepInfra", "saas_inference_api"),
    (r"api\.openrouter\.ai", "OpenRouter", "saas_inference_api"),
    (r"openrouter\.ai", "OpenRouter", "saas_inference_api"),
    (r"router\.huggingface\.co", "HuggingFace Inference", "saas_inference_api"),
    (r"api-inference\.huggingface\.co", "HuggingFace Inference", "saas_inference_api"),
    # SaaS chat browser endpoints
    (r"chatgpt\.com", "ChatGPT (web)", "saas_chat_browser"),
    (r"chat\.openai\.com", "ChatGPT (web)", "saas_chat_browser"),
    (r"claude\.ai", "Claude (web)", "saas_chat_browser"),
    (r"gemini\.google\.com", "Gemini (web)", "saas_chat_browser"),
    (r"bard\.google\.com", "Bard (web)", "saas_chat_browser"),
    (r"copilot\.microsoft\.com", "Microsoft Copilot (web)", "saas_chat_browser"),
    (r"www\.perplexity\.ai", "Perplexity (web)", "saas_chat_browser"),
    (r"perplexity\.ai", "Perplexity (web)", "saas_chat_browser"),
    (r"poe\.com", "Poe", "saas_chat_browser"),
    (r"you\.com", "You.com", "saas_chat_browser"),
    (r"chat\.mistral\.ai", "Le Chat (Mistral)", "saas_chat_browser"),
    (r"chat\.deepseek\.com", "DeepSeek Chat", "saas_chat_browser"),
    (r"grok\.com", "Grok (web)", "saas_chat_browser"),
    (r"(?:.*\.)?character\.ai", "Character.ai", "saas_chat_browser"),
    (r"(?:.*\.)?janitorai\.com", "JanitorAI", "saas_chat_browser"),
    # Code assistant APIs (note: GitHub Copilot for Business is sanctioned
    # if env-allow-listed; the verdict layer downgrades.)
    (r"api\.github\.com", "GitHub API (incl. Copilot)", "code_assistant_api"),
    (r"copilot-proxy\.githubusercontent\.com", "GitHub Copilot", "code_assistant_api"),
    (r"api\.individual\.githubcopilot\.com", "GitHub Copilot (individual)", "code_assistant_api"),
    (r"api\.business\.githubcopilot\.com", "GitHub Copilot (business)", "code_assistant_api"),
    (r"sourcegraph\.com", "Sourcegraph Cody", "code_assistant_api"),
    (r"(?:.*\.)?sourcegraph\.com", "Sourcegraph Cody", "code_assistant_api"),
    (r"api\.tabnine\.com", "Tabnine", "code_assistant_api"),
    (r"server\.codeium\.com", "Codeium", "code_assistant_api"),
    (r"(?:.*\.)?codeium\.com", "Codeium", "code_assistant_api"),
    # Model / dataset hubs
    (r"huggingface\.co", "Hugging Face", "model_hub"),
    (r"(?:.*\.)?huggingface\.co", "Hugging Face", "model_hub"),
    (r"hf\.co", "Hugging Face", "model_hub"),
    (r"replicate\.com", "Replicate", "model_hub"),
    (r"api\.replicate\.com", "Replicate", "model_hub"),
    (r"civitai\.com", "Civitai", "model_hub"),
    (r"modelscope\.cn", "ModelScope", "model_hub"),
    (r"(?:.*\.)?modelscope\.cn", "ModelScope", "model_hub"),
    (r"ollama\.com", "Ollama (model registry)", "model_hub"),
    (r"registry\.ollama\.ai", "Ollama (model registry)", "model_hub"),
    # Agent / MCP infra
    (r"smithery\.ai", "Smithery (MCP registry)", "agent_infra"),
    (r"api\.smithery\.ai", "Smithery (MCP registry)", "agent_infra"),
    (r"(?:.*\.)?smithery\.ai", "Smithery (MCP registry)", "agent_infra"),
    (r"api\.smith\.langchain\.com", "LangSmith", "agent_infra"),
    (r"smith\.langchain\.com", "LangSmith", "agent_infra"),
    (r"api\.langchain\.com", "LangChain", "agent_infra"),
    (r"langfuse\.com", "Langfuse", "agent_infra"),
    (r"(?:.*\.)?langfuse\.com", "Langfuse", "agent_infra"),
    (r"helicone\.ai", "Helicone", "agent_infra"),
    (r"(?:.*\.)?helicone\.ai", "Helicone", "agent_infra"),
]

_AI_EGRESS_PYRX = [
    (re.compile(rf"^{atom}$", re.IGNORECASE), tool, posture)
    for atom, tool, posture in AI_EGRESS_CATALOG
]


def domain_regex_alternation() -> str:
    """Return CQL-safe alternation of all egress domain atoms. Caller
    wraps in `DomainName=/^(?:<alt>)$/i` for full-match anchoring.
    """
    return "|".join(atom for atom, _, _ in AI_EGRESS_CATALOG)


def classify_egress_domain(domain: str) -> tuple[str | None, str | None]:
    """Match a DNS query / connect domain against AI_EGRESS_CATALOG.
    Returns (tool, posture_tag) or (None, None) when no match.
    """
    if not domain:
        return None, None
    d = domain.strip().lower().rstrip(".")
    for rx, tool, posture in _AI_EGRESS_PYRX:
        if rx.fullmatch(d):
            return tool, posture
    return None, None


# ---------------------------------------------------------------------------
# Layer 3: MCP-server + agentic-framework cmdline signatures.
#
# Each entry: (cmdline_substring_or_regex, canonical_tool, family, kind,
# posture_tag). `kind` is "literal" for plain substring or "regex" for
# `re.search`.
#
# posture_tag here is always either "mcp_host" (process IS an MCP server)
# or "agentic_framework" (process is an agent loop / orchestrator). Both
# warrant the same operator response: identify, scope, sanction or remove.
# ---------------------------------------------------------------------------

MCP_CMDLINE_CATALOG: list[tuple[str, str, str, str, str]] = [
    # Direct MCP server invocations
    ("@modelcontextprotocol/server-", "MCP server (npm)", "mcp_npm", "literal", "mcp_host"),
    ("@modelcontextprotocol/sdk", "MCP SDK", "mcp_sdk", "literal", "mcp_host"),
    ("mcp-server-", "MCP server (binary)", "mcp_binary", "literal", "mcp_host"),
    (r"\bmcp[_-]?server\b", "MCP server (generic)", "mcp_generic", "regex", "mcp_host"),
    # uvx-spawned MCP packages (pattern: `uvx <pkg-name>` where pkg starts with mcp- / awslabs.mcp- / etc.)
    (r"\buvx\s+(?:--from\s+\S+\s+)?(?:mcp[-_]|awslabs\.mcp[-_]|@?[\w-]+/mcp[-_])", "MCP server (uvx)", "mcp_uvx", "regex", "mcp_host"),
    # Agentic frameworks
    ("langchain", "LangChain", "langchain", "literal", "agentic_framework"),
    ("langgraph", "LangGraph", "langgraph", "literal", "agentic_framework"),
    ("autogen-agentchat", "Microsoft AutoGen", "autogen", "literal", "agentic_framework"),
    ("autogenstudio", "Microsoft AutoGen Studio", "autogen_studio", "literal", "agentic_framework"),
    ("crewai", "CrewAI", "crewai", "literal", "agentic_framework"),
    ("llama_index", "LlamaIndex", "llamaindex", "literal", "agentic_framework"),
    ("llamaindex", "LlamaIndex", "llamaindex", "literal", "agentic_framework"),
    ("haystack", "Haystack", "haystack", "literal", "agentic_framework"),
    ("semantic-kernel", "Semantic Kernel", "semantic_kernel", "literal", "agentic_framework"),
    ("semantic_kernel", "Semantic Kernel", "semantic_kernel", "literal", "agentic_framework"),
    ("dspy", "DSPy", "dspy", "literal", "agentic_framework"),
    ("@anthropic-ai/sdk", "Anthropic SDK (npm)", "anthropic_sdk", "literal", "agentic_framework"),
    ("@anthropic-ai/claude-code", "Claude Code", "claude_code", "literal", "agentic_framework"),
    # Self-hosted agent loops
    ("openinterpreter", "Open Interpreter", "open_interpreter", "literal", "agentic_framework"),
    ("open-interpreter", "Open Interpreter", "open_interpreter", "literal", "agentic_framework"),
    ("autogpt", "Auto-GPT", "autogpt", "literal", "agentic_framework"),
    ("babyagi", "BabyAGI", "babyagi", "literal", "agentic_framework"),
    ("agentgpt", "AgentGPT", "agentgpt", "literal", "agentic_framework"),
    ("smol-developer", "smol-developer", "smol_developer", "literal", "agentic_framework"),
    ("gpt-engineer", "GPT-Engineer", "gpt_engineer", "literal", "agentic_framework"),
    ("aider-chat", "Aider", "aider", "literal", "agentic_framework"),
    ("aider --", "Aider", "aider", "literal", "agentic_framework"),
]


@dataclass
class MCPSignatureMatch:
    tool: str
    family: str
    posture: str
    matched_token: str


def classify_mcp_cmdline(cmdline: str) -> MCPSignatureMatch | None:
    """Scan a process command line for MCP-server / agentic-framework
    signatures. Returns the first match (catalog order = priority) or
    None. Match is case-insensitive.
    """
    if not cmdline:
        return None
    haystack = cmdline.lower()
    for token, tool, family, kind, posture in MCP_CMDLINE_CATALOG:
        if kind == "literal":
            if token.lower() in haystack:
                return MCPSignatureMatch(tool=tool, family=family, posture=posture, matched_token=token)
        else:  # regex
            m = re.search(token, cmdline, re.IGNORECASE)
            if m:
                return MCPSignatureMatch(
                    tool=tool, family=family, posture=posture, matched_token=m.group(0)[:120]
                )
    return None


# ---------------------------------------------------------------------------
# Local inference listening ports — for hosts where we observe an
# OUTBOUND connection from a non-AI process to a localhost port that
# matches a known local-inference server. Useful for catching the case
# where a user runs Ollama on their workstation (port 11434) and a
# browser / IDE talks to it. Port-only signal is weak; combine with the
# app or cmdline layer before flagging.
# ---------------------------------------------------------------------------

LOCAL_INFERENCE_PORTS: dict[int, str] = {
    11434: "Ollama",
    1234: "LM Studio",
    8080: "llama.cpp / generic",  # high false-positive — many things use 8080
    8000: "vLLM / generic",
    7860: "Gradio (HF Spaces local)",
    7861: "Gradio (HF Spaces local)",
    11435: "Ollama (alt)",
    5001: "KoboldCpp",
    8188: "ComfyUI",
    7869: "text-generation-webui",
    3000: "AnythingLLM / generic",  # high false-positive
}

# Subset of LOCAL_INFERENCE_PORTS unambiguous enough to use as a primary
# NGSIEM filter. Excludes 8080 / 8000 / 3000 (massively shared with web
# dev tooling); a peer on those ports plus *no* other AI signal is more
# likely a webpack dev server than vLLM. The full dict is still used for
# label lookup when one of those ports surfaces alongside other signals.
LOCAL_INFERENCE_PORTS_HIGH_CONFIDENCE: tuple[int, ...] = (
    11434,
    11435,
    1234,
    5001,
    8188,
    7860,
    7861,
    7869,
)


def classify_local_inference_port(port: int | None) -> str | None:
    """Return the canonical tool name for a local-inference port, or
    None if the port isn't in the catalog.
    """
    if port is None:
        return None
    return LOCAL_INFERENCE_PORTS.get(int(port))


def is_loopback_ipv4(addr: str | None) -> bool:
    """Cheap check: address in 127.0.0.0/8 (loopback). Avoids pulling
    ipaddress for what is one prefix comparison."""
    if not isinstance(addr, str) or not addr:
        return False
    return addr.startswith("127.")


# ---------------------------------------------------------------------------
# Verdict / posture layer.
#
# Inputs: bag of (signal_type, posture_tag) tuples observed on a host
# across the three layers. Output: a single posture verdict, intended to
# drive UI grouping + remediation primer routing.
#
# Verdicts (most→least concerning to a SOC operator):
#   - "model_developer"   : host runs local inference / training. High
#                           data-egress risk on training data,
#                           proprietary code embedded in prompts, etc.
#                           Often a developer workstation.
#   - "mcp_host"          : host runs an MCP server. Agent has whatever
#                           permissions the MCP server exposes — file
#                           system, browser, source control, RTR. The
#                           highest-blast-radius category.
#   - "agentic_developer" : host runs an agent loop / framework but no
#                           MCP server. Building / experimenting.
#   - "unsanctioned_saas" : pure egress to SaaS chat / inference, no
#                           local app or MCP signal. Browser-only or
#                           ad-hoc curl. Low blast radius, high DLP risk.
#   - "code_assistant"    : code-assistant traffic only. Often
#                           sanctioned (Copilot Business) — flag for
#                           operator allow-list confirmation.
#   - "image_video_gen"   : creative-AI tooling. Different DLP model.
#   - "sanctioned"        : ONLY signals that match an operator-supplied
#                           allow-list. (Allow-list integration is a
#                           future pass — placeholder posture today.)
#   - "no_signal"         : no AI signal observed.
#
# Precedence: model_developer > mcp_host > agentic_developer >
# code_assistant > image_video_gen > unsanctioned_saas > no_signal.
# ---------------------------------------------------------------------------

_VERDICT_PRECEDENCE = [
    "model_developer",
    "mcp_host",
    "agentic_developer",
    "code_assistant",
    "image_video_gen",
    "unsanctioned_saas",
    "sanctioned",
    "no_signal",
]


def classify_posture(signals: Iterable[tuple[str, str]]) -> str:
    """Reduce a bag of (layer, posture_tag) signals to a single verdict.

    `layer` is one of {"app", "egress", "mcp"}. `posture_tag` is the
    layer-specific tag from one of the three catalogs.
    """
    sigs = list(signals)
    if not sigs:
        return "no_signal"

    has_local_model = any(p == "model_developer" for _, p in sigs)
    has_mcp_host = any(layer == "mcp" and p == "mcp_host" for layer, p in sigs)
    has_agentic_framework = any(
        layer == "mcp" and p == "agentic_framework" for layer, p in sigs
    )
    has_agentic_client_app = any(
        layer == "app" and p == "agentic_client" for layer, p in sigs
    )
    has_code_assistant = any(
        p in ("code_assistant", "code_assistant_api") for _, p in sigs
    )
    has_image_video = any(p == "image_video_gen" for _, p in sigs)
    has_saas_egress = any(
        p in ("saas_inference_api", "saas_chat_browser", "model_hub", "agent_infra")
        for _, p in sigs
    )
    has_saas_chat_app = any(
        layer == "app" and p == "saas_chat_client" for layer, p in sigs
    )

    if has_local_model:
        return "model_developer"
    if has_mcp_host:
        return "mcp_host"
    if has_agentic_framework or has_agentic_client_app:
        return "agentic_developer"
    if has_code_assistant and not has_saas_egress and not has_saas_chat_app:
        return "code_assistant"
    if has_image_video:
        return "image_video_gen"
    if has_saas_egress or has_saas_chat_app:
        return "unsanctioned_saas"
    if has_code_assistant:
        return "code_assistant"
    return "no_signal"


def verdict_severity(verdict: str) -> int:
    """Smaller is more concerning. Used to sort hosts in the UI."""
    try:
        return _VERDICT_PRECEDENCE.index(verdict)
    except ValueError:
        return len(_VERDICT_PRECEDENCE)
