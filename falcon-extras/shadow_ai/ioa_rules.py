"""Curated Custom IOA rule corpus for Shadow-AI prevention.

Each rule is a Process-Creation IOA rule that BLOCKS (disposition_id=30,
"Block Execution") the launch of an unsanctioned-AI binary or a known
MCP-server / agent runtime cmdline pattern. The rule group is bound to a
Prevention Policy
which the operator pre-attaches to the AI-Banned host group; hosts
moved into that group via `extras_host_group_action(add-hosts)` start
enforcing the ruleset on next sensor heartbeat.

Design notes:
  * One single rule group, name "Project Eyas - Shadow-AI Block",
    Windows-only. Adding mac/linux is straight extension once we have
    the catalog atoms for those.
  * Rules are AUTHORED here (declarative dataclass) and rendered into
    the FalconPy `create_rule` payload by `to_field_values`. No agent
    ever supplies a rule body.
  * Process-Creation ruletype_id is looked up at adoption time (it is
    deterministic per tenant but not constant across Falcon platform
    deployments).
  * Two rule shapes:
      (a) IMAGE-only — `ImageFileName` regex (full-match-anchored
          basename) blocks the binary regardless of how it was
          launched. Used for desktop apps with stable image names
          (Cursor, Ollama, LM Studio, Claude Desktop).
      (b) IMAGE+CMDLINE — `ImageFileName` matches an interpreter
          (python.exe / node.exe / npx.exe / uvx.exe) AND `CommandLine`
          matches an MCP/agent-runtime regex. Used for the agent-loop
          and MCP-server cases where the image is a generic runtime.
  * disposition_id 30 = "Block Execution" (prevents the process from
    running — the actual kill). 20 = "Detect" (raises a detection only);
    10 = "Monitor" (log only). The adoption tool's `mode` arg selects
    'block' (30) or 'detect' (20); the default is 'block' so provisioning
    enforces. Rules are also created DISABLED by Falcon and must be
    enabled via update_rules — the adoption tool does that automatically.

Adoption is idempotent: running twice creates the rule group once and
appends only missing rules. Rule "name" is the dedup key.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# disposition_id values per Falcon's Custom IOA "Process Creation"
# disposition_map (confirmed live against the ruletype, 2026-06-30):
#   10 = Monitor          (log only)
#   20 = Detect           (raises a detection — does NOT block)
#   30 = Block Execution  (prevents the process from running — the kill)
# HISTORY: this file previously had BLOCK=20 / DETECT=10, which is off by
# one notch against the real map — so "block mode" only ever set Detect
# (20) and nothing was ever prevented, and "detect" set Monitor (10).
# 30 is the enforcing disposition for Process Creation rules.
DISPOSITION_MONITOR = 10
DISPOSITION_DETECT = 20
DISPOSITION_BLOCK = 30


@dataclass(frozen=True)
class ShadowAiIoaRule:
    name: str
    description: str
    pattern_severity: str  # "informational" / "low" / "medium" / "high" / "critical"
    image_regex: str  # full-match-anchored basename regex, e.g. r".*\\Cursor\.exe"
    cmdline_regex: str | None = None  # optional CommandLine regex
    parent_image_regex: str | None = None  # optional ParentImageFileName regex
    rationale_tag: str = ""  # short freeform tag used in rule comment

    def to_field_values(self) -> list[dict]:
        """Render the rule's match conditions as Falcon Custom IOA
        `field_values`. Each entry is a Process-Creation rule field
        with type `excludable` and a single positive value.
        """
        fields: list[dict] = []
        if self.image_regex:
            fields.append(
                {
                    "name": "ImageFilename",
                    "label": "Image Filename",
                    "type": "excludable",
                    "values": [{"label": "include", "value": self.image_regex}],
                }
            )
        if self.cmdline_regex:
            fields.append(
                {
                    "name": "CommandLine",
                    "label": "Command Line",
                    "type": "excludable",
                    "values": [{"label": "include", "value": self.cmdline_regex}],
                }
            )
        if self.parent_image_regex:
            fields.append(
                {
                    "name": "ParentImageFilename",
                    "label": "Parent Image Filename",
                    "type": "excludable",
                    "values": [{"label": "include", "value": self.parent_image_regex}],
                }
            )
        return fields


# Rule group identity — used for idempotent lookup-by-name on adoption.
# Per-platform: Falcon Custom IOA rule groups are platform-scoped, so a
# Windows-platform group can't bind to a macOS / Linux prevention policy
# (Falcon API rejects cross-platform binds with HTTP 400). Each platform
# gets its own group with its own corpus authored against the platform's
# Process Creation ruletype.
SHADOW_AI_RULE_GROUP_NAME = "Project Eyas - Shadow-AI Block"  # Windows (legacy bare name)
SHADOW_AI_RULE_GROUP_NAMES = {
    "windows": "Project Eyas - Shadow-AI Block",
    "mac": "Project Eyas - Shadow-AI Block (mac)",
    "linux": "Project Eyas - Shadow-AI Block (linux)",
}
SHADOW_AI_RULE_GROUP_DESCRIPTION = (
    "Blocks unsanctioned generative-AI desktop apps, MCP servers, and agent "
    "runtimes on hosts assigned to the AI-Banned host group. Authored by "
    "Project Eyas via extras_shadow_ai_adopt_prevention. Edit in Falcon "
    "Console if you need to tune; the adoption tool is idempotent and will "
    "not overwrite operator changes once the rule already exists by name."
)


# Curated rule corpus. Order is informational only (Falcon evaluates all
# matching rules); operators can re-order in the console.
SHADOW_AI_RULE_CORPUS: list[ShadowAiIoaRule] = [
    ShadowAiIoaRule(
        name="ShadowAI: Cursor (agentic IDE)",
        description=(
            "Blocks Cursor.exe (Anysphere / Cursor) — agentic IDE with "
            "built-in MCP client and hosted agent loop. Per-user Squirrel "
            "install at %LOCALAPPDATA%\\Programs\\cursor."
        ),
        pattern_severity="medium",
        image_regex=r".*\\Cursor\.exe",
        rationale_tag="cursor",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Ollama (local-inference runtime)",
        description=(
            "Blocks Ollama daemon + tray + helper images. Local LLM runtime "
            "exposing an OpenAI-compatible REST API on 11434; main local-"
            "inference data-egress surface. Both `ollama.exe` and "
            "`ollama app.exe` (tray) are matched."
        ),
        pattern_severity="medium",
        image_regex=r".*\\(?:ollama|ollama app|ollama_llama_server)\.exe",
        rationale_tag="ollama",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: LM Studio (local-inference desktop)",
        description=(
            "Blocks LM Studio desktop. Squirrel-installed Electron app that "
            "exposes an OpenAI-compatible local server on 1234 by default."
        ),
        pattern_severity="medium",
        image_regex=r".*\\(?:LM Studio|lms)\.exe",
        rationale_tag="lmstudio",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Claude Desktop (Anthropic, MCP host)",
        description=(
            "Blocks Claude Desktop. The MCP-host capability (claude_desktop_"
            "config.json registers MCP servers that inherit user privileges) "
            "is the load-bearing reason — preserving Claude itself without "
            "MCP wiring is not a posture the app supports."
        ),
        pattern_severity="medium",
        image_regex=r".*\\AnthropicClaude\\.*\\Claude\.exe",
        rationale_tag="claude_desktop",
    ),
    # Installer-shape rules. The post-install binary rules above only fire
    # at LAUNCH — by the time they hit, the installer has already written
    # files to disk and the operator perceives the install as "successful."
    # These rules block the Squirrel / NSIS installer process directly so
    # re-installation after Ban+Clean fails at the installer step.
    ShadowAiIoaRule(
        name="ShadowAI: Claude Desktop installer (Squirrel)",
        description=(
            "Blocks Anthropic's Claude-Setup.exe Squirrel installer. Pairs "
            "with the post-install Claude.exe rule so re-installs after "
            "Ban+Clean fail at the installer, not just the launch step."
        ),
        pattern_severity="medium",
        image_regex=r".*\\Claude[-_.]?Setup(?:[-_.][\d.]+)?\.exe",
        rationale_tag="claude_desktop_installer",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Cursor installer (Squirrel)",
        description=(
            "Blocks Cursor-Setup-X.Y.Z-{x64,arm64}.exe (Anysphere). Same "
            "reasoning as the Claude Desktop installer — IOA at launch is "
            "necessary but not sufficient against re-install."
        ),
        pattern_severity="medium",
        image_regex=r".*\\Cursor[-_]?Setup(?:[-_.][\w.]+)*\.exe",
        rationale_tag="cursor_installer",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: LM Studio installer",
        description=(
            "Blocks LM-Studio-X.Y.Z-Setup.exe / LM-Studio-Setup.exe. NSIS-"
            "shaped installer; covers both versioned and bare names."
        ),
        pattern_severity="medium",
        image_regex=r".*\\LM[-_. ]?Studio[-_. ]?(?:[\d.]+[-_. ])?Setup\.exe",
        rationale_tag="lmstudio_installer",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Ollama installer",
        description=(
            "Blocks OllamaSetup.exe (the only installer name Ollama ships). "
            "Pairs with the ollama.exe / ollama-app.exe runtime rules."
        ),
        pattern_severity="medium",
        image_regex=r".*\\Ollama[-_.]?Setup\.exe",
        rationale_tag="ollama_installer",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: ComfyUI (local image/video generation)",
        description=(
            "Blocks python.exe / pythonw.exe whose CommandLine references "
            "ComfyUI's main.py or server.py. ComfyUI is not a packaged "
            "installer — image-only rules don't apply; cmdline match is the "
            "only reliable signal."
        ),
        pattern_severity="medium",
        image_regex=r".*\\(?:python|pythonw|python3)\.exe",
        cmdline_regex=r".*[\\/](?:ComfyUI|comfyui)[\\/](?:main|server)\.py.*",
        rationale_tag="comfyui",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: MCP server (npm @modelcontextprotocol)",
        description=(
            "Blocks node.exe / npx.exe spawning an @modelcontextprotocol/* "
            "package. This is the canonical npm-distributed MCP server "
            "shape; the agent gets whatever capabilities the server "
            "exposes (filesystem, github, shell) under the user's identity."
        ),
        pattern_severity="high",
        image_regex=r".*\\(?:node|npx|npx-cli)\.exe",
        cmdline_regex=r".*@modelcontextprotocol\/(?:server-|sdk).*",
        rationale_tag="mcp_npm",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: MCP server (uvx Python launcher)",
        description=(
            "Blocks uvx.exe spawning an mcp-* / awslabs.mcp-* / @org/mcp-* "
            "package. uvx is the de-facto Python MCP-server launcher; the "
            "package-name pattern is stable across MCP server publishers."
        ),
        pattern_severity="high",
        image_regex=r".*\\uvx\.exe",
        cmdline_regex=r".*\W(?:mcp[-_]|awslabs\.mcp[-_]|@?[\w-]+\/mcp[-_]).*",
        rationale_tag="mcp_uvx",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: MCP server (python -m mcp_server / mcp-server-*)",
        description=(
            "Blocks python.exe -m mcp_server* / mcp-server-* invocations "
            "(self-hosted MCP servers run directly via the python module "
            "system rather than via uvx)."
        ),
        pattern_severity="high",
        image_regex=r".*\\(?:python|pythonw|python3)\.exe",
        cmdline_regex=r".*\W(?:-m\s+mcp[-_]?server|mcp[-_]server[-_])[\w.-]*.*",
        rationale_tag="mcp_python",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Aider (agentic coding loop)",
        description=(
            "Blocks the Aider agentic-coding REPL. Aider runs as `python -m "
            "aider` or via the `aider` console_script; the cmdline match "
            "covers both shapes."
        ),
        pattern_severity="medium",
        image_regex=r".*\\(?:python|pythonw|python3|aider)\.exe",
        cmdline_regex=r".*\W(?:-m\s+aider|aider(?:[-_]chat)?)(?:\W.*)?",
        rationale_tag="aider",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: DeepSeek model load (any runtime)",
        description=(
            "Blocks any process whose CommandLine references a DeepSeek "
            "model name (deepseek-r1 / deepseek-v3 / deepseek-coder / "
            "deepseek-chat / deepseek-llm / deepseek-moe). Catches the "
            "case where Ollama / LM Studio / llama.cpp themselves are "
            "sanctioned but loading a DeepSeek-family weight isn't. "
            "DeepSeek is hosted in China and the company's published "
            "policy explicitly states user prompts are retained for "
            "training; even local-weight inference of these models is "
            "frequently policy-disallowed in regulated environments. "
            "Image is unrestricted on purpose — runs against any "
            "process loading the model name."
        ),
        pattern_severity="high",
        image_regex=r".*\\.+\.exe",
        # Two alternations:
        #   (a) Model-name atom: matches `ollama run deepseek-r1`,
        #       `--model deepseek-coder`, `lmstudio --model deepseek-v3`,
        #       etc. Anchored to known DeepSeek family suffixes (r1 /
        #       v3 / coder / chat / etc.) so it doesn't false-positive
        #       on the bare word "deepseek" in unrelated text.
        #   (b) File-path atom: matches any cmdline that references a
        #       file or directory whose basename contains "deepseek"
        #       (e.g. `-m C:\models\my-deepseek.gguf`,
        #       `--model-path .\deepseek-r1-distill\`). Catches the
        #       rename-evasion case where the model file was renamed
        #       but the directory or filename still carries the brand.
        #       Trade-off: some false-positive risk on paths that
        #       happen to contain the word in non-AI contexts; the
        #       blast radius is one approval-gated detection per
        #       firing, not silent fleet-wide breakage.
        cmdline_regex=(
            r".*(?:"
            r"\Wdeepseek[-_]?(?:r1|v3|v2|coder|chat|llm|moe|reasoner)[-\w.:]*"
            r"|"
            r"[\\/][^\\/\s\"']*deepseek[^\\/\s\"']*(?:\.(?:gguf|safetensors|bin|pt|pth|onnx|q[2-8]_[01k_m]+)|[\\/])"
            r").*"
        ),
        rationale_tag="deepseek_model",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Open Interpreter (local agent loop)",
        description=(
            "Blocks Open Interpreter. Runs a local LLM-driven shell; "
            "highest-blast-radius agentic framework currently in the "
            "catalog because it directly executes shell commands."
        ),
        pattern_severity="high",
        image_regex=r".*\\(?:python|pythonw|python3|interpreter)\.exe",
        cmdline_regex=r".*\W(?:open[-_]?interpreter|openinterpreter)(?:\W.*)?",
        rationale_tag="open_interpreter",
    ),
]


def rule_corpus_summary() -> list[dict]:
    """Render the Windows corpus as a list of dicts for legacy callers.
    Use ``rule_corpus_for_platform(platform)`` for per-platform output.
    """
    return rule_corpus_summary_for_platform("windows")


def rule_corpus_summary_for_platform(platform: str) -> list[dict]:
    return [
        {
            "name": r.name,
            "description": r.description,
            "pattern_severity": r.pattern_severity,
            "rationale_tag": r.rationale_tag,
            "image_regex": r.image_regex,
            "cmdline_regex": r.cmdline_regex,
            "parent_image_regex": r.parent_image_regex,
        }
        for r in CORPUS_BY_PLATFORM.get(platform.lower(), [])
    ]


# ---------------------------------------------------------------------------
# macOS corpus
# ---------------------------------------------------------------------------
#
# macOS app images live at ``/Applications/<App>.app/Contents/MacOS/<binary>``
# (system-wide install) or ``~/Applications/<App>.app/Contents/MacOS/<binary>``
# (per-user). Falcon's macOS Process Creation ruletype matches the full
# executable path against ``ImageFilename``. Patterns below allow either
# location prefix and any depth between the .app bundle and the binary.
#
# macOS installers are typically ``.dmg`` mounts (where the user drags the
# .app into /Applications) or ``.pkg`` installers run via ``installer``.
# The .dmg mount-and-copy path doesn't fire a distinct "installer" image,
# so the post-install Image rules above are the load-bearing block. The
# ``.pkg`` installer cmdline is `/usr/sbin/installer -pkg <path>`; we'd
# need to intercept Apple's own installer binary, which is fragile.
# Skipping the installer rules for macOS — the Image rules at launch are
# sufficient and the prevention policy ML/AV layer covers the install
# write itself.

SHADOW_AI_RULE_CORPUS_MAC: list[ShadowAiIoaRule] = [
    ShadowAiIoaRule(
        name="ShadowAI: Cursor (agentic IDE) — macOS",
        description=(
            "Blocks /Applications/Cursor.app launches on macOS. Cursor for "
            "Mac is distributed as a .dmg-bundled .app; the post-install "
            "binary lives at <prefix>/Cursor.app/Contents/MacOS/Cursor."
        ),
        pattern_severity="medium",
        image_regex=r".*/Cursor\.app/Contents/MacOS/Cursor",
        rationale_tag="cursor_mac",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Ollama (local-inference runtime) — macOS",
        description=(
            "Blocks Ollama on macOS — both the bundled tray app at "
            "/Applications/Ollama.app and the daemon binary installed at "
            "/usr/local/bin/ollama or /opt/homebrew/bin/ollama (Homebrew "
            "Apple Silicon prefix). Same data-egress concern as Windows: "
            "exposes a local OpenAI-compatible REST API on 11434."
        ),
        pattern_severity="medium",
        image_regex=(
            r"(?:.*/Ollama\.app/Contents/MacOS/Ollama"
            r"|/usr/local/bin/ollama"
            r"|/opt/homebrew/bin/ollama)"
        ),
        rationale_tag="ollama_mac",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: LM Studio (local-inference desktop) — macOS",
        description=(
            "Blocks LM Studio.app launches on macOS. Bundle path is "
            "/Applications/LM Studio.app/Contents/MacOS/LM Studio."
        ),
        pattern_severity="medium",
        image_regex=r".*/LM Studio\.app/Contents/MacOS/LM Studio",
        rationale_tag="lmstudio_mac",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Claude Desktop (Anthropic, MCP host) — macOS",
        description=(
            "Blocks Claude.app on macOS. Same MCP-host capability concern "
            "as the Windows rule — claude_desktop_config.json registers MCP "
            "servers under user privileges. macOS bundle path is "
            "<prefix>/Claude.app/Contents/MacOS/Claude."
        ),
        pattern_severity="medium",
        image_regex=r".*/Claude\.app/Contents/MacOS/Claude",
        rationale_tag="claude_desktop_mac",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: ComfyUI (local image/video generation) — macOS",
        description=(
            "Blocks python3 / python launches whose CommandLine references "
            "ComfyUI's main.py or server.py. Same shape as the Windows "
            "rule — image-only doesn't apply (Python is the real runtime); "
            "cmdline is the only reliable signal."
        ),
        pattern_severity="medium",
        image_regex=r"(?:.*/python3?(?:\.\d+)?|/usr/bin/python3?(?:\.\d+)?|/opt/homebrew/bin/python3?(?:\.\d+)?|/usr/local/bin/python3?(?:\.\d+)?)",
        cmdline_regex=r".*/(?:ComfyUI|comfyui)/(?:main|server)\.py.*",
        rationale_tag="comfyui_mac",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: MCP server (npm @modelcontextprotocol) — macOS",
        description=(
            "Blocks node / npx spawning an @modelcontextprotocol/* package "
            "on macOS. Standard install paths covered: Homebrew "
            "(/opt/homebrew, /usr/local), nvm-managed (~/.nvm/versions/), "
            "and Volta (~/.volta/bin). Falcon's macOS Custom IOA regex "
            "engine is full-match-anchored implicitly; no trailing `$`."
        ),
        pattern_severity="high",
        image_regex=r".*/(?:node|npx|npx-cli\.js)",
        cmdline_regex=r".*@modelcontextprotocol/(?:server-|sdk).*",
        rationale_tag="mcp_npm_mac",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: MCP server (uvx Python launcher) — macOS",
        description=(
            "Blocks uvx spawning an mcp-* / awslabs.mcp-* / @org/mcp-* "
            "package on macOS. uvx is typically installed at "
            "~/.cargo/bin/uvx, /opt/homebrew/bin/uvx, or /usr/local/bin/uvx."
        ),
        pattern_severity="high",
        image_regex=r".*/uvx",
        cmdline_regex=r".*\W(?:mcp[-_]|awslabs\.mcp[-_]|@?[\w-]+/mcp[-_]).*",
        rationale_tag="mcp_uvx_mac",
    ),
    ShadowAiIoaRule(
        # Name shortened to fit Falcon's 64-char rule-name limit. The
        # Windows variant fits because it has no platform suffix.
        name="ShadowAI: MCP server (python module) — macOS",
        description=(
            "Blocks python -m mcp_server* / mcp-server-* invocations on "
            "macOS. Self-hosted Python MCP servers run directly via the "
            "module system rather than via uvx."
        ),
        pattern_severity="high",
        image_regex=r"(?:.*/python3?(?:\.\d+)?|/usr/bin/python3?(?:\.\d+)?|/opt/homebrew/bin/python3?(?:\.\d+)?|/usr/local/bin/python3?(?:\.\d+)?)",
        cmdline_regex=r".*\W(?:-m\s+mcp[-_]?server|mcp[-_]server[-_])[\w.-]*.*",
        rationale_tag="mcp_python_mac",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Aider (agentic coding loop) — macOS",
        description=(
            "Blocks the Aider REPL on macOS — `python -m aider` or the "
            "`aider` console_script (typically at ~/.local/bin/aider, "
            "/opt/homebrew/bin/aider)."
        ),
        pattern_severity="medium",
        image_regex=r"(?:.*/python3?(?:\.\d+)?|.*/aider)",
        cmdline_regex=r".*\W(?:-m\s+aider|aider(?:[-_]chat)?)(?:\W.*)?",
        rationale_tag="aider_mac",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: DeepSeek model load (any runtime) — macOS",
        description=(
            "Blocks any process whose CommandLine references a DeepSeek "
            "model name on macOS. Same rationale as the Windows rule — "
            "DeepSeek's hosted policy retains user prompts for training. "
            "Image is unrestricted on purpose."
        ),
        pattern_severity="high",
        image_regex=r".+",
        cmdline_regex=(
            r".*(?:"
            r"\Wdeepseek[-_]?(?:r1|v3|v2|coder|chat|llm|moe|reasoner)[-\w.:]*"
            r"|"
            r"/[^/\s\"']*deepseek[^/\s\"']*(?:\.(?:gguf|safetensors|bin|pt|pth|onnx|q[2-8]_[01k_m]+)|/)"
            r").*"
        ),
        rationale_tag="deepseek_model_mac",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Open Interpreter (local agent loop) — macOS",
        description=(
            "Blocks Open Interpreter on macOS. Same rationale as the "
            "Windows rule: highest-blast-radius agentic framework — runs a "
            "local LLM-driven shell."
        ),
        pattern_severity="high",
        image_regex=r"(?:.*/python3?(?:\.\d+)?|.*/interpreter)",
        cmdline_regex=r".*\W(?:open[-_]?interpreter|openinterpreter)(?:\W.*)?",
        rationale_tag="open_interpreter_mac",
    ),
]


# ---------------------------------------------------------------------------
# Linux corpus
# ---------------------------------------------------------------------------
#
# Linux AI tooling distributes via three vectors:
#   * AppImage (Cursor, LM Studio) — a single self-extracting executable.
#     The AppImage path is what shows up in ImageFilename; .AppImage
#     extension is the marker.
#   * .deb / .rpm packages installing under /opt/<vendor>/<binary> or
#     /usr/bin/<binary>. Cursor's deb installs at /opt/Cursor/cursor or
#     /usr/share/cursor. Ollama's curl|sh script lands at /usr/local/bin/
#     ollama or /usr/bin/ollama.
#   * pip / pipx for Python tooling (Aider, ComfyUI, Open Interpreter).
#     Same cmdline patterns as macOS — runtime is the binary, package
#     name is the cmdline match.
#
# Claude Desktop has no official Linux build — omitted.

SHADOW_AI_RULE_CORPUS_LINUX: list[ShadowAiIoaRule] = [
    ShadowAiIoaRule(
        name="ShadowAI: Cursor (agentic IDE) — Linux",
        description=(
            "Blocks Cursor on Linux. Distributed as AppImage "
            "(Cursor-X.Y.Z.AppImage) or .deb (/opt/Cursor/cursor, "
            "/usr/share/cursor/cursor, /usr/bin/cursor)."
        ),
        pattern_severity="medium",
        image_regex=(
            r"(?:.*/[Cc]ursor[-_.]?[\d.]*\.AppImage"
            r"|/opt/[Cc]ursor/cursor"
            r"|/usr/(?:bin|share/cursor)/cursor)"
        ),
        rationale_tag="cursor_linux",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Ollama (local-inference runtime) — Linux",
        description=(
            "Blocks Ollama on Linux. The official curl|sh installer drops "
            "the binary at /usr/local/bin/ollama or /usr/bin/ollama; "
            "AppImage / Snap installs are also possible. Both the daemon "
            "and CLI invocations are blocked."
        ),
        pattern_severity="medium",
        image_regex=(
            r"(?:/usr/local/bin/ollama"
            r"|/usr/bin/ollama"
            r"|.*/ollama-linux-(?:amd64|arm64)"
            r"|/snap/ollama/current/.*/ollama)"
        ),
        rationale_tag="ollama_linux",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: LM Studio (local-inference desktop) — Linux",
        description=(
            "Blocks LM Studio on Linux. Distributed as AppImage "
            "(LM-Studio-X.Y.Z.AppImage)."
        ),
        pattern_severity="medium",
        image_regex=r".*/LM[-_. ]?Studio[-_. ]?[\d.]*\.AppImage",
        rationale_tag="lmstudio_linux",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: ComfyUI (local image/video generation) — Linux",
        description=(
            "Blocks python3 launches whose CommandLine references ComfyUI's "
            "main.py or server.py on Linux. Same shape as Windows / macOS."
        ),
        pattern_severity="medium",
        image_regex=r"(?:.*/python3?(?:\.\d+)?|/usr/bin/python3?(?:\.\d+)?|/usr/local/bin/python3?(?:\.\d+)?)",
        cmdline_regex=r".*/(?:ComfyUI|comfyui)/(?:main|server)\.py.*",
        rationale_tag="comfyui_linux",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: MCP server (npm @modelcontextprotocol) — Linux",
        description=(
            "Blocks node / npx spawning an @modelcontextprotocol/* package "
            "on Linux. Covers /usr/bin/, /usr/local/bin/, nvm-managed "
            "(~/.nvm/versions/), and Volta (~/.volta/bin). Falcon's Linux "
            "Custom IOA regex engine is full-match-anchored implicitly; "
            "no trailing `$`."
        ),
        pattern_severity="high",
        image_regex=r".*/(?:node|npx|npx-cli\.js)",
        cmdline_regex=r".*@modelcontextprotocol/(?:server-|sdk).*",
        rationale_tag="mcp_npm_linux",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: MCP server (uvx Python launcher) — Linux",
        description=(
            "Blocks uvx spawning an mcp-* / awslabs.mcp-* / @org/mcp-* "
            "package on Linux. Standard install: ~/.cargo/bin/uvx, "
            "/usr/local/bin/uvx."
        ),
        pattern_severity="high",
        image_regex=r".*/uvx",
        cmdline_regex=r".*\W(?:mcp[-_]|awslabs\.mcp[-_]|@?[\w-]+/mcp[-_]).*",
        rationale_tag="mcp_uvx_linux",
    ),
    ShadowAiIoaRule(
        # Name shortened to fit Falcon's 64-char rule-name limit.
        name="ShadowAI: MCP server (python module) — Linux",
        description=(
            "Blocks python -m mcp_server* / mcp-server-* invocations on "
            "Linux."
        ),
        pattern_severity="high",
        image_regex=r"(?:.*/python3?(?:\.\d+)?|/usr/bin/python3?(?:\.\d+)?|/usr/local/bin/python3?(?:\.\d+)?)",
        cmdline_regex=r".*\W(?:-m\s+mcp[-_]?server|mcp[-_]server[-_])[\w.-]*.*",
        rationale_tag="mcp_python_linux",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Aider (agentic coding loop) — Linux",
        description=(
            "Blocks the Aider REPL on Linux — `python -m aider` or the "
            "`aider` console_script (typically at ~/.local/bin/aider, "
            "/usr/local/bin/aider)."
        ),
        pattern_severity="medium",
        image_regex=r"(?:.*/python3?(?:\.\d+)?|.*/aider)",
        cmdline_regex=r".*\W(?:-m\s+aider|aider(?:[-_]chat)?)(?:\W.*)?",
        rationale_tag="aider_linux",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: DeepSeek model load (any runtime) — Linux",
        description=(
            "Blocks any process whose CommandLine references a DeepSeek "
            "model name on Linux. Same rationale as the Windows rule."
        ),
        pattern_severity="high",
        image_regex=r".+",
        cmdline_regex=(
            r".*(?:"
            r"\Wdeepseek[-_]?(?:r1|v3|v2|coder|chat|llm|moe|reasoner)[-\w.:]*"
            r"|"
            r"/[^/\s\"']*deepseek[^/\s\"']*(?:\.(?:gguf|safetensors|bin|pt|pth|onnx|q[2-8]_[01k_m]+)|/)"
            r").*"
        ),
        rationale_tag="deepseek_model_linux",
    ),
    ShadowAiIoaRule(
        name="ShadowAI: Open Interpreter (local agent loop) — Linux",
        description=(
            "Blocks Open Interpreter on Linux. Same rationale as the "
            "Windows rule."
        ),
        pattern_severity="high",
        image_regex=r"(?:.*/python3?(?:\.\d+)?|.*/interpreter)",
        cmdline_regex=r".*\W(?:open[-_]?interpreter|openinterpreter)(?:\W.*)?",
        rationale_tag="open_interpreter_linux",
    ),
]


CORPUS_BY_PLATFORM: dict[str, list[ShadowAiIoaRule]] = {
    "windows": SHADOW_AI_RULE_CORPUS,
    "mac": SHADOW_AI_RULE_CORPUS_MAC,
    "linux": SHADOW_AI_RULE_CORPUS_LINUX,
}
