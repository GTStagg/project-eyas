// Shadow-AI catalog: generative-AI desktop apps, AI egress endpoints, MCP
// server / agentic-framework command-line signatures and local-inference
// ports, plus the posture verdict and the deterministic cleanup routing.
//
// Four signal layers, four workplace risks:
//   1. APPS — generative-AI desktop apps (Cursor, LM Studio, Ollama, Claude
//      Desktop, …) seen in ProcessRollup2.
//   2. EGRESS — DNS to public AI inference / chat endpoints. A browser tab on
//      chatgpt.com or a `curl api.openai.com` never lands a binary on disk.
//   3. MCP / agentic infrastructure — command lines that look like an MCP
//      server or an agent framework: an unsanctioned agent with shell or
//      source-control access.
//   4. LOCAL INFERENCE — connections to well-known local model-server ports.
//
// Broad but curated. Sanctioned tools are not excluded: the scan flags them
// `sanctioned` so the operator sees coverage as well as gaps. The catalog goes
// stale with every release cycle; adding an entry is one row per layer.
//
// The egress list is lib/eyas-tools/ai-egress-catalog.json, shared with the IR
// detection classifiers. Ported from the sidecar's shadow_ai/catalog.py
// (Python `re` atoms run as JS regexes); tested in scripts/test-shadow-ai.mjs.

import egressCatalog from "../ai-egress-catalog.json";

// --------------------------------------------------------------------- apps
// [image atom, canonical tool, family, posture tag]. The atom matches the
// whole basename (case-insensitive) with `.exe` appended. Atoms are narrow so
// they don't shadow unrelated binaries (`cursor`, not `cur`, so not `curl`).
// Posture tags: model_developer (local inference / training),
// agentic_client (MCP-aware clients), saas_chat_client (desktop wrappers for
// SaaS chat), code_assistant, image_video_gen.
export const AI_APP_CATALOG: ReadonlyArray<readonly [string, string, string, string]> = [
  // Local inference / model developer tooling
  [String.raw`ollama(?:\s+app)?`, "Ollama", "ollama", "model_developer"],
  ["ollama-app", "Ollama", "ollama", "model_developer"],
  [String.raw`lm[\s_-]?studio`, "LM Studio", "lmstudio", "model_developer"],
  ["jan(?:-app)?", "Jan", "jan", "model_developer"],
  ["msty", "Msty", "msty", "model_developer"],
  [String.raw`gpt4all(?:[\w-]*)?`, "GPT4All", "gpt4all", "model_developer"],
  [String.raw`anythingllm(?:[\w-]*)?`, "AnythingLLM", "anythingllm", "model_developer"],
  [String.raw`llama[\s_-]?cpp`, "llama.cpp", "llamacpp", "model_developer"],
  ["text-generation-webui", "text-generation-webui", "tgwui", "model_developer"],
  [String.raw`koboldcpp(?:[\w-]*)?`, "KoboldCpp", "koboldcpp", "model_developer"],
  ["vllm", "vLLM", "vllm", "model_developer"],
  // Agentic clients (these correlate strongly with the MCP layer)
  [String.raw`claude(?:[\s_-]?desktop)?`, "Claude Desktop", "claude_desktop", "agentic_client"],
  ["cursor", "Cursor", "cursor", "agentic_client"],
  ["windsurf", "Windsurf", "windsurf", "agentic_client"],
  ["cline", "Cline", "cline", "agentic_client"],
  ["continue", "Continue", "continue", "agentic_client"],
  ["goose", "Goose", "goose", "agentic_client"],
  // SaaS chat desktop wrappers
  ["chatgpt", "ChatGPT (desktop)", "chatgpt_desktop", "saas_chat_client"],
  ["perplexity", "Perplexity (desktop)", "perplexity_desktop", "saas_chat_client"],
  ["poe", "Poe (desktop)", "poe_desktop", "saas_chat_client"],
  [String.raw`you(?:[\s_-]?app)?`, "You.com (desktop)", "you_desktop", "saas_chat_client"],
  // Code assistants
  [String.raw`copilot(?:[\s_-]?cli)?`, "GitHub Copilot CLI", "copilot_cli", "code_assistant"],
  ["cody", "Sourcegraph Cody", "cody", "code_assistant"],
  ["tabby", "Tabby", "tabby", "code_assistant"],
  ["codeium", "Codeium", "codeium", "code_assistant"],
  ["aider", "Aider", "aider", "code_assistant"],
  // Image / video generation
  ["comfyui", "ComfyUI", "comfyui", "image_video_gen"],
  ["pinokio", "Pinokio", "pinokio", "image_video_gen"],
  ["a1111", "AUTOMATIC1111", "automatic1111", "image_video_gen"],
  [String.raw`stable[\s_-]?diffusion`, "Stable Diffusion (UI)", "sd_ui", "image_video_gen"],
  ["invokeai", "InvokeAI", "invokeai", "image_video_gen"],
];

const APP_RX = AI_APP_CATALOG.map(([atom, tool, family, posture]) => [new RegExp(`^(?:${atom})\\.exe$`, "i"), tool, family, posture] as const);

/** The app atoms as one alternation (no `.exe`), for the CQL image filter. */
export function imageRegexAlternation(): string {
  return AI_APP_CATALOG.map(([atom]) => atom).join("|");
}

/** [tool, family, posture] for an image path whose basename is a catalogued
 *  AI app, else nulls. */
export function classifyAppImage(imagePath: string): [string | null, string | null, string | null] {
  if (!imagePath) return [null, null, null];
  const base = (imagePath.split("\\").pop() as string).split("/").pop() as string;
  for (const [rx, tool, family, posture] of APP_RX) {
    if (rx.test(base)) return [tool, family, posture];
  }
  return [null, null, null];
}

// ------------------------------------------------------------ cleanup routing
// Deterministic uninstall selection: the scan hands each app a ready-to-fire
// cleanup plan, so the ban-and-clean agent never decides MSIX vs Squirrel from
// paths itself (an instruction agents skip — and the curated Squirrel script
// no-ops against an MSIX install). family → curated uninstaller for the
// Squirrel / per-user install form; MSIX goes to host-uninstall-appx-package.

export const FAMILY_CLEANUP_SCRIPT: Readonly<Record<string, string>> = {
  cursor: "host-uninstall-cursor",
  ollama: "host-uninstall-ollama",
  lmstudio: "host-uninstall-lmstudio",
  claude_desktop: "host-uninstall-claude-desktop",
  comfyui: "host-uninstall-comfyui",
};

const APPX_SCRIPT = "host-uninstall-appx-package";

// MSIX/AppX: runs from WindowsApps, or per-user package state under
// AppData\Local\Packages.
const isMsixPath = (p: string) => {
  const lp = p.toLowerCase();
  return lp.includes("\\windowsapps\\") || lp.includes("\\appdata\\local\\packages\\");
};
// Squirrel / per-user: under %LOCALAPPDATA% but not the Packages subtree.
const isSquirrelPath = (p: string) => {
  const lp = p.toLowerCase();
  return lp.includes("\\appdata\\local\\") && !lp.includes("\\appdata\\local\\packages\\");
};
// A Microsoft-published Store package: never host-uninstalled (the appx script
// refuses `^Microsoft\.`, and Copilot is Group-Policy / Intune managed).
const isMicrosoftWindowsApps = (p: string) => p.toLowerCase().includes("\\windowsapps\\microsoft.");

/** The AppX package family name (WindowsApps folder segment up to the first
 *  underscore) for host-uninstall-appx-package, or null. */
function msixPackagePattern(imagePaths: string[]): string | null {
  const marker = "\\windowsapps\\";
  for (const p of imagePaths) {
    const idx = p.toLowerCase().indexOf(marker);
    if (idx === -1) continue;
    const seg = p.slice(idx + marker.length).split("\\")[0];
    const family = seg.split("_")[0].trim();
    if (/^[A-Za-z0-9.*-]{1,128}$/.test(family)) return family;
  }
  return null;
}

/** 'msix', 'squirrel', 'both' (rare) or 'unknown', from observed paths. */
export function classifyDistributionForm(imagePaths: string[]): string {
  const paths = imagePaths.filter(Boolean);
  const msix = paths.some(isMsixPath);
  const squirrel = paths.some(isSquirrelPath);
  if (msix && squirrel) return "both";
  if (msix) return "msix";
  if (squirrel) return "squirrel";
  return "unknown";
}

export type CleanupStep = { script_id: string; params: Record<string, string> };

/**
 * [distribution_form, microsoft_managed, cleanup[]] for one app. `cleanup`
 * is what the ban-and-clean workflow fires via extras_rtr_run_cleanup:
 * MSIX (non-Microsoft) → appx uninstaller + package_name_pattern; Squirrel /
 * unknown with a curated family → the curated uninstaller; both forms → both;
 * a Microsoft Store package → [] and microsoft_managed; nothing curated → []
 * (kill + delete fallback).
 */
export function cleanupPlan(family: string, imagePaths: string[]): [string, boolean, CleanupStep[]] {
  const form = classifyDistributionForm(imagePaths);
  if (imagePaths.some((p) => p && isMicrosoftWindowsApps(p))) return [form, true, []];
  const curated = FAMILY_CLEANUP_SCRIPT[family];
  const plan: CleanupStep[] = [];
  if (form === "msix" || form === "both") {
    const pattern = msixPackagePattern(imagePaths);
    if (pattern) plan.push({ script_id: APPX_SCRIPT, params: { package_name_pattern: pattern } });
  }
  if ((form === "squirrel" || form === "unknown" || form === "both") && curated) plan.push({ script_id: curated, params: {} });
  return [form, false, plan];
}

// ------------------------------------------------------------------- egress
// FQDN atoms, whole-name match (lowercased). Posture tags: saas_inference_api,
// saas_chat_browser, code_assistant_api, model_hub, agent_infra.

type EgressEntry = { pattern: string; tool: string; posture: string };
export const AI_EGRESS_CATALOG: readonly EgressEntry[] = egressCatalog as EgressEntry[];
const EGRESS_RX = AI_EGRESS_CATALOG.map((e) => [new RegExp(`^(?:${e.pattern})$`, "i"), e.tool, e.posture] as const);

/** The egress atoms as one alternation, for the CQL DomainName filter. */
export function domainRegexAlternation(): string {
  return AI_EGRESS_CATALOG.map((e) => e.pattern).join("|");
}

/** [tool, posture] for a catalogued AI domain, else nulls. */
export function classifyEgressDomain(domain: string): [string | null, string | null] {
  if (!domain) return [null, null];
  const d = domain.trim().toLowerCase().replace(/\.+$/, "");
  for (const [rx, tool, posture] of EGRESS_RX) {
    if (rx.test(d)) return [tool, posture];
  }
  return [null, null];
}

// -------------------------------------------------------------- MCP / agents
// [token, tool, family, kind, posture]; kind "literal" = case-insensitive
// substring, "regex" = case-insensitive search. Catalog order is priority.
export const MCP_CMDLINE_CATALOG: ReadonlyArray<readonly [string, string, string, "literal" | "regex", string]> = [
  // Direct MCP server invocations
  ["@modelcontextprotocol/server-", "MCP server (npm)", "mcp_npm", "literal", "mcp_host"],
  ["@modelcontextprotocol/sdk", "MCP SDK", "mcp_sdk", "literal", "mcp_host"],
  ["mcp-server-", "MCP server (binary)", "mcp_binary", "literal", "mcp_host"],
  [String.raw`\bmcp[_-]?server\b`, "MCP server (generic)", "mcp_generic", "regex", "mcp_host"],
  // uvx-spawned MCP packages
  [
    String.raw`\buvx\s+(?:--from\s+\S+\s+)?(?:mcp[-_]|awslabs\.mcp[-_]|@?[\w-]+/mcp[-_])`,
    "MCP server (uvx)",
    "mcp_uvx",
    "regex",
    "mcp_host",
  ],
  // Agentic frameworks
  ["langchain", "LangChain", "langchain", "literal", "agentic_framework"],
  ["langgraph", "LangGraph", "langgraph", "literal", "agentic_framework"],
  ["autogen-agentchat", "Microsoft AutoGen", "autogen", "literal", "agentic_framework"],
  ["autogenstudio", "Microsoft AutoGen Studio", "autogen_studio", "literal", "agentic_framework"],
  ["crewai", "CrewAI", "crewai", "literal", "agentic_framework"],
  ["llama_index", "LlamaIndex", "llamaindex", "literal", "agentic_framework"],
  ["llamaindex", "LlamaIndex", "llamaindex", "literal", "agentic_framework"],
  ["haystack", "Haystack", "haystack", "literal", "agentic_framework"],
  ["semantic-kernel", "Semantic Kernel", "semantic_kernel", "literal", "agentic_framework"],
  ["semantic_kernel", "Semantic Kernel", "semantic_kernel", "literal", "agentic_framework"],
  ["dspy", "DSPy", "dspy", "literal", "agentic_framework"],
  ["@anthropic-ai/sdk", "Anthropic SDK (npm)", "anthropic_sdk", "literal", "agentic_framework"],
  ["@anthropic-ai/claude-code", "Claude Code", "claude_code", "literal", "agentic_framework"],
  // Self-hosted agent loops
  ["openinterpreter", "Open Interpreter", "open_interpreter", "literal", "agentic_framework"],
  ["open-interpreter", "Open Interpreter", "open_interpreter", "literal", "agentic_framework"],
  ["autogpt", "Auto-GPT", "autogpt", "literal", "agentic_framework"],
  ["babyagi", "BabyAGI", "babyagi", "literal", "agentic_framework"],
  ["agentgpt", "AgentGPT", "agentgpt", "literal", "agentic_framework"],
  ["smol-developer", "smol-developer", "smol_developer", "literal", "agentic_framework"],
  ["gpt-engineer", "GPT-Engineer", "gpt_engineer", "literal", "agentic_framework"],
  ["aider-chat", "Aider", "aider", "literal", "agentic_framework"],
  ["aider --", "Aider", "aider", "literal", "agentic_framework"],
];

const MCP_RX = MCP_CMDLINE_CATALOG.map((row) => (row[3] === "regex" ? new RegExp(row[0], "i") : null));

export type McpMatch = { tool: string; family: string; posture: string; matched_token: string };

/** The first MCP-server / agentic-framework signature in a command line. */
export function classifyMcpCmdline(cmdline: string): McpMatch | null {
  if (!cmdline) return null;
  const hay = cmdline.toLowerCase();
  for (let i = 0; i < MCP_CMDLINE_CATALOG.length; i++) {
    const [token, tool, family, kind, posture] = MCP_CMDLINE_CATALOG[i];
    if (kind === "literal") {
      if (hay.includes(token.toLowerCase())) return { tool, family, posture, matched_token: token };
    } else {
      const m = (MCP_RX[i] as RegExp).exec(cmdline);
      if (m) return { tool, family, posture, matched_token: m[0].slice(0, 120) };
    }
  }
  return null;
}

// ---------------------------------------------------------- local inference
// Ports of known local model servers. Port-only signal is weak; 8080 / 8000 /
// 3000 are shared with web tooling, so the search filters on the
// high-confidence subset and the full map only labels.
export const LOCAL_INFERENCE_PORTS: Readonly<Record<number, string>> = {
  11434: "Ollama",
  1234: "LM Studio",
  8080: "llama.cpp / generic",
  8000: "vLLM / generic",
  7860: "Gradio (HF Spaces local)",
  7861: "Gradio (HF Spaces local)",
  11435: "Ollama (alt)",
  5001: "KoboldCpp",
  8188: "ComfyUI",
  7869: "text-generation-webui",
  3000: "AnythingLLM / generic",
};

export const LOCAL_INFERENCE_PORTS_HIGH_CONFIDENCE: readonly number[] = [11434, 11435, 1234, 5001, 8188, 7860, 7861, 7869];

export function classifyLocalInferencePort(port: number | null): string | null {
  if (port === null) return null;
  return LOCAL_INFERENCE_PORTS[port] ?? null;
}

/** Address in 127.0.0.0/8. */
export function isLoopbackIpv4(addr: unknown): boolean {
  return typeof addr === "string" && addr.startsWith("127.");
}

// ------------------------------------------------------------------ verdict
// A bag of (layer, posture tag) signals → one host verdict. Precedence:
// model_developer > mcp_host > agentic_developer > code_assistant (when it is
// the only kind of signal) > image_video_gen > unsanctioned_saas >
// code_assistant > no_signal.

const VERDICT_PRECEDENCE = [
  "model_developer",
  "mcp_host",
  "agentic_developer",
  "code_assistant",
  "image_video_gen",
  "unsanctioned_saas",
  "sanctioned",
  "no_signal",
];

export function classifyPosture(signals: Array<[string, string]>): string {
  if (signals.length === 0) return "no_signal";
  const any = (f: (layer: string, p: string) => boolean) => signals.some(([l, p]) => f(l, p));
  const localModel = any((_, p) => p === "model_developer");
  const mcpHost = any((l, p) => l === "mcp" && p === "mcp_host");
  const agenticFramework = any((l, p) => l === "mcp" && p === "agentic_framework");
  const agenticClientApp = any((l, p) => l === "app" && p === "agentic_client");
  const codeAssistant = any((_, p) => p === "code_assistant" || p === "code_assistant_api");
  const imageVideo = any((_, p) => p === "image_video_gen");
  const saasEgress = any((_, p) => ["saas_inference_api", "saas_chat_browser", "model_hub", "agent_infra"].includes(p));
  const saasChatApp = any((l, p) => l === "app" && p === "saas_chat_client");
  if (localModel) return "model_developer";
  if (mcpHost) return "mcp_host";
  if (agenticFramework || agenticClientApp) return "agentic_developer";
  if (codeAssistant && !saasEgress && !saasChatApp) return "code_assistant";
  if (imageVideo) return "image_video_gen";
  if (saasEgress || saasChatApp) return "unsanctioned_saas";
  if (codeAssistant) return "code_assistant";
  return "no_signal";
}

/** Smaller is more concerning (UI sort order). */
export function verdictSeverity(verdict: string): number {
  const i = VERDICT_PRECEDENCE.indexOf(verdict);
  return i < 0 ? VERDICT_PRECEDENCE.length : i;
}
