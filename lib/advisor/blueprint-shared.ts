// Client-safe blueprint data (no "server-only"): the small link + seed
// constants the /blueprint page and its client component render directly. The
// heavy REFERENCE_ARCHITECTURE_BRIEF stays server-only in blueprint-knowledge.ts
// so it never ships to the browser.

/** Curated deep-links to developer.crowdstrike.com (+ the two canonical repos).
 *  The advisor cites these for platform primitives; the page renders them as a
 *  static "Authoritative sources" panel. Own the patterns, link out for the
 *  primitives. */
export type DevPortalLink = { topic: string; url: string; blurb: string };

export const DEV_PORTAL_LINKS: DevPortalLink[] = [
  {
    topic: "Falcon MCP",
    url: "https://developer.crowdstrike.com/falcon-mcp/overview/",
    blurb: "The official Model Context Protocol server — the read surface your loop composes.",
  },
  {
    topic: "Python SDK (FalconPy)",
    url: "https://developer.crowdstrike.com/sdks/python/",
    blurb: "The SDK a sidecar uses to cover writes and gaps falcon-mcp doesn't reach yet.",
  },
  {
    topic: "API Reference",
    url: "https://developer.crowdstrike.com/api-reference/overview/",
    blurb: "The full REST surface, operations, and the OAuth scopes each one needs.",
  },
  {
    topic: "Falcon Foundry",
    url: "https://developer.crowdstrike.com/foundry/understanding-foundry/",
    blurb: "In-tenant app + Fusion SOAR platform — the alternative to a self-hosted console.",
  },
  {
    topic: "Next-Gen SIEM",
    url: "https://developer.crowdstrike.com/ngsiem/overview/",
    blurb: "CQL/LogScale query surface for streaming detection and correlation logic.",
  },
  {
    topic: "SDKs (all languages)",
    url: "https://developer.crowdstrike.com/sdks/overview/",
    blurb: "Go, PowerShell, JavaScript/TypeScript, Rust, Ruby, and Terraform, beyond Python.",
  },
  {
    topic: "Task guides (Accomplish)",
    url: "https://developer.crowdstrike.com/accomplish/investigate-threats/",
    blurb: "Outcome-oriented recipes: investigate threats, automate response, hunt vulnerabilities.",
  },
  {
    topic: "falcon-mcp source",
    url: "https://github.com/CrowdStrike/falcon-mcp",
    blurb: "The MCP server's source — module list, tool schemas, and release notes.",
  },
  {
    topic: "FalconPy source",
    url: "https://github.com/CrowdStrike/falconpy",
    blurb: "The Python SDK's source — the operation names a sidecar wraps.",
  },
];

/** Seeded developer blueprints. Each is a ready-to-run question that produces a
 *  build-analysis decision document. They double as the empty-state chips. */
export type BlueprintSeed = { label: string; question: string };

export const BLUEPRINT_SEEDS: BlueprintSeed[] = [
  {
    label: "In-process MCP client vs. the native connector",
    question:
      "I want to drive Falcon with Claude. Should I use an in-process MCP client with a manual tool-use loop, or Anthropic's native MCP connector? Walk me through the tradeoffs and how I'd wire the in-process approach.",
  },
  {
    label: "Approval-gating writes",
    question:
      "How do I put a human-in-the-loop approval gate in front of every Falcon write action (containment, IOC creation, policy changes) in a Claude tool-use loop?",
  },
  {
    label: "falcon-mcp vs. FalconPy — when do I need a sidecar?",
    question:
      "falcon-mcp covers a lot of reads but I need writes and some capabilities it doesn't expose. How do I decide what to use falcon-mcp for versus building a FalconPy sidecar, and how do I compose both into one agent loop?",
  },
  {
    label: "Deterministic enrichment + agentic synthesis",
    question:
      "My agent fans out too many tool calls and the results are slow and unreliable. What's the pattern for bounding cost and latency while keeping the analysis trustworthy?",
  },
  {
    label: "Scopes & capability gating",
    question:
      "How should I handle per-tenant OAuth scopes so my console degrades gracefully when a scope isn't granted, instead of erroring?",
  },
  {
    label: "Composing multiple MCP servers into one loop",
    question:
      "How do I merge falcon-mcp and my own FalconPy MCP server into a single tool catalog that one Claude loop can drive, and what are the gotchas?",
  },
];
