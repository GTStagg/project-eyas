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
    topic: "eyas-mcp",
    url: "https://github.com/GTStagg/eyas-mcp",
    blurb: "The open-source Falcon tool server this console runs on: its tools, their inputs and its release notes.",
  },
  {
    topic: "Python SDK",
    url: "https://developer.crowdstrike.com/sdks/python/",
    blurb: "CrowdStrike's Python SDK, for Falcon operations your tool server doesn't cover yet.",
  },
  {
    topic: "API Reference",
    url: "https://developer.crowdstrike.com/api-reference/overview/",
    blurb: "The full REST surface, operations, and the API scopes each one needs.",
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
    topic: "Python SDK source",
    url: "https://github.com/CrowdStrike/falconpy",
    blurb: "The Python SDK's source code, with every operation name.",
  },
];

/** Seeded developer blueprints. Each is a ready-to-run question that produces a
 *  build-analysis decision document. They double as the empty-state chips. */
export type BlueprintSeed = { label: string; question: string };

export const BLUEPRINT_SEEDS: BlueprintSeed[] = [
  {
    label: "Self-hosted tool server vs. a hosted connector",
    question:
      "I want to drive Falcon with Claude. Should my console run the Falcon tool server itself and drive its own tool-use loop, or use Anthropic's hosted connector? Walk me through the tradeoffs and how I'd wire the self-hosted approach.",
  },
  {
    label: "Approval-gating writes",
    question:
      "How do I put a human-in-the-loop approval gate in front of every Falcon write action (containment, IOC creation, policy changes) in a Claude tool-use loop?",
  },
  {
    label: "Tool server vs. your own tools — where does custom code go?",
    question:
      "My Falcon tool server covers most Falcon operations, but I also have workflow logic of my own (playbooks, script libraries, provisioning). How do I decide what belongs in the tool server versus my app's own tools, and how do I compose both into one agent loop?",
  },
  {
    label: "Deterministic enrichment + agentic synthesis",
    question:
      "My agent fans out too many tool calls and the results are slow and unreliable. What's the pattern for bounding cost and latency while keeping the analysis trustworthy?",
  },
  {
    label: "Scopes & capability gating",
    question:
      "How should I handle per-tenant API scopes so my console degrades gracefully when a scope isn't granted, instead of erroring?",
  },
  {
    label: "One tool catalog for one agent",
    question:
      "How do I merge the Falcon tool server's tools and my app's own tools into a single catalog that one Claude agent can drive, and what are the gotchas?",
  },
];
