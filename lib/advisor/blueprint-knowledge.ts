import "server-only";

// Grounding corpus for the /blueprint developer advisor.
//
// This is the DIFFERENTIATED content: developer.crowdstrike.com documents the
// platform primitives (APIs, SDKs, scopes, Foundry) — it cannot
// teach the composition patterns that make an agentic SOC actually work. That
// knowledge lives in this reference implementation. So the advisor grounds on
// the brief below (curated from docs/WHITEPAPER.md and the CLAUDE.md
// conventions) and deep-links OUT to the dev
// portal for the primitives — it never re-hosts vendor docs.
//
// Compiled into the bundle as constants (not a runtime file read) so the
// surface works on a fresh install with only Anthropic configured — it has NO
// Falcon dependency.

/** The reference-architecture brief the advisor reasons from. Kept tight on
 *  purpose: it's the load-bearing "how the pieces compose" knowledge, not a
 *  doc dump. Everything here is a pattern a developer would replicate. */
export const REFERENCE_ARCHITECTURE_BRIEF = `
# Reference architecture: an agentic SOC on eyas-mcp + Claude

This console (codename Eyas) is a self-hosted, human-in-the-loop operator
console that drives CrowdStrike Falcon through Claude. It is a *reference
implementation* — the point is that a Falcon-licensed team can build the same
shape in their own org. What follows is the architecture, not a feature list.

## The defining choice: in-process MCP client + a manual tool-use loop

We run eyas-mcp through an **in-process MCP client** inside the Next.js server and
pair it with a **manual Anthropic tool-use loop** — deliberately NOT Anthropic's
native MCP connector. Four reasons a builder should weigh:
- **Data residency** — tenant data flows through your own server, not a
  third-party connector egress.
- **Network exposure** — eyas-mcp stays on a private bridge, never
  internet-facing. Only the app process reaches it.
- **Per-tool approval gating** — a manual loop can pause before any write and
  require a human click. A native connector executes tools opaquely.
- **Ownable audit log** — you record every tool call, input, and result.

The tradeoff: you write and maintain the loop (~a few hundred lines) instead of
getting it free. For a security console the control is worth it.

## Composition: one MCP server plus the app's own tools, one loop

- **eyas-mcp** (an independent MCP server derived from CrowdStrike's
  MIT-licensed falcon-mcp) supplies the generic Falcon surface — detections,
  hosts, vulnerabilities, intel, recon, IOCs, NGSIEM, containment, RTR, host
  groups, policies, exclusions, workflows and more. About 200 tools reach the
  agent.
- **The app's own tools** carry what is specific to this console — IR and
  Shadow-AI playbooks, the patch / cleanup script library, provisioning, the
  remediation-ledger closers, classifiers. They run in-process in the app and
  make every Falcon call through eyas-mcp's tools. A small Python sidecar that
  once filled gaps is being retired as those capabilities land upstream.
- Everything merges into ONE tool bridge and the SAME agent loop — the model
  sees a single flat tool catalog and cannot tell what backs a tool. Generic
  Falcon operations go into the MCP server; product-specific logic stays in
  the app as its own tools.

## The three interception points (and the one you don't get)

For a *native* MCP-server tool, an in-process integration has exactly three
seams: (1) hide it from the model at the bridge, (2) a binary approval gate
(allow/deny, no input transform), (3) post-result processing. There is **no
pre-write hook and no in-sidecar hook** on a native tool. This single fact
drives the reconciliation policy below — any value-add that must run *before* a
write (canonical naming, regex pre-flight, disable-before-delete) cannot be
grafted onto a native tool, so it lives in the app's own tool, which validates
first and then calls the native tool.

## Reconciliation policy on every MCP-server version bump

- **Reads → expose them.** Token-bound each with a projection that drops heavy
  blobs so the model's context stays cheap and focused.
- **Writes → land conservatively: suppress + approval-gate ALL of them first**,
  then adopt a native write as the primary path ONLY when it has no richer
  twin (nothing to lose). Otherwise keep it routed to the app's twin. Never
  regress a behavior the twin performs before the write. Missing generic
  capabilities are requested in the MCP server rather than patched around in
  the app.

## The interaction pattern: deterministic enrichment + agentic synthesis

The naive shape — hand the model a goal and let it fan out dozens of tool calls
— degrades on real workloads (unbounded cost, unbounded latency, unprovable
results, agents that truncate large captures and skip tedious clustering). The
pattern that holds:
- **The route (server-side) does the deterministic work**: parallel MCP calls,
  then pure-function join / classify / cluster / correlate (milliseconds),
  attaching the result to the existing data shapes.
- **The agent does synthesis only** on the assembled bundle — 0–2 corroborating
  calls max — and produces a decision document, not a table.
This bounds cost (cents per report, not dollars), bounds latency, makes
provenance enforceable, and makes quality testable. New cross-module surfaces
follow it; agents are invoked on operator request via a seeded hand-off, never
told to discover a brand-new tool from a long prompt (they bias hard toward the
tools they already know).

## Approval gating

Every write tool is in an explicit approval registry; the loop pauses and emits
a pending-approval event the UI turns into an Allow/Deny card. A fail-closed
backstop also gates any tool the server annotates as a write (readOnlyHint:
false) even if it's missing from the registry — annotations are a backstop, not
the primary gate (never trust a server's annotations to be *less* restrictive).

## Security posture a builder should copy

Server-only credentials (no secrets in the browser, no client-side calls to
Anthropic or eyas-mcp). eyas-mcp on a private network, never exposed.
Per-tool approval on writes + an ownable audit trail. Credentials encrypted at
rest with column encryption; the DB file is the single source of truth at
runtime.

## Gotchas worth warning a builder about

- **Spawn a fresh MCP client per call — don't pool by default.** A stdio
  server that runs blocking handlers serializes JSON-RPC per connection, so a
  shared client serializes all concurrent callers and blows the timeout.
  Parallelism comes from multiple clients; share one only where the server is
  known to handle concurrent requests.
- **Keep the tool catalog byte-stable between requests.** Prompt caching only
  reuses an identical prefix; sort tools and resources so a server that lists
  them in a different order doesn't force a full re-cache every turn.
- **Upstream API errors can arrive as *successful* tool results** (isError:
  false with the error nested in the payload). Detect and promote them, or the
  model reads a failure as "zero results."
- **FQL has no ~ / contains operator** — wildcards are asterisks inside the
  quoted value (name:'*chrome*'). Surface the platform's FQL guides to the
  model rather than letting it guess.
- **Two-step search tools and multi-facet Spotlight queries have version-
  specific quirks** — pin a version and read the changelog.
- **Model tool-name bias**: agents favor tools they recognize and will ignore
  even emphatic instructions to call an unfamiliar one. Prefer deterministic
  server-side enrichment over prompt-instructing a new tool.
`.trim();
