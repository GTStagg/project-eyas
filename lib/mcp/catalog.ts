import "server-only";
import type Anthropic from "@anthropic-ai/sdk";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { buildToolBridge, NATIVE_WRITE_SUPPRESS } from "@/lib/mcp/tool-bridge";
import { requiresApproval } from "@/lib/mcp/write-tools";

// The agent-visible tool catalog, surfaced read-only on the /agent-toolbox
// developer Reference page. Built from buildToolBridge so it reflects the EXACT
// post-suppression set the chat agent sees — no second copy of the suppression
// rules. Tenant-independent: falcon-mcp loads every module's tools regardless of
// granted scope (scope only gates call-time success), so this is a function of
// the configured eyas-mcp version + Eyas's own tools, not the active environment.

export type CatalogTool = {
  name: string;
  description: string;
  provider: "eyas-mcp" | "extension";
  gated: boolean;
  /** Native tool that advertises a write via MCP annotation (readOnlyHint:false).
   *  Healthy state: annotatedWrite ⇒ gated. See ToolCatalog.driftWarnings. */
  annotatedWrite: boolean;
  paramNames: string[];
  schema: Anthropic.Tool["input_schema"];
};

export type CatalogResource = {
  uri: string;
  name?: string;
  description?: string;
};

export type ToolCatalogCounts = {
  total: number;
  eyasMcp: number;
  extension: number;
  gated: number;
  readOnly: number;
};

export type ToolCatalog = {
  ok: boolean;
  error?: string;
  tools: CatalogTool[];
  counts: ToolCatalogCounts;
  resources: CatalogResource[];
  /** The native falcon-mcp writes suppressed at the bridge (routed to richer
   *  Eyas twins). Surfaced for the "why are some native writes not shown?"
   *  disclosure — kept single-source with the bridge via the shared export. */
  suppressedNativeWrites: string[];
  /** Native writes advertised via annotation (readOnlyHint:false) that are NOT
   *  in REQUIRES_APPROVAL — should always be empty. A non-empty list means a
   *  falcon-mcp bump added a write we haven't gated; the agent loop still gates
   *  it via the annotation backstop, but the registry needs the entry. */
  driftWarnings: string[];
  builtAt: number;
};

// Eyas's own tools are uniformly named `extras_*` (served in-process);
// everything else (including the synthetic `falcon_read_resource`) is eyas-mcp.
function classifyProvider(name: string): CatalogTool["provider"] {
  return name.startsWith("extras_") ? "extension" : "eyas-mcp";
}

function paramNamesOf(schema: Anthropic.Tool["input_schema"]): string[] {
  const props = (schema as { properties?: Record<string, unknown> } | undefined)?.properties;
  return props ? Object.keys(props) : [];
}

async function buildCatalog(): Promise<ToolCatalog> {
  const suppressedNativeWrites = [...NATIVE_WRITE_SUPPRESS].sort();
  try {
    const bridge = await withFalconMcpClient((client) => buildToolBridge(client));

    const tools: CatalogTool[] = bridge.anthropicTools.map((t) => ({
      name: t.name,
      description: t.description ?? "",
      provider: classifyProvider(t.name),
      gated: requiresApproval(t.name),
      annotatedWrite:
        bridge.annotatedNativeWrites.has(t.name) || bridge.unclassifiedEyasTools.has(t.name),
      paramNames: paramNamesOf(t.input_schema),
      schema: t.input_schema,
    }));

    const driftWarnings = tools
      .filter((t) => t.annotatedWrite && !t.gated)
      .map((t) => t.name);

    const counts: ToolCatalogCounts = {
      total: tools.length,
      eyasMcp: tools.filter((t) => t.provider === "eyas-mcp").length,
      extension: tools.filter((t) => t.provider === "extension").length,
      gated: tools.filter((t) => t.gated).length,
      readOnly: tools.filter((t) => !t.gated).length,
    };

    const resources: CatalogResource[] = bridge.resources.map((r) => ({
      uri: r.uri,
      name: r.name,
      description: r.description,
    }));

    return {
      ok: true,
      tools,
      counts,
      resources,
      suppressedNativeWrites,
      driftWarnings,
      builtAt: Date.now(),
    };
  } catch (err) {
    // Falcon not configured, or the MCP processes couldn't spawn. Return a
    // graceful empty catalog so the page renders a calm reference-mode note
    // instead of throwing a 500.
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      tools: [],
      counts: { total: 0, eyasMcp: 0, extension: 0, gated: 0, readOnly: 0 },
      resources: [],
      suppressedNativeWrites,
      driftWarnings: [],
      builtAt: Date.now(),
    };
  }
}

// Building the catalog spawns the eyas-mcp process — the same cost as a health
// probe — and the result only changes on an eyas-mcp version bump or a scope
// grant. Cache it process-wide with an
// in-flight de-dup, pinned to globalThis so Next.js dev's per-route re-import
// doesn't reset it. Mirrors lib/health.ts::getHealthReport.
const CATALOG_TTL_MS = 5 * 60_000;

const catalogState = (globalThis as unknown as {
  __eyasToolCatalog?: {
    cache: { at: number; catalog: ToolCatalog } | null;
    inflight: Promise<ToolCatalog> | null;
  };
}).__eyasToolCatalog ??= { cache: null, inflight: null };

export async function getToolCatalog(opts?: { force?: boolean }): Promise<ToolCatalog> {
  if (
    !opts?.force &&
    catalogState.cache &&
    Date.now() - catalogState.cache.at < CATALOG_TTL_MS
  ) {
    return catalogState.cache.catalog;
  }
  if (catalogState.inflight) return catalogState.inflight;
  catalogState.inflight = buildCatalog()
    .then((catalog) => {
      // Only cache a COMPLETE successful build. ok:true with zero native tools
      // means eyas-mcp came up empty mid-build — don't pin that incomplete
      // catalog for the full TTL; re-probe each request until it reports tools.
      if (catalog.ok && catalog.counts.eyasMcp > 0) {
        catalogState.cache = { at: Date.now(), catalog };
      }
      return catalog;
    })
    .finally(() => {
      catalogState.inflight = null;
    });
  return catalogState.inflight;
}
