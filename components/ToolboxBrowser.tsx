"use client";

import { useMemo, useState } from "react";
import { Search, X, ChevronRight, ShieldCheck, Eye, Server, Boxes, AlertTriangle } from "lucide-react";
import type { CatalogTool, CatalogResource } from "@/lib/mcp/catalog";

type FilterKey = "all" | "falcon-mcp" | "extension" | "read" | "gated";

const FILTERS: { key: FilterKey; label: string }[] = [
  { key: "all", label: "All" },
  { key: "falcon-mcp", label: "falcon-mcp" },
  { key: "extension", label: "Extension" },
  { key: "read", label: "Read-only" },
  { key: "gated", label: "Approval-gated" },
];

function matchesFilter(t: CatalogTool, filter: FilterKey): boolean {
  switch (filter) {
    case "falcon-mcp":
      return t.provider === "falcon-mcp";
    case "extension":
      return t.provider === "extension";
    case "read":
      return !t.gated;
    case "gated":
      return t.gated;
    default:
      return true;
  }
}

function ProviderBadge({ provider }: { provider: CatalogTool["provider"] }) {
  const isExt = provider === "extension";
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.08em] ${
        isExt
          ? "border-sky-900/60 bg-sky-950/30 text-sky-300"
          : "border-neutral-700 bg-neutral-900 text-neutral-300"
      }`}
    >
      {isExt ? <Boxes className="h-2.5 w-2.5" strokeWidth={2} /> : <Server className="h-2.5 w-2.5" strokeWidth={2} />}
      {isExt ? "extension" : "falcon-mcp"}
    </span>
  );
}

function AccessChip({ gated }: { gated: boolean }) {
  return gated ? (
    <span className="inline-flex shrink-0 items-center gap-1 rounded border border-amber-800/60 bg-amber-950/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.08em] text-amber-300">
      <ShieldCheck className="h-2.5 w-2.5" strokeWidth={2} />
      approval-gated
    </span>
  ) : (
    <span className="inline-flex shrink-0 items-center gap-1 rounded border border-teal-800/60 bg-teal-950/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.08em] text-teal-300">
      <Eye className="h-2.5 w-2.5" strokeWidth={2} />
      read-only
    </span>
  );
}

function ToolRow({ tool }: { tool: CatalogTool }) {
  const schemaJson = useMemo(() => JSON.stringify(tool.schema ?? {}, null, 2), [tool.schema]);
  return (
    <details className="group border-b border-neutral-900 last:border-b-0">
      <summary className="flex cursor-pointer list-none items-start gap-3 px-4 py-3 hover:bg-neutral-900/40">
        <ChevronRight
          className="mt-0.5 h-4 w-4 shrink-0 text-neutral-600 transition-transform group-open:rotate-90"
          strokeWidth={2}
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <code className="font-mono text-[13px] font-semibold text-neutral-100">{tool.name}</code>
            <ProviderBadge provider={tool.provider} />
            <AccessChip gated={tool.gated} />
          </div>
          {tool.description ? (
            <p className="mt-1 text-[13px] leading-snug text-neutral-400">{tool.description}</p>
          ) : null}
        </div>
      </summary>
      <div className="space-y-3 px-4 pb-4 pl-11">
        {tool.paramNames.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {tool.paramNames.map((p) => (
              <span
                key={p}
                className="rounded bg-neutral-900 px-1.5 py-0.5 font-mono text-[11px] text-neutral-300"
              >
                {p}
              </span>
            ))}
          </div>
        ) : (
          <p className="font-mono text-[11px] uppercase tracking-[0.1em] text-neutral-600">No parameters</p>
        )}
        <div>
          <div className="mb-1 font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500">
            Input schema
          </div>
          <pre className="overflow-x-auto rounded border border-neutral-800 bg-neutral-950 p-3 font-mono text-[11.5px] leading-relaxed text-neutral-300">
            {schemaJson}
          </pre>
        </div>
      </div>
    </details>
  );
}

function ToolSection({
  title,
  tools,
}: {
  title: string;
  tools: CatalogTool[];
}) {
  if (tools.length === 0) return null;
  return (
    <section className="overflow-hidden rounded-lg border border-neutral-800 bg-neutral-950">
      <div className="flex items-center justify-between border-b border-neutral-800 bg-neutral-900/40 px-4 py-2.5">
        <h2 className="font-mono text-[12px] font-semibold uppercase tracking-[0.16em] text-neutral-200">
          {title}
        </h2>
        <span className="font-mono text-[12px] tabular-nums text-neutral-500">
          {tools.length} {tools.length === 1 ? "tool" : "tools"}
        </span>
      </div>
      <div>
        {tools.map((t) => (
          <ToolRow key={t.name} tool={t} />
        ))}
      </div>
    </section>
  );
}

export default function ToolboxBrowser({
  tools,
  resources,
  suppressedNativeWrites,
  driftWarnings,
}: {
  tools: CatalogTool[];
  resources: CatalogResource[];
  suppressedNativeWrites: string[];
  driftWarnings: string[];
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<FilterKey>("all");

  const { falcon, extension, visibleCount } = useMemo(() => {
    const q = query.trim().toLowerCase();
    const matched = tools
      .filter((t) => matchesFilter(t, filter))
      .filter(
        (t) =>
          !q ||
          t.name.toLowerCase().includes(q) ||
          t.description.toLowerCase().includes(q),
      )
      .sort((a, b) => a.name.localeCompare(b.name));
    return {
      falcon: matched.filter((t) => t.provider === "falcon-mcp"),
      extension: matched.filter((t) => t.provider === "extension"),
      visibleCount: matched.length,
    };
  }, [tools, query, filter]);

  return (
    <div className="space-y-5">
      {/* Approval-gate drift. A native falcon-mcp tool advertises a write
          (readOnlyHint:false) but isn't in REQUIRES_APPROVAL — the agent loop
          still gates it via the annotation backstop, but the registry is the
          authoritative source and needs the entry. Empty in the healthy state.
          Raw tool names are intentional here (developer Reference surface). */}
      {driftWarnings.length > 0 && (
        <div className="rounded-lg border border-amber-600/50 bg-amber-950/30 p-4">
          <div className="flex items-center gap-2 text-amber-300">
            <AlertTriangle className="h-4 w-4 shrink-0" strokeWidth={2} />
            <span className="font-mono text-[12px] uppercase tracking-[0.14em]">
              Approval-gate drift ({driftWarnings.length})
            </span>
          </div>
          <p className="mt-2 text-[13px] leading-relaxed text-amber-100/80">
            {driftWarnings.length === 1 ? "This native tool advertises" : "These native tools advertise"}{" "}
            a write (<code className="font-mono text-[12px]">readOnlyHint: false</code>) but{" "}
            {driftWarnings.length === 1 ? "isn't" : "aren't"} listed in{" "}
            <code className="font-mono text-[12px]">REQUIRES_APPROVAL</code>. The agent still gates{" "}
            {driftWarnings.length === 1 ? "it" : "them"} via the annotation backstop, but add{" "}
            {driftWarnings.length === 1 ? "it" : "them"} to{" "}
            <code className="font-mono text-[12px]">lib/mcp/write-tools.ts</code> so the registry stays authoritative.
          </p>
          <ul className="mt-3 flex flex-wrap gap-1.5">
            {driftWarnings.map((n) => (
              <li
                key={n}
                className="rounded bg-amber-900/40 px-1.5 py-0.5 font-mono text-[11px] text-amber-200"
              >
                {n}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Search + filter chips */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2 rounded-md border border-neutral-800 bg-neutral-950/60 px-2.5 focus-within:border-brand-700/60 sm:w-72">
          <Search className="h-4 w-4 shrink-0 text-neutral-600" strokeWidth={2} />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter tools…"
            aria-label="Filter tools"
            className="h-9 w-full bg-transparent text-[13px] text-neutral-200 placeholder:text-neutral-600 focus:outline-none"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery("")}
              title="Clear filter"
              className="shrink-0 text-neutral-600 hover:text-neutral-300"
            >
              <X className="h-3.5 w-3.5" strokeWidth={2} />
            </button>
          )}
        </div>
        <div className="flex flex-wrap gap-1.5">
          {FILTERS.map((f) => {
            const active = filter === f.key;
            return (
              <button
                key={f.key}
                type="button"
                onClick={() => setFilter(f.key)}
                aria-pressed={active}
                className={`rounded-full border px-3 py-1 font-mono text-[12px] tracking-[0.04em] transition-colors ${
                  active
                    ? "border-brand-700/50 bg-brand-600/15 text-neutral-50"
                    : "border-neutral-800 bg-neutral-950 text-neutral-400 hover:border-neutral-700 hover:text-neutral-200"
                }`}
              >
                {f.label}
              </button>
            );
          })}
        </div>
      </div>

      {visibleCount === 0 ? (
        <div className="rounded-lg border border-dashed border-neutral-800 bg-neutral-950/60 p-10 text-center text-sm text-neutral-500">
          No tools match this filter.
        </div>
      ) : (
        <div className="space-y-5">
          <ToolSection title="falcon-mcp" tools={falcon} />
          <ToolSection title="Extension (FalconPy)" tools={extension} />
        </div>
      )}

      {/* Readable MCP resources (FQL guides etc.) */}
      {resources.length > 0 && (
        <details className="rounded-lg border border-neutral-800 bg-neutral-950">
          <summary className="cursor-pointer px-4 py-3 font-mono text-[12px] uppercase tracking-[0.14em] text-neutral-300 hover:text-neutral-100">
            Reference resources ({resources.length})
          </summary>
          <ul className="space-y-2 border-t border-neutral-800 px-4 py-3">
            {resources.map((r) => (
              <li key={r.uri} className="text-[13px]">
                <code className="font-mono text-[12px] text-neutral-200">{r.uri}</code>
                {r.description ? (
                  <span className="ml-2 text-neutral-500">— {r.description}</span>
                ) : null}
              </li>
            ))}
          </ul>
        </details>
      )}

      {/* Why some native writes aren't shown — the curation talking point */}
      {suppressedNativeWrites.length > 0 && (
        <details className="rounded-lg border border-neutral-800 bg-neutral-950">
          <summary className="cursor-pointer px-4 py-3 font-mono text-[12px] uppercase tracking-[0.14em] text-neutral-300 hover:text-neutral-100">
            Why are some native writes not shown?
          </summary>
          <div className="border-t border-neutral-800 px-4 py-3">
            <p className="text-[13px] leading-relaxed text-neutral-400">
              These native falcon-mcp write tools are deliberately routed to richer
              equivalents so their pre-write safety checks aren&apos;t lost — IOA
              regex validation, canonical host-group naming, disable-before-delete,
              and canonical verdict tagging. The agent calls the curated version
              instead; the write itself stays human-approved either way.
            </p>
            <ul className="mt-3 flex flex-wrap gap-1.5">
              {suppressedNativeWrites.map((n) => (
                <li
                  key={n}
                  className="rounded bg-neutral-900 px-1.5 py-0.5 font-mono text-[11px] text-neutral-400"
                >
                  {n}
                </li>
              ))}
            </ul>
          </div>
        </details>
      )}
    </div>
  );
}
