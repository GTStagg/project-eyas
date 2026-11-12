import { Blocks } from "lucide-react";
import AppShell from "@/components/AppShell";
import PageHero from "@/components/PageHero";
import ToolboxBrowser from "@/components/ToolboxBrowser";
import { getToolCatalog } from "@/lib/mcp/catalog";

export const dynamic = "force-dynamic";

function StatStrip({
  counts,
}: {
  counts: { total: number; eyasMcp: number; extension: number; readOnly: number; gated: number };
}) {
  const items = [
    { value: counts.total, label: "tools" },
    { value: counts.eyasMcp, label: "eyas-mcp" },
    { value: counts.extension, label: "extension" },
    { value: counts.readOnly, label: "read-only" },
    { value: counts.gated, label: "approval-gated" },
  ];
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-500">
      {items.map((it, i) => (
        <span key={it.label} className="flex items-center gap-2">
          {i > 0 && <span className="text-neutral-700">·</span>}
          <span className="text-neutral-300 tabular-nums">{it.value}</span>
          {it.label}
        </span>
      ))}
    </div>
  );
}

export default async function AgentToolboxPage() {
  const catalog = await getToolCatalog();

  return (
    <AppShell title="Agent toolbox">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up space-y-8">
          <PageHero
            icon={Blocks}
            eyebrow="Reference · developer surface"
            title="One AI, the entire live Falcon tool surface."
            subtitle="Every tool this console's agent can compose — eyas-mcp plus the FalconPy extension — each marked read-only or human-approved."
          />

          {catalog.ok ? (
            <>
              <StatStrip counts={catalog.counts} />
              <ToolboxBrowser
                tools={catalog.tools}
                resources={catalog.resources}
                suppressedNativeWrites={catalog.suppressedNativeWrites}
                driftWarnings={catalog.driftWarnings}
              />
            </>
          ) : (
            <div className="rounded-lg border border-dashed border-neutral-800 bg-neutral-950/60 p-10 text-center">
              <div className="text-base font-semibold text-neutral-200">
                Connect a Falcon tenant to populate the live catalog
              </div>
              <p className="mx-auto mt-2 max-w-md text-sm text-neutral-400">
                This page reads the live tool surface directly from the connected
                Falcon environment. Once connections are configured, the full
                catalog appears here.
              </p>
            </div>
          )}
        </div>
      </main>
    </AppShell>
  );
}
