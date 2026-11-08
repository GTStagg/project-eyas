import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { detectFalconError, parseConcatenatedJson } from "@/lib/mcp/parse";
import { enrichRowsWithAdversary } from "@/lib/intel/adversary";
import Link from "next/link";
import { ArrowUpRight, ListChecks } from "lucide-react";
import AppShell from "@/components/AppShell";
import DetectionsTable, { type Detection } from "@/components/DetectionsTable";

export const dynamic = "force-dynamic";

const DEFAULT_LIMIT = 50;

async function fetchDetections(
  limit: number,
): Promise<{ items: Detection[] } | { error: string }> {
  const attempt = async (): Promise<Detection[]> =>
    withFalconMcpClient(async (client) => {
      const result = await client.callTool({
        name: "falcon_search_detections",
        arguments: {
          // Endpoint detections only — see app/api/queue/route.ts for rationale.
          // Without this, NGSIEM correlation rules and IDP policy events fill
          // the page with noise that has no host attribution.
          filter: "product:'epp'",
          limit,
          sort: "created_timestamp.desc",
        },
      });
      const text = (result.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      const parsed = parseConcatenatedJson<Detection>(text);
      const upstreamErr = detectFalconError(parsed);
      if (upstreamErr) throw new Error(upstreamErr);
      parsed.sort((a, b) =>
        (b.created_timestamp ?? "").localeCompare(a.created_timestamp ?? ""),
      );
      // Resolve Falcon-native adversary attribution. One batched
      // falcon_search_actors call covers every distinct adversary_id
      // across the page; rows without correlation simply leave the
      // chip unset.
      await enrichRowsWithAdversary(client, parsed);
      return parsed;
    });

  try {
    return { items: await attempt() };
  } catch {
    try {
      return { items: await attempt() };
    } catch (err) {
      return { error: err instanceof Error ? err.message : String(err) };
    }
  }
}

export default async function DetectionsPage() {
  const result = await fetchDetections(DEFAULT_LIMIT);

  return (
    <AppShell title="Detections">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <div className="eyebrow">Endpoint // Detections</div>
              <h1 className="mt-2 text-4xl font-bold tracking-tight text-white">Recent detections</h1>
            </div>
            <span className="font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-400">
              top {DEFAULT_LIMIT} · sorted newest first · click row to expand
            </span>
          </div>

          {"error" in result ? (
            <div className="mt-6 rounded-lg border border-red-900 bg-red-950/40 px-4 py-3 text-sm text-red-200">
              <div className="font-semibold">Failed to load detections</div>
              <div className="mt-1 font-mono text-xs">{result.error}</div>
              <div className="mt-2 text-xs text-oxblood-300/70">
                Upstream Falcon API failure (retried once). This is usually
                transient — refresh in a moment.
              </div>
            </div>
          ) : (
            <>
              <div className="mt-6 flex items-start gap-3 rounded-lg border border-neutral-800 bg-neutral-950/60 px-4 py-3">
                <ListChecks className="mt-0.5 h-5 w-5 shrink-0 text-oxblood-400" strokeWidth={2} />
                <div className="flex-1 text-sm text-neutral-300">
                  <span className="text-neutral-100">Triaging open detections?</span>{" "}
                  Use the Triage Queue for ranked priorities, campaign clustering, identity overlay, tuning candidates, and the agent triage brief. This page is the raw newest-first feed.
                  <div className="mt-2">
                    <Link
                      href="/queue"
                      className="inline-flex h-7 items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950 px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-neutral-700 hover:text-white"
                    >
                      Triage queue
                      <ArrowUpRight className="h-3 w-3" strokeWidth={2} />
                    </Link>
                  </div>
                </div>
              </div>
              <div className="mt-4 text-base text-neutral-400">
                {result.items.length}{" "}
                {result.items.length === 1 ? "detection" : "detections"} returned.
              </div>
              <DetectionsTable items={result.items} />
            </>
          )}
        </div>
      </main>
    </AppShell>
  );
}
