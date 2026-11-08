"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Radar, RefreshCw, AlertTriangle, ArrowRight, MessageSquare } from "lucide-react";
import type { IntelHuntMatch } from "@/lib/intel/hunt";
import { buildPrimerHref } from "@/components/primerHandoff";

type Meta = {
  intel_window_days: number;
  detections_window_days: number;
  indicators_pulled: number;
  detections_pulled: number;
  iocs_pulled: number;
  active_in_tenant: number;
  covered_by_intel: number;
  watchlist_only: number;
};

type Payload =
  | { ok: true; matches: IntelHuntMatch[]; meta: Meta }
  | { ok: false; error: string };

const VERDICT_LABEL: Record<IntelHuntMatch["verdict"], string> = {
  active_in_tenant: "active in tenant",
  covered_by_intel: "covered by intel",
  watchlist_only: "watchlist only",
};

const VERDICT_TONE: Record<IntelHuntMatch["verdict"], string> = {
  active_in_tenant: "border-red-800 bg-red-950/50 text-red-200",
  covered_by_intel: "border-teal-800 bg-teal-950/40 text-teal-200",
  watchlist_only: "border-neutral-700 bg-neutral-900 text-neutral-300",
};

function huntPrimer(m: IntelHuntMatch): string {
  if (m.verdict === "active_in_tenant") {
    return [
      `Investigate the active intel hit on indicator \`${m.indicator}\` (${m.indicator_type}).`,
      `${m.detection_hits} fires across hosts: ${m.detection_hosts.join(", ")}.`,
      m.actors.length > 0 ? `Actors: ${m.actors.join(", ")}.` : "",
      m.malware_families.length > 0 ? `Families: ${m.malware_families.join(", ")}.` : "",
      `Sample composite_ids: ["${m.detection_sample_ids.join('", "')}"].`,
    ]
      .filter(Boolean)
      .join(" ");
  }
  return [
    `Look up indicator \`${m.indicator}\` (${m.indicator_type}) in Falcon Intel.`,
    m.actors.length > 0 ? `Actors: ${m.actors.join(", ")}.` : "",
    m.malware_families.length > 0 ? `Families: ${m.malware_families.join(", ")}.` : "",
  ]
    .filter(Boolean)
    .join(" ");
}

function MatchCard({ m }: { m: IntelHuntMatch }) {
  const router = useRouter();
  return (
    <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] ${VERDICT_TONE[m.verdict]}`}
            >
              {VERDICT_LABEL[m.verdict]}
            </span>
            <span className="rounded border border-neutral-800 bg-neutral-900/60 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-400">
              {m.indicator_type}
            </span>
            {m.malicious_confidence && (
              <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500">
                {m.malicious_confidence}
              </span>
            )}
            {m.detection_hits > 0 && (
              <span className="rounded border border-red-900 bg-red-950/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-oxblood-300">
                {m.detection_hits} det · {m.detection_hosts.length} host
                {m.detection_hosts.length === 1 ? "" : "s"}
              </span>
            )}
            {m.on_custom_ioc_list && (
              <span className="rounded border border-blue-900 bg-blue-950/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-blue-300">
                custom IOC
                {m.custom_ioc_action ? ` · ${m.custom_ioc_action}` : ""}
              </span>
            )}
          </div>
          <div
            className="mt-1.5 break-all font-mono text-[12px] text-neutral-100"
            title={m.indicator}
          >
            {m.indicator.length > 80
              ? `${m.indicator.slice(0, 60)}…${m.indicator.slice(-12)}`
              : m.indicator}
          </div>
          {m.detection_hosts.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {m.detection_hosts.slice(0, 6).map((h) => (
                <span
                  key={h}
                  className="rounded border border-neutral-800 bg-neutral-900/60 px-1.5 py-0.5 font-mono text-[10.5px] text-neutral-300"
                >
                  {h}
                </span>
              ))}
              {m.detection_hosts.length > 6 && (
                <span className="rounded border border-neutral-800 bg-neutral-900/40 px-1.5 py-0.5 font-mono text-[10.5px] text-neutral-500">
                  +{m.detection_hosts.length - 6} more
                </span>
              )}
            </div>
          )}
          {m.reasons.length > 0 && (
            <div className="mt-1.5 text-[11px] text-neutral-500">
              {m.reasons.join(" · ")}
            </div>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <button
            onClick={() =>
              router.push(buildPrimerHref(huntPrimer(m)))
            }
            title={
              m.verdict === "active_in_tenant"
                ? "Hand to chat agent for active-hit investigation (host context, IR scoping)"
                : "Hand to chat agent for IOC enrichment (Intel context, proactive recommendation)"
            }
            className="flex h-8 items-center gap-1 rounded-md border border-brand-900/60 bg-brand-950/40 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-oxblood-200 transition hover:bg-brand-900/40 hover:text-white"
          >
            <MessageSquare className="h-3 w-3" strokeWidth={1.75} />
            {m.verdict === "active_in_tenant" ? "Investigate" : "Enrich"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function IntelHuntPanel() {
  const [matches, setMatches] = useState<IntelHuntMatch[] | null>(null);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [showWatchlist, setShowWatchlist] = useState(false);

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/api/intel/hunt", { cache: "no-store" });
      const j = (await r.json()) as Payload;
      if (!j.ok) throw new Error(j.error);
      setMatches(j.matches);
      setMeta(j.meta);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  // Hide watchlist+covered-by-intel by default unless toggled — they're
  // long-tail awareness, not action items. Active-in-tenant always shows.
  const visible = matches
    ? showWatchlist
      ? matches
      : matches.filter((m) => m.verdict === "active_in_tenant")
    : null;

  return (
    <section className="rounded-md border border-orange-900/40 bg-gradient-to-br from-neutral-950 via-neutral-950 to-orange-950/15 p-4 shadow-[0_18px_45px_-30px_rgba(251,146,60,0.4)]">
      <div className="mb-2 flex items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs uppercase tracking-[0.16em] text-orange-300">
          <Radar className="h-3.5 w-3.5" strokeWidth={1.75} />
          intel // tenant hunt
          {meta && (
            <>
              <span className="text-neutral-600">·</span>
              <span className="text-oxblood-300">{meta.active_in_tenant} active</span>
              <span className="text-neutral-600">·</span>
              <span className="text-teal-300">{meta.covered_by_intel} covered</span>
              <span className="text-neutral-600">·</span>
              <span className="text-neutral-400">
                {meta.indicators_pulled} indicators × {meta.detections_pulled}{" "}
                detections, last {meta.intel_window_days}d
              </span>
            </>
          )}
        </div>
        <button
          onClick={refresh}
          disabled={loading}
          className="flex h-7 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950 px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-neutral-700 hover:text-white disabled:opacity-50"
        >
          <RefreshCw
            className={`h-3 w-3 ${loading ? "animate-spin" : ""}`}
            strokeWidth={1.75}
          />
          Refresh
        </button>
      </div>
      <p className="mb-3 text-[12px] text-neutral-400">
        This week&rsquo;s top Falcon Intel indicators cross-referenced against
        your tenant&rsquo;s last 30 days of detections + custom IOC list. Active
        hits are ranked first; covered-by-intel and watchlist tiers hidden by
        default.
      </p>

      {error && (
        <div className="mb-3 flex items-start gap-2 rounded-md border border-red-900 bg-red-950/40 px-3 py-2 font-mono text-xs text-red-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.75} />
          <span>{error}</span>
        </div>
      )}

      {!error && visible && visible.length === 0 && !loading && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-3 text-[12px] text-neutral-500">
          No active intel hits in your tenant.
          {meta && meta.covered_by_intel > 0 && (
            <button
              onClick={() => setShowWatchlist(true)}
              className="inline-flex h-7 items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950 px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-neutral-700 hover:text-white"
            >
              Show {meta.covered_by_intel + meta.watchlist_only} covered/watchlist
              <ArrowRight className="h-3 w-3" strokeWidth={2} />
            </button>
          )}
        </div>
      )}

      {visible && visible.length > 0 && (
        <div className="space-y-2.5">
          {visible.map((m) => (
            <MatchCard key={`${m.indicator_type}:${m.indicator}`} m={m} />
          ))}
        </div>
      )}

      {meta && (meta.covered_by_intel + meta.watchlist_only) > 0 && (
        <div className="mt-3">
          <button
            onClick={() => setShowWatchlist((s) => !s)}
            className="font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500 hover:text-oxblood-300"
          >
            {showWatchlist ? "hide" : "show"} watchlist tiers (
            {meta.covered_by_intel + meta.watchlist_only})
          </button>
        </div>
      )}
    </section>
  );
}
