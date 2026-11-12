"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { SlidersHorizontal, RefreshCw, AlertTriangle, MessageSquare } from "lucide-react";
import type { TuningCandidate } from "@/lib/queue/tuning";
import { buildPrimerHref } from "@/components/primerHandoff";

type Meta = {
  window_days: number;
  sampled: number;
  candidate_count: number;
  truncated?: boolean;
};

type Payload =
  | { ok: true; candidates: TuningCandidate[]; meta: Meta }
  | { ok: false; error: string };

const SIGNAL_LABEL: Record<TuningCandidate["signal"], string> = {
  fp_pattern: "FP pattern",
  queue_drown: "queue drown",
};

const SIGNAL_TONE: Record<TuningCandidate["signal"], string> = {
  fp_pattern: "border-red-900 bg-red-950/40 text-oxblood-300",
  queue_drown: "border-orange-900 bg-orange-950/40 text-orange-300",
};

function tunePrimer(c: TuningCandidate): string {
  const ids = c.sample_composite_ids.slice(0, 4).join('", "');
  if (c.signal === "fp_pattern") {
    const total = c.fp_count + c.tp_count;
    const rate = Math.round((c.fp_rate ?? 0) * 100);
    return `Draft a tuning recommendation for rule \`${c.display_name}\`. Evidence: ${c.fp_count}/${total} closed as FP (${rate}%), ${c.unique_hosts} hosts, max severity ${c.severity_max_name ?? "—"}. Sample composite_ids: ["${ids}"].`;
  }
  return `Draft a tuning recommendation for rule \`${c.display_name}\`. Evidence: ${c.total_fires} fires across ${c.unique_hosts} hosts in 30d with no closures (queue drown), max severity ${c.severity_max_name ?? "—"}. Sample composite_ids: ["${ids}"].`;
}

function CandidateCard({
  c,
  exclusionsAvailable,
}: {
  c: TuningCandidate;
  exclusionsAvailable: boolean;
}) {
  const router = useRouter();
  return (
    <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] ${SIGNAL_TONE[c.signal]}`}
            >
              {SIGNAL_LABEL[c.signal]}
            </span>
            {c.severity_max_name && (
              <span className="rounded border border-neutral-800 bg-neutral-900/60 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-400">
                {c.severity_max_name}
              </span>
            )}
            <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500">
              {c.total_fires} fires · {c.unique_hosts} hosts
            </span>
            {c.signal === "fp_pattern" && c.fp_rate !== undefined && (
              <span className="rounded border border-red-900 bg-red-950/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-oxblood-300">
                {Math.round(c.fp_rate * 100)}% FP
              </span>
            )}
            {c.open_count > 0 && (
              <span className="rounded border border-amber-900 bg-amber-950/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-amber-300">
                {c.open_count} open
              </span>
            )}
          </div>
          <div className="mt-1.5 truncate text-[13.5px] font-semibold text-neutral-100">
            {c.display_name}
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            {c.hostnames.map((h) => (
              <span
                key={h}
                className="rounded border border-neutral-800 bg-neutral-900/60 px-1.5 py-0.5 font-mono text-[10.5px] text-neutral-300"
              >
                {h}
              </span>
            ))}
            {c.unique_hosts > c.hostnames.length && (
              <span className="rounded border border-neutral-800 bg-neutral-900/40 px-1.5 py-0.5 font-mono text-[10.5px] text-neutral-500">
                +{c.unique_hosts - c.hostnames.length} more
              </span>
            )}
          </div>
          {c.reasons.length > 0 && (
            <div className="mt-1.5 text-[11px] text-neutral-500">
              {c.reasons.join(" · ")}
            </div>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          {exclusionsAvailable && (
            <button
              onClick={() =>
                router.push(buildPrimerHref(tunePrimer(c)))
              }
              title="Hand to the chat agent for a tuning recommendation (sample inspection + exclusion proposal, gated create)"
              className="flex h-8 items-center gap-1 rounded-md border border-brand-900/60 bg-brand-950/40 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-oxblood-200 transition hover:bg-brand-900/40 hover:text-white"
            >
              <MessageSquare className="h-3 w-3" strokeWidth={1.75} />
              Tune
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export default function TuningPanel() {
  const [candidates, setCandidates] = useState<TuningCandidate[] | null>(null);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // True when at least one exclusion scope (ML or IOA) is granted. Hides the
  // Tune chip otherwise — the recommendation has no execution path. Defaults
  // to true so a transient health-probe blip doesn't make the chip vanish.
  const [exclusionsAvailable, setExclusionsAvailable] = useState(true);

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/api/detections/tuning", { cache: "no-store" });
      const j = (await r.json()) as Payload;
      if (!j.ok) throw new Error(j.error);
      setCandidates(j.candidates);
      setMeta(j.meta);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
    fetch("/api/health", { cache: "no-store" })
      .then((r) => r.json())
      .then((j) => {
        const caps = j?.falconMcp?.capabilities ?? {};
        // Hide only on confirmed scope denial (=== false). Missing/undefined
        // — probe failed — defaults to show.
        if (caps.mlExclusions === false && caps.ioaExclusions === false) {
          setExclusionsAvailable(false);
        }
      })
      .catch(() => {
        // Probe blip: keep chip visible.
      });
  }, []);

  return (
    <section className="rounded-md border border-orange-900/40 bg-gradient-to-br from-neutral-950 via-neutral-950 to-orange-950/15 p-4 shadow-[0_18px_45px_-30px_rgba(251,146,60,0.4)]">
      <div className="mb-2 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-[0.16em] text-orange-300">
          <SlidersHorizontal className="h-3.5 w-3.5" strokeWidth={1.75} />
          detection // tuning candidates
          {meta && (
            <>
              <span className="text-neutral-600">·</span>
              <span className="text-neutral-400">
                {meta.candidate_count} from {meta.sampled} detections in last{" "}
                {meta.window_days}d
              </span>
              {meta.truncated && (
                <span
                  className="text-amber-300"
                  title={`Only the most recent ${meta.sampled} detections were analyzed — older ones in the window weren't sampled.`}
                >
                  · sampled (capped)
                </span>
              )}
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
        Detection rules firing repeatedly with FP-closure pattern, or drowning
        the queue at low/medium severity. Click{" "}
        <span className="font-mono text-oxblood-300">Tune</span> to hand a tuning
        recommendation (sample inspection + exclusion proposal) to the agent.
      </p>

      {error && (
        <div className="mb-3 flex items-start gap-2 rounded-md border border-red-900 bg-red-950/40 px-3 py-2 font-mono text-xs text-red-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.75} />
          <span>{error}</span>
        </div>
      )}

      {!error && candidates && candidates.length === 0 && !loading && (
        <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-3 text-[12px] text-neutral-500">
          No tuning candidates in the current window. Either the queue is well
          tuned already, or there&apos;s not enough closure history to compute
          patterns yet.
        </div>
      )}

      {candidates && candidates.length > 0 && (
        <div className="space-y-2.5">
          {candidates.map((c) => (
            <CandidateCard
              key={c.display_name}
              c={c}
              exclusionsAvailable={exclusionsAvailable}
            />
          ))}
        </div>
      )}
    </section>
  );
}
