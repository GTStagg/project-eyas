"use client";

// Spend breakdown — read-only capability panel. Mirrors the /cost page's
// per-surface / per-model tables in a compact side panel. Data from /api/cost.

import { useEffect, useState } from "react";
import Link from "next/link";
import { Loader2, ArrowUpRight } from "lucide-react";

type Bucket = { surface?: string; model?: string; cost: number; turns: number };
type CostPayload = {
  ok: true;
  totals: { cost: number };
  projectedMonthly: number;
  avgPerDay: number;
  bySurface: Bucket[];
  byModel: Bucket[];
};

// Plain-language surface labels (subset mirrors app/cost + app/scorecard).
const SURFACE_LABEL: Record<string, string> = {
  chat: "Chat",
  briefing: "Daily briefing",
  investigate: "Host investigation",
  ngsiem: "Threat hunting",
  "dashboard-ngsiem": "Threat hunting (dashboard)",
  "queue-brief": "Queue review",
  intel: "Adversary intel",
  "intel-dossier": "Intel dossier",
  identity: "Identity posture",
  recon: "Exposure recon",
  malquery: "Malware search",
  "patch-plan": "Patch planning",
  discover: "Asset discovery",
  correlation: "Correlation rules",
  "data-protection": "Data protection",
  quarantine: "Quarantine review",
  guardian: "AI agent activity",
};

function label(s?: string): string {
  if (!s) return "—";
  return SURFACE_LABEL[s] ?? s.charAt(0).toUpperCase() + s.slice(1).replace(/[-_]/g, " ");
}

const usd = (n: number) => `$${n.toFixed(2)}`;

function BreakdownRows({ rows, total, keyOf }: { rows: Bucket[]; total: number; keyOf: (b: Bucket) => string }) {
  if (rows.length === 0) return <div className="py-2 text-sm text-neutral-500">No spend recorded yet.</div>;
  return (
    <div className="space-y-2">
      {rows.map((b, i) => {
        const pct = total > 0 ? (b.cost / total) * 100 : 0;
        return (
          <div key={i} className="flex items-center gap-3">
            <div className="w-40 shrink-0 truncate text-sm text-neutral-200">{keyOf(b)}</div>
            <div className="h-2 flex-1 overflow-hidden rounded-full bg-neutral-900">
              <div
                className="h-full rounded-full bg-gradient-to-r from-brand-700 to-brand-500"
                style={{ width: `${Math.max(3, pct)}%` }}
              />
            </div>
            <div className="w-16 shrink-0 text-right font-mono text-[12px] tabular-nums text-neutral-300">
              {usd(b.cost)}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function SpendPanel() {
  const [data, setData] = useState<CostPayload | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const r = await fetch("/api/cost", { cache: "no-store" });
        const j = await r.json();
        if (j?.ok) setData(j as CostPayload);
        else setErr(j?.error ?? "Could not load spend.");
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    })();
  }, []);

  if (err) return <div className="text-sm text-oxblood-200">{err}</div>;
  if (!data)
    return (
      <div className="flex items-center gap-2 py-6 text-sm text-neutral-500">
        <Loader2 className="h-4 w-4 animate-spin" strokeWidth={2} /> Loading…
      </div>
    );

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div className="rounded-lg border border-brand-800/60 bg-gradient-to-br from-brand-950/40 via-neutral-950 to-neutral-950 p-4">
          <div className="font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-400">Projected / mo</div>
          <div className="mt-1.5 font-mono text-2xl font-bold tabular-nums text-oxblood-200">
            {usd(data.projectedMonthly)}
          </div>
        </div>
        <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-4">
          <div className="font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-400">All-time</div>
          <div className="mt-1.5 font-mono text-2xl font-bold tabular-nums text-neutral-50">{usd(data.totals.cost)}</div>
        </div>
      </div>

      <div>
        <div className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-neutral-500">By surface</div>
        <BreakdownRows rows={data.bySurface} total={data.totals.cost} keyOf={(b) => label(b.surface)} />
      </div>

      <div>
        <div className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-neutral-500">By model</div>
        <BreakdownRows rows={data.byModel} total={data.totals.cost} keyOf={(b) => b.model ?? "—"} />
      </div>
    </div>
  );
}

export function spendFooter() {
  return (
    <Link
      href="/cost"
      className="inline-flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-brand-700/60 hover:text-oxblood-200"
    >
      Full cost report
      <ArrowUpRight className="h-3.5 w-3.5" strokeWidth={2} />
    </Link>
  );
}
