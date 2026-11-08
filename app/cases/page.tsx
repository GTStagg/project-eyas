"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Briefcase, MessageSquare } from "lucide-react";
import AppShell from "@/components/AppShell";
import { buildPrimerHref } from "@/components/primerHandoff";
import PageHero from "@/components/PageHero";

type CaseRow = {
  id: string;
  reference_id?: string;
  name: string;
  status: string;
  severity: number;
  created_timestamp?: string;
  updated_timestamp?: string;
  assigned_to_name?: string;
  description?: string;
  tags: string[];
  alert_evidence_count: number;
  event_evidence_count: number;
};

type CasesResp = {
  ok: boolean;
  scope_pending?: boolean;
  note?: string;
  error?: string;
  items?: CaseRow[];
  summary?: { total: number; open: number; unassigned: number; high_sev: number };
};

function sevTone(sev: number): { label: string; cls: string } {
  if (sev >= 75) return { label: "Critical", cls: "border-red-800/60 bg-red-950/40 text-red-200" };
  if (sev >= 50) return { label: "High", cls: "border-amber-800/60 bg-amber-950/40 text-amber-200" };
  if (sev >= 25) return { label: "Medium", cls: "border-sky-800/60 bg-sky-950/40 text-sky-200" };
  return { label: "Low", cls: "border-neutral-700 bg-neutral-900 text-neutral-300" };
}

const STATUS_TONE: Record<string, string> = {
  new: "border-sky-800/60 bg-sky-950/40 text-sky-200",
  in_progress: "border-amber-800/60 bg-amber-950/40 text-amber-200",
  reopened: "border-red-800/60 bg-red-950/40 text-red-200",
  closed: "border-emerald-800/60 bg-emerald-950/30 text-emerald-300/90",
};

function age(ts?: string): string {
  if (!ts) return "—";
  const d = Date.parse(ts);
  if (Number.isNaN(d)) return "—";
  const h = (Date.now() - d) / 36e5;
  if (h < 1) return "<1h";
  if (h < 24) return `${Math.floor(h)}h`;
  return `${Math.floor(h / 24)}d`;
}

// Load-bearing context only: one declarative sentence + the ids the chat
// system prompt can't derive. Decision-doc structure / tool ordering lives
// in app/api/chat/route.ts, not here.
function casePrimer(c: CaseRow): string {
  const ref = c.reference_id ?? c.id;
  return `Triage Falcon case \`${ref}\` (case id \`${c.id}\`). Load it with falcon_get_cases and proceed.`;
}

export default function CasesPage() {
  const [data, setData] = useState<CasesResp | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/cases", { cache: "no-store" })
      .then((r) => r.json())
      .then((j) => {
        if (!cancelled) setData(j);
      })
      .catch((err) => {
        if (!cancelled) setData({ ok: false, error: String(err) });
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <AppShell title="Cases">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up space-y-8">
          <PageHero
            icon={Briefcase}
            eyebrow="Cases"
            title="Filed investigations and their evidence."
            subtitle="Open cases ranked by severity, with attached alert and event counts."
          />

          {loading && (
            <div className="border border-dashed border-neutral-800 bg-neutral-950/60 p-8 text-center text-neutral-400">
              Loading cases…
            </div>
          )}

          {!loading && data && !data.ok && (
            <div className="rounded-lg border border-red-900 bg-red-950/40 px-4 py-3 text-sm text-red-200">
              <div className="font-semibold">Couldn&rsquo;t load cases</div>
              <div className="mt-1 text-red-200/80">
                {data.error ??
                  "Falcon didn't return case data. Refresh to try again; if it persists, check the Falcon connection on the status page."}
              </div>
            </div>
          )}

          {!loading && data?.ok && data.scope_pending && (
            <div className="rounded-lg border border-amber-900 bg-amber-950/40 px-4 py-3 text-sm text-amber-100">
              <div className="font-semibold">Scope pending</div>
              <div className="mt-1">
                {data.note ?? "Cases API scope is not granted on this tenant."}
              </div>
              <div className="mt-2 text-amber-200/70">
                Add the <span className="font-mono">Cases (Read)</span> scope to your Falcon API client and the surface lights up automatically.
              </div>
            </div>
          )}

          {!loading && data?.ok && !data.scope_pending && data.items && (
            <>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <SummaryTile label="Total cases" value={data.summary?.total ?? data.items.length} />
                <SummaryTile label="Open" value={data.summary?.open ?? 0} tone={data.summary?.open ? "warn" : "neutral"} />
                <SummaryTile label="Unassigned" value={data.summary?.unassigned ?? 0} tone={data.summary?.unassigned ? "warn" : "neutral"} />
                <SummaryTile label="High severity" value={data.summary?.high_sev ?? 0} tone={data.summary?.high_sev ? "danger" : "neutral"} />
              </div>

              {data.items.length === 0 ? (
                <div className="border border-dashed border-neutral-800 bg-neutral-950/60 p-8 text-center text-neutral-400">
                  No cases found.
                </div>
              ) : (
                <div className="overflow-x-auto rounded-md border border-neutral-800 bg-neutral-950">
                  <table className="w-full min-w-[900px] text-left">
                    <thead className="border-b border-neutral-800 bg-neutral-950/80 text-[11px] uppercase tracking-[0.14em] text-neutral-500">
                      <tr>
                        <th className="px-3 py-2 font-mono">Case</th>
                        <th className="px-3 py-2 font-mono">Severity</th>
                        <th className="px-3 py-2 font-mono">Status</th>
                        <th className="px-3 py-2 font-mono">Assignee</th>
                        <th className="px-3 py-2 font-mono">Evidence</th>
                        <th className="px-3 py-2 font-mono">Age</th>
                        <th className="px-3 py-2 font-mono"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.items.map((c) => {
                        const sev = sevTone(c.severity);
                        return (
                          <tr key={c.id} className="border-b border-neutral-900 last:border-b-0 hover:bg-neutral-900/40">
                            <td className="max-w-[28rem] px-3 py-2.5">
                              <div className="truncate text-sm font-semibold text-neutral-100" title={c.name}>{c.name}</div>
                              <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[12px] text-neutral-500">
                                {c.reference_id && (
                                  <span className="font-mono text-neutral-400">{c.reference_id}</span>
                                )}
                                {c.tags.slice(0, 4).map((t) => (
                                  <span key={t} className="rounded-sm border border-neutral-800 bg-neutral-900 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.1em] text-neutral-400">
                                    {t}
                                  </span>
                                ))}
                              </div>
                            </td>
                            <td className="whitespace-nowrap px-3 py-2.5">
                              <span className={`inline-block whitespace-nowrap rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.1em] ${sev.cls}`}>
                                {sev.label} · {c.severity}
                              </span>
                            </td>
                            <td className="whitespace-nowrap px-3 py-2.5">
                              <span className={`inline-block whitespace-nowrap rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.1em] ${STATUS_TONE[c.status] ?? "border-neutral-700 bg-neutral-900 text-neutral-300"}`}>
                                {c.status.replace(/_/g, " ")}
                              </span>
                            </td>
                            <td className="px-3 py-2.5 font-mono text-[12px] text-neutral-400">
                              {c.assigned_to_name ?? <span className="text-amber-300/70">unassigned</span>}
                            </td>
                            <td className="whitespace-nowrap px-3 py-2.5 font-mono text-[12px] text-neutral-400">
                              {c.alert_evidence_count} alert{c.alert_evidence_count === 1 ? "" : "s"} · {c.event_evidence_count} event{c.event_evidence_count === 1 ? "" : "s"}
                            </td>
                            <td className="px-3 py-2.5 font-mono text-[12px] text-neutral-400">{age(c.created_timestamp)}</td>
                            <td className="whitespace-nowrap px-3 py-2.5 text-right">
                              <Link
                                href={buildPrimerHref(casePrimer(c))}
                                className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-sm border border-neutral-800 bg-neutral-950 px-2 py-1 font-mono text-[11px] uppercase tracking-[0.1em] text-neutral-300 transition hover:border-neutral-700 hover:text-white"
                              >
                                <MessageSquare className="h-3 w-3" strokeWidth={1.75} />
                                Triage
                              </Link>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </div>
      </main>
    </AppShell>
  );
}

function SummaryTile({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: number;
  tone?: "neutral" | "warn" | "danger";
}) {
  const ring =
    tone === "danger"
      ? "border-red-800/60 bg-red-950/30"
      : tone === "warn"
        ? "border-amber-800/60 bg-amber-950/30"
        : "border-neutral-800 bg-neutral-950";
  const valueColor =
    tone === "danger"
      ? "text-oxblood-300"
      : tone === "warn"
        ? "text-amber-300"
        : "text-neutral-100";
  return (
    <div className={`rounded-md border ${ring} px-4 py-3`}>
      <div className="font-mono text-[11px] uppercase tracking-[0.14em] text-neutral-500">
        {label}
      </div>
      <div className={`mt-1 text-2xl font-bold ${valueColor}`}>{value}</div>
    </div>
  );
}
