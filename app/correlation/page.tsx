"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Network, Play, ArrowUpRight, RotateCcw, ShieldAlert } from "lucide-react";
import AppShell from "@/components/AppShell";
import PageHero from "@/components/PageHero";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";
import { buildPrimerHref } from "@/components/primerHandoff";

type Health = {
  total: number;
  byStatus: { active: number; inactive: number };
  bySeverity: { critical: number; high: number; medium: number; low: number; informational: number };
  mitre: { tactics: string[]; techniques: string[] };
  stale: { id?: string; name?: string; lastUpdated?: string; ageDays: number }[];
  inactive: { id?: string; name?: string; severity: number }[];
  rules: {
    id?: string;
    name?: string;
    status?: string;
    severity: number;
    type?: string;
    lastUpdated?: string;
  }[];
};
type GetResponse = { ok: boolean; scope_pending?: boolean; note?: string; error?: string; health?: Health };

function Stat({ label, value, tone = "default" }: { label: string; value: number; tone?: "default" | "amber" | "rose" }) {
  const t = tone === "amber" ? "text-amber-300" : tone === "rose" ? "text-rose-300" : "text-neutral-100";
  return (
    <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-3">
      <div className={`text-2xl font-semibold ${t}`}>{value}</div>
      <div className="mt-0.5 text-xs uppercase tracking-wider text-neutral-500">{label}</div>
    </div>
  );
}

export default function CorrelationPage() {
  const ref = useRef<AgentRunHandle>(null);
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<GetResponse | null>(null);
  const [generated, setGenerated] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/correlation", { cache: "no-store" });
      setData((await r.json()) as GetResponse);
    } catch {
      setData({ ok: false, error: "Couldn't load correlation rules. Refresh to try again." });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const generate = () => {
    setGenerated(true);
    setTimeout(() => ref.current?.start(), 0);
  };

  const tuneHref = (name?: string, id?: string) =>
    buildPrimerHref(
      `Review and tune the NGSIEM correlation rule \`${name ?? id ?? "?"}\`` +
        (id ? ` (rule id \`${id}\`)` : "") +
        " — pull its current definition first, then propose an updated search filter.",
    );
  const disableHref = (name?: string, id?: string) =>
    buildPrimerHref(
      `Disable the NGSIEM correlation rule \`${name ?? id ?? "?"}\`` +
        (id ? ` (rule id \`${id}\`)` : "") +
        " — set its status to inactive.",
    );

  const health = data?.health;
  const scopePending = data?.ok && data?.scope_pending;

  return (
    <AppShell title="Correlation rules">
      <main className="flex-1 px-6 py-8">
        <div className="mx-auto max-w-5xl space-y-6">
          <PageHero
            icon={Network}
            eyebrow="Correlation rules"
            title="Detection content health"
            subtitle="Your NGSIEM correlation rules, summarized for coverage gaps and drift."
          />

          {loading && (
            <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
              Loading…
            </div>
          )}

          {!loading && scopePending && (
            <div className="rounded-lg border border-amber-900 bg-amber-950/40 px-4 py-3 text-sm text-amber-100">
              <div className="font-semibold">Scope pending</div>
              <div className="mt-1">{data?.note ?? "Correlation Rules scope is not granted on this tenant."}</div>
              <div className="mt-2 text-amber-200/70">
                Add the <span className="font-mono">NGSIEM Correlation Rules</span> scope to your
                Falcon API client and this surface lights up automatically.
              </div>
            </div>
          )}

          {!loading && data && !data.ok && (
            <div className="rounded-lg border border-rose-900/60 bg-rose-950/30 px-4 py-3 text-sm text-rose-300">
              {data.error ?? "Something went wrong."}
            </div>
          )}

          {!loading && health && (
            <>
              <section className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                <Stat label="Published" value={health.total} />
                <Stat label="Active" value={health.byStatus.active} />
                <Stat label="Inactive" value={health.byStatus.inactive} tone="amber" />
                <Stat label="MITRE tactics" value={health.mitre.tactics.length} />
                <Stat label="Stale (>180d)" value={health.stale.length} tone="rose" />
              </section>

              {health.total === 0 ? (
                <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
                  No published correlation rules on this tenant yet.
                </div>
              ) : (
                <>
                  <section className="rounded-lg border border-neutral-800 bg-neutral-950 p-6 shadow-lg shadow-black/40">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <h2 className="text-lg font-semibold text-white">Assessment</h2>
                        <p className="mt-1 text-sm text-neutral-400">
                          Generate a decision document: coverage gaps, stale rules, and what to tune.
                        </p>
                      </div>
                      {!generated ? (
                        <button
                          onClick={generate}
                          className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-brand-800 bg-brand-900/40 px-4 py-2 text-xs font-medium uppercase tracking-wider text-white hover:border-brand-700 hover:bg-brand-900/60"
                        >
                          <Play className="h-3.5 w-3.5" /> Generate assessment
                        </button>
                      ) : (
                        <button
                          onClick={() => ref.current?.start()}
                          className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-900 px-4 py-2 text-xs font-medium uppercase tracking-wider text-neutral-200 hover:border-neutral-700 hover:bg-neutral-800"
                        >
                          <RotateCcw className="h-3.5 w-3.5" /> Re-run
                        </button>
                      )}
                    </div>
                    {generated && (
                      <div className="mt-4">
                        <AgentRun
                          ref={ref}
                          endpoint="/api/correlation"
                          body={{}}
                          webhookTitle="Correlation rule health"
                          webhookSource="correlation"
                        />
                      </div>
                    )}
                  </section>

                  <section className="overflow-hidden rounded-lg border border-neutral-800 bg-neutral-950/60">
                    <div className="border-b border-neutral-800 px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-neutral-400">
                      Published rules
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-neutral-800/80 text-left text-xs uppercase tracking-wider text-neutral-500">
                            <th className="px-4 py-2 font-medium">Rule</th>
                            <th className="px-4 py-2 font-medium">Status</th>
                            <th className="px-4 py-2 font-medium">Severity</th>
                            <th className="px-4 py-2 font-medium">Updated</th>
                            <th className="px-4 py-2 text-right font-medium">Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {health.rules.slice(0, 100).map((r, i) => (
                            <tr key={r.id ?? i} className="border-b border-neutral-800/50 last:border-0">
                              <td className="px-4 py-2 text-neutral-200">{r.name ?? "—"}</td>
                              <td className="px-4 py-2">
                                <span
                                  className={`text-xs ${
                                    (r.status ?? "").toLowerCase() === "active"
                                      ? "text-emerald-300"
                                      : "text-amber-300"
                                  }`}
                                >
                                  {r.status ?? "—"}
                                </span>
                              </td>
                              <td className="px-4 py-2 text-xs text-neutral-400">{r.severity || "—"}</td>
                              <td className="px-4 py-2 text-xs text-neutral-500">
                                {r.lastUpdated ? r.lastUpdated.slice(0, 10) : "—"}
                              </td>
                              <td className="px-4 py-2">
                                <div className="flex justify-end gap-1">
                                  <a
                                    href={tuneHref(r.name, r.id)}
                                    className="inline-flex items-center gap-1 rounded-md border border-neutral-700 px-2 py-1 text-xs text-neutral-300 hover:bg-neutral-800"
                                  >
                                    Tune <ArrowUpRight className="h-3 w-3" />
                                  </a>
                                  {(r.status ?? "").toLowerCase() === "active" && (
                                    <a
                                      href={disableHref(r.name, r.id)}
                                      className="inline-flex items-center gap-1 rounded-md border border-amber-900/60 px-2 py-1 text-xs text-amber-300 hover:bg-amber-950/40"
                                    >
                                      Disable <ArrowUpRight className="h-3 w-3" />
                                    </a>
                                  )}
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {health.rules.length > 100 && (
                      <div className="border-t border-neutral-800 px-4 py-2 text-xs text-neutral-500">
                        Showing 100 of {health.rules.length}. Use the assessment for prioritized actions.
                      </div>
                    )}
                  </section>

                  <p className="flex items-center gap-1.5 text-xs text-neutral-600">
                    <ShieldAlert className="h-3.5 w-3.5" /> Tune and disable open in chat for review
                    before any rule change is applied.
                  </p>
                </>
              )}
            </>
          )}
        </div>
      </main>
    </AppShell>
  );
}
