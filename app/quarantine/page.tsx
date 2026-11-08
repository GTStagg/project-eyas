"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { FileLock2, Play, ArrowUpRight, ShieldAlert, RotateCcw } from "lucide-react";
import AppShell from "@/components/AppShell";
import PageHero from "@/components/PageHero";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";
import { buildPrimerHref } from "@/components/primerHandoff";

type HostCluster = { hostname: string; count: number; hashes: string[] };
type HashCluster = { sha256: string; count: number; hosts: string[] };
type QRecord = {
  id?: string;
  sha256?: string;
  hostname?: string;
  state?: string;
  dateUpdated?: string;
  paths: string[];
};
type Summary = {
  total: number;
  byState: { quarantined: number; released: number; other: number };
  hostCount: number;
  hashCount: number;
  repeatHosts: HostCluster[];
  spreadHashes: HashCluster[];
  records: QRecord[];
};
type GetResponse = {
  ok: boolean;
  scope_pending?: boolean;
  note?: string;
  error?: string;
  summary?: Summary;
};

function shortHash(h?: string): string {
  if (!h) return "—";
  return h.length > 16 ? `${h.slice(0, 12)}…` : h;
}

function Stat({ label, value, tone = "default" }: { label: string; value: number; tone?: "default" | "amber" | "emerald" }) {
  const toneClass =
    tone === "amber"
      ? "text-amber-300"
      : tone === "emerald"
        ? "text-emerald-300"
        : "text-neutral-100";
  return (
    <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-3">
      <div className={`text-2xl font-semibold ${toneClass}`}>{value}</div>
      <div className="mt-0.5 text-xs uppercase tracking-wider text-neutral-500">{label}</div>
    </div>
  );
}

export default function QuarantinePage() {
  const ref = useRef<AgentRunHandle>(null);
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<GetResponse | null>(null);
  const [generated, setGenerated] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/quarantine", { cache: "no-store" });
      setData((await r.json()) as GetResponse);
    } catch {
      setData({ ok: false, error: "Couldn't load quarantine data. Refresh to try again." });
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

  // Primer hand-off: the gated release/delete happens in chat, not here.
  const releaseHref = (r: QRecord) =>
    buildPrimerHref(
      `Release the quarantined file \`${r.sha256 ?? "?"}\` on host \`${r.hostname ?? "?"}\`` +
        (r.id ? ` (quarantine id \`${r.id}\`)` : "") +
        " — it has been confirmed a false positive.",
    );
  const deleteHref = (r: QRecord) =>
    buildPrimerHref(
      `Permanently delete the quarantined file \`${r.sha256 ?? "?"}\` on host \`${r.hostname ?? "?"}\`` +
        (r.id ? ` (quarantine id \`${r.id}\`)` : "") +
        " — it has been confirmed malicious.",
    );

  const summary = data?.summary;
  const scopePending = data?.ok && data?.scope_pending;

  return (
    <AppShell title="Quarantine">
      <main className="flex-1 px-6 py-8">
        <div className="mx-auto max-w-5xl space-y-6">
          <PageHero
            icon={FileLock2}
            eyebrow="Quarantine"
            title="Quarantine review"
            subtitle="Files Falcon is holding in quarantine across your tenant, clustered for review."
          />

          {loading && (
            <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
              Loading…
            </div>
          )}

          {!loading && scopePending && (
            <div className="rounded-lg border border-amber-900 bg-amber-950/40 px-4 py-3 text-sm text-amber-100">
              <div className="font-semibold">Scope pending</div>
              <div className="mt-1">{data?.note ?? "Quarantine scope is not granted on this tenant."}</div>
              <div className="mt-2 text-amber-200/70">
                Add the <span className="font-mono">Quarantine</span> scope to your Falcon API client
                and this surface lights up automatically.
              </div>
            </div>
          )}

          {!loading && data && !data.ok && (
            <div className="rounded-lg border border-rose-900/60 bg-rose-950/30 px-4 py-3 text-sm text-rose-300">
              {data.error ?? "Something went wrong."}
            </div>
          )}

          {!loading && summary && (
            <>
              {/* Deterministic summary */}
              <section className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                <Stat label="Total" value={summary.total} />
                <Stat label="Quarantined" value={summary.byState.quarantined} tone="amber" />
                <Stat label="Released" value={summary.byState.released} tone="emerald" />
                <Stat label="Hosts" value={summary.hostCount} />
                <Stat label="Distinct files" value={summary.hashCount} />
              </section>

              {summary.total === 0 ? (
                <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
                  Nothing is in quarantine on this tenant right now.
                </div>
              ) : (
                <>
                  {/* Agentic assessment */}
                  <section className="rounded-lg border border-neutral-800 bg-neutral-950 p-6 shadow-lg shadow-black/40">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <h2 className="text-lg font-semibold text-white">Assessment</h2>
                        <p className="mt-1 text-sm text-neutral-400">
                          Generate a decision document: what needs release, what needs purging, and why.
                        </p>
                      </div>
                      {!generated && (
                        <button
                          onClick={generate}
                          className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-brand-800 bg-brand-900/40 px-4 py-2 text-xs font-medium uppercase tracking-wider text-white hover:border-brand-700 hover:bg-brand-900/60"
                        >
                          <Play className="h-3.5 w-3.5" /> Generate assessment
                        </button>
                      )}
                      {generated && (
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
                          endpoint="/api/quarantine"
                          body={{}}
                          webhookTitle="Quarantine review"
                          webhookSource="quarantine"
                        />
                      </div>
                    )}
                  </section>

                  {/* Record table with gated-write hand-off */}
                  <section className="overflow-hidden rounded-lg border border-neutral-800 bg-neutral-950/60">
                    <div className="border-b border-neutral-800 px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-neutral-400">
                      Quarantined files
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-neutral-800/80 text-left text-xs uppercase tracking-wider text-neutral-500">
                            <th className="px-4 py-2 font-medium">Host</th>
                            <th className="px-4 py-2 font-medium">File (sha256)</th>
                            <th className="px-4 py-2 font-medium">State</th>
                            <th className="px-4 py-2 font-medium">Updated</th>
                            <th className="px-4 py-2 text-right font-medium">Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {summary.records.slice(0, 100).map((r, i) => (
                            <tr key={r.id ?? i} className="border-b border-neutral-800/50 last:border-0">
                              <td className="px-4 py-2 text-neutral-200">{r.hostname ?? "—"}</td>
                              <td className="px-4 py-2 font-mono text-xs text-neutral-400" title={r.sha256}>
                                {shortHash(r.sha256)}
                              </td>
                              <td className="px-4 py-2">
                                <span className="text-xs text-neutral-300">{r.state ?? "—"}</span>
                              </td>
                              <td className="px-4 py-2 text-xs text-neutral-500">
                                {r.dateUpdated ? r.dateUpdated.slice(0, 10) : "—"}
                              </td>
                              <td className="px-4 py-2">
                                <div className="flex justify-end gap-1">
                                  <a
                                    href={releaseHref(r)}
                                    className="inline-flex items-center gap-1 rounded-md border border-emerald-900/60 px-2 py-1 text-xs text-emerald-300 hover:bg-emerald-950/40"
                                  >
                                    Release <ArrowUpRight className="h-3 w-3" />
                                  </a>
                                  <a
                                    href={deleteHref(r)}
                                    className="inline-flex items-center gap-1 rounded-md border border-rose-900/60 px-2 py-1 text-xs text-rose-300 hover:bg-rose-950/40"
                                  >
                                    Delete <ArrowUpRight className="h-3 w-3" />
                                  </a>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {summary.records.length > 100 && (
                      <div className="border-t border-neutral-800 px-4 py-2 text-xs text-neutral-500">
                        Showing 100 of {summary.records.length}. Use the assessment for prioritized actions.
                      </div>
                    )}
                  </section>

                  <p className="flex items-center gap-1.5 text-xs text-neutral-600">
                    <ShieldAlert className="h-3.5 w-3.5" /> Release and delete open in chat for review
                    before anything is applied.
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
