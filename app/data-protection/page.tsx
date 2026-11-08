"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Lock, Play, RotateCcw, ShieldPlus } from "lucide-react";
import AppShell from "@/components/AppShell";
import PageHero from "@/components/PageHero";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";
import { buildPrimerHref } from "@/components/primerHandoff";

type Policy = {
  name?: string;
  platform: string;
  isEnabled: boolean;
  isDefault: boolean;
  precedence?: number;
};
type Posture = {
  policies: Policy[];
  policyCounts: { total: number; enabled: number; disabled: number; enabledNonDefault: number };
  classificationCount: number;
  classifications: string[];
  contentPatternCount: number;
  patternsByCategory: Record<string, number>;
  patternsByRegion: Record<string, number>;
};
type GetResponse = { ok: boolean; scope_pending?: boolean; note?: string; error?: string; posture?: Posture };

function Stat({ label, value, tone = "default" }: { label: string; value: number; tone?: "default" | "emerald" | "amber" }) {
  const t = tone === "emerald" ? "text-emerald-300" : tone === "amber" ? "text-amber-300" : "text-neutral-100";
  return (
    <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-3">
      <div className={`text-2xl font-semibold ${t}`}>{value}</div>
      <div className="mt-0.5 text-xs uppercase tracking-wider text-neutral-500">{label}</div>
    </div>
  );
}

// One declarative sentence + the hand-off target. The playbook
// (extras_data_protection_provision_playbook) owns the workflow; the operator
// supplies the load-bearing input (what to protect) in chat. Primers carry
// context the system prompt can't, not workflow boilerplate.
const PROVISION_PRIMER =
  "Provision Data Protection coverage. Load the playbook with extras_data_protection_provision_playbook and proceed — first ask me what sensitive data to protect and on which platform.";

export default function DataProtectionPage() {
  const router = useRouter();
  const ref = useRef<AgentRunHandle>(null);
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<GetResponse | null>(null);
  const [generated, setGenerated] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/data-protection", { cache: "no-store" });
      setData((await r.json()) as GetResponse);
    } catch {
      setData({ ok: false, error: "Couldn't load Data Protection configuration. Refresh to try again." });
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

  const posture = data?.posture;
  const scopePending = data?.ok && data?.scope_pending;

  return (
    <AppShell title="Data Protection">
      <main className="flex-1 px-6 py-8">
        <div className="mx-auto max-w-5xl space-y-6">
          <PageHero
            icon={Lock}
            eyebrow="Data Protection"
            title="Data exposure posture"
            subtitle="Whether Data Protection is enforcing or just watching, and what's actually firing."
          />

          {loading && (
            <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
              Loading…
            </div>
          )}

          {!loading && scopePending && (
            <div className="rounded-lg border border-amber-900 bg-amber-950/40 px-4 py-3 text-sm text-amber-100">
              <div className="font-semibold">Scope pending</div>
              <div className="mt-1">{data?.note ?? "Data Protection scope is not granted on this tenant."}</div>
              <div className="mt-2 text-amber-200/70">
                Add the <span className="font-mono">Data Protection</span> scope to your Falcon API
                client and this surface lights up automatically.
              </div>
            </div>
          )}

          {!loading && data && !data.ok && (
            <div className="rounded-lg border border-rose-900/60 bg-rose-950/30 px-4 py-3 text-sm text-rose-300">
              {data.error ?? "Something went wrong."}
            </div>
          )}

          {!loading && posture && (
            <>
              <section className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                <Stat label="Policies" value={posture.policyCounts.total} />
                <Stat label="Enabled" value={posture.policyCounts.enabled} tone="emerald" />
                <Stat label="Custom enabled" value={posture.policyCounts.enabledNonDefault} />
                <Stat label="Classifications" value={posture.classificationCount} />
                <Stat label="Content patterns" value={posture.contentPatternCount} />
              </section>

              <section className="rounded-lg border border-neutral-800 bg-neutral-950 p-6 shadow-lg shadow-black/40">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <h2 className="text-lg font-semibold text-white">Assessment</h2>
                    <p className="mt-1 text-sm text-neutral-400">
                      Generate a decision document: is data protection enforcing, monitoring, or dormant — and what&apos;s firing.
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
                      endpoint="/api/data-protection"
                      body={{}}
                      webhookTitle="Data Protection posture"
                      webhookSource="data-protection"
                    />
                  </div>
                )}
              </section>

              <section className="rounded-lg border border-neutral-800 bg-neutral-950 p-6 shadow-lg shadow-black/40">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <h2 className="text-lg font-semibold text-white">Provision coverage</h2>
                    <p className="mt-1 text-sm text-neutral-400">
                      Describe sensitive data to watch for in plain language. The agent drafts and
                      validates the match patterns, then stands up a monitor-first content pattern,
                      classification, and policy — each change approved by you before it lands.
                    </p>
                  </div>
                  <button
                    onClick={() => router.push(buildPrimerHref(PROVISION_PRIMER))}
                    className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-brand-800 bg-brand-900/40 px-4 py-2 text-xs font-medium uppercase tracking-wider text-white hover:border-brand-700 hover:bg-brand-900/60"
                  >
                    <ShieldPlus className="h-3.5 w-3.5" /> Provision coverage
                  </button>
                </div>
              </section>

              {posture.policies.length > 0 && (
                <section className="overflow-hidden rounded-lg border border-neutral-800 bg-neutral-950/60">
                  <div className="border-b border-neutral-800 px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-neutral-400">
                    Policies
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-neutral-800/80 text-left text-xs uppercase tracking-wider text-neutral-500">
                          <th className="px-4 py-2 font-medium">Platform</th>
                          <th className="px-4 py-2 font-medium">Name</th>
                          <th className="px-4 py-2 font-medium">State</th>
                          <th className="px-4 py-2 font-medium">Kind</th>
                          <th className="px-4 py-2 font-medium">Precedence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {posture.policies.map((p, i) => (
                          <tr key={i} className="border-b border-neutral-800/50 last:border-0">
                            <td className="px-4 py-2 text-xs uppercase text-neutral-400">{p.platform}</td>
                            <td className="px-4 py-2 text-neutral-200">{p.name ?? "—"}</td>
                            <td className="px-4 py-2">
                              <span className={`text-xs ${p.isEnabled ? "text-emerald-300" : "text-neutral-500"}`}>
                                {p.isEnabled ? "enabled" : "disabled"}
                              </span>
                            </td>
                            <td className="px-4 py-2 text-xs text-neutral-400">{p.isDefault ? "default" : "custom"}</td>
                            <td className="px-4 py-2 text-xs text-neutral-500">{p.precedence ?? "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}
            </>
          )}
        </div>
      </main>
    </AppShell>
  );
}
