"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Boxes, Play, RotateCcw, ShieldAlert } from "lucide-react";
import AppShell from "@/components/AppShell";
import PageHero from "@/components/PageHero";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";

// Shapes mirror lib/discover/inventory.ts::DiscoverSummary.
type Asset = {
  hostname?: string;
  entityType?: string;
  platform?: string;
  osVersion?: string;
  localIp?: string;
  externalIp?: string;
  lastSeen?: string;
};
type Account = {
  accountName?: string;
  username?: string;
  accountType?: string;
  admin?: boolean;
  lastLogin?: string;
  lastLoginType?: string;
  lastLoginHost?: string;
  passwordLastSet?: string;
};
type Application = {
  name?: string;
  vendor?: string;
  version?: string;
  softwareType?: string;
  suspicious?: boolean;
  hostHostname?: string;
};
type Summary = {
  assets: {
    total: number;
    sampled: number;
    managed: number;
    unmanaged: number;
    byPlatform: Array<{ platform: string; count: number }>;
    stale: Asset[];
    unmanagedList: Asset[];
  };
  accounts: {
    total: number;
    sampled: number;
    privileged: number;
    localAdmins: Account[];
    stalePassword: Account[];
  };
  applications: {
    total: number;
    sampled: number;
    suspicious: Application[];
    byType: Array<{ type: string; count: number }>;
    topVendors: Array<{ vendor: string; count: number }>;
  };
  scopePending: boolean;
  errors: string[];
};
type GetResponse = {
  ok: boolean;
  scope_pending?: boolean;
  note?: string;
  error?: string;
  summary?: Summary;
};

function Stat({
  label,
  value,
  tone = "default",
  sub,
}: {
  label: string;
  value: number;
  tone?: "default" | "amber" | "rose";
  sub?: string;
}) {
  const toneClass =
    tone === "amber" ? "text-amber-300" : tone === "rose" ? "text-rose-300" : "text-neutral-100";
  return (
    <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-3">
      <div className={`text-2xl font-semibold ${toneClass}`}>{value}</div>
      <div className="mt-0.5 text-xs uppercase tracking-wider text-neutral-500">{label}</div>
      {sub && <div className="mt-0.5 text-[11px] text-neutral-600">{sub}</div>}
    </div>
  );
}

function day(ts?: string): string {
  return ts ? ts.slice(0, 10) : "—";
}

export default function DiscoverPage() {
  const ref = useRef<AgentRunHandle>(null);
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<GetResponse | null>(null);
  const [generated, setGenerated] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/discover", { cache: "no-store" });
      setData((await r.json()) as GetResponse);
    } catch {
      setData({ ok: false, error: "Couldn't load inventory. Refresh to try again." });
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

  const summary = data?.summary;
  const scopePending = data?.ok && data?.scope_pending;
  const empty =
    summary &&
    summary.assets.total === 0 &&
    summary.accounts.total === 0 &&
    summary.applications.total === 0;

  return (
    <AppShell title="Discover">
      <main className="flex-1 px-6 py-8">
        <div className="mx-auto max-w-5xl space-y-6">
          <PageHero
            icon={Boxes}
            eyebrow="Discover"
            title="Asset inventory"
            subtitle="Assets, applications, and accounts inventoried across your tenant, surfaced for coverage and hygiene review."
          />

          {loading && (
            <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
              Loading…
            </div>
          )}

          {!loading && scopePending && (
            <div className="rounded-lg border border-amber-900 bg-amber-950/40 px-4 py-3 text-sm text-amber-100">
              <div className="font-semibold">Scope pending</div>
              <div className="mt-1">
                {data?.note ?? "Asset-inventory scope is not granted on this tenant."}
              </div>
              <div className="mt-2 text-amber-200/70">
                Add the asset-inventory (Falcon Discover) scope to your Falcon API client and this
                surface lights up automatically.
              </div>
            </div>
          )}

          {!loading && data && !data.ok && (
            <div className="rounded-lg border border-rose-900/60 bg-rose-950/30 px-4 py-3 text-sm text-rose-300">
              {data.error ?? "Something went wrong."}
            </div>
          )}

          {!loading && summary && !scopePending && (
            <>
              <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <Stat label="Assets" value={summary.assets.total} sub={`${summary.assets.managed} managed`} />
                <Stat label="Unmanaged" value={summary.assets.unmanaged} tone="amber" sub="no Falcon sensor" />
                <Stat label="Admin accounts" value={summary.accounts.privileged} tone="amber" sub={`of ${summary.accounts.total} total`} />
                <Stat label="Suspicious apps" value={summary.applications.suspicious.length} tone="rose" sub={`of ${summary.applications.total} apps`} />
              </section>

              {empty ? (
                <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
                  Falcon Discover has no inventory for this tenant yet.
                </div>
              ) : (
                <>
                  {/* Agentic assessment */}
                  <section className="rounded-lg border border-neutral-800 bg-neutral-950 p-6 shadow-lg shadow-black/40">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <h2 className="text-lg font-semibold text-white">Posture assessment</h2>
                        <p className="mt-1 text-sm text-neutral-400">
                          Generate a decision document: coverage gaps, privileged-account hygiene,
                          and software worth investigating.
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
                          endpoint="/api/discover"
                          body={{}}
                          webhookTitle="Discover posture review"
                          webhookSource="discover"
                        />
                      </div>
                    )}
                  </section>

                  {/* Unmanaged endpoints — coverage gap */}
                  {summary.assets.unmanagedList.length > 0 && (
                    <section className="overflow-hidden rounded-lg border border-amber-900/50 bg-neutral-950/60">
                      <div className="border-b border-amber-900/40 px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-amber-300">
                        Unmanaged endpoints — no Falcon sensor
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-neutral-800/80 text-left text-xs uppercase tracking-wider text-neutral-500">
                              <th className="px-4 py-2 font-medium">Host</th>
                              <th className="px-4 py-2 font-medium">Platform</th>
                              <th className="px-4 py-2 font-medium">IP</th>
                              <th className="px-4 py-2 font-medium">Last seen</th>
                            </tr>
                          </thead>
                          <tbody>
                            {summary.assets.unmanagedList.slice(0, 50).map((a, i) => (
                              <tr key={i} className="border-b border-neutral-800/50 last:border-0">
                                <td className="px-4 py-2 text-neutral-200">{a.hostname ?? "—"}</td>
                                <td className="px-4 py-2 text-xs text-neutral-400">{a.platform ?? "—"}</td>
                                <td className="px-4 py-2 font-mono text-xs text-neutral-400">{a.localIp ?? a.externalIp ?? "—"}</td>
                                <td className="px-4 py-2 text-xs text-neutral-500">{day(a.lastSeen)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  )}

                  {/* Local administrator accounts */}
                  {summary.accounts.localAdmins.length > 0 && (
                    <section className="overflow-hidden rounded-lg border border-neutral-800 bg-neutral-950/60">
                      <div className="border-b border-neutral-800 px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-neutral-400">
                        Local administrator accounts
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-neutral-800/80 text-left text-xs uppercase tracking-wider text-neutral-500">
                              <th className="px-4 py-2 font-medium">Account</th>
                              <th className="px-4 py-2 font-medium">Last login</th>
                              <th className="px-4 py-2 font-medium">Type</th>
                              <th className="px-4 py-2 font-medium">On host</th>
                              <th className="px-4 py-2 font-medium">Password set</th>
                            </tr>
                          </thead>
                          <tbody>
                            {summary.accounts.localAdmins.slice(0, 50).map((a, i) => (
                              <tr key={i} className="border-b border-neutral-800/50 last:border-0">
                                <td className="px-4 py-2 text-neutral-200">{a.accountName ?? a.username ?? "—"}</td>
                                <td className="px-4 py-2 text-xs text-neutral-500">{day(a.lastLogin)}</td>
                                <td className="px-4 py-2 text-xs text-neutral-400">{a.lastLoginType ?? "—"}</td>
                                <td className="px-4 py-2 text-xs text-neutral-400">{a.lastLoginHost ?? "—"}</td>
                                <td className="px-4 py-2 text-xs text-neutral-500">{day(a.passwordLastSet)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  )}

                  {/* Suspicious applications */}
                  {summary.applications.suspicious.length > 0 && (
                    <section className="overflow-hidden rounded-lg border border-rose-900/50 bg-neutral-950/60">
                      <div className="border-b border-rose-900/40 px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-rose-300">
                        Applications flagged suspicious
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-neutral-800/80 text-left text-xs uppercase tracking-wider text-neutral-500">
                              <th className="px-4 py-2 font-medium">Application</th>
                              <th className="px-4 py-2 font-medium">Vendor</th>
                              <th className="px-4 py-2 font-medium">Version</th>
                              <th className="px-4 py-2 font-medium">On host</th>
                            </tr>
                          </thead>
                          <tbody>
                            {summary.applications.suspicious.slice(0, 50).map((a, i) => (
                              <tr key={i} className="border-b border-neutral-800/50 last:border-0">
                                <td className="px-4 py-2 text-neutral-200">{a.name ?? "—"}</td>
                                <td className="px-4 py-2 text-xs text-neutral-400">{a.vendor ?? "—"}</td>
                                <td className="px-4 py-2 font-mono text-xs text-neutral-500">{a.version ?? "—"}</td>
                                <td className="px-4 py-2 text-xs text-neutral-400">{a.hostHostname ?? "—"}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  )}

                  <p className="flex items-center gap-1.5 text-xs text-neutral-600">
                    <ShieldAlert className="h-3.5 w-3.5" /> Counts above are a sampled subset; the
                    assessment reasons over the full tenant totals.
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
