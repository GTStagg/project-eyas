"use client";

import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import AppShell from "@/components/AppShell";
import PageHero from "@/components/PageHero";

type Settings = Record<string, string | boolean | undefined>;

type Policy = {
  id: string;
  name: string;
  platform: string;
  enabled: boolean;
  description?: string;
  groups?: { id: string; name: string }[];
  settings: Settings;
  flags: string[];
};

type PostureResp = {
  ok: boolean;
  scope_pending?: boolean;
  note?: string;
  error?: string;
  items?: Policy[];
  count?: number;
  platform_counts?: Record<string, number>;
  summary?: { total: number; disabled: number; detect_only: number };
};

const FLAG_LABEL: Record<string, string> = {
  disabled: "Disabled",
  ml_detect_only: "ML detect-only",
  cloud_av_detect_only: "Cloud AV detect-only",
};

const FLAG_TONE: Record<string, string> = {
  disabled: "border-red-800/60 bg-red-950/40 text-red-200",
  ml_detect_only: "border-amber-800/60 bg-amber-950/40 text-amber-200",
  cloud_av_detect_only: "border-amber-800/60 bg-amber-950/40 text-amber-200",
};

export default function PreventionPage() {
  const [data, setData] = useState<PostureResp | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/prevention-policies", { cache: "no-store" })
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
    <AppShell title="Prevention policies">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up space-y-8">
          <PageHero
            icon={ShieldCheck}
            eyebrow="Prevention policies"
            title="Prevention coverage across every policy."
            subtitle="Anything in detect-only or disabled is flagged."
          />

          {loading && (
            <div className="border border-dashed border-neutral-800 bg-neutral-950/60 p-8 text-center text-neutral-400">
              Loading prevention policy posture…
            </div>
          )}

          {!loading && data && !data.ok && (
            <div className="rounded-lg border border-red-900 bg-red-950/40 px-4 py-3 text-sm text-red-200">
              <div className="font-semibold">Failed to load prevention policies</div>
              <div className="mt-1 font-mono text-xs">{data.error}</div>
            </div>
          )}

          {!loading && data?.ok && data.scope_pending && (
            <div className="rounded-lg border border-amber-900 bg-amber-950/40 px-4 py-3 text-sm text-amber-100">
              <div className="font-semibold">Scope pending</div>
              <div className="mt-1">
                {data.note ?? "Prevention Policies API scope is not granted on this tenant."}
              </div>
              <div className="mt-2 text-amber-200/70">
                Add the <span className="font-mono">Prevention Policies (Read)</span> scope to your Falcon API client and the surface lights up automatically.
              </div>
            </div>
          )}

          {!loading && data?.ok && !data.scope_pending && data.items && (
            <>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <SummaryTile label="Total policies" value={data.summary?.total ?? data.items.length} />
                <SummaryTile
                  label="Detect-only"
                  value={data.summary?.detect_only ?? 0}
                  tone={data.summary?.detect_only ? "warn" : "neutral"}
                />
                <SummaryTile
                  label="Disabled"
                  value={data.summary?.disabled ?? 0}
                  tone={data.summary?.disabled ? "danger" : "neutral"}
                />
              </div>

              {data.platform_counts && Object.keys(data.platform_counts).length > 0 && (
                <div className="flex flex-wrap items-center gap-2 text-sm text-neutral-400">
                  <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-neutral-500">
                    by platform:
                  </span>
                  {Object.entries(data.platform_counts).map(([platform, count]) => (
                    <span
                      key={platform}
                      className="rounded-sm border border-neutral-800 bg-neutral-950 px-2 py-0.5 font-mono text-[11px] uppercase tracking-[0.1em] text-neutral-300"
                    >
                      {platform} · {count}
                    </span>
                  ))}
                </div>
              )}

              <div className="overflow-hidden rounded-md border border-neutral-800 bg-neutral-950">
                <table className="w-full text-left">
                  <thead className="border-b border-neutral-800 bg-neutral-950/80 text-[11px] uppercase tracking-[0.14em] text-neutral-500">
                    <tr>
                      <th className="px-4 py-2 font-mono">Policy</th>
                      <th className="px-4 py-2 font-mono">Platform</th>
                      <th className="px-4 py-2 font-mono">Posture flags</th>
                      <th className="px-4 py-2 font-mono">ML det/prev</th>
                      <th className="px-4 py-2 font-mono">Cloud AV det/prev</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((p) => (
                      <tr key={p.id} className="border-b border-neutral-900 last:border-b-0 hover:bg-neutral-900/40">
                        <td className="px-4 py-2.5">
                          <div className="text-sm font-semibold text-neutral-100">{p.name}</div>
                          {p.description && (
                            <div className="mt-0.5 text-[12px] text-neutral-500">
                              {p.description}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-[12px] text-neutral-400">
                          {p.platform}
                        </td>
                        <td className="px-4 py-2.5">
                          {p.flags.length === 0 ? (
                            <span className="font-mono text-[11px] uppercase tracking-[0.1em] text-emerald-400/80">
                              ok
                            </span>
                          ) : (
                            <div className="flex flex-wrap gap-1">
                              {p.flags.map((f) => (
                                <span
                                  key={f}
                                  className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.1em] ${
                                    FLAG_TONE[f] ?? "border-neutral-700 bg-neutral-900 text-neutral-300"
                                  }`}
                                >
                                  {FLAG_LABEL[f] ?? f}
                                </span>
                              ))}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-[12px] text-neutral-400">
                          {p.settings.ml_detection ?? "—"} / {p.settings.ml_prevention ?? "—"}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-[12px] text-neutral-400">
                          {p.settings.cloud_anti_malware_detection ?? "—"} /{" "}
                          {p.settings.cloud_anti_malware_prevention ?? "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
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
      <div className={`mt-1 text-2xl font-bold tracking-tight ${valueColor}`}>
        {value}
      </div>
    </div>
  );
}
