"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, ArrowUpRight, RefreshCw } from "lucide-react";
import HostActionButtons from "@/components/HostActionButtons";

type AtRiskHost = {
  device_id: string;
  hostname: string;
  platform_name?: string;
  os_product_name?: string;
  os_version?: string;
  rtr_state?: string;
  status?: string;
  product_type_desc?: string;
  detection_count_24h: number; // server-side field name, now 72h-window
  highest_severity: number;
  most_recent_detection_ts: string;
};

const SEV_TONE: Record<number, string> = {
  90: "bg-red-900/60 text-red-200 border border-red-800",
  80: "bg-red-900/60 text-red-200 border border-red-800",
  70: "bg-amber-900/60 text-amber-200 border border-amber-800",
  60: "bg-amber-900/60 text-amber-200 border border-amber-800",
  50: "bg-yellow-900/60 text-yellow-200 border border-yellow-800",
};

function sevTone(n: number): string {
  const bucket = Math.floor(n / 10) * 10;
  return (
    SEV_TONE[bucket] ??
    "bg-neutral-800 text-neutral-300 border border-neutral-700"
  );
}

function relativeMinutes(ts: string): string {
  if (!ts) return "—";
  const ms = Date.now() - new Date(ts).getTime();
  if (Number.isNaN(ms)) return "—";
  const min = Math.floor(ms / 60_000);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  return `${hr}h ago`;
}

export default function AtRiskHostsPanel({
  irEnabled,
}: {
  irEnabled: boolean;
}) {
  const [items, setItems] = useState<AtRiskHost[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/api/hosts/at-risk", { cache: "no-store" });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error ?? "request failed");
      setItems(j.items as AtRiskHost[]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  return (
    <section className="mb-8 rounded-lg border border-red-900/40 bg-gradient-to-br from-red-950/20 via-neutral-950 to-neutral-950 p-6 shadow-lg shadow-black/40">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3.5">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-red-900/60 bg-red-950/60 text-oxblood-300">
            <AlertTriangle className="h-5 w-5" strokeWidth={1.75} />
          </div>
          <div>
            <div className="font-mono text-[12px] font-semibold uppercase tracking-[0.14em] text-oxblood-300">
              At-risk // detections in last 72h
            </div>
            <h2 className="mt-1 text-2xl font-semibold tracking-tight text-white">
              {items?.length ?? "…"} host
              {items?.length === 1 ? "" : "s"} with recent detections.
            </h2>
            <p className="mt-1.5 max-w-2xl text-sm text-neutral-400">
              Hosts ranked by highest detection severity in the last 72 hours.
              Click <span className="font-mono text-amber-300">IR</span> to run
              the agentic incident-response workflow on a host.
            </p>
            <div className="mt-3 flex items-center gap-2 text-sm text-neutral-500">
              For detection-level triage, open
              <a
                href="/queue"
                className="inline-flex h-7 items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950 px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-neutral-700 hover:text-white"
              >
                Triage queue
                <ArrowUpRight className="h-3 w-3" strokeWidth={2} />
              </a>
            </div>
          </div>
        </div>
        <button
          onClick={refresh}
          disabled={loading}
          className="flex h-8 shrink-0 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-neutral-700 hover:text-white disabled:opacity-50"
        >
          <RefreshCw
            className={`h-3 w-3 ${loading ? "animate-spin" : ""}`}
            strokeWidth={1.75}
          />
          Refresh
        </button>
      </div>

      {error && (
        <div className="mt-4 rounded-md border border-red-900 bg-red-950/40 px-3 py-2 font-mono text-xs text-red-200">
          {error}
        </div>
      )}

      {!error && items && items.length === 0 && (
        <div className="mt-4 rounded-md border border-dashed border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
          No detections in the last 72 hours. Quiet tenant.
        </div>
      )}

      {!error && items && items.length > 0 && (
        <ul className="mt-4 divide-y divide-neutral-900 rounded-md border border-neutral-900 bg-neutral-950/40">
          {items.map((h) => (
            <li
              key={h.device_id}
              className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
            >
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="truncate font-mono text-sm text-white">
                    {h.hostname}
                  </span>
                  <span
                    className={`rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] ${sevTone(
                      h.highest_severity,
                    )}`}
                  >
                    sev {h.highest_severity}
                  </span>
                  {h.status && h.status !== "normal" && (
                    <span className="rounded border border-red-800 bg-red-900/60 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-red-200">
                      {h.status}
                    </span>
                  )}
                </div>
                <div className="mt-0.5 truncate font-mono text-[11px] text-neutral-500">
                  {h.os_product_name ?? h.os_version ?? h.platform_name ?? "—"}
                  {" · "}
                  {h.detection_count_24h} detection
                  {h.detection_count_24h === 1 ? "" : "s"}
                  {" · last "}
                  {relativeMinutes(h.most_recent_detection_ts)}
                </div>
              </div>
              <HostActionButtons host={h} irEnabled={irEnabled} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
