"use client";

import { useEffect, useState } from "react";
import { Lock, RefreshCw } from "lucide-react";
import HostActionButtons from "@/components/HostActionButtons";

type ContainedHost = {
  device_id?: string;
  hostname?: string;
  platform_name?: string;
  os_product_name?: string;
  os_version?: string;
  rtr_state?: string;
  status?: string;
  last_seen?: string;
};

export default function ContainedHostsPanel({
  irEnabled,
}: {
  irEnabled: boolean;
}) {
  const [items, setItems] = useState<ContainedHost[] | null>(null);
  const [extrasDisabled, setExtrasDisabled] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/api/hosts/contained", { cache: "no-store" });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error ?? "request failed");
      setExtrasDisabled(Boolean(j.extras_disabled));
      setItems(j.items as ContainedHost[]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  if (extrasDisabled) {
    return null;
  }

  return (
    <section className="mb-8 rounded-lg border border-teal-900/40 bg-gradient-to-br from-teal-950/20 via-neutral-950 to-neutral-950 p-6 shadow-lg shadow-black/40">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3.5">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-teal-900/60 bg-teal-950/60 text-teal-300">
            <Lock className="h-5 w-5" strokeWidth={1.75} />
          </div>
          <div>
            <div className="font-mono text-[12px] font-semibold uppercase tracking-[0.14em] text-teal-300">
              Network contained
            </div>
            <h2 className="mt-1 text-2xl font-semibold tracking-tight text-white">
              {items?.length ?? "…"} host
              {items?.length === 1 ? "" : "s"} currently isolated.
            </h2>
            <p className="mt-1.5 max-w-2xl text-sm text-neutral-400">
              Hosts with active or pending network containment. Telemetry
              continues; all other comms blocked. Run{" "}
              <span className="font-mono text-amber-300">IR</span> to walk a
              host through cleanup → verification → release; the IR workflow
              lifts containment when verified clean.
            </p>
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
          No hosts are currently contained.
        </div>
      )}

      {!error && items && items.length > 0 && (
        <ul className="mt-4 divide-y divide-neutral-900 rounded-md border border-neutral-900 bg-neutral-950/40">
          {items.map((h) => (
            <li
              key={h.device_id ?? h.hostname}
              className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
            >
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="truncate font-mono text-sm text-white">
                    {h.hostname ?? h.device_id ?? "?"}
                  </span>
                  {h.status && (
                    <span className="rounded border border-teal-800 bg-teal-900/60 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-teal-200">
                      {h.status}
                    </span>
                  )}
                </div>
                <div className="mt-0.5 truncate font-mono text-[11px] text-neutral-500">
                  {h.os_product_name ?? h.os_version ?? h.platform_name ?? "—"}
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
