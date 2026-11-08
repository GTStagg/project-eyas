"use client";

import { useEffect, useState } from "react";
import { RefreshCw, AlertTriangle } from "lucide-react";
import QueueTable from "./QueueTable";
import CampaignsPanel from "./CampaignsPanel";
import type { QueueRow } from "@/lib/queue/rank";
import type { Campaign } from "@/lib/queue/campaigns";

type Meta = {
  window_days: number;
  total: number;
  epp: number;
  idp: number;
  top: number;
  active: number;
  stale: number;
  contained_overlay: number;
  campaigns?: number;
};

type Payload =
  | { ok: true; rows: QueueRow[]; campaigns?: Campaign[]; meta: Meta }
  | { ok: false; error: string };

export default function QueueClient({ irEnabled }: { irEnabled: boolean }) {
  const [rows, setRows] = useState<QueueRow[] | null>(null);
  const [campaigns, setCampaigns] = useState<Campaign[] | null>(null);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState<Date | null>(null);

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/api/queue", { cache: "no-store" });
      const j = (await r.json()) as Payload;
      if (!j.ok) throw new Error(j.error);
      setRows(j.rows);
      setCampaigns(j.campaigns ?? []);
      setMeta(j.meta);
      setLoadedAt(new Date());
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
    <div>
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-md border border-neutral-900 bg-neutral-950/60 px-4 py-3">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1 font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-400">
          {meta ? (
            <>
              <span>
                <span className="text-neutral-500">total</span>{" "}
                <span className="text-white">{meta.total}</span>
              </span>
              <span>
                <span className="text-neutral-500">endpoint</span>{" "}
                <span className="text-neutral-200">{meta.epp}</span>
              </span>
              {meta.idp > 0 && (
                <span>
                  <span className="text-neutral-500">identity</span>{" "}
                  <span className="text-teal-300">{meta.idp}</span>
                </span>
              )}
              <span>
                <span className="text-neutral-500">top</span>{" "}
                <span className="text-oxblood-300">{meta.top}</span>
              </span>
              <span>
                <span className="text-neutral-500">active</span>{" "}
                <span className="text-amber-300">{meta.active}</span>
              </span>
              <span>
                <span className="text-neutral-500">stale</span>{" "}
                <span className="text-neutral-300">{meta.stale}</span>
              </span>
              <span>
                <span className="text-neutral-500">contained hosts</span>{" "}
                <span className="text-teal-300">{meta.contained_overlay}</span>
              </span>
              {meta.campaigns !== undefined && meta.campaigns > 0 && (
                <span>
                  <span className="text-neutral-500">campaigns</span>{" "}
                  <span className="text-orange-300">{meta.campaigns}</span>
                </span>
              )}
              <span>
                <span className="text-neutral-500">window</span>{" "}
                <span className="text-neutral-300">{meta.window_days}d</span>
              </span>
            </>
          ) : loading ? (
            <span className="text-neutral-500">loading…</span>
          ) : (
            <span className="text-neutral-500">no data</span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {loadedAt && !loading && (
            <span className="font-mono text-[11px] text-neutral-500">
              loaded {loadedAt.toLocaleTimeString()}
            </span>
          )}
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
      </div>

      {error && (
        <div className="mb-5 flex items-start gap-2 rounded-md border border-red-900 bg-red-950/40 px-4 py-3 font-mono text-xs text-red-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.75} />
          <span>{error}</span>
        </div>
      )}

      {!error && campaigns && campaigns.length > 0 && (
        <CampaignsPanel campaigns={campaigns} />
      )}

      {!error && rows && <QueueTable rows={rows} irEnabled={irEnabled} />}
    </div>
  );
}
