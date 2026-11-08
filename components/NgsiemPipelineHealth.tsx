"use client";

import { useEffect, useState } from "react";
import { Database, Filter, Table } from "lucide-react";

type ConnectionItem = {
  id?: string;
  name?: string;
  status?: string;
  enabled?: boolean;
  last_event_at?: string | null;
};

type ToolPayload<T> = {
  ok?: boolean;
  scope_pending?: boolean;
  error?: string;
  count?: number;
  items?: T[];
  status_counts?: Record<string, number>;
} | null;

type Pipeline = {
  ok: boolean;
  error?: string;
  connections: ToolPayload<ConnectionItem>;
  lookupFiles: ToolPayload<unknown>;
  parsers: ToolPayload<unknown>;
};

type StatusTone = "green" | "amber" | "red" | "neutral";

function tone(status: StatusTone): string {
  switch (status) {
    case "green":
      return "border-emerald-800 bg-emerald-950/30 text-emerald-300";
    case "amber":
      return "border-amber-800 bg-amber-950/30 text-amber-300";
    case "red":
      return "border-rose-800 bg-rose-950/30 text-rose-300";
    default:
      return "border-neutral-800 bg-neutral-950 text-neutral-300";
  }
}

type CellState = { tone: StatusTone; label: string; detail?: string };

function connectionsTone(p: ToolPayload<ConnectionItem>): CellState {
  if (!p) return { tone: "neutral", label: "—" };
  if (p.scope_pending) return { tone: "amber", label: "scope pending" };
  if (p.ok === false) return { tone: "red", label: "error", detail: p.error };
  const counts = p.status_counts ?? {};
  const total = p.count ?? 0;
  if (total === 0) return { tone: "amber", label: "0 connections" };
  // NGSIEM API status values are Active / Idle / Pending (lowercased by
  // the rollup). Idle is not an error — connection exists but didn't
  // ingest recently. Pending is mid-provisioning.
  const errored =
    (counts.error ?? 0) + (counts.failed ?? 0) + (counts.unhealthy ?? 0);
  const active = counts.active ?? 0;
  if (errored > 0)
    return { tone: "red", label: `${errored} errored / ${total} total` };
  if (active > 0) return { tone: "green", label: `${active} / ${total} active` };
  return { tone: "neutral", label: `${total} connection${total === 1 ? "" : "s"}` };
}

function simpleCount(p: ToolPayload<unknown>): CellState {
  if (!p) return { tone: "neutral", label: "—" };
  if (p.scope_pending) return { tone: "amber", label: "scope pending" };
  if (p.ok === false) return { tone: "red", label: "error", detail: p.error };
  const c = p.count ?? 0;
  return {
    tone: c > 0 ? "green" : "amber",
    label: `${c}`,
  };
}

export default function NgsiemPipelineHealth() {
  const [data, setData] = useState<Pipeline | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/ngsiem-pipeline")
      .then(async (r) => {
        const j = await r.json().catch(() => null);
        if (cancelled) return;
        if (!r.ok || !j) {
          setError(j?.error ?? `HTTP ${r.status}`);
          return;
        }
        setData(j as Pipeline);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <div className="border border-neutral-800 bg-neutral-950 px-4 py-3 text-xs text-neutral-500">
        Loading NGSIEM pipeline health…
      </div>
    );
  }
  if (error || !data) {
    return (
      <div className={`border px-4 py-3 text-xs ${tone("red")}`}>
        Pipeline health unavailable — {error ?? "no data"}
      </div>
    );
  }

  const cells: {
    icon: typeof Database;
    label: string;
    value: CellState;
  }[] = [
    {
      icon: Database,
      label: "Connections",
      value: connectionsTone(data.connections),
    },
    { icon: Filter, label: "Parsers", value: simpleCount(data.parsers) },
    { icon: Table, label: "Lookups", value: simpleCount(data.lookupFiles) },
  ];

  return (
    <div className="border border-neutral-800 bg-neutral-950">
      <div className="border-b border-neutral-800 bg-neutral-950 px-4 py-2 font-mono text-[10px] uppercase tracking-[0.18em] text-neutral-500">
        Pipeline health
      </div>
      <div className="grid grid-cols-3 divide-neutral-800 sm:divide-x">
        {cells.map(({ icon: Icon, label, value }) => (
          <div key={label} className="flex items-start gap-3 px-4 py-3">
            <Icon className="mt-0.5 h-4 w-4 shrink-0 text-neutral-500" strokeWidth={1.5} />
            <div className="min-w-0">
              <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-neutral-500">
                {label}
              </div>
              <div
                className={`mt-1 inline-flex items-center border px-2 py-0.5 font-mono text-[11px] ${tone(value.tone)}`}
                title={value.detail}
              >
                {value.label}
              </div>
              {value.detail ? (
                <div
                  className="mt-1 max-w-[28rem] break-words font-mono text-[10px] leading-tight text-rose-300/70"
                  title={value.detail}
                >
                  {value.detail}
                </div>
              ) : null}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
