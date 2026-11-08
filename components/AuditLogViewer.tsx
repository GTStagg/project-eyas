"use client";

import { useCallback, useEffect, useState } from "react";
import { History, RefreshCw, Loader2 } from "lucide-react";

type AuditEntry = {
  ts: string;
  op:
    | "bootstrap"
    | "anthropic_update"
    | "env_create"
    | "env_update"
    | "env_delete"
    | "env_set_active";
  env_id?: string;
  env_name?: string;
  fields_changed?: string[];
  active_id_before?: string;
  active_id_after?: string;
};

const OP_LABEL: Record<AuditEntry["op"], string> = {
  bootstrap: "bootstrap",
  anthropic_update: "anthropic",
  env_create: "env created",
  env_update: "env updated",
  env_delete: "env deleted",
  env_set_active: "env activated",
};

const OP_COLOR: Record<AuditEntry["op"], string> = {
  bootstrap: "border-amber-800/60 bg-amber-950/30 text-amber-200",
  anthropic_update: "border-blue-800/60 bg-blue-950/30 text-blue-200",
  env_create: "border-emerald-800/60 bg-emerald-950/30 text-emerald-200",
  env_update: "border-neutral-700 bg-neutral-900 text-neutral-200",
  env_delete: "border-rose-800/60 bg-rose-950/30 text-rose-200",
  env_set_active: "border-emerald-800/60 bg-emerald-950/30 text-emerald-200",
};

export default function AuditLogViewer({ initial }: { initial: AuditEntry[] }) {
  const [entries, setEntries] = useState<AuditEntry[]>(initial);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    setBusy(true);
    try {
      const r = await fetch("/api/config/audit?limit=200", { cache: "no-store" });
      const j = (await r.json()) as { entries?: AuditEntry[] };
      if (j.entries) setEntries(j.entries);
    } finally {
      setBusy(false);
    }
  }, []);

  // Auto-refresh every 30s while the tab is visible.
  useEffect(() => {
    const id = setInterval(() => {
      if (typeof document !== "undefined" && !document.hidden) refresh();
    }, 30_000);
    return () => clearInterval(id);
  }, [refresh]);

  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
      <div className="flex items-start gap-4">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
          <History className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div className="flex-1">
          <div className="text-xs font-semibold uppercase tracking-[0.14em] text-oxblood-400">
            Activity
          </div>
          <h2 className="mt-1.5 text-2xl font-semibold tracking-tight text-white">
            Recent setting changes
          </h2>
          <p className="mt-1.5 text-sm text-neutral-400">
            A timeline of every change to your connections. Only the names
            of the fields that changed are recorded — secret values never
            appear here. Refreshes automatically.
          </p>
        </div>
        <button
          type="button"
          onClick={refresh}
          disabled={busy}
          className="flex h-9 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-900 px-3 font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-200 transition-colors hover:border-brand-700/60 hover:bg-neutral-800 hover:text-oxblood-200 disabled:opacity-50"
        >
          {busy ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" strokeWidth={2} />
          ) : (
            <RefreshCw className="h-3.5 w-3.5" strokeWidth={2} />
          )}
          Refresh
        </button>
      </div>

      {entries.length === 0 ? (
        <div className="mt-6 rounded-md border border-neutral-800 bg-neutral-900/40 px-4 py-6 text-center text-sm text-neutral-500">
          No activity yet. Changes you save will appear here.
        </div>
      ) : (
        <div className="mt-6 divide-y divide-neutral-800 rounded-md border border-neutral-800">
          {entries.map((e, i) => (
            <div key={`${e.ts}-${i}`} className="flex flex-wrap items-start gap-3 px-4 py-3">
              <div className="font-mono text-[11px] uppercase tracking-wider text-neutral-500">
                <Timestamp iso={e.ts} />
              </div>
              <span
                className={`rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider ${OP_COLOR[e.op]}`}
              >
                {OP_LABEL[e.op]}
              </span>
              <div className="min-w-0 flex-1 font-mono text-[12px] text-neutral-300">
                {e.env_name && (
                  <span className="text-neutral-100">{e.env_name}</span>
                )}
                {e.env_name && e.env_id && (
                  <span className="ml-2 text-neutral-500">[{e.env_id}]</span>
                )}
                {e.fields_changed && e.fields_changed.length > 0 && (
                  <div className="mt-1 flex flex-wrap gap-1">
                    {e.fields_changed.map((f) => (
                      <span
                        key={f}
                        className="rounded bg-neutral-900 px-1.5 py-0.5 text-[11px] text-neutral-400"
                      >
                        {f}
                      </span>
                    ))}
                  </div>
                )}
                {e.active_id_before && e.active_id_after && (
                  <div className="mt-1 text-[11px] text-neutral-500">
                    {e.active_id_before} → {e.active_id_after}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Timestamp display that avoids SSR/CSR hydration mismatch. Server
// renders in server timezone (UTC), client renders in the browser's
// local timezone — feeding the same ISO string to toLocaleString in
// both places produces different markup and React errors.
//
// Two-phase render: initial pass returns the deterministic ISO string
// (matches between server + client first paint); a useEffect after
// mount swaps it for the operator's local-time formatted version.
function Timestamp({ iso }: { iso: string }) {
  const [local, setLocal] = useState<string | null>(null);
  useEffect(() => {
    try {
      const d = new Date(iso);
      setLocal(
        d.toLocaleString(undefined, {
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
      );
    } catch {
      setLocal(iso);
    }
  }, [iso]);
  // suppressHydrationWarning is a defense-in-depth: the timestamp text
  // ALSO matches between server and client on first paint (both serve
  // the raw ISO), but if a future change introduces a mismatch the
  // warning would land here rather than at the broader entry level.
  return <span suppressHydrationWarning>{local ?? iso}</span>;
}
