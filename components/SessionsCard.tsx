"use client";

import { useEffect, useState } from "react";
import { MessagesSquare } from "lucide-react";

type Stats = {
  sessionCount: number;
  totalMessages: number;
  oldestIdleMs: number | null;
};

function formatIdle(ms: number | null): string {
  if (ms === null) return "—";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  const rem = m % 60;
  return rem ? `${h}h ${rem}m` : `${h}h`;
}

export default function SessionsCard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function refresh() {
    try {
      const r = await fetch("/api/sessions", { cache: "no-store" });
      if (r.ok) setStats(await r.json());
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 30_000);
    return () => clearInterval(t);
  }, []);

  async function clearAll() {
    if (!confirm("Clear all in-memory chat sessions on this server? Active browsers will start fresh on their next message.")) return;
    setBusy(true);
    setMsg(null);
    try {
      const r = await fetch("/api/sessions", { method: "DELETE" });
      const data = await r.json();
      setMsg(`Cleared ${data.cleared} session${data.cleared === 1 ? "" : "s"}.`);
      await refresh();
    } catch (e) {
      setMsg(`Error: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
      <div className="flex items-start gap-4">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
          <MessagesSquare className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div className="flex-1">
          <div className="text-xs font-semibold uppercase tracking-[0.14em] text-oxblood-400">
            Sessions
          </div>
          <h1 className="mt-1.5 text-3xl font-semibold tracking-tight text-white">Chat memory</h1>
          <p className="mt-1.5 text-base text-neutral-400">
            In-memory conversation history per <code className="font-mono text-neutral-200">sessionId</code>. Idle sessions evict after 1 hour.
          </p>
        </div>
      </div>

      <div className="mt-6 grid grid-cols-3 gap-3">
        <Stat label="Active sessions" value={stats ? String(stats.sessionCount) : "—"} />
        <Stat label="Total messages" value={stats ? String(stats.totalMessages) : "—"} />
        <Stat label="Oldest idle" value={stats ? formatIdle(stats.oldestIdleMs) : "—"} />
      </div>

      <div className="mt-6 flex items-center gap-3">
        <button
          onClick={clearAll}
          disabled={busy || (stats?.sessionCount ?? 0) === 0}
          className="rounded-lg border border-red-900/60 bg-red-950/30 px-4 py-2 text-sm font-medium text-oxblood-300 transition-colors hover:bg-red-950/50 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? "Clearing…" : "Clear all sessions"}
        </button>
        {msg && <span className="text-xs text-neutral-400">{msg}</span>}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950/60 px-4 py-3">
      <div className="text-[11px] font-semibold uppercase tracking-[0.10em] text-neutral-500">
        {label}
      </div>
      <div className="mt-1 font-mono text-lg text-neutral-100">{value}</div>
    </div>
  );
}
