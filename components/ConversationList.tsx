"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Plus, Trash2, ShieldAlert, X, Search } from "lucide-react";
import SessionTtlPill from "./SessionTtlPill";

// claude.ai-style conversation drawer for /chat. Lists prior conversations
// (newest first by lastTouched), highlights the active one, surfaces a per-row
// TTL pill, and exposes resume / delete / new-chat. Mounts in Chat.tsx as a
// pop-out overlay at every breakpoint — the parent owns open/close state and
// renders the trigger button in the AppShell header.
//
// State responsibilities:
//   - Conversation rows: owned here, fetched from /api/chat/sessions.
//   - Active session id: owned by the parent (Chat.tsx) because it also
//     drives the message stream — we accept it as a prop.
//   - Resume / new chat: surfaced as callbacks; the parent does the actual
//     turn-list swap (we don't know how to render messages).

export type ConversationSummary = {
  id: string;
  title: string | null;
  createdAt: number;
  lastTouched: number;
  turnCount: number;
  expiresAt: number;
  irActive: boolean;
};

type Props = {
  activeSessionId: string;
  onResume: (id: string) => void;
  onNewChat: () => void;
  /** Bump this counter from the parent (Chat.tsx) any time a turn finishes
   *  so the rail re-fetches and the row's `lastTouched` / `turnCount` move. */
  refreshTick: number;
  /** Drawer open state — owned by the parent so the trigger button can live
   *  next to the New Chat button in the AppShell header rather than floating
   *  over the rail. */
  open: boolean;
  onClose: () => void;
};

function placeholderTitle(s: ConversationSummary): string {
  if (s.title) return s.title;
  return `Chat — ${new Date(s.createdAt).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  })}`;
}

// Relative-day bucket for grouping the rail. With the 72h idle TTL the only
// buckets that ever appear are Today / Yesterday / Earlier.
const BUCKET_ORDER = ["Today", "Yesterday", "Earlier"] as const;
function dayBucket(ts: number, now: number): (typeof BUCKET_ORDER)[number] {
  const startOfToday = new Date(now);
  startOfToday.setHours(0, 0, 0, 0);
  const t0 = startOfToday.getTime();
  if (ts >= t0) return "Today";
  if (ts >= t0 - 86_400_000) return "Yesterday";
  return "Earlier";
}

export default function ConversationList({
  activeSessionId,
  onResume,
  onNewChat,
  refreshTick,
  open,
  onClose,
}: Props) {
  const [sessions, setSessions] = useState<ConversationSummary[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [query, setQuery] = useState("");

  const fetchSessions = useCallback(async () => {
    try {
      const r = await fetch("/api/chat/sessions");
      if (!r.ok) return;
      const j = (await r.json()) as { ok: boolean; sessions?: ConversationSummary[] };
      if (j.ok && Array.isArray(j.sessions)) setSessions(j.sessions);
    } catch {
      /* network blip — keep the last known list */
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    fetchSessions();
  }, [fetchSessions, refreshTick]);

  const deleteOne = useCallback(
    async (id: string, e: React.MouseEvent) => {
      e.stopPropagation();
      // Optimistic: drop locally first so the click feels instant.
      setSessions((prev) => prev.filter((s) => s.id !== id));
      try {
        await fetch(`/api/chat/sessions/${encodeURIComponent(id)}`, { method: "DELETE" });
      } catch {
        // Re-fetch to recover the row if the server rejected.
        fetchSessions();
      }
      // Deleting the active conversation? Tell the parent to start fresh.
      if (id === activeSessionId) onNewChat();
    },
    [activeSessionId, fetchSessions, onNewChat],
  );

  const handleResume = useCallback(
    (id: string) => {
      onResume(id);
      onClose();
    },
    [onResume, onClose],
  );

  const handleNewChat = useCallback(() => {
    onNewChat();
    onClose();
  }, [onNewChat, onClose]);

  // Filter by title, then group by relative day so a long history stays
  // scannable. sessions arrive newest-first; grouping preserves that order.
  const groups = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = q
      ? sessions.filter((s) => placeholderTitle(s).toLowerCase().includes(q))
      : sessions;
    const now = Date.now();
    const byBucket = new Map<string, ConversationSummary[]>();
    for (const s of filtered) {
      const b = dayBucket(s.lastTouched, now);
      const arr = byBucket.get(b) ?? [];
      arr.push(s);
      byBucket.set(b, arr);
    }
    return BUCKET_ORDER.map((label) => ({ label, items: byBucket.get(label) ?? [] })).filter(
      (g) => g.items.length > 0,
    );
  }, [sessions, query]);

  const matchCount = groups.reduce((n, g) => n + g.items.length, 0);

  const renderRow = (s: ConversationSummary) => {
    const active = s.id === activeSessionId;
    return (
      <li key={s.id}>
        <button
          type="button"
          onClick={() => handleResume(s.id)}
          className={`group flex w-full flex-col gap-1 px-3 py-2.5 text-left transition-colors ${
            active ? "bg-brand-950/30" : "hover:bg-neutral-900/60"
          }`}
        >
          <div className="flex items-start justify-between gap-2">
            <span
              className={`flex-1 truncate text-[13px] ${
                active ? "text-oxblood-200" : "text-neutral-200"
              }`}
              title={placeholderTitle(s)}
            >
              {placeholderTitle(s)}
            </span>
            <span
              onClick={(e) => deleteOne(s.id, e)}
              role="button"
              tabIndex={-1}
              title="Delete this conversation"
              className="shrink-0 rounded p-0.5 text-neutral-600 opacity-0 transition-opacity hover:bg-neutral-900 hover:text-oxblood-300 group-hover:opacity-100"
            >
              <Trash2 className="h-3.5 w-3.5" strokeWidth={2} />
            </span>
          </div>
          <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-500">
            <span>
              {s.turnCount} {s.turnCount === 1 ? "turn" : "turns"}
            </span>
            <span>·</span>
            <SessionTtlPill expiresAt={s.expiresAt} variant="row" />
            {s.irActive && (
              <span
                className="inline-flex items-center gap-0.5 rounded border border-amber-800/60 bg-amber-950/40 px-1 text-amber-200"
                title="IR mode is active on this conversation"
              >
                <ShieldAlert className="h-2.5 w-2.5" strokeWidth={2.5} />
                IR
              </span>
            )}
          </div>
        </button>
      </li>
    );
  };

  const railBody = (
    <>
      <div className="flex items-center justify-between border-b border-neutral-800 px-3 py-3">
        <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-neutral-500">
          Conversations
        </span>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={handleNewChat}
            title="Start a new chat"
            className="flex h-7 items-center gap-1 rounded border border-neutral-800 bg-neutral-950/40 px-2 font-mono text-[10px] uppercase tracking-[0.14em] text-neutral-400 hover:border-brand-700/60 hover:bg-neutral-900 hover:text-oxblood-200"
          >
            <Plus className="h-3 w-3" strokeWidth={2.5} />
            New
          </button>
          <button
            type="button"
            onClick={onClose}
            title="Close conversations"
            className="flex h-7 w-7 items-center justify-center rounded border border-neutral-800 bg-neutral-950/40 text-neutral-400 hover:border-neutral-700 hover:text-neutral-200"
          >
            <X className="h-3.5 w-3.5" strokeWidth={2} />
          </button>
        </div>
      </div>
      {/* Search — only worth showing once there are enough rows to hunt through. */}
      {sessions.length > 6 && (
        <div className="border-b border-neutral-900 px-3 py-2">
          <div className="flex items-center gap-2 rounded border border-neutral-800 bg-neutral-950/60 px-2 focus-within:border-brand-700/60">
            <Search className="h-3.5 w-3.5 shrink-0 text-neutral-600" strokeWidth={2} />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter conversations…"
              className="h-7 w-full bg-transparent text-[12px] text-neutral-200 placeholder:text-neutral-600 focus:outline-none"
            />
            {query && (
              <button
                type="button"
                onClick={() => setQuery("")}
                title="Clear filter"
                className="shrink-0 text-neutral-600 hover:text-neutral-300"
              >
                <X className="h-3 w-3" strokeWidth={2} />
              </button>
            )}
          </div>
        </div>
      )}
      <div className="flex-1 overflow-y-auto">
        {loaded && sessions.length === 0 && (
          <p className="px-3 py-3 font-mono text-[11px] text-neutral-600">
            No prior chats.
          </p>
        )}
        {loaded && sessions.length > 0 && matchCount === 0 && (
          <p className="px-3 py-3 font-mono text-[11px] text-neutral-600">
            No conversations match &ldquo;{query}&rdquo;.
          </p>
        )}
        {groups.map((g) => (
          <div key={g.label}>
            <div className="sticky top-0 z-10 bg-neutral-950/90 px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-neutral-600 backdrop-blur-sm">
              {g.label}
            </div>
            <ul className="divide-y divide-neutral-900">{g.items.map(renderRow)}</ul>
          </div>
        ))}
      </div>
    </>
  );

  // Pop-out drawer at every breakpoint — overlays the chat rather than
  // occupying a persistent column, so the conversation surface stays bare
  // until the operator asks for history.
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex" role="dialog" aria-modal="true">
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
      />
      <aside className="relative z-50 flex w-72 max-w-[85vw] flex-col border-r border-neutral-800 bg-neutral-950 shadow-xl">
        {railBody}
      </aside>
    </div>
  );
}
