"use client";

import { useEffect, useState } from "react";
import { ChevronDown, ChevronRight, Layers, RefreshCw } from "lucide-react";
import HostsTable, { type Host } from "@/components/HostsTable";

type GroupSummary = {
  id: string;
  name: string;
  group_type?: string;
  description?: string;
};

export default function HostsTablePanel() {
  const [groups, setGroups] = useState<GroupSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadGroups = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/api/hosts/groups/list", { cache: "no-store" });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error ?? "load failed");
      setGroups(j.items as GroupSummary[]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadGroups();
  }, []);

  return (
    <section className="mt-8 rounded-lg border border-neutral-900 bg-neutral-950/40 shadow-lg shadow-black/40">
      <div className="flex items-center justify-between gap-3 px-6 py-4">
        <div className="flex items-center gap-2.5">
          <Layers className="h-4 w-4 text-neutral-400" strokeWidth={1.75} />
          <span className="font-mono text-[12px] font-semibold uppercase tracking-[0.14em] text-neutral-300">
            Hosts by group
          </span>
          {groups && (
            <span className="font-mono text-[11px] text-neutral-500">
              {groups.length} group{groups.length === 1 ? "" : "s"}
            </span>
          )}
        </div>
        <button
          onClick={loadGroups}
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

      <div className="border-t border-neutral-900 px-6 pb-6">
        {error && (
          <div className="mt-4 rounded-md border border-red-900 bg-red-950/40 px-3 py-2 font-mono text-xs text-red-200">
            {error}
          </div>
        )}

        {!error && groups && groups.length === 0 && (
          <div className="mt-4 rounded-md border border-dashed border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
            No host groups defined in this tenant.
          </div>
        )}

        {!error && groups && groups.length > 0 && (
          <ul className="mt-4 space-y-2">
            {groups.map((g) => (
              <GroupRow key={g.id} group={g} />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function GroupRow({ group }: { group: GroupSummary }) {
  const [open, setOpen] = useState(false);
  const [members, setMembers] = useState<Host[] | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(
        `/api/hosts/groups/members?group_id=${encodeURIComponent(group.id)}`,
        { cache: "no-store" },
      );
      const j = await r.json();
      if (!j.ok) throw new Error(j.error ?? "load failed");
      setMembers(j.items as Host[]);
      setTruncated(!!j.truncated);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = () => {
    const next = !open;
    setOpen(next);
    if (next && members === null) void load();
  };

  return (
    <li className="rounded-md border border-neutral-900 bg-neutral-950/60">
      <button
        onClick={handleToggle}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition hover:bg-neutral-900/50"
      >
        <div className="flex min-w-0 items-center gap-2.5">
          {open ? (
            <ChevronDown
              className="h-4 w-4 shrink-0 text-neutral-400"
              strokeWidth={1.75}
            />
          ) : (
            <ChevronRight
              className="h-4 w-4 shrink-0 text-neutral-400"
              strokeWidth={1.75}
            />
          )}
          <span className="truncate font-medium text-neutral-100">
            {group.name}
          </span>
          {group.group_type && (
            <span className="rounded border border-neutral-800 bg-neutral-950 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-400">
              {group.group_type}
            </span>
          )}
          {members && (
            <span className="font-mono text-[11px] text-neutral-500">
              {members.length}
              {truncated ? "+" : ""} host{members.length === 1 ? "" : "s"}
            </span>
          )}
        </div>
        <span className="font-mono text-[11px] text-neutral-500">
          {!open && members === null && "click to expand"}
          {open && loading && "loading…"}
        </span>
      </button>

      {open && (
        <div className="border-t border-neutral-900 px-4 pb-4 pt-3">
          {error && (
            <div className="rounded-md border border-red-900 bg-red-950/40 px-3 py-2 font-mono text-xs text-red-200">
              {error}
            </div>
          )}

          {!error && members && members.length === 0 && (
            <div className="rounded-md border border-dashed border-neutral-800 bg-neutral-950/60 px-4 py-4 text-center text-sm text-neutral-500">
              No hosts in this group.
            </div>
          )}

          {!error && members && members.length > 0 && (
            <>
              {truncated && (
                <div className="mb-2 rounded-md border border-amber-900/60 bg-amber-950/30 px-3 py-1.5 text-xs text-amber-300">
                  Showing the first {members.length} hosts — this group has more.
                </div>
              )}
              <HostsTable items={members} />
            </>
          )}
        </div>
      )}
    </li>
  );
}
