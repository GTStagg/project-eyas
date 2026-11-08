"use client";

import { useEffect, useRef, useState } from "react";
import { Search } from "lucide-react";
import HostActionButtons from "@/components/HostActionButtons";
import type { Host } from "@/components/HostsTable";

export default function HostSearchPanel({
  irEnabled,
}: {
  irEnabled: boolean;
}) {
  const [q, setQ] = useState("");
  const [items, setItems] = useState<Host[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    if (!q.trim()) {
      setItems(null);
      setError(null);
      return;
    }
    // Abort the prior in-flight request so a slow earlier query can't resolve
    // after a newer one and overwrite the result the operator is looking at.
    const controller = new AbortController();
    debounceRef.current = setTimeout(async () => {
      setLoading(true);
      setError(null);
      try {
        const r = await fetch(
          `/api/hosts/search?q=${encodeURIComponent(q.trim())}`,
          { cache: "no-store", signal: controller.signal },
        );
        const j = await r.json();
        if (!j.ok) throw new Error(j.error ?? "search failed");
        setItems(j.items as Host[]);
      } catch (err) {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }, 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
      controller.abort();
    };
  }, [q]);

  return (
    <section className="mb-8 rounded-lg border border-neutral-800 bg-neutral-950/60 p-6 shadow-lg shadow-black/40">
      <div className="flex items-start gap-3.5">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-neutral-800 bg-neutral-950 text-neutral-300">
          <Search className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[12px] font-semibold uppercase tracking-[0.14em] text-neutral-300">
            Find a host
          </div>
          <h2 className="mt-1 text-2xl font-semibold tracking-tight text-white">
            Search by hostname.
          </h2>
          <p className="mt-1.5 text-sm text-neutral-400">
            Substring match against hostname; up to 50 results, sorted by last
            seen. Run an audit or IR workflow directly from the result.
          </p>
          <div className="mt-3">
            <input
              type="text"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="e.g. WIN-FOO or jle-win11"
              className="h-10 w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 font-mono text-sm text-neutral-200 placeholder:text-neutral-600 focus:border-neutral-700 focus:outline-none focus:ring-1 focus:ring-neutral-700"
            />
            {loading && (
              <span className="ml-3 font-mono text-[11px] text-neutral-500">
                searching…
              </span>
            )}
          </div>
        </div>
      </div>

      {error && (
        <div className="mt-4 rounded-md border border-red-900 bg-red-950/40 px-3 py-2 font-mono text-xs text-red-200">
          {error}
        </div>
      )}

      {!error && items && items.length === 0 && q.trim() && !loading && (
        <div className="mt-4 rounded-md border border-dashed border-neutral-800 bg-neutral-950/60 px-4 py-4 text-center text-sm text-neutral-500">
          No hosts matched <span className="font-mono">{q.trim()}</span>.
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
                    {h.hostname ?? "?"}
                  </span>
                  {h.status && h.status !== "normal" && (
                    <span className="rounded border border-red-800 bg-red-900/60 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-red-200">
                      {h.status}
                    </span>
                  )}
                </div>
                <div className="mt-0.5 truncate font-mono text-[11px] text-neutral-500">
                  {h.os_product_name ?? h.os_version ?? h.platform_name ?? "—"}
                  {h.last_seen && (
                    <>
                      {" · last seen "}
                      {h.last_seen.slice(0, 10)}
                    </>
                  )}
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
