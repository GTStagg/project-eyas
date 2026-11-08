"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect } from "react";
import { LogOut } from "lucide-react";
import { useNavGating } from "@/lib/hooks/useNavGating";
import BrandMark from "./BrandMark";
import Wordmark from "./Wordmark";
import { BUILT_BY } from "./attribution";

export default function Sidebar({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const pathname = usePathname();
  // Capability gate is shared with the desktop IconRail so the two can never
  // disagree about which surfaces are visible on this tenant.
  const { visibleGroups } = useNavGating();

  // Close on Escape
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  // Close on route change
  useEffect(() => {
    onClose();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathname]);

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        aria-hidden="true"
        className={`fixed inset-0 z-40 bg-black/60 backdrop-blur-sm transition-opacity duration-300 md:hidden ${
          open ? "opacity-100" : "pointer-events-none opacity-0"
        }`}
      />

      {/* Drawer — mobile only; desktop uses the persistent IconRail. */}
      <aside
        aria-label="Navigation menu"
        className={`fixed inset-y-0 left-0 z-50 flex w-72 flex-col border-r border-neutral-800 bg-gradient-to-b from-neutral-950 to-neutral-900 shadow-2xl shadow-black/40 transition-transform duration-300 ease-out md:hidden ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="relative border-b border-neutral-800/80 px-5 py-4">
          <div className="pointer-events-none absolute inset-x-0 -bottom-px h-px bg-gradient-to-r from-transparent via-brand-700/50 to-transparent" />
          <div className="flex items-center gap-2.5">
            <BrandMark size={26} />
            <Wordmark tier="stacked" />
          </div>
          <p className="mt-2 pl-[2.4rem] font-mono text-[11px] uppercase tracking-[0.18em] text-neutral-500">
            Agentic console for Falcon
          </p>
        </div>

        <nav className="flex-1 overflow-y-auto px-3 py-4">
          {visibleGroups.map((group) => (
            <div key={group.label} className="mb-5 last:mb-0">
              <div className="mb-1.5 flex items-center gap-2 px-3 font-mono text-[12px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
                <span className="h-px w-2 bg-neutral-700" />
                {group.label}
              </div>
              <ul className="space-y-0.5">
                {group.items.map((item) => {
                  const active =
                    item.href === "/"
                      ? pathname === "/"
                      : pathname.startsWith(item.href);
                  const Icon = item.icon;
                  return (
                    <li key={item.href}>
                      <Link
                        href={item.href}
                        className={`group relative flex items-center gap-3 rounded-md px-3 py-2 text-[15px] transition-[background-color,color] duration-150 ${
                          active
                            ? "bg-brand-600/12 text-neutral-50 ring-1 ring-inset ring-brand-700/40"
                            : "text-neutral-400 hover:bg-neutral-900/70 hover:text-neutral-100"
                        }`}
                      >
                        {active && (
                          <span className="absolute left-0 top-1/2 h-5 w-[2px] -translate-y-1/2 rounded-r bg-brand-500 shadow-[0_0_10px_-1px_rgba(239,68,68,0.7)]" />
                        )}
                        <Icon
                          className={`h-[1.05em] w-[1.05em] shrink-0 transition-colors ${
                            active
                              ? "text-oxblood-400"
                              : "text-neutral-500 group-hover:text-neutral-300"
                          }`}
                          strokeWidth={2}
                        />
                        <span>{item.label}</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>

        <div className="border-t border-neutral-800/80 px-5 py-3">
          <div className="mb-2 flex items-center justify-between font-mono text-[12px] uppercase tracking-[0.14em] text-neutral-400">
            <span className="inline-flex items-center gap-1.5">
              <span className="live-dot" />
              <span>session live</span>
            </span>
            <span className="text-neutral-600">single-user</span>
          </div>
          <p className="font-mono text-[12px] text-neutral-500">
            Built by {BUILT_BY}
          </p>
          <form action="/api/auth/logout" method="post" className="mt-3">
            <button
              type="submit"
              className="inline-flex items-center gap-1.5 font-mono text-[12px] uppercase tracking-[0.14em] text-neutral-500 transition-colors hover:text-oxblood-300"
            >
              <LogOut className="h-3 w-3" strokeWidth={2} />
              sign out
            </button>
          </form>
        </div>
      </aside>
    </>
  );
}
