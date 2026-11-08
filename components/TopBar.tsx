"use client";

import { Menu, X, MessageSquare } from "lucide-react";
import ThemeToggle from "./ThemeToggle";
import EnvironmentSwitcher from "./EnvironmentSwitcher";
import { useChatDock } from "./ChatDock";

export default function TopBar({
  sidebarOpen,
  onMenuClick,
  title,
  right,
}: {
  sidebarOpen: boolean;
  onMenuClick: () => void;
  title?: string;
  right?: React.ReactNode;
}) {
  const chat = useChatDock();
  return (
    <header className="sticky top-0 z-30 shrink-0 border-b border-neutral-800/80 bg-neutral-950/70 backdrop-blur-xl">
      <div className="pointer-events-none absolute inset-x-0 -bottom-px h-px bg-gradient-to-r from-transparent via-brand-700/40 to-transparent" />

      {/* Centered Eyas wordmark — primary brand surface, visible on
          every authed page. EYAS in oxblood-300 extrabold, tracked. */}
      <div className="pointer-events-none absolute left-1/2 top-1/2 hidden -translate-x-1/2 -translate-y-1/2 select-none sm:flex">
        <div className="font-sans text-[16px] uppercase leading-none tracking-[0.18em]">
          <span className="font-extrabold text-oxblood-300">EYAS</span>
        </div>
      </div>

      <div className="relative flex h-14 items-center justify-between gap-3 px-3 sm:px-4">
        <div className="flex min-w-0 items-center gap-3">
          <button
            type="button"
            onClick={onMenuClick}
            aria-label={sidebarOpen ? "Close menu" : "Open menu"}
            aria-expanded={sidebarOpen}
            className="relative flex h-9 w-9 items-center justify-center rounded-md border border-neutral-800 bg-neutral-950/40 text-neutral-300 transition-[border-color,background-color,color] duration-150 hover:border-brand-700/60 hover:bg-neutral-900 hover:text-oxblood-200 md:hidden"
          >
            <Menu
              className={`absolute h-4 w-4 transition-all duration-200 ${
                sidebarOpen ? "rotate-90 opacity-0" : "rotate-0 opacity-100"
              }`}
              strokeWidth={2}
            />
            <X
              className={`absolute h-4 w-4 transition-all duration-200 ${
                sidebarOpen ? "rotate-0 opacity-100" : "-rotate-90 opacity-0"
              }`}
              strokeWidth={2}
            />
          </button>
          {title ? (
            <div className="flex min-w-0 items-center gap-2.5">
              <span className="hidden font-mono text-[12px] font-medium uppercase tracking-[0.16em] text-neutral-600 sm:inline">
                console //
              </span>
              <div className="truncate font-mono text-base font-semibold uppercase tracking-[0.14em] text-neutral-100">
                {title}
              </div>
            </div>
          ) : null}
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => chat.open()}
            aria-label="Ask the agent"
            className="flex h-9 items-center gap-1.5 rounded-md border border-brand-700/60 bg-brand-950/40 px-2.5 font-mono text-[12px] font-semibold uppercase tracking-[0.12em] text-oxblood-200 transition-[border-color,background-color,color] duration-150 hover:border-brand-600 hover:bg-brand-900/50 hover:text-white"
          >
            <MessageSquare className="h-3.5 w-3.5" strokeWidth={2} />
            <span className="hidden sm:inline">Ask</span>
          </button>
          <EnvironmentSwitcher />
          <ThemeToggle />
          {right}
        </div>
      </div>
    </header>
  );
}
