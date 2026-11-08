"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LogOut } from "lucide-react";
import { HOME_ITEM } from "@/lib/nav";
import { useNavGating } from "@/lib/hooks/useNavGating";
import BrandMark from "./BrandMark";

// Persistent thin navigation rail (desktop, md+). One icon per nav group; hover
// or keyboard-focus a group icon to reveal a flyout listing that group's items.
// Replaces the old full-width modal drawer on desktop — the drawer (Sidebar) is
// retained only for mobile. All 27 destinations and their capability gates are
// preserved; gating comes from the shared useNavGating hook so rail and drawer
// never disagree.
//
// The flyout is CSS-driven (group-hover + group-focus-within). The rail itself
// must NOT scroll — overflow-y:auto would compute overflow-x to auto and clip the
// flyout. The item list fits without scrolling at any realistic viewport height.

export default function IconRail() {
  const pathname = usePathname();
  const { visibleGroups } = useNavGating();

  const isActive = (href: string) =>
    href === "/" ? pathname === "/" : pathname.startsWith(href);

  const homeActive = pathname === HOME_ITEM.href;

  return (
    <aside
      aria-label="Primary navigation"
      className="sticky top-0 z-30 hidden h-screen w-16 shrink-0 flex-col items-center overflow-visible border-r border-neutral-800 bg-gradient-to-b from-neutral-950 to-neutral-900 py-3 md:flex"
    >
      <Link
        href={HOME_ITEM.href}
        aria-label="Home"
        className="mb-2 flex h-10 w-10 items-center justify-center rounded-md"
      >
        <BrandMark size={24} />
      </Link>

      <div className="my-1 h-px w-8 bg-neutral-800/80" />

      <nav className="flex flex-1 flex-col items-center gap-1">
        {/* Home — pinned, never gated */}
        <RailLink
          href={HOME_ITEM.href}
          label={HOME_ITEM.label}
          description={HOME_ITEM.description}
          Icon={HOME_ITEM.icon}
          active={homeActive}
        />

        {visibleGroups.map((group) => {
          const GroupIcon = group.icon;
          const groupActive = group.items.some((it) => isActive(it.href));
          return (
            <div key={group.label} className="group relative">
              <button
                type="button"
                aria-label={group.label}
                aria-haspopup="true"
                className={`flex h-10 w-10 items-center justify-center rounded-md transition-[background-color,color] duration-150 ${
                  groupActive
                    ? "bg-brand-600/12 text-neutral-50 ring-1 ring-inset ring-brand-700/40"
                    : "text-neutral-400 hover:bg-neutral-900/70 hover:text-neutral-100 group-focus-within:bg-neutral-900/70 group-focus-within:text-neutral-100"
                }`}
              >
                {groupActive && (
                  <span className="absolute left-0 top-1/2 h-5 w-[2px] -translate-y-1/2 rounded-r bg-brand-500 shadow-[0_0_10px_-1px_rgba(239,68,68,0.7)]" />
                )}
                <GroupIcon
                  className={`h-[1.15rem] w-[1.15rem] ${groupActive ? "text-oxblood-400" : ""}`}
                  strokeWidth={2}
                />
              </button>

              {/* Flyout — pl-2 is a hoverable bridge so the mouse can travel
                  from icon to panel without dropping group-hover. The wrapper
                  must NOT be pointer-events-none, or the bridge stops counting
                  as part of the group and the panel hides mid-traverse. */}
              <div className="absolute left-full top-0 z-50 hidden pl-2 group-hover:block group-focus-within:block">
                <div className="w-64 rounded-md border border-neutral-800 bg-neutral-950 py-2 shadow-2xl shadow-black/50">
                  <div className="mb-1 flex items-center gap-2 px-3 font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
                    <span className="h-px w-2 bg-neutral-700" />
                    {group.label}
                  </div>
                  <ul className="space-y-0.5 px-1.5">
                    {group.items.map((item) => {
                      const active = isActive(item.href);
                      const ItemIcon = item.icon;
                      return (
                        <li key={item.href}>
                          <Link
                            href={item.href}
                            className={`group/item relative flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-[background-color,color] duration-150 ${
                              active
                                ? "bg-brand-600/12 text-neutral-50 ring-1 ring-inset ring-brand-700/40"
                                : "text-neutral-300 hover:bg-neutral-900/70 hover:text-neutral-100"
                            }`}
                            title={item.description}
                          >
                            <ItemIcon
                              className={`h-[1.05em] w-[1.05em] shrink-0 ${
                                active ? "text-oxblood-400" : "text-neutral-500 group-hover/item:text-neutral-300"
                              }`}
                              strokeWidth={2}
                            />
                            <span className="truncate">{item.label}</span>
                          </Link>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              </div>
            </div>
          );
        })}
      </nav>

      <form action="/api/auth/logout" method="post" className="mt-2">
        <button
          type="submit"
          aria-label="Sign out"
          title="Sign out"
          className="flex h-10 w-10 items-center justify-center rounded-md text-neutral-500 transition-colors hover:bg-neutral-900/70 hover:text-oxblood-300"
        >
          <LogOut className="h-[1.1rem] w-[1.1rem]" strokeWidth={2} />
        </button>
      </form>
    </aside>
  );
}

function RailLink({
  href,
  label,
  description,
  Icon,
  active,
}: {
  href: string;
  label: string;
  description: string;
  Icon: typeof LogOut;
  active: boolean;
}) {
  return (
    <div className="group relative">
      <Link
        href={href}
        aria-label={label}
        className={`relative flex h-10 w-10 items-center justify-center rounded-md transition-[background-color,color] duration-150 ${
          active
            ? "bg-brand-600/12 text-neutral-50 ring-1 ring-inset ring-brand-700/40"
            : "text-neutral-400 hover:bg-neutral-900/70 hover:text-neutral-100"
        }`}
      >
        {active && (
          <span className="absolute left-0 top-1/2 h-5 w-[2px] -translate-y-1/2 rounded-r bg-brand-500 shadow-[0_0_10px_-1px_rgba(239,68,68,0.7)]" />
        )}
        <Icon
          className={`h-[1.15rem] w-[1.15rem] ${active ? "text-oxblood-400" : ""}`}
          strokeWidth={2}
        />
      </Link>
      <div className="absolute left-full top-0 z-50 hidden pl-2 group-hover:block group-focus-within:block">
        <div className="w-56 rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2.5 shadow-2xl shadow-black/50">
          <div className="text-sm font-medium text-neutral-100">{label}</div>
          <div className="mt-0.5 text-[12px] leading-snug text-neutral-500">{description}</div>
        </div>
      </div>
    </div>
  );
}
