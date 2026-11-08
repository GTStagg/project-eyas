import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import ReticleMark from "./ReticleMark";

// Compact page header, matching the Control Center style: the animated reticle
// graphic (page icon at center) + a small oxblood brand-cap (eyebrow) + a compact
// title. Descriptions are intentionally dropped app-wide — the page content is
// the substance. `subtitle` is still accepted (so the 24 call sites need no edit)
// but no longer rendered. `right` keeps the optional action slot.
export default function PageHero({
  icon,
  eyebrow,
  title,
  right,
}: {
  icon: LucideIcon;
  eyebrow: string;
  title: ReactNode;
  /** @deprecated no longer rendered — kept so existing call sites still typecheck. */
  subtitle?: ReactNode;
  right?: ReactNode;
}) {
  return (
    <div className="hero-frame flex flex-col items-start justify-between gap-5 sm:flex-row sm:items-center">
      <div className="flex items-center gap-4 sm:gap-5">
        <ReticleMark icon={icon} className="h-14 w-14 sm:h-16 sm:w-16" iconClassName="h-5 w-5 sm:h-6 sm:w-6" />
        <div className="min-w-0">
          <div className="font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-oxblood-300">
            {eyebrow}
          </div>
          <h1 className="mt-1.5 text-xl font-semibold leading-tight tracking-tight text-neutral-50 sm:text-2xl">
            {title}
          </h1>
        </div>
      </div>
      {right ? <div className="shrink-0 self-start sm:self-center">{right}</div> : null}
    </div>
  );
}
