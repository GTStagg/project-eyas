import type { LucideIcon } from "lucide-react";

// Shared SOC "reticle" graphic — the signature dashboard mark, generalized for
// every page header. Concentric rings on a brand-tinted dish, crosshair, corner
// ticks, and a slow rotating radar sweep (see `.cc-sweep` in globals.css, which
// honors prefers-reduced-motion). Center is the page's icon when given, else the
// radar-contact blips used on the Control Center landing.

export default function ReticleMark({
  icon: Icon,
  className = "h-14 w-14",
  iconClassName = "h-5 w-5",
}: {
  icon?: LucideIcon;
  /** Box size (Tailwind h-/w-). Percentage-based rings scale with it. */
  className?: string;
  iconClassName?: string;
}) {
  return (
    <div className={`relative shrink-0 ${className}`}>
      {/* Corner reticle ticks — square frame around the dish */}
      <span className="pointer-events-none absolute -left-px -top-px h-2 w-2 border-l border-t border-brand-500/70" />
      <span className="pointer-events-none absolute -right-px -top-px h-2 w-2 border-r border-t border-brand-500/70" />
      <span className="pointer-events-none absolute -bottom-px -left-px h-2 w-2 border-b border-l border-brand-500/70" />
      <span className="pointer-events-none absolute -bottom-px -right-px h-2 w-2 border-b border-r border-brand-500/70" />

      {/* Rings */}
      <div className="absolute inset-0 rounded-full border border-neutral-700/70 bg-gradient-to-br from-brand-950/40 via-neutral-950 to-neutral-950 shadow-[0_8px_30px_-12px_rgba(220,38,38,0.45),inset_0_1px_0_rgba(255,255,255,0.04)]" />
      <div className="absolute inset-[20%] rounded-full border border-neutral-800/80" />
      <div className="absolute inset-[40%] rounded-full border border-neutral-800/60" />

      {/* Crosshair */}
      <div className="absolute left-1/2 top-[6%] h-[88%] w-px -translate-x-1/2 bg-neutral-800/60" />
      <div className="absolute top-1/2 left-[6%] h-px w-[88%] -translate-y-1/2 bg-neutral-800/60" />

      {/* Rotating sweep — a conic wedge clipped to the dish circle */}
      <div
        className="cc-sweep absolute inset-0 rounded-full"
        style={{
          background:
            "conic-gradient(from 0deg, transparent 0deg 296deg, rgba(220,38,38,0.30) 348deg, rgba(239,68,68,0.60) 360deg)",
        }}
        aria-hidden="true"
      />

      {Icon ? (
        <>
          {/* Dark seat so the icon stays legible as the sweep passes behind it */}
          <div className="absolute inset-[26%] rounded-full bg-neutral-950/85" />
          <div className="absolute inset-0 flex items-center justify-center text-oxblood-300">
            <Icon className={iconClassName} strokeWidth={1.75} />
          </div>
        </>
      ) : (
        <>
          {/* Radar contacts + live center blip (Control Center landing) */}
          <span className="absolute left-[64%] top-[34%] h-1 w-1 rounded-full bg-oxblood-400/80" />
          <span className="absolute left-[36%] top-[62%] h-[3px] w-[3px] rounded-full bg-oxblood-500/60" />
          <span className="live-dot absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2" />
        </>
      )}
    </div>
  );
}
