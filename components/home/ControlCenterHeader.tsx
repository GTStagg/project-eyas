// Compact dashboard header — just "Control Center" + the on-theme animated radar
// graphic (shared ReticleMark, radar-contact variant). No big title/subtitle —
// the tiles below are the content.

import ReticleMark from "@/components/ReticleMark";

export default function ControlCenterHeader({ envName }: { envName: string }) {
  return (
    <div className="flex items-center gap-4 sm:gap-5">
      <ReticleMark className="h-16 w-16" />

      {/* Title */}
      <div className="min-w-0">
        <h1 className="font-sans text-2xl font-extrabold uppercase leading-none tracking-[0.16em] sm:text-3xl">
          <span className="text-neutral-50">Control </span>
          <span className="text-oxblood-300">Center</span>
        </h1>
        <div className="mt-2 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.16em] text-neutral-500">
          <span className="live-dot" />
          <span>
            Tenant <span className="text-neutral-300">{envName}</span>
          </span>
        </div>
      </div>
    </div>
  );
}

