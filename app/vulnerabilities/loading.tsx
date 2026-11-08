import AppShell from "@/components/AppShell";

// Rendered while the server component does its per-host Spotlight fan-out.
// On busy tenants (200-host fleet sweep) the cold-load can run 30-90s; without
// a loading state the operator sees a blank page and assumes the app hung.
// This screen makes it explicit that work is in flight.
export default function Loading() {
  return (
    <AppShell title="Vulnerabilities">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <div className="eyebrow">Spotlight // Vulnerabilities</div>
              <h1 className="mt-2 text-4xl font-bold tracking-tight text-white">
                Open vulnerabilities
              </h1>
            </div>
            <span className="font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-500">
              compiling fleet posture…
            </span>
          </div>

          {/* Status banner — explicit, operator-language, no jargon. */}
          <div className="mt-6 border border-neutral-800 bg-neutral-950 px-5 py-6">
            <div className="flex items-center gap-3 font-mono text-[12px] uppercase tracking-[0.16em] text-oxblood-300">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-brand-500 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-brand-500" />
              </span>
              Sweeping the fleet host-by-host
            </div>
            <p className="mt-3 max-w-3xl text-sm leading-relaxed text-neutral-300">
              Pulling open vulnerabilities for every managed host so the
              By-patch and By-host views accurately reflect fleet-wide spread
              rather than just the noisiest few machines.
            </p>
            <p className="mt-2 max-w-3xl text-xs text-neutral-500">
              On busy tenants this can take up to a minute or two. The page
              renders the moment results are ready — leave the tab open.
            </p>
          </div>

          {/* Skeleton tiles — match the real page's posture / hero strip
              dimensions so the layout doesn't pop on resolve. */}
          <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {Array.from({ length: 5 }).map((_, i) => (
              <SkeletonTile key={i} />
            ))}
          </div>
          <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <SkeletonTile key={i} tall />
            ))}
          </div>
          <div className="mt-6 h-64 rounded-md border border-neutral-800 bg-neutral-950/60 animate-pulse" />
        </div>
      </main>
    </AppShell>
  );
}

function SkeletonTile({ tall = false }: { tall?: boolean }) {
  return (
    <div
      className={`border border-neutral-800 bg-neutral-950/60 p-4 ${tall ? "h-32" : "h-24"} animate-pulse`}
    >
      <div className="h-3 w-24 rounded-sm bg-neutral-800/80" />
      <div className="mt-3 h-7 w-16 rounded-sm bg-neutral-800/60" />
      <div className="mt-2 h-2 w-32 rounded-sm bg-neutral-900" />
    </div>
  );
}
