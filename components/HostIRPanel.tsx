"use client";

import { ShieldAlert } from "lucide-react";

const PHASES = [
  "0 · Discover",
  "1 · Quarantine",
  "2 · Remediate",
  "3 · Verify",
  "4 · Release / Hold",
];

export default function HostIRPanel({
  quarantineConfigured,
}: {
  quarantineConfigured: boolean;
}) {
  return (
    <section className="mb-8 rounded-lg border border-amber-900/40 bg-gradient-to-br from-amber-950/20 via-neutral-950 to-neutral-950 p-5 shadow-lg shadow-black/40">
      <div className="flex items-start gap-3.5">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-amber-900/60 bg-amber-950/60 text-amber-300">
          <ShieldAlert className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[12px] font-semibold uppercase tracking-[0.14em] text-amber-300">
            Agent IR // Quarantine + cleanup + release
          </div>
          <h2 className="mt-1 text-xl font-semibold tracking-tight text-white">
            End-to-end agentic incident response on a single host.
          </h2>
          <p className="mt-1.5 text-sm text-neutral-400">
            Click <span className="font-mono text-amber-300">IR</span> on any
            host row below — the workflow opens in chat. Discovery and
            verification are read-only; quarantine, each cleanup action, and
            release gate on operator approval.
          </p>

          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            {PHASES.map((p, i) => (
              <span key={p} className="flex items-center gap-1.5">
                <span className="rounded border border-amber-900/40 bg-neutral-950/60 px-2 py-1 font-mono text-[11px] uppercase tracking-[0.12em] text-amber-200">
                  {p}
                </span>
                {i < PHASES.length - 1 && (
                  <span className="text-neutral-700">→</span>
                )}
              </span>
            ))}
          </div>

          {!quarantineConfigured && (
            <p className="mt-3 rounded-md border border-amber-900/40 bg-amber-950/30 px-3 py-2 font-mono text-[11px] text-amber-300">
              The active environment&apos;s &ldquo;IR quarantine host
              group&rdquo; is not set. Create a static Falcon host group with
              an aggressive prevention policy, then paste its id into the
              field on the active environment in /config to enable this
              surface.
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
