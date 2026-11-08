"use client";

import { useRef, useState } from "react";
import { Layers } from "lucide-react";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";

export default function HostGroupsPosturePanel() {
  const ref = useRef<AgentRunHandle>(null);
  const [open, setOpen] = useState(false);
  const [hasRun, setHasRun] = useState(false);

  return (
    <section className="mt-6 border border-neutral-800 bg-neutral-950">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition-colors hover:bg-neutral-900/40"
      >
        <div className="flex items-center gap-3">
          <Layers className="h-5 w-5 text-oxblood-400" strokeWidth={2} />
          <div>
            <div className="text-base font-semibold text-white">Group posture report</div>
            <div className="mt-0.5 text-sm text-neutral-400">
              Posture across every host group. Pair with Vulnerabilities to plan staged rollouts.
            </div>
          </div>
        </div>
        <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-neutral-500">
          {open ? "hide" : "show"}
        </span>
      </button>

      {open && (
        <div className="border-t border-neutral-800 p-4">
          <div className="mb-3 flex items-center justify-end">
            <button
              type="button"
              onClick={() => {
                setHasRun(true);
                ref.current?.start();
              }}
              className="rounded-md bg-brand-600 px-4 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-white shadow-[0_0_24px_-4px_rgba(220,38,38,0.55)] hover:bg-brand-500"
            >
              {hasRun ? "Regenerate" : "Generate report"}
            </button>
          </div>
          <AgentRun
            ref={ref}
            endpoint="/api/host-groups"
            body={{}}
            webhookTitle="Host group posture"
            webhookSource="host-groups"
            emptyHint={
              <div className="border border-dashed border-neutral-800 bg-neutral-950/60 p-6 text-center text-sm text-neutral-400">
                Click <span className="text-oxblood-400">Generate report</span> to run.
              </div>
            }
          />
        </div>
      )}
    </section>
  );
}
