"use client";

import { useRef, useState } from "react";
import { FileText, Building2 } from "lucide-react";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";

// Operator-facing CTA that turns ONE IR engagement into a leadership-ready
// incident report. Mounts AgentRun against /api/ir-report (synthesis-only, no
// upstream calls) and starts it on click; the report streams in place, then the
// Print + Webhook buttons appear. When the engagement ran under a different
// tenant than the active one, the report action is refused server-side — so the
// button is replaced with a plain note rather than a control that would 404.
export default function IrReportPanel({
  file,
  aid,
  crossTenant,
}: {
  file: string;
  aid: string;
  crossTenant: boolean;
}) {
  const ref = useRef<AgentRunHandle>(null);
  const [hasRun, setHasRun] = useState(false);

  if (crossTenant) {
    return (
      <section className="rounded-lg border border-neutral-800 bg-neutral-950 p-6">
        <div className="flex items-start gap-3.5">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-neutral-800 bg-neutral-900 text-neutral-400">
            <Building2 className="h-5 w-5" strokeWidth={1.75} />
          </div>
          <div>
            <h2 className="text-2xl font-semibold tracking-tight text-white">
              Incident report
            </h2>
            <p className="mt-1.5 max-w-2xl text-base text-neutral-400">
              This engagement ran under a different tenant. Switch to that tenant to generate
              its incident report.
            </p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="rounded-lg border border-brand-900/40 bg-gradient-to-br from-brand-950/30 via-neutral-950 to-neutral-950 p-6 shadow-lg shadow-black/40">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-start gap-3.5">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/60 bg-brand-950/60 text-oxblood-300">
            <FileText className="h-5 w-5" strokeWidth={1.75} />
          </div>
          <div>
            <div className="font-mono text-[12px] font-semibold uppercase tracking-[0.14em] text-oxblood-300">
              Incident report
            </div>
            <h2 className="mt-1 text-2xl font-semibold tracking-tight text-white">
              Generate incident report
            </h2>
            <p className="mt-1.5 max-w-2xl text-base text-neutral-400">
              A leadership-ready summary on top, full technical detail below — ready to share or
              attach to the case file.
            </p>
          </div>
        </div>
        <button
          onClick={() => {
            setHasRun(true);
            ref.current?.start();
          }}
          className="flex h-11 shrink-0 items-center gap-1.5 rounded-md bg-brand-600 px-5 font-mono text-[12px] font-semibold uppercase tracking-[0.16em] text-white shadow-[0_0_24px_-4px_rgba(220,38,38,0.55),inset_0_1px_0_rgba(255,255,255,0.12)] transition-[background-color,box-shadow] duration-150 hover:bg-brand-500 hover:shadow-[0_0_32px_-4px_rgba(239,68,68,0.7),inset_0_1px_0_rgba(255,255,255,0.18)]"
        >
          {hasRun ? "Regenerate" : "Generate report"}
        </button>
      </div>

      <div className="mt-5">
        <AgentRun
          ref={ref}
          endpoint="/api/ir-report"
          body={{ file }}
          webhookTitle={`Incident report · ${aid.slice(0, 8)}…`}
          webhookSource="incident-report"
          emptyHint={
            <div className="border border-dashed border-neutral-800 bg-neutral-950/60 p-6 text-center text-sm text-neutral-500">
              Click <span className="font-mono text-oxblood-300">Generate report</span> to write
              the incident report from this engagement.
            </div>
          }
        />
      </div>
    </section>
  );
}
