"use client";

import { useRef, useState } from "react";
import { FileText } from "lucide-react";
import AppShell from "@/components/AppShell";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";
import PageHero from "@/components/PageHero";

export default function BriefingPage() {
  const ref = useRef<AgentRunHandle>(null);
  const [hasRun, setHasRun] = useState(false);

  const today = new Date().toISOString().slice(0, 10);

  return (
    <AppShell title="Briefing">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-4xl animate-fade-in-up space-y-8">
          <PageHero
            icon={FileText}
            eyebrow="Daily briefing"
            title="One-page security briefing for stakeholders."
            subtitle={
              <span>
                Incidents, detections, vulnerabilities, and host hygiene as of{" "}
                <span className="font-mono text-neutral-300">{today}</span>. Print, send to a webhook, or schedule for daily delivery.
              </span>
            }
            right={
              <button
                onClick={() => {
                  setHasRun(true);
                  ref.current?.start();
                }}
                className="flex items-center gap-1.5 rounded-md bg-brand-600 px-6 py-3 font-mono text-[12px] font-semibold uppercase tracking-[0.16em] text-white shadow-[0_0_24px_-4px_rgba(220,38,38,0.55),inset_0_1px_0_rgba(255,255,255,0.12)] transition-[background-color,box-shadow] duration-150 hover:bg-brand-500 hover:shadow-[0_0_32px_-4px_rgba(239,68,68,0.7),inset_0_1px_0_rgba(255,255,255,0.18)]"
              >
                {hasRun ? "Regenerate" : "Generate briefing"}
              </button>
            }
          />

          <div>
            <AgentRun
              ref={ref}
              endpoint="/api/briefing"
              webhookTitle={`Falcon daily briefing · ${today}`}
              webhookSource="briefing"
              emptyHint={
                <div className="border border-dashed border-neutral-800 bg-neutral-950/60 p-8 text-center">
                  <div className="text-lg font-semibold text-white">
                    Click <span className="text-oxblood-400">Generate briefing</span> to start.
                  </div>
                </div>
              }
            />
          </div>
        </div>
      </main>
    </AppShell>
  );
}
