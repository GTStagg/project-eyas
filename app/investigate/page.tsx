"use client";

import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowUpRight, Microscope } from "lucide-react";
import AppShell from "@/components/AppShell";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";
import PageHero from "@/components/PageHero";

function InvestigateInner() {
  const router = useRouter();
  const search = useSearchParams();
  const initialHost = search.get("host") ?? "";
  const [input, setInput] = useState(initialHost);
  const [submitted, setSubmitted] = useState<string | null>(initialHost || null);
  const ref = useRef<AgentRunHandle>(null);

  const body = useMemo(
    () => (submitted ? { hostname: submitted } : undefined),
    [submitted],
  );

  const run = (host: string) => {
    const trimmed = host.trim();
    if (!trimmed) return;
    setSubmitted(trimmed);
    router.replace(`/investigate?host=${encodeURIComponent(trimmed)}`);
    setTimeout(() => ref.current?.start(), 0);
  };

  // If the URL provides ?host=X on first load, kick off the run automatically.
  useEffect(() => {
    if (initialHost) {
      // start once after mount
      setTimeout(() => ref.current?.start(), 0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <AppShell title="Investigate">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-4xl animate-fade-in-up space-y-8">
          <PageHero
            icon={Microscope}
            eyebrow="Host investigation"
            title="Per-host deep-dive across detections, vulnerabilities, and live state."
            subtitle="Pick a host. Get one report covering its detections, vulnerabilities, and live process state."
          />

          <div className="border border-neutral-800 bg-neutral-950 p-4">
            <div className="flex gap-2">
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    run(input);
                  }
                }}
                placeholder="Hostname (e.g. WIN10-FIN-07)"
                className="flex-1 border border-neutral-800 bg-neutral-950 px-3.5 py-2.5 text-base text-neutral-100 placeholder:text-neutral-600 focus:border-brand-700 focus:outline-none"
              />
              <button
                onClick={() => run(input)}
                disabled={!input.trim()}
                className="flex items-center gap-1.5 rounded-md bg-brand-600 px-5 py-2.5 font-mono text-[12px] font-semibold uppercase tracking-[0.16em] text-white shadow-[0_0_24px_-4px_rgba(220,38,38,0.55),inset_0_1px_0_rgba(255,255,255,0.12)] transition-[background-color,box-shadow] duration-150 hover:bg-brand-500 hover:shadow-[0_0_32px_-4px_rgba(239,68,68,0.7),inset_0_1px_0_rgba(255,255,255,0.18)] disabled:cursor-not-allowed disabled:bg-neutral-900 disabled:text-neutral-600 disabled:shadow-none"
              >
                Investigate
              </button>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-neutral-500">
              Tip: open
              <a
                href="/hosts"
                className="inline-flex h-7 items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950 px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-neutral-700 hover:text-white"
              >
                Hosts
                <ArrowUpRight className="h-3 w-3" strokeWidth={2} />
              </a>
              and click <strong className="text-neutral-300">Investigate</strong> on any row.
            </div>
          </div>

          <div>
            <AgentRun
              ref={ref}
              endpoint="/api/investigate"
              body={body}
              webhookTitle={submitted ? `Falcon investigation · ${submitted}` : "Falcon investigation"}
              webhookSource="investigate"
              emptyHint={
                <div className="border border-dashed border-neutral-800 bg-neutral-950/60 p-8 text-center">
                  <div className="text-lg font-semibold text-white">
                    Enter a hostname to begin.
                  </div>
                  <p className="mt-2 text-base text-neutral-400">
                    Typical investigation: 8-14 iterations, 30-90 seconds.
                  </p>
                </div>
              }
            />
          </div>
        </div>
      </main>
    </AppShell>
  );
}

export default function InvestigatePage() {
  return (
    <Suspense fallback={null}>
      <InvestigateInner />
    </Suspense>
  );
}
