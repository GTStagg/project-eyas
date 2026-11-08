"use client";

import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ScrollText } from "lucide-react";
import AppShell from "@/components/AppShell";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";
import PageHero from "@/components/PageHero";

function DossierInner() {
  const router = useRouter();
  const search = useSearchParams();
  const initial = search.get("q") ?? "";
  const [input, setInput] = useState(initial);
  const [submitted, setSubmitted] = useState<string | null>(initial || null);
  const ref = useRef<AgentRunHandle>(null);

  const canRun = input.trim().length > 0;
  const body = useMemo(
    () => (submitted ? { subject: submitted } : undefined),
    [submitted],
  );

  const run = (raw: string) => {
    const trimmed = raw.trim();
    if (!trimmed) return;
    setSubmitted(trimmed);
    router.replace(`/intel-dossier?q=${encodeURIComponent(trimmed)}`);
    setTimeout(() => ref.current?.start(), 0);
  };

  useEffect(() => {
    if (initial) setTimeout(() => ref.current?.start(), 0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <AppShell title="Dossier">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-4xl animate-fade-in-up space-y-8">
          <PageHero
            icon={ScrollText}
            eyebrow="Falcon Intelligence · finished-intel dossier"
            title="Everything Falcon knows about an adversary, in one document."
            subtitle="Enter a threat actor, campaign, or keyword. Pulls the full finished-intelligence report bodies, actor profiles, and Recon underground footprint — every time — then writes the dossier."
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
                placeholder="threat actor, campaign, or keyword (e.g. ExfilSquad, WIZARD SPIDER)"
                className="flex-1 border border-neutral-800 bg-neutral-950 px-3.5 py-2.5 font-mono text-base text-neutral-100 placeholder:text-neutral-600 focus:border-brand-700 focus:outline-none"
              />
              <button
                onClick={() => run(input)}
                disabled={!canRun}
                className="flex items-center gap-1.5 rounded-md bg-brand-600 px-5 py-2.5 font-mono text-[12px] font-semibold uppercase tracking-[0.16em] text-white shadow-[0_0_24px_-4px_rgba(220,38,38,0.55),inset_0_1px_0_rgba(255,255,255,0.12)] transition-[background-color,box-shadow] duration-150 hover:bg-brand-500 hover:shadow-[0_0_32px_-4px_rgba(239,68,68,0.7),inset_0_1px_0_rgba(255,255,255,0.18)] disabled:cursor-not-allowed disabled:bg-neutral-900 disabled:text-neutral-600 disabled:shadow-none"
              >
                Build dossier
              </button>
            </div>
            <div className="mt-2 text-sm text-neutral-500">
              Deterministic: searches reports + actors, fetches their full content, and scans the Recon corpus — on every run, regardless of the model.
            </div>
          </div>

          <div>
            <AgentRun
              ref={ref}
              endpoint="/api/intel-dossier"
              body={body}
              webhookTitle={submitted ? `Dossier · ${submitted}` : "Dossier"}
              webhookSource="intel-dossier"
              emptyHint={
                <div className="border border-dashed border-neutral-800 bg-neutral-950/60 p-8 text-center">
                  <div className="text-lg font-semibold text-white">
                    Enter a threat actor, campaign, or keyword to build a dossier.
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

export default function DossierPage() {
  return (
    <Suspense fallback={null}>
      <DossierInner />
    </Suspense>
  );
}
