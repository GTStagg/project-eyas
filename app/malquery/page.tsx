"use client";

import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Fingerprint } from "lucide-react";
import AppShell from "@/components/AppShell";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";
import PageHero from "@/components/PageHero";

const HASH_RX = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;

function parseHashes(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((h) => h.trim())
    .filter((h) => HASH_RX.test(h))
    .map((h) => h.toLowerCase());
}

function MalQueryInner() {
  const router = useRouter();
  const search = useSearchParams();
  const initial = search.get("h") ?? "";
  const [input, setInput] = useState(initial);
  const [submitted, setSubmitted] = useState<string[] | null>(() => {
    if (!initial) return null;
    const hs = parseHashes(initial);
    return hs.length > 0 ? hs : null;
  });
  const ref = useRef<AgentRunHandle>(null);

  const detected = useMemo(() => parseHashes(input), [input]);
  const canRun = detected.length > 0 && detected.length <= 25;

  const body = useMemo(
    () => (submitted ? { hashes: submitted } : undefined),
    [submitted],
  );

  const run = (raw: string) => {
    const hs = parseHashes(raw);
    if (hs.length === 0) return;
    setSubmitted(hs);
    router.replace(`/malquery?h=${encodeURIComponent(hs.join(","))}`);
    setTimeout(() => ref.current?.start(), 0);
  };

  useEffect(() => {
    if (initial && parseHashes(initial).length > 0) {
      setTimeout(() => ref.current?.start(), 0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <AppShell title="MalQuery">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-4xl animate-fade-in-up space-y-8">
          <PageHero
            icon={Fingerprint}
            eyebrow="MalQuery"
            title="Hash lineage in one screen."
            subtitle="Paste up to 25 file hashes. MalQuery prevalence and family attribution, cross-referenced against tenant detections."
          />

          <div className="border border-neutral-800 bg-neutral-950 p-4">
            <div className="flex flex-col gap-2">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Paste hashes (one per line, comma- or whitespace-separated)"
                rows={4}
                className="w-full border border-neutral-800 bg-neutral-950 px-3.5 py-2.5 font-mono text-sm text-neutral-100 placeholder:text-neutral-600 focus:border-brand-700 focus:outline-none"
              />
              <div className="flex items-center justify-between">
                <span className="text-sm text-neutral-500">
                  Detected:{" "}
                  <span
                    className={
                      detected.length > 0
                        ? "font-mono text-oxblood-300"
                        : "font-mono text-neutral-600"
                    }
                  >
                    {detected.length} valid hash{detected.length === 1 ? "" : "es"}
                  </span>
                </span>
                <button
                  onClick={() => run(input)}
                  disabled={!canRun}
                  className="flex items-center gap-1.5 rounded-md bg-brand-600 px-5 py-2.5 font-mono text-[12px] font-semibold uppercase tracking-[0.16em] text-white shadow-[0_0_24px_-4px_rgba(220,38,38,0.55),inset_0_1px_0_rgba(255,255,255,0.12)] transition-[background-color,box-shadow] duration-150 hover:bg-brand-500 hover:shadow-[0_0_32px_-4px_rgba(239,68,68,0.7),inset_0_1px_0_rgba(255,255,255,0.18)] disabled:cursor-not-allowed disabled:bg-neutral-900 disabled:text-neutral-600 disabled:shadow-none"
                >
                  Run hunt
                </button>
              </div>
            </div>
          </div>

          <AgentRun
            ref={ref}
            endpoint="/api/malquery"
            body={body}
            webhookTitle={
              submitted ? `MalQuery · ${submitted.length} hash(es)` : "MalQuery"
            }
            webhookSource="malquery"
            emptyHint={
              <div className="border border-dashed border-neutral-800 bg-neutral-950/60 p-8 text-center">
                <div className="text-lg font-semibold text-white">
                  Paste one or more hashes to begin.
                </div>
              </div>
            }
          />
        </div>
      </main>
    </AppShell>
  );
}

export default function MalQueryPage() {
  return (
    <Suspense fallback={null}>
      <MalQueryInner />
    </Suspense>
  );
}
