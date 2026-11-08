"use client";

import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Radar } from "lucide-react";
import AppShell from "@/components/AppShell";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";
import PageHero from "@/components/PageHero";

type Kind = "domain" | "email";

const DOMAIN_RX = /^[a-z0-9][a-z0-9.\-]{0,253}$/;
const EMAIL_RX = /^[a-z0-9._%+\-]+@[a-z0-9.\-]+$/;

function detectKind(input: string): Kind | "unknown" {
  const t = input.trim().toLowerCase();
  if (!t) return "unknown";
  if (EMAIL_RX.test(t)) return "email";
  if (DOMAIN_RX.test(t)) return "domain";
  return "unknown";
}

function ReconInner() {
  const router = useRouter();
  const search = useSearchParams();
  const initial = search.get("q") ?? "";
  const [input, setInput] = useState(initial);
  const [submitted, setSubmitted] = useState<{
    query: string;
    kind: Kind;
  } | null>(() => {
    if (!initial) return null;
    const k = detectKind(initial);
    if (k === "unknown") return null;
    return { query: initial.toLowerCase(), kind: k };
  });
  const ref = useRef<AgentRunHandle>(null);

  const detected = useMemo(() => detectKind(input), [input]);
  const canRun = input.trim().length > 0 && detected !== "unknown";

  const body = useMemo(
    () =>
      submitted
        ? { query: submitted.query, kind: submitted.kind }
        : undefined,
    [submitted],
  );

  const run = (raw: string) => {
    const trimmed = raw.trim().toLowerCase();
    if (!trimmed) return;
    const kind = detectKind(trimmed);
    if (kind === "unknown") return;
    setSubmitted({ query: trimmed, kind });
    router.replace(`/recon?q=${encodeURIComponent(trimmed)}`);
    setTimeout(() => ref.current?.start(), 0);
  };

  useEffect(() => {
    if (initial && detectKind(initial) !== "unknown") {
      setTimeout(() => ref.current?.start(), 0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <AppShell title="Recon">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-4xl animate-fade-in-up space-y-8">
          <PageHero
            icon={Radar}
            eyebrow="Adversary Intelligence Recon"
            title="Domain and credential exposure across the adversary corpus."
            subtitle="Search Falcon Adversary Intelligence Recon for mentions of a domain or email. Includes exposed credentials and existing alert coverage."
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
                placeholder="domain (e.g. example.com) or email (e.g. user@example.com)"
                className="flex-1 border border-neutral-800 bg-neutral-950 px-3.5 py-2.5 font-mono text-base text-neutral-100 placeholder:text-neutral-600 focus:border-brand-700 focus:outline-none"
              />
              <button
                onClick={() => run(input)}
                disabled={!canRun}
                className="flex items-center gap-1.5 rounded-md bg-brand-600 px-5 py-2.5 font-mono text-[12px] font-semibold uppercase tracking-[0.16em] text-white shadow-[0_0_24px_-4px_rgba(220,38,38,0.55),inset_0_1px_0_rgba(255,255,255,0.12)] transition-[background-color,box-shadow] duration-150 hover:bg-brand-500 hover:shadow-[0_0_32px_-4px_rgba(239,68,68,0.7),inset_0_1px_0_rgba(255,255,255,0.18)] disabled:cursor-not-allowed disabled:bg-neutral-900 disabled:text-neutral-600 disabled:shadow-none"
              >
                Run recon
              </button>
            </div>
            <div className="mt-2 flex items-center justify-between text-sm">
              <span className="text-neutral-500">
                Auto-detected:{" "}
                <span
                  className={
                    detected === "unknown"
                      ? "font-mono text-neutral-600"
                      : "font-mono text-oxblood-300"
                  }
                >
                  {input.trim() ? detected : "—"}
                </span>
              </span>
              <span className="text-neutral-600">
                Tip: configure OUTBOUND_WEBHOOK_URL to post the report to Slack / Telegram / Teams.
              </span>
            </div>
          </div>

          <div>
            <AgentRun
              ref={ref}
              endpoint="/api/recon"
              body={body}
              webhookTitle={
                submitted ? `Recon · ${submitted.query}` : "Recon"
              }
              webhookSource="recon"
              emptyHint={
                <div className="border border-dashed border-neutral-800 bg-neutral-950/60 p-8 text-center">
                  <div className="text-lg font-semibold text-white">
                    Enter a domain or email to begin.
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

export default function ReconPage() {
  return (
    <Suspense fallback={null}>
      <ReconInner />
    </Suspense>
  );
}
