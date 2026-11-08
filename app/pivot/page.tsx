"use client";

import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Search } from "lucide-react";
import AppShell from "@/components/AppShell";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";
import PageHero from "@/components/PageHero";

type ArtifactKind =
  | "sha256"
  | "sha1"
  | "md5"
  | "ipv4"
  | "ipv6"
  | "domain"
  | "url"
  | "unknown";

type Mode = "lookup" | "lineage";

function detectKind(input: string): ArtifactKind {
  const t = input.trim();
  if (!t) return "unknown";
  if (/^[a-f0-9]{64}$/i.test(t)) return "sha256";
  if (/^[a-f0-9]{40}$/i.test(t)) return "sha1";
  if (/^[a-f0-9]{32}$/i.test(t)) return "md5";
  if (/^https?:\/\//i.test(t)) return "url";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(t)) return "ipv4";
  if (/^[0-9a-f:]+$/i.test(t) && t.includes("::")) return "ipv6";
  if (/^[0-9a-f:]+$/i.test(t) && t.split(":").length >= 3) return "ipv6";
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(t))
    return "domain";
  return "unknown";
}

function kindLabel(kind: ArtifactKind): string {
  switch (kind) {
    case "sha256":
      return "SHA-256";
    case "sha1":
      return "SHA-1";
    case "md5":
      return "MD5";
    case "ipv4":
      return "IPv4";
    case "ipv6":
      return "IPv6";
    case "domain":
      return "domain";
    case "url":
      return "URL";
    default:
      return "unrecognized";
  }
}

const HASH_KINDS: ArtifactKind[] = ["sha256", "sha1", "md5"];

function PivotInner() {
  const router = useRouter();
  const search = useSearchParams();
  const initial = search.get("q") ?? "";
  const initialMode = (search.get("mode") as Mode | null) ?? "lookup";

  const [input, setInput] = useState(initial);
  const [mode, setMode] = useState<Mode>(initialMode);
  const [submitted, setSubmitted] = useState<{
    artifact: string;
    kind: ArtifactKind;
    mode: Mode;
  } | null>(
    initial && detectKind(initial) !== "unknown"
      ? { artifact: initial, kind: detectKind(initial), mode: initialMode }
      : null,
  );
  const ref = useRef<AgentRunHandle>(null);

  const detected = useMemo(() => detectKind(input), [input]);
  const isHash = HASH_KINDS.includes(detected);
  const lineageAllowed = isHash;
  const effectiveMode: Mode = lineageAllowed ? mode : "lookup";
  const canRun = input.trim().length > 0 && detected !== "unknown";

  const endpoint = submitted?.mode === "lineage" ? "/api/threat-graph" : "/api/lookup";
  const body = useMemo(() => {
    if (!submitted) return undefined;
    if (submitted.mode === "lineage") {
      return { indicator: submitted.artifact, indicator_type: submitted.kind };
    }
    return { artifact: submitted.artifact, kind: submitted.kind };
  }, [submitted]);

  const run = (raw: string) => {
    const trimmed = raw.trim();
    if (!trimmed) return;
    const kind = detectKind(trimmed);
    if (kind === "unknown") return;
    const finalMode: Mode = HASH_KINDS.includes(kind) ? mode : "lookup";
    setSubmitted({ artifact: trimmed, kind, mode: finalMode });
    const params = new URLSearchParams({ q: trimmed });
    if (finalMode === "lineage") params.set("mode", "lineage");
    router.replace(`/pivot?${params.toString()}`);
    setTimeout(() => ref.current?.start(), 0);
  };

  useEffect(() => {
    if (submitted) {
      setTimeout(() => ref.current?.start(), 0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <AppShell title="Pivot">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-4xl animate-fade-in-up space-y-8">
          <PageHero
            icon={Search}
            eyebrow="Artifact pivot"
            title="Cross-source pivot for any artifact."
            subtitle="Paste a hash, IP, domain, or URL. Looks across Falcon Adversary Intelligence, your IOC list, recent detections, and 30 days of NGSIEM. Switch to Execution lineage for hashes."
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
                placeholder="SHA-256, MD5, IPv4, domain, or URL"
                className="flex-1 border border-neutral-800 bg-neutral-950 px-3.5 py-2.5 font-mono text-base text-neutral-100 placeholder:text-neutral-600 focus:border-brand-700 focus:outline-none"
              />
              <button
                onClick={() => run(input)}
                disabled={!canRun}
                className="flex items-center gap-1.5 rounded-md bg-brand-600 px-5 py-2.5 font-mono text-[12px] font-semibold uppercase tracking-[0.16em] text-white shadow-[0_0_24px_-4px_rgba(220,38,38,0.55),inset_0_1px_0_rgba(255,255,255,0.12)] transition-[background-color,box-shadow] duration-150 hover:bg-brand-500 hover:shadow-[0_0_32px_-4px_rgba(239,68,68,0.7),inset_0_1px_0_rgba(255,255,255,0.18)] disabled:cursor-not-allowed disabled:bg-neutral-900 disabled:text-neutral-600 disabled:shadow-none"
              >
                Pivot
              </button>
            </div>

            <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-sm">
              <div className="flex items-center gap-2">
                <span className="text-neutral-500">Mode:</span>
                <button
                  type="button"
                  onClick={() => setMode("lookup")}
                  className={`rounded border px-2.5 py-1 font-mono text-[11px] uppercase tracking-[0.12em] transition-colors ${
                    effectiveMode === "lookup"
                      ? "border-brand-700 bg-brand-600/15 text-oxblood-200"
                      : "border-neutral-800 bg-neutral-950 text-neutral-500 hover:border-neutral-700"
                  }`}
                >
                  Cross-source lookup
                </button>
                <button
                  type="button"
                  onClick={() => lineageAllowed && setMode("lineage")}
                  disabled={!lineageAllowed}
                  title={lineageAllowed ? "" : "Hash artifact required"}
                  className={`rounded border px-2.5 py-1 font-mono text-[11px] uppercase tracking-[0.12em] transition-colors ${
                    effectiveMode === "lineage"
                      ? "border-brand-700 bg-brand-600/15 text-oxblood-200"
                      : "border-neutral-800 bg-neutral-950 text-neutral-500 hover:border-neutral-700"
                  } disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-neutral-800`}
                >
                  Execution lineage
                </button>
              </div>
              <span className="text-neutral-500">
                Auto-detected:{" "}
                <span
                  className={
                    detected === "unknown"
                      ? "font-mono text-neutral-600"
                      : "font-mono text-oxblood-300"
                  }
                >
                  {input.trim() ? kindLabel(detected) : "—"}
                </span>
              </span>
            </div>
          </div>

          <div>
            <AgentRun
              ref={ref}
              endpoint={endpoint}
              body={body}
              webhookTitle={
                submitted
                  ? `${submitted.mode === "lineage" ? "Execution lineage" : "Artifact lookup"} · ${submitted.artifact}`
                  : "Artifact pivot"
              }
              webhookSource={submitted?.mode === "lineage" ? "threat-graph" : "lookup"}
              emptyHint={
                <div className="border border-dashed border-neutral-800 bg-neutral-950/60 p-8 text-center">
                  <div className="text-lg font-semibold text-white">
                    Paste an indicator to begin.
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

export default function PivotPage() {
  return (
    <Suspense fallback={null}>
      <PivotInner />
    </Suspense>
  );
}
