"use client";

// AI-agent-activity snapshot for the /shadow-ai (AI) page — falcon-mcp 0.19.0
// Guardian (AIDR:read). Fetched on load so the page immediately answers "what AI
// agents are running in this tenant, and is anything scoring hot." The elevated
// Agentic Threat Scores are the act-now signal. "Run full review" reveals the
// agentic Guardian decision document inline (with its own follow-up chat).
//
// Gated: on scope_pending / error the card renders nothing (the page's
// unsanctioned-tooling scan below stands on its own).

import { useEffect, useState } from "react";
import { Bot, ShieldAlert, Loader2, ArrowUpRight, MessageSquare } from "lucide-react";
import { AgentToolPanel, AGENT_TOOLS } from "./panels/AgentToolPanel";

type Summary = {
  window: string;
  agents: number;
  sessions: number;
  products: number;
  topProducts: { name: string; count: number }[];
  detections: { hosts: number; maxScore: number };
  topScored: { agentId: string; product: string; score: number }[];
  elevatedCount: number;
};

function scoreTone(score: number): string {
  if (score >= 90) return "border-oxblood-800 bg-oxblood-900/50 text-oxblood-200";
  if (score >= 70) return "border-orange-800 bg-orange-900/50 text-orange-200";
  if (score >= 40) return "border-amber-800 bg-amber-900/40 text-amber-100";
  return "border-sky-800 bg-sky-900/40 text-sky-200";
}

function Stat({ label, value, emphasis }: { label: string; value: string; emphasis?: boolean }) {
  return (
    <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-3 py-2.5">
      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-500">{label}</div>
      <div className={`mt-1 font-mono text-xl font-bold tabular-nums ${emphasis ? "text-oxblood-200" : "text-neutral-50"}`}>
        {value}
      </div>
    </div>
  );
}

export default function GuardianActivityCard() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [hidden, setHidden] = useState(false);
  const [ready, setReady] = useState(false);
  const [mode, setMode] = useState<"review" | "prompts" | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const r = await fetch("/api/guardian/inventory", { cache: "no-store" });
        const j = await r.json();
        if (j?.ok && j.summary) setSummary(j.summary as Summary);
        else setHidden(true); // scope_pending or malformed → degrade cleanly
      } catch {
        setHidden(true);
      } finally {
        setReady(true);
      }
    })();
  }, []);

  if (hidden) return null;

  if (!ready || !summary) {
    return (
      <section className="rounded-lg border border-neutral-800 bg-neutral-950 p-5">
        <div className="flex items-center gap-2 text-sm text-neutral-500">
          <Loader2 className="h-4 w-4 animate-spin" strokeWidth={2} /> Loading AI-agent activity…
        </div>
      </section>
    );
  }

  const elevated = summary.topScored.filter((s) => s.score >= 70).slice(0, 6);

  return (
    <section className="rounded-lg border border-neutral-800 bg-neutral-950 p-5">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h2 className="flex items-center gap-2.5 font-mono text-sm font-semibold uppercase tracking-[0.16em] text-neutral-100">
          <Bot className="h-4 w-4 text-brand-400" strokeWidth={1.75} />
          AI agent activity
          <span className="font-normal text-neutral-600">· Guardian // last {summary.window}</span>
        </h2>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setMode((m) => (m === "prompts" ? null : "prompts"))}
            className={`inline-flex items-center gap-1.5 rounded-md border px-3.5 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] transition ${
              mode === "prompts"
                ? "border-brand-600 bg-brand-600 text-white"
                : "border-neutral-800 bg-neutral-950/60 text-neutral-300 hover:border-brand-700/60 hover:text-oxblood-200"
            }`}
          >
            <MessageSquare className="h-3.5 w-3.5" strokeWidth={2} />
            Inspect prompts
          </button>
          <button
            type="button"
            onClick={() => setMode((m) => (m === "review" ? null : "review"))}
            className={`inline-flex items-center gap-1.5 rounded-md border px-3.5 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] transition ${
              mode === "review"
                ? "border-brand-600 bg-brand-600 text-white"
                : "border-brand-600 bg-brand-600 text-white hover:bg-brand-500"
            }`}
          >
            {mode === "review" ? "Hide review" : "Run full review"}
            <ArrowUpRight className="h-3.5 w-3.5" strokeWidth={2} />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="AI agents" value={String(summary.agents)} />
        <Stat label="Active sessions" value={String(summary.sessions)} />
        <Stat label="Products" value={String(summary.products)} />
        <Stat
          label="Elevated agents"
          value={String(summary.elevatedCount)}
          emphasis={summary.elevatedCount > 0}
        />
      </div>

      {/* Act-now signal: agents with a hot Agentic Threat Score. */}
      {elevated.length > 0 ? (
        <div className="mt-4 rounded-md border border-oxblood-900/60 bg-oxblood-950/25 px-3 py-2.5">
          <div className="flex items-center gap-2 text-[13px] text-oxblood-200">
            <ShieldAlert className="h-4 w-4 shrink-0" strokeWidth={2} />
            <span>
              <span className="font-mono font-bold">{summary.elevatedCount}</span> AI{" "}
              {summary.elevatedCount === 1 ? "agent is" : "agents are"} scoring ≥70 — worth a look.
            </span>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {elevated.map((s) => (
              <span
                key={s.agentId}
                title={`Agent ${s.agentId}`}
                className={`rounded border px-1.5 py-0.5 font-mono text-[11px] ${scoreTone(s.score)}`}
              >
                {s.product} · {s.score}
              </span>
            ))}
          </div>
        </div>
      ) : (
        <div className="mt-4 text-[12px] text-neutral-500">
          No AI agents with an elevated Agentic Threat Score in the last {summary.window}.
        </div>
      )}

      {/* Product mix */}
      {summary.topProducts.length > 0 ? (
        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-600">Products</span>
          {summary.topProducts.map((p) => (
            <span
              key={p.name}
              className="rounded border border-neutral-800 bg-neutral-900/60 px-1.5 py-0.5 font-mono text-[11px] text-neutral-300"
            >
              {p.name} <span className="text-neutral-500">{p.count}</span>
            </span>
          ))}
        </div>
      ) : null}

      {/* Full agentic review / prompt inspection — mounted on demand. */}
      {mode ? (
        <div className="mt-4 border-t border-neutral-800/80 pt-4">
          <AgentToolPanel tool={AGENT_TOOLS[mode === "prompts" ? "guardian-prompts" : "guardian"]} />
        </div>
      ) : null}
    </section>
  );
}
