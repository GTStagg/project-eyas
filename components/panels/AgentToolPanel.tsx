"use client";

// Generic interactive capability panel: an input (or one-click "instant" run) +
// the embeddable AgentRun streaming into the panel. Every plain-English → agent
// tool (NGSIEM, artifact pivot, recon, MalQuery, daily briefing) is just a
// config of this — so adding another is one entry in AGENT_TOOLS, not a new
// component. Output persists until the panel closes (SnackPanel unmounts on close).

import { useRef, useState, type ReactNode } from "react";
import { CornerDownLeft, RotateCw, MessagesSquare } from "lucide-react";
import AgentRun, { type AgentRunHandle } from "../AgentRun";
import { ControlChatPanel } from "./ControlChatPanel";

export type AgentToolConfig = {
  endpoint: string;
  webhookTitle: string;
  webhookSource: string;
  hint?: ReactNode;
  // Input mode: prompt the operator, then translate the text to a request body.
  // Return an { error } to reject invalid input before firing the agent.
  input?: {
    placeholder: string;
    rows?: number;
    submitLabel?: string;
    buildBody: (value: string) => Record<string, unknown> | { error: string };
  };
  // Instant mode (no input): auto-run on open with this fixed body.
  instant?: { body?: Record<string, unknown> };
};

export function AgentToolPanel({ tool }: { tool: AgentToolConfig }) {
  const ref = useRef<AgentRunHandle>(null);
  const [input, setInput] = useState("");
  const [body, setBody] = useState<Record<string, unknown>>(tool.instant?.body ?? {});
  const [err, setErr] = useState<string | null>(null);
  // The completed report — enables the in-place follow-up chat. Cleared on re-run.
  const [report, setReport] = useState<string | null>(null);

  const run = () => {
    const built = tool.input!.buildBody(input.trim());
    if ("error" in built && typeof (built as { error?: unknown }).error === "string") {
      setErr((built as { error: string }).error);
      return;
    }
    setErr(null);
    setReport(null);
    setBody(built as Record<string, unknown>);
    setTimeout(() => ref.current?.start(), 0);
  };

  const rerun = () => {
    setReport(null);
    ref.current?.start();
  };

  return (
    <div className="space-y-4">
      {tool.input ? (
        <div>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
                e.preventDefault();
                run();
              }
            }}
            rows={tool.input.rows ?? 3}
            placeholder={tool.input.placeholder}
            className="w-full resize-y rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm text-neutral-100 placeholder:text-neutral-600 focus:border-brand-700 focus:outline-none"
          />
          {err ? <div className="mt-1.5 text-[12px] text-oxblood-300">{err}</div> : null}
          <div className="mt-2 flex items-center justify-between">
            <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-600">⌘/Ctrl + Enter</span>
            <button
              type="button"
              onClick={run}
              disabled={!input.trim()}
              className="inline-flex items-center gap-1.5 rounded-md border border-brand-600 bg-brand-600 px-3.5 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-white transition hover:bg-brand-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {tool.input.submitLabel ?? "Run"}
              <CornerDownLeft className="h-3.5 w-3.5" strokeWidth={2} />
            </button>
          </div>
        </div>
      ) : (
        <div className="flex justify-end">
          <button
            type="button"
            onClick={rerun}
            className="inline-flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950/60 px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-brand-700/60 hover:text-oxblood-200"
          >
            <RotateCw className="h-3.5 w-3.5" strokeWidth={2} />
            Run again
          </button>
        </div>
      )}

      <AgentRun
        ref={ref}
        endpoint={tool.endpoint}
        body={body}
        autoStart={Boolean(tool.instant)}
        webhookTitle={tool.webhookTitle}
        webhookSource={tool.webhookSource}
        emptyHint={tool.hint}
        onReport={setReport}
      />

      {/* In-place follow-up: once the report lands, converse about it right here.
          Seeded with the report (agent gets it as context); own ephemeral session
          so it doesn't touch the global chat thread. */}
      {report ? (
        <div className="border-t border-neutral-800/80 pt-4">
          <div className="mb-2 flex items-center gap-2 font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
            <MessagesSquare className="h-3.5 w-3.5 text-brand-400" strokeWidth={2} />
            Ask a follow-up
          </div>
          <ControlChatPanel seedContext={report} ephemeral embedded />
        </div>
      ) : null}
    </div>
  );
}

// ── artifact-kind detection (mirrors the /pivot client auto-detect) ───────────

const HEX = /^[a-f0-9]+$/i;
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

function detectArtifact(v: string): Record<string, unknown> | { error: string } {
  const s = v.trim();
  if (!s) return { error: "Paste a hash, IP, domain, or URL." };
  if (/^https?:\/\//i.test(s)) return { artifact: s, kind: "url" };
  if (HEX.test(s) && s.length === 64) return { artifact: s, kind: "sha256" };
  if (HEX.test(s) && s.length === 40) return { artifact: s, kind: "sha1" };
  if (HEX.test(s) && s.length === 32) return { artifact: s, kind: "md5" };
  if (IPV4.test(s)) return { artifact: s, kind: "ipv4" };
  if (s.includes(":") && /^[0-9a-f:]+$/i.test(s)) return { artifact: s, kind: "ipv6" };
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s) && !s.includes(" ")) return { artifact: s, kind: "domain" };
  return { error: "Couldn't recognize that as a hash, IP, domain, or URL." };
}

function detectReconSubject(v: string): Record<string, unknown> | { error: string } {
  const s = v.trim();
  if (!s) return { error: "Enter a domain or email address." };
  if (s.includes("@")) {
    if (/^[^\s@]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(s)) return { query: s, kind: "email" };
    return { error: "That doesn't look like a valid email address." };
  }
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s)) return { query: s, kind: "domain" };
  return { error: "Enter a valid domain (example.com) or email address." };
}

function parseHashes(v: string): Record<string, unknown> | { error: string } {
  const parts = v.split(/[\s,]+/).map((h) => h.trim()).filter(Boolean);
  const valid = parts.filter((h) => HEX.test(h) && [32, 40, 64].includes(h.length));
  if (valid.length === 0) return { error: "Enter one or more MD5 / SHA-1 / SHA-256 hashes." };
  if (valid.length > 25) return { error: "Up to 25 hashes at a time." };
  return { hashes: valid };
}

// ── the tool registry ─────────────────────────────────────────────────────────

export const AGENT_TOOLS: Record<string, AgentToolConfig> = {
  ngsiem: {
    endpoint: "/api/ngsiem",
    webhookTitle: "NGSIEM query",
    webhookSource: "ngsiem",
    hint: <p className="text-sm text-neutral-500">Your question translates to CQL and runs against the live tenant. Results appear here.</p>,
    input: {
      placeholder: "e.g. Show cmd.exe spawned by winword.exe in the last 24 hours",
      buildBody: (v) => ({ input: v }),
    },
  },
  pivot: {
    endpoint: "/api/lookup",
    webhookTitle: "Artifact lookup",
    webhookSource: "lookup",
    hint: <p className="text-sm text-neutral-500">Cross-source reputation, custom-list status, and tenant exposure for one indicator.</p>,
    input: {
      placeholder: "Paste a hash, IP, domain, or URL",
      rows: 2,
      submitLabel: "Look up",
      buildBody: detectArtifact,
    },
  },
  recon: {
    endpoint: "/api/recon",
    webhookTitle: "Exposure recon",
    webhookSource: "recon",
    hint: <p className="text-sm text-neutral-500">Breach, dark-web, paste, and Telegram exposure for a domain or email.</p>,
    input: {
      placeholder: "example.com  or  user@example.com",
      rows: 2,
      submitLabel: "Scan",
      buildBody: detectReconSubject,
    },
  },
  malquery: {
    endpoint: "/api/malquery",
    webhookTitle: "MalQuery lineage",
    webhookSource: "malquery",
    hint: <p className="text-sm text-neutral-500">Prevalence, family, and tenant exposure for file hashes from CrowdStrike's malware corpus.</p>,
    input: {
      placeholder: "One or more file hashes (comma or space separated)",
      rows: 2,
      submitLabel: "Search",
      buildBody: parseHashes,
    },
  },
  briefing: {
    endpoint: "/api/briefing",
    webhookTitle: "Daily briefing",
    webhookSource: "briefing",
    hint: <p className="text-sm text-neutral-500">Generating today's one-page security briefing for this tenant…</p>,
    instant: { body: {} },
  },
  intel: {
    endpoint: "/api/intel",
    webhookTitle: "Adversary intel",
    webhookSource: "intel",
    hint: <p className="text-sm text-neutral-500">Compiling the adversaries with evidence in this tenant…</p>,
    instant: { body: {} },
  },
  identity: {
    endpoint: "/api/identity",
    webhookTitle: "Identity posture",
    webhookSource: "identity",
    hint: <p className="text-sm text-neutral-500">Assessing risky identities, active IDP detections, and sensor posture…</p>,
    instant: { body: {} },
  },
  discover: {
    endpoint: "/api/discover",
    webhookTitle: "Asset discovery",
    webhookSource: "discover",
    hint: <p className="text-sm text-neutral-500">Reviewing asset, application, and account inventory for coverage gaps…</p>,
    instant: { body: {} },
  },
  correlation: {
    endpoint: "/api/correlation",
    webhookTitle: "Correlation-rule health",
    webhookSource: "correlation",
    hint: <p className="text-sm text-neutral-500">Reviewing NGSIEM correlation-rule health — coverage, stale, inactive…</p>,
    instant: { body: {} },
  },
  guardian: {
    endpoint: "/api/guardian",
    webhookTitle: "AI agent activity",
    webhookSource: "guardian",
    hint: <p className="text-sm text-neutral-500">Reviewing AI agents, sessions, models, and Agentic Threat Scores in this tenant…</p>,
    instant: { body: {} },
  },
  "guardian-prompts": {
    endpoint: "/api/guardian/prompts",
    webhookTitle: "AI agent prompts",
    webhookSource: "guardian",
    hint: (
      <p className="text-sm text-neutral-500">
        Ask about what users have prompted AI agents in this tenant — the answer quotes the actual prompt text from Guardian.
      </p>
    ),
    input: {
      placeholder:
        "e.g. Show recent prompts on host WS-FIN-0042 · Any prompts trying to access secrets? · What was prompted in the flagged Claude Code sessions?",
      rows: 2,
      submitLabel: "Ask",
      buildBody: (v) => ({ input: v }),
    },
  },
};
