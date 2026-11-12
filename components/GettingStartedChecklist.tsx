"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  CheckCircle2,
  Circle,
  ArrowRight,
  Loader2,
  AlertTriangle,
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  KeyRound,
  Activity,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

// Post-wizard activation checklist. Reads state from existing diagnostic
// endpoints, renders one row per step with a CTA pointing at the
// relevant /config / setup surface. Each row is independently
// loading/ok/needs-action so a single slow probe doesn't stall the page.

type Status = "loading" | "ok" | "needs-action" | "error";

type Row = {
  key: string;
  title: string;
  description: string;
  icon: LucideIcon;
  href: string;
  ctaLabel: string;
  status: Status;
  detail?: string;
};

export default function GettingStartedChecklist() {
  const [rows, setRows] = useState<Row[]>(() => initialRows());

  useEffect(() => {
    let cancelled = false;
    void Promise.all([
      probeHealth(),
      probeIrQuarantine(),
      probeShadowAi(),
    ]).then(([health, ir, shadow]) => {
      if (cancelled) return;
      setRows((prev) =>
        prev.map((r) => {
          if (r.key === "anthropic") return mergeHealthRow(r, health, "anthropic");
          if (r.key === "falcon") return mergeHealthRow(r, health, "falcon");
          if (r.key === "scopes") return mergeScopesRow(r, health);
          if (r.key === "ir-quarantine") return mergeIrRow(r, ir);
          if (r.key === "shadow-ai") return mergeShadowAiRow(r, shadow);
          return r;
        }),
      );
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const remaining = rows.filter((r) => r.status === "needs-action").length;
  const total = rows.length;
  const ready = rows.every((r) => r.status === "ok");

  return (
    <section className="space-y-5">
      <header className="flex flex-col gap-2 rounded-lg border border-neutral-800 bg-neutral-950 p-6 shadow-lg shadow-black/40 sm:flex-row sm:items-end sm:justify-between sm:gap-6">
        <div>
          <div className="text-xs font-mono uppercase tracking-[0.14em] text-oxblood-400">
            Welcome
          </div>
          <h1 className="mt-1.5 text-3xl font-semibold tracking-tight text-white">
            Activate full functionality
          </h1>
          <p className="mt-1.5 max-w-2xl text-sm text-neutral-400">
            The wizard saved your credentials. The rest of the platform's
            value — agentic incident response, Shadow-AI enforcement, full
            Falcon scope coverage — depends on a few one-time tenant
            provisioning steps. Each row below probes its current state and
            points you at the right surface to complete it.
          </p>
        </div>
        <div className="shrink-0 text-right">
          {ready ? (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-800/60 bg-emerald-950/30 px-3 py-1 font-mono text-[11px] uppercase tracking-wide text-emerald-200">
              <CheckCircle2 className="h-3.5 w-3.5" strokeWidth={2} />
              All steps complete
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-800/60 bg-amber-950/30 px-3 py-1 font-mono text-[11px] uppercase tracking-wide text-amber-200">
              {remaining} of {total} pending
            </span>
          )}
          <div className="mt-2">
            <Link
              href="/"
              className="inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wide text-neutral-500 hover:text-neutral-300"
            >
              Skip to app
              <ArrowRight className="h-3 w-3" strokeWidth={2} />
            </Link>
          </div>
        </div>
      </header>

      <ol className="space-y-3">
        {rows.map((r) => (
          <ChecklistRow key={r.key} row={r} />
        ))}
      </ol>
    </section>
  );
}

function ChecklistRow({ row }: { row: Row }) {
  return (
    <li className="rounded-lg border border-neutral-800 bg-neutral-950 p-5">
      <div className="flex items-start gap-4">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-neutral-800 bg-neutral-900 text-neutral-300">
          <row.icon className="h-4 w-4" strokeWidth={1.75} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-semibold text-white">{row.title}</h3>
            <StatusPill status={row.status} />
          </div>
          <p className="mt-1 text-sm text-neutral-400">{row.description}</p>
          {row.detail && (
            <p className="mt-1.5 font-mono text-[11px] text-neutral-500">{row.detail}</p>
          )}
        </div>
        {row.status !== "ok" && (
          <Link
            href={row.href}
            className="shrink-0 inline-flex items-center gap-1.5 self-start rounded border border-neutral-800 bg-neutral-900 px-3 py-1.5 font-mono text-[11px] uppercase tracking-wide text-neutral-300 hover:border-neutral-700 hover:text-white"
          >
            {row.ctaLabel}
            <ArrowRight className="h-3 w-3" strokeWidth={2} />
          </Link>
        )}
      </div>
    </li>
  );
}

function StatusPill({ status }: { status: Status }) {
  if (status === "loading") {
    return (
      <span className="inline-flex items-center gap-1 font-mono text-[10px] uppercase tracking-wide text-neutral-500">
        <Loader2 className="h-3 w-3 animate-spin" strokeWidth={2} />
        checking
      </span>
    );
  }
  if (status === "ok") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-800/60 bg-emerald-950/30 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-emerald-200">
        <CheckCircle2 className="h-3 w-3" strokeWidth={2} />
        ready
      </span>
    );
  }
  if (status === "needs-action") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-amber-800/60 bg-amber-950/30 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-amber-200">
        <Circle className="h-3 w-3" strokeWidth={2} />
        action needed
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-red-800/60 bg-red-950/30 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-oxblood-200">
      <AlertTriangle className="h-3 w-3" strokeWidth={2} />
      probe failed
    </span>
  );
}

// ---------------------------------------------------------------------------
// Initial / merging state helpers
// ---------------------------------------------------------------------------

function initialRows(): Row[] {
  return [
    {
      key: "anthropic",
      title: "Anthropic API",
      description:
        "The LLM that powers every agentic surface. Saved during registration; we just confirm the credentials authenticate.",
      icon: KeyRound,
      href: "/config",
      ctaLabel: "Open /config",
      status: "loading",
    },
    {
      key: "falcon",
      title: "CrowdStrike Falcon API",
      description:
        "The data source for every detection, host, vulnerability, and IOC. Saved during registration; we confirm the OAuth client authenticates.",
      icon: ShieldCheck,
      href: "/config",
      ctaLabel: "Open /config",
      status: "loading",
    },
    {
      key: "scopes",
      title: "Falcon API scope coverage",
      description:
        "Surfaces light up automatically as scopes are granted. Pages whose required scope isn't yet on your API client appear staged with a 'scope pending' note.",
      icon: Activity,
      href: "/status",
      ctaLabel: "Review on /status",
      status: "loading",
    },
    {
      key: "ir-quarantine",
      title: "IR quarantine setup",
      description:
        "The agentic incident-response workflow needs a dedicated host group, three platform prevention policies, and an IOA exclusion. /config has a setup card that detects what you have and provisions what you don't.",
      icon: ShieldAlert,
      href: "/config",
      ctaLabel: "Set up in /config",
      status: "loading",
    },
    {
      key: "shadow-ai",
      title: "Shadow-AI prevention",
      description:
        "Custom IOA rule group that blocks unsanctioned AI tooling at the sensor — Claude Desktop, Cursor, Ollama, LM Studio, MCP-host runtimes, etc. Configured from /shadow-ai.",
      icon: Sparkles,
      href: "/shadow-ai",
      ctaLabel: "Open /shadow-ai",
      status: "loading",
    },
  ];
}

type HealthLite = {
  anthropic?: { status?: string; message?: string };
  falconMcp?: { status?: string; message?: string; capabilities?: Record<string, boolean> };
};

async function probeHealth(): Promise<HealthLite | null> {
  try {
    const r = await fetch("/api/health");
    if (!r.ok) return null;
    return (await r.json()) as HealthLite;
  } catch {
    return null;
  }
}

async function probeIrQuarantine(): Promise<{ ok?: boolean; case?: string } | null> {
  try {
    const r = await fetch("/api/ir-quarantine/diagnose");
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

async function probeShadowAi(): Promise<{ ok?: boolean; ready?: boolean; missing_steps?: string[] } | null> {
  try {
    const r = await fetch("/api/shadow-ai/audit");
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

function mergeHealthRow(row: Row, h: HealthLite | null, which: "anthropic" | "falcon"): Row {
  if (!h) return { ...row, status: "error", detail: "Couldn't reach /api/health." };
  const probe = which === "anthropic" ? h.anthropic : h.falconMcp;
  const status = probe?.status;
  if (status === "ok") return { ...row, status: "ok" };
  if (status === "disabled") return { ...row, status: "needs-action", detail: probe?.message };
  return { ...row, status: "needs-action", detail: probe?.message ?? "Probe didn't return ok." };
}

function mergeScopesRow(row: Row, h: HealthLite | null): Row {
  if (!h) return { ...row, status: "error", detail: "Couldn't reach /api/health." };
  // A surface's flag is false only on a confirmed scope denial.
  const caps = h.falconMcp?.capabilities ?? {};
  const pending = Object.entries(caps).filter(([, v]) => v === false);
  if (pending.length === 0) return { ...row, status: "ok" };
  return {
    ...row,
    status: "needs-action",
    detail: `${pending.length} surface${pending.length === 1 ? "" : "s"} pending scope grant: ${pending.map(([k]) => k).join(", ")}`,
  };
}

function mergeIrRow(row: Row, ir: { ok?: boolean; case?: string } | null): Row {
  if (!ir || ir.ok === false) return { ...row, status: "error", detail: "IR diagnostic returned an error." };
  if (ir.case === "ready") return { ...row, status: "ok" };
  if (ir.case === "no_group_id") return { ...row, status: "needs-action", detail: "No quarantine host group is set." };
  if (ir.case === "group_missing")
    return { ...row, status: "needs-action", detail: "Configured group id doesn't exist in Falcon." };
  if (ir.case === "A_no_policy")
    return { ...row, status: "needs-action", detail: "Group has no dedicated prevention policy attached." };
  if (ir.case === "B_dedicated_single_group")
    return { ...row, status: "needs-action", detail: "Quarantine policy needs to be standardized to AGGRESSIVE + IR exclusions." };
  if (ir.case === "C_shared_policy")
    return { ...row, status: "needs-action", detail: "Quarantine policy is shared with other groups — needs a dedicated one." };
  return { ...row, status: "needs-action", detail: ir.case ?? "Unknown state" };
}

function mergeShadowAiRow(row: Row, s: { ok?: boolean; ready?: boolean; missing_steps?: string[] } | null): Row {
  if (!s) return { ...row, status: "error", detail: "Shadow-AI diagnostic unreachable." };
  if (s.ok === false) return { ...row, status: "error", detail: "Shadow-AI diagnostic returned an error." };
  if (s.ready) return { ...row, status: "ok" };
  const detail = s.missing_steps && s.missing_steps.length
    ? s.missing_steps.join("; ")
    : "Prevention bundle not yet adopted on this tenant.";
  return { ...row, status: "needs-action", detail };
}
