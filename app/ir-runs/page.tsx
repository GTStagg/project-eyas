import { ShieldAlert, AlertTriangle, CheckCircle2, XCircle, Clock, ArrowUpRight, ShieldCheck, Pause, Activity } from "lucide-react";
import Link from "next/link";
import AppShell from "@/components/AppShell";
import PageHero from "@/components/PageHero";
import { listRecords, recordBasenameFor, totalUsdForRun, type IrRunRecord, type ToolCallRecord, type TurnRecord } from "@/lib/chat/ir-run-record";
import { deriveDisposition, extractOutcome, type RunDisposition } from "@/lib/chat/ir-run-analysis";
import { getAnthropicModel } from "@/lib/llm/anthropic";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function fmtAbs(ts: number): string {
  return new Date(ts).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function fmtRel(deltaMs: number): string {
  const sec = Math.round(deltaMs / 1000);
  if (sec < 90) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min} min ago`;
  const hr = Math.round(min / 60);
  if (hr < 36) return `${hr}h ago`;
  const days = Math.round(hr / 24);
  return `${days}d ago`;
}

function fmtDuration(ms: number | undefined): string {
  if (ms === undefined) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

function fmtUsd(n: number): string {
  if (n === 0) return "$0.00";
  if (n < 0.01) return `$${n.toFixed(4)}`;
  return `$${n.toFixed(2)}`;
}

function runHasErrors(record: IrRunRecord): boolean {
  return record.turns.some(
    (t) =>
      t.status === "errored" ||
      t.toolCalls.some((c) => c.result?.isError === true),
  );
}

function StatusPill({ status }: { status: TurnRecord["status"] }) {
  const map: Record<TurnRecord["status"], { label: string; cls: string; icon: typeof CheckCircle2 }> = {
    completed: {
      label: "Completed",
      cls: "border-emerald-800/60 bg-emerald-950/40 text-emerald-200",
      icon: CheckCircle2,
    },
    cancelled: {
      label: "Cancelled",
      cls: "border-amber-800/60 bg-amber-950/40 text-amber-200",
      icon: Clock,
    },
    errored: {
      label: "Errored",
      cls: "border-red-800/60 bg-red-950/40 text-oxblood-200",
      icon: XCircle,
    },
  };
  const { label, cls, icon: Icon } = map[status];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-mono uppercase tracking-wide ${cls}`}>
      <Icon className="h-3 w-3" strokeWidth={2} />
      {label}
    </span>
  );
}

function ApprovalChip({ approval }: { approval: ToolCallRecord["approval"] }) {
  if (approval === "none") {
    return <span className="font-mono text-[11px] text-neutral-500">read</span>;
  }
  const map: Record<Exclude<ToolCallRecord["approval"], "none">, string> = {
    allow: "border-emerald-800/60 bg-emerald-950/40 text-emerald-200",
    deny: "border-red-800/60 bg-red-950/40 text-oxblood-200",
    timeout: "border-amber-800/60 bg-amber-950/40 text-amber-200",
  };
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide ${map[approval]}`}>
      {approval}
    </span>
  );
}

function ToolCallRow({ call }: { call: ToolCallRecord }) {
  const errored = call.result?.isError === true;
  return (
    <details className="group rounded border border-neutral-800/80 bg-neutral-950/60 px-3 py-2 open:border-neutral-700">
      <summary className="flex cursor-pointer items-center gap-3 text-sm text-neutral-200">
        <span className={`font-mono text-xs ${errored ? "text-oxblood-300" : "text-neutral-300"}`}>
          {call.name}
        </span>
        <ApprovalChip approval={call.approval} />
        {errored && (
          <span className="inline-flex items-center gap-1 rounded border border-red-800/60 bg-red-950/40 px-1.5 py-0.5 font-mono text-[10px] text-oxblood-200">
            <AlertTriangle className="h-3 w-3" strokeWidth={2} />
            errored
          </span>
        )}
        <span className="ml-auto font-mono text-[11px] text-neutral-500">
          {fmtDuration(call.result?.durationMs)}
        </span>
      </summary>
      <div className="mt-3 space-y-3">
        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-neutral-500">
            Input
          </div>
          <pre className="overflow-x-auto rounded bg-neutral-900/60 px-3 py-2 font-mono text-[11px] text-neutral-300">
            {JSON.stringify(call.input, null, 2)}
          </pre>
        </div>
        {call.result && (
          <div>
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-neutral-500">
              Result excerpt
            </div>
            <pre className="overflow-x-auto rounded bg-neutral-900/60 px-3 py-2 font-mono text-[11px] text-neutral-300 whitespace-pre-wrap">
              {call.result.contentExcerpt}
            </pre>
          </div>
        )}
      </div>
    </details>
  );
}

function TurnBlock({ turn }: { turn: TurnRecord }) {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950/60 p-4">
      <div className="flex flex-wrap items-center gap-3 text-sm text-neutral-200">
        <span className="font-mono text-xs uppercase tracking-wide text-neutral-500">
          Turn {turn.turnIndex}
        </span>
        <StatusPill status={turn.status} />
        <span className="text-neutral-500">·</span>
        <span className="text-neutral-400">
          {turn.toolCalls.length} action{turn.toolCalls.length === 1 ? "" : "s"}
        </span>
        <span className="text-neutral-500">·</span>
        <span className="text-neutral-400">{turn.iterations} iteration{turn.iterations === 1 ? "" : "s"}</span>
        <span className="ml-auto font-mono text-[11px] text-neutral-500">
          {fmtAbs(turn.startedAt)}
        </span>
      </div>
      {turn.userInput && (
        <div className="mt-3 rounded border border-neutral-800/60 bg-neutral-900/40 px-3 py-2 font-mono text-[11px] text-neutral-400">
          {turn.userInput.length > 280 ? turn.userInput.slice(0, 280) + "…" : turn.userInput}
        </div>
      )}
      {turn.toolCalls.length > 0 && (
        <div className="mt-3 space-y-2">
          {turn.toolCalls.map((c) => (
            <ToolCallRow key={c.id} call={c} />
          ))}
        </div>
      )}
    </div>
  );
}

const DISPOSITION_PILL: Record<RunDisposition, { label: string; cls: string; icon: typeof CheckCircle2 }> = {
  remediated: { label: "Remediated", cls: "border-emerald-800/60 bg-emerald-950/40 text-emerald-200", icon: CheckCircle2 },
  released: { label: "Released", cls: "border-emerald-800/60 bg-emerald-950/40 text-emerald-200", icon: ShieldCheck },
  held: { label: "Held for review", cls: "border-amber-800/60 bg-amber-950/40 text-amber-200", icon: Pause },
  in_progress: { label: "In progress", cls: "border-sky-800/60 bg-sky-950/40 text-sky-200", icon: Activity },
  errored: { label: "Errored", cls: "border-red-800/60 bg-red-950/40 text-oxblood-200", icon: XCircle },
  no_findings: { label: "No action taken", cls: "border-neutral-800 bg-neutral-950/40 text-neutral-300", icon: CheckCircle2 },
};

function RunCard({ record, modelId }: { record: IrRunRecord; modelId: string }) {
  const errors = runHasErrors(record);
  const totalIterations = record.turns.reduce((acc, t) => acc + (t.iterations ?? 0), 0);
  const totalActions = record.turns.reduce((acc, t) => acc + t.toolCalls.length, 0);
  const totalUsd = totalUsdForRun(record, modelId);
  const detailHref = `/ir-runs/${encodeURIComponent(recordBasenameFor(record.aid, record.startedAt))}`;
  const outcome = extractOutcome(record);
  const disposition = deriveDisposition(record, outcome);
  const pill = DISPOSITION_PILL[disposition];
  return (
    <details className="group rounded-lg border border-neutral-800 bg-neutral-950 shadow-lg shadow-black/40 open:border-neutral-700">
      <summary className="flex cursor-pointer flex-col gap-3 p-5 sm:flex-row sm:items-center sm:gap-6">
        <div className="flex min-w-0 flex-1 items-center gap-3">
          <div
            className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border ${
              errors
                ? "border-red-900/60 bg-red-950/40 text-oxblood-300"
                : "border-brand-900/40 bg-brand-950/40 text-oxblood-400"
            }`}
          >
            <ShieldAlert className="h-5 w-5" strokeWidth={1.75} />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <div className="font-mono text-xs uppercase tracking-wide text-neutral-500">Host</div>
              <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${pill.cls}`}>
                <pill.icon className="h-3 w-3" strokeWidth={2} />
                {pill.label}
              </span>
            </div>
            <div className="truncate font-mono text-sm text-neutral-200">{record.aid}</div>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
          <Stat label="Last activity" value={fmtRel(Date.now() - record.lastTouched)} hint={fmtAbs(record.lastTouched)} />
          <Stat
            label="Closed"
            value={String(outcome.detectionsClosed)}
            hint={outcome.ledgerEvidenceCaptured ? "ledger-driven" : outcome.bulkClosedHost ? "bulk" : undefined}
          />
          <Stat
            label="Left open"
            value={String(outcome.detectionsLeftOpen)}
            hint={outcome.detectionsLeftOpen > 0 ? "for review" : undefined}
          />
          <Stat label="Cost" value={fmtUsd(totalUsd)} hint={`${totalActions} actions`} />
        </div>
        {errors && (
          <span className="inline-flex items-center gap-1.5 self-start rounded-full border border-red-800/60 bg-red-950/40 px-2 py-0.5 text-[11px] font-mono uppercase tracking-wide text-oxblood-200 sm:self-center">
            <AlertTriangle className="h-3 w-3" strokeWidth={2} />
            errors
          </span>
        )}
      </summary>
      <div className="space-y-4 border-t border-neutral-800 px-5 py-5">
        <div className="flex items-center justify-between gap-3">
          <div className="grid flex-1 grid-cols-2 gap-3 text-xs text-neutral-400 sm:grid-cols-4">
            <Kv label="Started" value={fmtAbs(record.startedAt)} />
            <Kv label="Total iterations" value={String(totalIterations)} />
            <Kv
              label="Playbook"
              value={record.playbook.ok ? "Loaded" : `Error: ${record.playbook.error ?? "unknown"}`}
            />
            <Kv label="Session" value={record.sessionId} mono />
          </div>
          <Link
            href={detailHref}
            className="inline-flex shrink-0 items-center gap-1.5 self-start rounded border border-brand-800/60 bg-brand-950/40 px-3 py-1.5 font-mono text-[11px] uppercase tracking-wide text-oxblood-200 transition hover:border-brand-700 hover:text-white"
          >
            Open replay
            <ArrowUpRight className="h-3 w-3" strokeWidth={2} />
          </Link>
        </div>
        {record.turns.length === 0 ? (
          <div className="rounded border border-dashed border-neutral-800 bg-neutral-950/50 px-4 py-6 text-center text-sm text-neutral-500">
            No turns recorded yet — this run was created on entry but no
            assistant turn finished. The most likely cause is a cancelled
            session before the agent's first response.
          </div>
        ) : (
          <div className="space-y-3">
            {record.turns.map((t) => (
              <TurnBlock key={`${t.turnIndex}-${t.startedAt}`} turn={t} />
            ))}
          </div>
        )}
      </div>
    </details>
  );
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div>
      <div className="text-[11px] font-mono uppercase tracking-wide text-neutral-500">
        {label}
      </div>
      <div className="text-sm text-neutral-200">{value}</div>
      {hint && <div className="font-mono text-[10px] text-neutral-600">{hint}</div>}
    </div>
  );
}

function Kv({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-[11px] font-mono uppercase tracking-wide text-neutral-500">
        {label}
      </div>
      <div className={`text-neutral-300 ${mono ? "font-mono text-xs break-all" : "text-sm"}`}>
        {value}
      </div>
    </div>
  );
}

export default async function IrRunsPage() {
  const records = await listRecords();
  const modelId = getAnthropicModel();
  return (
    <AppShell title="IR runs">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up space-y-8">
          <PageHero
            icon={ShieldAlert}
            eyebrow="Audit trail"
            title="Incident-response engagements run from this console."
            subtitle="Every IR workflow you've launched, with the captured scope and per-turn actions kept on disk for after-the-fact review."
          />
          {records.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-neutral-800 bg-neutral-950/60 p-12 text-center">
              <div className="flex h-10 w-10 items-center justify-center rounded-full border border-brand-900/60 bg-brand-950/40 text-oxblood-300">
                <ShieldAlert className="h-5 w-5" strokeWidth={1.75} />
              </div>
              <div className="text-lg font-semibold text-white">No IR runs yet.</div>
              <div className="max-w-md text-sm text-neutral-400">
                Launch the IR workflow on a host from the queue or the host detail
                view; an entry will appear here as soon as the engagement starts.
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              {records.map((r) => (
                <RunCard key={`${r.aid}-${r.startedAt}`} record={r} modelId={modelId} />
              ))}
            </div>
          )}
        </div>
      </main>
    </AppShell>
  );
}
