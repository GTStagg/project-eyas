import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronLeft,
  Lock,
  Unlock,
  Trash2,
  Activity,
  ShieldCheck,
  Pause,
} from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import AppShell from "@/components/AppShell";
import PageHero from "@/components/PageHero";
import CopyShareLink from "@/components/CopyShareLink";
import IrReportPanel from "@/components/IrReportPanel";
import {
  readRecord,
  totalUsdForRun,
  type IrRunRecord,
  type ToolCallRecord,
  type TurnRecord,
} from "@/lib/chat/ir-run-record";
import {
  callsByPhase,
  classifyCalls,
  deriveDisposition,
  extractGuardrails,
  extractOutcome,
  PHASE_LABEL,
  runHasErrors,
  turnsTotalActions,
  turnsTotalIterations,
  type Guardrail,
  type Outcome,
  type Phase,
  type RunDisposition,
} from "@/lib/chat/ir-run-analysis";
import { getAnthropicModel } from "@/lib/llm/anthropic";
import { getActiveEnvironmentId } from "@/lib/config/environments";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function fmtAbs(ts: number): string {
  return new Date(ts).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
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

function fmtSpan(start: number, end: number): string {
  const sec = Math.round((end - start) / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min} min`;
  const hr = (min / 60).toFixed(1);
  return `${hr}h`;
}

const DISPOSITION_LABEL: Record<RunDisposition, { label: string; cls: string; icon: typeof CheckCircle2 }> = {
  remediated: {
    label: "Remediated",
    cls: "border-emerald-800/60 bg-emerald-950/40 text-emerald-200",
    icon: CheckCircle2,
  },
  released: {
    label: "Released",
    cls: "border-emerald-800/60 bg-emerald-950/40 text-emerald-200",
    icon: ShieldCheck,
  },
  held: {
    label: "Held for review",
    cls: "border-amber-800/60 bg-amber-950/40 text-amber-200",
    icon: Pause,
  },
  in_progress: {
    label: "In progress",
    cls: "border-sky-800/60 bg-sky-950/40 text-sky-200",
    icon: Activity,
  },
  errored: {
    label: "Errored",
    cls: "border-red-800/60 bg-red-950/40 text-oxblood-200",
    icon: XCircle,
  },
  no_findings: {
    label: "No action taken",
    cls: "border-neutral-800 bg-neutral-950/40 text-neutral-300",
    icon: CheckCircle2,
  },
};

function DispositionPill({ disposition }: { disposition: RunDisposition }) {
  const { label, cls, icon: Icon } = DISPOSITION_LABEL[disposition];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-mono uppercase tracking-wide ${cls}`}>
      <Icon className="h-3.5 w-3.5" strokeWidth={2} />
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

function ToolCallRow({ call, turnIndex }: { call: ToolCallRecord; turnIndex: number }) {
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
        <span className="ml-auto flex items-center gap-3 font-mono text-[11px] text-neutral-500">
          <span>turn {turnIndex}</span>
          <span>{fmtDuration(call.result?.durationMs)}</span>
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

function PhaseBlock({
  phase,
  calls,
}: {
  phase: Phase;
  calls: ReturnType<typeof classifyCalls>;
}) {
  if (calls.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-neutral-900 bg-neutral-950/40 px-4 py-3">
        <PhaseHeader phase={phase} count={0} />
        <div className="mt-1 font-mono text-[11px] text-neutral-600">
          {phase === 0
            ? "No discovery calls recorded."
            : phase === 1
              ? "No quarantine action — host stayed in its original groups."
              : phase === 2
                ? "No remediation actions taken."
                : phase === 3
                  ? "No verification scope captured."
                  : "Workflow did not reach closure."}
        </div>
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950/60 p-4">
      <PhaseHeader phase={phase} count={calls.length} />
      <div className="mt-3 space-y-2">
        {calls.map((c) => (
          <ToolCallRow key={c.call.id} call={c.call} turnIndex={c.turnIndex} />
        ))}
      </div>
    </div>
  );
}

function PhaseHeader({ phase, count }: { phase: Phase; count: number }) {
  return (
    <div className="flex items-center gap-3">
      <span className="inline-flex h-6 w-6 items-center justify-center rounded-full border border-brand-800/50 bg-brand-950/40 font-mono text-[10px] text-oxblood-300">
        {phase}
      </span>
      <span className="text-sm font-semibold text-neutral-200">
        Phase {phase} — {PHASE_LABEL[phase]}
      </span>
      <span className="font-mono text-[11px] text-neutral-500">
        {count} action{count === 1 ? "" : "s"}
      </span>
    </div>
  );
}

function OutcomePanel({ outcome }: { outcome: Outcome }) {
  const rows: { icon: typeof Lock; label: string; value: string; tone?: "ok" | "warn" | "neutral" }[] = [];
  if (outcome.hostQuarantined || outcome.hostReleased) {
    rows.push({
      icon: outcome.hostReleased ? Unlock : Lock,
      label: outcome.hostReleased ? "Host released from quarantine" : "Host moved into quarantine group",
      value: outcome.hostReleased ? "Released" : "Quarantined",
      tone: outcome.hostReleased ? "ok" : "warn",
    });
  }
  if (outcome.hostContained || outcome.hostContainmentLifted) {
    rows.push({
      icon: outcome.hostContainmentLifted ? Unlock : Lock,
      label: outcome.hostContainmentLifted ? "Network containment lifted" : "Network containment applied",
      value: outcome.hostContainmentLifted ? "Lifted" : "Contained",
      tone: outcome.hostContainmentLifted ? "ok" : "warn",
    });
  }
  for (const c of outcome.cleanupActions) {
    rows.push({
      icon: Trash2,
      label: c.scriptId,
      value: `${c.count} run${c.count === 1 ? "" : "s"}`,
    });
  }
  if (outcome.iocsAdded > 0) {
    rows.push({
      icon: ShieldAlert,
      label: "Custom IOCs added to tenant watchlist",
      value: String(outcome.iocsAdded),
    });
  }
  if (outcome.iocsRemoved > 0) {
    rows.push({
      icon: ShieldAlert,
      label: "Custom IOCs removed",
      value: String(outcome.iocsRemoved),
    });
  }
  if (outcome.exclusionsAdded > 0) {
    rows.push({
      icon: ShieldCheck,
      label: "Detection exclusions created",
      value: String(outcome.exclusionsAdded),
    });
  }
  if (outcome.detectionsClosed > 0) {
    rows.push({
      icon: CheckCircle2,
      label: outcome.bulkClosedHost
        ? "Detections closed (bulk)"
        : outcome.ledgerEvidenceCaptured
          ? "Detections closed with per-id ledger evidence"
          : "Detections closed",
      value: String(outcome.detectionsClosed),
      tone: "ok",
    });
  }
  if (outcome.detectionsLeftOpen > 0) {
    rows.push({
      icon: AlertTriangle,
      label: "Detections left open — no Phase 2 action touched their evidence",
      value: String(outcome.detectionsLeftOpen),
      tone: "warn",
    });
  }

  return (
    <section className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-950 p-5">
      <div className="flex items-center justify-between">
        <h2 className="font-mono text-xs uppercase tracking-wide text-neutral-500">
          What changed on this host
        </h2>
        {outcome.ledgerEvidenceCaptured && (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-800/60 bg-emerald-950/40 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-emerald-200">
            <ShieldCheck className="h-3 w-3" strokeWidth={2} />
            ledger-driven closure
          </span>
        )}
      </div>
      {rows.length === 0 ? (
        <div className="rounded border border-dashed border-neutral-800 bg-neutral-950/50 px-4 py-4 text-sm text-neutral-500">
          No remediating actions recorded for this run. Either the workflow ran
          read-only Phase 0 and stopped (clean host), or the operator denied
          every gated action.
        </div>
      ) : (
        <ul className="divide-y divide-neutral-900">
          {rows.map((r, i) => (
            <li key={i} className="flex items-center justify-between gap-3 py-2.5 text-sm">
              <div className="flex min-w-0 items-center gap-3">
                <r.icon
                  className={`h-4 w-4 shrink-0 ${
                    r.tone === "ok"
                      ? "text-emerald-300"
                      : r.tone === "warn"
                        ? "text-amber-300"
                        : "text-neutral-400"
                  }`}
                  strokeWidth={1.75}
                />
                <span className="truncate text-neutral-200">{r.label}</span>
              </div>
              <span
                className={`shrink-0 font-mono text-xs ${
                  r.tone === "ok"
                    ? "text-emerald-200"
                    : r.tone === "warn"
                      ? "text-amber-200"
                      : "text-neutral-300"
                }`}
              >
                {r.value}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

const GUARDRAIL_TONE: Record<Guardrail["kind"], { label: string; cls: string }> = {
  approval_denied: {
    label: "Operator gate",
    cls: "border-red-800/60 bg-red-950/30 text-oxblood-200",
  },
  approval_timeout: {
    label: "Approval timeout",
    cls: "border-amber-800/60 bg-amber-950/30 text-amber-200",
  },
  tool_errored: {
    label: "Upstream error",
    cls: "border-red-800/60 bg-red-950/30 text-oxblood-200",
  },
  scope_pending: {
    label: "Staged build",
    cls: "border-sky-800/60 bg-sky-950/30 text-sky-200",
  },
  anchor_recovered: {
    label: "Anchor recovery",
    cls: "border-emerald-800/60 bg-emerald-950/30 text-emerald-200",
  },
  retrospective_classified: {
    label: "Retrospective filter",
    cls: "border-emerald-800/60 bg-emerald-950/30 text-emerald-200",
  },
  workflow_self_classified: {
    label: "Self-trigger filter",
    cls: "border-emerald-800/60 bg-emerald-950/30 text-emerald-200",
  },
  unmatched_left_open: {
    label: "Ledger boundary",
    cls: "border-amber-800/60 bg-amber-950/30 text-amber-200",
  },
  cql_lint_blocked: {
    label: "CQL lint",
    cls: "border-emerald-800/60 bg-emerald-950/30 text-emerald-200",
  },
};

function GuardrailsPanel({ guardrails }: { guardrails: Guardrail[] }) {
  return (
    <section className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-950 p-5">
      <div>
        <h2 className="font-mono text-xs uppercase tracking-wide text-neutral-500">
          What the system caught
        </h2>
        <p className="mt-1 text-xs text-neutral-500">
          Guardrails that fired during the run — denied writes, timed-out approvals, deterministic classifiers, and pre-flight filters that prevented bad actions from reaching the tenant.
        </p>
      </div>
      {guardrails.length === 0 ? (
        <div className="rounded border border-dashed border-neutral-800 bg-neutral-950/50 px-4 py-4 text-sm text-neutral-500">
          No guardrails fired. Every approval was granted, no tool errored, and no deterministic classifier needed to flag a result.
        </div>
      ) : (
        <ul className="space-y-2">
          {guardrails.map((g, i) => {
            const tone = GUARDRAIL_TONE[g.kind];
            return (
              <li
                key={i}
                className={`flex items-start gap-3 rounded border px-3 py-2 ${tone.cls}`}
              >
                <span className="mt-0.5 shrink-0 rounded border border-current/40 bg-black/20 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide">
                  {tone.label}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-sm">{g.detail}</div>
                  <div className="mt-0.5 font-mono text-[10px] uppercase tracking-wide opacity-70">
                    {g.toolName}
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

function MetricCard({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-4">
      <div className="font-mono text-[10px] uppercase tracking-wide text-neutral-500">
        {label}
      </div>
      <div className="mt-1.5 text-xl font-semibold text-white">{value}</div>
      {hint && <div className="mt-0.5 font-mono text-[10px] text-neutral-600">{hint}</div>}
    </div>
  );
}

function TurnBreadcrumb({ turn }: { turn: TurnRecord }) {
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
  const { label, cls, icon: Icon } = map[turn.status];
  return (
    <div className="flex flex-wrap items-center gap-3 rounded border border-neutral-900 bg-neutral-950/40 px-3 py-2 text-xs">
      <span className="font-mono text-[10px] uppercase tracking-wide text-neutral-500">
        Turn {turn.turnIndex}
      </span>
      <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${cls}`}>
        <Icon className="h-3 w-3" strokeWidth={2} />
        {label}
      </span>
      <span className="text-neutral-500">{turn.toolCalls.length} actions</span>
      <span className="text-neutral-500">·</span>
      <span className="text-neutral-500">{turn.iterations} iterations</span>
      <span className="ml-auto font-mono text-[10px] text-neutral-600">
        {fmtAbs(turn.startedAt)}
      </span>
    </div>
  );
}

export default async function IrRunDetailPage({
  params,
}: {
  params: Promise<{ file: string }>;
}) {
  const { file } = await params;
  // Strict basename — refuse anything containing a path separator or ..
  if (file.includes("/") || file.includes("\\") || file.includes("..")) notFound();
  const record: IrRunRecord | null = await readRecord(decodeURIComponent(file));
  if (!record) notFound();

  const modelId = getAnthropicModel();
  const outcome = extractOutcome(record);
  const guardrails = extractGuardrails(record);
  const buckets = callsByPhase(record);
  const disposition = deriveDisposition(record, outcome);
  const totalUsd = totalUsdForRun(record, modelId);
  const errored = runHasErrors(record);
  // A report is a per-tenant artifact; the route refuses an engagement from
  // another environment. Surface that state in the panel rather than offering a
  // button that would 404.
  const crossTenant = record.envId != null && record.envId !== getActiveEnvironmentId();

  return (
    <AppShell title={`IR run · ${record.aid.slice(0, 8)}…`}>
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up space-y-6">
          <Link
            href="/ir-runs"
            className="inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wide text-neutral-500 hover:text-neutral-300"
          >
            <ChevronLeft className="h-3 w-3" strokeWidth={2} />
            All IR runs
          </Link>

          <PageHero
            icon={ShieldAlert}
            eyebrow="IR engagement"
            title={
              <span className="font-mono">
                {record.aid}
              </span>
            }
            subtitle={
              <span>
                Started {fmtAbs(record.startedAt)} · Wall-clock{" "}
                {fmtSpan(record.startedAt, record.lastTouched)} · {record.turns.length} turn
                {record.turns.length === 1 ? "" : "s"}
              </span>
            }
            right={
              <div className="flex flex-col items-end gap-2">
                <DispositionPill disposition={disposition} />
                <CopyShareLink href={`/ir-runs/${encodeURIComponent(file)}`} />
              </div>
            }
          />

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <MetricCard
              label="Actions"
              value={String(turnsTotalActions(record.turns))}
              hint={`${turnsTotalIterations(record.turns)} agent iterations`}
            />
            <MetricCard
              label="Detections closed"
              value={String(outcome.detectionsClosed)}
              hint={
                outcome.detectionsLeftOpen > 0
                  ? `${outcome.detectionsLeftOpen} left open for review`
                  : outcome.ledgerEvidenceCaptured
                    ? "ledger-driven"
                    : undefined
              }
            />
            <MetricCard
              label="Guardrails fired"
              value={String(guardrails.length)}
              hint={errored ? "includes errored tools" : undefined}
            />
            <MetricCard
              label="Run cost"
              value={fmtUsd(totalUsd)}
              hint={`projected at ${modelId}`}
            />
          </div>

          <IrReportPanel file={file} aid={record.aid} crossTenant={crossTenant} />

          <div className="grid gap-4 lg:grid-cols-2">
            <OutcomePanel outcome={outcome} />
            <GuardrailsPanel guardrails={guardrails} />
          </div>

          <section className="space-y-3">
            <div>
              <h2 className="font-mono text-xs uppercase tracking-wide text-neutral-500">
                Phase-by-phase replay
              </h2>
              <p className="mt-1 text-xs text-neutral-500">
                Tool calls grouped by IR phase, in chronological order. Read tools
                inherit the phase of the most recent classified call. Click any
                row to expand input + result excerpt.
              </p>
            </div>
            <div className="space-y-3">
              {([0, 1, 2, 3, 4] as Phase[]).map((p) => (
                <PhaseBlock key={p} phase={p} calls={buckets[p]} />
              ))}
            </div>
          </section>

          <section className="space-y-3">
            <div>
              <h2 className="font-mono text-xs uppercase tracking-wide text-neutral-500">
                Per-turn breakdown
              </h2>
              <p className="mt-1 text-xs text-neutral-500">
                Conversational turns as they happened — useful when reading the
                replay against the original chat.
              </p>
            </div>
            <div className="space-y-2">
              {record.turns.map((t) => (
                <TurnBreadcrumb key={`${t.turnIndex}-${t.startedAt}`} turn={t} />
              ))}
            </div>
          </section>
        </div>
      </main>
    </AppShell>
  );
}
