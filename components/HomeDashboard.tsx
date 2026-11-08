"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  Network,
  ListChecks,
  MessageSquare,
  Copy,
  ArrowRight,
  ArrowUpRight,
  Loader2,
  Sparkles,
  Server,
} from "lucide-react";
import { buildPrimerHref } from "./primerHandoff";
import { IrChip, endpointIrEligibility } from "./irEligibility";
import { useToast } from "./ToastProvider";
import CampaignsPanel from "./CampaignsPanel";
import SnackPanel from "./SnackPanel";
import {
  PreventionDetail,
  preventionFooter,
  ContainedDetail,
  IrRunDetail,
  irFooter,
} from "./HomeDetailPanels";
import { detName, severityTone, relTime, triagePrimer } from "./homeHelpers";
import { reconstructPrimer, type Campaign } from "@/lib/queue/campaigns";
import type { QueueRow } from "@/lib/queue/rank";
import { ControlCenterGrid, type WidgetKind } from "./home/widgets";
import { SpendPanel, spendFooter } from "./panels/SpendPanel";
import { AgentToolPanel, AGENT_TOOLS } from "./panels/AgentToolPanel";
import { useChatDock } from "./ChatDock";

// ── shapes (mirror the deterministic route payloads) ─────────────────────────

type Summary = {
  ok: true;
  generatedAt: string;
  counts: { total: number; top: number; active: number; stale: number; contained: number; hosts: number };
  campaigns: Campaign[];
  top: QueueRow[];
};

type IrRun = {
  file: string;
  aid: string;
  startedAt: number;
  lastTouched: number;
  turnsCount: number;
  hasErrors: boolean;
};

type Hero =
  | { tone: "campaign" | "ir" | "triage"; label: string; title: string; detail: string; primer: string }
  | null;

// What the right-side snack-panel is showing (null = closed). Triage list panels
// carry their data; capability tools are dataless (fetch on open).
type Panel =
  | { kind: "priority"; rows: QueueRow[] }
  | { kind: "campaigns"; campaigns: Campaign[] }
  | { kind: "prevention"; count: number }
  | { kind: "contained" }
  | { kind: "ir"; file: string; aid: string }
  | { kind: "spend" }
  | { kind: "ngsiem" }
  | { kind: "pivot" }
  | { kind: "recon" }
  | { kind: "malquery" }
  | { kind: "briefing" }
  | { kind: "intel" }
  | { kind: "identity" }
  | { kind: "discover" }
  | { kind: "correlation" }
  | { kind: "guardian" }
  | null;

function pickHero(summary: Summary, irEnabled: boolean): Hero {
  // 1. Cross-host campaign — the highest-leverage agentic kickoff.
  const c = summary.campaigns[0];
  if (c) {
    const uncontained = c.uncontained_count > 0 ? ` · ${c.uncontained_count} uncontained` : "";
    return {
      tone: "campaign",
      label: "Reconstruct the campaign",
      title: `Cross-host campaign across ${c.host_count} hosts`,
      detail: `${c.artifact_label}${c.severity_max_name ? ` · ${c.severity_max_name}` : ""}${uncontained}`,
      primer: reconstructPrimer(c),
    };
  }
  // 2. Critical detection on an IR-eligible host → guided IR.
  const top = summary.top[0];
  if (top?.device?.hostname) {
    const host = top.device.hostname;
    if ((top.severity ?? 0) >= 80) {
      const elig = endpointIrEligibility(
        { device_id: top.device.device_id, hostname: host, platform_name: top.device.platform_name },
        irEnabled,
      );
      if (elig.state === "eligible") {
        return {
          tone: "ir",
          label: "Run guided IR",
          title: `Critical detection on ${host}`,
          detail: detName(top),
          primer: elig.primer,
        };
      }
    }
    // 3. Otherwise triage the top-ranked detection.
    return {
      tone: "triage",
      label: "Triage detection",
      title: `Top priority: ${detName(top)}`,
      detail: `on ${host}`,
      primer: triagePrimer(top),
    };
  }
  return null;
}

// ── main ────────────────────────────────────────────────────────────────────

export default function HomeDashboard({ irEnabled }: { irEnabled: boolean }) {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [summaryErr, setSummaryErr] = useState<string | null>(null);
  const [projectedMonthly, setProjectedMonthly] = useState<number | null>(null);
  const [panel, setPanel] = useState<Panel>(null);

  useEffect(() => {
    void (async () => {
      try {
        const r = await fetch("/api/home/summary", { cache: "no-store" });
        const j = await r.json();
        if (j.ok) setSummary(j as Summary);
        else setSummaryErr(j.error ?? "Could not load the priority feed.");
      } catch (e) {
        setSummaryErr(e instanceof Error ? e.message : String(e));
      }
    })();
    void (async () => {
      try {
        const r = await fetch("/api/cost", { cache: "no-store" });
        const j = await r.json();
        if (j?.ok) setProjectedMonthly(j.projectedMonthly ?? 0);
      } catch {
        /* tile stat degrades to blurb-only */
      }
    })();
  }, []);

  const hero = summary ? pickHero(summary, irEnabled) : null;
  const chatDock = useChatDock();

  const openWidget = (kind: WidgetKind) => {
    if (kind === "chat") return chatDock.open();
    if (kind === "priority") return setPanel({ kind: "priority", rows: summary?.top ?? [] });
    if (kind === "campaigns") return setPanel({ kind: "campaigns", campaigns: summary?.campaigns ?? [] });
    setPanel({ kind });
  };

  const widgetStats: Partial<Record<WidgetKind, string>> = {
    priority: summary ? `${summary.counts.top} open` : undefined,
    campaigns: summary ? `${summary.campaigns.length} cross-host` : undefined,
    contained: summary ? `${summary.counts.contained} isolated` : undefined,
    spend: projectedMonthly === null ? undefined : `$${projectedMonthly.toFixed(2)} / mo`,
  };

  return (
    <div className="space-y-6">
      <HeroBand summary={summary} error={summaryErr} hero={hero} />

      {/* Control center — every capability is a glanceable tile that pops its
          live surface into the right-side panel. This is the whole dashboard. */}
      <ControlCenterGrid onOpen={openWidget} stats={widgetStats} />

      {/* Supporting context that self-hides when there's nothing to show. */}
      <RecentIr onSelect={(file, aid) => setPanel({ kind: "ir", file, aid })} />
      <PreventionGapCard onOpen={(count) => setPanel({ kind: "prevention", count })} />

      <SnackPanel
        open={panel !== null}
        onClose={() => setPanel(null)}
        title={panelTitle(panel)}
        subtitle={panelSubtitle(panel)}
        footer={panelFooter(panel, irEnabled)}
        width={panelWidth(panel)}
      >
        {panelBody(panel, irEnabled)}
      </SnackPanel>
    </div>
  );
}

// ── snack-panel content routing ───────────────────────────────────────────────

function panelTitle(panel: Panel): React.ReactNode {
  if (!panel) return "";
  switch (panel.kind) {
    case "priority":
      return "Priority detections";
    case "campaigns":
      return "Cross-host campaigns";
    case "prevention":
      return "Prevention posture gap";
    case "contained":
      return "Contained hosts";
    case "ir":
      return "Incident response";
    case "spend":
      return "Spend";
    case "ngsiem":
      return "NGSIEM query";
    case "pivot":
      return "Artifact pivot";
    case "recon":
      return "Exposure recon";
    case "malquery":
      return "MalQuery";
    case "briefing":
      return "Daily briefing";
    case "intel":
      return "Adversary intel";
    case "identity":
      return "Identity posture";
    case "discover":
      return "Asset discovery";
    case "correlation":
      return "Correlation rules";
    case "guardian":
      return "AI agent activity";
  }
}

function panelSubtitle(panel: Panel): React.ReactNode {
  if (!panel) return undefined;
  switch (panel.kind) {
    case "priority":
      return `${panel.rows.length} ranked`;
    case "campaigns":
      return `${panel.campaigns.length} ${panel.campaigns.length === 1 ? "cluster" : "clusters"}`;
    case "ir":
      return panel.aid;
    case "ngsiem":
      return "Plain-English → CQL, live tenant";
    case "pivot":
      return "Hash / IP / domain / URL";
    case "recon":
      return "Domain or email exposure";
    case "malquery":
      return "Hash lineage";
    case "briefing":
      return "One-page report for this tenant";
    case "intel":
      return "Adversaries with tenant evidence";
    case "identity":
      return "Risky users · IDP posture";
    case "discover":
      return "Inventory coverage gaps";
    case "correlation":
      return "NGSIEM rule health";
    case "guardian":
      return "Agents · sessions · models";
    default:
      return undefined;
  }
}

function panelWidth(panel: Panel): "md" | "lg" {
  if (!panel) return "md";
  return [
    "priority",
    "campaigns",
    "ngsiem",
    "pivot",
    "recon",
    "malquery",
    "briefing",
    "intel",
    "identity",
    "discover",
    "correlation",
    "guardian",
  ].includes(panel.kind)
    ? "lg"
    : "md";
}

function panelBody(panel: Panel, irEnabled: boolean): React.ReactNode {
  if (!panel) return null;
  switch (panel.kind) {
    case "priority":
      return <PriorityList rows={panel.rows} irEnabled={irEnabled} />;
    case "campaigns":
      return <CampaignsPanel campaigns={panel.campaigns} bare />;
    case "prevention":
      return <PreventionDetail />;
    case "contained":
      return <ContainedDetail />;
    case "ir":
      return <IrRunDetail file={panel.file} />;
    case "spend":
      return <SpendPanel />;
    case "ngsiem":
    case "pivot":
    case "recon":
    case "malquery":
    case "briefing":
    case "intel":
    case "identity":
    case "discover":
    case "correlation":
    case "guardian":
      return <AgentToolPanel tool={AGENT_TOOLS[panel.kind]} />;
  }
}

function fullQueueFooter() {
  return (
    <Link
      href="/queue"
      className="inline-flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-brand-700/60 hover:text-oxblood-200"
    >
      Full queue
      <ArrowUpRight className="h-3.5 w-3.5" strokeWidth={2} />
    </Link>
  );
}

function panelFooter(panel: Panel, _irEnabled: boolean): React.ReactNode {
  if (!panel) return undefined;
  switch (panel.kind) {
    case "priority":
    case "campaigns":
      return fullQueueFooter();
    case "prevention":
      return preventionFooter(panel.count);
    case "ir":
      return irFooter(panel.file);
    case "spend":
      return spendFooter();
    default:
      return undefined;
  }
}

// ── hero band ─────────────────────────────────────────────────────────────────

const HERO_TONE: Record<string, { ring: string; icon: typeof ShieldAlert; chip: string }> = {
  campaign: { ring: "border-orange-800/70 from-orange-950/30", icon: Network, chip: "text-orange-300" },
  ir: { ring: "border-oxblood-800/70 from-oxblood-950/30", icon: ShieldAlert, chip: "text-oxblood-300" },
  triage: { ring: "border-brand-800/70 from-brand-950/30", icon: ListChecks, chip: "text-oxblood-300" },
};

function HeroBand({ summary, error, hero }: { summary: Summary | null; error: string | null; hero: Hero }) {
  if (error) {
    return (
      <div className="rounded-lg border border-oxblood-900/60 bg-oxblood-950/30 px-4 py-3 text-sm text-oxblood-200">
        Couldn&apos;t load the priority feed: {error}
      </div>
    );
  }
  if (!summary) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-neutral-800 bg-neutral-950 px-5 py-6 text-sm text-neutral-500">
        <Loader2 className="h-4 w-4 animate-spin" strokeWidth={2} /> Ranking open detections…
      </div>
    );
  }

  const briefLink = (
    <Link
      href="/queue"
      className="inline-flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950/60 px-3 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-brand-700/60 hover:text-oxblood-200"
    >
      <Sparkles className="h-3.5 w-3.5" strokeWidth={2} />
      Generate the morning brief
    </Link>
  );

  if (!hero) {
    return (
      <div className="flex flex-col items-start gap-3 rounded-lg border border-emerald-900/50 bg-gradient-to-br from-emerald-950/20 via-neutral-950 to-neutral-950 px-5 py-5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck className="h-6 w-6 shrink-0 text-emerald-400" strokeWidth={1.75} />
          <div>
            <div className="text-base font-semibold text-neutral-100">Nothing needs you right now.</div>
            <div className="mt-0.5 text-sm text-neutral-400">
              No priority detections or cross-host campaigns in the last 14 days.
            </div>
          </div>
        </div>
        {briefLink}
      </div>
    );
  }

  const tone = HERO_TONE[hero.tone];
  const Icon = tone.icon;
  return (
    <div className={`rounded-lg border bg-gradient-to-br to-neutral-950 px-5 py-5 shadow-[0_20px_50px_-30px_rgba(220,38,38,0.4)] ${tone.ring}`}>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-3.5">
          <div className={`mt-0.5 flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-neutral-800 bg-neutral-950/60 ${tone.chip}`}>
            <Icon className="h-5 w-5" strokeWidth={1.75} />
          </div>
          <div className="min-w-0">
            <div className={`font-mono text-[11px] font-semibold uppercase tracking-[0.16em] ${tone.chip}`}>
              Recommended next move
            </div>
            <div className="mt-1 text-lg font-semibold text-neutral-50">{hero.title}</div>
            <div className="mt-0.5 truncate font-mono text-[12px] text-neutral-400">{hero.detail}</div>
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {briefLink}
          <Link
            href={buildPrimerHref(hero.primer)}
            className="inline-flex items-center gap-1.5 rounded-md border border-brand-600 bg-brand-600 px-4 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-white transition hover:bg-brand-500"
          >
            {hero.label}
            <ArrowUpRight className="h-3.5 w-3.5" strokeWidth={2} />
          </Link>
        </div>
      </div>
    </div>
  );
}

// ── priority detections list (snack-panel body) ──────────────────────────────

function PriorityList({ rows, irEnabled }: { rows: QueueRow[]; irEnabled: boolean }) {
  const toast = useToast();

  const copyHost = async (name: string) => {
    try {
      await navigator.clipboard.writeText(name);
      toast(`Copied ${name}`, { kind: "success" });
    } catch {
      toast("Couldn't copy to clipboard", { kind: "error" });
    }
  };

  if (rows.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-1.5 py-10 text-center">
        <ShieldCheck className="h-6 w-6 text-emerald-400" strokeWidth={1.75} />
        <div className="text-sm text-neutral-300">No priority detections.</div>
        <div className="text-[12px] text-neutral-500">The ranked queue is clear for now.</div>
      </div>
    );
  }

  return (
    <ul className="divide-y divide-neutral-900">
      {rows.map((d) => {
        const tone = severityTone(d.severity ?? 0);
        const host = d.device?.hostname;
        return (
          <li key={d.composite_id ?? d.id} className="flex items-center gap-3 py-2.5">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className={`shrink-0 rounded border px-1.5 py-px font-mono text-[10px] uppercase tracking-[0.08em] ${tone.cls}`}>
                  {d.severity_name ?? tone.label}
                </span>
                <span className="truncate text-sm font-medium text-neutral-100">{detName(d)}</span>
              </div>
              <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[11px] text-neutral-500">
                {host ? (
                  <span className="inline-flex items-center gap-1">
                    <Server className="h-3 w-3" strokeWidth={2} />
                    {host}
                    <button
                      type="button"
                      onClick={() => void copyHost(host)}
                      aria-label={`Copy ${host}`}
                      className="rounded p-0.5 text-neutral-600 transition-colors hover:text-neutral-300"
                    >
                      <Copy className="h-3 w-3" strokeWidth={2} />
                    </button>
                  </span>
                ) : null}
                {d.tactic ? (
                  <>
                    <span className="text-neutral-700">·</span>
                    <span>{d.tactic}</span>
                  </>
                ) : null}
                <span className="text-neutral-700">·</span>
                <span>{relTime(d.created_timestamp ?? "")}</span>
                {d.contained ? (
                  <span className="rounded border border-teal-800 bg-teal-950/50 px-1.5 py-px text-teal-200">contained</span>
                ) : null}
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-1.5">
              <Link
                href={buildPrimerHref(triagePrimer(d))}
                title="Hand this detection to the agent for triage"
                className="flex h-8 items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950/60 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-brand-700/60 hover:text-oxblood-200"
              >
                <MessageSquare className="h-3 w-3" strokeWidth={2} />
                Triage
              </Link>
              {host ? (
                <IrChip
                  eligibility={endpointIrEligibility(
                    { device_id: d.device?.device_id, hostname: host, platform_name: d.device?.platform_name },
                    irEnabled,
                  )}
                />
              ) : null}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

// ── recent incident response ──────────────────────────────────────────────────

const IR_RECENT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

function RecentIr({ onSelect }: { onSelect: (file: string, aid: string) => void }) {
  const [runs, setRuns] = useState<IrRun[] | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const r = await fetch("/api/ir-runs", { cache: "no-store" });
        const j = await r.json();
        if (j?.ok && Array.isArray(j.runs)) setRuns(j.runs as IrRun[]);
        else setRuns([]);
      } catch {
        setRuns([]);
      }
    })();
  }, []);

  if (runs === null) return null;
  const recent = runs
    .filter((r) => Date.now() - r.lastTouched < IR_RECENT_WINDOW_MS)
    .sort((a, b) => b.lastTouched - a.lastTouched)
    .slice(0, 3);
  if (recent.length === 0) return null;

  return (
    <SectionCard
      icon={ShieldAlert}
      title="Recent incident response"
      right={
        <Link
          href="/ir-runs"
          className="flex items-center gap-1 font-mono text-[11px] uppercase tracking-[0.14em] text-neutral-400 transition-colors hover:text-oxblood-200"
        >
          All runs <ArrowRight className="h-3 w-3" strokeWidth={2} />
        </Link>
      }
    >
      <ul className="divide-y divide-neutral-900">
        {recent.map((run) => (
          <li key={run.file}>
            <button
              type="button"
              onClick={() => onSelect(run.file, run.aid)}
              className="flex w-full items-center gap-3 py-2.5 text-left outline-none transition-colors hover:text-neutral-100 focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-brand-700/50"
            >
              <div className="min-w-0 flex-1">
                <div className="truncate font-mono text-sm text-neutral-200">{run.aid}</div>
                <div className="mt-0.5 font-mono text-[11px] uppercase tracking-[0.08em] text-neutral-500">
                  {run.turnsCount} {run.turnsCount === 1 ? "turn" : "turns"} · {relTime(run.lastTouched)}
                  {run.hasErrors ? <span className="ml-2 text-amber-300">had errors</span> : null}
                </div>
              </div>
              <ArrowRight className="h-3.5 w-3.5 shrink-0 text-neutral-600" strokeWidth={2} />
            </button>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}

// ── prevention gap (self-hides when nothing is detect-only) ───────────────────

function PreventionGapCard({ onOpen }: { onOpen: (count: number) => void }) {
  const [summary, setSummary] = useState<{ detect_only: number } | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        const r = await fetch("/api/prevention-policies", { cache: "no-store" });
        const j = await r.json();
        if (j?.ok && j.summary) setSummary(j.summary as { detect_only: number });
      } catch {
        /* card hides on failure */
      } finally {
        setReady(true);
      }
    })();
  }, []);

  if (!ready || !summary || summary.detect_only === 0) return null;
  const n = summary.detect_only;

  return (
    <button
      type="button"
      onClick={() => onOpen(n)}
      className="w-full rounded-lg border border-neutral-800 bg-neutral-950 p-5 text-left outline-none transition-colors hover:border-brand-700/60 focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-brand-700/50"
    >
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2.5 font-mono text-sm font-semibold uppercase tracking-[0.16em] text-neutral-100">
          <ShieldCheck className="h-4 w-4 text-brand-400" strokeWidth={1.75} />
          Prevention posture gap
        </h2>
        <ArrowRight className="h-3.5 w-3.5 text-neutral-600" strokeWidth={2} />
      </div>
      <p className="text-sm text-neutral-300">
        <span className="font-mono text-oxblood-300">{n}</span> prevention{" "}
        {n === 1 ? "policy is" : "policies are"} set to detect-only — they alert but
        don&apos;t block. Open to see which and hand the review to the agent.
      </p>
    </button>
  );
}

// ── shared presentational ─────────────────────────────────────────────────────

function SectionCard({
  icon: Icon,
  title,
  children,
  right,
}: {
  icon: typeof ShieldAlert;
  title: string;
  children: React.ReactNode;
  right?: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-neutral-800 bg-neutral-950 p-5">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2.5 font-mono text-sm font-semibold uppercase tracking-[0.16em] text-neutral-100">
          <Icon className="h-4 w-4 text-brand-400" strokeWidth={1.75} />
          {title}
        </h2>
        {right}
      </div>
      {children}
    </section>
  );
}
