import { Gauge, ShieldCheck, Activity, TrendingUp, ArrowDown, ArrowUp, Minus } from "lucide-react";
import AppShell from "@/components/AppShell";
import PageHero from "@/components/PageHero";
import { getActiveEnvironment, getActiveEnvironmentId } from "@/lib/config/environments";
import { computeScorecard } from "@/lib/scorecard/compute";
import type { ActivityMetrics, OperationsMetrics, PostureDigest, PostureHeadline } from "@/lib/scorecard/types";

export const dynamic = "force-dynamic";

const WINDOW_DAYS = 30;

// Plain-language names for the raw agent-activity surfaces. The investigate:*
// sub-surfaces all roll up to "Host investigation" at render so the list reads
// in operator terms, not internal slugs.
const SURFACE_LABEL: Record<string, string> = {
  chat: "Chat",
  briefing: "Daily briefing",
  investigate: "Host investigation",
  "investigate:fingerprint": "Host investigation",
  "investigate:threats": "Host investigation",
  "investigate:posture": "Host investigation",
  ngsiem: "Threat hunting",
  "ngsiem-playbook": "Threat hunting",
  "triage-vulns": "Vulnerability triage",
  "triage-detections": "Detection triage",
  "queue-brief": "Queue review",
  lookup: "Artifact lookup",
  intel: "Adversary intel",
  "patch-plan": "Patch planning",
  "adversary-exposure": "Adversary exposure",
  recon: "Exposure recon",
  "host-groups": "Host groups",
  malquery: "Malware search",
  workflows: "Workflow review",
  identity: "Identity posture",
  "threat-graph": "Threat graph",
  quarantine: "Quarantine review",
  correlation: "Correlation rules",
  "data-protection": "Data protection",
  discover: "Asset discovery",
  "incident-report": "Incident report",
};

function humanizeSurface(slug: string): string {
  const known = SURFACE_LABEL[slug];
  if (known) return known;
  const base = slug.split(":")[0].replace(/[-_]/g, " ");
  return base.charAt(0).toUpperCase() + base.slice(1);
}

function fmtInt(n: number): string {
  return n.toLocaleString("en-US");
}

function fmtDuration(ms: number | null): string {
  if (ms === null) return "—";
  const secs = Math.round(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  const rem = mins % 60;
  return rem ? `${hrs}h ${rem}m` : `${hrs}h`;
}

function signed(n: number): string {
  if (n > 0) return `+${fmtInt(n)}`;
  if (n < 0) return `−${fmtInt(Math.abs(n))}`;
  return "0";
}

export default async function ScorecardPage() {
  const envId = getActiveEnvironmentId();
  const envName = getActiveEnvironment().name;
  const scorecard = await computeScorecard(envId, { windowDays: WINDOW_DAYS });
  const { operations, activity, posture } = scorecard;

  return (
    <AppShell title="Scorecard">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up space-y-8">
          <PageHero
            icon={Gauge}
            eyebrow="Operations scorecard"
            title="What this console has accomplished for your tenant."
            subtitle="Incident-response engagements, reviewed actions, and agentic work run from this console — and how your tenant's posture moved while it operated."
          />

          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-500">
            <span>Trailing {scorecard.windowDays} days</span>
            <span className="text-neutral-700">·</span>
            <span>
              Tenant <span className="text-neutral-300">{envName}</span>
            </span>
          </div>

          <OperationsSection ops={operations} />
          <ActivitySection activity={activity} />
          <PostureSection posture={posture} />
        </div>
      </main>
    </AppShell>
  );
}

function Section({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon: typeof Gauge;
  children: React.ReactNode;
}) {
  return (
    <section>
      <h2 className="mb-3 flex items-center gap-2.5 font-mono text-sm font-semibold uppercase tracking-[0.16em] text-neutral-100">
        <Icon className="h-4 w-4 text-brand-400" strokeWidth={1.75} />
        {title}
      </h2>
      {children}
    </section>
  );
}

function EmptyCard({ title, body }: { title: string; body: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-neutral-800 bg-neutral-950/60 p-10 text-center">
      <div className="text-base font-semibold text-neutral-200">{title}</div>
      <p className="max-w-md text-sm text-neutral-400">{body}</p>
    </div>
  );
}

function StatCard({
  label,
  value,
  sub,
  emphasis,
}: {
  label: string;
  value: string;
  sub?: React.ReactNode;
  emphasis?: boolean;
}) {
  return (
    <div
      className={`relative overflow-hidden rounded-lg border p-5 transition-colors ${
        emphasis
          ? "border-brand-800/60 bg-gradient-to-br from-brand-950/40 via-neutral-950 to-neutral-950"
          : "border-neutral-800 bg-neutral-950 hover:border-neutral-700"
      }`}
    >
      <div className="font-mono text-[12px] font-medium uppercase tracking-[0.14em] text-neutral-400">
        {label}
      </div>
      <div
        className={`mt-2.5 font-mono text-[26px] font-bold leading-none tracking-tight tabular-nums ${
          emphasis ? "text-oxblood-200" : "text-neutral-50"
        }`}
      >
        {value}
      </div>
      {sub ? (
        <div className="mt-2 font-mono text-[12px] uppercase tracking-[0.10em] text-neutral-500">
          {sub}
        </div>
      ) : null}
    </div>
  );
}

// Neutral period-over-period note for activity counts (more or less work is not
// inherently good or bad — unlike posture, which is colored by direction).
function PriorDelta({ current, prev, unit }: { current: number; prev: number; unit: string }) {
  const delta = current - prev;
  if (prev === 0 && current === 0) return <span>no prior {unit}</span>;
  return (
    <span>
      {signed(delta)} vs prior {WINDOW_DAYS}d
    </span>
  );
}

function OperationsSection({ ops }: { ops: OperationsMetrics }) {
  if (ops.engagements === 0) {
    return (
      <Section title="Agentic operations" icon={ShieldCheck}>
        <EmptyCard
          title="No incident-response engagements yet"
          body="When you run the guided incident-response workflow on a host for this tenant, its engagements, reviewed actions, and resolved detections show up here."
        />
      </Section>
    );
  }

  return (
    <Section title="Agentic operations" icon={ShieldCheck}>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Engagements"
          value={fmtInt(ops.engagements)}
          sub={<PriorDelta current={ops.engagements} prev={ops.engagementsPrev} unit="engagements" />}
          emphasis
        />
        <StatCard
          label="Median time to close"
          value={fmtDuration(ops.medianCloseMs)}
          sub={ops.meanCloseMs !== null ? `mean ${fmtDuration(ops.meanCloseMs)}` : undefined}
        />
        <StatCard
          label="Detections resolved"
          value={fmtInt(ops.detectionsResolved)}
          sub={
            <PriorDelta
              current={ops.detectionsResolved}
              prev={ops.detectionsResolvedPrev}
              unit="detections"
            />
          }
        />
        <StatCard
          label="Actions reviewed"
          value={fmtInt(ops.actions.reviewed)}
          sub={`${ops.actions.allowed} allowed · ${ops.actions.declined} declined · ${ops.actions.expired} expired`}
        />
      </div>
      <div className="mt-3 font-mono text-[12px] uppercase tracking-[0.10em] text-neutral-500">
        {fmtInt(ops.turns)} {ops.turns === 1 ? "turn" : "turns"} ·{" "}
        {fmtInt(ops.iterations)} {ops.iterations === 1 ? "iteration" : "iterations"}
        {ops.erroredEngagements > 0
          ? ` · ${fmtInt(ops.erroredEngagements)} with errors`
          : ""}
      </div>
    </Section>
  );
}

function ActivitySection({ activity }: { activity: ActivityMetrics }) {
  // Merge sub-surfaces that share a plain-language label (e.g. the investigate:*
  // family) so the list reads cleanly and counts aren't split across slugs.
  const merged = new Map<string, number>();
  for (const s of activity.bySurface) {
    const label = humanizeSurface(s.surface);
    merged.set(label, (merged.get(label) ?? 0) + s.runs);
  }
  const surfaces = [...merged.entries()]
    .map(([label, runs]) => ({ label, runs }))
    .sort((a, b) => b.runs - a.runs);
  const max = surfaces.reduce((m, s) => Math.max(m, s.runs), 0);

  if (activity.totalRuns === 0) {
    return (
      <Section title="Agentic activity" icon={Activity}>
        <EmptyCard
          title="No agentic activity in this window"
          body="Once you run chats, briefings, investigations, or hunts for this tenant, the breadth of that work appears here broken down by area."
        />
      </Section>
    );
  }

  return (
    <Section title="Agentic activity" icon={Activity}>
      <div className="grid gap-4 lg:grid-cols-3">
        <StatCard
          label="Workflows run"
          value={fmtInt(activity.totalRuns)}
          sub={<PriorDelta current={activity.totalRuns} prev={activity.totalRunsPrev} unit="runs" />}
          emphasis
        />
        <StatCard label="Total iterations" value={fmtInt(activity.iterations)} sub="agent steps" />
        <StatCard label="Areas active" value={fmtInt(surfaces.length)} sub="distinct surfaces" />
      </div>

      <div className="mt-4 rounded-lg border border-neutral-800 bg-neutral-950 p-5">
        <div className="space-y-2.5">
          {surfaces.map((s) => (
            <div key={s.label} className="flex items-center gap-3">
              <div className="w-44 shrink-0 truncate text-sm text-neutral-200">{s.label}</div>
              <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-neutral-900">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-brand-700 to-brand-500"
                  style={{ width: `${max > 0 ? Math.max(4, (s.runs / max) * 100) : 0}%` }}
                />
              </div>
              <div className="w-12 shrink-0 text-right font-mono text-sm tabular-nums text-neutral-400">
                {fmtInt(s.runs)}
              </div>
            </div>
          ))}
        </div>
      </div>
    </Section>
  );
}

function PostureSection({ posture }: { posture: PostureDigest }) {
  if (!posture.available || posture.headlines.length === 0) {
    return (
      <Section title="Posture movement" icon={TrendingUp}>
        <EmptyCard
          title="Posture trends appear after the second capture"
          body="Posture is captured for this tenant once a day. After the second capture, the movement between them shows up here."
        />
      </Section>
    );
  }

  return (
    <Section title="Posture movement" icon={TrendingUp}>
      <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-2">
        <div className="grid gap-px sm:grid-cols-2">
          {posture.headlines.map((h) => (
            <PostureRow key={h.key} headline={h} />
          ))}
        </div>
      </div>
      <div className="mt-2 font-mono text-[12px] uppercase tracking-[0.10em] text-neutral-500">
        Movement over {posture.windowDays} {posture.windowDays === 1 ? "day" : "days"}
      </div>
    </Section>
  );
}

function PostureRow({ headline }: { headline: PostureHeadline }) {
  const { current, delta, direction, lowerIsBetter } = headline;
  // "good" when the metric moved in the operator's favor.
  const good =
    delta === null || delta === 0
      ? null
      : lowerIsBetter
        ? delta < 0
        : delta > 0;

  const tone =
    good === null
      ? { text: "text-neutral-400", icon: "text-neutral-500" }
      : good
        ? { text: "text-emerald-300", icon: "text-emerald-400" }
        : { text: "text-amber-300", icon: "text-amber-400" };

  const Arrow = direction === "up" ? ArrowUp : direction === "down" ? ArrowDown : Minus;

  return (
    <div className="flex items-center justify-between gap-3 rounded-md px-4 py-3">
      <div className="min-w-0">
        <div className="truncate text-sm text-neutral-200">{headline.label}</div>
        <div className="font-mono text-[12px] uppercase tracking-[0.10em] text-neutral-500">
          now {current === null ? "—" : fmtInt(current)}
        </div>
      </div>
      <div className={`flex shrink-0 items-center gap-1.5 font-mono text-sm tabular-nums ${tone.text}`}>
        <Arrow className={`h-4 w-4 ${tone.icon}`} strokeWidth={2} />
        {delta === null ? "—" : signed(delta)}
      </div>
    </div>
  );
}
