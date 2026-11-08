import { DollarSign, AlertTriangle } from "lucide-react";
import AppShell from "@/components/AppShell";
import PageHero from "@/components/PageHero";
import { summarizeCost } from "@/lib/cost/log";
import { pricingFor } from "@/lib/cost/pricing";
import { getAnthropicModel } from "@/lib/llm/anthropic";

export const dynamic = "force-dynamic";

const SURFACE_LABEL: Record<string, string> = {
  chat: "Chat",
  briefing: "Briefing",
  investigate: "Investigate",
  ngsiem: "NGSIEM",
  "ngsiem-playbook": "NGSIEM playbook",
  "triage-vulns": "Vuln triage",
};

function fmtUSD(n: number, dp = 4): string {
  if (n === 0) return "$0.00";
  if (n < 0.01) return `$${n.toFixed(dp)}`;
  return `$${n.toFixed(2)}`;
}

function fmtInt(n: number): string {
  return n.toLocaleString("en-US");
}

function fmtTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export default async function CostPage() {
  // Aggregated in SQLite (see summarizeCost) — no full-table read / per-row
  // JSON.parse on the event loop. surfaceRows/modelRows/days/recent keep the
  // shapes the JSX below already binds to.
  const { totals, days, bySurface: surfaceRows, byModel: modelRows, recent } =
    summarizeCost();

  const avgPerDay = days.length > 0 ? totals.cost / days.length : 0;
  const projectedMonthly = avgPerDay * 30;

  const todayKey = new Date().toISOString().slice(0, 10);
  const todaySpend = days.find((d) => d.day === todayKey)?.cost ?? 0;
  const budgetEnv = process.env.DAILY_COST_BUDGET_USD;
  const dailyBudget = budgetEnv ? Number.parseFloat(budgetEnv) : NaN;
  const budgetActive = Number.isFinite(dailyBudget) && dailyBudget > 0;

  const currentModel = getAnthropicModel();
  const currentPricing = pricingFor(currentModel);

  return (
    <AppShell title="Cost">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up space-y-8">
          <PageHero
            icon={DollarSign}
            eyebrow="Spend tracking"
            title="Token spend across every agentic surface."
            subtitle="Per-turn Anthropic API spend across every agentic surface, logged server-side and persisted for the life of the install."
          />

          {budgetActive && (
            <BudgetBanner today={todaySpend} budget={dailyBudget} />
          )}

          {totals.turns === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-neutral-800 bg-neutral-950/60 p-12 text-center">
              <div className="flex h-10 w-10 items-center justify-center rounded-full border border-brand-900/60 bg-brand-950/40 text-oxblood-300">
                <DollarSign className="h-5 w-5" strokeWidth={1.75} />
              </div>
              <div className="text-lg font-semibold text-white">No usage logged yet.</div>
              <p className="max-w-md text-base text-neutral-400">
                Run a chat, briefing, investigation, or NGSIEM query and refresh
                this page.
              </p>
            </div>
          ) : (
            <>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <SummaryCard label="Total spend" value={fmtUSD(totals.cost)} sub={`${totals.turns} ${totals.turns === 1 ? "turn" : "turns"}`} />
                <SummaryCard
                  label="Avg per day"
                  value={fmtUSD(avgPerDay)}
                  sub={`across ${days.length} ${days.length === 1 ? "day" : "days"}`}
                />
                <SummaryCard
                  label="Projected monthly"
                  value={fmtUSD(projectedMonthly)}
                  sub="avg × 30"
                  emphasis
                />
                <SummaryCard
                  label="Tokens (in / out)"
                  value={`${fmtInt(totals.input)} / ${fmtInt(totals.output)}`}
                  sub={`+${fmtInt(totals.cacheRead)} cache read · +${fmtInt(totals.cacheWrite)} cache write`}
                />
              </div>

              <Section title="Spend per day">
                <DayChart days={days} />
              </Section>

              <Section title="By surface">
                <SimpleTable
                  rows={surfaceRows.map((s) => [
                    SURFACE_LABEL[s.surface] ?? s.surface,
                    fmtInt(s.turns),
                    fmtUSD(s.cost),
                    pctBar(s.cost, totals.cost),
                  ])}
                  headers={["Surface", "Turns", "Cost", "Share"]}
                />
              </Section>

              <Section title="By model">
                <SimpleTable
                  rows={modelRows.map((m) => [
                    m.model,
                    fmtInt(m.turns),
                    fmtUSD(m.cost),
                    pctBar(m.cost, totals.cost),
                  ])}
                  headers={["Model", "Turns", "Cost", "Share"]}
                />
              </Section>

              <Section title="Recent turns">
                <div className="overflow-x-auto rounded-lg border border-neutral-800 bg-neutral-950/40">
                  <table className="w-full min-w-[720px] text-left text-[15px]">
                    <thead className="border-b border-brand-900/40 bg-gradient-to-b from-neutral-900 to-neutral-950 font-mono text-[12px] uppercase tracking-[0.14em] text-neutral-400">
                      <tr>
                        <th className="px-4 py-3 font-semibold">Time</th>
                        <th className="px-4 py-3 font-semibold">Surface</th>
                        <th className="px-4 py-3 font-semibold">Model</th>
                        <th className="px-4 py-3 font-semibold text-right">Iter</th>
                        <th className="px-4 py-3 font-semibold text-right">In</th>
                        <th className="px-4 py-3 font-semibold text-right">Out</th>
                        <th className="px-4 py-3 font-semibold text-right">Cache R/W</th>
                        <th className="px-4 py-3 font-semibold text-right">Cost</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recent.map((r, i) => (
                        <tr
                          key={`${r.ts}-${i}`}
                          className={`border-t border-neutral-800/80 transition-colors hover:bg-brand-950/15 ${i % 2 === 1 ? "bg-neutral-950/40" : ""}`}
                        >
                          <td className="whitespace-nowrap px-4 py-2.5 font-mono text-sm tabular-nums text-neutral-500">
                            {fmtTime(r.ts)}
                          </td>
                          <td className="px-4 py-2.5 text-neutral-200">
                            {SURFACE_LABEL[r.surface] ?? r.surface}
                          </td>
                          <td className="px-4 py-2.5 font-mono text-sm text-neutral-400">
                            {r.model}
                          </td>
                          <td className="px-4 py-2.5 text-right font-mono text-sm tabular-nums text-neutral-300">
                            {r.iterations ?? 1}
                          </td>
                          <td className="px-4 py-2.5 text-right font-mono text-sm tabular-nums text-neutral-300">
                            {fmtInt(r.usage.input_tokens ?? 0)}
                          </td>
                          <td className="px-4 py-2.5 text-right font-mono text-sm tabular-nums text-neutral-300">
                            {fmtInt(r.usage.output_tokens ?? 0)}
                          </td>
                          <td className="px-4 py-2.5 text-right font-mono text-sm tabular-nums text-neutral-500">
                            {fmtInt(r.usage.cache_read_input_tokens ?? 0)} / {fmtInt(r.usage.cache_creation_input_tokens ?? 0)}
                          </td>
                          <td className="px-4 py-2.5 text-right font-mono text-sm tabular-nums font-semibold text-oxblood-300">
                            {fmtUSD(r.cost)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Section>
            </>
          )}

          <Section title="Pricing reference">
            <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-5">
              <div className="text-sm text-neutral-400">
                Current model: <span className="font-mono text-neutral-200">{currentModel}</span>
              </div>
              {currentPricing ? (
                <div className="mt-3 grid gap-4 text-sm sm:grid-cols-4">
                  <PriceCell label="Input" value={`$${currentPricing.input.toFixed(2)} / Mtok`} />
                  <PriceCell label="Output" value={`$${currentPricing.output.toFixed(2)} / Mtok`} />
                  <PriceCell label="Cache write" value={`$${currentPricing.cacheWrite.toFixed(2)} / Mtok`} />
                  <PriceCell label="Cache read" value={`$${currentPricing.cacheRead.toFixed(2)} / Mtok`} />
                </div>
              ) : (
                <p className="mt-2 text-sm text-amber-300">
                  No pricing entry for this model — costs above will read $0. Add a
                  prefix to <span className="font-mono">lib/cost/pricing.ts</span>.
                </p>
              )}
            </div>
          </Section>
        </div>
      </main>
    </AppShell>
  );
}

function SummaryCard({
  label,
  value,
  sub,
  emphasis,
}: {
  label: string;
  value: string;
  sub?: string;
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
      {emphasis && (
        <div className="absolute right-0 top-0 h-16 w-16 -translate-y-1/2 translate-x-1/2 rounded-full bg-brand-600/15 blur-2xl" />
      )}
      <div className="relative">
        <div className="font-mono text-[12px] font-medium uppercase tracking-[0.14em] text-neutral-400">{label}</div>
        <div
          className={`mt-2.5 font-mono text-[26px] font-bold leading-none tracking-tight tabular-nums ${
            emphasis ? "text-oxblood-200" : "text-neutral-50"
          }`}
        >
          {value}
        </div>
        {sub ? <div className="mt-2 font-mono text-[12px] uppercase tracking-[0.10em] text-neutral-500">{sub}</div> : null}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="mb-3 flex items-center gap-2.5 font-mono text-sm font-semibold uppercase tracking-[0.16em] text-neutral-100">
        <span className="h-px w-4 bg-brand-700" />
        {title}
      </h2>
      {children}
    </section>
  );
}

function DayChart({ days }: { days: Array<{ day: string; cost: number; turns: number }> }) {
  if (days.length === 0) {
    return (
      <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-5 text-sm text-neutral-500">
        Nothing yet.
      </div>
    );
  }
  const max = Math.max(...days.map((d) => d.cost), 0.000001);
  const peakIdx = days.reduce((best, d, i, arr) => (d.cost > arr[best].cost ? i : best), 0);
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-5">
      <div className="flex items-end gap-2 overflow-x-auto pb-1" style={{ minHeight: 180 }}>
        {days.map((d, i) => {
          const h = Math.max(2, (d.cost / max) * 140);
          const isPeak = i === peakIdx;
          return (
            <div key={d.day} className="group/bar flex shrink-0 flex-col items-center gap-2" style={{ width: 56 }}>
              <div className={`font-mono text-[12px] tabular-nums transition-colors ${isPeak ? "text-oxblood-300" : "text-neutral-500 group-hover/bar:text-neutral-300"}`}>
                {fmtUSD(d.cost)}
              </div>
              <div
                className={`w-full rounded-t transition-all ${
                  isPeak
                    ? "bg-gradient-to-t from-brand-700 to-brand-400 shadow-[0_0_18px_-4px_rgba(248,113,113,0.55)]"
                    : "bg-gradient-to-t from-brand-800/80 to-brand-600/80 group-hover/bar:from-brand-700 group-hover/bar:to-brand-500"
                }`}
                style={{ height: h }}
                title={`${d.day} · ${d.turns} ${d.turns === 1 ? "turn" : "turns"} · ${fmtUSD(d.cost)}`}
              />
              <div className="font-mono text-[12px] tabular-nums text-neutral-500">{d.day.slice(5)}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SimpleTable({
  headers,
  rows,
}: {
  headers: string[];
  rows: Array<Array<React.ReactNode>>;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border border-neutral-800 bg-neutral-950/40">
      <table className="w-full text-left text-[15px]">
        <thead className="border-b border-brand-900/40 bg-gradient-to-b from-neutral-900 to-neutral-950 font-mono text-[12px] uppercase tracking-[0.14em] text-neutral-400">
          <tr>
            {headers.map((h, i) => (
              <th key={i} className="px-4 py-3 font-semibold">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, ri) => (
            <tr key={ri} className={`border-t border-neutral-800/80 ${ri % 2 === 1 ? "bg-neutral-950/40" : ""}`}>
              {row.map((cell, ci) => (
                <td key={ci} className="px-4 py-2.5 text-neutral-200">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function pctBar(value: number, total: number): React.ReactNode {
  const pct = total > 0 ? (value / total) * 100 : 0;
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 w-32 overflow-hidden rounded-full bg-neutral-900">
        <div
          className="h-full bg-gradient-to-r from-brand-700 to-brand-500"
          style={{ width: `${Math.min(100, pct)}%` }}
        />
      </div>
      <span className="font-mono text-sm text-neutral-400">{pct.toFixed(1)}%</span>
    </div>
  );
}

function BudgetBanner({ today, budget }: { today: number; budget: number }) {
  const pct = budget > 0 ? (today / budget) * 100 : 0;
  const tier = pct >= 100 ? "over" : pct >= 75 ? "warn" : "ok";
  const palette =
    tier === "over"
      ? {
          ring: "border-red-900/70 bg-red-950/40",
          icon: "text-oxblood-300",
          bar: "from-red-700 to-red-500",
          headline: "text-red-200",
          label: "Over today's budget",
        }
      : tier === "warn"
        ? {
            ring: "border-amber-900/70 bg-amber-950/30",
            icon: "text-amber-300",
            bar: "from-amber-600 to-amber-400",
            headline: "text-amber-200",
            label: "Approaching budget",
          }
        : {
            ring: "border-emerald-900/60 bg-emerald-950/20",
            icon: "text-emerald-300",
            bar: "from-emerald-700 to-emerald-500",
            headline: "text-emerald-200",
            label: "Within budget",
          };
  return (
    <div className={`rounded-lg border px-5 py-4 ${palette.ring}`}>
      <div className="flex items-center gap-3">
        <AlertTriangle className={`h-5 w-5 shrink-0 ${palette.icon}`} strokeWidth={1.75} />
        <div className="flex-1">
          <div className="flex items-baseline justify-between gap-3">
            <div className={`font-mono text-[12px] font-semibold uppercase tracking-[0.14em] ${palette.headline}`}>
              {palette.label}
            </div>
            <div className="font-mono text-sm tabular-nums text-neutral-300">
              <span className={palette.headline}>{fmtUSD(today)}</span>
              <span className="text-neutral-500"> / {fmtUSD(budget)}</span>
              <span className="text-neutral-500"> · {pct.toFixed(0)}%</span>
            </div>
          </div>
          <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-neutral-900">
            <div
              className={`h-full bg-gradient-to-r ${palette.bar}`}
              style={{ width: `${Math.min(100, pct)}%` }}
            />
          </div>
          <div className="mt-1.5 text-xs text-neutral-500">
            Soft cap (UTC day). Visual only — does not throttle. Configure via{" "}
            <span className="font-mono text-neutral-400">DAILY_COST_BUDGET_USD</span>.
          </div>
        </div>
      </div>
    </div>
  );
}

function PriceCell({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wider text-neutral-500">{label}</div>
      <div className="mt-1 font-mono text-sm text-neutral-200">{value}</div>
    </div>
  );
}
