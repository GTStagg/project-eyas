import { ArrowUpRight, Plug2, Package, Activity, KeyRound, History } from "lucide-react";
import AppShell from "@/components/AppShell";
import SessionsCard from "@/components/SessionsCard";
import ScopeChecklist, { type ScopeCapStates } from "@/components/ScopeChecklist";
import { getActiveEnvironment, getActiveEnvironmentId } from "@/lib/config/environments";
import { countSnapshots, getRecentSnapshots } from "@/lib/posture/trend";
import { getBuildInfo } from "@/lib/build-info";
import {
  getHealthReport,
  FIRST_LAUNCH_SETUP_MSG,
  type ProbeResult,
  type ProbeStatus,
} from "@/lib/health";

export const dynamic = "force-dynamic";

export default async function Status() {
  const [buildInfo, health] = await Promise.all([getBuildInfo(), getHealthReport()]);
  const overall: ProbeStatus =
    health.anthropic.status === "error" || health.falconMcp.status === "error"
      ? "error"
      : health.anthropic.status === "initializing" || health.falconMcp.status === "initializing"
        ? "initializing"
        : health.anthropic.status === "ok" && health.falconMcp.status === "ok"
          ? "ok"
          : "error";

  // Live per-environment scope availability for the ScopeChecklist blips. Only
  // the staged / optional surfaces are probed (see CAP_BY_CONSOLE); the values
  // are undefined when a probe didn't run, which the checklist renders neutral.
  const mcpCaps = health.falconMcp.capabilities;
  const capStates: ScopeCapStates = {
    intel: mcpCaps?.intel,
    cases: mcpCaps?.cases,
    quarantine: mcpCaps?.quarantine,
    correlationRules: mcpCaps?.correlationRules,
    dataProtection: mcpCaps?.dataProtection,
    recon: mcpCaps?.recon,
    malQuery: mcpCaps?.malQuery,
    threatGraph: mcpCaps?.threatGraph,
    workflows: mcpCaps?.workflows,
    idp: mcpCaps?.idp,
    discover: mcpCaps?.discover,
  };
  const envName = getActiveEnvironment().name;

  // Posture history readout — pure DB reads; degrade silently to the empty
  // state if the table can't be read.
  let postureHistory = { count: 0, lastCapturedAt: null as string | null, lastPartial: false };
  try {
    const postureEnvId = getActiveEnvironmentId();
    const latest = getRecentSnapshots(postureEnvId, 1)[0] ?? null;
    postureHistory = {
      count: countSnapshots(postureEnvId),
      lastCapturedAt: latest?.capturedAt ?? null,
      lastPartial: latest?.partial ?? false,
    };
  } catch {
    // leave default
  }

  return (
    <AppShell title="Status">
      <main className="flex-1 px-6 py-12">
        <div className="mx-auto max-w-3xl animate-fade-in-up space-y-6">
          {/* ── Health ─────────────────────────────────────────── */}
          <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
            <div className="flex items-start gap-4">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
                <Activity className="h-5 w-5" strokeWidth={1.75} />
              </div>
              <div className="flex-1">
                <div className="text-xs font-semibold uppercase tracking-[0.14em] text-oxblood-400">
                  Health
                </div>
                <h1 className="mt-1.5 text-3xl font-semibold tracking-tight text-white">
                  {overall === "ok"
                    ? "All systems go"
                    : overall === "initializing"
                      ? "Setting up…"
                      : "Degraded"}
                </h1>
                <p className="mt-1.5 text-base text-neutral-400">
                  Connectivity and auth checks for the underlying services.
                </p>
              </div>
              <StatusDot status={overall} large />
            </div>

            <div className="mt-6 space-y-2">
              <ProbeRow
                label="Anthropic"
                hint="Confirms the saved key reaches Anthropic and your model is available."
                probe={health.anthropic}
              />
              <ProbeRow
                label="CrowdStrike Falcon"
                hint="Connects to Falcon and lists the tools available with your current API permissions."
                probe={health.falconMcp}
              />
            </div>
          </div>

          {/* Cards below Health are ordered alphabetically by section title:
              Build → Diagnostics → Posture history → Scopes → Sessions. */}

          {/* ── Build ──────────────────────────────────────────── */}
          <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
            <div className="flex items-start gap-4">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
                <Package className="h-5 w-5" strokeWidth={1.75} />
              </div>
              <div>
                <div className="text-xs font-semibold uppercase tracking-[0.14em] text-oxblood-400">
                  Build
                </div>
                <h1 className="mt-1.5 text-3xl font-semibold tracking-tight text-white">
                  {buildInfo.mode === "standalone"
                    ? buildInfo.bundle.buildKind === "docker"
                      ? "Container image"
                      : "Standalone bundle"
                    : "Development build"}
                </h1>
                <p className="mt-1.5 text-base text-neutral-400">
                  {buildInfo.mode === "standalone"
                    ? "Versions are pinned at the time the build was made."
                    : "Versions are resolved live as the app runs."}
                </p>
              </div>
            </div>

            {buildInfo.mode === "standalone" ? (
              <>
                <Group title="Bundle">
                  <KV label="App version" value={buildInfo.bundle.appVersion} />
                  <KV label="Built" value={buildInfo.bundle.builtAt} />
                  <KV label="Git SHA" value={buildInfo.bundle.gitSha} />
                  <KV label="Node (build host)" value={buildInfo.bundle.nodeVersion} />
                  <KV label="Node (runtime)" value={buildInfo.runtime.node} />
                </Group>
                <Group title="Pinned upstream">
                  <KV
                    label={buildInfo.bundle.mcpServer?.package ?? "MCP server"}
                    value={buildInfo.bundle.pins["mcp-server"]}
                  />
                  {buildInfo.bundle.mcpServer && (
                    <KV
                      label={`${buildInfo.bundle.mcpServer.package} commit`}
                      value={buildInfo.bundle.mcpServer.ref.slice(0, 12)}
                    />
                  )}
                </Group>
                {buildInfo.bundle.wheelTarget && (
                  <Group title="Wheel target">
                    <KV label="Python" value={buildInfo.bundle.wheelTarget.pythonVersion} />
                    <KV label="Platform" value={buildInfo.bundle.wheelTarget.platform} />
                  </Group>
                )}
              </>
            ) : (
              <Group title="Live versions">
                <KV label="Node (runtime)" value={buildInfo.runtime.node} />
                <KV
                  label="MCP server (resolved)"
                  value={buildInfo.mcpServer?.version ?? buildInfo.mcpError ?? "not reachable"}
                  warn={!buildInfo.mcpServer}
                />
                <KV label="server name" value={buildInfo.mcpServer?.name ?? "—"} />
              </Group>
            )}
          </div>

          {/* ── Endpoints ──────────────────────────────────────── */}
          <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
            <div className="flex items-start gap-4">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
                <Plug2 className="h-5 w-5" strokeWidth={1.75} />
              </div>
              <div>
                <div className="text-xs font-semibold uppercase tracking-[0.14em] text-oxblood-400">
                  Diagnostics
                </div>
                <h1 className="mt-1.5 text-3xl font-semibold tracking-tight text-white">Endpoints</h1>
                <p className="mt-1.5 text-base text-neutral-400">Direct links to the underlying data, useful when troubleshooting.</p>
              </div>
            </div>

            <Group title="API">
              <Row label="Build details" value="/api/build-info" />
              <Row label="Detections" value="/api/detections" />
              <Row label="Available Falcon tools" value="/api/eyas-mcp-list-tools" />
              <Row label="Liveness probe" value="/api/healthz" />
              <Row label="Health checks" value="/api/health" />
            </Group>
          </div>

          {/* ── Posture history ────────────────────────────────── */}
          <PostureHistoryCard
            count={postureHistory.count}
            lastCapturedAt={postureHistory.lastCapturedAt}
            lastPartial={postureHistory.lastPartial}
          />

          {/* ── Scopes ─────────────────────────────────────────── */}
          <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
            <div className="flex items-start gap-4">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
                <KeyRound className="h-5 w-5" strokeWidth={1.75} />
              </div>
              <div>
                <div className="text-xs font-semibold uppercase tracking-[0.14em] text-oxblood-400">
                  Scopes
                </div>
                <h1 className="mt-1.5 text-3xl font-semibold tracking-tight text-white">
                  Falcon API scopes
                </h1>
                <p className="mt-1.5 text-base text-neutral-400">
                  Every console scope this app can use, by tier — what it
                  unlocks and which surfaces light up. Grant on the API client
                  whose ID + secret powers this console (Falcon →{" "}
                  <span className="font-mono text-neutral-300">
                    Support → API Clients and Keys
                  </span>
                  ). Surfaces with missing scopes degrade cleanly; the sidebar
                  hides their nav items automatically.
                </p>
              </div>
            </div>
            <div className="mt-6">
              <ScopeChecklist initiallyOpen capStates={capStates} envName={envName} />
            </div>
          </div>

          {/* ── Sessions ───────────────────────────────────────── */}
          <SessionsCard />
        </div>
      </main>
    </AppShell>
  );
}

function formatWhen(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function PostureHistoryCard({
  count,
  lastCapturedAt,
  lastPartial,
}: {
  count: number;
  lastCapturedAt: string | null;
  lastPartial: boolean;
}) {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
      <div className="flex items-start gap-4">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
          <History className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.14em] text-oxblood-400">
            Posture history
          </div>
          <h1 className="mt-1.5 text-3xl font-semibold tracking-tight text-white">
            Trend snapshots
          </h1>
          <p className="mt-1.5 text-base text-neutral-400">
            A daily record of detections, vulnerabilities, coverage, and policy
            posture, so you can see how this tenant moves week over week.
          </p>
        </div>
      </div>

      {count === 0 ? (
        <div className="mt-6 rounded-lg border border-neutral-800 bg-neutral-950/60 p-4 text-sm text-neutral-400">
          No snapshots captured yet. Once the daily capture is turned on, the
          first record appears automatically; trends compare each capture with
          the one from about a week earlier.
        </div>
      ) : (
        <Group title="Latest capture">
          <KV label="Captured" value={formatWhen(lastCapturedAt)} />
          <KV label="Snapshots stored" value={String(count)} />
          <KV
            label="Coverage"
            value={lastPartial ? "Partial — some areas unavailable" : "All areas captured"}
            warn={lastPartial}
          />
        </Group>
      )}
    </div>
  );
}

function ProbeRow({
  label,
  hint,
  probe,
}: {
  label: string;
  hint: string;
  probe: ProbeResult;
}) {
  const detail = probe.detail
    ? Object.entries(probe.detail)
        .map(([k, v]) => `${k}: ${v}`)
        .join(" · ")
    : null;
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950/60 px-4 py-3">
      <div className="flex items-center gap-3">
        <StatusDot status={probe.status} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-neutral-100">{label}</span>
            <StatusBadge status={probe.status} />
            {probe.status !== "disabled" && (
              <span className="font-mono text-xs text-neutral-500">{probe.latencyMs} ms</span>
            )}
          </div>
          <div className="mt-0.5 text-xs text-neutral-500">{hint}</div>
        </div>
      </div>
      {(detail || probe.message) && (
        <div className="mt-2 ml-6 font-mono text-xs">
          {detail && <div className="text-neutral-400">{detail}</div>}
          {probe.message && (
            <div
              className={
                probe.status === "error"
                  ? "text-oxblood-400"
                  : probe.status === "initializing"
                    ? "text-amber-300"
                    : "text-neutral-500"
              }
            >
              {probe.message}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StatusDot({ status, large = false }: { status: ProbeStatus; large?: boolean }) {
  const size = large ? "h-3 w-3" : "h-2.5 w-2.5";
  const ring = large ? "ring-4" : "ring-2";
  const color =
    status === "ok"
      ? "bg-emerald-400 ring-emerald-400/15"
      : status === "initializing"
        ? "bg-amber-400 ring-amber-400/15 animate-pulse"
        : status === "error"
          ? "bg-red-500 ring-red-500/15"
          : "bg-neutral-500 ring-neutral-500/15";
  return <span className={`inline-block shrink-0 rounded-full ${size} ${ring} ${color}`} />;
}

function StatusBadge({ status }: { status: ProbeStatus }) {
  const text =
    status === "ok"
      ? "ok"
      : status === "initializing"
        ? "setup"
        : status === "error"
          ? "error"
          : "disabled";
  const cls =
    status === "ok"
      ? "border-emerald-900/60 bg-emerald-950/40 text-emerald-300"
      : status === "initializing"
        ? "border-amber-900/60 bg-amber-950/40 text-amber-300"
        : status === "error"
          ? "border-red-900/60 bg-red-950/40 text-oxblood-300"
          : "border-neutral-800 bg-neutral-900 text-neutral-400";
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${cls}`}
    >
      {text}
    </span>
  );
}

function Group({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mt-8">
      <h2 className="text-[13px] font-semibold uppercase tracking-[0.10em] text-neutral-400">
        {title}
      </h2>
      <div className="mt-3 overflow-hidden rounded-lg border border-neutral-800 bg-neutral-950/60">
        {children}
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <a
      href={value}
      className="group flex items-center justify-between gap-4 border-b border-neutral-800/80 px-4 py-2.5 transition-colors last:border-0 hover:bg-brand-950/15"
    >
      <span className="text-neutral-300 group-hover:text-white">{label}</span>
      <span className="inline-flex items-center gap-1 font-mono text-sm text-sky-400 group-hover:text-sky-300">
        {value}
        <ArrowUpRight className="h-3.5 w-3.5 opacity-0 transition-opacity group-hover:opacity-100" strokeWidth={2.25} />
      </span>
    </a>
  );
}

function KV({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-neutral-800/80 px-4 py-2.5 last:border-0">
      <span className="text-neutral-300">{label}</span>
      <span className={`font-mono text-sm ${warn ? "text-amber-400" : "text-neutral-100"}`}>
        {value}
      </span>
    </div>
  );
}
