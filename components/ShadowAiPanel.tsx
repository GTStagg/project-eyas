"use client";

import { useEffect, useMemo, useState } from "react";
import { ChevronDown, RefreshCw, Sparkles, MessageSquare, Shield, Check, ShieldAlert } from "lucide-react";
import HostActionButtons from "@/components/HostActionButtons";
import { buildPrimerHref } from "@/components/primerHandoff";

type FleetTool = {
  tool: string;
  posture: string;
  query_count: number;
  first_seen_ms: number | null;
  last_seen_ms: number | null;
  sample_domains: string[];
  sanctioned?: boolean;
};

type FleetItem = {
  aid: string;
  hostname?: string;
  platform?: string;
  os_product_name?: string;
  os_version?: string;
  rtr_state?: string;
  tools: FleetTool[];
};

type FleetResponse = {
  ok: boolean;
  items?: FleetItem[];
  events_scanned?: number;
  hours_back?: number;
  truncated?: boolean;
  scope_pending?: boolean;
  error?: string;
  note?: string;
};

type HostApp = {
  tool: string;
  family: string;
  posture: string;
  image_paths: string[];
  exec_count: number;
  last_seen_ms: number | null;
  top_user: string | null;
  sample_command_line: string | null;
  sanctioned?: boolean;
};

type HostMcp = {
  tool: string;
  family: string;
  posture: string;
  matched_tokens: string[];
  images: string[];
  exec_count: number;
  last_seen_ms: number | null;
  top_user: string | null;
  sample_command_line: string | null;
  sanctioned?: boolean;
};

type HostEgress = {
  tool: string;
  posture: string;
  domain: string;
  query_count: number;
  last_seen_ms: number | null;
  top_image: string | null;
  sanctioned?: boolean;
};

type HostLocalInference = {
  tool: string;
  port: number;
  scope: "loopback" | "peer";
  posture: string;
  remote_addresses: string[];
  conn_count: number;
  last_seen_ms: number | null;
  top_image: string | null;
  top_user: string | null;
  sanctioned?: boolean;
};

type HostResponse = {
  ok: boolean;
  device_id?: string;
  verdict?: string;
  apps?: HostApp[];
  mcp?: HostMcp[];
  egress?: HostEgress[];
  local_inference?: HostLocalInference[];
  events_scanned?: number;
  hours_back?: number;
  partial?: boolean;
  error?: string;
};

type AuditPolicy = {
  id: string;
  name: string;
  platform: string;
  enabled: boolean;
  rule_group_bound: boolean;
};

type AuditResponse = {
  ok?: boolean;
  ready?: boolean;
  banned_group_id?: string | null;
  rule_group_name?: string;
  rule_group_exists?: boolean;
  rule_group_enabled?: boolean;
  attached_policies?: AuditPolicy[];
  missing_steps?: string[];
  error?: string;
};

const HOURS_OPTIONS = [24, 72, 168] as const;

const VERDICT_LABEL: Record<string, string> = {
  model_developer: "Local model developer",
  mcp_host: "MCP server host",
  agentic_developer: "Agent developer",
  unsanctioned_saas: "Unsanctioned SaaS",
  code_assistant: "Code assistant",
  image_video_gen: "Creative AI",
  sanctioned: "Sanctioned",
  no_signal: "No AI signal",
};

const VERDICT_TONE: Record<string, string> = {
  model_developer:
    "border-rose-900/60 bg-rose-950/40 text-rose-200",
  mcp_host: "border-orange-900/60 bg-orange-950/40 text-orange-200",
  agentic_developer:
    "border-amber-900/60 bg-amber-950/40 text-amber-200",
  unsanctioned_saas: "border-sky-900/60 bg-sky-950/40 text-sky-200",
  code_assistant: "border-blue-900/60 bg-blue-950/40 text-blue-200",
  image_video_gen: "border-teal-900/60 bg-teal-950/40 text-teal-200",
  sanctioned: "border-emerald-900/60 bg-emerald-950/40 text-emerald-200",
  no_signal: "border-neutral-800 bg-neutral-950 text-neutral-400",
};

const POSTURE_TONE: Record<string, string> = {
  saas_inference_api: "border-sky-900 bg-sky-950/60 text-sky-200",
  saas_chat_browser: "border-blue-900 bg-blue-950/60 text-blue-200",
  code_assistant_api: "border-blue-900 bg-blue-950/60 text-blue-200",
  model_hub: "border-cyan-900 bg-cyan-950/60 text-cyan-200",
  agent_infra: "border-orange-900 bg-orange-950/60 text-orange-200",
  model_developer: "border-rose-900 bg-rose-950/60 text-rose-200",
  agentic_client: "border-amber-900 bg-amber-950/60 text-amber-200",
  saas_chat_client: "border-blue-900 bg-blue-950/60 text-blue-200",
  code_assistant: "border-blue-900 bg-blue-950/60 text-blue-200",
  image_video_gen: "border-teal-900 bg-teal-950/60 text-teal-200",
  mcp_host: "border-orange-900 bg-orange-950/60 text-orange-200",
  agentic_framework: "border-amber-900 bg-amber-950/60 text-amber-200",
};

function formatRelative(ms: number | null | undefined): string {
  if (!ms) return "—";
  const diff = Date.now() - ms;
  if (diff < 0) return "future";
  const m = Math.round(diff / 60_000);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  return `${d}d ago`;
}

// Maps the `family` tag from the Shadow-AI catalog (catalog.py) to a
// per-product uninstall script id from cleanup/manifest.json. Only the
// products with curated uninstall scripts appear here; everything else
// falls back to the generic host-kill-process + host-delete-folder
// recommendation in the primer.
function buildBanCleanPrimer(item: FleetItem) {
  const hostname = item.hostname ?? item.aid;
  const aid = item.aid;
  return `Run the agentic Shadow-AI ban-and-clean workflow on host \`${hostname}\` (AID \`${aid}\`). Load the playbook with extras_shadow_ai_workflow_playbook and proceed.`;
}

function buildRemediationPrimer(item: FleetItem, host: HostResponse | null) {
  const hostname = item.hostname ?? item.aid;
  const aid = item.aid;
  const lines: string[] = [
    `Build a Shadow-AI remediation plan for host \`${hostname}\` (AID \`${aid}\`).`,
    `Posture verdict: ${host?.verdict ?? "(unknown — re-run scan first)"}.`,
  ];
  if (host?.apps?.length) {
    lines.push(
      `Apps: ${host.apps.map((a) => `${a.tool} (${a.posture})`).join(", ")}.`,
    );
  }
  if (host?.mcp?.length) {
    lines.push(
      `MCP / agentic: ${host.mcp.map((m) => `${m.tool} (${m.posture})`).join(", ")}.`,
    );
  }
  if (host?.egress?.length) {
    lines.push(
      `Egress (top 5): ${host.egress
        .slice(0, 5)
        .map((e) => `${e.domain} → ${e.tool}`)
        .join(", ")}.`,
    );
  }
  if (host?.local_inference?.length) {
    lines.push(
      `Local inference: ${host.local_inference
        .map(
          (li) =>
            `${li.tool}:${li.port} (${li.scope}${li.scope === "peer" && li.remote_addresses[0] ? ` → ${li.remote_addresses[0]}` : ""}, ${li.conn_count} conn)`,
        )
        .join(", ")}.`,
    );
  }
  return lines.join(" ");
}

export default function ShadowAiPanel() {
  const [hours, setHours] = useState<(typeof HOURS_OPTIONS)[number]>(24);
  const [data, setData] = useState<FleetResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [hostScans, setHostScans] = useState<Record<string, HostResponse>>({});
  const [hostLoading, setHostLoading] = useState<Record<string, boolean>>({});
  const [bannedGroupId, setBannedGroupId] = useState<string | null>(null);
  const [sanctionedTools, setSanctionedTools] = useState<string[]>([]);
  const [audit, setAudit] = useState<AuditResponse | null>(null);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditOpen, setAuditOpen] = useState(false);

  const reloadConfig = async () => {
    try {
      const r = await fetch("/api/shadow-ai/config", { cache: "no-store" });
      const j = (await r.json()) as {
        ok?: boolean;
        bannedGroupId?: string | null;
        sanctionedTools?: string[];
      };
      if (j?.ok) {
        setBannedGroupId(j.bannedGroupId ?? null);
        setSanctionedTools(Array.isArray(j.sanctionedTools) ? j.sanctionedTools : []);
      }
    } catch {
      /* config fetch failures leave Ban+Clean disabled with the env-not-set message */
    }
  };

  useEffect(() => {
    void reloadConfig();
  }, []);

  const runAudit = async () => {
    setAuditLoading(true);
    setAuditOpen(true);
    try {
      const r = await fetch("/api/shadow-ai/audit", { cache: "no-store" });
      const j = (await r.json()) as AuditResponse;
      setAudit(j);
    } catch (err) {
      setAudit({ ok: false, error: err instanceof Error ? err.message : String(err) });
    } finally {
      setAuditLoading(false);
    }
  };

  const toggleSanction = async (tool: string, sanctioned: boolean) => {
    // Optimistic local update — the next fleet/host refresh re-derives
    // the verdict from the sidecar, but the chips flip immediately.
    setSanctionedTools((prev) => {
      const set = new Set(prev);
      if (sanctioned) set.add(tool.toLowerCase());
      else set.delete(tool.toLowerCase());
      return [...set].sort();
    });
    try {
      const r = await fetch("/api/shadow-ai/config", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ tool, sanctioned }),
      });
      const j = (await r.json()) as { ok?: boolean; sanctionedTools?: string[] };
      if (j?.ok && Array.isArray(j.sanctionedTools)) {
        setSanctionedTools(j.sanctionedTools);
      }
      // Drop cached host scans so the next drill-in re-fetches with
      // updated sanctioned flags + verdict from the sidecar.
      setHostScans({});
      void refresh();
    } catch {
      // Revert optimistic update on failure.
      void reloadConfig();
    }
  };

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(`/api/shadow-ai/fleet?hours=${hours}`, {
        cache: "no-store",
      });
      const j = (await r.json()) as FleetResponse;
      if (!j.ok) throw new Error(j.error ?? "request failed");
      setData(j);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hours]);

  const drillIn = async (aid: string) => {
    if (expanded === aid) {
      setExpanded(null);
      return;
    }
    setExpanded(aid);
    if (hostScans[aid]) return;
    setHostLoading((prev) => ({ ...prev, [aid]: true }));
    try {
      const r = await fetch("/api/shadow-ai/host", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ device_id: aid, hours_back: hours }),
      });
      const j = (await r.json()) as HostResponse;
      setHostScans((prev) => ({ ...prev, [aid]: j }));
    } catch (err) {
      setHostScans((prev) => ({
        ...prev,
        [aid]: {
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        },
      }));
    } finally {
      setHostLoading((prev) => ({ ...prev, [aid]: false }));
    }
  };

  const verdictBuckets = useMemo(() => {
    const buckets: Record<string, number> = {};
    Object.values(hostScans).forEach((h) => {
      if (h.verdict) buckets[h.verdict] = (buckets[h.verdict] ?? 0) + 1;
    });
    return buckets;
  }, [hostScans]);

  const items = data?.items ?? [];

  return (
    <section className="rounded-lg border border-neutral-800 bg-gradient-to-br from-neutral-950 via-neutral-950 to-neutral-950 p-6 shadow-lg shadow-black/40">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3.5">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-orange-900/60 bg-orange-950/40 text-orange-300">
            <Sparkles className="h-5 w-5" strokeWidth={1.75} />
          </div>
          <div>
            <div className="font-mono text-[12px] font-semibold uppercase tracking-[0.14em] text-orange-300">
              Fleet egress scan
            </div>
            <h2 className="mt-1 text-2xl font-semibold tracking-tight text-white">
              {data?.scope_pending
                ? "NGSIEM scope pending."
                : `${items.length} host${items.length === 1 ? "" : "s"} with AI egress signal.`}
            </h2>
            <p className="mt-1.5 max-w-3xl text-sm text-neutral-400">
              DNS queries to the AI-egress catalog over the last {hours}h, grouped by host and tool. Drill into a host for the full triple-layer profile (apps + MCP + egress) and a posture verdict.
              {data?.events_scanned !== undefined && (
                <>
                  {" "}
                  <span className="font-mono text-[11px] text-neutral-500">
                    {data.events_scanned.toLocaleString()} DNS events scanned
                    {data.truncated ? " · result truncated" : ""}.
                  </span>
                </>
              )}
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <div className="flex overflow-hidden rounded-md border border-neutral-800 bg-neutral-950">
            {HOURS_OPTIONS.map((h) => (
              <button
                key={h}
                onClick={() => setHours(h)}
                className={`px-2.5 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] transition ${
                  hours === h
                    ? "bg-neutral-800 text-white"
                    : "text-neutral-400 hover:text-white"
                }`}
              >
                {h}h
              </button>
            ))}
          </div>
          <button
            onClick={runAudit}
            disabled={auditLoading}
            title="Walk the chain from the AI-Banned host group → prevention policies → IOA rule group binding. Reports whether Ban+Clean is actually enforcing."
            className="flex h-8 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-neutral-700 hover:text-white disabled:opacity-50"
          >
            <ShieldAlert
              className={`h-3 w-3 ${auditLoading ? "animate-pulse" : ""}`}
              strokeWidth={1.75}
            />
            Audit enforcement chain
          </button>
          <button
            onClick={refresh}
            disabled={loading}
            className="flex h-8 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-neutral-700 hover:text-white disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3 w-3 ${loading ? "animate-spin" : ""}`}
              strokeWidth={1.75}
            />
            Refresh
          </button>
        </div>
      </div>

      {auditOpen && (
        <AuditPanel
          audit={audit}
          loading={auditLoading}
          onClose={() => setAuditOpen(false)}
        />
      )}

      {Object.keys(verdictBuckets).length > 0 && (
        <div className="mt-4 flex flex-wrap gap-2">
          {Object.entries(verdictBuckets).map(([v, n]) => (
            <span
              key={v}
              className={`rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] ${VERDICT_TONE[v] ?? VERDICT_TONE.no_signal}`}
            >
              {VERDICT_LABEL[v] ?? v} · {n}
            </span>
          ))}
        </div>
      )}

      {error && (
        <div className="mt-4 rounded-md border border-red-900 bg-red-950/40 px-3 py-2 font-mono text-xs text-red-200">
          {error}
        </div>
      )}

      {data?.scope_pending && (
        <div className="mt-4 rounded-md border border-dashed border-neutral-800 bg-neutral-950/60 px-4 py-6 text-sm text-neutral-400">
          NGSIEM scope is not granted on this tenant API client. Once granted, this surface will populate automatically.
        </div>
      )}

      {!error && !loading && data?.ok && items.length === 0 && (
        <div className="mt-4 rounded-md border border-dashed border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
          No DNS queries to known AI-egress endpoints in the last {hours}h.
        </div>
      )}

      {items.length > 0 && (
        <ul className="mt-4 divide-y divide-neutral-900 rounded-md border border-neutral-900 bg-neutral-950/40">
          {items.map((item) => {
            const isOpen = expanded === item.aid;
            const scan = hostScans[item.aid];
            const hostBusy = hostLoading[item.aid];
            const totalQueries = item.tools.reduce(
              (acc, t) => acc + (t.query_count || 0),
              0,
            );
            return (
              <li key={item.aid} className="px-4 py-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <button
                    onClick={() => drillIn(item.aid)}
                    className="flex min-w-0 flex-1 items-center gap-2 text-left"
                  >
                    <ChevronDown
                      className={`h-4 w-4 shrink-0 text-neutral-500 transition-transform ${
                        isOpen ? "rotate-0" : "-rotate-90"
                      }`}
                      strokeWidth={1.75}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="truncate font-mono text-sm text-white">
                          {item.hostname ??
                            `AID ${item.aid.slice(0, 8)}…${item.aid.slice(-4)}`}
                        </span>
                        {!item.hostname && (
                          <span className="rounded border border-neutral-800 bg-neutral-950 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-500">
                            not in host inventory
                          </span>
                        )}
                        {scan?.verdict && (
                          <span
                            className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] ${VERDICT_TONE[scan.verdict] ?? VERDICT_TONE.no_signal}`}
                          >
                            {VERDICT_LABEL[scan.verdict] ?? scan.verdict}
                          </span>
                        )}
                        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-500">
                          {totalQueries.toLocaleString()} DNS hits
                        </span>
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        {item.tools.slice(0, 6).map((t) => (
                          <span
                            key={t.tool}
                            className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.1em] ${
                              t.sanctioned
                                ? VERDICT_TONE.sanctioned
                                : POSTURE_TONE[t.posture] ?? POSTURE_TONE.saas_chat_browser
                            }`}
                          >
                            {t.tool} · {t.query_count}
                            {t.sanctioned ? " ✓" : ""}
                          </span>
                        ))}
                        {item.tools.length > 6 && (
                          <span className="font-mono text-[10px] text-neutral-500">
                            +{item.tools.length - 6} more
                          </span>
                        )}
                      </div>
                    </div>
                  </button>
                  <div className="flex shrink-0 items-center gap-2">
                    <HostActionButtons
                      host={{
                        device_id: item.aid,
                        hostname: item.hostname,
                        platform_name: item.platform,
                        rtr_state: item.rtr_state,
                      }}
                      irEnabled={false}
                      showIr={false}
                      size="sm"
                    />
                  </div>
                </div>

                {isOpen && (
                  <div className="mt-3 border-l-2 border-orange-900/40 pl-4">
                    {hostBusy && (
                      <div className="font-mono text-[11px] text-neutral-500">
                        Scanning host (apps + MCP + egress)…
                      </div>
                    )}
                    {scan?.ok === false && (
                      <div className="rounded-md border border-red-900 bg-red-950/40 px-3 py-2 font-mono text-xs text-red-200">
                        {scan.error ?? "scan failed"}
                      </div>
                    )}
                    {scan?.ok && (
                      <HostScanDetail
                        item={item}
                        scan={scan}
                        bannedGroupId={bannedGroupId}
                        sanctionedTools={sanctionedTools}
                        onToggleSanction={toggleSanction}
                      />
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

function HostScanDetail({
  item,
  scan,
  bannedGroupId,
  sanctionedTools,
  onToggleSanction,
}: {
  item: FleetItem;
  scan: HostResponse;
  bannedGroupId: string | null;
  sanctionedTools: string[];
  onToggleSanction: (tool: string, sanctioned: boolean) => void;
}) {
  const sanctionedSet = useMemo(
    () => new Set(sanctionedTools.map((t) => t.toLowerCase())),
    [sanctionedTools],
  );
  const isSanctioned = (tool: string) => sanctionedSet.has(tool.toLowerCase());
  const apps = scan.apps ?? [];
  const mcp = scan.mcp ?? [];
  const egress = scan.egress ?? [];
  const localInference = scan.local_inference ?? [];
  const empty =
    apps.length === 0 &&
    mcp.length === 0 &&
    egress.length === 0 &&
    localInference.length === 0;
  const primer = buildRemediationPrimer(item, scan);
  const banPrimer = bannedGroupId ? buildBanCleanPrimer(item) : null;
  // Ban+Clean only makes sense when there's something to ban / clean —
  // a host with zero observed Shadow-AI signal shouldn't be moved to
  // the banned group from this surface.
  const banDisabledReason = !bannedGroupId
    ? "Shadow-AI banned host group is not set on the active environment (/config)"
    : empty
      ? "no Shadow-AI artifacts to clean on this host"
      : null;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <a
          href={buildPrimerHref(primer)}
          className="flex h-8 items-center gap-1.5 rounded-md border border-orange-900/60 bg-orange-950/40 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-orange-200 transition hover:bg-orange-900/40 hover:text-white"
        >
          <MessageSquare className="h-3 w-3" strokeWidth={1.75} />
          Ask agent
        </a>
        {banDisabledReason ? (
          <span
            title={banDisabledReason}
            className="flex h-8 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950/60 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-600"
          >
            <Shield className="h-3 w-3" strokeWidth={1.75} />
            Ban + Clean (workflow) unavailable
          </span>
        ) : (
          <a
            href={buildPrimerHref(banPrimer!)}
            title="Move host into AI-Banned group, fire per-product uninstalls, add detect-only IOCs for SaaS endpoints. Each write step prompts for approval."
            className="flex h-8 items-center gap-1.5 rounded-md border border-brand-900/60 bg-brand-950/40 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-oxblood-200 transition hover:bg-brand-900/40 hover:text-white"
          >
            <Shield className="h-3 w-3" strokeWidth={1.75} />
            Ban + Clean (workflow)
          </a>
        )}
        {scan.partial && (
          <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-amber-300">
            Partial result — at least one NGSIEM pass returned an error
          </span>
        )}
        {scan.events_scanned !== undefined && (
          <span className="font-mono text-[10px] text-neutral-500">
            {scan.events_scanned.toLocaleString()} events scanned · last{" "}
            {scan.hours_back}h
          </span>
        )}
      </div>

      {empty && (
        <div className="rounded-md border border-dashed border-neutral-800 bg-neutral-950/60 px-3 py-4 text-center text-sm text-neutral-500">
          Egress observed at the fleet layer, but no app, MCP, or DNS catalog
          match on this host within the deeper window. The egress may be from
          a process the catalog doesn&apos;t enumerate (e.g. a background
          browser tab); widen <code>hours</code> or inspect manually.
        </div>
      )}

      {apps.length > 0 && (
        <DetailList
          title="AI desktop apps"
          onToggleSanction={onToggleSanction}
          rows={apps.map((a) => ({
            tool: a.tool,
            head: a.tool,
            posture: a.posture,
            sanctioned: isSanctioned(a.tool),
            secondary:
              (a.image_paths[0] ?? "") +
              (a.image_paths.length > 1
                ? ` (+${a.image_paths.length - 1} path${a.image_paths.length > 2 ? "s" : ""})`
                : ""),
            tertiary: `${a.exec_count} execution${a.exec_count === 1 ? "" : "s"}${a.top_user ? ` · ${a.top_user}` : ""} · ${formatRelative(a.last_seen_ms)}`,
          }))}
        />
      )}

      {mcp.length > 0 && (
        <DetailList
          title="MCP / agentic-framework processes"
          onToggleSanction={onToggleSanction}
          rows={mcp.map((m) => ({
            tool: m.tool,
            head: m.tool,
            posture: m.posture,
            sanctioned: isSanctioned(m.tool),
            secondary: m.sample_command_line ?? m.matched_tokens.join(", "),
            tertiary: `${m.exec_count} exec · ${m.top_user ?? "unknown user"} · ${formatRelative(m.last_seen_ms)}`,
          }))}
        />
      )}

      {egress.length > 0 && (
        <DetailList
          title="DNS egress to AI endpoints"
          onToggleSanction={onToggleSanction}
          rows={egress.map((e) => ({
            tool: e.tool,
            head: e.domain,
            posture: e.posture,
            sanctioned: isSanctioned(e.tool),
            secondary: `${e.tool}${e.top_image ? ` · via ${e.top_image.split(/[\\/]/).pop()}` : ""}`,
            tertiary: `${e.query_count} quer${e.query_count === 1 ? "y" : "ies"} · ${formatRelative(e.last_seen_ms)}`,
          }))}
        />
      )}

      {localInference.length > 0 && (
        <DetailList
          title="Local-inference connections (loopback = host serves a model · peer = host consumes a peer's model)"
          onToggleSanction={onToggleSanction}
          rows={localInference.map((li) => {
            const remote =
              li.scope === "peer" && li.remote_addresses.length > 0
                ? li.remote_addresses[0] +
                  (li.remote_addresses.length > 1
                    ? ` (+${li.remote_addresses.length - 1})`
                    : "")
                : "127.0.0.0/8";
            const headTag =
              li.scope === "peer" ? "PEER" : "LOOPBACK";
            return {
              tool: li.tool,
              head: `${headTag} · ${li.tool}:${li.port}`,
              posture: li.posture,
              sanctioned: isSanctioned(li.tool),
              secondary: `${remote}${li.top_image ? ` · via ${li.top_image.split(/[\\/]/).pop()}` : ""}${li.top_user ? ` · ${li.top_user}` : ""}`,
              tertiary: `${li.conn_count} connection${li.conn_count === 1 ? "" : "s"} · ${formatRelative(li.last_seen_ms)}`,
            };
          })}
        />
      )}
    </div>
  );
}

function AuditPanel({
  audit,
  loading,
  onClose,
}: {
  audit: AuditResponse | null;
  loading: boolean;
  onClose: () => void;
}) {
  const ready = audit?.ok && audit.ready === true;
  const failed = audit && (audit.ok === false || audit.ready === false);
  const tone = ready
    ? "border-emerald-900/60 bg-emerald-950/30"
    : failed
      ? "border-amber-900/60 bg-amber-950/30"
      : "border-neutral-800 bg-neutral-950/60";
  const headlineTone = ready
    ? "text-emerald-200"
    : failed
      ? "text-amber-200"
      : "text-neutral-300";

  return (
    <div className={`mt-4 rounded-md border ${tone} px-4 py-3`}>
      <div className="flex items-center justify-between gap-2">
        <div className={`font-mono text-[11px] font-semibold uppercase tracking-[0.14em] ${headlineTone}`}>
          {loading
            ? "Auditing prevention binding…"
            : ready
              ? "Prevention is enforcing on the AI-Banned host group"
              : audit?.ok === false
                ? `Audit failed: ${audit.error ?? "unknown error"}`
                : "Prevention is NOT enforcing — see steps below"}
        </div>
        <button
          onClick={onClose}
          className="font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-500 hover:text-white"
        >
          Close
        </button>
      </div>

      {!loading && audit?.ok !== false && (
        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="space-y-1 font-mono text-[11px] text-neutral-400">
            <div>
              <span className="text-neutral-500">Banned group:</span>{" "}
              {audit?.banned_group_id ? (
                <span className="text-neutral-200">{audit.banned_group_id}</span>
              ) : (
                <span className="text-amber-300">unset</span>
              )}
            </div>
            <div>
              <span className="text-neutral-500">Rule group:</span>{" "}
              {audit?.rule_group_exists ? (
                <span
                  className={
                    audit?.rule_group_enabled ? "text-emerald-200" : "text-amber-300"
                  }
                >
                  {audit.rule_group_name}
                  {audit?.rule_group_enabled ? " · enabled" : " · disabled"}
                </span>
              ) : (
                <span className="text-amber-300">not created</span>
              )}
            </div>
          </div>
          <div className="space-y-1 font-mono text-[11px]">
            <div className="text-neutral-500">Attached prevention policies:</div>
            {audit?.attached_policies && audit.attached_policies.length > 0 ? (
              <ul className="space-y-0.5">
                {audit.attached_policies.map((p) => (
                  <li key={p.id}>
                    <span className="text-neutral-200">{p.name}</span>{" "}
                    <span className="text-neutral-500">({p.platform})</span>{" "}
                    <span
                      className={
                        p.rule_group_bound && p.enabled
                          ? "text-emerald-300"
                          : "text-amber-300"
                      }
                    >
                      {p.enabled ? (p.rule_group_bound ? "✓ bound" : "rule group not bound") : "policy disabled"}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <span className="text-amber-300">none</span>
            )}
          </div>
        </div>
      )}

      {!loading && audit?.missing_steps && audit.missing_steps.length > 0 && (
        <ol className="mt-3 list-decimal space-y-1.5 pl-5 text-sm text-neutral-300">
          {audit.missing_steps.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
      )}
    </div>
  );
}

function DetailList({
  title,
  rows,
  onToggleSanction,
}: {
  title: string;
  rows: Array<{
    tool: string;
    head: string;
    posture: string;
    sanctioned: boolean;
    secondary: string;
    tertiary: string;
  }>;
  onToggleSanction: (tool: string, sanctioned: boolean) => void;
}) {
  return (
    <div>
      <div className="mb-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-neutral-400">
        {title}
      </div>
      <ul className="divide-y divide-neutral-900 rounded-md border border-neutral-900 bg-neutral-950/60">
        {rows.map((r, i) => (
          <li key={`${r.head}-${i}`} className="px-3 py-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm text-white">{r.head}</span>
              <span
                className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.1em] ${
                  r.sanctioned
                    ? VERDICT_TONE.sanctioned
                    : POSTURE_TONE[r.posture] ?? "border-neutral-800 bg-neutral-950 text-neutral-300"
                }`}
              >
                {r.sanctioned ? "sanctioned" : r.posture}
              </span>
              <button
                onClick={() => onToggleSanction(r.tool, !r.sanctioned)}
                title={
                  r.sanctioned
                    ? `Remove "${r.tool}" from this tenant's sanctioned-tools list`
                    : `Mark "${r.tool}" sanctioned for this tenant — drops it from the verdict signal bag and hides it from fleet-only-sanctioned hosts`
                }
                className={`ml-auto flex h-6 items-center gap-1 rounded border px-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] transition ${
                  r.sanctioned
                    ? "border-emerald-900/60 bg-emerald-950/40 text-emerald-200 hover:border-emerald-800 hover:text-white"
                    : "border-neutral-800 bg-neutral-950 text-neutral-400 hover:border-emerald-900 hover:text-emerald-200"
                }`}
              >
                <Check className="h-3 w-3" strokeWidth={2} />
                {r.sanctioned ? "Sanctioned" : "Sanction"}
              </button>
            </div>
            {r.secondary && (
              <div className="mt-0.5 truncate font-mono text-[11px] text-neutral-400">
                {r.secondary}
              </div>
            )}
            <div className="mt-0.5 font-mono text-[10px] text-neutral-500">
              {r.tertiary}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
