"use client";

// Control-center widget registry + grid. Each widget is a capability launcher:
// click a tile → the dashboard opens that capability's live panel in the
// right-side snack panel. Adding a new capability later = one entry here + one
// panel (or an AGENT_TOOLS config) + one case in HomeDashboard's panel router.
//
// Widgets are grouped into labelled sections so the grid stays scannable as the
// library grows, capability-gated per tenant, and can show a live "glance"
// stat on the tile before you click in.

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  MessageSquare,
  Terminal,
  Search,
  FileText,
  Radar,
  Fingerprint,
  UserSearch,
  KeyRound,
  Boxes,
  Network,
  ListChecks,
  Bot,
  DollarSign,
  ShieldCheck,
  ArrowUpRight,
  type LucideIcon,
} from "lucide-react";

export type WidgetKind =
  | "priority"
  | "campaigns"
  | "chat"
  | "ngsiem"
  | "pivot"
  | "briefing"
  | "recon"
  | "malquery"
  | "intel"
  | "identity"
  | "discover"
  | "correlation"
  | "guardian"
  | "spend"
  | "contained";

type WidgetGroup = "Triage" | "Ask & hunt" | "Posture" | "Operations";

// Capability key gating the widget (eyas-mcp capability flags from /api/health).
type Cap = "recon" | "malQuery" | "idp" | "discover" | "intel" | "correlationRules" | "guardian";

export type WidgetDef = {
  id: WidgetKind;
  group: WidgetGroup;
  label: string;
  blurb: string;
  icon: LucideIcon;
  requiresCap?: Cap;
};

export const CONTROL_WIDGETS: WidgetDef[] = [
  // Triage — what's happening right now; tiles pop the results into the panel.
  { id: "priority", group: "Triage", label: "Priority detections", blurb: "Open detections ranked for attention — triage or run IR in place.", icon: ListChecks },
  { id: "campaigns", group: "Triage", label: "Cross-host campaigns", blurb: "Detections clustered across hosts by shared artifact — reconstruct the campaign.", icon: Network },
  { id: "contained", group: "Triage", label: "Contained hosts", blurb: "Hosts currently isolated by response actions.", icon: ShieldCheck },
  // Ask & hunt — interactive tools.
  { id: "chat", group: "Ask & hunt", label: "Ask the agent", blurb: "Prompt the agent right here — full tool access, approvals inline.", icon: MessageSquare },
  { id: "ngsiem", group: "Ask & hunt", label: "NGSIEM query", blurb: "Ask in plain English; CQL and results stream into the panel.", icon: Terminal },
  { id: "pivot", group: "Ask & hunt", label: "Artifact pivot", blurb: "Hash / IP / domain / URL — reputation, custom list, tenant exposure.", icon: Search },
  { id: "briefing", group: "Ask & hunt", label: "Daily briefing", blurb: "One-page security report for this tenant, generated on demand.", icon: FileText },
  { id: "recon", group: "Ask & hunt", label: "Exposure recon", blurb: "Breach, dark-web, and paste exposure for a domain or email.", icon: Radar, requiresCap: "recon" },
  { id: "malquery", group: "Ask & hunt", label: "MalQuery", blurb: "Hash lineage across CrowdStrike's malware research corpus.", icon: Fingerprint, requiresCap: "malQuery" },
  // Posture — one-click decision documents.
  { id: "intel", group: "Posture", label: "Adversary intel", blurb: "Adversaries with evidence in this tenant and their playbooks.", icon: UserSearch, requiresCap: "intel" },
  { id: "identity", group: "Posture", label: "Identity posture", blurb: "Risky identities, active IDP detections, sensor posture.", icon: KeyRound, requiresCap: "idp" },
  { id: "discover", group: "Posture", label: "Asset discovery", blurb: "Inventory coverage gaps and privileged-account review.", icon: Boxes, requiresCap: "discover" },
  { id: "correlation", group: "Posture", label: "Correlation rules", blurb: "NGSIEM rule health — coverage gaps, stale and inactive rules.", icon: Network, requiresCap: "correlationRules" },
  { id: "guardian", group: "Posture", label: "AI agent activity", blurb: "AI agents, sessions, and models in this tenant — with Agentic Threat Scores.", icon: Bot, requiresCap: "guardian" },
  // Operations.
  { id: "spend", group: "Operations", label: "Spend", blurb: "Monthly projection broken down by surface and model.", icon: DollarSign },
];

const GROUP_ORDER: WidgetGroup[] = ["Triage", "Ask & hunt", "Posture", "Operations"];

export function ControlCenterGrid({
  onOpen,
  stats,
}: {
  onOpen: (kind: WidgetKind) => void;
  stats?: Partial<Record<WidgetKind, string>>;
}) {
  const [deniedCaps, setDeniedCaps] = useState<Set<Cap>>(() => new Set());
  const [capsReady, setCapsReady] = useState(false);
  // Live "glance" stats fetched by the grid itself (parent supplies spend +
  // contained). Only fired for capabilities the tenant actually has.
  const [liveStats, setLiveStats] = useState<Partial<Record<WidgetKind, string>>>({});

  useEffect(() => {
    let cancelled = false;
    fetch("/api/health", { cache: "no-store" })
      .then((r) => r.json())
      .then((j) => {
        if (cancelled) return;
        const mc = j?.falconMcp?.capabilities ?? {};
        const denied = new Set<Cap>();
        // Hide a widget only on a CONCLUSIVE denial (=== false).
        (["recon", "discover", "intel", "correlationRules", "guardian", "malQuery", "idp"] as const).forEach((c) => {
          if (mc[c] === false) denied.add(c);
        });
        setDeniedCaps(denied);
        setCapsReady(true);
      })
      .catch(() => setCapsReady(true));
    return () => {
      cancelled = true;
    };
  }, []);

  // Glanceable stats for Discover + Correlation (both have a cheap GET). Fired
  // only after caps resolve, and only when the scope is present — non-blocking,
  // so tiles render immediately and the number fills in when ready.
  useEffect(() => {
    if (!capsReady) return;
    let cancelled = false;
    if (!deniedCaps.has("discover")) {
      void fetch("/api/discover", { cache: "no-store" })
        .then((r) => r.json())
        .then((j) => {
          if (cancelled || !j?.ok || j.scope_pending || !j.summary) return;
          const n = j.summary?.assets?.unmanaged ?? 0;
          setLiveStats((s) => ({ ...s, discover: `${n} unmanaged` }));
        })
        .catch(() => {});
    }
    if (!deniedCaps.has("correlationRules")) {
      void fetch("/api/correlation", { cache: "no-store" })
        .then((r) => r.json())
        .then((j) => {
          if (cancelled || !j?.ok || j.scope_pending || !j.health) return;
          const stale = j.health?.stale?.length ?? 0;
          const inactive = j.health?.byStatus?.inactive ?? 0;
          setLiveStats((s) => ({ ...s, correlation: `${stale} stale · ${inactive} inactive` }));
        })
        .catch(() => {});
    }
    return () => {
      cancelled = true;
    };
  }, [capsReady, deniedCaps]);

  const merged = { ...liveStats, ...stats };
  const visible = CONTROL_WIDGETS.filter((w) => !(w.requiresCap && deniedCaps.has(w.requiresCap)));

  return (
    <div className="space-y-5">
      {GROUP_ORDER.map((group) => {
        const items = visible
          .filter((w) => w.group === group)
          .sort((a, b) => a.label.localeCompare(b.label));
        if (items.length === 0) return null;
        return (
          <div key={group}>
            <div className="mb-2 flex items-center gap-2 px-0.5 font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
              <span className="h-px w-3 bg-neutral-700" />
              {group}
            </div>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {items.map((w) => (
                <WidgetTile key={w.id} def={w} stat={merged?.[w.id]} onClick={() => onOpen(w.id)} />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function WidgetTile({
  def,
  stat,
  onClick,
}: {
  def: WidgetDef;
  stat?: string;
  onClick: () => void;
}) {
  const Icon = def.icon;
  return (
    <button
      type="button"
      onClick={onClick}
      className="group relative flex h-full flex-col rounded-lg border border-neutral-800 bg-neutral-950 p-4 text-left outline-none transition-colors hover:border-brand-700/60 focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-brand-700/50"
    >
      <div className="flex items-start justify-between">
        <div className="flex h-9 w-9 items-center justify-center rounded-md border border-brand-900/40 bg-brand-950/40 text-oxblood-300">
          <Icon className="h-4.5 w-4.5" strokeWidth={1.75} />
        </div>
        <ArrowUpRight className="h-4 w-4 text-neutral-700 transition-colors group-hover:text-oxblood-300" strokeWidth={2} />
      </div>
      <div className="mt-3 text-sm font-semibold text-neutral-100">{def.label}</div>
      {stat ? (
        <div className="mt-0.5 font-mono text-[13px] font-bold tabular-nums text-oxblood-200">{stat}</div>
      ) : null}
      <p className="mt-1 text-[12px] leading-snug text-neutral-500">{def.blurb}</p>
    </button>
  );
}

export function fullChatFooter() {
  return (
    <Link
      href="/"
      className="inline-flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-brand-700/60 hover:text-oxblood-200"
    >
      Open full chat
      <ArrowUpRight className="h-3.5 w-3.5" strokeWidth={2} />
    </Link>
  );
}
