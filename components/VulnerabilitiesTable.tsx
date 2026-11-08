"use client";

import { useMemo, useRef, useState } from "react";
import Link from "next/link";
import { ArrowUpRight, ChevronRight, ExternalLink, MessageSquare, Search, ShieldCheck, Wrench } from "lucide-react";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";
import { buildPrimerHref } from "@/components/primerHandoff";

type CVE = {
  id?: string;
  description?: string;
  severity?: string;
  base_score?: number;
  exprt_rating?: string;
  exploit_status?: number;
  cvss_v3_score?: { score?: number; vector?: string };
  vendor_advisory?: string[];
  references?: string[];
  cisa_info?: { is_cisa_kev?: boolean; due_date?: string };
};

type HostInfo = {
  hostname?: string;
  platform?: string;
  os_version?: string;
  device_id?: string;
};

type App = {
  product_name_version?: string;
  product_name_normalized?: string;
  vendor?: string;
  vendor_normalized?: string;
};

type RemediationEntity = {
  id?: string;
  reference?: string;
  title?: string;
  action?: string;
  link?: string;
  vendor_url?: string;
  recommendation_type?: string;
};

type Remediation = { ids?: string[]; entities?: RemediationEntity[] };

export type Vulnerability = {
  id?: string;
  aid?: string;
  status?: string;
  created_timestamp?: string;
  closed_timestamp?: string;
  cve?: CVE;
  cve_id?: string;
  severity?: string;
  cvss_base_score?: number;
  exprt_rating?: string;
  hostname?: string;
  platform?: string;
  os_version?: string;
  product?: string;
  apps_count?: number;
  remediation?: string[] | Remediation;
  host_info?: HostInfo;
  apps?: App[];
  // Server-derived: true when the vuln's aid does not match any managed
  // Falcon host (network-discovered via NVA / Discover, no sensor installed).
  // Patch automation cannot run against these; surface as awareness only.
  _unmanaged?: boolean;
  // Server-derived: true when this is a Windows remediation that no curated
  // patch script covers, but the generic installer can still close it at
  // runtime (operator supplies a vendor URL). Drives the coverage-gap badge.
  capability_gap?: boolean;
};

// ExPRT is the higher-signal risk rating (CrowdStrike's adjusted score factoring in
// real-world exploitation), so it gets the strong palette. Severity is the raw CVSS
// bucket — useful but secondary, so it gets the subdued pill treatment.
const EXPRT_TONE: Record<string, string> = {
  CRITICAL: "bg-red-900/60 text-red-200 border border-red-800",
  HIGH: "bg-orange-900/60 text-orange-200 border border-orange-800",
  MEDIUM: "bg-yellow-900/60 text-yellow-100 border border-yellow-800",
  LOW: "bg-sky-900/60 text-sky-200 border border-sky-800",
  MINIMAL: "bg-neutral-800 text-neutral-300 border border-neutral-700",
};

const SEV_TONE: Record<string, string> = {
  CRITICAL: "bg-red-900/40 text-oxblood-300",
  HIGH: "bg-orange-900/40 text-orange-300",
  MEDIUM: "bg-amber-900/40 text-amber-300",
  LOW: "bg-emerald-900/40 text-emerald-300",
  UNKNOWN: "bg-neutral-800 text-neutral-400",
};

const STATUS_TONE: Record<string, string> = {
  open: "bg-amber-900/60 text-amber-200",
  closed: "bg-neutral-800 text-neutral-400",
  reopen: "bg-emerald-900/60 text-emerald-200",
  expired: "bg-neutral-800 text-neutral-500",
};

function formatTime(iso?: string): string {
  if (!iso) return "—";
  return iso.slice(0, 10);
}

function pickCveId(v: Vulnerability): string {
  return v.cve_id ?? v.cve?.id ?? "—";
}
function pickSeverity(v: Vulnerability): string {
  return (v.severity ?? v.cve?.severity ?? "UNKNOWN").toUpperCase();
}
function pickCvss(v: Vulnerability): number | undefined {
  return v.cvss_base_score ?? v.cve?.base_score ?? v.cve?.cvss_v3_score?.score;
}
function pickExprt(v: Vulnerability): string | undefined {
  return v.exprt_rating ?? v.cve?.exprt_rating;
}
function pickHostname(v: Vulnerability): string {
  return v.hostname ?? v.host_info?.hostname ?? "—";
}
function pickProduct(v: Vulnerability): string {
  return v.product ?? v.apps?.[0]?.product_name_version ?? "—";
}
function pickRemediationEntities(v: Vulnerability): RemediationEntity[] {
  const r = v.remediation;
  if (!r) return [];
  if (Array.isArray(r)) return r.map((id) => ({ id }));
  if (r.entities && r.entities.length > 0) return r.entities;
  return (r.ids ?? []).map((id) => ({ id }));
}

// Returns the recommended remediation entity (or the first one) for grouping.
function pickRecommendedRemediation(v: Vulnerability): RemediationEntity | undefined {
  const ents = pickRemediationEntities(v);
  if (ents.length === 0) return undefined;
  return ents.find((e) => e.recommendation_type === "recommended") ?? ents[0];
}

// Stable string id used as a Map key when grouping; falls back through layers
// so groups still cluster correctly even when CrowdStrike returns only minimal data.
function remediationKey(e: RemediationEntity): string {
  return e.id ?? e.reference ?? e.title ?? "?";
}

// Human-readable label for a remediation. Examples:
//   "Update Mozilla Firefox · 150.0"
//   "Update Mozilla Firefox"
//   "(internal id 6e9908f24…)"
function remediationLabel(e: RemediationEntity): string {
  if (e.title && e.reference) return `${e.title} · ${e.reference}`;
  if (e.title) return e.title;
  if (e.id) return `id ${e.id.slice(0, 12)}…`;
  return "(unknown)";
}

export type ViewMode = "flat" | "patch" | "host";
export type FilterKey = "criticalHigh" | "exploited" | "hasFix" | "stale" | "kev";

// CISA Known Exploited Vulnerabilities catalog — gold-standard "actively
// exploited in the wild" signal published by the US government. The Spotlight
// CVE record carries this flag directly; we surface it as a per-row chip and
// a top-level filter because Falcon Intel's CVE→actor linkage is sparse and
// CISA KEV gives the operator a more reliable "drop everything" signal.
function isCisaKev(v: Vulnerability): boolean {
  return v.cve?.cisa_info?.is_cisa_kev === true;
}

function exploitStatusScore(v: Vulnerability): number {
  return v.cve?.exploit_status ?? 0;
}

const STALE_DAYS = 30;

function daysSince(iso?: string): number | undefined {
  if (!iso) return undefined;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return undefined;
  return Math.floor((Date.now() - t) / 86_400_000);
}

// "Actively exploited" per CrowdStrike — combines all in-record signals so
// an operator clicking the Exploited filter (or the hero tile) sees the full
// CrowdStrike-recognized set, not just the ExPRT slice. Components:
//   - ExPRT rating High/Critical (CrowdStrike's analyst-curated rating);
//   - exploit_status >= 60 (Easily accessible code; 90+ = actively used);
//   - CISA KEV flag (US-CERT confirmed in-the-wild exploitation).
// CISA KEV is included because the catalog occasionally adds CVEs ahead of
// ExPRT graduating them — leaving them out under-reads the actively-exploited
// surface this tool is supposed to highlight.
function isExploited(v: Vulnerability): boolean {
  const exprt = (pickExprt(v) ?? "").toUpperCase();
  if (exprt === "HIGH" || exprt === "CRITICAL") return true;
  const status = v.cve?.exploit_status ?? 0;
  if (status >= 60) return true;
  return isCisaKev(v);
}

function osLabel(v: Vulnerability): string {
  const platform = v.platform ?? v.host_info?.platform;
  const os = v.os_version ?? v.host_info?.os_version;
  if (platform && os) return `${platform} · ${os}`;
  return os ?? platform ?? "—";
}

const SEV_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

type PatchGroup = {
  key: string;
  label: string;
  hasFix: boolean;
  vulns: Vulnerability[];
  hosts: Set<string>;
  unmanagedHosts: Set<string>;
  cves: Set<string>;
  maxSev: string;
  maxExprt: string;
  exploitedCount: number;
  // True when no curated patch script covers this remediation but the generic
  // installer can still close it (Windows + operator-supplied vendor URL).
  // Server-stamped per row via capability_gap; aggregated here.
  capabilityGap: boolean;
};

const EXPRT_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  MINIMAL: 0,
  "": -1,
};

function groupByPatch(items: Vulnerability[]): PatchGroup[] {
  const groups = new Map<string, PatchGroup>();
  for (const v of items) {
    const rec = pickRecommendedRemediation(v);
    const hasFix = !!rec;
    const key = hasFix ? remediationKey(rec) : "__no_fix";
    const label = hasFix ? remediationLabel(rec) : "No fix available";
    let g = groups.get(key);
    if (!g) {
      g = {
        key,
        label,
        hasFix,
        vulns: [],
        hosts: new Set(),
        unmanagedHosts: new Set(),
        cves: new Set(),
        maxSev: "UNKNOWN",
        maxExprt: "",
        exploitedCount: 0,
        capabilityGap: false,
      };
      groups.set(key, g);
    }
    g.vulns.push(v);
    if (v.capability_gap) g.capabilityGap = true;
    const host = pickHostname(v);
    if (host && host !== "—") {
      g.hosts.add(host);
      if (v._unmanaged) g.unmanagedHosts.add(host);
    }
    const cve = pickCveId(v);
    if (cve && cve !== "—") g.cves.add(cve);
    const sev = pickSeverity(v);
    if ((SEV_RANK[sev] ?? 0) > (SEV_RANK[g.maxSev] ?? 0)) g.maxSev = sev;
    const exprt = (pickExprt(v) ?? "").toUpperCase();
    if ((EXPRT_RANK[exprt] ?? -1) > (EXPRT_RANK[g.maxExprt] ?? -1)) g.maxExprt = exprt;
    if (exprt === "HIGH" || exprt === "CRITICAL") g.exploitedCount += 1;
  }
  return Array.from(groups.values()).sort((a, b) => {
    // No-fix bucket last; then ExPRT (the risk-adjusted signal that drives
    // the demo's prioritization), then exploited count, then CVE count.
    if (a.hasFix !== b.hasFix) return a.hasFix ? -1 : 1;
    const exprt = (EXPRT_RANK[b.maxExprt] ?? -1) - (EXPRT_RANK[a.maxExprt] ?? -1);
    if (exprt !== 0) return exprt;
    if (b.exploitedCount !== a.exploitedCount) return b.exploitedCount - a.exploitedCount;
    return b.cves.size - a.cves.size;
  });
}

type HostGroup = {
  hostname: string;
  os: string;
  vulns: Vulnerability[];
  cves: Set<string>;
  maxSev: string;
  exploitedCount: number;
  oldestDays: number;
  topPatch?: { id: string; closes: number };
};

function groupByHost(items: Vulnerability[]): HostGroup[] {
  const groups = new Map<string, HostGroup>();
  for (const v of items) {
    const hostname = pickHostname(v);
    if (!hostname || hostname === "—") continue;
    let g = groups.get(hostname);
    if (!g) {
      g = {
        hostname,
        os: osLabel(v),
        vulns: [],
        cves: new Set(),
        maxSev: "UNKNOWN",
        exploitedCount: 0,
        oldestDays: 0,
      };
      groups.set(hostname, g);
    }
    g.vulns.push(v);
    const cve = pickCveId(v);
    if (cve && cve !== "—") g.cves.add(cve);
    const sev = pickSeverity(v);
    if ((SEV_RANK[sev] ?? 0) > (SEV_RANK[g.maxSev] ?? 0)) g.maxSev = sev;
    if (isExploited(v)) g.exploitedCount += 1;
    const age = daysSince(v.created_timestamp) ?? 0;
    if (age > g.oldestDays) g.oldestDays = age;
  }
  // Compute top patch per host: the remediation closing the most CVEs on this host.
  for (const g of groups.values()) {
    const counts = new Map<string, { label: string; cves: Set<string> }>();
    for (const v of g.vulns) {
      const cve = pickCveId(v);
      if (!cve || cve === "—") continue;
      const rec = pickRecommendedRemediation(v);
      if (!rec) continue;
      const k = remediationKey(rec);
      let entry = counts.get(k);
      if (!entry) {
        entry = { label: remediationLabel(rec), cves: new Set() };
        counts.set(k, entry);
      }
      entry.cves.add(cve);
    }
    let best: { id: string; closes: number } | undefined;
    for (const [, entry] of counts.entries()) {
      if (!best || entry.cves.size > best.closes) {
        best = { id: entry.label, closes: entry.cves.size };
      }
    }
    g.topPatch = best;
  }
  return Array.from(groups.values()).sort((a, b) => {
    const sev = (SEV_RANK[b.maxSev] ?? 0) - (SEV_RANK[a.maxSev] ?? 0);
    if (sev !== 0) return sev;
    if (b.exploitedCount !== a.exploitedCount)
      return b.exploitedCount - a.exploitedCount;
    return b.cves.size - a.cves.size;
  });
}

type ActiveFilters = Record<FilterKey, boolean>;

const EMPTY_FILTERS: ActiveFilters = {
  criticalHigh: false,
  exploited: false,
  hasFix: false,
  stale: false,
  kev: false,
};

function filtersFromList(keys: FilterKey[] | undefined): ActiveFilters {
  if (!keys || keys.length === 0) return EMPTY_FILTERS;
  return {
    criticalHigh: keys.includes("criticalHigh"),
    exploited: keys.includes("exploited"),
    hasFix: keys.includes("hasFix"),
    stale: keys.includes("stale"),
    kev: keys.includes("kev"),
  };
}

function applyFilters(items: Vulnerability[], f: ActiveFilters): Vulnerability[] {
  if (!f.criticalHigh && !f.exploited && !f.hasFix && !f.stale && !f.kev) return items;
  return items.filter((v) => {
    if (f.criticalHigh) {
      const exprt = (pickExprt(v) ?? "").toUpperCase();
      if (exprt !== "CRITICAL" && exprt !== "HIGH") return false;
    }
    if (f.exploited && !isExploited(v)) return false;
    if (f.hasFix && pickRemediationEntities(v).length === 0) return false;
    if (f.kev && !isCisaKev(v)) return false;
    if (f.stale) {
      const age = daysSince(v.created_timestamp);
      if (age == null || age < STALE_DAYS) return false;
    }
    return true;
  });
}

export default function VulnerabilitiesTable({
  items,
  defaultView,
  defaultFilters,
}: {
  items: Vulnerability[];
  defaultView?: ViewMode;
  defaultFilters?: FilterKey[];
}) {
  const [view, setView] = useState<ViewMode>(defaultView ?? "flat");
  const [filters, setFilters] = useState<ActiveFilters>(filtersFromList(defaultFilters));

  const filtered = useMemo(() => applyFilters(items, filters), [items, filters]);
  const groups = useMemo(
    () => (view === "patch" ? groupByPatch(filtered) : []),
    [view, filtered],
  );
  const hostGroups = useMemo(
    () => (view === "host" ? groupByHost(filtered) : []),
    [view, filtered],
  );

  const counts = useMemo(
    () => ({
      flat: filtered.length,
      patch: groupByPatch(filtered).length,
      host: groupByHost(filtered).length,
    }),
    [filtered],
  );

  if (items.length === 0) {
    return (
      <div className="mt-6 flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-neutral-800 bg-neutral-950/60 p-12 text-center">
        <div className="flex h-10 w-10 items-center justify-center rounded-full border border-emerald-900/60 bg-emerald-950/40 text-emerald-300">
          <ShieldCheck className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div className="text-base font-semibold text-neutral-100">No open vulnerabilities.</div>
        <div className="max-w-sm text-sm text-neutral-500">
          Either Spotlight is quiet, or filters trimmed the result set to nothing.
        </div>
      </div>
    );
  }

  const toggleFilter = (k: keyof ActiveFilters) =>
    setFilters((f) => ({ ...f, [k]: !f[k] }));

  return (
    <>
      <div className="mt-4 flex flex-wrap items-center gap-2 font-mono text-[11px] uppercase tracking-[0.14em] text-neutral-400">
        <span>filter //</span>
        <FilterChip label="Critical + High" active={filters.criticalHigh} onClick={() => toggleFilter("criticalHigh")} />
        <FilterChip label="CISA KEV" active={filters.kev} onClick={() => toggleFilter("kev")} tone="red" />
        <FilterChip label="Exploited" active={filters.exploited} onClick={() => toggleFilter("exploited")} tone="red" />
        <FilterChip label="Has fix" active={filters.hasFix} onClick={() => toggleFilter("hasFix")} />
        <FilterChip label={`Stale ${STALE_DAYS}d+`} active={filters.stale} onClick={() => toggleFilter("stale")} tone="amber" />
        {(filters.criticalHigh || filters.exploited || filters.hasFix || filters.stale || filters.kev) && (
          <button
            type="button"
            onClick={() => setFilters(EMPTY_FILTERS)}
            className="rounded px-2 py-1 text-neutral-500 hover:text-neutral-200"
          >
            clear
          </button>
        )}
      </div>

      <div className="mt-2 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.14em] text-neutral-400">
        <span>view //</span>
        <ViewToggle label={`Flat (${counts.flat})`} active={view === "flat"} onClick={() => setView("flat")} />
        <ViewToggle label={`By patch (${counts.patch})`} active={view === "patch"} onClick={() => setView("patch")} />
        <ViewToggle label={`By host (${counts.host})`} active={view === "host"} onClick={() => setView("host")} />
      </div>

      {filtered.length === 0 ? (
        <div className="mt-4 rounded-md border border-dashed border-neutral-800 bg-neutral-950/60 p-8 text-center text-sm text-neutral-400">
          No vulnerabilities match the active filters.
        </div>
      ) : view === "patch" ? (
        <PatchView groups={groups} />
      ) : view === "host" ? (
        <HostView groups={hostGroups} />
      ) : (
        <div className="mt-3 overflow-x-auto rounded-md border border-neutral-800 bg-neutral-950/40 shadow-[inset_0_1px_0_rgba(255,255,255,0.02)]">
          <table className="w-full text-left text-[15px]">
            <thead className="sticky top-0 z-10 bg-gradient-to-b from-neutral-900 to-neutral-950 font-mono text-[12px] uppercase tracking-[0.14em] text-neutral-400 backdrop-blur">
              <tr className="border-b border-brand-900/40">
                <th className="px-4 py-3 font-semibold">CVE</th>
                <th className="px-4 py-3 font-semibold">ExPRT</th>
                <th className="px-4 py-3 font-semibold">Severity</th>
                <th className="px-4 py-3 font-semibold">CVSS</th>
                <th className="px-4 py-3 font-semibold">Host</th>
                <th className="px-4 py-3 font-semibold">Product</th>
                <th className="px-4 py-3 font-semibold">Detected</th>
                <th className="px-4 py-3 font-semibold">Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((v, i) => (
                <Row key={v.id ?? i} v={v} zebra={i % 2 === 1} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function FilterChip({
  label,
  active,
  onClick,
  tone,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  tone?: "red" | "amber";
}) {
  const activeTone =
    tone === "red"
      ? "border-red-800 bg-red-950/40 text-red-200"
      : tone === "amber"
        ? "border-amber-800 bg-amber-950/40 text-amber-200"
        : "border-brand-700 bg-brand-950/40 text-oxblood-200";
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded border px-2 py-1 transition-colors ${
        active ? activeTone : "border-neutral-800 bg-neutral-950 text-neutral-400 hover:text-neutral-200"
      }`}
    >
      {label}
    </button>
  );
}

// Inline chips next to a CVE id calling out the two highest-signal "actively
// exploited" markers we already have in the Spotlight payload — CISA KEV and
// CrowdStrike's exploit_status. Falcon Intel actor attribution is sparse for
// CVEs (proven on this tenant: 0/30 indicator hits), so these flags are what
// the operator should be triaging against, not actor names.
function CveIntentChips({ v }: { v: Vulnerability }) {
  const kev = isCisaKev(v);
  const score = exploitStatusScore(v);
  if (!kev && score < 60) return null;
  return (
    <span className="inline-flex items-center gap-1">
      {kev && (
        <span
          className="inline-flex items-center rounded border border-red-800 bg-red-950/60 px-1 py-0 text-[10px] font-semibold uppercase tracking-wide text-red-200"
          title="CISA Known Exploited Vulnerabilities catalog. Actively exploited in the wild per US-CERT."
        >
          KEV
        </span>
      )}
      {score >= 60 && (
        <span
          className={`inline-flex items-center rounded border px-1 py-0 text-[10px] font-mono ${
            score >= 90
              ? "border-red-800 bg-red-950/40 text-red-300"
              : "border-amber-800 bg-amber-950/40 text-amber-300"
          }`}
          title={`Exploit status ${score}/100. ${score >= 90 ? "Actively used." : "Easily accessible exploit code."}`}
        >
          {score >= 90 ? "exploit:active" : "exploit:public"}
        </span>
      )}
    </span>
  );
}

function ViewToggle({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded border px-2 py-1 transition-colors ${
        active
          ? "border-brand-700 bg-brand-950/40 text-oxblood-200"
          : "border-neutral-800 bg-neutral-950 text-neutral-400 hover:text-neutral-200"
      }`}
    >
      {label}
    </button>
  );
}

function HostView({ groups }: { groups: HostGroup[] }) {
  return (
    <div className="mt-3 overflow-x-auto rounded-md border border-neutral-800 bg-neutral-950/40 shadow-[inset_0_1px_0_rgba(255,255,255,0.02)]">
      <table className="w-full text-left text-[15px]">
        <thead className="sticky top-0 z-10 bg-gradient-to-b from-neutral-900 to-neutral-950 font-mono text-[12px] uppercase tracking-[0.14em] text-neutral-400 backdrop-blur">
          <tr className="border-b border-brand-900/40">
            <th className="w-8 px-2 py-3"></th>
            <th className="px-4 py-3 font-semibold">Host</th>
            <th className="px-4 py-3 font-semibold">OS</th>
            <th className="px-4 py-3 font-semibold">CVEs</th>
            <th className="px-4 py-3 font-semibold">Max severity</th>
            <th className="px-4 py-3 font-semibold">Exploited</th>
            <th className="px-4 py-3 font-semibold">Top patch</th>
            <th className="px-4 py-3 font-semibold">Oldest</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((g, i) => (
            <HostRow key={g.hostname} g={g} zebra={i % 2 === 1} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HostRow({ g, zebra }: { g: HostGroup; zebra: boolean }) {
  const [open, setOpen] = useState(false);
  const sevTone = SEV_TONE[g.maxSev] ?? SEV_TONE.UNKNOWN;
  const ageTone =
    g.oldestDays >= 90
      ? "bg-red-900/40 text-oxblood-300"
      : g.oldestDays >= 30
        ? "bg-amber-900/40 text-amber-300"
        : "text-neutral-400";
  return (
    <>
      <tr
        className={`group cursor-pointer border-t border-neutral-800/80 transition-colors hover:bg-brand-950/15 ${zebra && !open ? "bg-neutral-950/40" : ""}`}
        onClick={() => setOpen((o) => !o)}
      >
        <td className="px-2 py-2.5 text-neutral-500">
          <ChevronRight className={`h-4 w-4 transition-transform ${open ? "rotate-90" : ""}`} strokeWidth={2} />
        </td>
        <td className="px-4 py-2.5 font-mono text-sm text-neutral-100 group-hover:text-oxblood-200">
          {g.hostname}
        </td>
        <td className="px-4 py-2.5 text-sm text-neutral-300">{g.os}</td>
        <td className="px-4 py-2.5 font-mono text-sm tabular-nums text-neutral-300">{g.cves.size}</td>
        <td className="px-4 py-2.5">
          <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${sevTone}`}>{g.maxSev}</span>
        </td>
        <td className="px-4 py-2.5">
          {g.exploitedCount > 0 ? (
            <span className="inline-flex items-center rounded bg-red-900/40 px-2 py-0.5 text-xs font-medium text-oxblood-300">
              {g.exploitedCount}
            </span>
          ) : (
            <span className="text-xs text-neutral-600">—</span>
          )}
        </td>
        <td className="px-4 py-2.5 font-mono text-sm text-neutral-200">
          {g.topPatch ? (
            <span>
              {g.topPatch.id}
              <span className="ml-2 text-xs text-neutral-500">closes {g.topPatch.closes}</span>
            </span>
          ) : (
            <span className="text-xs text-neutral-600">no fix</span>
          )}
        </td>
        <td className={`px-4 py-2.5 font-mono text-sm tabular-nums ${ageTone}`}>
          {g.oldestDays}d
        </td>
      </tr>
      {open && (
        <tr className="border-t border-neutral-800/80 bg-neutral-950/60">
          <td colSpan={8} className="px-4 py-4">
            <div className="mb-3">
              <Link
                href={`/investigate?host=${encodeURIComponent(g.hostname)}`}
                onClick={(e) => e.stopPropagation()}
                className="inline-flex h-7 items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950 px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-neutral-700 hover:text-white"
              >
                <Search className="h-3 w-3" strokeWidth={2} />
                Investigate {g.hostname}
              </Link>
            </div>
            <div className="overflow-x-auto rounded border border-neutral-800/80 bg-neutral-950/60">
              <table className="w-full text-left text-[14px]">
                <thead className="bg-neutral-900/60 font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500">
                  <tr>
                    <th className="px-4 py-2 font-semibold">CVE</th>
                    <th className="px-4 py-2 font-semibold">ExPRT</th>
                    <th className="px-4 py-2 font-semibold">Severity</th>
                    <th className="px-4 py-2 font-semibold">CVSS</th>
                    <th className="px-4 py-2 font-semibold">Host</th>
                    <th className="px-4 py-2 font-semibold">Product</th>
                    <th className="px-4 py-2 font-semibold">Detected</th>
                    <th className="px-4 py-2 font-semibold">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {g.vulns.map((v, i) => (
                    <Row key={v.id ?? i} v={v} zebra={i % 2 === 1} />
                  ))}
                </tbody>
              </table>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function PatchView({ groups }: { groups: PatchGroup[] }) {
  return (
    <div className="mt-3 overflow-x-auto rounded-md border border-neutral-800 bg-neutral-950/40 shadow-[inset_0_1px_0_rgba(255,255,255,0.02)]">
      <table className="w-full text-left text-[15px]">
        <thead className="sticky top-0 z-10 bg-gradient-to-b from-neutral-900 to-neutral-950 font-mono text-[12px] uppercase tracking-[0.14em] text-neutral-400 backdrop-blur">
          <tr className="border-b border-brand-900/40">
            <th className="w-8 px-2 py-3"></th>
            <th className="px-4 py-3 font-semibold">Patch / KB</th>
            <th className="px-4 py-3 font-semibold">Hosts</th>
            <th className="px-4 py-3 font-semibold">CVEs</th>
            <th className="px-4 py-3 font-semibold">Max severity</th>
            <th className="px-4 py-3 font-semibold">Exploited</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((g, i) => (
            <PatchRow key={g.key} g={g} zebra={i % 2 === 1} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function deriveRemediation(g: PatchGroup): { vendor: string; product: string; version: string } {
  // Best-effort: derive vendor + product from the first vuln's apps[0]; fall
  // back to splitting the remediation label (e.g. "Update Mozilla Firefox · 150.0").
  const v = g.vulns[0];
  const app = v?.apps?.[0];
  const vendor = app?.vendor ?? app?.vendor_normalized ?? "";
  const product = app?.product_name_version ?? app?.product_name_normalized ?? "";
  if (vendor || product) {
    return { vendor, product, version: "" };
  }
  const [titlePart, refPart] = g.label.split(" · ");
  return {
    vendor: "",
    product: (titlePart ?? "").replace(/^Update\s+/i, ""),
    version: refPart ?? "",
  };
}

function buildRunPatchPrimer(
  remediation: { vendor: string; product: string; version: string },
  deviceIds: string[],
): string {
  // Cap the embedded id list so we stay well under URL length limits and
  // don't accidentally invite a fleet-wide rollout in one click. The agent
  // will refuse anything over 25 anyway without confirm_large_batch=true.
  const MAX = 25;
  const ids = deviceIds.slice(0, MAX);
  const truncated = deviceIds.length > MAX ? ` (truncated from ${deviceIds.length})` : "";
  const idList = ids.map((id) => `"${id}"`).join(", ");
  const prompt = `Patch ${remediation.vendor} ${remediation.product} via the curated RTR script library on ${ids.length}${truncated} host${ids.length === 1 ? "" : "s"}: [${idList}].`;
  return buildPrimerHref(prompt);
}

// Generic-installer hand-off: the app has no curated script, so the operator
// supplies a vendor URL (and optional SHA-256). Same id cap + truncation as the
// curated primer. The chat system prompt owns the resolve/dry-run/approval
// mechanics; this just carries the product, hosts, URL, and optional hash.
function buildGenericInstallerPrimer(
  remediation: { vendor: string; product: string; version: string },
  deviceIds: string[],
  url: string,
  sha256?: string,
): string {
  const MAX = 25;
  const ids = deviceIds.slice(0, MAX);
  const truncated = deviceIds.length > MAX ? ` (truncated from ${deviceIds.length})` : "";
  const idList = ids.map((id) => `"${id}"`).join(", ");
  const name = [remediation.vendor, remediation.product].filter(Boolean).join(" ").trim() || "this app";
  const pin = sha256 ? ` Verify the download against SHA-256 ${sha256}.` : "";
  const prompt = `Install ${name} via the generic Windows installer from ${url} on ${ids.length}${truncated} host${ids.length === 1 ? "" : "s"}: [${idList}].${pin}`;
  return buildPrimerHref(prompt);
}

// Save-as-profile hand-off: persist the vendor URL as a reusable install
// source for this tenant. No host action — the agent just records the profile.
function buildSaveProfilePrimer(
  remediation: { vendor: string; product: string; version: string },
  url: string,
  sha256?: string,
): string {
  const name = [remediation.vendor, remediation.product].filter(Boolean).join(" ").trim() || "this app";
  const pin = sha256 ? ` Pin SHA-256 ${sha256}.` : "";
  const prompt = `Save a reusable patch profile for ${name} from vendor URL ${url}.${pin}`;
  return buildPrimerHref(prompt);
}

function deriveDeviceIds(g: PatchGroup): string[] {
  // Managed hosts only — NVA-discovered hosts have no Falcon sensor and the
  // RTR session would fail to initialize. The table separately surfaces the
  // unmanaged count so the operator knows manual remediation is still owed.
  const ids = new Set<string>();
  for (const v of g.vulns) {
    if (v._unmanaged) continue;
    const id = v.aid ?? v.host_info?.device_id;
    if (id) ids.add(id);
  }
  return Array.from(ids);
}

type VerifyState =
  | { kind: "idle" }
  | { kind: "loading" }
  | {
      kind: "ok";
      deviceIds: string[];
      truncated: boolean;
      droppedNva: number;
      filterDegraded: boolean;
      unverifiedCount: number;
    }
  | { kind: "error"; message: string };

function PatchRow({ g, zebra }: { g: PatchGroup; zebra: boolean }) {
  const [open, setOpen] = useState(false);
  const [showPlan, setShowPlan] = useState(false);
  const [verify, setVerify] = useState<VerifyState>({ kind: "idle" });
  const planRef = useRef<AgentRunHandle>(null);
  const sevTone = SEV_TONE[g.maxSev] ?? SEV_TONE.UNKNOWN;
  const remediation = useMemo(() => deriveRemediation(g), [g]);
  const sampleDeviceIds = useMemo(() => deriveDeviceIds(g), [g]);
  const cveIds = useMemo(() => Array.from(g.cves), [g.cves]);
  const effectiveDeviceIds =
    verify.kind === "ok" ? verify.deviceIds : sampleDeviceIds;
  const planBody = useMemo(
    () => ({ remediation, device_ids: effectiveDeviceIds }),
    [remediation, effectiveDeviceIds],
  );
  const planAvailable = g.hasFix && sampleDeviceIds.length > 0;
  // Coverage gap: a fix exists but no curated script covers it (Windows only).
  // The generic-installer path replaces the curated buttons for these groups.
  const isGap = g.hasFix && g.capabilityGap;

  // Action-time host enumeration. The page-load Spotlight fetch is capped, so
  // the rows in this bundle may only sample a fraction of the truly affected
  // hosts. Before kicking off the patch plan or chat primer we re-query
  // Spotlight scoped to this bundle's CVEs and union the result with what we
  // already know — that way the agent receives every affected device, even if
  // the page-level table undercounts.
  async function ensureVerifiedHosts(): Promise<string[]> {
    if (verify.kind === "ok") return verify.deviceIds;
    if (cveIds.length === 0) return sampleDeviceIds;
    setVerify({ kind: "loading" });
    try {
      const res = await fetch("/api/vulnerabilities/hosts-for-patch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ cve_ids: cveIds }),
      });
      const data = (await res.json()) as {
        ok?: boolean;
        device_ids?: string[];
        truncated?: boolean;
        dropped_nva?: number;
        filter_degraded?: boolean;
        unverified_count?: number;
        error?: string;
      };
      if (!data.ok || !Array.isArray(data.device_ids)) {
        const message = data.error ?? `verification failed (HTTP ${res.status})`;
        setVerify({ kind: "error", message });
        return sampleDeviceIds;
      }
      // Union with the sample, then drop anything flagged unmanaged in the
      // page enrichment — endpoint already filters NVA on its side, but the
      // sample union could re-introduce them.
      const sampleManaged = sampleDeviceIds.filter((id) => {
        const v = g.vulns.find((vv) => (vv.aid ?? vv.host_info?.device_id) === id);
        return !v?._unmanaged;
      });
      const union = Array.from(new Set([...sampleManaged, ...data.device_ids]));
      setVerify({
        kind: "ok",
        deviceIds: union,
        truncated: !!data.truncated,
        droppedNva: data.dropped_nva ?? 0,
        filterDegraded: !!data.filter_degraded,
        unverifiedCount: data.unverified_count ?? 0,
      });
      return union;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setVerify({ kind: "error", message });
      return sampleDeviceIds;
    }
  }

  async function handleBuildPlan() {
    await ensureVerifiedHosts();
    setShowPlan(true);
    // start once the AgentRun has mounted; the planBody useMemo will already
    // have flipped to the verified ids by the time start() reads it.
    setTimeout(() => planRef.current?.start(), 0);
  }

  async function handleRunInChat() {
    const ids = await ensureVerifiedHosts();
    window.location.href = buildRunPatchPrimer(remediation, ids);
  }

  async function handleGenericInstaller() {
    const product = remediation.product || "this app";
    const url = window
      .prompt(`Vendor download URL for ${product} (HTTPS link to the .msi or .exe):`)
      ?.trim();
    if (!url) return;
    if (!url.startsWith("https://")) {
      window.alert("The download URL must start with https://");
      return;
    }
    const sha = window
      .prompt(
        "Optional: paste a SHA-256 checksum to verify the download (leave blank to skip — the install will be marked unverified):",
      )
      ?.trim();
    const ids = await ensureVerifiedHosts();
    window.location.href = buildGenericInstallerPrimer(remediation, ids, url, sha || undefined);
  }

  async function handleSaveProfile() {
    const product = remediation.product || "this app";
    const url = window
      .prompt(`Vendor download URL to save as a reusable source for ${product} (HTTPS link to the .msi or .exe):`)
      ?.trim();
    if (!url) return;
    if (!url.startsWith("https://")) {
      window.alert("The download URL must start with https://");
      return;
    }
    const sha = window.prompt("Optional: paste a SHA-256 checksum to pin (leave blank to skip):")?.trim();
    window.location.href = buildSaveProfilePrimer(remediation, url, sha || undefined);
  }
  return (
    <>
      <tr
        className={`group cursor-pointer border-t border-neutral-800/80 transition-colors hover:bg-brand-950/15 ${zebra && !open ? "bg-neutral-950/40" : ""}`}
        onClick={() => setOpen((o) => !o)}
      >
        <td className="px-2 py-2.5 text-neutral-500">
          <ChevronRight
            className={`h-4 w-4 transition-transform ${open ? "rotate-90" : ""}`}
            strokeWidth={2}
          />
        </td>
        <td className="px-4 py-2.5 font-mono text-sm text-neutral-100 group-hover:text-oxblood-200">
          {g.hasFix ? (
            g.label
          ) : (
            <span className="text-neutral-400">{g.label}</span>
          )}
          {isGap && (
            <span
              className="ml-2 inline-flex items-center rounded bg-sky-950/60 px-1.5 py-0.5 text-[10px] font-medium text-sky-300"
              title="No built-in patch script for this app. Install it from a vendor download link you provide."
            >
              generic installer
            </span>
          )}
        </td>
        <td className="px-4 py-2.5 font-mono text-sm tabular-nums text-neutral-300">
          {g.hosts.size}
          {g.unmanagedHosts.size > 0 && (
            <span
              className="ml-2 inline-flex items-center rounded bg-neutral-800 px-1.5 py-0.5 text-[10px] font-medium text-neutral-400"
              title={`${g.unmanagedHosts.size} NVA-discovered host(s). No Falcon sensor; manual remediation only.`}
            >
              {g.unmanagedHosts.size} NVA
            </span>
          )}
        </td>
        <td className="px-4 py-2.5 font-mono text-sm tabular-nums text-neutral-300">{g.cves.size}</td>
        <td className="px-4 py-2.5">
          <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${sevTone}`}>
            {g.maxSev}
          </span>
        </td>
        <td className="px-4 py-2.5">
          {g.exploitedCount > 0 ? (
            <span className="inline-flex items-center rounded bg-red-900/40 px-2 py-0.5 text-xs font-medium text-oxblood-300">
              {g.exploitedCount} ExPRT-high
            </span>
          ) : (
            <span className="text-xs text-neutral-600">—</span>
          )}
        </td>
      </tr>
      {open && (
        <tr className="border-t border-neutral-800/80 bg-neutral-950/60">
          <td colSpan={6} className="px-4 py-4">
            {!planAvailable && g.hasFix && g.unmanagedHosts.size === g.hosts.size && g.hosts.size > 0 && (
              <div className="mb-4 rounded-md border border-neutral-800 bg-neutral-950/60 px-3 py-2 text-xs text-neutral-400">
                🛰 Every host in this bundle is NVA-discovered. No Falcon sensor → no
                automated patching. Track these {g.hosts.size} host
                {g.hosts.size === 1 ? "" : "s"} for manual remediation.
              </div>
            )}
            {planAvailable && (
              <div className="mb-4">
                {!showPlan ? (
                  <div className="flex flex-col gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      {isGap ? (
                        <>
                          <button
                            onClick={handleGenericInstaller}
                            disabled={verify.kind === "loading"}
                            className="inline-flex items-center gap-2 rounded-md border border-amber-700/60 bg-amber-950/40 px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-amber-200 transition-colors hover:border-amber-600 hover:bg-amber-900/40 disabled:opacity-50"
                          >
                            <Wrench className="h-3.5 w-3.5" strokeWidth={2} />
                            Patch via generic installer ({effectiveDeviceIds.length} hosts)
                          </button>
                          <button
                            onClick={handleSaveProfile}
                            className="inline-flex items-center gap-2 rounded-md border border-sky-800/60 bg-sky-950/40 px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-sky-200 transition-colors hover:border-sky-700 hover:bg-sky-900/40"
                          >
                            Save as profile
                          </button>
                        </>
                      ) : (
                        <>
                          <button
                            onClick={handleBuildPlan}
                            disabled={verify.kind === "loading"}
                            className="inline-flex items-center gap-2 rounded-md border border-brand-800/60 bg-brand-950/40 px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-oxblood-200 transition-colors hover:border-brand-700 hover:bg-brand-900/40 disabled:opacity-50"
                          >
                            <Wrench className="h-3.5 w-3.5" strokeWidth={2} />
                            Build patch plan ({effectiveDeviceIds.length} hosts)
                          </button>
                          <button
                            onClick={handleRunInChat}
                            disabled={verify.kind === "loading"}
                            className="inline-flex items-center gap-2 rounded-md border border-amber-700/60 bg-amber-950/40 px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-amber-200 transition-colors hover:border-amber-600 hover:bg-amber-900/40 disabled:opacity-50"
                          >
                            <Wrench className="h-3.5 w-3.5" strokeWidth={2} />
                            Run patch in chat →
                          </button>
                        </>
                      )}
                    </div>
                    {isGap && (
                      <div className="text-xs text-neutral-400">
                        No built-in script covers this app. The generic installer
                        downloads it from the vendor link you provide and installs it —
                        pin a SHA-256 checksum to verify the download first.
                      </div>
                    )}
                    <VerificationStatus verify={verify} sampleCount={sampleDeviceIds.length} />
                    {g.unmanagedHosts.size > 0 && (
                      <div className="text-xs text-neutral-400">
                        🛰 {g.unmanagedHosts.size} NVA-discovered host
                        {g.unmanagedHosts.size === 1 ? "" : "s"} in this bundle
                        will <em className="not-italic text-amber-300">not</em> be
                        included — no Falcon sensor, no RTR. Track manually.
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="rounded-lg border border-brand-900/40 bg-gradient-to-br from-brand-950/30 via-neutral-950 to-neutral-950 p-4">
                    <div className="mb-3 flex items-center justify-between">
                      <div className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-oxblood-300">
                        Patch plan · {g.label}
                      </div>
                      <div className="flex items-center gap-3">
                        <button
                          onClick={handleRunInChat}
                          className="font-mono text-[11px] uppercase tracking-[0.14em] text-amber-300 hover:text-amber-200"
                        >
                          Run patch in chat →
                        </button>
                        <button
                          onClick={() => planRef.current?.start()}
                          className="font-mono text-[11px] uppercase tracking-[0.14em] text-neutral-400 hover:text-oxblood-200"
                        >
                          Regenerate
                        </button>
                      </div>
                    </div>
                    <div className="mb-3">
                      <VerificationStatus verify={verify} sampleCount={sampleDeviceIds.length} />
                    </div>
                    <AgentRun
                      ref={planRef}
                      endpoint="/api/patch-plan"
                      body={planBody}
                      webhookTitle={`Patch plan · ${g.label}`}
                      webhookSource="patch-plan"
                    />
                  </div>
                )}
              </div>
            )}
            <div className="overflow-x-auto rounded border border-neutral-800/80 bg-neutral-950/60">
              <table className="w-full text-left text-[14px]">
                <thead className="bg-neutral-900/60 font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500">
                  <tr>
                    <th className="px-4 py-2 font-semibold">CVE</th>
                    <th className="px-4 py-2 font-semibold">ExPRT</th>
                    <th className="px-4 py-2 font-semibold">Severity</th>
                    <th className="px-4 py-2 font-semibold">CVSS</th>
                    <th className="px-4 py-2 font-semibold">Host</th>
                    <th className="px-4 py-2 font-semibold">Product</th>
                    <th className="px-4 py-2 font-semibold">Detected</th>
                    <th className="px-4 py-2 font-semibold">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {g.vulns.map((v, i) => (
                    <Row key={v.id ?? i} v={v} zebra={i % 2 === 1} />
                  ))}
                </tbody>
              </table>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function VerificationStatus({
  verify,
  sampleCount,
}: {
  verify: VerifyState;
  sampleCount: number;
}) {
  if (verify.kind === "idle") {
    return (
      <div className="text-xs text-neutral-500">
        Sample shows {sampleCount} {sampleCount === 1 ? "host" : "hosts"}. Full
        host list will be re-enumerated from Spotlight when you act.
      </div>
    );
  }
  if (verify.kind === "loading") {
    return (
      <div className="text-xs text-oxblood-300">
        Verifying full host list against Spotlight…
      </div>
    );
  }
  if (verify.kind === "error") {
    return (
      <div className="text-xs text-amber-300">
        Verification failed ({verify.message}). Falling back to the {sampleCount}-host
        sample shown above.
      </div>
    );
  }
  const verified = verify.deviceIds.length;
  const delta = verified - sampleCount;
  const truncatedNote = verify.truncated
    ? " (Spotlight returned the maximum batch; there may be even more)"
    : "";
  const nvaNote =
    verify.droppedNva > 0
      ? ` · ${verify.droppedNva} NVA host${verify.droppedNva === 1 ? "" : "s"} dropped (no sensor)`
      : "";
  const degradedNote = verify.filterDegraded ? (
    <div className="mt-1 text-xs text-amber-300">
      {verify.unverifiedCount} host{verify.unverifiedCount === 1 ? "" : "s"} couldn&apos;t be
      confirmed sensor-managed (lookup error) — included anyway; a few may fail to start a
      remote session.
    </div>
  ) : null;
  if (delta > 0) {
    return (
      <>
        <div className="text-xs text-emerald-300">
          Verified {verified} managed host{verified === 1 ? "" : "s"} ({delta} more than the page sample){truncatedNote}
          {nvaNote}.
        </div>
        {degradedNote}
      </>
    );
  }
  return (
    <>
      <div className="text-xs text-emerald-300">
        Verified {verified} managed {verified === 1 ? "host" : "hosts"} · matches the page
        sample{truncatedNote}
        {nvaNote}.
      </div>
      {degradedNote}
    </>
  );
}

function Row({ v, zebra }: { v: Vulnerability; zebra: boolean }) {
  const [open, setOpen] = useState(false);
  const sev = pickSeverity(v);
  const sevTone = SEV_TONE[sev] ?? SEV_TONE.UNKNOWN;
  const exprt = pickExprt(v) ?? "";
  const exprtTone = EXPRT_TONE[exprt.toUpperCase()] ?? "bg-neutral-800 text-neutral-500";
  const statusTone =
    (v.status && STATUS_TONE[v.status]) || "bg-neutral-800 text-neutral-400";
  const cvss = pickCvss(v);

  return (
    <>
      <tr
        className={`group cursor-pointer border-t border-neutral-800/80 transition-colors hover:bg-brand-950/15 focus-visible:bg-brand-950/15 ${zebra && !open ? "bg-neutral-950/40" : ""}`}
        onClick={() => setOpen((o) => !o)}
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setOpen((o) => !o);
          }
        }}
      >
        <td className="px-4 py-2.5 font-mono text-sm text-neutral-100 group-hover:text-oxblood-200">
          <div className="flex items-center gap-1.5">
            <span>{pickCveId(v)}</span>
            <CveIntentChips v={v} />
          </div>
        </td>
        <td className="px-4 py-2.5">
          {exprt ? (
            <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${exprtTone}`}>
              {exprt}
            </span>
          ) : (
            <span className="text-xs text-neutral-600">—</span>
          )}
        </td>
        <td className="px-4 py-2.5">
          <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${sevTone}`}>
            {sev}
          </span>
        </td>
        <td className="px-4 py-2.5 font-mono text-sm tabular-nums text-neutral-300">
          {cvss != null ? cvss.toFixed(1) : "—"}
        </td>
        <td className="px-4 py-2.5 text-neutral-200">
          {(() => {
            const hn = pickHostname(v);
            const node = hn;
            return (
              <>
                {node}
                {v._unmanaged && (
                  <span
                    className="ml-2 inline-flex items-center rounded border border-neutral-700 bg-neutral-900 px-1.5 py-0.5 text-[10px] font-medium text-neutral-400"
                    title="NVA-discovered: no Falcon sensor on this host. Manual remediation only."
                  >
                    🛰 NVA
                  </span>
                )}
              </>
            );
          })()}
        </td>
        <td className="px-4 py-2.5 text-sm text-neutral-300">{pickProduct(v)}</td>
        <td className="whitespace-nowrap px-4 py-2.5 font-mono text-sm tabular-nums text-neutral-500">
          {formatTime(v.created_timestamp)}
          {(() => {
            const age = daysSince(v.created_timestamp);
            if (age == null || age < STALE_DAYS) return null;
            const tone =
              age >= 90 ? "bg-red-900/40 text-oxblood-300" : "bg-amber-900/40 text-amber-300";
            return (
              <span className={`ml-2 inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium ${tone}`}>
                {age}d
              </span>
            );
          })()}
        </td>
        <td className="px-4 py-2.5">
          <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${statusTone}`}>
            {v.status ?? "—"}
          </span>
        </td>
      </tr>
      {open && (
        <tr className="border-t border-neutral-800/80 bg-neutral-950/60">
          <td colSpan={8} className="px-4 py-4">
            <DetailPanel v={v} />
          </td>
        </tr>
      )}
    </>
  );
}

function DetailPanel({ v }: { v: Vulnerability }) {
  const cveDesc = v.cve?.description;
  const remediation = pickRemediationEntities(v);
  const cvssVector = v.cve?.cvss_v3_score?.vector;
  const apps = v.apps ?? [];

  return (
    <div className="space-y-3">
      {cveDesc && (
        <div>
          <div className="mb-1 text-xs uppercase tracking-wider text-neutral-500">
            CVE description
          </div>
          <div className="text-sm text-neutral-200">{cveDesc}</div>
        </div>
      )}
      <div className="grid gap-3 text-sm md:grid-cols-3">
        {cvssVector && <Field label="CVSS vector" value={cvssVector} mono />}
        {v.host_info?.device_id && (
          <Field label="Device ID" value={v.host_info.device_id} mono />
        )}
        {v.host_info?.platform && <Field label="Platform" value={v.host_info.platform} />}
        {v.host_info?.os_version && (
          <Field label="OS" value={v.host_info.os_version} />
        )}
        {(v.apps_count ?? apps.length) > 1 && (
          <Field
            label="Affected apps"
            value={`${v.apps_count ?? apps.length} apps total`}
          />
        )}
        {v.closed_timestamp && (
          <Field label="Closed" value={v.closed_timestamp.slice(0, 10)} />
        )}
      </div>
      {apps.length > 0 && (
        <div>
          <div className="mb-1 text-xs uppercase tracking-wider text-neutral-500">
            Affected apps
          </div>
          <ul className="space-y-1 text-sm text-neutral-300">
            {apps.slice(0, 8).map((a, i) => (
              <li key={i}>
                <span className="font-mono">{a.product_name_version ?? "?"}</span>
                {a.vendor && (
                  <span className="ml-2 text-neutral-500">({a.vendor})</span>
                )}
              </li>
            ))}
            {apps.length > 8 && (
              <li className="text-neutral-500">… and {apps.length - 8} more</li>
            )}
          </ul>
        </div>
      )}
      {remediation.length > 0 && (
        <div>
          <div className="mb-1 text-xs uppercase tracking-wider text-neutral-500">
            Remediation
          </div>
          <ul className="space-y-2">
            {remediation.map((e, i) => (
              <li
                key={e.id ?? i}
                className="rounded border border-neutral-800 bg-neutral-950/60 px-3 py-2"
              >
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="text-sm font-semibold text-neutral-100">
                    {e.title ?? "Update"}
                  </span>
                  {e.reference && (
                    <span className="font-mono text-xs text-amber-300">
                      {e.reference}
                    </span>
                  )}
                  {e.recommendation_type && (
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-medium uppercase ${
                        e.recommendation_type === "recommended"
                          ? "bg-brand-900/40 text-oxblood-200"
                          : "bg-neutral-800 text-neutral-400"
                      }`}
                    >
                      {e.recommendation_type}
                    </span>
                  )}
                </div>
                {e.action && (
                  <div className="mt-1 text-sm text-neutral-300">{e.action}</div>
                )}
                {(e.link || e.vendor_url) && (
                  <a
                    href={e.link || e.vendor_url}
                    target="_blank"
                    rel="noreferrer"
                    className="mt-1 inline-flex h-7 items-center gap-1 rounded-md border border-sky-900/60 bg-sky-950/30 px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-sky-300 transition hover:border-sky-700 hover:text-white"
                  >
                    Vendor advisory
                    <ArrowUpRight className="h-3 w-3" strokeWidth={2} />
                  </a>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      <VulnActions v={v} />

      <details className="mt-1">
        <summary className="cursor-pointer text-xs uppercase tracking-wider text-neutral-500 hover:text-neutral-300">
          Raw vulnerability JSON
        </summary>
        <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap break-words rounded bg-neutral-900 px-3 py-2 font-mono text-xs text-neutral-400">
          {JSON.stringify(v, null, 2)}
        </pre>
      </details>
    </div>
  );
}

function VulnActions({ v }: { v: Vulnerability }) {
  const cveId = pickCveId(v);
  const hostname = pickHostname(v);
  const product = pickProduct(v);
  const sev = pickSeverity(v);
  const exprt = pickExprt(v);

  const askPrimer = [
    `Help me triage ${cveId}${hostname && hostname !== "—" ? ` on host \`${hostname}\`` : ""}.`,
    product && product !== "—" ? `Affected product: ${product}.` : "",
    `Severity ${sev}${exprt ? `, ExPRT ${exprt}` : ""}.`,
    `What's the exploit status, is there a fix available, and is this host already showing related detections?`,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div className="flex flex-wrap gap-2 pt-1">
      {hostname && hostname !== "—" && (
        <Link
          href={`/investigate?host=${encodeURIComponent(hostname)}`}
          className="inline-flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-900 px-2.5 py-1 text-xs font-medium text-neutral-200 transition-colors hover:border-neutral-700 hover:text-white"
        >
          <Search className="h-3 w-3" strokeWidth={2} />
          Investigate host
        </Link>
      )}
      <Link
        href={buildPrimerHref(askPrimer)}
        className="inline-flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-900 px-2.5 py-1 text-xs font-medium text-neutral-200 transition-colors hover:border-brand-700 hover:text-oxblood-200"
      >
        <MessageSquare className="h-3 w-3" strokeWidth={2} />
        Ask agent
      </Link>
      {cveId && cveId !== "—" && (
        <a
          href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-900 px-2.5 py-1 text-xs font-medium text-sky-400 transition-colors hover:border-sky-700 hover:text-sky-300"
        >
          <ExternalLink className="h-3 w-3" strokeWidth={2} />
          NVD
        </a>
      )}
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value?: string; mono?: boolean }) {
  if (!value) return null;
  return (
    <div>
      <div className="text-xs uppercase tracking-wider text-neutral-500">{label}</div>
      <div className={`text-neutral-200 ${mono ? "font-mono break-all text-sm" : "text-sm"}`}>
        {value}
      </div>
    </div>
  );
}
