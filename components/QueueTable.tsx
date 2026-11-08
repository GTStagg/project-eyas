"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { Flame, ListChecks, Archive, MessageSquare, Search, ChevronRight } from "lucide-react";
import type { QueueRow } from "@/lib/queue/rank";
import { buildPrimerHref } from "./primerHandoff";
import { endpointIrEligibility, identityIrEligibility, IrChip } from "./irEligibility";

// Fire-and-forget claim: marks detection(s) in_progress server-side so they
// stop resurfacing in the queue. Failure is non-blocking — navigate to chat
// regardless. The route accepts a single composite_id or an array; the array
// form is one Falcon Alerts API call regardless of size, so a 97-detection
// host hand-off is one request not ninety-seven (which previously blocked
// navigation behind 97 parallel POSTs through the in-process MCP client).
async function claim(ids: string | string[] | undefined): Promise<void> {
  const composite_ids = (Array.isArray(ids) ? ids : ids ? [ids] : []).filter(Boolean);
  if (composite_ids.length === 0) return;
  try {
    const r = await fetch("/api/queue/claim", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ composite_ids }),
    });
    const j = await r.json().catch(() => ({}));
    if (!j.ok && !j.scope_pending) {
      console.warn("[queue/claim] failed:", j);
    }
  } catch (err) {
    console.warn("[queue/claim] threw:", err);
  }
}

const SEV_TONE: Record<string, string> = {
  Critical: "bg-red-900/60 text-red-200 border border-red-800",
  High: "bg-orange-900/60 text-orange-200 border border-orange-800",
  Medium: "bg-yellow-900/60 text-yellow-100 border border-yellow-800",
  Low: "bg-sky-900/60 text-sky-200 border border-sky-800",
  Informational: "bg-neutral-800 text-neutral-300 border border-neutral-700",
};

// Cross-module identity-overlap chip. Renders only when the correlation
// resolved a user. Two visual modes:
//   - red, when the user has open IDP detections in the last 14d (the
//     signature cross-module priority signal — endpoint AND identity hot)
//   - sky, when the user is just IDP-known (risk score visible)
// Severity-of-risk-score is shown as the suffix; HIGH/CRITICAL bumps to red
// even without a current IDP detection.
function IdentityOverlapChip({
  overlap,
}: {
  overlap: NonNullable<QueueRow["identity_overlap"]>;
}) {
  const sev = (overlap.risk_score_severity ?? "").toUpperCase();
  const hot =
    overlap.idp_detection_count > 0 || sev === "HIGH" || sev === "CRITICAL";
  const tone = hot
    ? "border-red-800 bg-red-950/60 text-red-200"
    : "border-sky-800 bg-sky-950/60 text-sky-200";
  const label = overlap.last_login_user
    ? `id: ${overlap.last_login_user}`
    : "id resolved";
  const suffix = sev ? ` · ${sev.toLowerCase()}` : "";
  const det =
    overlap.idp_detection_count > 0
      ? ` · +${overlap.idp_detection_count} idp`
      : "";
  return (
    <span
      className={`rounded border px-1.5 py-0.5 font-mono text-[10px] tracking-[0.06em] ${tone}`}
      title={
        `Identity overlap — the host's last signed-in user. ` +
        `User: ${overlap.last_login_user ?? "(unknown)"}${
          overlap.primary_display_name
            ? ` (${overlap.primary_display_name})`
            : ""
        }. Risk score severity: ${sev || "n/a"}. ` +
        `Open IDP detections naming this user (14d): ${overlap.idp_detection_count}.`
      }
    >
      {label}
      {suffix}
      {det}
    </span>
  );
}

// Falcon-native adversary chip. Set on rows where Falcon's correlation
// engine tagged the detection with one or more `adversary_ids` and the
// route resolved one to a canonical actor name (FANCY BEAR, WIZARD
// SPIDER, etc.). Click hands off to chat with a primer — same shape the
// other row chips use. Oxblood tone signals brand/Falcon-native ground
// truth, not the chromatic-severity tones used for sev/recency.
function AdversaryChip({
  adversary,
}: {
  adversary: NonNullable<QueueRow["adversary"]>;
}) {
  const primer = `Tell me about adversary \`${adversary.name ?? adversary.id}\` (Falcon ID ${adversary.id}). What detections in this tenant are attributed to them, on which hosts, and what's their typical playbook? Use falcon_get_intel_actors for the full profile.`;
  return (
    <Link
      href={buildPrimerHref(primer)}
      onClick={(e) => e.stopPropagation()}
      title={`Falcon-native attribution: ${adversary.name ?? adversary.id}. Click to ask about this adversary's tenant activity.`}
      className="rounded border border-brand-700/60 bg-brand-900/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.08em] text-oxblood-200 transition hover:border-brand-600 hover:bg-brand-900/50 hover:text-oxblood-100"
    >
      {adversary.name ?? `adv ${adversary.id}`}
    </Link>
  );
}

function severityLabel(sev?: number): string {
  if (sev == null) return "—";
  if (sev >= 90) return "Critical";
  if (sev >= 70) return "High";
  if (sev >= 50) return "Medium";
  if (sev >= 30) return "Low";
  return "Informational";
}

function relativeAge(hours: number): string {
  if (hours < 1) return `${Math.floor(hours * 60)}m`;
  if (hours < 48) return `${Math.floor(hours)}h`;
  return `${Math.floor(hours / 24)}d`;
}

// Host-level triage primer: triage every endpoint detection on a given host
// in one pass. Used when the top bucket groups multiple detections under the
// same AID. Carries the same identity-overlap context the per-row primer
// would inject (we already have it pre-computed on the lead row).
function hostTriagePrimer(rows: QueueRow[]): string {
  const lead = rows[0];
  const host = lead.device?.hostname ?? "(unknown host)";
  const aid = lead.device?.device_id;
  const aidSuffix = aid ? ` (AID \`${aid}\`)` : "";
  const ids = rows
    .map((r) => r.composite_id ?? r.id)
    .filter((s): s is string => Boolean(s));
  const lines = rows
    .map((r) => {
      const name = r.display_name ?? r.name ?? "(unnamed)";
      const sev = severityLabel(r.severity);
      const tac = [r.tactic, r.technique].filter(Boolean).join(" / ") || "—";
      const age = relativeAge(r.age_hours);
      return `- ${name} · ${sev} · ${tac} · ${age} ago`;
    })
    .join("\n");
  const idCtx = (() => {
    const ov = lead.identity_overlap;
    if (!ov || !ov.identity_resolved) return "";
    const user = ov.last_login_user ?? "(unknown user)";
    const sev = (ov.risk_score_severity ?? "").toLowerCase() || "n/a";
    const idpCount = ov.idp_detection_count;
    const hot =
      idpCount > 0 || sev === "high" || sev === "critical";
    return hot
      ? ` This host's last-logged-in user \`${user}\` is **identity-hot** (IDP risk: ${sev}, ${idpCount} open IDP detection${idpCount === 1 ? "" : "s"} in 14d). Treat as a cross-module priority.`
      : ` This host's last-logged-in user \`${user}\` has IDP risk score ${sev}.`;
  })();
  return [
    `Triage ${rows.length} open detections on host \`${host}\`${aidSuffix}:`,
    lines,
    idCtx ? idCtx.trimStart() : null,
  ]
    .filter(Boolean)
    .join("\n\n");
}

function triagePrimer(r: QueueRow): string {
  const host = r.device?.hostname;
  const detName = r.display_name ?? r.name ?? "this detection";
  const falconLink = r.falcon_host_link;
  const detRef = falconLink ? `[${detName}](${falconLink})` : `**${detName}**`;
  const tac = r.tactic || r.technique
    ? ` (${[r.tactic, r.technique].filter(Boolean).join(" / ")})`
    : "";

  if (r.source === "idp") {
    // IDP triage primer — agent should pull entity context from
    // falcon_search_risky_identities + cross-reference recent IDP detections
    // for this user, not run the host-centric flow.
    const user = r.idp_source_account ?? r.idp_user_name ?? r.user_name ?? "?";
    return `Triage IDP detection ${detRef} for user \`${user}\`${host ? ` on endpoint \`${host}\`` : ""}${tac}.`;
  }

  // Identity overlay (when correlation pre-computed it server-side): inject
  // the cross-module context inline so the agent doesn't have to rediscover.
  const idCtx = (() => {
    const ov = r.identity_overlap;
    if (!ov || !ov.identity_resolved) return "";
    const user = ov.last_login_user ?? "(unknown user)";
    const sev = (ov.risk_score_severity ?? "").toLowerCase() || "n/a";
    const idpCount = ov.idp_detection_count;
    const hot = idpCount > 0 || sev === "high" || sev === "critical";
    const headline = hot
      ? `This host's last-logged-in user \`${user}\` is **identity-hot** (IDP risk: ${sev}, ${idpCount} open IDP detection${idpCount === 1 ? "" : "s"} in 14d). Treat as a cross-module priority.`
      : `This host's last-logged-in user \`${user}\` has IDP risk score ${sev}.`;
    return ` ${headline}`;
  })();

  return `Triage detection ${detRef}${host ? ` on host \`${host}\`` : ""}${tac}.${idCtx}`;
}

// IR eligibility for a queue row. Endpoint rows now carry the SAME platform
// check as /hosts (a Linux host no longer gets a live IR chip here); identity
// rows key on the resolved samAccountName. Returns null for sources that have
// no IR surface at all, so no chip is rendered for them.
function rowIrEligibility(r: QueueRow, irEnabled: boolean) {
  if (r.source === "epp") {
    return endpointIrEligibility(
      {
        device_id: r.device?.device_id,
        hostname: r.device?.hostname,
        platform_name: r.platform ?? r.device?.platform_name,
        // Queue projections don't carry rtr_state; the platform gate plus the
        // workflow's own RTR check cover it.
      },
      irEnabled,
    );
  }
  if (r.source === "idp") {
    // Prefer source_account_name (closest to samAccountName), fall back to
    // user_name. The detection's source_endpoint_host_name is context, not the
    // pivot.
    const sam =
      r.idp_user_name ?? r.user_name ?? extractSamFromAccount(r.idp_source_account);
    return identityIrEligibility(sam, irEnabled);
  }
  return null;
}

// idp_source_account is "DOMAIN\sam" format from extras_identity_detections;
// strip the domain to get the bare samAccountName.
function extractSamFromAccount(acct?: string): string | undefined {
  if (!acct) return undefined;
  const idx = acct.lastIndexOf("\\");
  return idx >= 0 ? acct.slice(idx + 1) : acct;
}

// One renderable item in a bucket. Endpoint detections that share an AID
// collapse into a "host" group (single host card with N stacked detections);
// identity rows and singleton-host endpoint rows pass through as "single".
type QueueItem =
  | { kind: "host"; aid: string; rows: QueueRow[] }
  | { kind: "single"; row: QueueRow };

// Group endpoint rows by AID; preserve input ordering (the deterministic
// ranker already sorted by score desc). A host's group score is the lead
// row's score (already the highest in the group due to ordering).
function groupByHost(rows: QueueRow[]): QueueItem[] {
  const out: QueueItem[] = [];
  const groupIndex = new Map<string, number>();
  for (const r of rows) {
    const aid =
      r.source === "epp" ? r.device?.device_id ?? null : null;
    if (!aid) {
      out.push({ kind: "single", row: r });
      continue;
    }
    const idx = groupIndex.get(aid);
    if (idx === undefined) {
      groupIndex.set(aid, out.length);
      out.push({ kind: "host", aid, rows: [r] });
    } else {
      const existing = out[idx];
      if (existing.kind === "host") existing.rows.push(r);
    }
  }
  // Collapse single-detection host groups back to flat rows — no point in a
  // host card containing one detection.
  return out.map((it) =>
    it.kind === "host" && it.rows.length === 1
      ? { kind: "single" as const, row: it.rows[0] }
      : it,
  );
}

export default function QueueTable({
  rows,
  irEnabled,
}: {
  rows: QueueRow[];
  irEnabled: boolean;
}) {
  const top = rows.filter((r) => r.bucket === "top");
  const active = rows.filter((r) => r.bucket === "active");
  const stale = rows.filter((r) => r.bucket === "stale");

  return (
    <div className="space-y-8">
      <Section
        icon={<Flame className="h-4 w-4" strokeWidth={1.75} />}
        accent="text-oxblood-300 border-red-900/60 bg-red-950/40"
        title="Top priorities"
        subtitle="High-score, fresh, and uncontained. Work these first. Endpoint detections are grouped by host."
        items={groupByHost(top)}
        count={top.length}
        irEnabled={irEnabled}
        emptyText="Nothing meets the top-priority bar in the current window."
      />
      <Section
        icon={<ListChecks className="h-4 w-4" strokeWidth={1.75} />}
        accent="text-amber-300 border-amber-900/60 bg-amber-950/40"
        title="Active queue"
        subtitle="Open detections within the last 7 days, ranked."
        items={active.map((row) => ({ kind: "single" as const, row }))}
        count={active.length}
        irEnabled={irEnabled}
        emptyText="Active queue is clear."
      />
      <Section
        icon={<Archive className="h-4 w-4" strokeWidth={1.75} />}
        accent="text-neutral-400 border-neutral-800 bg-neutral-950/60"
        title="Stale (>7d open)"
        subtitle="Open detections older than a week. Close, suppress, or work."
        items={stale.map((row) => ({ kind: "single" as const, row }))}
        count={stale.length}
        irEnabled={irEnabled}
        emptyText="No stale detections."
        defaultCollapsed
      />
    </div>
  );
}

function Section({
  icon,
  accent,
  title,
  subtitle,
  items,
  count,
  irEnabled,
  emptyText,
  defaultCollapsed = false,
}: {
  icon: React.ReactNode;
  accent: string;
  title: string;
  subtitle: string;
  items: QueueItem[];
  count: number;
  irEnabled: boolean;
  emptyText: string;
  defaultCollapsed?: boolean;
}) {
  return (
    <details open={!defaultCollapsed} className="group">
      <summary className="flex cursor-pointer items-center justify-between gap-3 rounded-md border border-neutral-900 bg-neutral-950/60 px-4 py-3 transition hover:bg-neutral-900/40">
        <div className="flex items-center gap-3">
          <span
            className={`flex h-7 w-7 items-center justify-center rounded-md border ${accent}`}
          >
            {icon}
          </span>
          <div>
            <div className="text-sm font-semibold text-white">
              {title}{" "}
              <span className="ml-1 font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-500">
                {count}
              </span>
            </div>
            <div className="text-xs text-neutral-500">{subtitle}</div>
          </div>
        </div>
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-600 group-open:hidden">
          expand
        </span>
        <span className="hidden font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-600 group-open:inline">
          collapse
        </span>
      </summary>

      <div className="mt-3">
        {items.length === 0 ? (
          <div className="rounded-md border border-dashed border-neutral-800 bg-neutral-950/40 px-4 py-6 text-center text-sm text-neutral-500">
            {emptyText}
          </div>
        ) : (
          <ul className="divide-y divide-neutral-900 rounded-md border border-neutral-900 bg-neutral-950/40">
            {items.map((item, i) =>
              item.kind === "host" ? (
                <HostGroup
                  key={`host:${item.aid}`}
                  rows={item.rows}
                  irEnabled={irEnabled}
                />
              ) : (
                <Row
                  key={item.row.composite_id ?? item.row.id ?? i}
                  r={item.row}
                  irEnabled={irEnabled}
                />
              ),
            )}
          </ul>
        )}
      </div>
    </details>
  );
}

// Host-grouped card: one header (host + IR/Triage at host level) with the
// stacked detections rendered compactly underneath. Triage button uses
// hostTriagePrimer so the agent works every detection on this host in one
// pass; IR uses the same per-host AID primer as the flat row.
function HostGroup({
  rows,
  irEnabled,
}: {
  rows: QueueRow[];
  irEnabled: boolean;
}) {
  const router = useRouter();
  const lead = rows[0];
  const host = lead.device?.hostname ?? "(unknown host)";
  const aid = lead.device?.device_id;
  const maxSev = severityLabel(
    rows.reduce((m, r) => Math.max(m, r.severity ?? 0), 0),
  );
  const sevTone = SEV_TONE[maxSev] ?? SEV_TONE.Informational;
  const oldestAge = rows.reduce((m, r) => Math.max(m, r.age_hours), 0);
  const newestAge = rows.reduce((m, r) => Math.min(m, r.age_hours), Infinity);
  const containedCount = rows.filter((r) => r.contained).length;
  const irEligibility = rowIrEligibility(lead, irEnabled);
  const triage = hostTriagePrimer(rows);

  const handoff = (primer: string) => () => {
    // Bulk-claim every detection in the group, fire-and-forget. Single API
    // call regardless of group size; navigation is no longer blocked by
    // claim round-trips. If the claim fails (network blip, scope_pending,
    // etc.), rows stay `new` until the agent's verdict update closes them
    // — same fallback as before, just non-blocking.
    void claim(rows.map((r) => r.composite_id).filter((x): x is string => Boolean(x)));
    router.push(buildPrimerHref(primer));
  };

  // Stop the click bubbling up to <summary> — otherwise the action button
  // both fires its handler AND toggles the collapsible.
  const stop = (e: React.MouseEvent) => e.stopPropagation();

  return (
    <li className="px-0 py-0">
      <details className="group/host">
        <summary className="flex cursor-pointer flex-wrap items-start justify-between gap-3 px-4 py-3 transition hover:bg-neutral-900/40 [&::-webkit-details-marker]:hidden">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <ChevronRight
                className="h-3.5 w-3.5 text-neutral-500 transition-transform group-open/host:rotate-90"
                strokeWidth={2}
              />
              <span
                className={`rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] ${sevTone}`}
              >
                {maxSev}
              </span>
              <span className="rounded border border-oxblood-700 bg-oxblood-950/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-oxblood-300">
                {rows.length} detections
              </span>
              <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500">
                top score {lead.score.toFixed(0)}
              </span>
              <span className="font-mono text-[11px] tabular-nums text-neutral-500">
                {relativeAge(newestAge)}–{relativeAge(oldestAge)} ago
              </span>
              {containedCount > 0 && (
                <span className="rounded border border-teal-800 bg-teal-950/60 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-teal-200">
                  {containedCount === rows.length
                    ? "contained"
                    : `${containedCount}/${rows.length} contained`}
                </span>
              )}
              {lead.identity_overlap?.identity_resolved && (
                <IdentityOverlapChip overlap={lead.identity_overlap} />
              )}
            </div>
            <div className="mt-1 truncate text-sm text-neutral-100">
              {host}
              {aid && (
                <span className="ml-2 font-mono text-[10px] text-neutral-600">
                  {aid}
                </span>
              )}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <Link
              href={`/investigate?host=${encodeURIComponent(host)}`}
              onClick={stop}
              className="flex h-8 items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-neutral-700 hover:text-white"
            >
              <Search className="h-3 w-3" strokeWidth={1.75} />
              Investigate
            </Link>
            <button
              onClick={(e) => {
                stop(e);
                void handoff(triage)();
              }}
              className="flex h-8 items-center gap-1 rounded-md border border-brand-900/60 bg-brand-950/40 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-oxblood-200 transition hover:bg-brand-900/40 hover:text-white"
            >
              <MessageSquare className="h-3 w-3" strokeWidth={1.75} />
              Triage host
            </button>
            {irEligibility && (
              <IrChip
                eligibility={irEligibility}
                onStart={(primer) => void handoff(primer)()}
              />
            )}
          </div>
        </summary>
        <ul className="mb-3 ml-7 mr-4 space-y-1 border-l border-neutral-800 pl-3">
        {rows.map((r, i) => {
          const sev = severityLabel(r.severity);
          const det = r.display_name ?? r.name ?? "—";
          const tac =
            [r.tactic, r.technique].filter(Boolean).join(" · ") || "—";
          return (
            <li
              key={r.composite_id ?? r.id ?? i}
              className="flex flex-wrap items-center gap-2 text-[12px]"
            >
              <span
                className={`rounded px-1 py-0.5 font-mono text-[9px] uppercase tracking-[0.12em] ${SEV_TONE[sev] ?? SEV_TONE.Informational}`}
              >
                {sev}
              </span>
              <span className="truncate text-neutral-200">{det}</span>
              <span className="font-mono text-[10px] text-neutral-500">
                {tac} · {relativeAge(r.age_hours)} ago
              </span>
              {r.contained && (
                <span className="rounded border border-teal-800 bg-teal-950/60 px-1 py-0.5 font-mono text-[9px] uppercase tracking-[0.12em] text-teal-200">
                  contained
                </span>
              )}
            </li>
          );
        })}
        </ul>
      </details>
    </li>
  );
}

function Row({ r, irEnabled }: { r: QueueRow; irEnabled: boolean }) {
  const router = useRouter();
  const sev = severityLabel(r.severity);
  const sevTone = SEV_TONE[sev] ?? SEV_TONE.Informational;
  const detName = r.display_name ?? r.name ?? "—";
  const host = r.device?.hostname ?? "—";
  const tactic = [r.tactic, r.technique].filter(Boolean).join(" · ") || "—";
  const irEligibility = rowIrEligibility(r, irEnabled);
  const triage = triagePrimer(r);

  // Click handler: fire claim (don't await — keep nav snappy), then navigate.
  // The claim is fire-and-forget; if it fails, the row stays `new` and the
  // agent's verdict update will close the loop later.
  const handoff = (primer: string) => () => {
    void claim(r.composite_id);
    router.push(buildPrimerHref(primer));
  };

  return (
    <li className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] ${sevTone}`}
          >
            {sev}
          </span>
          {r.source === "idp" && (
            <span className="rounded border border-teal-800 bg-teal-950/60 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-teal-200">
              identity
            </span>
          )}
          <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500">
            score {r.score.toFixed(0)}
          </span>
          <span className="font-mono text-[11px] tabular-nums text-neutral-500">
            {relativeAge(r.age_hours)} ago
          </span>
          {r.contained && (
            <span className="rounded border border-teal-800 bg-teal-950/60 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-teal-200">
              contained
            </span>
          )}
          {r.identity_overlap?.identity_resolved && (
            <IdentityOverlapChip overlap={r.identity_overlap} />
          )}
          {r.adversary && <AdversaryChip adversary={r.adversary} />}
          {r.status && (
            <span className="rounded border border-neutral-800 bg-neutral-900/60 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-400">
              {r.status}
            </span>
          )}
        </div>
        <div className="mt-1 truncate text-sm text-neutral-100">{detName}</div>
        <div className="mt-0.5 truncate font-mono text-[11px] text-neutral-500">
          {r.source === "idp" ? (
            <>
              <span className="text-neutral-300">
                {r.idp_source_account ?? r.idp_user_name ?? "?"}
              </span>
              {host !== "—" && (
                <>
                  {" on "}
                  <span className="text-neutral-400">{host}</span>
                </>
              )}
              {" · "}
              {tactic}
            </>
          ) : (
            <>
              <span className="text-neutral-400">{host}</span>
              {" · "}
              {tactic}
            </>
          )}
        </div>
        {r.reasons.length > 0 && (
          <div className="mt-1 text-[11px] text-neutral-500">
            {r.reasons.join(" · ")}
          </div>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-1.5">
        {r.source === "epp" && host !== "—" && (
          <Link
            href={`/investigate?host=${encodeURIComponent(host)}`}
            className="flex h-8 items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-neutral-700 hover:text-white"
          >
            <Search className="h-3 w-3" strokeWidth={1.75} />
            Investigate
          </Link>
        )}
        <button
          onClick={handoff(triage)}
          className="flex h-8 items-center gap-1 rounded-md border border-brand-900/60 bg-brand-950/40 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-oxblood-200 transition hover:bg-brand-900/40 hover:text-white"
        >
          <MessageSquare className="h-3 w-3" strokeWidth={1.75} />
          Triage
        </button>
        {irEligibility && (
          <IrChip
            eligibility={irEligibility}
            label={r.source === "idp" ? "Identity IR" : "IR"}
            onStart={(primer) => void handoff(primer)()}
          />
        )}
      </div>
    </li>
  );
}
