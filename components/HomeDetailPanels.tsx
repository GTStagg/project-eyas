"use client";

// Snack-panel detail views for the /home control center. Each renders inside a
// SnackPanel; the parent HomeDashboard owns the open/close state and chooses the
// footer. In-memory views (campaign, detection) take their object as a prop;
// lazy views fetch on mount with the standard fetch(no-store) loading pattern.

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Server,
  ShieldAlert,
  MessageSquare,
  Loader2,
  ArrowUpRight,
} from "lucide-react";
import { buildPrimerHref } from "./primerHandoff";
import { IrChip, endpointIrEligibility } from "./irEligibility";
import { detName, severityTone, relTime, triagePrimer, askHostPrimer } from "./homeHelpers";
import { reconstructPrimer, type Campaign, type CampaignType } from "@/lib/queue/campaigns";
import type { QueueRow } from "@/lib/queue/rank";

// ── shared bits ───────────────────────────────────────────────────────────────

function Field({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="flex flex-col gap-0.5">
      <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-neutral-500">{label}</span>
      <span className={`text-sm text-neutral-200 ${mono ? "break-all font-mono text-[12px]" : ""}`}>{value}</span>
    </div>
  );
}

function footerLink(href: string, label: string, kind: "primary" | "secondary" = "primary") {
  const cls =
    kind === "primary"
      ? "border-brand-600 bg-brand-600 text-white hover:bg-brand-500"
      : "border-neutral-800 bg-neutral-950/60 text-neutral-300 hover:border-brand-700/60 hover:text-oxblood-200";
  return (
    <Link
      href={href}
      className={`inline-flex items-center gap-1.5 rounded-md border px-4 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] transition ${cls}`}
    >
      {label}
      <ArrowUpRight className="h-3.5 w-3.5" strokeWidth={2} />
    </Link>
  );
}

function LoadingRow() {
  return (
    <div className="flex items-center gap-2 py-6 text-sm text-neutral-500">
      <Loader2 className="h-4 w-4 animate-spin" strokeWidth={2} /> Loading…
    </div>
  );
}

// ── campaign (in memory) ──────────────────────────────────────────────────────

const CAMPAIGN_TYPE_LABEL: Record<CampaignType, string> = {
  shared_binary: "shared binary",
  shared_command: "shared command",
  lateral_movement: "lateral movement",
};

export function CampaignDetail({ campaign: c }: { campaign: Campaign }) {
  const tone = severityTone(c.severity_max);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded border border-neutral-800 bg-neutral-900 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-300">
          {CAMPAIGN_TYPE_LABEL[c.type]}
        </span>
        {c.severity_max_name ? (
          <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] ${tone.cls}`}>
            {c.severity_max_name}
          </span>
        ) : null}
        <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500">
          {c.host_count} hosts · {c.detection_count} detections
        </span>
      </div>

      <Field label="Shared artifact" value={c.artifact_label} mono />

      <div>
        <div className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-neutral-500">
          Affected hosts
        </div>
        <div className="flex flex-wrap gap-1.5">
          {c.hosts.map((h) => (
            <span
              key={h.aid ?? h.hostname}
              className={`rounded border px-1.5 py-0.5 font-mono text-[11px] ${
                h.contained
                  ? "border-teal-800 bg-teal-950/50 text-teal-200"
                  : "border-neutral-800 bg-neutral-900/60 text-neutral-300"
              }`}
            >
              {h.hostname}
              {h.contained ? " · contained" : ""}
            </span>
          ))}
        </div>
      </div>

      {c.techniques.length > 0 ? (
        <Field label="Techniques" value={c.techniques.join(" · ")} />
      ) : null}

      <div className="grid grid-cols-2 gap-4">
        <Field label="First seen" value={c.earliest_ts ? relTime(c.earliest_ts) : "—"} />
        <Field label="Last seen" value={c.latest_ts ? relTime(c.latest_ts) : "—"} />
        <Field label="Uncontained hosts" value={String(c.uncontained_count)} />
        <Field label="Lead detections" value={String(c.composite_ids.length)} />
      </div>

      {c.reasons.length > 0 ? (
        <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-3 py-2 text-[12px] text-neutral-400">
          {c.reasons.join(" · ")}
        </div>
      ) : null}
    </div>
  );
}

export function campaignFooter(c: Campaign) {
  return footerLink(buildPrimerHref(reconstructPrimer(c)), "Reconstruct the campaign");
}

// ── detection (in memory) ─────────────────────────────────────────────────────

export function DetectionDetail({ row: d }: { row: QueueRow }) {
  const tone = severityTone(d.severity ?? 0);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] ${tone.cls}`}>
          {d.severity_name ?? tone.label}
        </span>
        {d.status ? (
          <span className="rounded border border-neutral-800 bg-neutral-900 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-300">
            {d.status}
          </span>
        ) : null}
        {d.contained ? (
          <span className="rounded border border-teal-800 bg-teal-950/50 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-teal-200">
            contained
          </span>
        ) : null}
      </div>

      <div className="grid grid-cols-2 gap-4">
        <Field
          label="Host"
          value={
            d.device?.hostname ? (
              <span className="inline-flex items-center gap-1">
                <Server className="h-3 w-3 text-neutral-500" strokeWidth={2} />
                {d.device.hostname}
              </span>
            ) : null
          }
        />
        <Field label="Platform" value={d.device?.platform_name} />
        <Field label="Tactic" value={d.tactic} />
        <Field label="Technique" value={[d.technique, d.technique_id].filter(Boolean).join(" · ")} />
        <Field label="User" value={d.user_name} />
        <Field label="Seen" value={d.created_timestamp ? relTime(d.created_timestamp) : null} />
      </div>

      <Field label="File" value={d.filename ?? d.filepath} mono />
      <Field label="SHA-256" value={d.sha256} mono />
      {!d.sha256 ? <Field label="MD5" value={d.md5} mono /> : null}
      <Field label="Command line" value={d.cmdline} mono />

      {d.reasons.length > 0 ? (
        <div>
          <div className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-neutral-500">
            Why it ranked
          </div>
          <ul className="flex flex-wrap gap-1.5">
            {d.reasons.map((r) => (
              <li key={r} className="rounded border border-neutral-800 bg-neutral-900/60 px-1.5 py-0.5 font-mono text-[11px] text-neutral-300">
                {r}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

export function detectionFooter(d: QueueRow, irEnabled: boolean) {
  const host = d.device?.hostname;
  return (
    <div className="flex items-center gap-2">
      {footerLink(buildPrimerHref(triagePrimer(d)), "Triage")}
      {host ? (
        <IrChip
          size="md"
          eligibility={endpointIrEligibility(
            { device_id: d.device?.device_id, hostname: host, platform_name: d.device?.platform_name },
            irEnabled,
          )}
        />
      ) : null}
    </div>
  );
}

// ── prevention posture (lazy) ─────────────────────────────────────────────────

type PreventionItem = { id?: string; name?: string; platform?: string; flags?: string[] };

export function PreventionDetail() {
  const [items, setItems] = useState<PreventionItem[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const r = await fetch("/api/prevention-policies", { cache: "no-store" });
        const j = await r.json();
        if (j?.ok && Array.isArray(j.items)) {
          setItems(
            (j.items as PreventionItem[]).filter((p) =>
              (p.flags ?? []).some((f) => f.endsWith("_detect_only")),
            ),
          );
        } else setErr(j?.error ?? "Could not load prevention posture.");
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    })();
  }, []);

  if (err) return <div className="text-sm text-oxblood-200">{err}</div>;
  if (items === null) return <LoadingRow />;
  if (items.length === 0)
    return <div className="py-6 text-sm text-neutral-400">No detect-only policies — prevention is enforcing.</div>;

  return (
    <div className="space-y-3">
      <p className="text-sm text-neutral-400">
        These policies alert but don&apos;t block. Escalating them to blocking closes the gap.
      </p>
      <ul className="space-y-2">
        {items.map((p, i) => (
          <li key={p.id ?? i} className="rounded-md border border-neutral-800 bg-neutral-950/60 px-3 py-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="truncate text-sm text-neutral-100">{p.name ?? "(unnamed policy)"}</span>
              {p.platform ? (
                <span className="shrink-0 rounded border border-neutral-800 bg-neutral-900 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.1em] text-neutral-400">
                  {p.platform}
                </span>
              ) : null}
            </div>
            <div className="mt-1 flex flex-wrap gap-1">
              {(p.flags ?? [])
                .filter((f) => f.endsWith("_detect_only"))
                .map((f) => (
                  <span key={f} className="rounded border border-amber-900 bg-amber-950/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.1em] text-amber-200">
                    {f.replace(/_/g, " ")}
                  </span>
                ))}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function preventionFooter(count: number) {
  const primer = `Review the ${count} detect-only prevention ${count === 1 ? "policy" : "policies"} and recommend which should move to blocking.`;
  return footerLink(buildPrimerHref(primer), "Have the agent review");
}

// ── contained hosts (lazy) ────────────────────────────────────────────────────

type ContainedHost = {
  device_id?: string;
  hostname?: string;
  platform_name?: string;
  os_product_name?: string;
  status?: string;
  last_seen?: string;
};

export function ContainedDetail() {
  const [items, setItems] = useState<ContainedHost[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const r = await fetch("/api/hosts/contained", { cache: "no-store" });
        const j = await r.json();
        if (j?.ok && Array.isArray(j.items)) setItems(j.items as ContainedHost[]);
        else setErr(j?.error ?? "Could not load contained hosts.");
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    })();
  }, []);

  if (err) return <div className="text-sm text-oxblood-200">{err}</div>;
  if (items === null) return <LoadingRow />;
  if (items.length === 0)
    return <div className="py-6 text-sm text-neutral-400">No hosts are currently contained.</div>;

  return (
    <ul className="space-y-2">
      {items.map((h, i) => (
        <li
          key={h.device_id ?? i}
          className="flex items-center gap-3 rounded-md border border-neutral-800 bg-neutral-950/60 px-3 py-2.5"
        >
          <Server className="h-4 w-4 shrink-0 text-teal-300" strokeWidth={1.75} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm text-neutral-100">{h.hostname ?? h.device_id}</div>
            <div className="mt-0.5 font-mono text-[11px] text-neutral-500">
              {[h.platform_name, h.os_product_name].filter(Boolean).join(" · ") || "—"}
              {h.last_seen ? ` · seen ${relTime(h.last_seen)}` : ""}
            </div>
          </div>
          {h.hostname ? (
            <Link
              href={buildPrimerHref(askHostPrimer(h))}
              title="Ask the agent about this host"
              className="flex h-8 shrink-0 items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950/60 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-brand-700/60 hover:text-oxblood-200"
            >
              <MessageSquare className="h-3 w-3" strokeWidth={2} />
              Ask
            </Link>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

// ── IR run (lazy) ─────────────────────────────────────────────────────────────

type IrRecord = {
  aid: string;
  startedAt: number;
  lastTouched: number;
  turns?: Array<{ status?: string; iterations?: number; toolCalls?: Array<{ result?: { isError?: boolean } }> }>;
  campaignScope?: { campaigns?: unknown[] } | null;
};

export function IrRunDetail({ file }: { file: string }) {
  const [record, setRecord] = useState<IrRecord | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const r = await fetch(`/api/ir-runs?file=${encodeURIComponent(file)}`, { cache: "no-store" });
        const j = await r.json();
        if (j?.ok && j.record) setRecord(j.record as IrRecord);
        else setErr(j?.error ?? "Could not load this engagement.");
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [file]);

  if (err) return <div className="text-sm text-oxblood-200">{err}</div>;
  if (record === null) return <LoadingRow />;

  const turns = record.turns ?? [];
  const iterations = turns.reduce((n, t) => n + (t.iterations ?? 0), 0);
  const errored = turns.some(
    (t) => t.status === "errored" || (t.toolCalls ?? []).some((c) => c.result?.isError),
  );
  const campaigns = Array.isArray(record.campaignScope?.campaigns)
    ? record.campaignScope!.campaigns!.length
    : null;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <Field label="Host (AID)" value={record.aid} mono />
        <Field label="Started" value={relTime(record.startedAt)} />
        <Field label="Last activity" value={relTime(record.lastTouched)} />
        <Field label="Turns" value={`${turns.length} · ${iterations} iterations`} />
        {campaigns !== null ? <Field label="Campaign scope" value={`${campaigns} campaigns`} /> : null}
        <Field
          label="Status"
          value={
            errored ? (
              <span className="text-amber-300">completed with errors</span>
            ) : (
              <span className="text-emerald-300">clean</span>
            )
          }
        />
      </div>
      <div className="flex items-center gap-2 rounded-md border border-neutral-800 bg-neutral-950/60 px-3 py-2 text-[12px] text-neutral-400">
        <ShieldAlert className="h-4 w-4 shrink-0 text-oxblood-300" strokeWidth={1.75} />
        Full phase-by-phase audit trail is on the engagement record.
      </div>
    </div>
  );
}

export function irFooter(file: string) {
  return footerLink(`/ir-runs/${file}`, "Open full record", "secondary");
}
