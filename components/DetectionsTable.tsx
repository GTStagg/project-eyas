"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowUpRight, ListChecks, Search, ShieldPlus, ShieldCheck } from "lucide-react";
import { buildPrimerHref } from "./primerHandoff";
import ProcessTree from "./ProcessTree";

type Device = {
  device_id?: string;
  hostname?: string;
  platform_name?: string;
  os_version?: string;
};

export type Detection = {
  composite_id?: string;
  id?: string;
  pivot_pid?: number;
  // Falcon graph id (matches ProcessRollup2 TargetProcessId) — needed
  // by extras_host_process_tree. Dashboards bypass the projection
  // layer, so we accept either the projected `pivot_pid` or the raw
  // `process_id` field directly.
  process_id?: string | number;
  // OS pid for human display only — what Task Manager / RTR shows.
  local_process_id?: string | number;
  created_timestamp?: string;
  updated_timestamp?: string;
  severity?: number;
  severity_name?: string;
  status?: string;
  display_name?: string;
  name?: string;
  description?: string;
  pattern_disposition_description?: string;
  tactic?: string;
  technique?: string;
  technique_id?: string;
  tactic_id?: string;
  cmdline?: string;
  filename?: string;
  filepath?: string;
  sha256?: string;
  md5?: string;
  user_name?: string;
  scenario?: string;
  objective?: string;
  product?: string;
  platform?: string;
  global_prevalence?: string;
  local_prevalence?: string;
  device?: Device;
  falcon_host_link?: string;
  // Falcon-native adversary attribution. `adversary_ids` is on the raw
  // detection record (Falcon's own correlation graph — same source the
  // Console uses for "FANCY BEAR" / "WIZARD SPIDER" labels). `adversary`
  // is the resolved chip — populated by routes that batch-resolve names
  // via falcon_search_actors. Rows without correlation simply leave both
  // unset.
  has_adversary?: boolean;
  adversary_ids?: string[];
  adversary?: { id: string; name?: string };
};

const SEV_TONE: Record<string, string> = {
  Critical: "bg-red-900/60 text-red-200 border border-red-800",
  High: "bg-orange-900/60 text-orange-200 border border-orange-800",
  Medium: "bg-yellow-900/60 text-yellow-100 border border-yellow-800",
  Low: "bg-sky-900/60 text-sky-200 border border-sky-800",
  Informational: "bg-neutral-800 text-neutral-300 border border-neutral-700",
};

const STATUS_TONE: Record<string, string> = {
  new: "bg-emerald-900/60 text-emerald-200",
  in_progress: "bg-amber-900/60 text-amber-200",
  true_positive: "bg-red-900/60 text-red-200",
  false_positive: "bg-neutral-800 text-neutral-400",
  ignored: "bg-neutral-800 text-neutral-500",
  closed: "bg-neutral-800 text-neutral-500",
  reopened: "bg-emerald-900/60 text-emerald-200",
};

// Falcon-native adversary chip — see QueueTable's AdversaryChip for the
// rationale. Set on rows where Falcon's correlation engine tagged the
// detection's adversary_ids and the route resolved one to a canonical
// actor name. Click stops row-toggle propagation and hands off to chat.
function AdversaryChip({
  adversary,
}: {
  adversary: NonNullable<Detection["adversary"]>;
}) {
  const primer = `Tell me about adversary \`${adversary.name ?? adversary.id}\` (Falcon ID ${adversary.id}). What detections in this tenant are attributed to them, on which hosts, and what's their typical playbook? Use falcon_get_intel_actors for the full profile.`;
  return (
    <Link
      href={buildPrimerHref(primer)}
      onClick={(e) => e.stopPropagation()}
      title={`Falcon-native attribution: ${adversary.name ?? adversary.id}. Click to ask about this adversary's tenant activity.`}
      className="ml-2 inline-flex items-center rounded border border-brand-700/60 bg-brand-900/30 px-1.5 py-0.5 align-middle font-mono text-[10px] uppercase tracking-[0.08em] text-oxblood-200 transition hover:border-brand-600 hover:bg-brand-900/50 hover:text-oxblood-100"
    >
      {adversary.name ?? `adv ${adversary.id}`}
    </Link>
  );
}

// Decision-doc primer for chat — mirrors /queue's Triage idiom so the
// chat system prompt hits its triage flow consistently regardless of
// whether the operator started from /queue or /detections. Falcon Host
// Link goes in as a markdown link when present; no other boilerplate.
// The chat system prompt at app/api/chat/route.ts owns decision-doc
// structure + verdict-tagging contracts — don't inline any of that here.
function triagePrimer(d: Detection): string {
  const host = d.device?.hostname;
  const detName = d.display_name ?? d.name ?? "this detection";
  const link = d.falcon_host_link;
  const detRef = link ? `[${detName}](${link})` : `**${detName}**`;
  const tac =
    d.tactic || d.technique
      ? ` (${[d.tactic, d.technique].filter(Boolean).join(" / ")})`
      : "";
  return `Triage detection ${detRef}${host ? ` on host \`${host}\`` : ""}${tac}.`;
}

function severityLabel(d: Detection): string {
  if (d.severity_name) return d.severity_name;
  const s = d.severity;
  if (s == null) return "—";
  if (s >= 90) return "Critical";
  if (s >= 70) return "High";
  if (s >= 50) return "Medium";
  if (s >= 30) return "Low";
  return "Informational";
}

function formatTime(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export default function DetectionsTable({ items }: { items: Detection[] }) {
  if (items.length === 0) {
    return (
      <div className="mt-6 flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-neutral-800 bg-neutral-950/60 p-12 text-center">
        <div className="flex h-10 w-10 items-center justify-center rounded-full border border-emerald-900/60 bg-emerald-950/40 text-emerald-300">
          <ShieldCheck className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div className="text-base font-semibold text-neutral-100">No detections returned.</div>
        <div className="max-w-sm text-sm text-neutral-500">
          Your tenant may be quiet — or try a chat query for more flexible filtering.
        </div>
      </div>
    );
  }

  return (
    <div className="mt-6 overflow-x-auto rounded-md border border-neutral-800 bg-neutral-950/40 shadow-[inset_0_1px_0_rgba(255,255,255,0.02)]">
      <table className="w-full min-w-[720px] text-left text-[15px]">
        <thead className="sticky top-0 z-10 bg-gradient-to-b from-neutral-900 to-neutral-950 font-mono text-[12px] uppercase tracking-[0.14em] text-neutral-400 backdrop-blur">
          <tr className="border-b border-brand-900/40">
            <th className="px-4 py-3 font-semibold">Time</th>
            <th className="px-4 py-3 font-semibold">Sev</th>
            <th className="px-4 py-3 font-semibold">Host</th>
            <th className="px-4 py-3 font-semibold">Detection</th>
            <th className="px-4 py-3 font-semibold">Tactic · Technique</th>
            <th className="px-4 py-3 font-semibold">Status</th>
            <th className="px-4 py-3 font-semibold">Action</th>
          </tr>
        </thead>
        <tbody>
          {items.map((d, i) => (
            <Row key={d.composite_id ?? d.id ?? i} d={d} zebra={i % 2 === 1} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Row({ d, zebra }: { d: Detection; zebra: boolean }) {
  const [open, setOpen] = useState(false);
  const sev = severityLabel(d);
  const sevTone = SEV_TONE[sev] ?? SEV_TONE.Informational;
  const statusTone =
    (d.status && STATUS_TONE[d.status]) || "bg-neutral-800 text-neutral-400";
  const detName = d.display_name ?? d.name ?? "—";

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
        <td className="whitespace-nowrap px-4 py-2.5 font-mono text-sm tabular-nums text-neutral-500">
          {formatTime(d.created_timestamp)}
        </td>
        <td className="px-4 py-2.5">
          <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${sevTone}`}>
            {sev}
          </span>
        </td>
        <td className="px-4 py-2.5 text-neutral-200 group-hover:text-oxblood-200">
          {d.device?.hostname ?? "—"}
        </td>
        <td className="px-4 py-2.5 text-neutral-100">
          {detName}
          {d.adversary && <AdversaryChip adversary={d.adversary} />}
        </td>
        <td className="px-4 py-2.5 text-neutral-300">
          {d.tactic || d.technique ? (
            <span>
              <span className="text-neutral-400">{d.tactic ?? "—"}</span>
              <span className="px-1 text-neutral-600">·</span>
              <span>{d.technique ?? "—"}</span>
              {d.technique_id && (
                <span className="ml-2 font-mono text-xs text-neutral-600">
                  {d.technique_id}
                </span>
              )}
            </span>
          ) : (
            "—"
          )}
        </td>
        <td className="px-4 py-2.5">
          <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${statusTone}`}>
            {d.status ?? "—"}
          </span>
        </td>
        <td className="px-4 py-2.5">
          <Link
            href={buildPrimerHref(triagePrimer(d))}
            onClick={(e) => e.stopPropagation()}
            title="Hand this detection off to chat as a decision-doc triage."
            className="inline-flex items-center gap-1 rounded-md border border-brand-700/60 bg-brand-900/30 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-oxblood-200 transition hover:border-brand-600 hover:bg-brand-900/50 hover:text-oxblood-100"
          >
            <ListChecks className="h-3 w-3" strokeWidth={2} />
            Triage
          </Link>
        </td>
      </tr>
      {open && (
        <tr className="border-t border-neutral-800/80 bg-neutral-950/60">
          <td colSpan={7} className="px-4 py-4">
            <DetailPanel d={d} />
          </td>
        </tr>
      )}
    </>
  );
}

function DetailPanel({ d }: { d: Detection }) {
  return (
    <div className="space-y-3">
      {d.description && (
        <div>
          <div className="mb-1 text-xs uppercase tracking-wider text-neutral-500">
            Description
          </div>
          <div className="text-sm text-neutral-200">{d.description}</div>
        </div>
      )}

      <div className="grid gap-3 text-sm md:grid-cols-2">
        <Field
          label="Device"
          value={`${d.device?.hostname ?? "—"} (${d.platform ?? d.device?.platform_name ?? "?"} · ${d.device?.os_version ?? "?"})`}
        />
        {d.user_name && <Field label="User" value={d.user_name} />}
        {d.scenario && <Field label="Scenario" value={d.scenario} />}
        {d.objective && <Field label="Objective" value={d.objective} />}
        {d.pattern_disposition_description && (
          <Field label="Disposition" value={d.pattern_disposition_description} />
        )}
        {d.product && <Field label="Product" value={d.product} />}
        {(d.global_prevalence || d.local_prevalence) && (
          <Field
            label="Prevalence"
            value={`global ${d.global_prevalence ?? "?"} · local ${d.local_prevalence ?? "?"}`}
          />
        )}
      </div>

      {d.filepath && (
        <Field label="File" value={d.filepath} mono />
      )}
      {d.cmdline && (
        <div>
          <div className="mb-1 text-xs uppercase tracking-wider text-neutral-500">
            Command line
          </div>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded bg-neutral-900 px-3 py-2 font-mono text-xs text-amber-200">
            {d.cmdline}
          </pre>
        </div>
      )}

      {(d.sha256 || d.md5) && (
        <div className="grid gap-3 text-sm font-mono md:grid-cols-2">
          {d.sha256 && <Field label="SHA-256" value={d.sha256} mono />}
          {d.md5 && <Field label="MD5" value={d.md5} mono />}
        </div>
      )}

      {d.device?.device_id && d.created_timestamp && (
        <ProcessTree
          deviceId={d.device.device_id}
          pivotPid={
            d.pivot_pid ??
            (typeof d.process_id === "string" && /^\d+$/.test(d.process_id)
              ? Number(d.process_id)
              : typeof d.process_id === "number"
                ? d.process_id
                : undefined)
          }
          pivotImage={d.filename}
          pivotTsIso={d.created_timestamp}
          enabled={true}
        />
      )}

      <DetectionActions d={d} />

      {d.falcon_host_link && (
        <div>
          <a
            href={d.falcon_host_link}
            target="_blank"
            rel="noreferrer"
            className="inline-flex h-7 items-center gap-1 rounded-md border border-sky-900/60 bg-sky-950/30 px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-sky-300 transition hover:border-sky-700 hover:text-white"
          >
            Open in Falcon console
            <ArrowUpRight className="h-3 w-3" strokeWidth={2} />
          </a>
        </div>
      )}

      <details className="mt-1">
        <summary className="cursor-pointer text-xs uppercase tracking-wider text-neutral-500 hover:text-neutral-300">
          Raw detection JSON
        </summary>
        <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap break-words rounded bg-neutral-900 px-3 py-2 font-mono text-xs text-neutral-400">
          {JSON.stringify(d, null, 2)}
        </pre>
      </details>
    </div>
  );
}

function DetectionActions({ d }: { d: Detection }) {
  const hostname = d.device?.hostname;
  const detName = d.display_name ?? d.name ?? "this detection";
  const ref = d.composite_id ?? d.id ?? "(unknown id)";

  const iocHash = d.sha256 ?? d.md5;
  const iocType = d.sha256 ? "sha256" : d.md5 ? "md5" : null;
  const iocPrimer = iocHash
    ? `Triage hash \`${iocHash}\` (type ${iocType}) from detection ${ref}${hostname ? ` on host \`${hostname}\`` : ""}: ${detName}.`
    : null;

  return (
    <div className="flex flex-wrap gap-2 pt-1">
      <Link
        href={buildPrimerHref(triagePrimer(d))}
        className="inline-flex items-center gap-1.5 rounded-md border border-brand-700/60 bg-brand-900/30 px-2.5 py-1 text-xs font-medium text-oxblood-200 transition-colors hover:border-brand-600 hover:bg-brand-900/50 hover:text-oxblood-100"
      >
        <ListChecks className="h-3 w-3" strokeWidth={2} />
        Triage
      </Link>
      {hostname && (
        <Link
          href={`/investigate?host=${encodeURIComponent(hostname)}`}
          className="inline-flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-900 px-2.5 py-1 text-xs font-medium text-neutral-200 transition-colors hover:border-neutral-700 hover:text-white"
        >
          <Search className="h-3 w-3" strokeWidth={2} />
          Investigate host
        </Link>
      )}
      {iocPrimer && (
        <Link
          href={buildPrimerHref(iocPrimer)}
          title={`Checks whether ${iocType} ${iocHash!.slice(0, 12)}… is already known to Falcon Intel or already on your custom IOC list. Only proposes adding it if both miss; you'll still confirm before any write runs.`}
          className="inline-flex items-center gap-1.5 rounded-md border border-amber-900/60 bg-amber-950/40 px-2.5 py-1 text-xs font-medium text-amber-200 transition-colors hover:border-amber-700 hover:text-amber-100"
        >
          <ShieldPlus className="h-3 w-3" strokeWidth={2} />
          Triage hash
        </Link>
      )}
    </div>
  );
}

function Field({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wider text-neutral-500">{label}</div>
      <div
        className={`text-neutral-200 ${mono ? "font-mono break-all text-sm" : "text-sm"}`}
      >
        {value}
      </div>
    </div>
  );
}
