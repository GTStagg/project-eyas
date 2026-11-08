"use client";

import { useState } from "react";
import Link from "next/link";
import { MessageSquare, Microscope, Server } from "lucide-react";
import { buildPrimerHref } from "@/components/primerHandoff";

export type Host = {
  device_id?: string;
  hostname?: string;
  platform_name?: string;
  os_product_name?: string;
  os_version?: string;
  product_type_desc?: string;
  first_seen?: string;
  last_seen?: string;
  status?: string;
  rtr_state?: string;
  reduced_functionality_mode?: string;
  external_ip?: string;
  local_ip?: string;
  service_provider?: string;
  service_provider_account_id?: string;
  instance_id?: string;
  serial_number?: string;
  agent_version?: string;
  mac_address?: string;
  machine_domain?: string;
  groups?: string[];
  tags?: string[];
};

const STATUS_TONE: Record<string, string> = {
  normal: "bg-emerald-900/60 text-emerald-200 border border-emerald-800",
  contained: "bg-red-900/60 text-red-200 border border-red-800",
  containment_pending: "bg-amber-900/60 text-amber-200 border border-amber-800",
  lift_containment_pending: "bg-amber-900/60 text-amber-200 border border-amber-800",
};

const PLATFORM_TONE: Record<string, string> = {
  Windows: "bg-sky-900/60 text-sky-200",
  Linux: "bg-orange-900/60 text-orange-200",
  Mac: "bg-neutral-800 text-neutral-200",
};

// Absolute-time formatter — "relative" formatting (X minutes ago) would
// require Date.now() at render time, which differs between SSR and client
// and triggers a hydration mismatch. Absolute is also more useful here:
// last-seen times are reference data, not "freshness" indicators.
function formatLastSeen(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export default function HostsTable({ items }: { items: Host[] }) {
  if (items.length === 0) {
    return (
      <div className="mt-6 flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-neutral-800 bg-neutral-950/60 p-12 text-center">
        <div className="flex h-10 w-10 items-center justify-center rounded-full border border-neutral-800 bg-neutral-900 text-neutral-400">
          <Server className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div className="text-base font-semibold text-neutral-100">No hosts returned.</div>
      </div>
    );
  }

  return (
    <div className="mt-6 overflow-x-auto rounded-md border border-neutral-800 bg-neutral-950/40 shadow-[inset_0_1px_0_rgba(255,255,255,0.02)]">
      <table className="w-full min-w-[820px] text-left text-[15px]">
        <thead className="sticky top-0 z-10 bg-gradient-to-b from-neutral-900 to-neutral-950 font-mono text-[12px] uppercase tracking-[0.14em] text-neutral-400 backdrop-blur">
          <tr className="border-b border-brand-900/40">
            <th className="px-4 py-3 font-semibold">Hostname</th>
            <th className="px-4 py-3 font-semibold">Platform · OS</th>
            <th className="px-4 py-3 font-semibold">Type</th>
            <th className="px-4 py-3 font-semibold">Last Seen</th>
            <th className="px-4 py-3 font-semibold">Status</th>
            <th className="px-4 py-3 font-semibold">RTR</th>
            <th className="px-4 py-3 font-semibold">External IP</th>
            <th className="px-4 py-3 font-semibold text-right">Action</th>
          </tr>
        </thead>
        <tbody>
          {items.map((h, i) => (
            <Row key={h.device_id ?? i} h={h} zebra={i % 2 === 1} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Row({ h, zebra }: { h: Host; zebra: boolean }) {
  const [open, setOpen] = useState(false);
  const platTone = (h.platform_name && PLATFORM_TONE[h.platform_name]) ?? "bg-neutral-800 text-neutral-300";
  const statusTone = (h.status && STATUS_TONE[h.status]) ?? "bg-neutral-800 text-neutral-400";
  const rtrOn = h.rtr_state === "enabled";

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
        <td className="px-4 py-2.5 font-medium text-neutral-100 group-hover:text-oxblood-200">{h.hostname ?? "—"}</td>
        <td className="px-4 py-2.5 text-neutral-300">
          <span className={`mr-2 inline-flex items-center rounded px-1.5 py-0.5 text-xs ${platTone}`}>
            {h.platform_name ?? "?"}
          </span>
          <span className="text-sm text-neutral-400">
            {h.os_product_name ?? h.os_version ?? "—"}
          </span>
        </td>
        <td className="px-4 py-2.5 text-sm text-neutral-400">{h.product_type_desc ?? "—"}</td>
        <td className="whitespace-nowrap px-4 py-2.5 font-mono text-sm tabular-nums text-neutral-500">{formatLastSeen(h.last_seen)}</td>
        <td className="px-4 py-2.5">
          <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${statusTone}`}>
            {h.status ?? "—"}
          </span>
        </td>
        <td className="px-4 py-2.5">
          <span
            className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${
              rtrOn ? "bg-emerald-900/40 text-emerald-300" : "bg-neutral-800 text-neutral-500"
            }`}
          >
            {h.rtr_state ?? "—"}
          </span>
        </td>
        <td className="px-4 py-2.5 font-mono text-sm tabular-nums text-neutral-300">
          {h.external_ip ?? "—"}
        </td>
        <td className="px-4 py-2.5 text-right">
          {h.hostname ? (
            <div className="flex items-center justify-end gap-1.5">
              <Link
                href={buildPrimerHref(
                  `Tell me about host \`${h.hostname}\` (${h.platform_name ?? "?"} · ${h.os_product_name ?? h.os_version ?? "?"}, last seen ${h.last_seen ?? "?"}, status ${h.status ?? "?"}). What's its detection history, are there open vulnerabilities, and is anything currently concerning?`,
                )}
                onClick={(e) => e.stopPropagation()}
                title="Open a free-form chat about this host"
                className="inline-flex items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950 px-2.5 py-1 text-xs font-medium text-neutral-300 transition-all hover:border-brand-700/50 hover:text-oxblood-200"
              >
                <MessageSquare className="h-3 w-3" strokeWidth={2.5} />
                Ask
              </Link>
              <Link
                href={`/investigate?host=${encodeURIComponent(h.hostname)}`}
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950 px-2.5 py-1 text-xs font-medium text-oxblood-400 transition-all hover:border-brand-700/50 hover:bg-brand-600/10 hover:text-oxblood-300"
              >
                <Microscope className="h-3 w-3" strokeWidth={2.5} />
                Investigate
              </Link>
            </div>
          ) : null}
        </td>
      </tr>
      {open && (
        <tr className="border-t border-neutral-800/80 bg-neutral-950/60">
          <td colSpan={8} className="px-4 py-4">
            <div className="grid gap-3 text-sm md:grid-cols-3">
              <Field label="Device ID" value={h.device_id} mono />
              <Field label="Local IP" value={h.local_ip} mono />
              <Field label="MAC" value={h.mac_address} mono />
              <Field label="First seen" value={h.first_seen} />
              <Field label="Agent version" value={h.agent_version} />
              <Field label="Cloud" value={h.service_provider} />
              <Field label="Cloud account" value={h.service_provider_account_id} />
              <Field label="Instance ID" value={h.instance_id} mono />
              <Field label="Serial" value={h.serial_number} mono />
              <Field label="Domain" value={h.machine_domain} />
              <Field label="RFM" value={h.reduced_functionality_mode} />
            </div>
            <details className="mt-3">
              <summary className="cursor-pointer text-xs uppercase tracking-wider text-neutral-500 hover:text-neutral-300">
                Raw host JSON
              </summary>
              <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap break-words rounded bg-neutral-900 px-3 py-2 font-mono text-xs text-neutral-400">
                {JSON.stringify(h, null, 2)}
              </pre>
            </details>
          </td>
        </tr>
      )}
    </>
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
