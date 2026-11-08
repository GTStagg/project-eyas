// Shared, pure presentational + primer helpers for the /home dashboard and its
// snack-panel detail views. No React, no "use client" — just formatting and the
// canonical primer strings (kept here so the dashboard cards and the drawer
// footers build identical hand-offs matched by components/primer.ts templates).

import type { QueueRow } from "@/lib/queue/rank";

export function detName(d: QueueRow): string {
  return d.display_name ?? d.name ?? "detection";
}

export function severityTone(sev: number): { label: string; cls: string } {
  if (sev >= 80) return { label: "Critical", cls: "border-oxblood-800 bg-oxblood-900/50 text-oxblood-200" };
  if (sev >= 60) return { label: "High", cls: "border-orange-800 bg-orange-900/50 text-orange-200" };
  if (sev >= 40) return { label: "Medium", cls: "border-amber-800 bg-amber-900/40 text-amber-100" };
  return { label: "Low", cls: "border-sky-800 bg-sky-900/40 text-sky-200" };
}

export function relTime(iso: string | number): string {
  const then = typeof iso === "number" ? iso : new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const mins = Math.max(0, Math.round((Date.now() - then) / 60000));
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

// Single-detection triage hand-off. Matches the `Triage detection` template.
export function triagePrimer(d: QueueRow): string {
  const host = d.device?.hostname ?? "";
  const tactic = d.tactic ? ` Tactic: ${d.tactic}.` : "";
  return `Triage detection ${detName(d)} on host \`${host}\`.${tactic}`;
}

// "Ask about host" hand-off. Matches the `Tell me about host` template.
export function askHostPrimer(host: {
  hostname?: string;
  platform_name?: string;
  os_product_name?: string;
  status?: string;
}): string {
  const bits = [host.platform_name, host.os_product_name].filter(Boolean).join(" · ");
  const ctx = [bits, host.status ? `status ${host.status}` : ""].filter(Boolean).join(", ");
  return `Tell me about host \`${host.hostname ?? ""}\`${ctx ? ` (${ctx})` : ""}. What's its detection history?`;
}
