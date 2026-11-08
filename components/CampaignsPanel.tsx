"use client";

import { useRouter } from "next/navigation";
import { Network, MessageSquare } from "lucide-react";
import type { Campaign, CampaignType } from "@/lib/queue/campaigns";
import { reconstructPrimer } from "@/lib/queue/campaigns";
import { buildPrimerHref } from "@/components/primerHandoff";

const SEV_TONE: Record<string, string> = {
  Critical: "border-red-800 bg-red-950/50 text-red-200",
  High: "border-orange-800 bg-orange-950/50 text-orange-200",
  Medium: "border-yellow-800 bg-yellow-950/40 text-yellow-100",
  Low: "border-sky-800 bg-sky-950/40 text-sky-200",
  Informational: "border-neutral-700 bg-neutral-900 text-neutral-300",
};

const TYPE_LABEL: Record<CampaignType, string> = {
  shared_binary: "shared binary",
  shared_command: "shared command",
  lateral_movement: "lateral movement",
};

const TYPE_TONE: Record<CampaignType, string> = {
  shared_binary: "border-red-900 bg-red-950/40 text-oxblood-300",
  shared_command: "border-orange-900 bg-orange-950/40 text-orange-300",
  lateral_movement: "border-blue-900 bg-blue-950/40 text-blue-300",
};

function relativeAge(iso?: string): string {
  if (!iso) return "—";
  const ms = Date.now() - new Date(iso).getTime();
  const h = ms / 3_600_000;
  if (h < 1) return `${Math.max(0, Math.floor(h * 60))}m`;
  if (h < 48) return `${Math.floor(h)}h`;
  return `${Math.floor(h / 24)}d`;
}

function CampaignCard({ c, onSelect }: { c: Campaign; onSelect?: (c: Campaign) => void }) {
  const router = useRouter();
  const sevTone = c.severity_max_name
    ? SEV_TONE[c.severity_max_name] ?? SEV_TONE.Informational
    : SEV_TONE.Informational;
  const reconstruct = reconstructPrimer(c);

  // When onSelect is provided (dashboard), the info body opens a detail drawer;
  // the Reconstruct button always hands off to chat. Without it (/queue), the
  // body is inert and only Reconstruct acts — byte-for-byte the prior behavior.
  const selectable = Boolean(onSelect);

  return (
    <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div
          className={`min-w-0 flex-1 ${selectable ? "cursor-pointer rounded outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-brand-700/50" : ""}`}
          {...(selectable
            ? {
                role: "button",
                tabIndex: 0,
                title: "Open campaign detail",
                onClick: () => onSelect!(c),
                onKeyDown: (e: React.KeyboardEvent) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    onSelect!(c);
                  }
                },
              }
            : {})}
        >
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] ${TYPE_TONE[c.type]}`}
            >
              {TYPE_LABEL[c.type]}
            </span>
            {c.severity_max_name && (
              <span
                className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] ${sevTone}`}
              >
                {c.severity_max_name}
              </span>
            )}
            <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500">
              {c.host_count} hosts · {c.detection_count} detections
            </span>
            {c.uncontained_count === c.host_count && (
              <span className="rounded border border-amber-800 bg-amber-950/50 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-amber-200">
                no host contained
              </span>
            )}
            {c.uncontained_count > 0 && c.uncontained_count < c.host_count && (
              <span className="rounded border border-amber-900 bg-amber-950/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-amber-300">
                {c.uncontained_count} uncontained
              </span>
            )}
          </div>
          <div
            className="mt-1.5 break-all font-mono text-[13px] text-neutral-100"
            title={c.shared_artifact}
          >
            {c.artifact_label}
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            {c.hosts.map((h) => (
              <span
                key={h.aid ?? h.hostname}
                className={`rounded border px-1.5 py-0.5 font-mono text-[10.5px] ${
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
          {c.techniques.length > 0 && (
            <div className="mt-1 truncate font-mono text-[11px] text-neutral-500">
              techniques: {c.techniques.slice(0, 4).join(" · ")}
              {c.techniques.length > 4 ? ` +${c.techniques.length - 4}` : ""}
            </div>
          )}
          <div className="mt-1 flex flex-wrap gap-x-4 font-mono text-[11px] text-neutral-500">
            {c.earliest_ts && <span>first seen {relativeAge(c.earliest_ts)} ago</span>}
            {c.latest_ts && <span>last seen {relativeAge(c.latest_ts)} ago</span>}
          </div>
          {c.reasons.length > 0 && (
            <div className="mt-1 text-[11px] text-neutral-500">
              {c.reasons.join(" · ")}
            </div>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <button
            onClick={() =>
              router.push(buildPrimerHref(reconstruct))
            }
            title="Hand campaign reconstruction to the chat agent (timeline, blast radius, recommended scope)"
            className="flex h-8 items-center gap-1 rounded-md border border-brand-900/60 bg-brand-950/40 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-oxblood-200 transition hover:bg-brand-900/40 hover:text-white"
          >
            <MessageSquare className="h-3 w-3" strokeWidth={1.75} />
            Reconstruct
          </button>
        </div>
      </div>
    </div>
  );
}

export default function CampaignsPanel({
  campaigns,
  onSelect,
  bare,
}: {
  campaigns: Campaign[];
  onSelect?: (c: Campaign) => void;
  /** Drop the section chrome — used inside the dashboard snack panel, which
   *  already supplies its own header. */
  bare?: boolean;
}) {
  if (bare) {
    return (
      <div className="space-y-2.5">
        {campaigns.length === 0 ? (
          <p className="py-6 text-center text-sm text-neutral-400">No cross-host campaigns right now.</p>
        ) : (
          campaigns.map((c) => <CampaignCard key={c.id} c={c} onSelect={onSelect} />)
        )}
      </div>
    );
  }
  return (
    <section className="mb-5 rounded-md border border-orange-900/40 bg-gradient-to-br from-neutral-950 via-neutral-950 to-orange-950/15 p-4 shadow-[0_18px_45px_-30px_rgba(251,146,60,0.4)]">
      <div className="mb-3 flex items-center gap-2 font-mono text-xs uppercase tracking-[0.16em] text-orange-300">
        <Network className="h-3.5 w-3.5" strokeWidth={1.75} />
        cross-host // campaigns
        <span className="text-neutral-600">·</span>
        <span className="text-neutral-400">{campaigns.length} detected</span>
      </div>
      <p className="mb-3 text-[12px] text-neutral-400">
        Detections clustered across 2+ hosts by shared artifact (binary hash,
        image+technique, or user with lateral-movement signal). Click{" "}
        <span className="font-mono text-oxblood-300">Reconstruct</span> to get a
        timeline and blast-radius report.
      </p>
      <div className="space-y-2.5">
        {campaigns.map((c) => (
          <CampaignCard key={c.id} c={c} onSelect={onSelect} />
        ))}
      </div>
    </section>
  );
}
