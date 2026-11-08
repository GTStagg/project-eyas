"use client";

import Link from "next/link";
import { Microscope } from "lucide-react";
import { endpointIrEligibility, IrChip } from "./irEligibility";

type Eligibility = {
  device_id?: string;
  hostname?: string;
  platform_name?: string;
  rtr_state?: string;
  product_type_desc?: string;
};

export default function HostActionButtons({
  host,
  irEnabled,
  size = "sm",
  showIr = true,
}: {
  host: Eligibility;
  irEnabled: boolean;
  size?: "sm" | "md";
  /** Surfaces that aren't detection-triage (e.g. the Shadow-AI fleet view)
   *  set this false to suppress the IR chip entirely — not even the greyed
   *  "set up IR" state belongs there. */
  showIr?: boolean;
}) {
  const baseClass =
    size === "sm"
      ? "flex h-8 items-center gap-1 rounded-md px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em]"
      : "flex h-9 items-center gap-1.5 rounded-md px-3 font-mono text-[11px] font-semibold uppercase tracking-[0.14em]";
  const iconClass = size === "sm" ? "h-3 w-3" : "h-3.5 w-3.5";

  const hostnameRaw = host.hostname ?? "";

  // Investigate is read-only and works on any host with a hostname — no RTR
  // eligibility required. Mirrors the chip in DetectionsTable / HostsTable /
  // QueueTable / VulnerabilitiesTable so the /investigate page's "open Hosts
  // and click Investigate" guidance lands on a real button.
  const investigateChip = hostnameRaw ? (
    <Link
      key="investigate"
      href={`/investigate?host=${encodeURIComponent(hostnameRaw)}`}
      className={`${baseClass} border border-neutral-800 bg-neutral-950 text-neutral-300 transition hover:border-neutral-700 hover:text-white`}
    >
      <Microscope className={iconClass} strokeWidth={1.75} />
      Investigate
    </Link>
  ) : null;

  // IR is always shown — live when eligible, greyed with a reason otherwise —
  // so its presence is predictable. Shared with /queue via irEligibility.
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {investigateChip}
      {showIr && (
        <IrChip eligibility={endpointIrEligibility(host, irEnabled)} size={size} />
      )}
    </div>
  );
}
