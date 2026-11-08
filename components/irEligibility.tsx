"use client";

import Link from "next/link";
import { AlertTriangle, ShieldAlert } from "lucide-react";
import { buildPrimerHref } from "./primerHandoff";
import type { IrEligibility } from "@/lib/hosts/ir-eligibility";

// Re-export the pure predicates so callers have one import site for both the
// logic and the chip. The logic lives in lib/ (unit-tested without a DOM).
export {
  endpointIrEligibility,
  identityIrEligibility,
} from "@/lib/hosts/ir-eligibility";
export type { IrEligibility } from "@/lib/hosts/ir-eligibility";

/**
 * Unified IR chip used by /hosts and /queue. Eligible renders a live amber chip
 * (a Link by default, or a button when `onStart` is supplied — the queue needs
 * to claim detections + navigate). Ineligible renders a greyed, non-interactive
 * chip with a tooltip reason. Off renders a greyed chip that links to Config so
 * the operator can set IR up. The chip is always present so its placement is
 * predictable — it never silently disappears.
 */
export function IrChip({
  eligibility,
  size = "sm",
  label = "IR",
  onStart,
}: {
  eligibility: IrEligibility;
  size?: "sm" | "md";
  label?: string;
  onStart?: (primer: string) => void;
}) {
  const base =
    size === "sm"
      ? "flex h-8 items-center gap-1 rounded-md px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em]"
      : "flex h-9 items-center gap-1.5 rounded-md px-3 font-mono text-[11px] font-semibold uppercase tracking-[0.14em]";
  const iconClass = size === "sm" ? "h-3 w-3" : "h-3.5 w-3.5";
  const stop = (e: React.MouseEvent) => e.stopPropagation();

  if (eligibility.state === "eligible") {
    // A caution (currently only "this is a Domain Controller") keeps the chip
    // fully clickable — operators legitimately IR a DC — but flips it red with a
    // warning icon + tooltip so the blast radius isn't an invisible foot-gun.
    const caution = eligibility.caution;
    const cls = caution
      ? `${base} border border-red-900/70 bg-red-950/40 text-red-200 transition hover:bg-red-900/40 hover:text-white`
      : `${base} border border-amber-900/60 bg-amber-950/40 text-amber-200 transition hover:bg-amber-900/40 hover:text-white`;
    const Icon = caution ? AlertTriangle : ShieldAlert;
    const title = caution ?? "Run the guided incident-response workflow";
    if (onStart) {
      return (
        <button
          type="button"
          onClick={(e) => {
            stop(e);
            onStart(eligibility.primer);
          }}
          title={title}
          className={cls}
        >
          <Icon className={iconClass} strokeWidth={1.75} />
          {label}
        </button>
      );
    }
    return (
      <Link
        href={buildPrimerHref(eligibility.primer)}
        onClick={stop}
        title={title}
        className={cls}
      >
        <Icon className={iconClass} strokeWidth={1.75} />
        {label}
      </Link>
    );
  }

  if (eligibility.state === "off") {
    return (
      <Link
        href="/config"
        onClick={stop}
        title={eligibility.reason}
        className={`${base} border border-neutral-800 bg-neutral-950/60 text-neutral-500 transition hover:border-neutral-700 hover:text-neutral-300`}
      >
        <ShieldAlert className={iconClass} strokeWidth={1.75} />
        {label}
      </Link>
    );
  }

  return (
    <span
      title={eligibility.reason}
      className={`${base} cursor-not-allowed border border-neutral-800 bg-neutral-950/40 text-neutral-600`}
    >
      <ShieldAlert className={iconClass} strokeWidth={1.75} />
      {label}
    </span>
  );
}
