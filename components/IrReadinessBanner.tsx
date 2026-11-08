"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ShieldAlert, ArrowRight, X } from "lucide-react";

// Surfaces a non-blocking banner on pages that launch IR (Hosts, Queue,
// detection drill-ins) when the tenant's IR quarantine setup isn't
// `ready`. Click-through to /config's setup card. Read-only — never
// fires writes itself.
//
// The banner is dismissible per-session (sessionStorage) so an operator
// who knowingly hasn't provisioned can suppress it for the rest of the
// tab. Returns to surfaced state on a fresh tab so it doesn't get
// permanently silenced.

type DiagnosticCase =
  | "no_group_id"
  | "group_missing"
  | "A_no_policy"
  | "B_dedicated_single_group"
  | "C_shared_policy"
  | "ready";

type Diagnostic = {
  ok: boolean;
  case?: DiagnosticCase;
  recommended_action?: { label: string; description: string } | null;
  error?: string;
};

const STORAGE_KEY = "ir-readiness-banner-dismissed";

const SHORT_LABEL: Record<Exclude<DiagnosticCase, "ready">, string> = {
  no_group_id: "No quarantine host group is set on this tenant.",
  group_missing: "The configured quarantine group doesn't exist in Falcon.",
  A_no_policy: "Quarantine group has no dedicated prevention policy attached.",
  B_dedicated_single_group: "Quarantine policy needs to be standardized to AGGRESSIVE + IR exclusions.",
  C_shared_policy: "Quarantine policy is shared with other groups — needs a dedicated one for IR.",
};

export default function IrReadinessBanner() {
  const [data, setData] = useState<Diagnostic | null>(null);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined" && sessionStorage.getItem(STORAGE_KEY) === "1") {
      setDismissed(true);
      return;
    }
    fetch("/api/ir-quarantine/diagnose")
      .then((r) => r.json())
      .then((d: Diagnostic) => setData(d))
      .catch(() => {
        // Silent — banner is opportunistic, not a hard requirement.
      });
  }, []);

  if (dismissed || !data || !data.ok || !data.case || data.case === "ready") return null;
  const short = SHORT_LABEL[data.case];
  if (!short) return null;

  return (
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-md border border-amber-700/60 bg-amber-950/40 px-4 py-3">
      <ShieldAlert className="h-4 w-4 shrink-0 text-amber-300" strokeWidth={2} />
      <div className="min-w-0 flex-1 text-sm text-amber-100">
        <span className="font-semibold">IR quarantine isn't fully provisioned.</span>{" "}
        <span className="text-amber-100/85">{short}</span>
      </div>
      <Link
        href="/config"
        className="inline-flex shrink-0 items-center gap-1.5 rounded border border-amber-700 bg-amber-950/60 px-3 py-1 font-mono text-[11px] uppercase tracking-wide text-amber-100 hover:bg-amber-900/60"
      >
        Set up in /config
        <ArrowRight className="h-3 w-3" strokeWidth={2} />
      </Link>
      <button
        type="button"
        onClick={() => {
          setDismissed(true);
          if (typeof window !== "undefined") sessionStorage.setItem(STORAGE_KEY, "1");
        }}
        aria-label="Dismiss for this session"
        className="inline-flex shrink-0 items-center justify-center rounded p-1 text-amber-300 hover:text-amber-100"
      >
        <X className="h-3.5 w-3.5" strokeWidth={2} />
      </button>
    </div>
  );
}
