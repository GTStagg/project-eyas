"use client";

import { useState } from "react";
import {
  ShieldAlert,
  Stethoscope,
  Network,
  SlidersHorizontal,
  Radar,
  Wrench,
  FolderOpen,
  ShieldCheck,
  Workflow,
  MessageCircle,
  ChevronDown,
  Play,
  X,
  type LucideIcon,
} from "lucide-react";
import type { PrimerAction, PrimerKind } from "./primer";

const KIND_ICON: Record<PrimerKind, LucideIcon> = {
  ir: ShieldAlert,
  triage: Stethoscope,
  reconstruct: Network,
  tune: SlidersHorizontal,
  intel: Radar,
  patch: Wrench,
  case: FolderOpen,
  provision: ShieldCheck,
  workflow: Workflow,
  ask: MessageCircle,
};

/**
 * Confirmation card shown above the composer when an action button hands off to
 * chat. Renders the operator-facing summary; the precise agent instruction is
 * tucked behind a disclosure for transparency. Nothing runs until the operator
 * clicks Start.
 */
export default function PendingActionCard({
  action,
  busy,
  onStart,
  onCancel,
  onEdit,
}: {
  action: PrimerAction;
  busy: boolean;
  onStart: () => void;
  onCancel: () => void;
  onEdit: () => void;
}) {
  const [showInstruction, setShowInstruction] = useState(false);
  const Icon = KIND_ICON[action.kind] ?? MessageCircle;

  return (
    <div className="mx-auto max-w-3xl">
      <div className="rounded-lg border border-brand-900/60 bg-gradient-to-b from-brand-950/30 to-neutral-950 p-4 shadow-[0_0_28px_-12px_rgba(220,38,38,0.4)]">
        <div className="flex items-start gap-3">
          <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-brand-900/60 bg-brand-950/50 text-oxblood-300">
            <Icon className="h-4.5 w-4.5" strokeWidth={1.75} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-neutral-500">
              Pending action
            </div>
            <div className="mt-0.5 text-[15px] font-semibold leading-snug text-white">
              {action.title}
            </div>
            {action.subtitle && (
              <div className="mt-0.5 text-[12px] text-neutral-400">{action.subtitle}</div>
            )}
            {action.description && (
              <p className="mt-2 text-[13px] leading-relaxed text-neutral-300">
                {action.description}
              </p>
            )}

            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={onStart}
                disabled={busy}
                className="flex items-center gap-1.5 rounded-md bg-brand-600 px-4 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-white shadow-[0_0_24px_-6px_rgba(220,38,38,0.6),inset_0_1px_0_rgba(255,255,255,0.12)] transition hover:bg-brand-500 disabled:cursor-not-allowed disabled:bg-neutral-900 disabled:text-neutral-600 disabled:shadow-none"
              >
                <Play className="h-3 w-3" strokeWidth={2.5} fill="currentColor" />
                Start
              </button>
              <button
                type="button"
                onClick={onCancel}
                className="flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-neutral-300 transition hover:border-neutral-700 hover:text-white"
              >
                <X className="h-3 w-3" strokeWidth={2.5} />
                Cancel
              </button>
              {action.matched && (
                <button
                  type="button"
                  onClick={onEdit}
                  className="font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500 transition hover:text-oxblood-300"
                >
                  Edit as message
                </button>
              )}
              <button
                type="button"
                onClick={() => setShowInstruction((v) => !v)}
                aria-expanded={showInstruction}
                className="ml-auto flex items-center gap-1 font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500 transition hover:text-neutral-300"
              >
                <ChevronDown
                  className={`h-3.5 w-3.5 transition-transform ${showInstruction ? "rotate-180" : ""}`}
                  strokeWidth={2}
                />
                Instructions
              </button>
            </div>

            {showInstruction && (
              <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-md border border-neutral-800 bg-neutral-950 p-3 font-mono text-[11.5px] leading-relaxed text-neutral-400">
                {action.instruction}
              </pre>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
