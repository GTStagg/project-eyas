"use client";

// Reusable right-side modal snack-panel (slide-over drawer). Surfaces detail in
// place without navigating away — the dashboard's control-center primitive.
// Modeled on ConversationList (right overlay) + Sidebar (slide transition).
//
// Always mounted so it can animate in/out; pointer-events are gated when closed.
// Backdrop z-40, panel z-50 — deliberately below toasts (z-[60]) so a "Copied"
// toast still shows over an open panel.

import { useEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";

export default function SnackPanel({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  width = "md",
  keepMounted = false,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  /** md ≈ 28rem (detail views); lg ≈ 40rem (interactive tools). */
  width?: "md" | "lg";
  /** Keep children mounted while closed (panel just slides off-screen) so
   *  stateful bodies — e.g. the chat dock's transcript — survive close/reopen. */
  keepMounted?: boolean;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);
  // Portal to <body> so the fixed overlay is never trapped by a transformed or
  // max-width ancestor (e.g. the dashboard's animate-fade-in-up container),
  // which would otherwise re-anchor `position: fixed` and shrink the backdrop.
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  // Esc-to-close.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  // Move focus into the panel on open; restore to the trigger on close.
  useEffect(() => {
    if (open) {
      restoreRef.current = document.activeElement as HTMLElement | null;
      // Defer so the element is focusable after the open transition starts.
      const id = window.setTimeout(() => panelRef.current?.focus(), 0);
      return () => window.clearTimeout(id);
    }
    restoreRef.current?.focus?.();
  }, [open]);

  if (!mounted) return null;

  return createPortal(
    <>
      {/* Backdrop */}
      <div
        aria-hidden="true"
        onClick={onClose}
        className={`fixed inset-0 z-40 bg-black/70 backdrop-blur-sm transition-opacity duration-300 ${
          open ? "opacity-100" : "pointer-events-none opacity-0"
        }`}
      />

      {/* Panel */}
      <aside
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-hidden={!open}
        tabIndex={-1}
        className={`fixed inset-y-0 right-0 z-50 flex ${
          width === "lg" ? "w-[40rem]" : "w-[28rem]"
        } max-w-[92vw] flex-col border-l border-neutral-800 bg-neutral-950 shadow-2xl shadow-black/50 outline-none transition-transform duration-300 ease-out ${
          open ? "translate-x-0" : "pointer-events-none translate-x-full"
        }`}
      >
        <div className="relative flex items-start justify-between gap-3 border-b border-neutral-800/80 px-5 py-4">
          <div className="pointer-events-none absolute inset-x-0 -bottom-px h-px bg-gradient-to-r from-transparent via-brand-700/40 to-transparent" />
          <div className="min-w-0">
            <div className="truncate text-base font-semibold text-neutral-50">{title}</div>
            {subtitle ? (
              <div className="mt-0.5 truncate font-mono text-[12px] text-neutral-500">{subtitle}</div>
            ) : null}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close panel"
            className="shrink-0 rounded-md border border-neutral-800 bg-neutral-950/40 p-1.5 text-neutral-400 transition-colors hover:border-brand-700/60 hover:text-oxblood-200"
          >
            <X className="h-4 w-4" strokeWidth={2} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4">{keepMounted || open ? children : null}</div>

        {footer ? (
          <div className="border-t border-neutral-800/80 px-5 py-3">{footer}</div>
        ) : null}
      </aside>
    </>,
    document.body,
  );
}
