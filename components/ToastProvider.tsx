"use client";

// Lightweight toast/snackbar system. Mounted once in AppShell so every page can
// call useToast(). Bottom-right stack, auto-dismiss, manual close. Theme-aware —
// uses neutral card tokens + a per-kind accent left border (no purple, per the
// UI palette rule). No developer jargon in any caller's copy.

import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { CheckCircle2, Info, AlertTriangle, XCircle, X } from "lucide-react";

export type ToastKind = "info" | "success" | "warn" | "error";

type Toast = {
  id: number;
  message: string;
  kind: ToastKind;
};

type ToastOptions = {
  kind?: ToastKind;
  /** Milliseconds before auto-dismiss. Default 4000; pass 0 to keep until closed. */
  ttl?: number;
};

type ToastFn = (message: string, opts?: ToastOptions) => void;

const ToastContext = createContext<ToastFn | null>(null);

/** Fire a transient toast. Safe to call from any client component under AppShell.
 *  If no provider is mounted (e.g. an isolated test render) it no-ops. */
export function useToast(): ToastFn {
  const ctx = useContext(ToastContext);
  return ctx ?? (() => {});
}

const KIND_STYLE: Record<
  ToastKind,
  { border: string; icon: typeof Info; iconClass: string }
> = {
  info: { border: "border-l-sky-500", icon: Info, iconClass: "text-sky-400" },
  success: {
    border: "border-l-emerald-500",
    icon: CheckCircle2,
    iconClass: "text-emerald-400",
  },
  warn: {
    border: "border-l-amber-500",
    icon: AlertTriangle,
    iconClass: "text-amber-400",
  },
  error: {
    border: "border-l-oxblood-500",
    icon: XCircle,
    iconClass: "text-oxblood-300",
  },
};

export default function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback<ToastFn>(
    (message, opts) => {
      const id = nextId.current++;
      const kind = opts?.kind ?? "info";
      const ttl = opts?.ttl ?? 4000;
      setToasts((prev) => [...prev, { id, message, kind }]);
      if (ttl > 0) {
        setTimeout(() => dismiss(id), ttl);
      }
    },
    [dismiss],
  );

  return (
    <ToastContext.Provider value={toast}>
      {children}
      <div
        className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(22rem,calc(100vw-2rem))] flex-col gap-2"
        aria-live="polite"
        role="status"
      >
        {toasts.map((t) => {
          const style = KIND_STYLE[t.kind];
          const Icon = style.icon;
          return (
            <div
              key={t.id}
              className={`pointer-events-auto flex animate-fade-in-up items-start gap-2.5 rounded-md border border-l-2 border-neutral-800 ${style.border} bg-neutral-900 px-3.5 py-3 shadow-2xl shadow-black/40`}
            >
              <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${style.iconClass}`} strokeWidth={2} />
              <div className="min-w-0 flex-1 text-sm text-neutral-100">{t.message}</div>
              <button
                type="button"
                onClick={() => dismiss(t.id)}
                aria-label="Dismiss"
                className="shrink-0 rounded p-0.5 text-neutral-500 transition-colors hover:text-neutral-200"
              >
                <X className="h-3.5 w-3.5" strokeWidth={2} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
