"use client";

import { useEffect, useState } from "react";
import { Check, Loader2, Printer, Send } from "lucide-react";

export function PrintReportButton() {
  useEffect(() => {
    const onAfter = () => document.body.classList.remove("print-mode");
    window.addEventListener("afterprint", onAfter);
    return () => window.removeEventListener("afterprint", onAfter);
  }, []);

  const print = () => {
    document.body.classList.add("print-mode");
    requestAnimationFrame(() => window.print());
  };

  return (
    <button
      type="button"
      onClick={print}
      title="Print or save as PDF"
      className="inline-flex items-center gap-1.5 border border-neutral-800 bg-neutral-950 px-3 py-1.5 text-xs font-semibold text-neutral-200 transition-colors hover:border-neutral-700 hover:bg-neutral-900 hover:text-white"
    >
      <Printer className="h-3.5 w-3.5" strokeWidth={2} />
      Print / PDF
    </button>
  );
}

export function WebhookSendButton({
  markdown,
  title,
  source,
}: {
  markdown: string;
  title?: string;
  source?: string;
}) {
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [state, setState] = useState<"idle" | "sending" | "sent" | "error">(
    "idle",
  );
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/webhook")
      .then((r) => r.json())
      .then((j: { configured?: boolean }) => {
        if (!cancelled) setConfigured(Boolean(j.configured));
      })
      .catch(() => {
        if (!cancelled) setConfigured(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!configured) return null;

  const send = async () => {
    setState("sending");
    setError(null);
    try {
      const resp = await fetch("/api/webhook", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ markdown, title, source }),
      });
      const j = (await resp.json().catch(() => ({}))) as {
        ok?: boolean;
        error?: string;
      };
      if (!resp.ok || !j.ok) {
        setError(j.error || `HTTP ${resp.status}`);
        setState("error");
        return;
      }
      setState("sent");
      setTimeout(() => setState("idle"), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setState("error");
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        type="button"
        onClick={send}
        disabled={state === "sending"}
        className="inline-flex items-center gap-1.5 border border-neutral-800 bg-neutral-950 px-3 py-1.5 text-xs font-semibold text-neutral-200 transition-colors hover:border-neutral-700 hover:bg-neutral-900 hover:text-white disabled:opacity-60"
      >
        {state === "sent" ? (
          <>
            <Check className="h-3.5 w-3.5 text-emerald-400" strokeWidth={2.5} />
            Sent
          </>
        ) : state === "sending" ? (
          <>
            <Loader2 className="h-3.5 w-3.5 animate-spin" strokeWidth={2.5} />
            Sending…
          </>
        ) : (
          <>
            <Send className="h-3.5 w-3.5" strokeWidth={2} />
            Send to webhook
          </>
        )}
      </button>
      {state === "error" && error && (
        <span className="font-mono text-xs text-oxblood-400">{error}</span>
      )}
    </div>
  );
}
