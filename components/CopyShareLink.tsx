"use client";

import { useState } from "react";
import { Copy, Check } from "lucide-react";

// Tiny client-side button: copies a relative URL (joined with the current
// origin) to the clipboard and flashes a confirmation. Used on the IR run
// detail page so an operator can paste the link into a ticket / chat.

export default function CopyShareLink({
  href,
  label = "Copy share link",
}: {
  href: string;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);

  async function onClick() {
    try {
      const url = new URL(href, window.location.origin).toString();
      await navigator.clipboard.writeText(url);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard write can fail in restricted contexts (no user gesture,
      // insecure origin). Silent — the operator can copy from the address
      // bar as a fallback.
    }
  }

  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1.5 rounded border border-neutral-800 bg-neutral-950 px-3 py-1.5 font-mono text-[11px] uppercase tracking-wide text-neutral-300 transition hover:border-neutral-700 hover:text-white"
      aria-label={label}
    >
      {copied ? (
        <>
          <Check className="h-3 w-3 text-emerald-300" strokeWidth={2} />
          Copied
        </>
      ) : (
        <>
          <Copy className="h-3 w-3" strokeWidth={2} />
          Share link
        </>
      )}
    </button>
  );
}
