"use client";

import { useEffect, useState } from "react";
import { Clock } from "lucide-react";

// Time-until-expiry indicator for the chat conversation history surface.
// The rolling idle TTL is enforced server-side (lib/chat/state.ts::TTL_MS —
// currently 72h); this pill just renders the countdown from `expiresAt` so the
// operator isn't surprised when a stored conversation falls off the list. Two
// visual sizes:
//   - "row" — compact pill shown next to each entry in the left rail.
//   - "header" — larger pill for the active chat header.
//
// Updates every minute via a single setInterval; no server polling.

function fmtRemaining(ms: number): string {
  if (ms <= 0) return "expired";
  const sec = Math.floor(ms / 1000);
  const day = Math.floor(sec / 86_400);
  if (day >= 2) return `${day}d`;
  const hr = Math.floor(sec / 3_600);
  if (hr >= 2) return `${hr}h`;
  const min = Math.floor(sec / 60);
  if (min >= 2) return `${min}m`;
  return "<1m";
}

function fmtRemainingLong(ms: number): string {
  if (ms <= 0) return "Expired";
  const sec = Math.floor(ms / 1000);
  const day = Math.floor(sec / 86_400);
  const hr = Math.floor((sec % 86_400) / 3_600);
  const min = Math.floor((sec % 3_600) / 60);
  if (day >= 1) return `Expires in ${day}d ${hr}h`;
  if (hr >= 1) return `Expires in ${hr}h ${min}m`;
  if (min >= 1) return `Expires in ${min}m`;
  return "Expires in <1m";
}

function colorFor(ms: number): string {
  if (ms <= 0) return "border-red-800/60 bg-red-950/40 text-oxblood-200";
  if (ms < 24 * 60 * 60 * 1000) return "border-amber-800/60 bg-amber-950/40 text-amber-200";
  return "border-neutral-800 bg-neutral-950/60 text-neutral-400";
}

type Props = {
  expiresAt: number;
  variant?: "row" | "header";
};

export default function SessionTtlPill({ expiresAt, variant = "row" }: Props) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(t);
  }, []);
  const remaining = expiresAt - now;
  const color = colorFor(remaining);
  if (variant === "header") {
    return (
      <span
        className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wide ${color}`}
        title={`Expires ${new Date(expiresAt).toLocaleString()}`}
      >
        <Clock className="h-3 w-3" strokeWidth={2} />
        {fmtRemainingLong(remaining)}
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 font-mono text-[10px] uppercase tracking-wide ${color}`}
      title={`Expires ${new Date(expiresAt).toLocaleString()}`}
    >
      {fmtRemaining(remaining)}
    </span>
  );
}
