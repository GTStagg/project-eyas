"use client";

import { useCallback, useRef, useState } from "react";
import { AlertCircle, ArrowRight, ExternalLink, Loader2, Square } from "lucide-react";
import SectionedMarkdown from "./SectionedMarkdown";
import { BLUEPRINT_SEEDS, DEV_PORTAL_LINKS } from "@/lib/advisor/blueprint-shared";

type ParsedSSE = { event: string; data: string };

function parseSSE(buffer: string): { events: ParsedSSE[]; rest: string } {
  const events: ParsedSSE[] = [];
  let rest = buffer;
  while (true) {
    const idx = rest.indexOf("\n\n");
    if (idx === -1) break;
    const block = rest.slice(0, idx);
    rest = rest.slice(idx + 2);
    let event = "message";
    const dataLines: string[] = [];
    for (const line of block.split("\n")) {
      if (line.startsWith("event: ")) event = line.slice(7);
      else if (line.startsWith("data: ")) dataLines.push(line.slice(6));
    }
    events.push({ event, data: dataLines.join("\n") });
  }
  return { events, rest };
}

type Phase = "idle" | "streaming" | "done" | "cancelled" | "error";

export default function BlueprintAdvisor() {
  const [input, setInput] = useState("");
  const [asked, setAsked] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{
    iterations: number;
    usage?: { input_tokens?: number; output_tokens?: number };
  } | null>(null);

  const inFlightRef = useRef(false);
  const abortRef = useRef<AbortController | null>(null);
  const cancelledRef = useRef(false);
  const outputRef = useRef<HTMLDivElement>(null);

  const run = useCallback(async (question: string) => {
    const q = question.trim();
    if (!q || inFlightRef.current) return;
    inFlightRef.current = true;
    cancelledRef.current = false;
    abortRef.current = new AbortController();
    setAsked(q);
    setText("");
    setError(null);
    setDone(null);
    setPhase("streaming");

    requestAnimationFrame(() => {
      outputRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });

    try {
      const resp = await fetch("/api/blueprint", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: q }),
        signal: abortRef.current.signal,
      });

      if (!resp.ok || !resp.body) {
        let msg = `HTTP ${resp.status}`;
        try {
          const j = (await resp.json()) as { error?: string };
          if (j.error) msg = j.error;
        } catch {
          /* keep status */
        }
        setError(msg);
        setPhase("error");
        return;
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done: readerDone, value } = await reader.read();
        if (readerDone) break;
        buf += decoder.decode(value, { stream: true });
        const { events, rest } = parseSSE(buf);
        buf = rest;
        for (const ev of events) {
          if (ev.event === "text") {
            setText((prev) => prev + ev.data);
            continue;
          }
          let data: unknown = ev.data;
          try {
            data = JSON.parse(ev.data);
          } catch {
            /* keep as string */
          }
          if (ev.event === "done") {
            setDone(
              data as { iterations: number; usage?: { input_tokens?: number; output_tokens?: number } },
            );
            setPhase("done");
          } else if (ev.event === "error") {
            setError((data as { message?: string }).message ?? "Something went wrong");
            setPhase("error");
          }
        }
      }
    } catch (err) {
      if (
        cancelledRef.current ||
        (err instanceof DOMException && err.name === "AbortError")
      ) {
        setPhase((p) => (p === "done" || p === "error" ? p : "cancelled"));
      } else {
        setError(err instanceof Error ? err.message : String(err));
        setPhase("error");
      }
    } finally {
      inFlightRef.current = false;
      abortRef.current = null;
    }
  }, []);

  const stop = useCallback(() => {
    if (!inFlightRef.current) return;
    cancelledRef.current = true;
    abortRef.current?.abort();
  }, []);

  const busy = phase === "streaming";
  const showEmpty = phase === "idle" && !text;

  return (
    <div className="space-y-8">
      {/* Ask box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          run(input);
        }}
        className="space-y-3"
      >
        <label
          htmlFor="blueprint-q"
          className="block font-mono text-[12px] uppercase tracking-[0.16em] text-neutral-500"
        >
          $ ask how to build it
        </label>
        <div className="flex flex-col gap-2 sm:flex-row">
          <textarea
            id="blueprint-q"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                run(input);
              }
            }}
            rows={2}
            placeholder="How would I build an approval-gated IR workflow on falcon-mcp + FalconPy + Claude?"
            className="min-h-[3rem] flex-1 resize-y rounded-md border border-neutral-800 bg-neutral-950 px-3.5 py-2.5 font-mono text-[15px] text-neutral-100 placeholder:text-neutral-600 focus:border-neutral-600 focus:outline-none"
          />
          {busy ? (
            <button
              type="button"
              onClick={stop}
              className="inline-flex h-fit items-center justify-center gap-1.5 rounded-md border border-neutral-700 bg-neutral-900 px-4 py-2.5 font-mono text-[13px] font-semibold uppercase tracking-[0.14em] text-neutral-200 transition-colors hover:border-amber-700 hover:bg-amber-950/40 hover:text-amber-200"
            >
              <Square className="h-3.5 w-3.5" strokeWidth={2.5} fill="currentColor" />
              Stop
            </button>
          ) : (
            <button
              type="submit"
              disabled={!input.trim()}
              className="inline-flex h-fit items-center justify-center gap-1.5 rounded-md border border-brand-800/60 bg-brand-950/30 px-4 py-2.5 font-mono text-[13px] font-semibold uppercase tracking-[0.14em] text-oxblood-200 transition-colors hover:border-brand-700 hover:bg-brand-950/60 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Ask
              <ArrowRight className="h-3.5 w-3.5" strokeWidth={2.5} />
            </button>
          )}
        </div>
        <p className="font-mono text-[11px] text-neutral-600">⌘/Ctrl + Enter to send</p>
      </form>

      {/* Seed blueprints */}
      {showEmpty && (
        <div className="space-y-3">
          <div className="font-mono text-[12px] uppercase tracking-[0.16em] text-neutral-500">
            › blueprints
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {BLUEPRINT_SEEDS.map((seed) => (
              <button
                key={seed.label}
                type="button"
                onClick={() => run(seed.question)}
                className="group flex items-center justify-between gap-3 rounded-md border border-neutral-800 bg-neutral-950 px-3.5 py-3 text-left transition-colors hover:border-neutral-600 hover:bg-neutral-900"
              >
                <span className="text-[15px] text-neutral-200">{seed.label}</span>
                <ArrowRight
                  className="h-4 w-4 shrink-0 text-neutral-600 transition-colors group-hover:text-oxblood-300"
                  strokeWidth={2}
                />
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Output */}
      <div ref={outputRef} className="space-y-4">
        {asked && !showEmpty && (
          <div className="flex items-start gap-2 border-l-2 border-neutral-800 pl-3 text-[15px] text-neutral-400">
            <span className="mt-0.5 shrink-0 font-mono text-neutral-600">?</span>
            <span>{asked}</span>
          </div>
        )}

        {(busy || phase === "cancelled" || phase === "error") && (
          <div className="flex items-center justify-between gap-3 border border-neutral-800 bg-gradient-to-br from-neutral-950 via-neutral-950 to-brand-950/20 px-4 py-2.5">
            <div className="flex items-center gap-2.5">
              {phase === "error" ? (
                <span className="inline-block h-2 w-2 rounded-full bg-red-500" />
              ) : phase === "cancelled" ? (
                <span className="inline-block h-2 w-2 rounded-full bg-amber-500" />
              ) : (
                <span className="live-dot" />
              )}
              <span className="font-mono text-[12px] uppercase tracking-[0.16em] text-neutral-400">
                blueprint //
              </span>
              <span className="text-[15px] font-medium text-neutral-100">
                {phase === "streaming"
                  ? "Composing the build analysis…"
                  : phase === "cancelled"
                    ? "Stopped"
                    : "Failed"}
              </span>
            </div>
            {busy && (
              <Loader2 className="spin-slow h-3.5 w-3.5 shrink-0 text-oxblood-400" strokeWidth={2.5} />
            )}
          </div>
        )}

        {text && (
          <div className="border border-neutral-800 bg-neutral-950 px-5 py-5 sm:px-7 sm:py-6">
            <div className="markdown">
              <SectionedMarkdown text={text} />
            </div>
          </div>
        )}

        {error && (
          <div className="flex items-start gap-3 rounded-md border border-red-900/70 bg-red-950/30 px-4 py-3.5 text-base text-red-200">
            <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-oxblood-400" strokeWidth={2} />
            <div className="min-w-0 flex-1">
              <div className="font-semibold text-red-100">Couldn&apos;t generate the blueprint</div>
              <div className="mt-1 break-words font-mono text-sm text-red-200/90">{error}</div>
            </div>
          </div>
        )}

        {done && done.usage && (
          <div className="font-mono text-[12px] uppercase tracking-[0.12em] tabular-nums text-neutral-500">
            {done.usage.input_tokens?.toLocaleString()} in ·{" "}
            {done.usage.output_tokens?.toLocaleString()} out
          </div>
        )}
      </div>

      {/* Authoritative sources — link out, never re-host */}
      <div className="space-y-3 border-t border-neutral-900 pt-6">
        <div className="font-mono text-[12px] uppercase tracking-[0.16em] text-neutral-500">
          › authoritative sources · developer.crowdstrike.com
        </div>
        <p className="max-w-2xl text-sm text-neutral-500">
          This advisor teaches the composition patterns. For the platform primitives
          themselves — APIs, SDKs, scopes — go to the source:
        </p>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {DEV_PORTAL_LINKS.map((link) => (
            <a
              key={link.url}
              href={link.url}
              target="_blank"
              rel="noreferrer"
              className="group flex flex-col gap-1 rounded-md border border-neutral-800 bg-neutral-950 px-3.5 py-3 transition-colors hover:border-neutral-600 hover:bg-neutral-900"
            >
              <span className="flex items-center gap-1.5 font-mono text-[13px] font-semibold text-neutral-200">
                {link.topic}
                <ExternalLink
                  className="h-3 w-3 text-neutral-600 transition-colors group-hover:text-oxblood-300"
                  strokeWidth={2}
                />
              </span>
              <span className="text-[13px] leading-snug text-neutral-500">{link.blurb}</span>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
