"use client";

import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from "react";
import { AlertCircle, Loader2, Square } from "lucide-react";
import SectionedMarkdown from "./SectionedMarkdown";
import { PrintReportButton, WebhookSendButton } from "./AgentArtifactActions";

type ToolUse = {
  id: string;
  name: string;
  input: Record<string, unknown>;
  result?: { content: string; isError: boolean; durationMs?: number };
};

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

export type AgentRunHandle = {
  start: () => void;
  stop: () => void;
};

export type AgentRunProps = {
  endpoint: string;
  body?: unknown;
  autoStart?: boolean;
  emptyHint?: React.ReactNode;
  onFinish?: () => void;
  /** Fired when a run completes (the `done` event) with the final report text —
   *  used by callers that continue the conversation about the result. */
  onReport?: (finalText: string) => void;
  webhookTitle?: string;
  webhookSource?: string;
};

const AgentRun = forwardRef<AgentRunHandle, AgentRunProps>(function AgentRun(
  { endpoint, body, autoStart = false, emptyHint, onFinish, onReport, webhookTitle, webhookSource },
  ref,
) {
  const [text, setText] = useState("");
  // Mirror of `text` for the onReport callback (state is stale in the SSE closure).
  const textRef = useRef("");
  const [toolUses, setToolUses] = useState<ToolUse[]>([]);
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<"idle" | "starting" | "running-tool" | "thinking" | "done" | "cancelled" | "error">("idle");
  const [currentToolName, setCurrentToolName] = useState<string | null>(null);
  const [highlightedToolId, setHighlightedToolId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{
    iterations: number;
    usage?: { input_tokens?: number; output_tokens?: number };
  } | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  const toolRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const toolStartTimes = useRef<Map<string, number>>(new Map());
  const abortRef = useRef<AbortController | null>(null);
  const cancelledRef = useRef(false);
  // Synchronous in-flight guard. `busy` is React state and lags behind
  // back-to-back start() calls (e.g. React strict-mode double-invoking a
  // useEffect that auto-starts the run); a state check passes on both
  // calls and we end up with two parallel streams writing to setText,
  // visibly interleaving chunks in the report.
  const inFlightRef = useRef(false);

  const start = useCallback(async () => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    cancelledRef.current = false;
    abortRef.current = new AbortController();
    setBusy(true);
    setPhase("starting");
    setText("");
    textRef.current = "";
    setToolUses([]);
    setError(null);
    setDone(null);
    setCurrentToolName(null);

    // Scroll the run area into view so the user sees the activity start.
    requestAnimationFrame(() => {
      containerRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });

    try {
      const resp = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body !== undefined ? JSON.stringify(body) : "{}",
        signal: abortRef.current.signal,
      });

      if (!resp.ok || !resp.body) {
        const errText = await resp.text().catch(() => `HTTP ${resp.status}`);
        setError(errText);
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
          let data: unknown = ev.data;
          if (ev.event !== "text") {
            try {
              data = JSON.parse(ev.data);
            } catch {
              // keep as string
            }
          }

          switch (ev.event) {
            case "iteration_start":
              // Reset the text buffer at the start of every model turn.
              // Only the FINAL iteration's prose becomes the report —
              // interim narrations between tool calls are suppressed.
              setText("");
              textRef.current = "";
              setPhase("thinking");
              break;
            case "text":
              setText((prev) => prev + ev.data);
              textRef.current += ev.data;
              setPhase((p) => (p === "running-tool" ? "thinking" : "thinking"));
              setCurrentToolName(null);
              break;
            case "tool_use": {
              const d = data as ToolUse;
              toolStartTimes.current.set(d.id, Date.now());
              setToolUses((prev) => [
                ...prev,
                { id: d.id, name: d.name, input: d.input },
              ]);
              setCurrentToolName(d.name);
              setPhase("running-tool");
              break;
            }
            case "tool_result": {
              const d = data as {
                tool_use_id: string;
                content: string;
                is_error: boolean;
                duration_ms?: number;
              };
              const startedAt = toolStartTimes.current.get(d.tool_use_id);
              const fallback =
                startedAt !== undefined ? Date.now() - startedAt : undefined;
              const durationMs = d.duration_ms ?? fallback;
              toolStartTimes.current.delete(d.tool_use_id);
              setToolUses((prev) =>
                prev.map((tu) =>
                  tu.id === d.tool_use_id
                    ? {
                        ...tu,
                        result: {
                          content: d.content,
                          isError: d.is_error,
                          durationMs,
                        },
                      }
                    : tu,
                ),
              );
              setCurrentToolName(null);
              break;
            }
            case "done": {
              const d = data as {
                iterations: number;
                usage?: { input_tokens?: number; output_tokens?: number };
              };
              setDone(d);
              setPhase("done");
              if (textRef.current.trim()) onReport?.(textRef.current);
              break;
            }
            case "cancelled": {
              const d = data as {
                iterations: number;
                usage?: { input_tokens?: number; output_tokens?: number };
              };
              setDone({ iterations: d.iterations, usage: d.usage });
              setPhase("cancelled");
              setCurrentToolName(null);
              break;
            }
            case "error": {
              const d = data as { message: string };
              setError(d.message);
              setPhase("error");
              break;
            }
          }
        }
      }
    } catch (err) {
      // User-initiated cancel surfaces as a fetch AbortError. Don't render
      // it as an error — `cancelled` SSE event already set the phase, or
      // the server never had a chance to emit one (e.g. cancel landed
      // during the connect phase).
      if (
        cancelledRef.current ||
        (err instanceof DOMException && err.name === "AbortError")
      ) {
        if (phase !== "cancelled") setPhase("cancelled");
      } else {
        setError(err instanceof Error ? err.message : String(err));
        setPhase("error");
      }
    } finally {
      inFlightRef.current = false;
      abortRef.current = null;
      setBusy(false);
      onFinish?.();
    }
  }, [endpoint, body, onFinish, onReport, phase]);

  const stop = useCallback(() => {
    if (!inFlightRef.current) return;
    cancelledRef.current = true;
    abortRef.current?.abort();
  }, []);

  useImperativeHandle(ref, () => ({ start, stop }), [start, stop]);

  useEffect(() => {
    if (autoStart) start();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStart]);

  const empty = !busy && !text && toolUses.length === 0 && !error && !done;

  // After the run completes, collapse the tool list into a single accordion
  // so the report stays close to the activity banner and doesn't run down
  // the page. Auto-collapses on `done`; user can re-expand. Citations
  // re-expand it programmatically.
  const [toolsCollapsed, setToolsCollapsed] = useState(false);
  useEffect(() => {
    if (done) setToolsCollapsed(true);
  }, [done]);

  // Numbered citation links: parse [N] tokens in assistant text and click→
  // scroll/highlight the corresponding tool call.
  const onCitationClick = useCallback((index: number) => {
    const tu = toolUses[index - 1];
    if (!tu) return;
    setToolsCollapsed(false);
    setHighlightedToolId(tu.id);
    // Defer one frame so the list is rendered before we scroll into it.
    requestAnimationFrame(() => {
      const el = toolRefs.current.get(tu.id);
      el?.scrollIntoView({ behavior: "smooth", block: "center" });
    });
    setTimeout(() => setHighlightedToolId((id) => (id === tu.id ? null : id)), 1600);
  }, [toolUses]);

  return (
    <div ref={containerRef} className="space-y-4">
      {empty && emptyHint ? <div>{emptyHint}</div> : null}

      {(busy || phase === "error" || phase === "cancelled") && (
        <ActivityBanner
          phase={phase}
          currentToolName={currentToolName}
          onStop={busy ? stop : undefined}
        />
      )}

      {(busy || toolUses.length > 0) && (
        <div className="space-y-2">
          {toolsCollapsed && toolUses.length > 0 ? (
            <button
              type="button"
              onClick={() => setToolsCollapsed(false)}
              className="flex w-full items-center justify-between gap-2 border border-neutral-800 bg-neutral-950 px-3.5 py-2.5 text-left font-mono text-[15px] text-neutral-400 transition-colors hover:border-neutral-700 hover:bg-neutral-900 hover:text-neutral-200"
            >
              <span className="flex items-center gap-2">
                <span className="text-neutral-500">▶</span>
                <span className="font-semibold text-neutral-300">
                  {toolUses.length} tool call{toolUses.length === 1 ? "" : "s"}
                </span>
                <span className="hidden text-xs text-neutral-500 sm:inline">
                  ({toolUses.map((t) => t.name).join(" · ")})
                </span>
              </span>
              <span className="text-xs uppercase tracking-wider text-neutral-500">
                show
              </span>
            </button>
          ) : (
            <>
              {toolUses.length > 1 && !busy && (
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => setToolsCollapsed(true)}
                    className="text-xs uppercase tracking-wider text-neutral-500 hover:text-neutral-300"
                  >
                    hide tool calls
                  </button>
                </div>
              )}
              {toolUses.map((tu, i) => (
                <ToolCallBlock
                  key={tu.id}
                  tool={tu}
                  index={i + 1}
                  highlighted={highlightedToolId === tu.id}
                  registerRef={(el) => {
                    if (el) toolRefs.current.set(tu.id, el);
                    else toolRefs.current.delete(tu.id);
                  }}
                />
              ))}
            </>
          )}
        </div>
      )}

      {text && (
        <div
          data-print-target
          className="border border-neutral-800 bg-neutral-950 px-5 py-5 sm:px-7 sm:py-6"
        >
          {/* Print-only masthead. Hidden on screen; appears at the top of the
              printed/PDF artifact so a stakeholder seeing this in their inbox
              knows it came from Eyas and the data is sourced from
              CrowdStrike Falcon. The "Unofficial" line keeps the relationship
              honest. */}
          <div className="print-masthead hidden print:flex print:items-center print:justify-between print:border-b print:border-black/20 print:pb-3 print:mb-5">
            <div className="flex flex-col text-left">
              <span className="text-[14px] font-extrabold uppercase tracking-[0.18em] text-neutral-900">
                Eyas
              </span>
              <span className="text-[9px] uppercase tracking-[0.20em] text-neutral-500">
                Agentic console for CrowdStrike Falcon
              </span>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right text-[9px] uppercase tracking-[0.18em] text-neutral-600">
                <div>Data sourced from CrowdStrike Falcon</div>
                <div>Not an official CrowdStrike product</div>
              </div>
            </div>
          </div>

          <div className="markdown">
            <SectionedMarkdown
              text={text}
              linkEntities
              pComponent={({ children }) => renderCitations(children, onCitationClick)}
              liComponent={({ children }) => renderCitations(children, onCitationClick)}
              tdComponent={({ children }) => renderCitations(children, onCitationClick)}
            />
          </div>
        </div>
      )}

      {error && (
        <div className="flex items-start gap-3 rounded-md border border-red-900/70 bg-red-950/30 px-4 py-3.5 text-base text-red-200 shadow-sm shadow-red-950/40">
          <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-oxblood-400" strokeWidth={2} />
          <div className="min-w-0 flex-1">
            <div className="font-semibold text-red-100">Something went wrong</div>
            <div className="mt-1 break-words font-mono text-sm text-red-200/90">{error}</div>
          </div>
        </div>
      )}

      {done && text && (
        <div className="flex flex-wrap items-center gap-2">
          <PrintReportButton />
          <WebhookSendButton
            markdown={text}
            title={webhookTitle}
            source={webhookSource}
          />
        </div>
      )}

      {done && (
        <div className="flex flex-wrap items-center gap-2 text-sm text-neutral-400">
          <span className="inline-flex items-center gap-1.5 border border-neutral-800 bg-neutral-950 px-2.5 py-1 font-mono text-[12px] uppercase tracking-[0.12em]">
            <span className="font-semibold tabular-nums text-oxblood-300">{done.iterations}</span>
            <span className="text-neutral-500">
              iter{done.iterations === 1 ? "" : "s"}
            </span>
          </span>
          <span className="inline-flex items-center gap-1.5 border border-neutral-800 bg-neutral-950 px-2.5 py-1 font-mono text-[12px] uppercase tracking-[0.12em]">
            <span className="font-semibold tabular-nums text-oxblood-300">{toolUses.length}</span>
            <span className="text-neutral-500">
              tool{toolUses.length === 1 ? "" : "s"}
            </span>
          </span>
          {done.usage && (
            <span className="font-mono text-[12px] uppercase tracking-[0.12em] tabular-nums text-neutral-400">
              {done.usage.input_tokens?.toLocaleString()} in ·{" "}
              {done.usage.output_tokens?.toLocaleString()} out
            </span>
          )}
        </div>
      )}
    </div>
  );
});

export default AgentRun;

function ActivityBanner({
  phase,
  currentToolName,
  onStop,
}: {
  phase: "idle" | "starting" | "running-tool" | "thinking" | "done" | "cancelled" | "error";
  currentToolName: string | null;
  onStop?: () => void;
}) {
  const label =
    phase === "starting"
      ? "Connecting to Falcon…"
      : phase === "running-tool"
        ? `Running tool: ${currentToolName ?? "…"}`
        : phase === "thinking"
          ? "Streaming response…"
          : phase === "error"
            ? "Run failed"
            : phase === "cancelled"
              ? "Stopped"
              : phase === "done"
                ? "Done"
                : "Working…";

  const idle = phase === "error" || phase === "done" || phase === "cancelled";

  return (
    <div className="relative overflow-hidden border border-neutral-800 bg-gradient-to-br from-neutral-950 via-neutral-950 to-brand-950/20">
      <div className="flex items-center justify-between gap-3 px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2.5">
          {phase === "error" ? (
            <span className="inline-block h-2 w-2 rounded-full bg-red-500" />
          ) : phase === "cancelled" ? (
            <span className="inline-block h-2 w-2 rounded-full bg-amber-500" />
          ) : (
            <span className="live-dot" />
          )}
          <span className="font-mono text-[12px] uppercase tracking-[0.16em] text-neutral-400">
            agent //
          </span>
          <span className="truncate text-[15px] font-medium text-neutral-100">
            {phase === "running-tool" && currentToolName ? (
              <>
                Running tool:{" "}
                <span className="font-mono text-oxblood-300">{currentToolName}</span>
              </>
            ) : (
              label
            )}
          </span>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {onStop && (
            <button
              type="button"
              onClick={onStop}
              title="Stop this run"
              className="inline-flex items-center gap-1.5 rounded-md border border-neutral-700 bg-neutral-900 px-2.5 py-1 font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-neutral-200 transition-colors hover:border-amber-700 hover:bg-amber-950/40 hover:text-amber-200"
            >
              <Square className="h-3 w-3" strokeWidth={2.5} fill="currentColor" />
              Stop
            </button>
          )}
          {!idle && (
            <Loader2 className="spin-slow h-3.5 w-3.5 shrink-0 text-oxblood-400" strokeWidth={2.5} />
          )}
        </div>
      </div>
      {!idle && <div className="activity-bar" />}
    </div>
  );
}

/** Walk a React children tree and replace `[N]` substrings inside text
 *  nodes with clickable citation badges. */
function renderCitations(
  children: React.ReactNode,
  onClick: (n: number) => void,
): React.ReactNode {
  if (typeof children === "string") {
    const parts: React.ReactNode[] = [];
    const re = /\[(\d{1,3})\]/g;
    let last = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(children)) !== null) {
      if (m.index > last) parts.push(children.slice(last, m.index));
      const n = parseInt(m[1], 10);
      parts.push(
        <button
          key={`${m.index}-${n}`}
          type="button"
          onClick={() => onClick(n)}
          className="citation"
          aria-label={`Source ${n}`}
        >
          {n}
        </button>,
      );
      last = m.index + m[0].length;
    }
    if (last < children.length) parts.push(children.slice(last));
    return parts.length === 1 && typeof parts[0] === "string" ? parts[0] : parts;
  }
  if (Array.isArray(children)) {
    return children.map((c, i) => (
      <span key={i}>{renderCitations(c, onClick)}</span>
    ));
  }
  return children;
}

function ToolCallBlock({
  tool,
  index,
  highlighted,
  registerRef,
}: {
  tool: ToolUse;
  index: number;
  highlighted: boolean;
  registerRef: (el: HTMLDivElement | null) => void;
}) {
  const [open, setOpen] = useState(false);
  const status = !tool.result ? "running" : tool.result.isError ? "error" : "ok";
  const tone =
    status === "running"
      ? "border-sky-900 bg-sky-950/40 text-sky-300"
      : status === "error"
        ? "border-red-900 bg-red-950/40 text-oxblood-300"
        : "border-neutral-800 bg-neutral-950 text-neutral-400";
  const ringClass = highlighted
    ? "ring-2 ring-brand-500 ring-offset-2 ring-offset-black"
    : "";

  return (
    <div
      ref={registerRef}
      className={`border ${tone} font-mono text-[15px] transition-shadow ${ringClass}`}
    >
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-2 px-3.5 py-2.5 text-left"
      >
        <span className="flex min-w-0 items-center gap-2 truncate">
          <span className="inline-flex h-5 min-w-[1.25rem] items-center justify-center bg-neutral-900 px-1.5 text-xs font-bold text-oxblood-300">
            {index}
          </span>
          <span className="text-neutral-500">{open ? "▼" : "▶"}</span>
          <span className="font-semibold">{tool.name}</span>
          {Object.keys(tool.input).length > 0 && (
            <span className="ml-1 text-neutral-500">
              ({Object.keys(tool.input).join(", ")})
            </span>
          )}
        </span>
        <span className="flex shrink-0 items-center gap-2 text-xs font-semibold uppercase tracking-wider">
          {tool.result?.durationMs !== undefined && (
            <span className="font-mono text-[12px] font-medium normal-case tracking-normal text-neutral-500">
              {tool.result.durationMs < 1000
                ? `${tool.result.durationMs} ms`
                : `${(tool.result.durationMs / 1000).toFixed(2)} s`}
            </span>
          )}
          <span>
            {status === "running" ? "running…" : status === "error" ? "error" : "ok"}
          </span>
        </span>
      </button>
      {open && (
        <div className="space-y-2.5 border-t border-current/20 px-3.5 py-3">
          <div>
            <div className="mb-1 text-xs font-semibold uppercase tracking-wider opacity-70">
              input
            </div>
            <pre className="overflow-x-auto whitespace-pre-wrap break-words text-[13px] text-neutral-200">
              {JSON.stringify(tool.input, null, 2)}
            </pre>
          </div>
          {tool.result && (
            <div>
              <div className="mb-1 text-xs font-semibold uppercase tracking-wider opacity-70">
                {tool.result.isError ? "error" : "result"}
              </div>
              <pre className="max-h-96 overflow-y-auto whitespace-pre-wrap break-words text-[13px] text-neutral-200">
                {tool.result.content}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
