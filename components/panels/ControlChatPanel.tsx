"use client";

// Compact interactive agent chat for the control-center panel. A SEPARATE, small
// consumer of the same APIs the full chat uses (POST /api/chat SSE + POST
// /api/chat/approve) — deliberately NOT a refactor of the 1,818-line Chat.tsx, so
// the main surface carries no regression risk. Uses its OWN isolated sessionId so
// its turns and write-approvals never cross with the chat at `/`.

import { useEffect, useRef, useState } from "react";
import { Loader2, Square, CornerDownLeft, Wrench, ShieldQuestion } from "lucide-react";
import SectionedMarkdown from "../SectionedMarkdown";
import { PrintReportButton } from "../AgentArtifactActions";

const SESSION_KEY = "eyas.control-chat.sessionId";

function makeId(): string {
  try {
    if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  } catch {
    /* fall through */
  }
  return `cc-${Math.abs(Date.now() ^ (performance?.now?.() ?? 0)).toString(36)}`;
}

function loadSessionId(): string {
  try {
    const existing = window.localStorage.getItem(SESSION_KEY);
    if (existing) return existing;
    const id = makeId();
    window.localStorage.setItem(SESSION_KEY, id);
    return id;
  } catch {
    return makeId();
  }
}

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

type ToolView = {
  id: string;
  name: string;
  status: "running" | "ok" | "error" | "pending";
};
type Msg = { id: string; role: "user" | "assistant"; text: string; tools: ToolView[] };

export function ControlChatPanel({
  initialPrompt,
  seedContext,
  ephemeral,
  embedded,
}: {
  initialPrompt?: string;
  /** Report/text silently prefixed to the FIRST message so the agent can answer
   *  about it. The user bubble shows only what they typed. */
  seedContext?: string;
  /** Use a fresh in-memory session (don't touch the persistent control-chat
   *  session) — so a per-report follow-up is its own thread. */
  ephemeral?: boolean;
  /** Embedded under a report (own bounded scroll, non-sticky composer) rather
   *  than owning a full-height panel with a sticky composer. */
  embedded?: boolean;
}) {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const sessionRef = useRef<string>("");
  const abortRef = useRef<AbortController | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const seededRef = useRef(false);
  const seedConsumedRef = useRef(false);

  useEffect(() => {
    sessionRef.current = ephemeral ? makeId() : loadSessionId();
  }, [ephemeral]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  // Mutate the last assistant message in place.
  const patchAssistant = (fn: (m: Msg) => Msg) => {
    setMessages((prev) => {
      const next = [...prev];
      for (let i = next.length - 1; i >= 0; i--) {
        if (next[i].role === "assistant") {
          next[i] = fn(next[i]);
          break;
        }
      }
      return next;
    });
  };

  const send = async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || busy) return;
    setError(null);
    setInput("");
    setBusy(true);
    setMessages((prev) => [
      ...prev,
      { id: makeId(), role: "user", text: trimmed, tools: [] },
      { id: makeId(), role: "assistant", text: "", tools: [] },
    ]);

    abortRef.current = new AbortController();
    // First turn only: prefix the seeded report so the agent has context. The
    // user bubble (above) still shows just `trimmed`.
    let payloadInput = trimmed;
    if (seedContext && !seedConsumedRef.current) {
      seedConsumedRef.current = true;
      payloadInput = `Context — a report I just generated in this console:\n\n${seedContext}\n\n---\n\nMy question about it: ${trimmed}`;
    }
    try {
      const resp = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId: sessionRef.current, input: payloadInput }),
        signal: abortRef.current.signal,
      });
      if (!resp.ok || !resp.body) {
        setError(await resp.text().catch(() => `HTTP ${resp.status}`));
        return;
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const { events, rest } = parseSSE(buf);
        buf = rest;
        for (const ev of events) {
          if (ev.event === "text") {
            patchAssistant((m) => ({ ...m, text: m.text + ev.data }));
            continue;
          }
          let d: Record<string, unknown> = {};
          try {
            d = JSON.parse(ev.data);
          } catch {
            /* non-JSON */
          }
          switch (ev.event) {
            case "iteration_start":
              patchAssistant((m) => ({ ...m, text: "" }));
              break;
            case "tool_use":
              patchAssistant((m) => ({
                ...m,
                tools: [...m.tools, { id: String(d.id), name: String(d.name), status: "running" }],
              }));
              break;
            case "tool_pending_approval":
              patchAssistant((m) => ({
                ...m,
                tools: m.tools.some((t) => t.id === d.id)
                  ? m.tools.map((t) => (t.id === d.id ? { ...t, status: "pending" } : t))
                  : [...m.tools, { id: String(d.id), name: String(d.name), status: "pending" }],
              }));
              break;
            case "tool_result":
              patchAssistant((m) => ({
                ...m,
                tools: m.tools.map((t) =>
                  t.id === d.tool_use_id ? { ...t, status: d.is_error ? "error" : "ok" } : t,
                ),
              }));
              break;
            case "tool_approval_resolved":
              patchAssistant((m) => ({
                ...m,
                tools: m.tools.map((t) =>
                  t.id === d.id ? { ...t, status: d.decision === "allow" ? "running" : "error" } : t,
                ),
              }));
              break;
            case "error":
              setError(String(d.message ?? "Something went wrong."));
              break;
            case "aidr_block":
              setError(String(d.display_message ?? "Blocked by content policy."));
              break;
          }
        }
      }
    } catch (err) {
      if (!(err instanceof DOMException && err.name === "AbortError")) {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setBusy(false);
      abortRef.current = null;
    }
  };

  const approve = async (toolUseId: string, decision: "allow" | "deny") => {
    // Optimistic: clear the pending state; the stream also emits resolved.
    patchAssistant((m) => ({
      ...m,
      tools: m.tools.map((t) =>
        t.id === toolUseId ? { ...t, status: decision === "allow" ? "running" : "error" } : t,
      ),
    }));
    try {
      await fetch("/api/chat/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ toolUseId, decision, sessionId: sessionRef.current }),
      });
    } catch {
      /* the stream will time the approval out if this failed */
    }
  };

  const stop = () => abortRef.current?.abort();

  // Seed an initial prompt once (from a widget/hero hand-off).
  useEffect(() => {
    if (initialPrompt && !seededRef.current) {
      seededRef.current = true;
      // sessionRef is set in the mount effect above; defer a tick.
      setTimeout(() => void send(initialPrompt), 0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialPrompt]);

  const pending = messages.flatMap((m) => m.tools.filter((t) => t.status === "pending"));

  return (
    <div className={embedded ? "flex flex-col" : "flex min-h-full flex-col"}>
      {/* Print / PDF toolbar — outside the print target so it's hidden in print.
          Dock only (embedded follow-ups don't need it). */}
      {!embedded && messages.length > 0 ? (
        <div className="mb-2 flex shrink-0 justify-end">
          <PrintReportButton />
        </div>
      ) : null}
      <div
        ref={scrollRef}
        data-print-target
        className={embedded ? "max-h-[22rem] space-y-3 overflow-y-auto pr-1" : "flex-1 space-y-3"}
      >
        {messages.length === 0 ? (
          <p className="text-sm text-neutral-500">
            {seedContext
              ? "Ask a follow-up about the results above — the agent has them in context, plus full Falcon tool access. Any write still waits for your approval right here."
              : "Ask anything — the agent has full Falcon tool access. Any write still waits for your approval right here."}
          </p>
        ) : (
          messages.map((m) =>
            m.role === "user" ? (
              <div key={m.id} className="flex justify-end">
                <div className="chat-print-user max-w-[85%] rounded-lg rounded-br-sm bg-brand-900/40 px-3 py-2 text-sm text-neutral-100">
                  {m.text}
                </div>
              </div>
            ) : (
              <div key={m.id} className="space-y-2">
                {m.tools.length > 0 ? (
                  <div className="chat-print-tool space-y-1">
                    {m.tools.map((t) => (
                      <ToolLine key={t.id} tool={t} onApprove={approve} />
                    ))}
                  </div>
                ) : null}
                {m.text ? (
                  <div className="markdown text-sm">
                    <SectionedMarkdown text={m.text} />
                  </div>
                ) : null}
              </div>
            ),
          )
        )}
        {error ? (
          <div className="rounded-md border border-red-900/70 bg-red-950/30 px-3 py-2 text-sm text-red-200">
            {error}
          </div>
        ) : null}
      </div>

      {/* Composer. Sticky to the panel's scroll container by default; embedded
          (under a report) it's a plain static block. */}
      <div
        className={
          embedded
            ? "mt-3 border-t border-neutral-800/80 pt-3"
            : "sticky bottom-0 -mx-5 mt-3 border-t border-neutral-800/80 bg-neutral-950 px-5 pt-3"
        }
      >
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void send(input);
            }
          }}
          rows={2}
          placeholder="Ask the agent…"
          className="w-full resize-none rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm text-neutral-100 placeholder:text-neutral-600 focus:border-brand-700 focus:outline-none"
        />
        <div className="mt-2 flex items-center justify-between">
          <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-600">
            {pending.length > 0 ? `${pending.length} awaiting approval` : "Enter to send"}
          </span>
          <div className="flex items-center gap-2">
            {busy ? (
              <button
                type="button"
                onClick={stop}
                className="inline-flex items-center gap-1.5 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-neutral-200 transition hover:border-amber-700 hover:text-amber-200"
              >
                <Square className="h-3 w-3" strokeWidth={2.5} fill="currentColor" />
                Stop
              </button>
            ) : (
              <button
                type="button"
                onClick={() => void send(input)}
                disabled={!input.trim()}
                className="inline-flex items-center gap-1.5 rounded-md border border-brand-600 bg-brand-600 px-3.5 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-white transition hover:bg-brand-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                Send
                <CornerDownLeft className="h-3.5 w-3.5" strokeWidth={2} />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ToolLine({
  tool,
  onApprove,
}: {
  tool: ToolView;
  onApprove: (id: string, decision: "allow" | "deny") => void;
}) {
  if (tool.status === "pending") {
    return (
      <div className="rounded-md border border-amber-900/70 bg-amber-950/30 px-3 py-2">
        <div className="flex items-center gap-2 text-[13px] text-amber-200">
          <ShieldQuestion className="h-3.5 w-3.5 shrink-0" strokeWidth={2} />
          <span className="font-mono">{tool.name}</span>
          <span className="text-amber-300/80">needs approval</span>
        </div>
        <div className="mt-2 flex items-center gap-2">
          <button
            type="button"
            onClick={() => onApprove(tool.id, "allow")}
            className="rounded-md border border-emerald-700 bg-emerald-900/40 px-3 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-emerald-200 transition hover:bg-emerald-800/50"
          >
            Allow
          </button>
          <button
            type="button"
            onClick={() => onApprove(tool.id, "deny")}
            className="rounded-md border border-neutral-700 bg-neutral-900 px-3 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-oxblood-700 hover:text-oxblood-200"
          >
            Deny
          </button>
        </div>
      </div>
    );
  }
  const tone =
    tool.status === "error"
      ? "text-oxblood-300"
      : tool.status === "running"
        ? "text-sky-300"
        : "text-neutral-500";
  return (
    <div className="flex items-center gap-2 font-mono text-[12px] text-neutral-500">
      {tool.status === "running" ? (
        <Loader2 className={`h-3 w-3 animate-spin ${tone}`} strokeWidth={2} />
      ) : (
        <Wrench className={`h-3 w-3 ${tone}`} strokeWidth={2} />
      )}
      <span className={tone}>{tool.name}</span>
      <span className="text-neutral-600">
        {tool.status === "running" ? "running…" : tool.status === "error" ? "error" : "ok"}
      </span>
    </div>
  );
}
