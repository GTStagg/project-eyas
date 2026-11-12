"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Download, PanelLeft, Plus, Send as SendIcon, ShieldAlert, ShieldCheck, Square } from "lucide-react";
import AppShell from "./AppShell";
import SectionedMarkdown from "./SectionedMarkdown";
import { PrintReportButton, WebhookSendButton } from "./AgentArtifactActions";
import { PRIMER_STASH_SENTINEL, readStashedPrimer } from "./primerHandoff";
import { describePrimer } from "./primer";
import type { PrimerAction } from "./primer";
import PendingActionCard from "./PendingActionCard";
import ConversationList from "./ConversationList";
import SessionTtlPill from "./SessionTtlPill";
import { SHOW_CROWDSTRIKE_LOCKUP } from "./attribution";

type ToolUse = {
  id: string;
  name: string;
  input: Record<string, unknown>;
  pendingApproval?: boolean;
  decision?: "allow" | "deny" | "timeout";
  result?: { content: string; isError: boolean; durationMs?: number; summary?: string };
  /** Server-computed ground truth attached to a write approval (S4). Independent
   *  of anything the agent reported in `input` — rendered as a distinct
   *  "Verified by Eyas" block on the approval card so the operator approves on
   *  facts the model can't fabricate (containment provenance, host role). */
  verified?: Record<string, unknown>;
};

type AidrBlock = {
  phase: "input" | "output";
  display_message: string;
  policy: string | null;
  detectors: string[];
};

type AssistantTurn = {
  role: "assistant";
  text: string;
  toolUses: ToolUse[];
  done?: { iterations: number; usage?: Record<string, number>; turn_count?: number };
  error?: string;
  /** Set when the user clicked Stop or the connection was otherwise aborted.
   *  Surfaces as an amber "Stopped" badge on the assistant bubble. */
  cancelled?: boolean;
  /** True after a tool call closes a text segment; the next text delta
   *  inserts a paragraph break before appending. Cleared once consumed. */
  awaitingTextBreak?: boolean;
  /** Populated when CrowdStrike AIDR blocks the turn. Input blocks fire
   *  before any LLM call; output blocks fire after the assistant finishes
   *  generating but BEFORE the transcript is saved (the blocked content is
   *  dropped, not persisted). The bubble renders as a shield card. */
  aidrBlock?: AidrBlock;
  /** Surface-only warning when the AIDR transport itself failed and the
   *  guardrail couldn't run. Chat proceeds unguarded for the turn. */
  aidrUnavailable?: { phase: "input" | "output"; message: string };
  /** Surface-only warning when an IR audit write (kickoff record or per-turn
   *  append) failed. The IR workflow keeps running (fail-open on the workflow),
   *  but the operator is told this turn may not be captured in the audit record
   *  (fail-visible on the audit). Mirrors aidrUnavailable. */
  irAuditUnavailable?: { phase: string; message: string };
};

type UserTurn = {
  role: "user";
  text: string;
};

type Turn = UserTurn | AssistantTurn;

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

const SESSION_STORAGE_KEY = "falcon-mcp-console.sessionId";

function newSessionId(): string {
  // crypto.randomUUID() is secure-context only (HTTPS or localhost).
  // Fall back to a manual UUID v4 from getRandomValues for HTTP-over-LAN dev access.
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  }
  return `s-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function writeStoredSessionId(id: string): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(SESSION_STORAGE_KEY, id);
  } catch {
    // localStorage unavailable (private mode, quota, etc.) — silently skip
  }
}

export default function Chat() {
  // Deferred to a useEffect so SSR doesn't bake in a random UUID that the
  // client would then disagree with on hydration. Empty string until mount;
  // Send button is disabled while empty.
  const [sessionId, setSessionId] = useState<string>("");
  const [turns, setTurns] = useState<Turn[]>([]);
  // Active session's expiresAt drives the header TTL pill. Refreshed when
  // the user resumes a conversation and bumped to TTL_MS-from-now after
  // each send (matches the rolling-TTL contract). 0 = no expiry to show.
  const [activeExpiresAt, setActiveExpiresAt] = useState<number>(0);
  // Bumped after every successful send so ConversationList re-fetches and
  // the active row's turn count + lastTouched move in real time.
  const [sessionListTick, setSessionListTick] = useState(0);
  const [railOpen, setRailOpen] = useState(false);
  const [input, setInput] = useState("");
  // A button hand-off lands here as a confirmation card above the composer.
  // Nothing runs until the operator clicks Start; the precise instruction is
  // preserved in the action for transparency + the actual agent turn.
  const [pending, setPending] = useState<PrimerAction | null>(null);
  const [busy, setBusy] = useState(false);
  const [activity, setActivity] = useState<{
    phase: "starting" | "thinking" | "running-tool";
    toolName?: string;
  } | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const cancelledRef = useRef(false);

  // Auto-grow the chat input as the user types or pastes, up to 240px.
  // Resets to a single-line height when input is cleared.
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 240)}px`;
  }, [input]);

  // Always start a fresh session on mount. Navigating back to /chat from
  // elsewhere in the console should land on a blank chat — prior
  // conversations are still resumable via an explicit click in the rail.
  // localStorage still gets written so the approval-resolve flow (which
  // reads it directly) sees the current id.
  useEffect(() => {
    const id = newSessionId();
    writeStoredSessionId(id);
    setSessionId(id);
  }, []);

  // Turn a ?primer=… hand-off into a confirmation card on first mount, then
  // strip the param so a reload doesn't re-prime. The card shows a plain-English
  // summary of what the action does; the precise agent instruction rides along
  // behind a disclosure. Nothing runs until the operator clicks Start.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const primerParam = params.get("primer");
    if (!primerParam) return;
    const primer = primerParam === PRIMER_STASH_SENTINEL
      ? readStashedPrimer()
      : primerParam;
    params.delete("primer");
    const qs = params.toString();
    const newUrl = window.location.pathname + (qs ? `?${qs}` : "") + window.location.hash;
    window.history.replaceState(null, "", newUrl);
    if (!primer) return;
    setPending(describePrimer(primer));
  }, []);

  useEffect(() => {
    if (turns.length === 0) return;
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [turns]);

  // "New chat" semantics with conversation history: start a fresh session
  // and leave the old one resumable from the rail. Distinct from explicit
  // delete (per-row trash button in ConversationList).
  const reset = useCallback(async () => {
    const fresh = newSessionId();
    writeStoredSessionId(fresh);
    setSessionId(fresh);
    setTurns([]);
    setInput("");
    setActiveExpiresAt(0);
    setSessionListTick((t) => t + 1);
  }, []);

  // Switch the active conversation. Fetches the flattened Turn[] from the
  // server, rewrites localStorage, and re-renders. A no-op if the target
  // is already active.
  const resume = useCallback(
    async (id: string) => {
      if (busy) return;
      if (id === sessionId) return;
      try {
        const r = await fetch(`/api/chat/sessions/${encodeURIComponent(id)}`);
        if (!r.ok) return;
        const j = (await r.json()) as {
          ok: boolean;
          session?: { expiresAt: number };
          turns?: Turn[];
        };
        if (!j.ok || !j.turns) return;
        writeStoredSessionId(id);
        setSessionId(id);
        setTurns(j.turns);
        setActiveExpiresAt(j.session?.expiresAt ?? 0);
        setInput("");
      } catch {
        /* silent — rail row stays clickable for retry */
      }
    },
    [busy, sessionId],
  );

  const exportConversation = useCallback(() => {
    if (turns.length === 0) return;
    const lines: string[] = [
      `# Eyas · conversation export`,
      ``,
      `_Agentic console for CrowdStrike Falcon. Data sourced from CrowdStrike Falcon. Not an official CrowdStrike product._`,
      ``,
      `_Exported ${new Date().toISOString()} · session ${sessionId.slice(0, 8)}_`,
      ``,
    ];
    for (const t of turns) {
      if (t.role === "user") {
        lines.push(`## You`, ``, t.text, ``);
      } else {
        lines.push(`## Assistant`, ``);
        for (const tu of t.toolUses) {
          const status = !tu.result
            ? "no result"
            : tu.result.isError
              ? "ERROR"
              : "ok";
          lines.push(
            `<details><summary><code>${tu.name}</code> · ${status}</summary>`,
            ``,
            "**Input:**",
            "```json",
            JSON.stringify(tu.input, null, 2),
            "```",
          );
          if (tu.result) {
            lines.push(
              `**${tu.result.isError ? "Error" : "Result"}:**`,
              "```",
              tu.result.content.slice(0, 4000) +
                (tu.result.content.length > 4000 ? "\n…[truncated]" : ""),
              "```",
            );
          }
          lines.push(`</details>`, ``);
        }
        if (t.text) lines.push(t.text, ``);
        if (t.error) lines.push(`> Error: ${t.error}`, ``);
      }
    }
    const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `eyas-chat-${sessionId.slice(0, 8)}-${new Date().toISOString().slice(0, 10)}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }, [turns, sessionId]);

  const sendText = useCallback(async (raw: string) => {
    const text = raw.trim();
    if (!text || busy || !sessionId) return;

    setInput("");
    setPending(null);
    setBusy(true);
    setActivity({ phase: "starting" });
    cancelledRef.current = false;
    abortRef.current = new AbortController();
    const toolStartTimes = new Map<string, number>();

    const userTurn: UserTurn = { role: "user", text };
    const assistantTurn: AssistantTurn = { role: "assistant", text: "", toolUses: [] };
    setTurns((prev) => [...prev, userTurn, assistantTurn]);

    const updateAssistant = (mut: (t: AssistantTurn) => void) => {
      setTurns((prev) => {
        const next = [...prev];
        const last = next[next.length - 1];
        if (last && last.role === "assistant") {
          const updated: AssistantTurn = { ...last, toolUses: [...last.toolUses] };
          mut(updated);
          next[next.length - 1] = updated;
        }
        return next;
      });
    };

    try {
      const resp = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId, input: text }),
        signal: abortRef.current.signal,
      });

      if (!resp.ok || !resp.body) {
        const errText = await resp.text().catch(() => `HTTP ${resp.status}`);
        updateAssistant((t) => {
          t.error = errText;
        });
        return;
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const { events, rest } = parseSSE(buffer);
        buffer = rest;
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
            case "ready":
              setActivity({ phase: "thinking" });
              break;
            case "iteration_start":
              setActivity({ phase: "thinking" });
              break;
            case "text": {
              const delta = ev.data;
              setActivity({ phase: "thinking" });
              updateAssistant((t) => {
                // Ensure a paragraph break between text segments that
                // bracket a tool call. Without this, Claude's pre-tool
                // narration ("Okay, now looking at this.") concatenates
                // straight into the post-tool continuation ("Found it.")
                // because deltas are appended raw.
                if (t.awaitingTextBreak && delta.trimStart().length > 0) {
                  if (t.text && !/\n\n$/.test(t.text)) {
                    t.text = t.text.replace(/\s+$/, "") + "\n\n";
                  }
                  t.awaitingTextBreak = false;
                }
                t.text += delta;
              });
              break;
            }
            case "tool_use": {
              const d = data as ToolUse;
              toolStartTimes.set(d.id, Date.now());
              setActivity({ phase: "running-tool", toolName: d.name });
              updateAssistant((t) => {
                t.toolUses.push({ id: d.id, name: d.name, input: d.input });
                // After a tool call, the next text delta should start a
                // fresh paragraph rather than continuing the previous one.
                t.awaitingTextBreak = true;
              });
              break;
            }
            case "tool_result": {
              const d = data as {
                tool_use_id: string;
                content: string;
                is_error: boolean;
                duration_ms?: number;
                summary?: string;
              };
              const startedAt = toolStartTimes.get(d.tool_use_id);
              const fallbackDuration =
                startedAt !== undefined ? Date.now() - startedAt : undefined;
              const durationMs = d.duration_ms ?? fallbackDuration;
              toolStartTimes.delete(d.tool_use_id);
              updateAssistant((t) => {
                const tu = t.toolUses.find((x) => x.id === d.tool_use_id);
                if (tu) {
                  tu.result = {
                    content: d.content,
                    isError: d.is_error,
                    durationMs,
                    summary: d.summary,
                  };
                  tu.pendingApproval = false;
                }
              });
              break;
            }
            case "tool_pending_approval": {
              const d = data as ToolUse;
              setActivity({ phase: "thinking" });
              updateAssistant((t) => {
                const existing = t.toolUses.find((x) => x.id === d.id);
                if (existing) {
                  existing.pendingApproval = true;
                  if (d.verified) existing.verified = d.verified;
                } else
                  t.toolUses.push({
                    id: d.id,
                    name: d.name,
                    input: d.input,
                    pendingApproval: true,
                    verified: d.verified,
                  });
              });
              break;
            }
            case "tool_approval_resolved": {
              const d = data as { id: string; decision: "allow" | "deny" | "timeout" };
              if (d.decision === "allow") {
                // Reset the start time so the duration excludes user think time.
                toolStartTimes.set(d.id, Date.now());
              }
              updateAssistant((t) => {
                const tu = t.toolUses.find((x) => x.id === d.id);
                if (tu) {
                  tu.pendingApproval = false;
                  tu.decision = d.decision;
                }
              });
              break;
            }
            case "done": {
              const d = data as AssistantTurn["done"];
              updateAssistant((t) => {
                t.done = d;
              });
              break;
            }
            case "session_state": {
              const d = data as { expiresAt?: number };
              if (typeof d?.expiresAt === "number") setActiveExpiresAt(d.expiresAt);
              break;
            }
            case "cancelled": {
              const d = data as AssistantTurn["done"];
              updateAssistant((t) => {
                t.done = d;
                t.cancelled = true;
              });
              break;
            }
            case "error": {
              const d = data as { message: string };
              updateAssistant((t) => {
                t.error = d.message;
              });
              break;
            }
            case "aidr_block": {
              const d = data as AidrBlock;
              updateAssistant((t) => {
                t.aidrBlock = d;
                if (d.phase === "output") {
                  // Drop any streamed text — the saved transcript also
                  // omits it. The block bubble replaces the response.
                  t.text = "";
                }
              });
              break;
            }
            case "aidr_unavailable": {
              const d = data as { phase: "input" | "output"; message: string };
              updateAssistant((t) => {
                t.aidrUnavailable = d;
              });
              break;
            }
            case "ir_audit_unavailable": {
              const d = data as { phase: string; message: string };
              updateAssistant((t) => {
                t.irAuditUnavailable = d;
              });
              break;
            }
          }
        }
      }
    } catch (err) {
      // User-initiated cancel surfaces as a fetch AbortError. The server
      // has already emitted the `cancelled` SSE event (or never had a
      // chance to). Either way, don't render it as an assistant error.
      if (
        cancelledRef.current ||
        (err instanceof DOMException && err.name === "AbortError")
      ) {
        updateAssistant((t) => {
          t.cancelled = true;
        });
      } else {
        updateAssistant((t) => {
          t.error = err instanceof Error ? err.message : String(err);
        });
      }
    } finally {
      abortRef.current = null;
      setBusy(false);
      setActivity(null);
      // Server emits `session_state` after each turn with the freshly-rolled
      // expiresAt — see the switch handler. We also bump the rail tick here
      // so the active row floats to top regardless of whether the SSE event
      // landed (abort / network glitch).
      setSessionListTick((t) => t + 1);
    }
  }, [busy, sessionId]);

  const send = useCallback(() => sendText(input), [sendText, input]);

  const stop = useCallback(() => {
    if (!abortRef.current) return;
    cancelledRef.current = true;
    abortRef.current.abort();
  }, []);

  return (
    <AppShell
      title="Chat"
      fullBleed
      right={
        <>
          {activeExpiresAt > 0 && turns.length > 0 && (
            <SessionTtlPill expiresAt={activeExpiresAt} variant="header" />
          )}
          <button
            onClick={exportConversation}
            disabled={turns.length === 0}
            title="Download chat as markdown"
            className="hidden h-9 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950/40 px-3 font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-400 transition-[border-color,background-color,color] duration-150 hover:border-brand-700/60 hover:bg-neutral-900 hover:text-oxblood-200 disabled:cursor-not-allowed disabled:opacity-40 sm:flex"
          >
            <Download className="h-3.5 w-3.5" strokeWidth={2} />
            Export
          </button>
          <button
            onClick={reset}
            disabled={busy || (turns.length === 0 && !sessionId)}
            className="flex h-9 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950/40 px-3 font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-400 transition-[border-color,background-color,color] duration-150 hover:border-brand-700/60 hover:bg-neutral-900 hover:text-oxblood-200 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Plus className="h-3.5 w-3.5" strokeWidth={2} />
            <span className="hidden sm:inline">New chat</span>
          </button>
        </>
      }
    >
      <div className="flex min-h-0 flex-1">
      <ConversationList
        activeSessionId={sessionId}
        onResume={resume}
        onNewChat={reset}
        refreshTick={sessionListTick}
        open={railOpen}
        onClose={() => setRailOpen(false)}
      />
      <div className="flex min-h-0 flex-1 flex-col">

      {/* Gemini-style panel toggle, anchored top-left where the drawer pops
          out from. Hidden behind the overlay while the drawer is open. */}
      <div className="flex items-center px-3 pt-3">
        <button
          type="button"
          onClick={() => setRailOpen(true)}
          title="Show conversations"
          aria-label="Show conversations"
          className="flex h-8 w-8 items-center justify-center rounded-md border border-neutral-800 bg-neutral-950/40 text-neutral-400 transition-[border-color,background-color,color] duration-150 hover:border-brand-700/60 hover:bg-neutral-900 hover:text-oxblood-200"
        >
          <PanelLeft className="h-4 w-4" strokeWidth={2} />
        </button>
      </div>

      <div ref={scrollRef} className="flex-1 overflow-y-auto px-6 pb-6 pt-3">
        <div className="mx-auto max-w-3xl space-y-6">
          <AidrStatusBanner />
          {turns.length === 0 && <EmptyState onPick={(p) => setInput(p)} />}
          {turns.map((turn, i) =>
            turn.role === "user" ? (
              <UserBubble key={i} text={turn.text} />
            ) : (
              <AssistantBubble key={i} turn={turn} />
            ),
          )}
        </div>
      </div>

      {activity && (
        <div className="relative border-t border-neutral-800 bg-gradient-to-b from-neutral-950 to-brand-950/20 px-6 py-2.5">
          <div className="mx-auto flex max-w-3xl items-center gap-2.5 text-sm text-neutral-200">
            <span className="live-dot" />
            <span className="font-mono text-[12px] uppercase tracking-[0.16em] text-neutral-400">
              agent //
            </span>
            <span className="flex-1 font-medium">
              {activity.phase === "starting"
                ? "Connecting to Falcon…"
                : activity.phase === "running-tool"
                  ? <>Running tool: <span className="font-mono text-oxblood-300">{activity.toolName}</span></>
                  : "Eyas is thinking…"}
            </span>
            <button
              type="button"
              onClick={stop}
              title="Stop this run"
              className="inline-flex items-center gap-1.5 rounded-md border border-neutral-700 bg-neutral-900 px-2.5 py-1 font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-neutral-200 transition-colors hover:border-amber-700 hover:bg-amber-950/40 hover:text-amber-200"
            >
              <Square className="h-3 w-3" strokeWidth={2.5} fill="currentColor" />
              Stop
            </button>
          </div>
          <div className="activity-bar absolute inset-x-0 bottom-0" />
        </div>
      )}

      {pending && !busy && (
        <div className="border-t border-neutral-800 bg-neutral-950 px-6 pt-4">
          <PendingActionCard
            action={pending}
            busy={busy}
            onStart={() => sendText(pending.instruction)}
            onCancel={() => setPending(null)}
            onEdit={() => {
              setInput(pending.instruction);
              setPending(null);
              requestAnimationFrame(() => textareaRef.current?.focus());
            }}
          />
        </div>
      )}

      <div className="border-t border-neutral-800 px-6 py-4">
        <div className="mx-auto flex max-w-3xl gap-2">
          <textarea
            ref={textareaRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                send();
              }
            }}
            placeholder="Eyas…"
            className="max-h-[240px] min-h-[48px] flex-1 resize-none overflow-y-auto rounded-md border border-neutral-800 bg-neutral-950 px-3.5 py-2.5 text-base text-neutral-100 shadow-[inset_0_1px_0_rgba(255,255,255,0.02)] placeholder:text-neutral-600 focus:border-brand-700 focus:outline-none focus:ring-1 focus:ring-brand-700/40"
            rows={1}
            disabled={busy}
          />
          <button
            onClick={send}
            disabled={busy || !input.trim() || !sessionId}
            className="flex items-center gap-1.5 rounded-md bg-brand-600 px-5 py-2.5 font-mono text-[12px] font-semibold uppercase tracking-[0.16em] text-white shadow-[0_0_24px_-4px_rgba(220,38,38,0.55),inset_0_1px_0_rgba(255,255,255,0.12)] transition-[background-color,box-shadow] duration-150 hover:bg-brand-500 hover:shadow-[0_0_32px_-4px_rgba(239,68,68,0.7),inset_0_1px_0_rgba(255,255,255,0.18)] disabled:cursor-not-allowed disabled:bg-neutral-900 disabled:text-neutral-600 disabled:shadow-none"
          >
            {busy ? (
              <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-current" />
            ) : (
              <SendIcon className="h-3.5 w-3.5" strokeWidth={2.5} />
            )}
            Send
          </button>
        </div>
      </div>
      </div>
      </div>
    </AppShell>
  );
}

const STARTER_PROMPTS: string[] = [
  "List hosts with an open Critical vulnerability and a detection in the last 7 days.",
  "Summarize this week's detections by tactic and host.",
  "Run the agentic IR workflow on <HOSTNAME>.",
];

function EmptyState({ onPick }: { onPick: (prompt: string) => void }) {
  return (
    <div className="font-mono text-[13px] leading-relaxed text-neutral-400">
      <div className="text-neutral-500">
        <span className="text-oxblood-400">$</span> agent --ready
      </div>
      <p className="mt-3 max-w-2xl text-neutral-300">
        Conversational access to your Falcon tenant. Ask across detections,
        hosts, vulnerabilities, intel, and the rest. Write actions are gated —
        you approve each one before it runs.
      </p>
      <div className="mt-6 space-y-1">
        {STARTER_PROMPTS.map((p) => (
          <button
            key={p}
            type="button"
            onClick={() => onPick(p)}
            className="block w-full text-left text-neutral-500 transition-colors hover:text-oxblood-300"
          >
            <span className="text-neutral-700">›</span> {p}
          </button>
        ))}
      </div>
    </div>
  );
}

// Top-of-chat banner shown when CrowdStrike AIDR is not configured for
// the active environment. Dismissible per browser session — operators who
// have decided to run without AIDR shouldn't be re-nagged on every reload.
// Re-appears if they switch to a differently-configured env later.
function AidrStatusBanner() {
  const [show, setShow] = useState(false);
  const [dismissed, setDismissed] = useState<string | null>(null);

  useEffect(() => {
    try {
      setDismissed(sessionStorage.getItem("falcon-mcp-console.aidrBannerDismissed"));
    } catch {
      /* ignore */
    }
    let cancelled = false;
    (async () => {
      try {
        const r = await fetch("/api/environments", { cache: "no-store" });
        const j = (await r.json()) as {
          ok: boolean;
          active_id: string;
          environments: Array<{ id: string; aidr_token_set: boolean }>;
        };
        if (cancelled) return;
        if (j.ok) {
          const active = j.environments.find((e) => e.id === j.active_id);
          setShow(!!active && !active.aidr_token_set);
        }
      } catch {
        /* ignore — banner is best-effort */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (!show || dismissed === "1") return null;
  return (
    <div className="flex items-start gap-3 rounded-md border border-neutral-800 bg-neutral-950 px-4 py-3 text-sm text-neutral-300">
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-neutral-500" strokeWidth={1.75} />
      <div className="flex-1">
        <span className="text-neutral-200">CrowdStrike AIDR isn&apos;t configured</span>{" "}
        for this environment — chat will run without guardrails on prompt
        injection, sensitive data, and policy violations. Configure it on{" "}
        <a href="/config" className="text-oxblood-300 underline-offset-2 hover:underline">
          /config
        </a>
        .
      </div>
      <button
        type="button"
        onClick={() => {
          try {
            sessionStorage.setItem("falcon-mcp-console.aidrBannerDismissed", "1");
          } catch {
            /* ignore */
          }
          setDismissed("1");
        }}
        className="text-xs text-neutral-500 hover:text-neutral-300"
      >
        Dismiss
      </button>
    </div>
  );
}

// Rendered in place of (or alongside) the assistant text when CrowdStrike
// AIDR blocks the turn. Visually heavier than a regular error — the
// security signal is the point. Detector chips give the operator a hint
// of which category fired without surfacing the full payload.
function AidrBlockBubble({ block }: { block: AidrBlock }) {
  const phaseLabel =
    block.phase === "input" ? "Prompt blocked" : "Response blocked";
  return (
    <div className="rounded-lg border border-oxblood-400/40 bg-oxblood-950/30 px-5 py-4">
      <div className="flex items-start gap-3">
        <ShieldAlert
          className="mt-0.5 h-5 w-5 shrink-0 text-oxblood-300"
          strokeWidth={1.75}
        />
        <div className="flex-1 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-[0.14em] text-oxblood-300">
              {phaseLabel}
            </span>
            <span className="text-[11px] uppercase tracking-wider text-neutral-500">
              CrowdStrike AIDR
            </span>
            {block.policy && (
              <span className="rounded border border-neutral-800 bg-neutral-950 px-2 py-0.5 font-mono text-[11px] text-neutral-400">
                {block.policy}
              </span>
            )}
          </div>
          <p className="text-[15px] leading-relaxed text-neutral-100">
            {block.display_message}
          </p>
          {block.detectors.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-1">
              {block.detectors.map((d) => (
                <span
                  key={d}
                  className="rounded border border-oxblood-400/30 bg-oxblood-950/40 px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider text-oxblood-200"
                >
                  {d.replace(/_/g, " ")}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function UserBubble({ text }: { text: string }) {
  // Recognized button hand-offs render as their plain-English summary with the
  // precise agent instruction tucked behind a disclosure — so the transcript
  // stays readable (and survives resume, since the summary is derived from the
  // instruction). Free-typed messages render verbatim.
  const action = describePrimer(text);
  const [showDetails, setShowDetails] = useState(false);

  if (!action.matched) {
    return (
      <div className="flex justify-end">
        <div className="max-w-[80%] whitespace-pre-wrap rounded-lg border border-brand-900/60 bg-brand-900/30 px-4 py-2.5 text-[15px] leading-relaxed text-white">
          {text}
        </div>
      </div>
    );
  }

  return (
    <div className="flex justify-end">
      <div className="max-w-[80%] rounded-lg border border-brand-900/60 bg-brand-900/30 px-4 py-2.5 text-white">
        <div className="text-[15px] font-medium leading-snug">{action.title}</div>
        <button
          type="button"
          onClick={() => setShowDetails((v) => !v)}
          aria-expanded={showDetails}
          className="mt-1 font-mono text-[10px] uppercase tracking-[0.12em] text-oxblood-300/70 transition hover:text-oxblood-200"
        >
          {showDetails ? "Hide instructions" : "Show instructions"}
        </button>
        {showDetails && (
          <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-md border border-brand-900/50 bg-neutral-950/60 p-2.5 font-mono text-[11px] leading-relaxed text-neutral-300">
            {action.instruction}
          </pre>
        )}
      </div>
    </div>
  );
}

function AssistantBubble({ turn }: { turn: AssistantTurn }) {
  const [highlighted, setHighlighted] = useState<string | null>(null);
  const toolRefs = useRef<Map<string, HTMLDivElement>>(new Map());

  // Auto-collapse the tool list once the turn is done, like AgentRun does on
  // /investigate/etc. Any pending-approval tool keeps the list expanded —
  // the user has to be able to see and act on the gate.
  const hasPendingApproval = turn.toolUses.some((t) => t.pendingApproval);
  const [toolsCollapsed, setToolsCollapsed] = useState(false);
  useEffect(() => {
    if (turn.done && !hasPendingApproval) setToolsCollapsed(true);
  }, [turn.done, hasPendingApproval]);

  // When a tool transitions to pending-approval, scroll the approval card
  // into view. Without this the gate can land off-screen above the viewport
  // when the assistant's prose has already pushed the page down.
  const scrolledPendingIds = useRef<Set<string>>(new Set());
  useEffect(() => {
    const pending = turn.toolUses.find(
      (t) => t.pendingApproval && !scrolledPendingIds.current.has(t.id),
    );
    if (!pending) return;
    scrolledPendingIds.current.add(pending.id);
    setToolsCollapsed(false);
    requestAnimationFrame(() => {
      const el = toolRefs.current.get(pending.id);
      el?.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  }, [turn.toolUses]);

  const onCitationClick = useCallback(
    (n: number) => {
      const tu = turn.toolUses[n - 1];
      if (!tu) return;
      setToolsCollapsed(false);
      setHighlighted(tu.id);
      requestAnimationFrame(() => {
        const el = toolRefs.current.get(tu.id);
        el?.scrollIntoView({ behavior: "smooth", block: "center" });
      });
      setTimeout(
        () => setHighlighted((id) => (id === tu.id ? null : id)),
        1600,
      );
    },
    [turn.toolUses],
  );

  return (
    <div className="space-y-2">
      {turn.toolUses.length > 0 && toolsCollapsed && !hasPendingApproval ? (
        <button
          type="button"
          onClick={() => setToolsCollapsed(false)}
          className="flex w-full items-center justify-between gap-2 border border-neutral-800 bg-neutral-950 px-3.5 py-2.5 text-left font-mono text-[15px] text-neutral-400 transition-colors hover:border-neutral-700 hover:bg-neutral-900 hover:text-neutral-200"
        >
          <span className="flex items-center gap-2">
            <span className="text-neutral-500">▶</span>
            <span className="font-semibold text-neutral-300">
              {turn.toolUses.length} tool call{turn.toolUses.length === 1 ? "" : "s"}
            </span>
            <span className="hidden text-xs text-neutral-500 sm:inline">
              ({turn.toolUses.map((t) => t.name).join(" · ")})
            </span>
          </span>
          <span className="text-xs uppercase tracking-wider text-neutral-500">
            show
          </span>
        </button>
      ) : (
        <>
          {turn.toolUses.length > 1 && turn.done && !hasPendingApproval && (
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
          {turn.toolUses.map((tu, i) => (
            <ToolCall
              key={tu.id}
              tool={tu}
              index={i + 1}
              highlighted={highlighted === tu.id}
              registerRef={(el) => {
                if (el) toolRefs.current.set(tu.id, el);
                else toolRefs.current.delete(tu.id);
              }}
            />
          ))}
        </>
      )}
      {/* Approval-needed prompts render their own buttons inside ToolCall */}
      {turn.text && (
        <div data-print-target className="border border-neutral-800 bg-neutral-950 px-5 py-4">
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
                <div>{SHOW_CROWDSTRIKE_LOCKUP ? "Data sourced from" : "Data sourced from CrowdStrike Falcon"}</div>
                <div>Not an official CrowdStrike product</div>
              </div>
              {SHOW_CROWDSTRIKE_LOCKUP && (
                // eslint-disable-next-line @next/next/no-img-element
                <img src="/crowdstrike-lockup.png" alt="CrowdStrike" className="h-10 w-auto" />
              )}
            </div>
          </div>
          <div className="markdown">
            <SectionedMarkdown
              text={turn.text}
              linkEntities
              pComponent={({ children }) => renderCitations(children, onCitationClick)}
              liComponent={({ children }) => renderCitations(children, onCitationClick)}
              tdComponent={({ children }) => renderCitations(children, onCitationClick)}
            />
          </div>
        </div>
      )}
      {turn.aidrBlock && <AidrBlockBubble block={turn.aidrBlock} />}
      {turn.aidrUnavailable && !turn.aidrBlock && (
        <div className="rounded-lg border border-amber-900/60 bg-amber-950/30 px-4 py-3 text-sm text-amber-200">
          CrowdStrike AIDR didn&apos;t respond for the {turn.aidrUnavailable.phase} scan; this turn ran without it.{" "}
          <span className="text-amber-300/70 font-mono text-xs">({turn.aidrUnavailable.message})</span>
        </div>
      )}
      {turn.irAuditUnavailable && (
        <div className="rounded-lg border border-amber-900/60 bg-amber-950/30 px-4 py-3 text-sm text-amber-200">
          This response went through, but it may not have been saved to the response record for this host. The
          investigation is still running normally.{" "}
          <span className="text-amber-300/70 font-mono text-xs">({turn.irAuditUnavailable.message})</span>
        </div>
      )}
      {turn.error && (
        <div className="rounded-lg border border-red-900 bg-red-950/40 px-4 py-3 text-base text-red-200">
          Error: {turn.error}
        </div>
      )}
      {turn.cancelled && !turn.error && (
        <div className="inline-flex items-center gap-1.5 rounded-md border border-amber-900/60 bg-amber-950/30 px-2.5 py-1 text-xs font-semibold uppercase tracking-wider text-amber-200">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500" />
          Stopped
        </div>
      )}
      {turn.done && turn.text && (
        <div className="flex flex-wrap items-center gap-2">
          <PrintReportButton />
          <WebhookSendButton
            markdown={turn.text}
            title={`Chat — ${new Date().toISOString().slice(0, 10)}`}
            source="chat"
          />
        </div>
      )}
      {turn.done && (
        <div className="flex flex-wrap items-center gap-2 text-sm text-neutral-400">
          <span className="inline-flex items-center gap-1.5 border border-neutral-800 bg-neutral-950 px-2.5 py-1 font-mono text-[12px] uppercase tracking-[0.12em]">
            <span className="font-semibold tabular-nums text-oxblood-300">{turn.done.iterations}</span>
            <span className="text-neutral-500">
              iter{turn.done.iterations === 1 ? "" : "s"}
            </span>
          </span>
          <span className="inline-flex items-center gap-1.5 border border-neutral-800 bg-neutral-950 px-2.5 py-1 font-mono text-[12px] uppercase tracking-[0.12em]">
            <span className="font-semibold tabular-nums text-oxblood-300">{turn.toolUses.length}</span>
            <span className="text-neutral-500">
              tool{turn.toolUses.length === 1 ? "" : "s"}
            </span>
          </span>
          {turn.done.usage && (
            <span className="font-mono text-[12px] uppercase tracking-[0.12em] tabular-nums text-neutral-500">
              {turn.done.usage.input_tokens?.toLocaleString()} in ·{" "}
              {turn.done.usage.output_tokens?.toLocaleString()} out
            </span>
          )}
        </div>
      )}
      {!turn.text && !turn.error && !turn.done && turn.toolUses.length === 0 && (
        <div className="text-base text-neutral-500">…</div>
      )}
    </div>
  );
}

/** Walk a React children tree and replace [N] markers in text nodes with
 *  clickable citation badges that reference numbered tool calls. */
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

function ToolCall({
  tool,
  index,
  highlighted,
  registerRef,
}: {
  tool: ToolUse;
  index?: number;
  highlighted?: boolean;
  registerRef?: (el: HTMLDivElement | null) => void;
}) {
  const status = tool.pendingApproval
    ? "pending"
    : !tool.result
      ? "running"
      : tool.decision === "deny"
        ? "denied"
        : tool.decision === "timeout"
          ? "timeout"
          : tool.result.isError
            ? "error"
            : "ok";

  // Pending-approval prompts auto-expand so the user can read inputs.
  const [open, setOpen] = useState<boolean>(status === "pending");
  useEffect(() => {
    if (status === "pending") setOpen(true);
  }, [status]);

  const tone =
    status === "pending"
      ? "border-amber-700 bg-amber-950/30 text-amber-200"
      : status === "running"
        ? "border-sky-900 bg-sky-950/40 text-sky-300"
        : status === "error" || status === "denied" || status === "timeout"
          ? "border-red-900 bg-red-950/30 text-oxblood-300"
          : "border-neutral-800 bg-neutral-950 text-neutral-400";

  const statusLabel =
    status === "pending"
      ? "approval needed"
      : status === "running"
        ? "running…"
        : status === "denied"
          ? "denied"
          : status === "timeout"
            ? "approval expired"
            : status === "error"
              ? "error"
              : "ok";

  const durationLabel =
    tool.result?.durationMs !== undefined
      ? tool.result.durationMs < 1000
        ? `${tool.result.durationMs} ms`
        : `${(tool.result.durationMs / 1000).toFixed(2)} s`
      : null;

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
          {index !== undefined && (
            <span className="inline-flex h-5 min-w-[1.25rem] items-center justify-center bg-neutral-900 px-1.5 text-xs font-bold text-oxblood-300">
              {index}
            </span>
          )}
          <span className="text-neutral-500">{open ? "▼" : "▶"}</span>
          <span className="font-semibold">{tool.name}</span>
          {Object.keys(tool.input).length > 0 && (
            <span className="ml-1 text-neutral-500">
              ({Object.keys(tool.input).join(", ")})
            </span>
          )}
        </span>
        <span className="flex shrink-0 items-center gap-2 text-xs font-semibold uppercase tracking-wider">
          {durationLabel && (
            <span className="font-mono text-[12px] font-medium normal-case tracking-normal text-neutral-500">
              {durationLabel}
            </span>
          )}
          <span>{statusLabel}</span>
        </span>
      </button>
      {tool.result?.summary && (
        <div className="border-t border-current/15 px-3.5 py-1.5 text-[12px] font-medium normal-case tracking-normal text-neutral-300">
          <span className="mr-2 text-neutral-500">↳</span>
          {tool.result.summary}
        </div>
      )}
      {open && (
        <div className="space-y-2.5 border-t border-current/20 px-3.5 py-3">
          {status === "pending" && <ApprovalSummary tool={tool} />}
          <div>
            <div className="mb-1 text-xs font-semibold uppercase tracking-wider opacity-70">input</div>
            <pre className="overflow-x-auto whitespace-pre-wrap break-words text-[13px] text-neutral-200">
              {JSON.stringify(tool.input, null, 2)}
            </pre>
          </div>
          {status === "pending" && <ApprovalButtons toolUseId={tool.id} />}
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

// Per-cleanup-script narration. Values are { title, what, denied }:
//   title   — short imperative shown as the dialog heading
//   what    — one-sentence "what this actually does on the host"
//   denied  — one-sentence "what happens if you say no"
// Keep these in operator language. No `extras_*` jargon, no PowerShell verbs,
// no file paths to scripts. The cleanup catalog id IS shown to the operator
// in the Script row, but the narration is the load-bearing part.
const CLEANUP_NARRATION: Record<string, { title: string; what: string; denied: string }> = {
  "host-list-wmi-persistence": {
    title: "Enumerate WMI persistence on the host",
    what: "Read-only walk of root\\subscription — lists every WMI event filter, binding, and consumer; flags suspicious entries by heuristic. No host writes, no service changes.",
    denied: "Phase 0 will be missing the WMI category — implants that persist via WMI subscription (the most common way an attacker survives a standard IR run) won't be visible in findings.",
  },
  "host-remove-wmi-persistence": {
    title: "Remove a WMI persistence entry",
    what: "Deletes the named WMI event filter and any consumers/bindings linked to it from root\\subscription. The persistence channel for that implant goes away on next reboot at the latest.",
    denied: "The WMI persistence stays. The implant survives every other cleanup primitive — kill-process, delete-folder, autorun-key removal — because none of them touch root\\subscription.",
  },
  "host-kill-process": {
    title: "Terminate a process by image name",
    what: "Sends SIGTERM-equivalent to every running process matching the image name. Files held open by that process will be releasable for delete/quarantine.",
    denied: "The process keeps running. Subsequent file/folder cleanup may fail with 'in use' if the same binary holds open handles.",
  },
  "host-quarantine-file": {
    title: "Quarantine a file (move + restrict + sidecar)",
    what: "Moves the file into C:\\ProgramData\\FalconCleanup\\quarantine with a restricted ACL and writes a SHA-256 sidecar for forensics. Reversible — bytes are preserved, not destroyed.",
    denied: "The file stays where it is. If it's an installer that's been run, the install artifacts (extracted contents, registered apps) remain regardless of whether this single binary is removed.",
  },
  "host-delete-file": {
    title: "Delete a file (irreversible)",
    what: "Permanently removes the file. No quarantine sidecar — bytes are gone.",
    denied: "The file stays. Quarantine is the safer default; only use delete when forensic preservation isn't needed.",
  },
  "host-delete-folder": {
    title: "Delete a folder tree (with locked-file fallback)",
    what: "Recursively removes the folder. Files held open by running processes are scheduled for delete on next reboot via MoveFileEx. Returns a structured report of deleted vs pending-reboot vs failed paths.",
    denied: "The folder and its contents stay. For installer-extracted toolkits, this is the most common Phase 0 miss — the extracted tree is the bigger blast radius than the original installer.",
  },
  "host-uninstall-anydesk": {
    title: "Uninstall AnyDesk fully",
    what: "Runs the official AnyDesk installer's uninstall switch, then sweeps known portable-binary paths (root-of-drive, ProgramData, Temp, AppData) including any drops outside the standard install root. Service + registry entries removed.",
    denied: "AnyDesk stays installed. Attacker-installed AnyDesk is a common persistent remote-access channel — leaving it gives the attacker continued access after the host is 'released.'",
  },
  "host-remove-ifeo-hijack": {
    title: "Remove an IFEO Debugger hijack",
    what: "Deletes the named image's Image File Execution Options registry key (both 64-bit and Wow6432 hives, plus any SilentProcessExit trigger). Refuses system-critical binaries by default.",
    denied: "The IFEO hijack stays — every time the named image runs, the attacker's Debugger value runs instead. Standard autorun sweeps don't catch IFEO entries; this is the only primitive that does.",
  },
  "host-remove-run-key": {
    title: "Remove an autorun registry value",
    what: "Deletes the named value from Run / RunOnce / Wow6432 / Winlogon roots. The autorun for that implant is gone.",
    denied: "The autorun stays — implant relaunches on next user logon.",
  },
  "host-remove-scheduled-task": {
    title: "Remove a scheduled task",
    what: "Calls schtasks /Delete on the named task. The persistence channel goes away.",
    denied: "The scheduled task stays — implant relaunches on its trigger schedule.",
  },
  "host-stop-service": {
    title: "Stop and disable a Windows service",
    what: "Stops the running service and sets its startup type to Disabled. Reversible via Set-Service.",
    denied: "The service keeps running and restarts on reboot.",
  },
  "host-delete-service": {
    title: "Delete a Windows service",
    what: "Calls sc.exe delete on the service. Service definition is gone after next reboot of the SCM.",
    denied: "The service definition remains — even if stopped, it's still registered and an attacker can re-enable it.",
  },
  "host-disable-local-user": {
    title: "Disable a local user account",
    what: "Sets the named account to Disabled. The account can't log on; existing sessions are NOT terminated by this call (use host-force-logoff for that).",
    denied: "The account stays enabled — if credentials were compromised, the attacker can keep using them.",
  },
  "host-force-logoff": {
    title: "Force-logoff active sessions for a user",
    what: "Logs the named user out of every active session on this host. Use after host-disable-local-user to terminate live sessions.",
    denied: "The user's existing sessions stay active even after the account is disabled.",
  },
  "host-block-outbound-ip": {
    title: "Block outbound traffic to an IP",
    what: "Adds a Windows Firewall outbound-block rule for the IP. Independent of network containment — survives across host group changes.",
    denied: "The C2 channel stays open even after policy quarantine. Containment severs all egress; this primitive blocks just the one IP if you want surgical isolation.",
  },
  "host-set-registry-value": {
    title: "Revert a credential-theft hardening regression",
    what: "Restores the canonical hardened value for the named registry slot (WDigest UseLogonCredential, LSA RunAsPPL, etc.). Slot-driven — no free-form registry writes.",
    denied: "The hardening regression stays. Credential dumping tools that exploit the regression keep working on this host.",
  },
  "host-reboot": {
    title: "Reboot the host",
    what: "Calls Restart-Computer -Force. Required to finalize MoveFileEx pending-delete operations and to apply some hardening reverts.",
    denied: "Pending-reboot file deletions stay on disk until the host reboots for another reason.",
  },
  "host-uninstall-cursor": {
    title: "Uninstall Cursor (unsanctioned AI tool)",
    what: "Runs Cursor's uninstaller, then sweeps install paths and AppData. Use when Shadow-AI policy has flagged Cursor on this host.",
    denied: "Cursor stays installed. The Shadow-AI policy violation persists until manually removed.",
  },
  "host-uninstall-claude-desktop": {
    title: "Uninstall Claude Desktop (unsanctioned AI tool)",
    what: "Runs the Claude Desktop uninstaller, removes the MSIX-registered app, and sweeps Downloads / AppData / WindowsApps for the package contents.",
    denied: "Claude Desktop stays installed and registered. The Shadow-AI policy violation persists until manually removed.",
  },
  "host-uninstall-ollama": {
    title: "Uninstall Ollama (unsanctioned AI tool)",
    what: "Runs Ollama's uninstaller and removes downloaded model weights from the standard model directory.",
    denied: "Ollama stays installed and any locally-cached model weights remain on disk.",
  },
  "host-uninstall-lmstudio": {
    title: "Uninstall LM Studio (unsanctioned AI tool)",
    what: "Runs LM Studio's uninstaller and removes downloaded model weights.",
    denied: "LM Studio stays installed and locally-cached model weights remain on disk.",
  },
  "host-uninstall-comfyui": {
    title: "Uninstall ComfyUI (unsanctioned AI tool)",
    what: "Removes the ComfyUI install directory and any registered Python virtual env.",
    denied: "ComfyUI stays installed.",
  },
};

// Network containment runs on eyas-mcp (`ids`); the retired sidecar names
// (`device_ids`) stay so resumed conversations still render their cards.
// Mirrors CONTAIN_TOOLS / LIFT_TOOLS in lib/chat/ir-ground-truth-pure.ts.
const CONTAIN_TOOL_NAMES: ReadonlySet<string> = new Set(["falcon_contain_hosts", "extras_host_contain"]);
const LIFT_TOOL_NAMES: ReadonlySet<string> = new Set([
  "falcon_lift_host_containment",
  "extras_host_lift_containment",
]);

function containmentTargets(input: Record<string, unknown>): string[] {
  const raw = input.ids ?? input.device_ids;
  return Array.isArray(raw) ? raw.map(String) : [];
}

/** Server-verified ground truth for the contain / lift / group-remove approval
 *  cards (S4/F5). Renders facts the route computed independently of the agent —
 *  containment provenance (did THIS workflow contain the host / add it to the
 *  group?), host role / blast radius, and the release-verification caveat — in a
 *  visually distinct block so the operator approves on evidence the model can't
 *  fabricate. Absent `tool.verified` → renders nothing. */
function VerifiedFacts({ tool }: { tool: ToolUse }) {
  const v = tool.verified;
  if (!v) return null;
  const isLift = LIFT_TOOL_NAMES.has(tool.name);
  const isContain = CONTAIN_TOOL_NAMES.has(tool.name);
  const isRemove = tool.name === "extras_host_group_remove_members";
  if (!isLift && !isContain && !isRemove) return null;

  const lines: { text: string; warn?: boolean; note?: boolean }[] = [];

  if (isLift || isContain) {
    const hostRole = typeof v.hostRole === "string" ? v.hostRole : null;
    const isDC = v.isDomainController === true;
    const agentContained = v.agentContained === true;
    const containedAtStart = v.containedAtStart;

    if (hostRole) {
      lines.push({ text: `Host role: ${hostRole}`, warn: isDC });
    } else if (isContain) {
      // Role capture is best-effort (S1) — a miss must NOT silently drop the
      // Domain-Controller blast-radius warning (fail-open). Fail toward caution:
      // tell the operator the role is unverified so they confirm before containing.
      lines.push({
        text: "Host role could not be verified. If this is a Domain Controller, network containment cuts off sign-ins across the whole environment — confirm before approving.",
        warn: true,
      });
    }
    if (isDC) {
      lines.push({
        text: "This host is a Domain Controller. Network containment cuts off sign-ins across the whole environment until it is released.",
        warn: true,
      });
    }
    if (agentContained) {
      lines.push({ text: "This investigation is what placed this host in containment." });
    } else if (containedAtStart === true) {
      lines.push({
        text: "This host was already contained before this investigation began — not by this workflow.",
        warn: true,
      });
    } else if (containedAtStart === false) {
      lines.push({ text: "This investigation has not placed this host in containment." });
    }
  }

  if (isRemove) {
    if (v.workflowAddedToGroup === true) {
      lines.push({
        text: "This investigation is what placed this host in the group it's being removed from.",
      });
    } else if (v.workflowAddedToGroup === false) {
      lines.push({
        text: "This investigation did not place this host in the group it's being removed from — that membership predates this engagement. Eyas will decline this removal; change it from the Falcon Console if intended.",
        warn: true,
      });
    }
  }

  // Release caveat (lift + group-remove): verification is detection-status-based,
  // Eyas may decline but never auto-releases and never overrides the Console.
  if (typeof v.releaseVerificationNote === "string" && v.releaseVerificationNote) {
    lines.push({ text: v.releaseVerificationNote, note: true });
  }

  if (lines.length === 0) return null;

  return (
    <div className="mt-3 rounded-md border border-teal-700/50 bg-teal-950/30 px-3 py-2.5">
      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-teal-300">
        <ShieldCheck className="h-3.5 w-3.5" />
        Verified by Eyas — independent of the agent
      </div>
      <ul className="mt-1.5 space-y-1 text-[13px] leading-snug">
        {lines.map((l, i) => (
          <li
            key={i}
            className={
              l.warn
                ? "text-red-300"
                : l.note
                  ? "text-[12px] italic text-teal-200/70"
                  : "text-teal-50"
            }
          >
            {l.text}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** A friendly write-action summary above the raw input JSON. Surfaces the
 *  highest-stakes fields (hash + indicator type for IOCs, rule-group name for
 *  firewall, etc.) so the audience reading the demo immediately understands
 *  what is about to mutate the tenant. Falls back to a generic banner. */
function ApprovalSummary({ tool }: { tool: ToolUse }) {
  const input = tool.input;
  const get = (k: string): string | undefined => {
    const v = input[k];
    return typeof v === "string" ? v : v == null ? undefined : String(v);
  };

  let title = "This will modify your Falcon tenant";
  let rows: { label: string; value: string; mono?: boolean }[] = [];
  let whatHappens: string | undefined;
  let ifDenied: string | undefined;

  if (tool.name === "falcon_add_ioc") {
    title = "Add indicator of compromise";
    const hash = get("value") ?? get("indicator") ?? "(missing)";
    const type = get("type") ?? get("indicator_type") ?? "(unspecified)";
    const action = get("action") ?? "(unspecified)";
    rows = [
      { label: "Indicator", value: hash, mono: true },
      { label: "Type", value: type },
      { label: "Action", value: action },
    ];
    if (get("description")) rows.push({ label: "Description", value: get("description")! });
    if (get("platforms")) rows.push({ label: "Platforms", value: get("platforms")! });
  } else if (tool.name === "falcon_remove_iocs") {
    title = "Remove indicators of compromise";
    const ids = get("ids") ?? get("filter") ?? "(unspecified)";
    rows = [{ label: "Targets", value: ids, mono: true }];
  } else if (tool.name === "falcon_create_firewall_rule_group") {
    title = "Create firewall rule group";
    rows = [
      { label: "Name", value: get("name") ?? "(unspecified)" },
      { label: "Enabled", value: get("enabled") ?? "(default)" },
    ];
  } else if (tool.name === "falcon_delete_firewall_rule_groups") {
    title = "Delete firewall rule groups";
    rows = [{ label: "Targets", value: get("ids") ?? "(unspecified)", mono: true }];
  } else if (tool.name.startsWith("falcon_create_ioa") || tool.name.startsWith("falcon_update_ioa")) {
    title = tool.name.includes("update") ? "Update IOA rule / group" : "Create IOA rule / group";
    rows = [{ label: "Name", value: get("name") ?? "(unspecified)" }];
  } else if (tool.name.startsWith("falcon_delete_ioa")) {
    title = "Delete IOA rule / group";
    rows = [{ label: "Targets", value: get("ids") ?? "(unspecified)", mono: true }];
  } else if (tool.name === "extras_rtr_run_patch") {
    const dryRun = String(input.dry_run ?? "true").toLowerCase() === "true";
    title = dryRun ? "Resolve patch plan (dry run)" : "Execute patch via RTR";
    const ids = Array.isArray(input.device_ids) ? (input.device_ids as string[]) : [];
    rows = [
      { label: "Script", value: get("script_id") ?? "(unspecified)", mono: true },
      { label: "Mode", value: dryRun ? "dry-run (no host I/O)" : "EXECUTE on hosts" },
      { label: "Hosts", value: String(ids.length) },
    ];
    if (ids.length > 0) {
      rows.push({ label: "Sample", value: ids.slice(0, 3).join(", "), mono: true });
    }
    if (ids.length > 25) {
      rows.push({
        label: "Batch size",
        value: `LARGE (>${25}) — requires confirm_large_batch=true`,
      });
    }
    const params = input.params;
    if (params && typeof params === "object" && Object.keys(params).length > 0) {
      rows.push({ label: "Params", value: JSON.stringify(params), mono: true });
    }
  } else if (CONTAIN_TOOL_NAMES.has(tool.name)) {
    title = "Network-contain host(s)";
    const ids = containmentTargets(input);
    rows = [{ label: "Hosts", value: String(ids.length) }];
    if (ids.length > 0) rows.push({ label: "Sample", value: ids.slice(0, 3).join(", "), mono: true });
    whatHappens = "Severs all network communication on the host except the Falcon sensor channel. Active C2 / data egress stops immediately.";
    ifDenied = "The host stays connected to the network. Policy-level quarantine still applies its stricter prevention, but active outbound communication continues.";
  } else if (LIFT_TOOL_NAMES.has(tool.name)) {
    title = "Lift containment on host(s)";
    const ids = containmentTargets(input);
    rows = [{ label: "Hosts", value: String(ids.length) }];
    if (ids.length > 0) rows.push({ label: "Sample", value: ids.slice(0, 3).join(", "), mono: true });
    whatHappens = "Restores the host's network connectivity. The sensor channel was always available; this re-opens the rest.";
    ifDenied = "The host stays contained — operator follow-up required to release it manually from the Falcon Console.";
  } else if (tool.name === "falcon_wait_for_rtr_sessions") {
    title = "Wait until cleanup can run on the host";
    const ids = Array.isArray(input.device_ids) ? (input.device_ids as string[]) : [];
    rows = [
      { label: "Hosts", value: String(ids.length) },
      { label: "Up to", value: `${get("timeout_seconds") ?? "180"} seconds` },
    ];
    if (ids.length > 0) rows.push({ label: "Sample", value: ids.slice(0, 3).join(", "), mono: true });
    whatHappens = "Repeatedly runs a harmless test script on the host (it only prints a marker) until one succeeds, so cleanup starts only once the new quarantine policy has reached the sensor. The test script is deleted afterwards.";
    ifDenied = "Cleanup isn't started. Running it before the policy reaches the sensor can fail silently, so the workflow treats this as not ready.";
  } else if (tool.name === "extras_rtr_run_cleanup") {
    const scriptId = get("script_id") ?? "(unspecified)";
    const dryRun = String(input.dry_run ?? "true").toLowerCase() === "true";
    const ids = Array.isArray(input.device_ids) ? (input.device_ids as string[]) : [];
    const narration = CLEANUP_NARRATION[scriptId];
    title = narration?.title
      ? dryRun ? `${narration.title} (dry-run preview)` : narration.title
      : dryRun ? `Cleanup primitive (dry-run preview)` : `Run cleanup primitive on host`;
    rows = [
      { label: "Script", value: scriptId, mono: true },
      { label: "Mode", value: dryRun ? "dry-run (no host changes)" : "EXECUTE on host" },
      { label: "Hosts", value: String(ids.length) },
    ];
    if (ids.length > 0) rows.push({ label: "Sample", value: ids.slice(0, 3).join(", "), mono: true });
    const params = input.params;
    if (params && typeof params === "object" && Object.keys(params).length > 0) {
      rows.push({ label: "Params", value: JSON.stringify(params), mono: true });
    }
    if (narration && !dryRun) {
      whatHappens = narration.what;
      ifDenied = narration.denied;
    } else if (dryRun) {
      whatHappens = "Renders the script with the supplied parameters and validates against the host's catalog — no host I/O fires. The next call (dry_run=False) is what mutates the host.";
      ifDenied = "The cleanup primitive doesn't run, including the preview. Phase 2 will skip this finding.";
    }
  } else if (tool.name === "extras_create_ioa_exclusion") {
    title = "Create IOA exclusion (suppress a behavioral detection)";
    rows = [
      { label: "Pattern", value: get("pattern_id") ?? "(unspecified)" },
      { label: "Name", value: get("name") ?? "(auto)" },
      { label: "Scope", value: get("groups") ?? "(unspecified)", mono: true },
    ];
    whatHappens = "Tells the sensor to stop firing the named IOA pattern on hosts in the listed groups. The exclusion lives until manually removed.";
    ifDenied = "The IOA keeps firing. For the IR-readiness exclusion specifically, every Phase 2 cleanup primitive will be sensor-blocked and the workflow will silently no-op.";
  } else if (tool.name === "extras_create_ml_exclusion") {
    title = "Create ML exclusion (suppress an ML conviction)";
    rows = [
      { label: "Pattern", value: get("value") ?? get("pattern") ?? "(unspecified)", mono: true },
      { label: "Scope", value: get("groups") ?? "(unspecified)" },
    ];
    whatHappens = "Tells the sensor to stop convicting on the named ML pattern in scope. Matched files won't be quarantined or alerted on.";
    ifDenied = "The ML conviction keeps firing — every matching file will be quarantined by the sensor.";
  } else if (tool.name === "extras_host_group_add_members") {
    title = "Move host(s) into a host group";
    const ids = Array.isArray(input.device_ids) ? (input.device_ids as string[]) : [];
    rows = [
      { label: "Group", value: get("group_id") ?? "(unspecified)", mono: true },
      { label: "Hosts", value: String(ids.length) },
    ];
    if (ids.length > 0) rows.push({ label: "Sample", value: ids.slice(0, 3).join(", "), mono: true });
    whatHappens = "Adds the host(s) to the named static group. Whatever prevention policy / response policy / sensor update policy is bound to that group will take effect after sensor propagation (typically 60–90s).";
    ifDenied = "The host stays in its current groups. For an IR Phase 1 quarantine call, denial leaves the host in its original (production) prevention policy.";
  } else if (tool.name === "extras_host_group_remove_members") {
    title = "Remove host(s) from a host group";
    const ids = Array.isArray(input.device_ids) ? (input.device_ids as string[]) : [];
    rows = [
      { label: "Group", value: get("group_id") ?? "(unspecified)", mono: true },
      { label: "Hosts", value: String(ids.length) },
    ];
    if (ids.length > 0) rows.push({ label: "Sample", value: ids.slice(0, 3).join(", "), mono: true });
    whatHappens = "Removes the host(s) from the named group. Policies bound to that group stop applying after sensor propagation.";
    ifDenied = "The host stays in the group. For an IR Phase 4 release, denial leaves the host in quarantine.";
  } else if (tool.name === "extras_ir_close_remediated") {
    const remediated = Array.isArray(input.remediated) ? (input.remediated as unknown[]) : [];
    title = "Close detections matched by the IR ledger";
    rows = [
      { label: "Host", value: get("device_id") ?? "(unspecified)", mono: true },
      { label: "Verdict", value: get("verdict") ?? "true_positive" },
      { label: "Ledger entries", value: String(remediated.length) },
    ];
    whatHappens = "Walks every open detection on the host and closes ONLY those whose evidence intersects an entry in the supplied remediation ledger. Each close carries per-id evidence linking it to the specific ledger entry that justified it.";
    ifDenied = "Detections stay open. The ledger is preserved — operator can review the entries and close manually from the queue.";
  } else if (tool.name === "extras_ir_close_untouched_originals") {
    title = "Close detections the IR workflow didn't remediate";
    rows = [
      { label: "Host", value: get("device_id") ?? "(unspecified)", mono: true },
      { label: "Verdict", value: get("verdict") ?? "(unspecified)" },
      { label: "Open before", value: get("before_iso") ?? "(unspecified)", mono: true },
    ];
    whatHappens = "Closes every detection on this host that is still open and was raised before the engagement began. These are the original detections no remediation touched; they block release until closed. Anything raised during the engagement is left alone.";
    ifDenied = "Those detections stay open and the host stays held in quarantine.";
  } else if (tool.name === "extras_close_all_open_detections_on_host") {
    title = "Bulk-close every open detection on the host";
    rows = [
      { label: "Host", value: get("device_id") ?? "(unspecified)", mono: true },
      { label: "Verdict", value: get("verdict") ?? "(unspecified)" },
    ];
    if (input.include_multi_host === true) {
      rows.push({ label: "Multi-host alerts", value: "also closed — they leave the other hosts' queues too" });
    }
    whatHappens = "Closes every open detection on this host with the supplied verdict — no ledger matching, no per-id audit trail. Out-of-band rescue lane for queue drain.";
    ifDenied = "Detections stay open for individual review.";
  } else if (tool.name === "falcon_update_detections") {
    const ids = Array.isArray(input.ids) ? (input.ids as string[]) : [];
    const addTags = Array.isArray(input.add_tags) ? (input.add_tags as string[]) : [];
    const verdict = addTags.find((t) => t === "true_positive" || t === "false_positive" || t === "ignored");
    title = verdict ? "Record a detection verdict" : "Update detections";
    rows = [{ label: "Detections", value: String(ids.length) }];
    if (get("status")) rows.push({ label: "Status", value: get("status") ?? "" });
    if (verdict) rows.push({ label: "Verdict", value: verdict });
    const otherTags = addTags.filter((t) => t !== verdict);
    if (otherTags.length > 0) rows.push({ label: "Add tags", value: otherTags.join(", ") });
    if (get("append_comment")) rows.push({ label: "Comment", value: get("append_comment") ?? "" });
    const assignee = get("assign_to_name") ?? get("assign_to_user_id") ?? get("assign_to_uuid");
    if (assignee) rows.push({ label: "Assign to", value: assignee });
    if (input.unassign === true) rows.push({ label: "Assignee", value: "removed" });
    whatHappens = "Updates the listed detections in Falcon: status, verdict tag, comment or assignee as shown. Changes are recorded in Falcon's audit log.";
    ifDenied = "The detections stay as they are.";
  } else if (tool.name === "falcon_execute_workflow") {
    title = "Run a Fusion workflow";
    rows = [
      { label: "Workflow", value: get("definition_id") ?? get("name") ?? "(unspecified)", mono: Boolean(get("definition_id")) },
    ];
    const params = input.parameters;
    if (params && typeof params === "object" && Object.keys(params as object).length > 0) {
      rows.push({ label: "Input", value: JSON.stringify(params), mono: true });
    }
    whatHappens = "Starts the workflow once with the input shown. Whatever the workflow does (notifications, host actions, tickets) happens.";
    ifDenied = "The workflow doesn't run.";
  } else if (tool.name === "extras_shadow_ai_adopt_prevention") {
    title = "Adopt the Shadow-AI prevention bundle";
    rows = [
      { label: "Policy", value: get("policy_id") ?? "(unspecified)", mono: true },
    ];
    whatHappens = "Creates (or refreshes) the Shadow-AI Custom IOA rule group + rules and binds it to the named Prevention Policy. Once that policy is attached to a host group, every covered host blocks the catalog of unsanctioned AI tool installers + launches.";
    ifDenied = "Shadow-AI rules don't get adopted on this tenant. Hosts continue to allow Claude Setup, Cursor, Ollama, etc. installations.";
  } else if (tool.name === "extras_create_quarantine_host_group") {
    title = "Create the IR quarantine host group";
    rows = [
      { label: "Name", value: get("name") ?? "Project Eyas - IR Quarantine" },
      { label: "Type", value: "static" },
    ];
    whatHappens = "Creates a new empty static host group on this tenant with the canonical app-managed naming. After this, save the returned id as the IR quarantine group on the active environment, then run extras_provision_quarantine_policy to attach the prevention policies.";
    ifDenied = "No new host group is created. You can paste an existing group id into /config instead and skip directly to provisioning.";
  } else if (tool.name === "extras_teardown_project_eyas_managed") {
    const live = input.dry_run === false;
    title = live ? "Tear down every Project Eyas object on this tenant" : "Preview a Project Eyas teardown (no changes)";
    rows = [{ label: "Mode", value: live ? "EXECUTE — deletes objects" : "dry run — lists what would be removed" }];
    whatHappens = live
      ? "Detaches, disables and deletes every Project Eyas prevention policy, deletes the Project Eyas Shadow-AI rule groups and the IR-readiness exclusion, then deletes the IR Quarantine and Shadow-AI Banned host groups. Hosts in those groups fall back to their other policies. This cannot be undone; re-run the /config setup cards to start again."
      : "Lists the Project Eyas host groups, prevention policies, rule groups and exclusions a teardown would remove. Nothing is changed.";
    ifDenied = live ? "Nothing is deleted." : "No preview is produced.";
  } else if (tool.name === "extras_delete_prevention_policy") {
    title = "Delete a prevention policy";
    rows = [{ label: "Policy", value: get("prevention_policy_id") ?? "(unspecified)", mono: true }];
    whatHappens = "Disables and deletes the policy. It must already be detached from every host group. This cannot be undone.";
    ifDenied = "The policy stays.";
  } else if (tool.name === "extras_delete_ioa_rule_group") {
    title = "Delete a Custom IOA rule group";
    rows = [
      { label: "Rule group", value: get("rule_group_id") ?? "(unspecified)", mono: true },
      { label: "Comment", value: get("comment") ?? "Project Eyas teardown" },
    ];
    whatHappens = "Deletes the rule group and its rules. Falcon refuses if a prevention policy still uses it. This cannot be undone.";
    ifDenied = "The rule group stays.";
  } else if (tool.name === "extras_detach_prevention_policy_from_host_group") {
    title = "Detach a prevention policy from a host group";
    rows = [
      { label: "Policy", value: get("prevention_policy_id") ?? "(unspecified)", mono: true },
      { label: "Host group", value: get("host_group_id") ?? "(unspecified)", mono: true },
    ];
    whatHappens = "Removes the named prevention policy from the named host group via the Falcon Prevention Policies API (action_name=remove-host-group). The policy itself is NOT deleted; it stays attached to its other host groups. Hosts in the named group fall to their next-precedence policy on next sensor heartbeat.";
    ifDenied = "The policy stays attached to this group. If a host is in both this group and the IR Quarantine / Shadow-AI Banned groups, the legacy policy can still apply via precedence depending on rank ordering.";
  } else if (tool.name === "extras_create_shadow_ai_banned_host_group") {
    title = "Create the Shadow-AI Banned host group";
    rows = [
      { label: "Name", value: get("name") ?? "Project Eyas - Shadow-AI Banned" },
      { label: "Type", value: "static" },
    ];
    whatHappens = "Creates a new empty static host group with the canonical app-managed naming. After this, save the returned id as the Shadow-AI banned group on the active environment, then run extras_provision_shadow_ai_banned_policy to attach the prevention policies + Shadow-AI rule group.";
    ifDenied = "No new host group is created. You can paste an existing group id into /config instead and skip directly to provisioning.";
  } else if (tool.name === "extras_provision_shadow_ai_banned_policy") {
    const mode = get("mode") ?? "adopt";
    title = mode === "create_dedicated"
      ? "Create dedicated Shadow-AI Banned prevention policies (per platform)"
      : "Adopt + standardize Shadow-AI Banned prevention policies (per platform)";
    rows = [
      { label: "Group", value: get("host_group_id") ?? "(unspecified)", mono: true },
      { label: "Mode", value: mode },
      { label: "Platforms", value: "Windows, macOS, Linux" },
      { label: "Sliders", value: "every detection/prevention slider → AGGRESSIVE" },
      { label: "Toggles", value: "every behavioral toggle → enabled" },
      { label: "Precedence", value: "above standard, below IR Quarantine" },
    ];
    if (mode === "create_dedicated") {
      whatHappens = "Per platform: creates a brand-new prevention policy bound only to the Shadow-AI Banned host group, pushes AGGRESSIVE sliders + enabled toggles, sets precedence above your standard policies (so it wins for hosts in this group) but below IR Quarantine (so an IR'd host still gets IR posture). Returns follow-up calls to attach the Shadow-AI Custom IOA rule group — that's a separate approval per policy.";
      ifDenied = "No new prevention policies are created. Hosts added to the Shadow-AI Banned group won't actually have AI tooling blocked until policies are provisioned.";
    } else {
      whatHappens = "Per platform: adopts the existing single-group prevention policy if any (renames to canonical naming) or attaches a fresh canonical policy if none exists; pushes AGGRESSIVE sliders + enabled toggles; sets precedence above standard, below IR Quarantine. Returns follow-up calls to attach the Shadow-AI Custom IOA rule group (separate approval per policy).";
      ifDenied = "Existing prevention policy stays as-is. Hosts added to the Shadow-AI Banned group won't have AI tooling blocked.";
    }
  } else if (tool.name === "extras_provision_quarantine_policy") {
    const mode = get("mode") ?? "adopt";
    title = mode === "create_dedicated"
      ? "Create dedicated IR-quarantine prevention policies (per platform)"
      : "Adopt + standardize IR-quarantine prevention policies (per platform)";
    rows = [
      { label: "Group", value: get("host_group_id") ?? "(unspecified)", mono: true },
      { label: "Mode", value: mode },
      { label: "Platforms", value: "Windows, macOS, Linux" },
      { label: "Sliders", value: "every detection/prevention slider → AGGRESSIVE" },
      { label: "Toggles", value: "every behavioral toggle → enabled" },
    ];
    if (mode === "create_dedicated") {
      whatHappens = "Per platform: creates a brand-new prevention policy bound only to the named host group, pushes every detection/prevention slider to AGGRESSIVE, enables every behavioral toggle (script monitoring, encoded-command, volume-shadow-copy protection, etc.), leaves any existing shared policy alone. Then verifies the IR-readiness IOA exclusion is in place (returns a separate follow-up call to create it if missing — exclusions are their own approval).";
      ifDenied = "No new prevention policies are created. Without provisioning, IR cleanup primitives can run against weaker enforcement than intended and Phase 3 verification can't distinguish 'cleanup ran but finding regenerated' from 'cleanup never executed'.";
    } else {
      whatHappens = "Per platform: adopts the existing single-group prevention policy if any (renames to canonical naming), or attaches a fresh canonical policy if none exists; pushes every detection/prevention slider to AGGRESSIVE; enables every behavioral toggle (script monitoring, encoded-command, volume-shadow-copy protection, etc.); verifies the IR-readiness IOA exclusion is in place.";
      ifDenied = "Existing prevention policy stays as-is. IR cleanup primitives may not run reliably until the policy is provisioned.";
    }
  }

  return (
    <div className="rounded-md border border-amber-700/60 bg-amber-950/40 px-3.5 py-3">
      <div className="text-xs font-semibold uppercase tracking-wider text-amber-300">
        Confirm write action
      </div>
      <div className="mt-0.5 text-[15px] font-semibold text-amber-100">{title}</div>
      {rows.length > 0 && (
        <dl className="mt-2 space-y-1 text-[13px]">
          {rows.map((r) => (
            <div key={r.label} className="flex items-baseline gap-2">
              <dt className="w-24 shrink-0 text-amber-400/80">{r.label}</dt>
              <dd
                className={`min-w-0 break-all text-amber-50 ${r.mono ? "font-mono" : ""}`}
              >
                {r.value}
              </dd>
            </div>
          ))}
        </dl>
      )}
      <VerifiedFacts tool={tool} />
      {(whatHappens || ifDenied) && (
        <div className="mt-3 space-y-1.5 border-t border-amber-800/40 pt-3 text-[13px] leading-snug">
          {whatHappens && (
            <div className="flex items-baseline gap-2">
              <span className="w-20 shrink-0 font-mono text-[10px] uppercase tracking-wide text-amber-400/80">
                If approved
              </span>
              <span className="min-w-0 text-amber-50">{whatHappens}</span>
            </div>
          )}
          {ifDenied && (
            <div className="flex items-baseline gap-2">
              <span className="w-20 shrink-0 font-mono text-[10px] uppercase tracking-wide text-amber-400/80">
                If denied
              </span>
              <span className="min-w-0 text-amber-50/90">{ifDenied}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ApprovalButtons({ toolUseId }: { toolUseId: string }) {
  const [submitting, setSubmitting] = useState<"allow" | "deny" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const decide = async (decision: "allow" | "deny") => {
    if (submitting) return;
    setSubmitting(decision);
    setError(null);
    try {
      // Server requires sessionId to match the pending approval's session —
      // prevents another tab (or any same-origin script) from resolving an
      // approval that belongs to a different chat session.
      const sessionId =
        typeof window !== "undefined"
          ? window.localStorage.getItem(SESSION_STORAGE_KEY) ?? ""
          : "";
      const res = await fetch("/api/chat/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ toolUseId, decision, sessionId }),
      });
      // A failed resolve returns a non-2xx (403 session mismatch / 400 bad
      // request) OR a 200 with { ok:false, found:false } (the pending entry
      // already expired/resolved). fetch does NOT throw on either, so without
      // this check `submitting` would stay latched and the button bricks —
      // exactly the multi-tab case where a second tab clobbered the stored
      // sessionId. Reset so the operator can retry, and tell them why.
      const data = (await res.json().catch(() => null)) as
        | { ok?: boolean; found?: boolean; error?: string }
        | null;
      if (!res.ok || !data?.ok) {
        const mismatch = res.status === 403 || data?.error === "session_mismatch";
        setError(
          mismatch
            ? "This approval belongs to another tab. Resolve it from the tab that started the turn."
            : "Couldn't submit — the approval may have expired. Try again or resend.",
        );
        setSubmitting(null);
      }
    } catch {
      setError("Network error — try again.");
      setSubmitting(null);
    }
  };

  return (
    <div className="space-y-1.5 pt-1">
      <div className="flex gap-2">
        <button
          onClick={() => decide("allow")}
          disabled={submitting !== null}
          className="rounded-md bg-amber-600 px-3.5 py-1.5 text-sm font-semibold text-white hover:bg-amber-500 disabled:opacity-50"
        >
          {submitting === "allow" ? "Approving…" : "Approve"}
        </button>
        <button
          onClick={() => decide("deny")}
          disabled={submitting !== null}
          className="rounded-md border border-neutral-700 bg-neutral-900 px-3.5 py-1.5 text-sm font-semibold text-neutral-200 hover:bg-neutral-800 disabled:opacity-50"
        >
          {submitting === "deny" ? "Denying…" : "Deny"}
        </button>
      </div>
      {error && <p className="text-xs text-amber-400/90">{error}</p>}
    </div>
  );
}
