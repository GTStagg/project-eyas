import "server-only";
import type Anthropic from "@anthropic-ai/sdk";

// Flatten an `Anthropic.MessageParam[]` (the on-disk shape of a session's
// conversation history) into the Turn[] shape that components/Chat.tsx
// renders. The agent-loop normally builds the UI shape live via SSE events;
// when the user resumes a stored conversation we don't replay the stream —
// we reconstruct the same shape from the persisted messages.
//
// Mapping:
//   Anthropic user message (text-only) -> UI UserTurn
//   Anthropic user message (tool_result-only) -> attach result to the
//     previous AssistantTurn's matching tool_use by id. NOT a new UI turn.
//   Anthropic assistant message -> UI AssistantTurn (text + toolUses).
//     Consecutive assistant messages (separated only by tool_result-only
//     user messages, which is the agent-loop iteration shape) collapse into
//     a single UI AssistantTurn — matches what the user saw live.

export type ResumedToolUse = {
  id: string;
  name: string;
  input: Record<string, unknown>;
  result?: { content: string; isError: boolean };
  /** Re-stamped by the resume route (`/api/chat/sessions/[id]`) when this
   *  tool_use's approval is still pending server-side. The agent loop's
   *  awaitApproval Promise is in-memory and survives across resumes within
   *  the 5-min approval timeout. */
  pendingApproval?: boolean;
};

export type ResumedUserTurn = { role: "user"; text: string };
export type ResumedAssistantTurn = {
  role: "assistant";
  text: string;
  toolUses: ResumedToolUse[];
};
export type ResumedTurn = ResumedUserTurn | ResumedAssistantTurn;

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  let out = "";
  for (const block of content) {
    if (block && typeof block === "object" && (block as { type?: string }).type === "text") {
      const t = (block as { text?: string }).text;
      if (typeof t === "string") out += t;
    }
  }
  return out;
}

function toolUsesOf(content: unknown): ResumedToolUse[] {
  if (!Array.isArray(content)) return [];
  const out: ResumedToolUse[] = [];
  for (const block of content) {
    if (block && typeof block === "object" && (block as { type?: string }).type === "tool_use") {
      const b = block as { id?: string; name?: string; input?: unknown };
      if (typeof b.id === "string" && typeof b.name === "string") {
        out.push({
          id: b.id,
          name: b.name,
          input: (b.input as Record<string, unknown>) ?? {},
        });
      }
    }
  }
  return out;
}

function toolResultsOf(
  content: unknown,
): Array<{ id: string; content: string; isError: boolean }> {
  if (!Array.isArray(content)) return [];
  const out: Array<{ id: string; content: string; isError: boolean }> = [];
  for (const block of content) {
    if (block && typeof block === "object" && (block as { type?: string }).type === "tool_result") {
      const b = block as { tool_use_id?: string; content?: unknown; is_error?: boolean };
      if (typeof b.tool_use_id !== "string") continue;
      let text = "";
      if (typeof b.content === "string") text = b.content;
      else if (Array.isArray(b.content)) {
        for (const inner of b.content) {
          if (inner && typeof inner === "object" && (inner as { type?: string }).type === "text") {
            const t = (inner as { text?: string }).text;
            if (typeof t === "string") text += t;
          }
        }
      }
      out.push({ id: b.tool_use_id, content: text, isError: !!b.is_error });
    }
  }
  return out;
}

function isToolResultOnly(msg: Anthropic.MessageParam): boolean {
  if (msg.role !== "user") return false;
  if (typeof msg.content === "string") return false;
  if (!Array.isArray(msg.content) || msg.content.length === 0) return false;
  return msg.content.every(
    (b) => b && typeof b === "object" && (b as { type?: string }).type === "tool_result",
  );
}

export function flattenMessagesToTurns(messages: Anthropic.MessageParam[]): ResumedTurn[] {
  const turns: ResumedTurn[] = [];
  let lastAssistant: ResumedAssistantTurn | null = null;

  for (const msg of messages) {
    if (msg.role === "user") {
      if (isToolResultOnly(msg)) {
        // Attach tool results to the most-recent assistant turn's tool_use
        // entries by id.
        if (!lastAssistant) continue;
        const results = toolResultsOf(msg.content);
        for (const r of results) {
          const tu = lastAssistant.toolUses.find((t) => t.id === r.id);
          if (tu) tu.result = { content: r.content, isError: r.isError };
        }
        continue;
      }
      const text = textOf(msg.content);
      if (!text) continue;
      turns.push({ role: "user", text });
      // A real user message terminates the previous assistant turn; the
      // next assistant message starts a fresh one.
      lastAssistant = null;
    } else if (msg.role === "assistant") {
      const text = textOf(msg.content);
      const toolUses = toolUsesOf(msg.content);
      if (lastAssistant) {
        // Continuation of the same logical assistant turn (separated only
        // by tool_result user messages — the agent-loop iteration shape).
        if (text) {
          if (lastAssistant.text && !/\n\n$/.test(lastAssistant.text)) {
            lastAssistant.text = lastAssistant.text.replace(/\s+$/, "") + "\n\n";
          }
          lastAssistant.text += text;
        }
        for (const tu of toolUses) lastAssistant.toolUses.push(tu);
      } else {
        const turn: ResumedAssistantTurn = { role: "assistant", text, toolUses };
        turns.push(turn);
        lastAssistant = turn;
      }
    }
  }

  return turns;
}
