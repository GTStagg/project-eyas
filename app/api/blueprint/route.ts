import "server-only";
import { NextResponse } from "next/server";
import type Anthropic from "@anthropic-ai/sdk";
import { getAnthropicClient, getAnthropicModel } from "@/lib/llm/anthropic";
import { streamMessage } from "@/lib/llm/messages";
import { sseEncode } from "@/lib/chat/agent-loop";
import { logUsage } from "@/lib/cost/log";
import { REFERENCE_ARCHITECTURE_BRIEF } from "@/lib/advisor/blueprint-knowledge";
import { DEV_PORTAL_LINKS } from "@/lib/advisor/blueprint-shared";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// The /blueprint developer advisor. Reasons about HOW to build an agentic SOC
// on eyas-mcp + Claude, grounded in this project's own reference
// architecture. It calls NO Falcon tenant tools — pure LLM synthesis — so it is
// deliberately NOT wired through streamAgent() (which spawns an eyas-mcp
// client and would require Falcon to be configured). A developer
// evaluating "could I build this" should get value with only Anthropic set up.

const SSE_HEADERS = {
  "Content-Type": "text/event-stream; charset=utf-8",
  "Cache-Control": "no-cache, no-transform",
  Connection: "keep-alive",
} as const;

const MAX_QUESTION_LEN = 2000;

function buildSystemPrompt(): string {
  const linkList = DEV_PORTAL_LINKS.map(
    (l) => `- ${l.topic}: ${l.url} — ${l.blurb}`,
  ).join("\n");

  return [
    "You are the Blueprint advisor inside Eyas, a reference agentic SOC console for CrowdStrike Falcon.",
    "Your audience is DEVELOPERS who want to build something like this in their own organization on eyas-mcp (an independent MCP server for the Falcon APIs, built on FalconPy) and Claude. Speak to engineers: raw tool names, provider names, and architecture terms are expected and welcome — do not dumb it down.",
    "",
    "Your value is the COMPOSITION PATTERNS this reference implementation proves — not the platform primitives themselves. developer.crowdstrike.com documents the primitives; you explain how to wire them together, the tradeoffs, and the gotchas. Ground every architectural claim in the reference brief below.",
    "",
    "OUTPUT: a concise decision document in GitHub-flavored Markdown. Use H2 (`##`) sections, in this order, omitting any that don't apply:",
    "- `## What you're building` — one or two sentences framing the goal in the developer's terms.",
    "- `## Platform primitives` — the eyas-mcp tools / FalconPy operations / OAuth scopes / SDK pieces involved. Link to the authoritative source with a Markdown link when you name one (use the URLs below). Do NOT invent API paths or scope names — point to the reference instead.",
    "- `## How Eyas composes it` — the actual pattern: the in-process client + tool-use loop, approval gating, the eyas-mcp natives vs. Eyas's own in-process tools split, deterministic enrichment vs. agentic synthesis — whichever apply.",
    "- `## Gotchas` — the traps a first-time builder hits (from the brief). Be specific.",
    "- `## Where to start` — 2–4 concrete first steps.",
    "Keep it tight and skimmable. Prefer short paragraphs and tight bullet lists over walls of text. Never fabricate specifics — if the brief doesn't cover it, say so and point to the authoritative source.",
    "",
    "=== AUTHORITATIVE SOURCES (link out; never re-host) ===",
    linkList,
    "",
    "=== REFERENCE ARCHITECTURE BRIEF (ground here) ===",
    REFERENCE_ARCHITECTURE_BRIEF,
  ].join("\n");
}

type RequestBody = { question?: string };

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as RequestBody;
  const question = (body.question ?? "").trim();
  if (!question) {
    return NextResponse.json({ ok: false, error: "question required" }, { status: 400 });
  }
  if (question.length > MAX_QUESTION_LEN) {
    return NextResponse.json(
      { ok: false, error: `question too long (max ${MAX_QUESTION_LEN} chars)` },
      { status: 400 },
    );
  }

  // Anthropic-only guard (no Falcon dependency). getAnthropicClient() throws a
  // clear message when neither an API key nor a gateway token is configured.
  try {
    getAnthropicClient();
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }

  const abort = new AbortController();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const emit = (event: string, data: unknown) => {
        try {
          controller.enqueue(sseEncode(event, data));
        } catch {
          // controller closed (client disconnect)
        }
      };

      let usage = {
        input_tokens: 0,
        output_tokens: 0,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
      };

      try {
        const anthropic = getAnthropicClient();
        const model = getAnthropicModel();
        const final = await streamMessage(
          anthropic,
          {
            model,
            max_tokens: 3072,
            system: [
              {
                type: "text",
                text: buildSystemPrompt(),
                cache_control: { type: "ephemeral", ttl: "1h" },
              },
            ],
            messages: [{ role: "user", content: question }],
          },
          {
            signal: abort.signal,
            onEvent: (event) => {
              if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
                emit("text", event.delta.text);
              }
            },
          },
        );
        if (final.usage) {
          usage = {
            input_tokens: final.usage.input_tokens ?? 0,
            output_tokens: final.usage.output_tokens ?? 0,
            cache_creation_input_tokens: final.usage.cache_creation_input_tokens ?? 0,
            cache_read_input_tokens: final.usage.cache_read_input_tokens ?? 0,
          };
        }

        emit("done", { iterations: 1, usage });

        void logUsage({
          ts: new Date().toISOString(),
          model,
          surface: "blueprint",
          iterations: 1,
          usage,
        });
      } catch (err) {
        // A client disconnect / Stop surfaces as an AbortError — expected,
        // don't render it as a failure.
        if (!(err instanceof Error && err.name === "AbortError")) {
          emit("error", { message: err instanceof Error ? err.message : String(err) });
        }
      } finally {
        try {
          controller.close();
        } catch {
          // already closed
        }
      }
    },
    cancel() {
      abort.abort();
    },
  });

  return new Response(stream, { headers: SSE_HEADERS });
}
