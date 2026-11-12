// Prompt-cache helpers for the agent loops.
//
// The prompt prefix is tools → system → messages, and a cache hit needs it to
// be byte-identical. Two things kept that from happening across chat turns:
//
// 1. eyas-mcp listed its tools, resources and some schema arrays (`examples`,
//    `enum`, `required`) in a different order in each Python process (set
//    iteration order is randomized per process). In dev it starts per turn,
//    so every chat turn re-wrote the ~175K-token tools + system prefix to the
//    cache. canonicalTools / canonicalResources sort them, so the prefix is
//    stable however the server orders them.
// 2. Only tools and system carried a cache marker, so each loop iteration
//    re-sent the whole conversation (tool results included) as uncached
//    input. withHistoryCacheMarker puts a marker on the last block of the
//    conversation, so each iteration reads the history from cache and only
//    the new tail is written.
//
// Pure. Tested in scripts/test-prompt-cache.mjs.

import type Anthropic from "@anthropic-ai/sdk";

type Json = unknown;

// Schema arrays whose order carries no meaning.
const UNORDERED_KEYS = new Set(["examples", "enum", "required"]);

const isScalar = (v: unknown) => v === null || ["string", "number", "boolean"].includes(typeof v);

function canonicalSchema(v: Json, key?: string): Json {
  if (Array.isArray(v)) {
    const items = v.map((x) => canonicalSchema(x));
    if (key && UNORDERED_KEYS.has(key) && items.every(isScalar)) {
      return [...items].sort((a, b) => {
        const x = JSON.stringify(a);
        const y = JSON.stringify(b);
        return x < y ? -1 : x > y ? 1 : 0;
      });
    }
    return items;
  }
  if (v && typeof v === "object") {
    const out: Record<string, Json> = {};
    for (const [k, val] of Object.entries(v as Record<string, Json>)) out[k] = canonicalSchema(val, k);
    return out;
  }
  return v;
}

const byString = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** Tools sorted by name, with order-free schema arrays sorted. */
export function canonicalTools<T extends Anthropic.Tool>(tools: T[]): T[] {
  return [...tools]
    .sort((a, b) => byString(a.name, b.name))
    .map((t) => ({ ...t, input_schema: canonicalSchema(t.input_schema) as T["input_schema"] }));
}

/** Resources sorted by URI (they are listed in the chat system prompt). */
export function canonicalResources<T extends { uri: string }>(resources: T[]): T[] {
  return [...resources].sort((a, b) => byString(a.uri, b.uri));
}

// Block types that accept a cache marker (thinking blocks don't).
const MARKABLE = new Set(["text", "tool_result", "tool_use", "image", "document"]);

/**
 * A copy of `messages` with a cache marker on the last markable block of the
 * last message. The input array and its messages are left untouched (the
 * conversation is persisted as-is).
 */
export function withHistoryCacheMarker(
  messages: Anthropic.Beta.BetaMessageParam[],
  ttl: "5m" | "1h",
): Anthropic.Beta.BetaMessageParam[] {
  if (messages.length === 0) return messages;
  const last = messages[messages.length - 1];
  if (last.role !== "user" && last.role !== "assistant") return messages;
  const marker = { type: "ephemeral" as const, ttl };
  const blocks = last.content as string | Anthropic.Beta.BetaContentBlockParam[] | undefined;
  let content: Anthropic.Beta.BetaContentBlockParam[];
  if (typeof blocks === "string") {
    if (!blocks) return messages;
    content = [{ type: "text", text: blocks, cache_control: marker }];
  } else {
    if (!blocks) return messages;
    const idx = blocks.map((b) => MARKABLE.has(b.type)).lastIndexOf(true);
    if (idx < 0) return messages;
    content = blocks.map((b, i) =>
      i === idx ? ({ ...b, cache_control: marker } as Anthropic.Beta.BetaContentBlockParam) : b,
    );
  }
  return [...messages.slice(0, -1), { ...last, content } as Anthropic.Beta.BetaMessageParam];
}
