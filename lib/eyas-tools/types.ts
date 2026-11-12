import type Anthropic from "@anthropic-ai/sdk";
import type { CallNative } from "@/lib/mcp/native-dispatch";

// Eyas's own agent tools, served in-process by the tool bridge. They keep the
// `extras_*` names they had in the retired falcon-extras sidecar, so IR
// records, approval cards, tool summaries and primers keep working. Any Falcon
// call a tool makes goes through eyas-mcp's native tools via `ctx.callNative`.
//
// Every tool must be classified exactly once: in REQUIRES_APPROVAL (writes) or
// EXTRAS_READ_ONLY (reads), both in lib/mcp/write-tools.ts. The bridge gates
// an unclassified one, and scripts/test-tool-classification.mjs fails on it.

export type EyasToolResult = { content: string; isError: boolean };

/** A native search shaped like the former sidecar payloads
 *  (lib/mcp/native-shape.ts): rows plus pagination.total, a scope denial, or
 *  an error. */
export type NativeSearchResult =
  | { ok: true; items: Record<string, unknown>[]; total?: number; scope_pending?: false }
  | { ok: true; scope_pending: true; items: []; total?: undefined }
  | { ok: false; error: string };

export type SearchNative = (name: string, args: Record<string, unknown>) => Promise<NativeSearchResult>;

export type EyasToolContext = {
  /** One eyas-mcp call; resolves to its first JSON object or an error. */
  callNative: CallNative;
  /** One eyas-mcp search call; resolves to all its rows. */
  searchNative: SearchNative;
};

export type EyasTool = {
  name: string;
  /** What the agent sees. */
  description: string;
  input_schema: Anthropic.Tool["input_schema"];
  /** Hand the result to the agent as-is, skipping the bridge's projection and
   *  12 KB cap. Only for Eyas's own content whose full text is the point —
   *  the playbooks (the agent's instruction set; the IR one is ~70 KB) and the
   *  script catalog listings. */
  rawResult?: boolean;
  run: (input: Record<string, unknown>, ctx: EyasToolContext) => Promise<EyasToolResult>;
};

/** Serialize an object result the way the sidecar did (pretty JSON), so the
 *  agent, projections and summaries see the same text as before. */
export function jsonResult(obj: Record<string, unknown>, isError = false): EyasToolResult {
  return { content: JSON.stringify(obj, null, 2), isError };
}
