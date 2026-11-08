import "server-only";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";
import { sseEncode } from "@/lib/chat/agent-loop";

export type Emit = (event: string, data: unknown) => void;

export interface StreamAgentContext {
  mcp: Client;
  extras: Client;
  emit: Emit;
  /** Aborts when the client disconnects from the SSE stream. The agent
   *  loop checks this between iterations to break out cleanly without
   *  burning further tokens after the user clicked Stop or navigated away. */
  signal: AbortSignal;
}

const SSE_HEADERS = {
  "Content-Type": "text/event-stream; charset=utf-8",
  "Cache-Control": "no-cache, no-transform",
  Connection: "keep-alive",
} as const;

export function streamAgent(
  setup: (ctx: StreamAgentContext) => Promise<void>,
  opts?: {
    /** Runs once the stream settles (normal completion, error, or client
     *  disconnect), in the stream's finally — use it to release a lock or
     *  other resource acquired alongside the request. Always runs if `start`
     *  ran, even when `setup` threw before reaching its own cleanup. */
    onSettled?: () => void;
  },
): Response {
  const abort = new AbortController();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const emit: Emit = (event, data) => {
        try {
          controller.enqueue(sseEncode(event, data));
        } catch {
          // controller closed (client disconnect)
        }
      };

      try {
        await withFalconMcpClient(async (mcp) => {
          await withFalconExtrasClient(async (extras) => {
            await setup({ mcp, extras, emit, signal: abort.signal });
          });
        });
      } catch (err) {
        // AbortError from a cancelled run is expected and already handled
        // by agent-loop emitting `cancelled` — don't surface as a user-facing
        // error.
        if (!(err instanceof Error && err.name === "AbortError")) {
          emit("error", {
            message: err instanceof Error ? err.message : String(err),
          });
        }
      } finally {
        // close() throws "Invalid state" if the consumer already cancelled the
        // stream (Stop / tab-close mid-turn) — same reason enqueue is guarded
        // above. An unguarded throw here would skip onSettled, which is the
        // only place the per-session lock is released (and it has no TTL), so
        // one cancel would 409 every later message in the conversation.
        try {
          controller.close();
        } catch {
          // controller already closed (client disconnect)
        }
        if (opts?.onSettled) {
          try {
            opts.onSettled();
          } catch {
            // a cleanup hook must never break stream teardown
          }
        }
      }
    },
    cancel() {
      // The consumer (browser fetch) closed the stream. Signal the agent
      // loop to stop spending tokens.
      abort.abort();
    },
  });

  return new Response(stream, { headers: SSE_HEADERS });
}
