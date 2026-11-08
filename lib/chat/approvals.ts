import "server-only";

export type Decision = "allow" | "deny" | "timeout";

type Pending = {
  resolve: (decision: Decision) => void;
  toolName: string;
  sessionId: string;
  createdAt: number;
};

// Pinned to globalThis so dev-mode hot-reload + per-route module duplication
// don't fragment the Map across route handlers. Without this, /api/chat and
// /api/chat/approve get separate Map instances and approvals never resolve.
const globalForApprovals = globalThis as unknown as {
  __falconPendingApprovals?: Map<string, Pending>;
};
const pending: Map<string, Pending> =
  globalForApprovals.__falconPendingApprovals ??
  (globalForApprovals.__falconPendingApprovals = new Map());
const APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;

export function awaitApproval(
  toolUseId: string,
  toolName: string,
  sessionId: string,
  signal?: AbortSignal,
): Promise<Decision> {
  return new Promise((resolve) => {
    // Client disconnect / Stop aborts the request signal. Without honoring it
    // here the loop blocks up to APPROVAL_TIMEOUT_MS (5 min), pinning the
    // in-flight lock (env-switch 409s) and the idle MCP client pair, and leaving
    // a pending entry that a resume would re-stamp as a live Allow button on a
    // dead loop. Resolve as "timeout" (not-executed, don't-retry) on abort.
    if (signal?.aborted) {
      resolve("timeout");
      return;
    }
    let settled = false;
    const settle = (decision: Decision) => {
      if (settled) return;
      settled = true;
      pending.delete(toolUseId);
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      resolve(decision);
    };
    const onAbort = () => settle("timeout");
    const timer = setTimeout(() => settle("timeout"), APPROVAL_TIMEOUT_MS);
    timer.unref?.();
    pending.set(toolUseId, {
      resolve: settle,
      toolName,
      sessionId,
      createdAt: Date.now(),
    });
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export type ResolveResult =
  | { ok: true }
  | { ok: false; reason: "not_found" | "session_mismatch" };

// Resolve a pending approval. The caller must present the same sessionId the
// approval was registered under — this prevents one authenticated browser tab
// (or any same-origin script) from resolving an approval that belongs to a
// different chat session. Defense in depth against accidental cross-session
// resolves and forged requests when a sessionId is known.
/** Tool-use ids currently awaiting approval for a session. Used by the
 *  conversation-resume path to re-stamp `pendingApproval: true` on the
 *  matching tool_use bubbles after a flatten — without this the rehydrated
 *  UI shows the tool as merely "called", with no Allow/Deny buttons. */
export function listPendingForSession(sessionId: string): Array<{
  toolUseId: string;
  toolName: string;
}> {
  const out: Array<{ toolUseId: string; toolName: string }> = [];
  for (const [toolUseId, entry] of pending) {
    if (entry.sessionId === sessionId) {
      out.push({ toolUseId, toolName: entry.toolName });
    }
  }
  return out;
}

export function resolveApproval(
  toolUseId: string,
  decision: Decision,
  expectedSessionId: string,
): ResolveResult {
  const entry = pending.get(toolUseId);
  if (!entry) return { ok: false, reason: "not_found" };
  if (entry.sessionId !== expectedSessionId) {
    return { ok: false, reason: "session_mismatch" };
  }
  pending.delete(toolUseId);
  entry.resolve(decision);
  return { ok: true };
}
