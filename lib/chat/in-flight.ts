import "server-only";

// Process-wide counter of in-flight agent runs / write actions.
// The environment switcher consults isBusy() to refuse a credential
// rotation while an agent loop is mid-tool-call — swapping Falcon
// creds while a withFalconMcpClient call is hanging on a long Spotlight
// fan-out would attribute the result to the wrong tenant in the trace.
//
// Pinned to globalThis so dev-mode per-route module duplication doesn't
// fragment the count across route files.

const g = globalThis as unknown as { __falconInFlight?: { count: number } };
const state = (g.__falconInFlight ??= { count: 0 });

export function beginInFlight(): void {
  state.count += 1;
}

export function endInFlight(): void {
  state.count = Math.max(0, state.count - 1);
}

export function isBusy(): boolean {
  return state.count > 0;
}

export function inFlightCount(): number {
  return state.count;
}

// Per-session mutex (distinct from the process-wide counter above). Two
// overlapping turns on the SAME chat sessionId — a double-submit, or two tabs
// resuming the same conversation — both load the same base transcript and the
// second saveConversation clobbers the first (last-writer-wins), dropping a
// turn's history while the IR turnCount drifts. The chat route acquires this
// before streaming and releases when the stream settles; a second concurrent
// request for the same session is refused with 409 (mirrors the env-switch
// refusal). Pinned to globalThis for the same reason the counter is.
const sg = globalThis as unknown as { __falconSessionLocks?: Set<string> };
const sessionLocks = (sg.__falconSessionLocks ??= new Set<string>());

/** Acquire the per-session lock. Returns false if a turn is already running
 *  for this session (caller should 409). */
export function tryEnterSession(sessionId: string): boolean {
  if (sessionLocks.has(sessionId)) return false;
  sessionLocks.add(sessionId);
  return true;
}

export function exitSession(sessionId: string): void {
  sessionLocks.delete(sessionId);
}
