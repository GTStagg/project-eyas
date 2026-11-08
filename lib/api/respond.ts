import "server-only";
import { NextResponse } from "next/server";

// Unified JSON response envelope for app/api/* routes. Standardises on
// { ok: true, ... } and { ok: false, error } so client callers can shape
// their handlers once instead of pattern-matching per route. Scope-pending
// is a third state (ok=true with a marker), preserving the staged-build
// convention the page renderers already read.

export function ok<T extends Record<string, unknown>>(data?: T): NextResponse {
  return NextResponse.json({ ok: true, ...(data ?? {}) });
}

export function fail(error: string, status = 400): NextResponse {
  return NextResponse.json({ ok: false, error }, { status });
}

export function scopePending(note?: string): NextResponse {
  return NextResponse.json({ ok: true, scope_pending: true, note });
}

// Catch-all for unexpected upstream / runtime errors. Default 502 because
// most callers wrap MCP / external work; 5xx tells the client this isn't
// a request validation failure they can fix by retrying with a different
// payload.
export function serverError(err: unknown, status = 502): NextResponse {
  const message = err instanceof Error ? err.message : String(err);
  return fail(message, status);
}
