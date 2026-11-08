import "server-only";

// Login attempt throttling for the single operator account.
//
// After FREE_ATTEMPTS consecutive failures from one client, each further
// attempt must wait an exponentially growing delay (30s, 60s, 120s, ...),
// capped at MAX_DELAY_MS, so a password can't be brute-forced but the
// operator is never locked out indefinitely. A successful login clears the
// client's record; records idle for RESET_AFTER_MS are forgotten.
//
// Client identity: by default every request shares one bucket. The app
// listens on loopback, and behind a reverse proxy every request arrives from
// the proxy, so per-IP keys would be meaningless and request headers can't be
// trusted. Set EYAS_TRUST_PROXY=true only when a reverse proxy you control
// sets X-Forwarded-For; the right-most entry (added by that proxy) then keys
// the bucket, so a remote attacker can't delay the operator's own logins.
//
// State is in memory and process-local, like pending approvals: a restart
// clears it.

const FREE_ATTEMPTS = 5;
const BASE_DELAY_MS = 30_000;
const MAX_DELAY_MS = 15 * 60_000;
const RESET_AFTER_MS = 60 * 60_000;
const MAX_TRACKED = 10_000;

type Entry = { failures: number; lockedUntil: number; lastFailure: number };

const g = globalThis as unknown as { __eyasLoginThrottle?: Map<string, Entry> };
const entries: Map<string, Entry> = (g.__eyasLoginThrottle ??= new Map());

export function clientKey(headers: Headers): string {
  if (process.env.EYAS_TRUST_PROXY?.toLowerCase() !== "true") return "global";
  const xff = headers.get("x-forwarded-for");
  const ip = xff?.split(",").map((s) => s.trim()).filter(Boolean).pop();
  return ip ? `ip:${ip}` : "global";
}

function current(key: string, now: number): Entry | undefined {
  const e = entries.get(key);
  if (e && now - e.lastFailure > RESET_AFTER_MS) {
    entries.delete(key);
    return undefined;
  }
  return e;
}

/** Milliseconds the client must still wait before another attempt (0 = allowed). */
export function retryAfterMs(key: string, now = Date.now()): number {
  const e = current(key, now);
  return e ? Math.max(0, e.lockedUntil - now) : 0;
}

export function recordFailure(key: string, now = Date.now()): void {
  const e = current(key, now) ?? { failures: 0, lockedUntil: 0, lastFailure: now };
  e.failures += 1;
  e.lastFailure = now;
  if (e.failures >= FREE_ATTEMPTS) {
    const delay = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** (e.failures - FREE_ATTEMPTS));
    e.lockedUntil = now + delay;
  }
  entries.delete(key);
  entries.set(key, e);
  // Bound memory when keyed by client address: drop the oldest records.
  while (entries.size > MAX_TRACKED) {
    const oldest = entries.keys().next().value;
    if (oldest === undefined) break;
    entries.delete(oldest);
  }
}

export function recordSuccess(key: string): void {
  entries.delete(key);
}

/** Test hook. */
export function _resetLoginThrottle(): void {
  entries.clear();
}
