import "server-only";

// Gate routine info-level logs behind DEBUG_LOGS=true. Errors should
// always go to stderr via console.error so log aggregators still see
// real failures. This helper only affects operational chatter
// (migration timings, scheduler ticks, etc.) that would otherwise
// flood structured-log pipelines with no signal-to-noise.

const DEBUG = process.env.DEBUG_LOGS === "true";

export function debugLog(...args: unknown[]): void {
  if (DEBUG) console.log(...args);
}
