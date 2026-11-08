import "server-only";
import { debugLog } from "@/lib/log";

const MAX_SAFE_DELAY_MS = 2 ** 31 - 1; // ~24.8 days

export type JobResult = { kind: string; message?: string };

export type RecurringJobConfig = {
  name: string;
  weekdays: ReadonlyArray<number>; // 0=Sun..6=Sat
  hour: number;
  minute: number;
  tz: string;
  run: () => Promise<JobResult>;
};

export type RecurringJob = {
  start: () => void;
  status: () => {
    started: boolean;
    nextFireAt: string | null;
    lastResult: { at: string; kind: string; message?: string } | null;
  };
  fireNow: () => Promise<JobResult>;
};

export function createRecurringJob(cfg: RecurringJobConfig): RecurringJob {
  let started = false;
  let nextFireAt: Date | null = null;
  let activeTimer: ReturnType<typeof setTimeout> | null = null;
  let lastResult: { at: Date; kind: string; message?: string } | null = null;
  // Concurrency guard: the scheduled timer and a manual fireNow() (or two
  // rapid fireNow() calls) must not run cfg.run() at the same time — jobs do
  // heavy MCP/LLM work and an overlap doubles cost + can race on shared state.
  let inFlight = false;

  const arm = () => {
    if (activeTimer) {
      clearTimeout(activeTimer);
      activeTimer = null;
    }
    const target = computeNextFireAt(new Date(), cfg.tz, cfg.weekdays, cfg.hour, cfg.minute);
    nextFireAt = target;
    const delay = Math.max(1_000, target.getTime() - Date.now());
    const capped = Math.min(delay, MAX_SAFE_DELAY_MS);
    activeTimer = setTimeout(async () => {
      if (capped < delay) {
        arm();
        return;
      }
      await fire();
    }, capped);
    if (typeof activeTimer === "object" && activeTimer && "unref" in activeTimer) {
      (activeTimer as unknown as { unref: () => void }).unref();
    }
  };

  const fire = async () => {
    if (inFlight) {
      // A manual fireNow() is still running. Skip this scheduled tick rather
      // than overlap, and re-arm for the next cadence slot.
      debugLog(`[scheduler] ${cfg.name} skipped scheduled fire — run already in progress`);
      arm();
      return;
    }
    inFlight = true;
    const startedAt = new Date();
    try {
      const result = await cfg.run();
      lastResult = { at: startedAt, kind: result.kind, message: result.message };
      if (result.kind === "error") {
        console.error(`[scheduler] ${cfg.name} error:`, result.message);
      } else {
        debugLog(`[scheduler] ${cfg.name} ${result.kind}:`, result.message ?? "");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      lastResult = { at: startedAt, kind: "error", message: msg };
      console.error(`[scheduler] ${cfg.name} threw:`, msg);
    } finally {
      inFlight = false;
      arm();
    }
  };

  return {
    start() {
      if (started) return;
      started = true;
      arm();
      debugLog(
        `[scheduler] ${cfg.name} armed; next fire at ${nextFireAt?.toISOString()} (${cfg.tz})`,
      );
    },
    status() {
      return {
        started,
        nextFireAt: nextFireAt ? nextFireAt.toISOString() : null,
        lastResult: lastResult
          ? { at: lastResult.at.toISOString(), kind: lastResult.kind, message: lastResult.message }
          : null,
      };
    },
    async fireNow() {
      // Manual-fire: does NOT re-arm. The armed timer keeps its position so
      // an ad-hoc run doesn't shift the recurring cadence.
      if (inFlight) {
        // The scheduled timer fired (or another manual run is going). Don't
        // launch a second concurrent cfg.run() — report it as skipped.
        return { kind: "skipped", message: "a run is already in progress" };
      }
      inFlight = true;
      const startedAt = new Date();
      try {
        const result = await cfg.run();
        lastResult = { at: startedAt, kind: result.kind, message: result.message };
        return result;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        lastResult = { at: startedAt, kind: "error", message: msg };
        return { kind: "error", message: msg };
      } finally {
        inFlight = false;
      }
    },
  };
}

/**
 * Compute the next instant matching one of `weekdays` at `hour`:`minute` in `tz`,
 * strictly after `from`. Returns a UTC Date.
 */
export function computeNextFireAt(
  from: Date,
  tz: string,
  weekdays: ReadonlyArray<number>,
  hour: number,
  minute: number,
): Date {
  const allowed = new Set(weekdays);
  for (let dayOffset = 0; dayOffset <= 14; dayOffset++) {
    const candidate = wallClockInZone(from, dayOffset, hour, minute, tz);
    const dow = weekdayInZone(candidate, tz);
    if (!allowed.has(dow)) continue;
    if (candidate.getTime() <= from.getTime()) continue;
    return candidate;
  }
  throw new Error(
    `Could not compute next [${[...weekdays].join(",")}]@${hour}:${minute} in ${tz}`,
  );
}

function wallClockInZone(
  base: Date,
  dayOffset: number,
  hour: number,
  minute: number,
  tz: string,
): Date {
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  const parts = Object.fromEntries(
    fmt.formatToParts(base).map((p) => [p.type, p.value]),
  ) as Record<string, string>;
  const y = Number(parts.year);
  const mo = Number(parts.month);
  const d = Number(parts.day);
  const naiveUtc = Date.UTC(y, mo - 1, d + dayOffset, hour, minute, 0, 0);
  const offsetMs = zoneOffsetMs(new Date(naiveUtc), tz);
  return new Date(naiveUtc - offsetMs);
}

function zoneOffsetMs(at: Date, tz: string): number {
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  const parts = Object.fromEntries(
    fmt.formatToParts(at).map((p) => [p.type, p.value]),
  ) as Record<string, string>;
  const localMs = Date.UTC(
    Number(parts.year),
    Number(parts.month) - 1,
    Number(parts.day),
    Number(parts.hour),
    Number(parts.minute),
    Number(parts.second),
  );
  return localMs - at.getTime();
}

function weekdayInZone(at: Date, tz: string): number {
  const fmt = new Intl.DateTimeFormat("en-US", { timeZone: tz, weekday: "short" });
  const wd = fmt.format(at);
  return ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(wd);
}
