import "server-only";

/**
 * SCHEDULES env grammar:
 *   SCHEDULES=<entry>[,<entry>…]
 *   <entry> = <jobId>[:<dayspec>[@<hh:mm>]]
 *   <dayspec> = DAILY | <day>[-<day>] | <day>[,<day>…]
 *   <day> = SUN|MON|TUE|WED|THU|FRI|SAT
 *
 * If <dayspec>/<time> are omitted, the job's defaults are used.
 * Whitespace is ignored. Case-insensitive on day names.
 *
 * Examples:
 *   SCHEDULES=patch-digest
 *   SCHEDULES=patch-digest:MON@09:00,daily-briefing:MON-FRI@09:00
 *   SCHEDULES=daily-briefing:MON,WED,FRI@07:30
 */

export type ManifestEntry = {
  jobId: string;
  weekdays: number[]; // empty = use job default
  hour: number | null;
  minute: number | null;
  raw: string;
};

const DAY_NAMES = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"] as const;

function parseDay(token: string): number {
  const idx = DAY_NAMES.indexOf(token.toUpperCase() as (typeof DAY_NAMES)[number]);
  if (idx < 0) throw new Error(`Unknown day "${token}" (expected SUN..SAT)`);
  return idx;
}

function parseDayspec(spec: string): number[] {
  const upper = spec.toUpperCase();
  if (upper === "DAILY") return [0, 1, 2, 3, 4, 5, 6];
  if (upper.includes("-")) {
    const [from, to] = upper.split("-").map((s) => s.trim());
    const fromIdx = parseDay(from);
    const toIdx = parseDay(to);
    const result: number[] = [];
    let i = fromIdx;
    while (true) {
      result.push(i);
      if (i === toIdx) break;
      i = (i + 1) % 7;
      if (result.length > 7) throw new Error(`Bad day range "${spec}"`);
    }
    return result;
  }
  return upper.split(",").map((s) => parseDay(s.trim()));
}

function parseTime(spec: string): { hour: number; minute: number } {
  const m = /^(\d{1,2}):(\d{2})$/.exec(spec.trim());
  if (!m) throw new Error(`Bad time "${spec}" (expected HH:MM)`);
  const hour = Number(m[1]);
  const minute = Number(m[2]);
  if (hour < 0 || hour > 23) throw new Error(`Bad hour ${hour} in "${spec}"`);
  if (minute < 0 || minute > 59) throw new Error(`Bad minute ${minute} in "${spec}"`);
  return { hour, minute };
}

export function parseScheduleEntry(raw: string): ManifestEntry {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error("Empty schedule entry");

  const [jobAndDay, time] = trimmed.split("@").map((s) => s.trim());
  const [jobId, dayspec] = jobAndDay.split(":").map((s) => s.trim());

  if (!jobId) throw new Error(`Missing job id in "${trimmed}"`);

  const weekdays = dayspec ? parseDayspec(dayspec) : [];
  const t = time ? parseTime(time) : null;

  return {
    jobId,
    weekdays,
    hour: t?.hour ?? null,
    minute: t?.minute ?? null,
    raw: trimmed,
  };
}

export function parseSchedulesEnv(env: string | undefined): ManifestEntry[] {
  if (!env) return [];
  return env
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map(parseScheduleEntry);
}
