import "server-only";
import { createRecurringJob, type RecurringJob } from "./recurring";
import { getJob, listJobIds, type JobDefinition } from "./jobs";
import { parseSchedulesEnv, type ManifestEntry } from "./manifest";
import { getOutboundWebhookUrl } from "@/lib/webhook/deliver";

const DEFAULT_TZ = "America/Denver";

type ArmedJob = {
  id: string;
  label: string;
  cadence: { weekdays: number[]; hour: number; minute: number; tz: string };
  job: RecurringJob;
};

// Pinned to globalThis so Next.js's per-route module duplication (dev HMR and
// the standalone server's route bundling) can't fragment the armed-jobs state
// across copies — otherwise one route file boots the scheduler while another
// reports started:false and re-arms, double-firing jobs. Same rationale as
// lib/db/client.ts and lib/chat/in-flight.ts.
const sg = globalThis as unknown as {
  __eyasScheduler?: { booted: boolean; armed: ArmedJob[]; bootError: string | null };
};
const state = (sg.__eyasScheduler ??= { booted: false, armed: [], bootError: null });

export type SchedulerStatus = {
  enabled: boolean;
  started: boolean;
  webhookConfigured: boolean;
  bootError: string | null;
  jobs: Array<{
    id: string;
    label: string;
    cadence: { weekdays: number[]; hour: number; minute: number; tz: string };
    started: boolean;
    nextFireAt: string | null;
    lastResult: { at: string; kind: string; message?: string } | null;
  }>;
};

function tz(): string {
  return process.env.SCHEDULER_TZ?.trim() || DEFAULT_TZ;
}

function buildArmedJob(def: JobDefinition, entry: ManifestEntry): ArmedJob {
  const weekdays = entry.weekdays.length > 0 ? entry.weekdays : [...def.defaultWeekdays];
  const hour = entry.hour ?? def.defaultHour;
  const minute = entry.minute ?? def.defaultMinute;
  const zone = tz();
  const job = createRecurringJob({
    name: def.id,
    weekdays,
    hour,
    minute,
    tz: zone,
    run: def.run,
  });
  return {
    id: def.id,
    label: def.label,
    cadence: { weekdays, hour, minute, tz: zone },
    job,
  };
}

export function startScheduler(): SchedulerStatus {
  if (state.booted) return getSchedulerStatus();
  if (process.env.SCHEDULER_ENABLED !== "true") return getSchedulerStatus();

  // Most jobs deliver to a webhook and can't do anything without one. A job
  // that persists locally (requiresWebhook: false, e.g. posture-snapshot) still
  // arms here; webhook-delivery jobs are skipped per-job below when no webhook
  // is configured, with a soft bootError noting which.
  const hasWebhook = !!getOutboundWebhookUrl();

  let entries: ManifestEntry[];
  try {
    entries = parseSchedulesEnv(process.env.SCHEDULES);
  } catch (err) {
    state.bootError = `Failed to parse SCHEDULES: ${err instanceof Error ? err.message : String(err)}`;
    console.error(`[scheduler] ${state.bootError}`);
    state.booted = true;
    return getSchedulerStatus();
  }

  if (entries.length === 0) {
    state.bootError =
      "SCHEDULER_ENABLED=true but SCHEDULES is empty. No jobs armed. " +
      `Available job ids: ${listJobIds().join(", ")}`;
    console.warn(`[scheduler] ${state.bootError}`);
    state.booted = true;
    return getSchedulerStatus();
  }

  const skippedForWebhook: string[] = [];
  for (const entry of entries) {
    const def = getJob(entry.jobId);
    if (!def) {
      console.warn(
        `[scheduler] Skipping unknown job "${entry.jobId}" in SCHEDULES. Known: ${listJobIds().join(", ")}`,
      );
      continue;
    }
    if (!hasWebhook && def.requiresWebhook !== false) {
      skippedForWebhook.push(def.id);
      continue;
    }
    const armedJob = buildArmedJob(def, entry);
    armedJob.job.start();
    state.armed.push(armedJob);
  }

  if (skippedForWebhook.length > 0) {
    state.bootError =
      `OUTBOUND_WEBHOOK_URL is unset — skipped delivery job(s): ${skippedForWebhook.join(", ")}. ` +
      "Configure the webhook to arm them; jobs that store results locally were armed normally.";
    console.warn(`[scheduler] ${state.bootError}`);
  }

  state.booted = true;
  return getSchedulerStatus();
}

export function getSchedulerStatus(): SchedulerStatus {
  return {
    enabled: process.env.SCHEDULER_ENABLED === "true",
    started: state.booted,
    webhookConfigured: !!getOutboundWebhookUrl(),
    bootError: state.bootError,
    jobs: state.armed.map((a) => {
      const s = a.job.status();
      return {
        id: a.id,
        label: a.label,
        cadence: a.cadence,
        started: s.started,
        nextFireAt: s.nextFireAt,
        lastResult: s.lastResult,
      };
    }),
  };
}

export async function fireJobNow(
  id: string,
): Promise<{ ok: true; result: { kind: string; message?: string } } | { ok: false; error: string }> {
  const armedJob = state.armed.find((a) => a.id === id);
  if (armedJob) {
    const result = await armedJob.job.fireNow();
    return { ok: true, result };
  }
  // Allow firing a registered job even if it wasn't included in SCHEDULES —
  // useful for ad-hoc test runs without a server restart.
  const def = getJob(id);
  if (!def) return { ok: false, error: `Unknown job "${id}"` };
  try {
    const result = await def.run();
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

export function listKnownJobIds(): string[] {
  return listJobIds();
}
