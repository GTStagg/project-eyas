import "server-only";
import type { JobResult } from "@/lib/scheduler/recurring";

export type JobDefinition = {
  id: string;
  label: string;
  /** Defaults applied when the SCHEDULES manifest entry omits day/time. */
  defaultWeekdays: ReadonlyArray<number>;
  defaultHour: number;
  defaultMinute: number;
  /**
   * Whether this job needs an outbound webhook to do anything useful.
   * Defaults to true (the delivery jobs). A job that persists locally instead
   * of delivering (e.g. posture-snapshot) sets this false so it still arms
   * when no webhook is configured. See startScheduler's per-job gate.
   */
  requiresWebhook?: boolean;
  run: () => Promise<JobResult>;
};
