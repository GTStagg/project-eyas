import "server-only";
import { captureSnapshot } from "@/lib/posture/snapshot";
import type { JobDefinition } from "./types";
import type { JobResult } from "@/lib/scheduler/recurring";

// Daily deterministic capture of the active tenant's posture into
// posture_snapshots. Unlike the delivery jobs this writes locally rather than
// to a webhook (requiresWebhook: false), so it arms even without a webhook
// configured. captureSnapshot never throws — it returns a result we map to a
// JobResult; kind "error" is the only value the runtime treats specially.
async function runPostureSnapshot(): Promise<JobResult> {
  const result = await captureSnapshot();
  if (!result.ok) {
    return { kind: "error", message: result.error ?? "capture failed" };
  }
  const partialNote = result.partial
    ? " (partial — some categories unavailable)"
    : "";
  return {
    kind: "captured",
    message: `snapshot written: ${result.metricsWritten} metrics in ${result.captureMs}ms${partialNote}`,
  };
}

export const postureSnapshotJob: JobDefinition = {
  id: "posture-snapshot",
  label: "Daily posture snapshot",
  requiresWebhook: false,
  defaultHour: 10,
  defaultMinute: 7,
  defaultWeekdays: [0, 1, 2, 3, 4, 5, 6], // every day
  run: runPostureSnapshot,
};
