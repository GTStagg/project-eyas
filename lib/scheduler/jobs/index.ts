import "server-only";
import { patchDigestJob } from "./patch-digest";
import { dailyBriefingJob } from "./daily-briefing";
import { releaseWatcherJob } from "./release-watcher";
import { postureSnapshotJob } from "./posture-snapshot";
import type { JobDefinition } from "./types";

export const JOB_REGISTRY: Record<string, JobDefinition> = {
  [patchDigestJob.id]: patchDigestJob,
  [dailyBriefingJob.id]: dailyBriefingJob,
  [releaseWatcherJob.id]: releaseWatcherJob,
  [postureSnapshotJob.id]: postureSnapshotJob,
};

export function getJob(id: string): JobDefinition | undefined {
  return JOB_REGISTRY[id];
}

export function listJobIds(): string[] {
  return Object.keys(JOB_REGISTRY);
}

export type { JobDefinition };
