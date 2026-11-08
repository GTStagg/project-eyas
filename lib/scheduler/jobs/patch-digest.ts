import "server-only";
import { runPatchDigest } from "@/lib/scheduler/patch-digest";
import type { JobDefinition } from "./types";

export const patchDigestJob: JobDefinition = {
  id: "patch-digest",
  label: "Top open ExPRT-high+ patch bundle digest",
  defaultHour: 9,
  defaultMinute: 0,
  defaultWeekdays: [1], // Monday
  async run() {
    const result = await runPatchDigest();
    if (result.kind === "delivered") {
      return {
        kind: "delivered",
        message: `delivered ${result.chunks} chunk(s); ${result.markdownLength} chars; bundle=${result.bundle.label}`,
      };
    }
    if (result.kind === "skipped") return { kind: "skipped", message: result.reason };
    return { kind: "error", message: result.message };
  },
};
