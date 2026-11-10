import "server-only";
import { promises as fs } from "node:fs";
import path from "node:path";
import { deliverToWebhook, getOutboundWebhookUrl } from "@/lib/webhook/deliver";
import type { JobDefinition } from "./types";
import type { JobResult } from "@/lib/scheduler/recurring";
import versions from "@/versions.json";
import { EYAS_MCP_BRANCH, EYAS_MCP_REPO, checkForUpdate, type CompareResponse } from "./release-watcher-format";

// Watches eyas-mcp (the Falcon MCP server Eyas runs) for commits newer than
// Eyas's pin (versions.json `mcp-server-ref`). eyas-mcp publishes no GitHub
// releases or tags, so "an update" is its default branch moving past the pin;
// the message lists the new commits and the pin to move. Message logic lives
// in release-watcher-format.ts (pure, unit-tested).
const STATE_FILE = "release-watcher.json";

// last_head_sha: the eyas-mcp commit we last told the operator about.
type StoredState = { last_head_sha?: string; last_seen_at?: string };
function dataDir(): string {
  return process.env.FALCON_DATA_DIR ?? path.join(process.cwd(), "data");
}

async function readState(): Promise<StoredState> {
  try {
    const buf = await fs.readFile(path.join(dataDir(), STATE_FILE), "utf8");
    const parsed = JSON.parse(buf);
    return typeof parsed === "object" && parsed ? (parsed as StoredState) : {};
  } catch {
    return {};
  }
}

async function writeState(state: StoredState): Promise<void> {
  const dir = dataDir();
  await fs.mkdir(dir, { recursive: true });
  // Write-then-rename so a crash mid-write can't leave a truncated JSON file
  // that readState() would silently treat as first-run (swallowing a release).
  const target = path.join(dir, STATE_FILE);
  const tmp = `${target}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(state, null, 2), "utf8");
  await fs.rename(tmp, target);
}

async function fetchCompare(pinRef: string): Promise<CompareResponse> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "project-eyas-release-watcher",
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  const url = `https://api.github.com/repos/${EYAS_MCP_REPO}/compare/${encodeURIComponent(pinRef)}...${EYAS_MCP_BRANCH}`;
  const resp = await fetch(url, { headers, signal: AbortSignal.timeout(15_000) });
  if (!resp.ok) {
    throw new Error(`GitHub API ${resp.status} ${resp.statusText}`);
  }
  return (await resp.json()) as CompareResponse;
}

async function runReleaseWatcher(): Promise<JobResult> {
  if (!getOutboundWebhookUrl()) {
    return {
      kind: "skipped",
      message: "OUTBOUND_WEBHOOK_URL is not configured.",
    };
  }

  const pinRef = String(versions["mcp-server-ref"] ?? "").trim();
  const pinLabel = String(versions["mcp-server"] ?? "").trim();
  if (!/^[0-9a-f]{7,40}$/i.test(pinRef)) {
    return { kind: "error", message: "versions.json has no valid mcp-server-ref commit." };
  }

  let compare: CompareResponse;
  try {
    compare = await fetchCompare(pinRef);
  } catch (err) {
    return {
      kind: "error",
      message: err instanceof Error ? err.message : String(err),
    };
  }

  const check = checkForUpdate(compare, pinRef, pinLabel);
  if (check.kind === "current") return { kind: "skipped", message: check.message };

  const prior = await readState();
  if (prior.last_head_sha === check.headSha) {
    return {
      kind: "skipped",
      message: `already notified about ${check.headSha.slice(0, 7)}`,
    };
  }

  // No silent first run: a commit newer than the pin is actionable on its
  // own, unlike the old "latest upstream release" which said nothing about
  // what Eyas runs.
  const result = await deliverToWebhook({
    title: check.heading,
    source: "scheduled-release-watcher",
    markdown: check.markdown,
  });
  // Persist ONLY after delivery is confirmed. If delivery fails (Discord 429
  // exhaustion, transient 5xx, network), the next scheduled run retries the
  // notification instead of skipping it as already sent.
  if (!result.ok) return { kind: "error", message: result.error };
  await writeState({ last_head_sha: check.headSha, last_seen_at: new Date().toISOString() });
  return {
    kind: "delivered",
    message: `delivered ${result.chunks} chunk(s); eyas-mcp ${EYAS_MCP_BRANCH} is ${check.aheadBy} ahead of the pin`,
  };
}

export const releaseWatcherJob: JobDefinition = {
  id: "release-watcher",
  label: "Falcon integration update check",
  defaultHour: 9,
  defaultMinute: 0,
  defaultWeekdays: [1], // Monday
  run: runReleaseWatcher,
};
