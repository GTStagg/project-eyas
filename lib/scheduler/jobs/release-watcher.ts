import "server-only";
import { promises as fs } from "node:fs";
import path from "node:path";
import { deliverToWebhook, getOutboundWebhookUrl } from "@/lib/webhook/deliver";
import type { JobDefinition } from "./types";
import type { JobResult } from "@/lib/scheduler/recurring";

const STATE_FILE = "release-watcher.json";
const RELEASES_API =
  "https://api.github.com/repos/crowdstrike/falcon-mcp/releases/latest";

type StoredState = { last_tag?: string; last_seen_at?: string };

type Release = {
  tag_name?: string;
  name?: string;
  html_url?: string;
  published_at?: string;
  body?: string;
};

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

async function fetchLatestRelease(): Promise<Release> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "project-eyas-release-watcher",
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  const resp = await fetch(RELEASES_API, {
    headers,
    signal: AbortSignal.timeout(15_000),
  });
  if (!resp.ok) {
    throw new Error(`GitHub API ${resp.status} ${resp.statusText}`);
  }
  return (await resp.json()) as Release;
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1).trimEnd() + "…";
}

async function runReleaseWatcher(): Promise<JobResult> {
  if (!getOutboundWebhookUrl()) {
    return {
      kind: "skipped",
      message: "OUTBOUND_WEBHOOK_URL is not configured.",
    };
  }

  let release: Release;
  try {
    release = await fetchLatestRelease();
  } catch (err) {
    return {
      kind: "error",
      message: err instanceof Error ? err.message : String(err),
    };
  }
  const tag = (release.tag_name ?? "").trim();
  if (!tag) {
    return { kind: "error", message: "GitHub returned no tag_name." };
  }

  const prior = await readState();
  if (prior.last_tag === tag) {
    return {
      kind: "skipped",
      message: `no new release; current tag is ${tag}`,
    };
  }

  const isFirstRun = !prior.last_tag;
  const next: StoredState = {
    last_tag: tag,
    last_seen_at: new Date().toISOString(),
  };

  // First-run policy: store the tag silently. We don't want to spam an
  // operator with "current latest is X" the first time we arm. They'll get
  // a notification on the next actual release. Nothing is delivered, so it's
  // safe to persist immediately here.
  if (isFirstRun) {
    await writeState(next);
    return {
      kind: "skipped",
      message: `first run — initialized state to ${tag} without delivering`,
    };
  }

  const heading = `falcon-mcp ${tag} — upstream release`;
  const url = release.html_url ?? `https://github.com/crowdstrike/falcon-mcp/releases/tag/${encodeURIComponent(tag)}`;
  const published = release.published_at ?? "(no date)";
  const notes = release.body ? truncate(release.body, 1500) : "";

  const markdown = [
    `## ${heading}`,
    "",
    `Published: ${published}`,
    `Release: ${url}`,
    `Previous tag tracked: ${prior.last_tag ?? "(none)"}`,
    "",
    notes ? "### Release notes\n" + notes : "_No release notes provided._",
    "",
    "---",
    "Bump the pinned `falcon-mcp` version in `docker-compose.yml` and the standalone wheel bundle once you've reviewed the notes.",
  ].join("\n");

  const result = await deliverToWebhook({
    title: heading,
    source: "scheduled-release-watcher",
    markdown,
  });
  // Persist the new tag ONLY after delivery is confirmed. If delivery fails
  // (Discord 429 exhaustion, transient 5xx, network), last_tag stays at the
  // prior value so the next scheduled run retries the notification instead of
  // seeing last_tag === tag and silently skipping — a single delivery hiccup
  // must not drop the release alert forever.
  if (!result.ok) return { kind: "error", message: result.error };
  await writeState(next);
  return {
    kind: "delivered",
    message: `delivered ${result.chunks} chunk(s); ${tag} (was ${prior.last_tag ?? "—"})`,
  };
}

export const releaseWatcherJob: JobDefinition = {
  id: "release-watcher",
  label: "Upstream falcon-mcp release watcher",
  defaultHour: 9,
  defaultMinute: 0,
  defaultWeekdays: [1], // Monday
  run: runReleaseWatcher,
};
