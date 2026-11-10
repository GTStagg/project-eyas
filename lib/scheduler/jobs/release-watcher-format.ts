// Pure helpers for the eyas-mcp update watcher (release-watcher.ts): decide
// whether there's news and render the webhook markdown. No I/O, so they're
// unit-tested in scripts/test-release-watcher.mjs.
//
// eyas-mcp publishes no GitHub releases or tags; Eyas pins it by commit
// (versions.json `mcp-server-ref`). "An update" therefore means eyas-mcp's
// default branch has commits the pin doesn't, as reported by GitHub's compare
// API (`GET /repos/{owner}/{repo}/compare/{pin}...{branch}`).

export const EYAS_MCP_REPO = "GTStagg/eyas-mcp";
export const EYAS_MCP_BRANCH = "main";

/** The subset of GitHub's compare response the watcher reads. */
export type CompareResponse = {
  status?: string; // "ahead" | "identical" | "behind" | "diverged"
  ahead_by?: number;
  html_url?: string;
  commits?: Array<{
    sha?: string;
    html_url?: string;
    commit?: { message?: string; author?: { date?: string } };
  }>;
};

export type UpdateCheck =
  | { kind: "current"; message: string }
  | { kind: "update"; headSha: string; aheadBy: number; heading: string; markdown: string };

const MAX_COMMITS_LISTED = 15;

function firstLine(s: string | undefined): string {
  return (s ?? "").split("\n")[0].trim() || "(no message)";
}

/**
 * Turn a compare result into "nothing new" or an update notice. `pinLabel` is
 * versions.json `mcp-server` (a human version label like "0.21.0").
 */
export function checkForUpdate(compare: CompareResponse, pinRef: string, pinLabel: string): UpdateCheck {
  const commits = Array.isArray(compare.commits) ? compare.commits : [];
  const aheadBy = typeof compare.ahead_by === "number" ? compare.ahead_by : commits.length;
  if (compare.status === "identical" || aheadBy <= 0 || commits.length === 0) {
    return { kind: "current", message: `eyas-mcp ${EYAS_MCP_BRANCH} matches the pin (${pinRef.slice(0, 7)})` };
  }
  const head = commits[commits.length - 1];
  const headSha = head?.sha ?? "";
  if (!headSha) return { kind: "current", message: "compare returned no head commit" };

  const heading = `eyas-mcp update available — ${aheadBy} new commit${aheadBy === 1 ? "" : "s"}`;
  // Newest first, like a changelog.
  const listed = commits
    .slice(-MAX_COMMITS_LISTED)
    .reverse()
    .map((c) => {
      const date = c.commit?.author?.date ? ` (${c.commit.author.date.slice(0, 10)})` : "";
      return `- \`${(c.sha ?? "").slice(0, 7)}\` ${firstLine(c.commit?.message)}${date}`;
    });
  const more = commits.length > MAX_COMMITS_LISTED ? [`- …and ${commits.length - MAX_COMMITS_LISTED} earlier`] : [];
  const diverged =
    compare.status === "diverged"
      ? ["", "_Note: the pinned commit is no longer on eyas-mcp's main branch (it diverged). Check before moving the pin._"]
      : [];

  const markdown = [
    `## ${heading}`,
    "",
    `Pinned: \`${pinRef.slice(0, 12)}\` (${pinLabel || "no version label"})`,
    `Latest on ${EYAS_MCP_BRANCH}: \`${headSha.slice(0, 12)}\``,
    ...(compare.html_url ? [`Changes: ${compare.html_url}`] : []),
    ...diverged,
    "",
    "### New commits",
    ...listed,
    ...more,
    "",
    "---",
    "To upgrade, review the changes, then move `mcp-server-ref` in `versions.json` and the matching commit in " +
      "`docker-compose.yml` (update the `mcp-server` version label if it changed), and rebuild the standalone bundle.",
  ].join("\n");

  return { kind: "update", headSha, aheadBy, heading, markdown };
}
