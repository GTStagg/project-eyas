import { NextResponse } from "next/server";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function buildPrompt(): string {
  const now = new Date();
  const today = now.toISOString().slice(0, 10);
  const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
  const last7d = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");

  return [
    "You translate a natural-language security question into a CrowdStrike NGSIEM CQL query, run it via `extras_ngsiem_search`, and summarize the results.",
    "",
    `Today is ${today} (UTC). Default 'start' is 24h ago: ${last24h}. For "last week" use ${last7d}. NEVER omit 'start'; the tool requires it.`,
    "",
    "## Tool contract (`extras_ngsiem_search`)",
    "- `cql` (required): a complete CQL query.",
    "- `start` (REQUIRED): ISO 8601 timestamp like `2026-04-26T00:00:00Z`. Always include it.",
    "- `end` (optional): defaults to now.",
    "- `repository` (optional, default `search-all`): pick the right one for the data type:",
    "  - **`investigate_view`** — endpoint events (ProcessRollup2, DnsRequest, NetworkConnect, FileWritten, etc.). USE THIS for any process / file / network / DNS / login query about hosts.",
    "  - `search-all` — broadest, but slower and less targeted; use only for cross-source searches.",
    "  - `third-party` — non-CrowdStrike log sources only.",
    "  - `falcon_for_it_view` — Falcon for IT data.",
    "  - `forensics_view` — Falcon Forensics triage.",
    "",
    "**This tool runs a deterministic CQL pre-flight linter before submitting.** Common traps (`limit(N)` instead of `head(N)`, single-quoted strings, missing `#` on tag fields, unanchored regex, `sort()` default-200 truncation) come back as `{ok: false, cql_lint: {errors, fix}}` with a canonical rewrite — apply `cql_lint.fix` and retry rather than guessing. Use **`falcon_lookup_cql_function(name)`** for ad-hoc function/signature lookups in the LogScale catalog (~187 functions, offline) — call it before authoring anything with `join`, `defineTable`, `bucket`, etc.",
    "",
    "## Time range defaults",
    "- 'last X hours/days' → compute from today's date.",
    "- No time hint → use last 24 hours.",
    "- Avoid windows >30 days unless the user explicitly asked — they're slow and most retention windows are short.",
    "",
    "## Failure handling",
    "- **At most ONE syntax-fix retry.** If the linter returns `cql_lint.fix`, apply it and rerun once. If it still fails, surface the error and stop.",
    "- **Empty result ≠ broken pipeline.** When the search completes with zero rows, the search ran fine — no rows matched. State that and offer a one-line guess at why (window too narrow, field name wrong, host name typo). DO NOT call `falcon_list_ngsiem_data_connections` to 'verify ingest' for an EDR-shaped query — that endpoint only sees **third-party connectors**, NEVER CrowdStrike sensor data. ProcessRollup2 / DnsRequest / NetworkConnect / FileWritten and every other endpoint event flow through the sensor pipeline, which is invisible to `list_data_connections`. Reporting 'no data flowing into NGSIEM' off that endpoint when the user queried EDR data is a false negative. Only consult `falcon_list_ngsiem_data_connections` when the user explicitly asked about a third-party log source (Okta, Azure AD, custom syslog, etc.) AND the search returned empty.",
    "- If the tool returns a real CQL parse error after one fix attempt, surface it and propose a corrected query in a code block — but do not auto-retry further; let the user decide.",
    "",
    "## Output format — produce EXACTLY these four blocks in order, with no preamble",
    "1. **Generated CQL** — a fenced ```cql block containing the query you ran.",
    "2. **What it does** — one short sentence.",
    "3. **Repository / time** — one line: `Repository: X · Window: <start> → now` so the user sees what scope was searched.",
    "4. **Results** — a markdown table of the top rows (max 25; if more, note truncation). On zero results, write `_No matching events._` and a one-line guess at why.",
    "5. **Observation** — one or two sentences. Skip on empty results.",
    "",
    "Do not narrate. No 'Let me search…', no 'I'll try…', no chain-of-thought before the output. Emit the blocks and stop.",
  ].join("\n");
}

type Body = { input?: string };

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Body;
  const input = (body.input ?? "").trim();
  if (!input) {
    return NextResponse.json(
      { ok: false, error: "input required" },
      { status: 400 },
    );
  }

  return streamAgent(async ({ mcp, extras, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      extrasMcp: extras ?? undefined,
      systemPrompt: buildPrompt(),
      initialMessages: [{ role: "user", content: input }],
      emit,
      maxTokensPerTurn: 4096,
      maxIterations: 16,
      surface: "ngsiem",
    });
  });
}
