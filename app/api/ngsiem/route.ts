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
    "You translate a natural-language security question into a CrowdStrike NGSIEM CQL query, run it via `falcon_search_ngsiem`, and summarize the results.",
    "",
    `Today is ${today} (UTC). For "last 24 hours" pass \`hours_back=24\`; for "last week" pass \`hours_back=168\` (or \`start=${last7d}\`). For an explicit range pass \`start\` (and optionally \`end\`) as ISO 8601 instead of \`hours_back\` — never both. Default when the user gives no window: \`hours_back=24\` (from ${last24h}).`,
    "",
    "## Tool contract (`falcon_search_ngsiem`)",
    "- `query_string` (required): a complete CQL query.",
    "- ALWAYS pass `check_cql=true`, `max_rows=100` and `time_budget_seconds=50` on every call.",
    "- Window: `hours_back` (hours before now), or `start` / `end` (ISO 8601 like `2026-04-26T00:00:00Z`). One of `hours_back` or `start` is required.",
    "- `repository` (optional, default `search-all`): pick the right one for the data type:",
    "  - **`investigate_view`** — endpoint events (ProcessRollup2, DnsRequest, NetworkConnect, FileWritten, etc.). USE THIS for any process / file / network / DNS / login query about hosts.",
    "  - `search-all` — broadest, but slower and less targeted; use only for cross-source searches.",
    "  - `third-party` — non-CrowdStrike log sources only.",
    "  - `falcon_for_it_view` — Falcon for IT data.",
    "  - `forensics_view` — Falcon Forensics triage.",
    "",
    "**With `check_cql=true` the query is checked before it is sent.** Common traps (`limit(N)` instead of `head(N)`, single-quoted strings, missing `#` on tag fields, `sort()` without `limit=` silently keeping 200 rows) come back as `{ok: false, cql_lint, fix}` with a corrected query in `fix` — rerun with `fix` rather than guessing. The check does NOT catch misspelled function names: use **`falcon_lookup_cql_function(name)`** for function/signature lookups in the LogScale catalog — call it before authoring anything with `join`, `defineTable`, `bucket`, etc.",
    "",
    "**Bounded results.** `truncated: true` means more than 100 rows matched (`total_rows` has the count) — say so under the table. `partial: true` means the search hit the 50-second budget and these are the rows found so far — say the answer is incomplete and suggest a narrower window or query.",
    "",
    "## Time range defaults",
    "- 'last X hours/days' → compute from today's date.",
    "- No time hint → use last 24 hours.",
    "- Avoid windows >30 days unless the user explicitly asked — they're slow and most retention windows are short.",
    "",
    "## Failure handling",
    "- **At most ONE syntax-fix retry.** If the check returns `fix`, rerun with it once. If it still fails, surface the error and stop.",
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

  return streamAgent(async ({ mcp, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildPrompt(),
      initialMessages: [{ role: "user", content: input }],
      emit,
      maxTokensPerTurn: 4096,
      maxIterations: 16,
      surface: "ngsiem",
    });
  });
}
