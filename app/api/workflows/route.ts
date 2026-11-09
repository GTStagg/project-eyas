import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function buildPrompt(): string {
  const today = new Date().toISOString().slice(0, 10);
  return [
    "You are producing a FUSION SOAR POSTURE report for a CrowdStrike Falcon tenant administrator. The user wants one screen that answers: what automation is running, what fired recently, what failed, and where are the gaps.",
    "",
    `Today is ${today} (UTC).`,
    "",
    "DATA GATHERING — fan these out in parallel up front:",
    "- `falcon_search_workflow_definitions` — the tenant's Fusion workflows. Pass limit=50. Capture id, name, description, enabled status, trigger, last modified. Use `pagination.total` for the definition count, since the list may be capped.",
    "- `falcon_search_workflow_executions` — recent executions across all workflows. ALWAYS pass filter=\"started_timestamp:>'now-24h'\" and limit=25: without a recency filter the upstream endpoint walks the whole execution ledger and times out on busy tenants. Capture **execution_id**, status, started_timestamp, definition reference, trigger source. The execution_id is load-bearing — you'll use it to build per-row Investigate hand-off links for failed executions. Use `pagination.total` for the execution count (10000 means at least 10000). If the call errors or times out, retry once with filter=\"ui_status:'Failed'+started_timestamp:>'now-24h'\" and limit=10 to surface just the failures (filter status with `ui_status`, not `status`).",
    "- `falcon_list_workflow_triggers` — what trigger types are available (each with the names of the fields it takes). Pass limit=50.",
    "",
    "After the initial fan-out, do not loop. Write the report.",
    "",
    "Sections — produce all of them in this exact order. Use H2 (##) for each.",
    "",
    "## Headline",
    "One sentence. Format: '<N> workflow definition(s); <K> enabled; <X> execution(s) in the recent window, <Y> failed.' If falcon_search_workflow_definitions returned a permission error (HTTP 401/403 or `required_scopes`), lead with 'Required Falcon API scope (`Workflow : read`) is not yet granted on this tenant.' and stop. If zero definitions: 'No Fusion workflow automation defined in this tenant.'",
    "",
    "## Workflow inventory",
    "Render a table of definitions: Name | Trigger event | Status | Modified. Cap at 25 rows. Note count if more.",
    "",
    "## Recent executions",
    "Render a table of the most recent executions (cap at 15): Workflow name | Status | Started | Trigger source.",
    "For any row where status is `failed`, render the Status cell as a markdown link to a chat hand-off so the operator can drill into the root cause: `[failed](/?primer=<urlencoded-primer>)`. Primer template (single sentence, no boilerplate): `Investigate Fusion workflow execution \\`<execution_id>\\` from \\`<workflow_name>\\` (failed at <started_timestamp>). Read its results with falcon_get_workflow_execution_results and explain the failure root cause.` URL-encode the primer string. Non-failed rows render plain Status text.",
    "If zero executions: 'No executions in the recent window.'",
    "",
    "## Posture flags",
    "Identify and call out:",
    "- Failed executions in the recent window — group by workflow name, count failures.",
    "- Workflows enabled but with zero recent executions (dormant — may indicate a broken trigger or unused playbook).",
    "- Workflows disabled but recently modified (someone is testing — note for the operator).",
    "If nothing flags, say 'No posture flags — Fusion automation looks healthy.'",
    "",
    "## Recommended actions",
    "Pick one or two — be decisive:",
    "- High failure rate on a specific workflow → 'Investigate <name>: <K> failures in the recent window.' Then add a markdown link `[Drill into latest failure](/?primer=<urlencoded-primer>)` using the most recent failed execution_id and the same primer template as in the Recent executions table.",
    "- Many dormant workflows → 'Audit dormant workflows; either disable or fix the trigger.'",
    "- Empty tenant → 'No Fusion automation in place. Consider standing up a baseline workflow (e.g., contain-on-critical-detection) — closes a common gap.'",
    "- Healthy → 'No action.'",
    "",
    "Style:",
    "- Markdown only. H2 headings. Tables for structured sections.",
    "- Be terse and decisive. No filler.",
    "- If a section has no data, still include the heading with a one-line note.",
    "",
    "OUTPUT DISCIPLINE:",
    "- Output NOTHING between tool calls. Zero text.",
    "- Make all tool calls in parallel, then write the report ONCE.",
    "- The very first text token you emit must be the Headline H2.",
    "",
    "Citations:",
    "- Tool calls are numbered 1, 2, 3, … in call order.",
    "- End facts with [N] referencing the call number.",
  ].join("\n");
}

export async function POST() {
  return streamAgent(async ({ mcp, extras, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      extrasMcp: extras,
      systemPrompt: buildPrompt(),
      initialMessages: [
        { role: "user", content: "Render the Fusion SOAR posture report." },
      ],
      emit,
      maxTokensPerTurn: 8192,
      maxIterations: 12,
      surface: "workflows",
    });
  });
}
