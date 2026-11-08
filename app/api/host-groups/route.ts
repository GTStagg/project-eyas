import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function buildPrompt(): string {
  const today = new Date().toISOString().slice(0, 10);
  return [
    "You are producing a HOST GROUP POSTURE report for a CrowdStrike Falcon tenant administrator. The user wants one screen that answers: what groups exist, how big are they, when were they last touched, and where are the gaps.",
    "",
    `Today is ${today} (UTC).`,
    "",
    "DATA GATHERING — fan these out in parallel up front:",
    "- `extras_host_group_list` — list every host group in the tenant. Pass limit=200. Capture id, name, group_type (static | dynamic), assignment_rule, modified_timestamp, modified_by.",
    "- For each of the FIRST 5 groups returned (by modified_timestamp desc), call `extras_host_group_members` with that group_id and limit=10 so you can render a representative member sample. Do not enumerate all members of all groups — just the top 5 most recently modified.",
    "- `falcon_search_hosts` with limit=1 — just to confirm a real host count is reachable; capture meta.pagination.total if exposed. Pass NO filter.",
    "",
    "After the initial fan-out, do not loop. Write the report.",
    "",
    "Sections — produce all of them in this exact order. Use H2 (##) for each.",
    "",
    "## Headline",
    "One sentence. Format: '<N> host group(s) defined; <K> dynamic, <S> static; most recently changed <date> by <actor>.' If extras_host_group_list returned scope_pending=true, lead with 'Required Falcon API scope (`Host Group : read`) is not yet granted on this tenant.' and stop. If zero groups: 'No host groups defined in this tenant.'",
    "",
    "## Group inventory",
    "Render a table of all groups: Name | Type | Modified | Modified by | Description. Cap at 25 rows. If more than 25, note the count.",
    "",
    "## Sample membership",
    "For the 5 most recently modified groups (the ones you fetched members for), render: Group | Sample hostnames (up to 5 comma-separated) | Note. The note column reads 'static — frozen membership' or 'dynamic — assignment rule: <rule>' depending on group_type.",
    "",
    "## Posture flags",
    "Identify and call out:",
    "- Groups with no recent modification (>90 days) — name them.",
    "- Static groups that look orphaned (created but never modified, or modified once long ago).",
    "- Dynamic groups whose assignment_rule looks stale (e.g., references OS versions or hostnames patterns that may not exist anymore — call them out for review, but don't speculate beyond what's visible).",
    "If nothing flags, say 'No posture flags — group inventory looks healthy.'",
    "",
    "## Recommended actions",
    "Pick one or two — be decisive:",
    "- Many static groups + low dynamic adoption → 'Consider migrating frequent-change static groups to dynamic with FQL assignment rules.'",
    "- Empty tenant + active patching surface → 'Stand up a baseline pilot group (e.g., 10% of Windows hosts by hostname pattern or last_seen recency) so the patching arc has a target population that isn't the full fleet.'",
    "- Healthy posture → 'No action. Posture is healthy.'",
    "",
    "Style:",
    "- Markdown only. H2 headings.",
    "- Tables for the structured sections.",
    "- Be terse and decisive. No filler.",
    "- If a section has no data, still include the heading with a one-line note.",
    "",
    "OUTPUT DISCIPLINE:",
    "- Output NOTHING between tool calls. Zero text.",
    "- Make all tool calls in parallel where possible, then write the report ONCE.",
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
      mcp,
      extrasMcp: extras,
      systemPrompt: buildPrompt(),
      initialMessages: [
        { role: "user", content: "Render the host-group posture report." },
      ],
      emit,
      maxTokensPerTurn: 8192,
      maxIterations: 12,
      surface: "host-groups",
      signal,
    });
  });
}
