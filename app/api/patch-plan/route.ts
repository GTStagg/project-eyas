import { NextResponse } from "next/server";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Body = {
  remediation?: { vendor?: string; product?: string; version?: string };
  device_ids?: string[];
  // Optional override: skip remediation matching and ask for a specific
  // script id (used for diagnostics like 'win-update-status').
  script_id?: string;
};

function buildPrompt(
  remediation: { vendor: string; product: string; version: string },
  deviceCount: number,
  scriptIdOverride: string | undefined,
): string {
  const today = new Date().toISOString().slice(0, 10);
  return [
    "You are producing a PATCH PLAN decision document for a CrowdStrike Falcon tenant administrator. The user picked a Spotlight remediation bundle and wants one screen that answers: which curated script will run, on which hosts, what does it do, what's the change-window guidance, and what's the rollback story. NO writes happen in this turn — this is a read-only planning surface. Execution is a separate, approval-gated turn.",
    "",
    `Today is ${today} (UTC).`,
    `Remediation entity: vendor=${JSON.stringify(remediation.vendor)}, product=${JSON.stringify(remediation.product)}, version=${JSON.stringify(remediation.version)}`,
    `Target host count: ${deviceCount}`,
    scriptIdOverride ? `Script override: ${scriptIdOverride}` : "",
    "",
    "DATA GATHERING — fan these out in parallel:",
    "- `extras_rtr_resolve_patch_plan` — resolve the curated script for this remediation (or for the override script_id). Pass the remediation entity and the device_ids the user supplied. Capture: matched script_id, title, params (with defaults filled), reboot_risk, expected_runtime_minutes, target_device_count, target_device_sample, and the script preview.",
    "- `falcon_search_hosts` — look up the target devices by id (`device_id` filter) so you can render hostname / OS version / last_seen for the sample. If many ids, just enrich the first 5 from target_device_sample.",
    "- `falcon_search_vulnerabilities` (facet=cve) — for the same vendor+product, gather a snapshot of CVE coverage this patch closes. Cap at the most-severe 5 by ExPRT rating.",
    "",
    "After the initial fan-out, do not loop. Write the report.",
    "",
    "Sections — produce all of them in this exact order. H2 (##) for each:",
    "",
    "## Plan",
    "One sentence: 'Apply <script title> to <N> hosts to remediate <vendor> <product>.' If no curated script matched, lead with 'No curated script matches this remediation entity yet — manual handling required.' and stop after the next section.",
    "",
    "## Curated script",
    "Render a small table: Field | Value, with rows for script_id, OS, reboot_risk, expected_runtime_minutes, parameters (one line per resolved param). Then a fenced code block with the script preview verbatim. Do not modify or paraphrase the preview.",
    "",
    "## Targets",
    "Number of hosts. Sample table of up to 5: hostname | OS | last seen | platform. If you couldn't enrich, say so explicitly.",
    "",
    "## CVE coverage",
    "Up to 5 CVEs this patch is expected to close, sorted by ExPRT rating descending. Columns: CVE | ExPRT | CVSS | Exploited? | Title. If Spotlight returns nothing, say 'No CVE entries found for this vendor+product in Spotlight.'",
    "",
    "## Change-window guidance",
    "Concrete recommendation, not a checklist:",
    "- reboot_risk=high → 'Stage to a 10% pilot group first; full rollout in next maintenance window.'",
    "- reboot_risk=none → 'Safe to roll fleet-wide during business hours; user-visible interruption is unlikely.'",
    "- target host count > 100 → recommend batching (e.g., 50/wave) and call out RTR session limits.",
    "Tailor to the actual numbers in this plan.",
    "",
    "## Rollback",
    "Plain-English rollback for THIS script:",
    "- windows updates → uninstall via `wusa /uninstall /kb:<id>` or `Remove-WindowsUpdate -KBArticleID`; full rollback may require a system restore point.",
    "- app upgrades (chrome/firefox/edge) → previous installer from vendor archive; winget cannot trivially downgrade.",
    "Be honest about the limitations.",
    "",
    "## Next step",
    "One sentence stating the exact tool call the operator would invoke to execute, with the resolved script_id, device_ids count, and params. Format as inline code. Example: `extras_rtr_run_patch(script_id='app-firefox', device_ids=[...12 ids...], params={}, dry_run=false)`. Do NOT invoke the tool — `extras_rtr_run_patch` is not registered yet, and even when it is it will be approval-gated.",
    "",
    "Style:",
    "- Markdown only. H2 headings.",
    "- Tables for the structured sections above.",
    "- Be terse and decisive. No filler.",
    "",
    "OUTPUT DISCIPLINE:",
    "- Output NOTHING between tool calls. Zero text.",
    "- Make all tool calls in parallel, then write the report ONCE.",
    "- The very first text token you emit must be the Plan H2.",
    "",
    "Citations:",
    "- Tool calls are numbered 1, 2, 3, … in call order.",
    "- End facts with [N] referencing the call number.",
    "- Do not invent citations.",
  ]
    .filter(Boolean)
    .join("\n");
}

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Body;
  const remediation = {
    vendor: (body.remediation?.vendor ?? "").trim(),
    product: (body.remediation?.product ?? "").trim(),
    version: (body.remediation?.version ?? "").trim(),
  };
  const deviceIds = Array.isArray(body.device_ids) ? body.device_ids : [];
  const scriptIdOverride = body.script_id?.trim() || undefined;

  if (!scriptIdOverride && (!remediation.vendor || !remediation.product)) {
    return NextResponse.json(
      { ok: false, error: "remediation.vendor and remediation.product required (or pass script_id)" },
      { status: 400 },
    );
  }
  if (deviceIds.length === 0) {
    return NextResponse.json(
      { ok: false, error: "device_ids must be a non-empty array" },
      { status: 400 },
    );
  }

  return streamAgent(async ({ mcp, extras, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      extrasMcp: extras,
      systemPrompt: buildPrompt(remediation, deviceIds.length, scriptIdOverride),
      initialMessages: [
        {
          role: "user",
          content: JSON.stringify({
            remediation,
            device_ids: deviceIds,
            script_id: scriptIdOverride,
          }),
        },
      ],
      emit,
      maxTokensPerTurn: 8192,
      maxIterations: 10,
      surface: "patch-plan",
    });
  });
}
