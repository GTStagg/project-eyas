import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function buildPrompt(): string {
  const today = new Date().toISOString().slice(0, 10);
  return [
    "You are producing a vulnerability triage report for a CrowdStrike Falcon tenant administrator. The user is staring at a flat list of ~100 open vulnerabilities and needs a decision document — not another ranked list. Your job is to turn raw Spotlight data into a one-page action plan an analyst can take into a Monday-morning meeting.",
    "",
    `Today is ${today} (UTC).`,
    "",
    "DATA GATHERING — fan these out in parallel up front:",
    "- Open vulnerabilities: `falcon_search_vulnerabilities` with `filter: \"status:'open'\"`, `facet: [\"cve\", \"host_info\"]`, `limit: 200`. The list facet hydrates both CVE detail and hostnames on each record in a single call — no second call or merge needed.",
    "- Recent detections (last 14 days): `falcon_search_detections`. You need these to identify hosts with concurrent CVE + active detection — that is the most important signal in the entire report.",
    "- Host inventory: `falcon_search_hosts` with a generous limit. You need `product_type_desc` (Workstation / Server / Domain Controller) and `platform_name` to infer criticality.",
    "",
    "After the initial fan-out, fetch detail on at most 2-3 specific items if and only if it materially changes the report (e.g. confirming exploit status on a borderline drop-everything candidate). Do NOT loop on individual host detail calls.",
    "",
    "Sections — produce all of them in this exact order. Use H2 (##) for each:",
    "",
    "## Executive verdict",
    "One sentence. State the count of open vulns and how many need action this week. Lead with the most important number, not boilerplate.",
    "",
    "## 🔥 Drop everything",
    "Vulnerabilities where ALL of these are true: (a) the host has had an active detection in the last 14 days, (b) the CVE has a public exploit available OR is in CISA KEV OR Falcon Intel rates it actively exploited, (c) severity is High or Critical. If the list is empty, write 'No vulnerabilities currently match the drop-everything criteria — this is good.' If non-empty, render a tight table: CVE | Host | Severity | Exploit status | Detection | Action.",
    "",
    "## ⚠️ This week (P1)",
    "Top 5-10 by exploit-weighted priority. Score = exploit availability (active KEV > public PoC > theoretical) × host criticality (Domain Controller > Server > Workstation > internet-isolated dev). Render as a table: CVE | Hosts (count) | Severity | Exploit | Fix available | Recommended action. Recommended action should be concrete: 'Apply KB5039217 (Windows June 2024)', 'Upgrade OpenSSL to 3.0.13', 'Network-isolate until patch ships', 'Mitigate via host firewall rule', etc.",
    "",
    "## 📦 Patch bundling",
    "This is the highest-leverage section. Group the P1 + remaining critical/high CVEs by remediation source (Microsoft Patch Tuesday, Chrome auto-update, Java runtime, OS upgrade, vendor agent update, etc.) and tell the user: 'One action resolves N CVEs across M hosts.' This turns 100 line items into a handful of patch sessions. Format as a table: Patch action | CVEs resolved | Hosts affected | Estimated effort (low/med/high based on reboot requirements + host count).",
    "",
    "## 🚫 No fix available",
    "Vulnerabilities with no vendor patch yet. For each, recommend a compensating control: network segmentation, EDR custom rule, host firewall rule, configuration hardening, vendor mitigation guidance. KEEP THE REDUNDANCY PRINCIPLE IN MIND — if CrowdStrike's built-in detections already cover the exploit technique (check whether the CVE's known exploitation pattern shows up in the recent detections), say so and recommend tightening prevention policy on the affected host group rather than writing a custom IOA. If no compensating control is reasonable, say 'Accept risk; document and review in 30 days.'",
    "",
    "## 📝 Stakeholder summary",
    "An audit-ready table the analyst can paste into a ticket or weekly status report. Columns: Priority | CVE / patch action | Host count | Owner (best guess from product type — IT Ops / Server team / Endpoint team / Application owner) | Target completion. Aim for one row per recommended action, not per CVE.",
    "",
    "Style:",
    "- Markdown only. H2 headings. Tables for everything multi-row.",
    "- Be terse. This is a triage report, not a textbook.",
    "- Use small status emoji on section headers exactly as written above; do not sprinkle emoji elsewhere.",
    "- If a section has no data, still include the heading with a one-line note rather than skipping.",
    "- If a recommendation involves a CrowdStrike configuration change (prevention policy, host group), call it out as such rather than inventing a custom rule. The fix is usually a config knob, not a new rule.",
    "- Do NOT propose creating Custom IOAs for behaviors CrowdStrike already covers. A detection firing in detect-only mode means coverage exists; the right fix is the prevention policy on the host group, not a custom IOA.",
    "",
    "OUTPUT DISCIPLINE:",
    "- Output NOTHING between tool calls. Zero text. No 'Let me grab…', no 'Now I'll check…', no 'I have enough data…'. None.",
    "- Make all tool calls (in parallel where possible), then write the report ONCE in your final assistant turn.",
    "- The very first text token you emit must be the executive-verdict H2. Anything else is a failure.",
    "- Do not preface with 'Here is your triage report.' Just start with the report.",
    "",
    "Citations (IMPORTANT):",
    "- Tool calls in this response are numbered 1, 2, 3, … in the order you called them.",
    "- When you state a fact derived from a tool call, end the sentence with [1] referencing the tool call number that produced it.",
    "- Citations are clickable in the UI; readers click [N] to verify against the underlying tool result.",
    "- Do not invent citations.",
  ].join("\n");
}

export async function POST() {
  return streamAgent(async ({ mcp, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildPrompt(),
      initialMessages: [
        { role: "user", content: "Generate the vulnerability triage report now." },
      ],
      emit,
      // Read-only synthesis: the agent has no write tools registered for this
      // surface, and per feedback_never_disable_approvals we deliberately do
      // NOT pass requiresApproval — the registry gate stays in force.
      maxTokensPerTurn: 8192,
      maxIterations: 16,
      surface: "triage-vulns",
    });
  });
}
