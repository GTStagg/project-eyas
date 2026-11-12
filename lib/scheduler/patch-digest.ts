import "server-only";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { detectFalconError, parseConcatenatedJson } from "@/lib/mcp/parse";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { deliverToWebhook, getOutboundWebhookUrl } from "@/lib/webhook/deliver";

type RemediationEntity = {
  id?: string;
  reference?: string;
  title?: string;
  recommendation_type?: string;
};

type Vuln = {
  id?: string;
  aid?: string;
  hostname?: string;
  cve_id?: string;
  cve?: { id?: string; exprt_rating?: string };
  exprt_rating?: string;
  apps?: Array<{
    vendor?: string;
    vendor_normalized?: string;
    product_name_version?: string;
    product_name_normalized?: string;
  }>;
  remediation?: { entities?: RemediationEntity[]; ids?: string[] };
  host_info?: { hostname?: string; device_id?: string };
};

type Bundle = {
  key: string;
  label: string;
  vendor: string;
  product: string;
  version: string;
  cveCount: number;
  hostCount: number;
  exprtHighCount: number;
  maxExprt: string;
  deviceIds: string[];
};

const EXPRT_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  MINIMAL: 0,
  "": -1,
};

const SPOTLIGHT_FILTER = "status:'open'+cve.exprt_rating:['CRITICAL','HIGH']";
const SPOTLIGHT_LIMIT = 1000;
const MAX_DEVICE_IDS = 25;

export type PatchDigestResult =
  | { kind: "delivered"; bundle: Bundle; chunks: number; markdownLength: number }
  | { kind: "skipped"; reason: string }
  | { kind: "error"; message: string };

function pickRecommended(v: Vuln): RemediationEntity | undefined {
  const ents = v.remediation?.entities;
  if (!ents || ents.length === 0) return undefined;
  return ents.find((e) => e.recommendation_type === "recommended") ?? ents[0];
}

function remediationKey(e: RemediationEntity): string {
  return e.id ?? e.reference ?? e.title ?? "?";
}

function remediationLabel(e: RemediationEntity): string {
  if (e.title && e.reference) return `${e.title} · ${e.reference}`;
  return e.title ?? (e.id ? `id ${e.id.slice(0, 12)}…` : "(unknown)");
}

function deriveRemediation(
  label: string,
  sample: Vuln,
): { vendor: string; product: string; version: string } {
  const app = sample.apps?.[0];
  const vendor = app?.vendor ?? app?.vendor_normalized ?? "";
  const product = app?.product_name_version ?? app?.product_name_normalized ?? "";
  if (vendor || product) return { vendor, product, version: "" };
  const [titlePart, refPart] = label.split(" · ");
  return {
    vendor: "",
    product: (titlePart ?? "").replace(/^Update\s+/i, ""),
    version: refPart ?? "",
  };
}

async function fetchAndGroup(): Promise<Bundle[] | { error: string }> {
  return withFalconMcpClient(async (client) => {
    // falcon-mcp 0.14.0 accepts a list facet (PR #460): one call hydrates the
    // cve, host_info and remediation blocks per record — replaces the prior
    // three-facet fan-out + merge-by-id (empirically confirmed the combined
    // endpoint returns all three sub-objects per row).
    let merged: Vuln[];
    try {
      const result = await client.callTool({
        name: "falcon_search_vulnerabilities",
        arguments: {
          filter: SPOTLIGHT_FILTER,
          sort: "created_timestamp|desc",
          limit: SPOTLIGHT_LIMIT,
          facet: ["cve", "host_info", "remediation"],
        },
      });
      const text = (result.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      merged = parseConcatenatedJson<Vuln>(text);
      const upstreamErr = detectFalconError(merged);
      if (upstreamErr) throw new Error(upstreamErr);
    } catch (err) {
      return { error: err instanceof Error ? err.message : String(err) };
    }

    type Acc = {
      key: string;
      label: string;
      sample: Vuln;
      vulns: Vuln[];
      cves: Set<string>;
      hosts: Set<string>;
      deviceIds: Set<string>;
      exprtHighCount: number;
      maxExprt: string;
    };
    const groups = new Map<string, Acc>();
    for (const v of merged) {
      const rec = pickRecommended(v);
      if (!rec) continue; // only has-fix bundles
      const key = remediationKey(rec);
      const label = remediationLabel(rec);
      let g = groups.get(key);
      if (!g) {
        g = {
          key,
          label,
          sample: v,
          vulns: [],
          cves: new Set(),
          hosts: new Set(),
          deviceIds: new Set(),
          exprtHighCount: 0,
          maxExprt: "",
        };
        groups.set(key, g);
      }
      g.vulns.push(v);
      const cve = v.cve_id ?? v.cve?.id;
      if (cve) g.cves.add(cve);
      const hostname = v.hostname ?? v.host_info?.hostname;
      if (hostname) g.hosts.add(hostname);
      const aid = v.aid ?? v.host_info?.device_id;
      if (aid) g.deviceIds.add(aid);
      const exprt = (v.exprt_rating ?? v.cve?.exprt_rating ?? "").toUpperCase();
      if ((EXPRT_RANK[exprt] ?? -1) > (EXPRT_RANK[g.maxExprt] ?? -1)) g.maxExprt = exprt;
      if (exprt === "HIGH" || exprt === "CRITICAL") g.exprtHighCount += 1;
    }

    const bundles: Bundle[] = Array.from(groups.values()).map((g) => {
      const rem = deriveRemediation(g.label, g.sample);
      return {
        key: g.key,
        label: g.label,
        vendor: rem.vendor,
        product: rem.product,
        version: rem.version,
        cveCount: g.cves.size,
        hostCount: g.hosts.size,
        exprtHighCount: g.exprtHighCount,
        maxExprt: g.maxExprt,
        deviceIds: Array.from(g.deviceIds).slice(0, MAX_DEVICE_IDS),
      };
    });

    bundles.sort((a, b) => {
      const exprt = (EXPRT_RANK[b.maxExprt] ?? -1) - (EXPRT_RANK[a.maxExprt] ?? -1);
      if (exprt !== 0) return exprt;
      if (b.exprtHighCount !== a.exprtHighCount) return b.exprtHighCount - a.exprtHighCount;
      return b.cveCount - a.cveCount;
    });

    return bundles;
  });
}

function buildPatchPlanPrompt(bundle: Bundle): string {
  const today = new Date().toISOString().slice(0, 10);
  return [
    "You are producing a SCHEDULED PATCH-PLAN decision document for a CrowdStrike Falcon tenant administrator. This is the Monday-morning automated digest. Lead with the headline that this patch bundle is the top open ExPRT-high+ remediation surface today. NO writes happen — execution is a separate, approval-gated turn the operator drives manually from the UI.",
    "",
    `Today is ${today} (UTC).`,
    `Remediation entity: vendor=${JSON.stringify(bundle.vendor)}, product=${JSON.stringify(bundle.product)}, version=${JSON.stringify(bundle.version)}`,
    `Top-bundle stats (already computed): ${bundle.cveCount} CVE(s) across ${bundle.hostCount} host(s), max ExPRT=${bundle.maxExprt}, ${bundle.exprtHighCount} ExPRT-High+ rows.`,
    `Target host count for this run: ${bundle.deviceIds.length}`,
    "",
    "DATA GATHERING — fan these out in parallel, ONCE:",
    "- `extras_rtr_resolve_patch_plan` — resolve the curated script for this remediation. Pass the remediation entity + the device_ids from the user payload. Capture: matched script_id, title, params, reboot_risk, expected_runtime_minutes, target_device_count, target_device_sample, script preview.",
    "- `falcon_search_hosts` — enrich the first 5 ids from target_device_sample (hostname / OS / last seen / platform).",
    "- `falcon_search_vulnerabilities` (facet=cve) — for the same vendor+product, gather CVE coverage (top 5 by ExPRT desc).",
    "",
    "After the initial fan-out, do not loop. Write the report.",
    "",
    "Sections — produce all of them in this exact order. H2 (##) for each:",
    "",
    "## Headline",
    "One paragraph: name the bundle, ExPRT max, ExPRT-high count, host count, CVE count, and that this is the highest-priority has-fix remediation surface in the open Spotlight queue right now. End with: 'Operator action: review and run from the /vulnerabilities By-patch view when ready.'",
    "",
    "## Curated script",
    "Render a small table (Field | Value) with rows for script_id, OS, reboot_risk, expected_runtime_minutes, parameters. Then a fenced code block with the script preview verbatim.",
    "",
    "## Targets",
    "Sample table of up to 5: hostname | OS | last seen | platform.",
    "",
    "## CVE coverage",
    "Up to 5 CVEs this patch closes, sorted by ExPRT desc. Columns: CVE | ExPRT | CVSS | Exploited? | Title.",
    "",
    "## Change-window guidance",
    "- reboot_risk=high → 'Stage to a 10% pilot first.'",
    "- reboot_risk=none → 'Safe fleet-wide during business hours.'",
    "- host count > 100 → recommend batching (50/wave) + RTR session limits.",
    "Tailor to the actual numbers.",
    "",
    "## Rollback",
    "Plain-English rollback for THIS script type. Be honest about limitations (winget cannot trivially downgrade; Windows updates may need wusa /uninstall or a restore point).",
    "",
    "## Next step",
    "One sentence with the exact tool call to execute, formatted as inline code: `extras_rtr_run_patch(script_id='<id>', device_ids=[…], params={}, dry_run=false)`. Do NOT invoke the tool.",
    "",
    "Style:",
    "- Markdown only. H2 headings.",
    "- Be terse and decisive.",
    "",
    "OUTPUT DISCIPLINE:",
    "- Output NOTHING between tool calls. Zero text.",
    "- Make all tool calls in parallel, then write the report ONCE.",
    "- The very first text token you emit must be the Headline H2.",
  ].join("\n");
}

export async function runPatchDigest(): Promise<PatchDigestResult> {
  if (!getOutboundWebhookUrl()) {
    return { kind: "skipped", reason: "OUTBOUND_WEBHOOK_URL is not configured." };
  }

  const groupResult = await fetchAndGroup();
  if (!Array.isArray(groupResult)) {
    return { kind: "error", message: groupResult.error };
  }

  const eligible = groupResult.filter(
    (b) => b.exprtHighCount > 0 && b.deviceIds.length > 0 && (b.vendor || b.product),
  );
  if (eligible.length === 0) {
    return {
      kind: "skipped",
      reason: "No has-fix bundles with ExPRT High+ hosts and at least one managed device id.",
    };
  }

  const bundle = eligible[0];

  // Run the patch-plan agent loop, collecting assistant text.
  let buffer = "";
  let agentError: string | null = null;
  try {
    await withFalconMcpClient(async (mcp) => {
      {
        await runAgentLoop({
          mcp,
          systemPrompt: buildPatchPlanPrompt(bundle),
          initialMessages: [
            {
              role: "user",
              content: JSON.stringify({
                remediation: {
                  vendor: bundle.vendor,
                  product: bundle.product,
                  version: bundle.version,
                },
                device_ids: bundle.deviceIds,
              }),
            },
          ],
          emit: (event, data) => {
            if (event === "iteration_start") {
              // Keep only the final iteration's prose — earlier iterations
              // are tool-call rounds with no narration.
              buffer = "";
            } else if (event === "text" && typeof data === "string") {
              buffer += data;
            } else if (event === "error") {
              const msg =
                typeof data === "object" && data && "message" in data
                  ? String((data as { message?: unknown }).message ?? "")
                  : String(data ?? "");
              agentError = msg || "agent loop emitted an error event";
            }
          },
          maxTokensPerTurn: 8192,
          maxIterations: 10,
          surface: "patch-plan",
        });
      }
    });
  } catch (err) {
    return { kind: "error", message: err instanceof Error ? err.message : String(err) };
  }

  if (agentError) return { kind: "error", message: agentError };
  const markdown = buffer.trim();
  if (!markdown) {
    return { kind: "error", message: "Agent produced no markdown." };
  }

  const title = `Monday patch digest — ${bundle.label}`;
  const result = await deliverToWebhook({
    title,
    source: "scheduled-patch-digest",
    markdown,
  });

  if (!result.ok) return { kind: "error", message: result.error };
  return {
    kind: "delivered",
    bundle,
    chunks: result.chunks,
    markdownLength: markdown.length,
  };
}
