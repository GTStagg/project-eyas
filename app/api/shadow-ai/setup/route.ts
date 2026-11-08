import { NextResponse } from "next/server";
import { getRuntimeConfig } from "@/lib/config/runtime";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Drives the Shadow-AI setup card on `/shadow-ai`. Returns:
//   - bannedGroupId       — from active environment config (32-hex)
//   - rule group state    — from extras_shadow_ai_prevention_status
//   - bound prevention policies — resolved server-side by walking
//     extras_prevention_policy_posture and matching `groups[].id` against
//     the configured banned group id. The operator usually only knows the
//     host group; the policy id is the parameter `extras_shadow_ai_adopt_prevention`
//     wants. Resolving here means the "Adopt prevention rules" button can
//     pre-fill the primer with a single resolved policy id without making
//     the agent rediscover it.
//
// Read-only end-to-end. The button itself fires a chat primer hand-off;
// the actual write happens via the approval-gated sidecar tool.

type ToolText = { type?: string; text?: string };

function parseToolResult(result: unknown): unknown {
  if (!result || typeof result !== "object") return null;
  const content = (result as { content?: ToolText[] }).content;
  if (!Array.isArray(content) || content.length === 0) return null;
  const first = content[0];
  if (!first || typeof first.text !== "string") return null;
  try {
    return JSON.parse(first.text);
  } catch {
    return null;
  }
}

type PostureGroup = { id?: string; name?: string };
type PosturePolicy = {
  id?: string;
  name?: string;
  platform?: string;
  enabled?: boolean;
  groups?: PostureGroup[];
};
type PostureResp = { ok?: boolean; items?: PosturePolicy[] };

type StatusResp = {
  ok?: boolean;
  rule_group_exists?: boolean;
  rule_group_id?: string;
  rule_group_name?: string;
  rule_group_enabled?: boolean;
  installed_rule_count?: number;
  installed_rules?: string[];
  missing_rules?: string[];
  corpus_count?: number;
};

export async function GET() {
  const cfg = getRuntimeConfig();
  const raw = (cfg.shadowAiBannedGroupId || "").trim();
  const valid = /^[a-fA-F0-9]{32}$/.test(raw);
  const bannedGroupId = valid ? raw : null;

  if (!bannedGroupId) {
    return NextResponse.json({
      ok: true,
      configured: false,
      bannedGroupId: null,
      ruleGroup: null,
      boundPolicies: [],
      note: 'Set the "Shadow-AI banned host group" field on the active environment in /config before adopting Shadow-AI prevention.',
    });
  }

  return withFalconExtrasClient(async (client) => {
    const [statusRaw, postureRaw] = await Promise.all([
      client.callTool({
        name: "extras_shadow_ai_prevention_status",
        arguments: {},
      }),
      client.callTool({
        name: "extras_prevention_policy_posture",
        arguments: { limit: 200 },
      }),
    ]);

    const status = (parseToolResult(statusRaw) as StatusResp | null) ?? {};
    const posture = (parseToolResult(postureRaw) as PostureResp | null) ?? {};

    const boundPolicies = (posture.items ?? [])
      .filter((p) =>
        (p.groups ?? []).some(
          (g) => (g?.id ?? "").toLowerCase() === bannedGroupId.toLowerCase(),
        ),
      )
      .map((p) => ({
        id: p.id ?? "",
        name: p.name ?? "",
        platform: p.platform ?? "",
        enabled: p.enabled ?? true,
      }))
      .filter((p) => p.id);

    return NextResponse.json({
      ok: true,
      configured: true,
      bannedGroupId,
      ruleGroup: {
        exists: !!status.rule_group_exists,
        id: status.rule_group_id ?? null,
        name: status.rule_group_name ?? null,
        enabled: status.rule_group_enabled ?? null,
        installed: status.installed_rules ?? [],
        installedCount: status.installed_rule_count ?? 0,
        missing: status.missing_rules ?? [],
        corpusCount: status.corpus_count ?? 0,
      },
      boundPolicies,
    });
  });
}
